"""Notes tools — take and query vector-tagged engagement observations.

Thin MCP surface over the **ephemeral, per-session** :class:`NotesStore`
(`kambo.notes`). No data is persisted unless the operator explicitly opts in
via ``KAMBO_NOTES_PATH`` — every response echoes ``ephemeral`` so the session
scope is never ambiguous.

The two tools embody the perspective shift: ``note_add`` records an observation
indexed by attack vector with an *evidence-backed* stance (the evidence chain,
not gut feel, sets how far a vector may be claimed), and ``note_query`` reads it
back through the attacker's lens (flat list, vector pivot, progress board, or
blind-spot coverage)."""

from __future__ import annotations

from typing import Any

from kambo.bounty_pricing import acceptance_rate
from kambo.models import Confidence, EvidenceChain, Severity
from kambo.notes import (
    AttackVector,
    Note,
    VectorStance,
    get_notes_store,
    next_action_for,
    stance_rank,
)
from kambo.tools import reporting

# AttackVector value -> bounty_pricing acceptance-table key (where one exists).
_VECTOR_PRICING_KEY: dict[str, str] = {
    "sqli": "sqli", "rce": "rce", "ssrf": "ssrf", "idor": "idor", "bola": "bola",
    "access_control": "bfla", "jwt": "jwt", "ssti": "ssti", "lfi": "path_traversal",
    "xxe": "xxe", "deserialization": "insecure_deserialization",
    "prototype_pollution": "prototype_pollution", "xss": "xss", "cors": "cors",
    "csrf": "csrf", "open_redirect": "open_redirect", "auth": "auth_bypass",
    "secrets": "credential_exposure", "info_disclosure": "information_disclosure",
    "misconfig": "misconfig", "subdomain_takeover": "subdomain_takeover",
}

# Advisory acceptance for vectors with no entry in the pricing table.
_VECTOR_ADVISORY_ACCEPTANCE: dict[str, float] = {
    "business_logic": 0.80, "race": 0.75, "graphql": 0.70,
    "recon": 0.10, "other": 0.30,
}

# How much pushing a vector at this stance is worth — rewards promising,
# in-flight work; a confirmed vector is already realized (little left to
# "advance"), a ruled-out one is dead.
_STANCE_ADVANCE_WEIGHT: dict[str, float] = {
    "suspected": 1.0, "probing": 1.0, "untested": 0.6,
    "confirmed": 0.2, "ruled_out": 0.0,
}


def _vector_acceptance(vector: str) -> float:
    key = _VECTOR_PRICING_KEY.get(vector)
    if key:
        return acceptance_rate(key)
    return _VECTOR_ADVISORY_ACCEPTANCE.get(vector, 0.5)


def _roi_for(vector: str, stance: str, confidence: int) -> dict[str, Any]:
    """A self-contained, config-free priority score for *advancing* a vector:
    acceptance (pays off if real) × operator confidence × how-worth-pushing.
    Relative 0-100 — no program payout needed, so it stays per-session."""
    acc = _vector_acceptance(vector)
    weight = _STANCE_ADVANCE_WEIGHT.get(stance, 0.5)
    score = round(acc * (max(1, min(10, confidence)) / 10) * weight * 100)
    return {"acceptance": round(acc, 2), "stance_weight": weight, "priority_score": score}

# Evidence-chain confidence → the strongest stance that evidence justifies.
# A note may never claim a stronger stance than its evidence supports; a stance
# claimed with no evidence is capped at "untested" intent and flagged.
_EVIDENCE_FLOOR: dict[Confidence, VectorStance] = {
    Confidence.CONFIRMED: VectorStance.CONFIRMED,
    Confidence.FIRM: VectorStance.PROBING,
    Confidence.TENTATIVE: VectorStance.SUSPECTED,
}

# Stances strong enough that recording them without evidence is just a hunch.
_STRONG_STANCES = {VectorStance.PROBING, VectorStance.CONFIRMED}


def _valid_values(enum_cls: type) -> list[str]:
    return [e.value for e in enum_cls]


def _build_chain(signals: list[dict] | None) -> EvidenceChain:
    chain = EvidenceChain()
    for sig in signals or []:
        chain = chain.add(
            signal=str(sig.get("signal", "")),
            source=str(sig.get("source", "")),
            raw_data=str(sig.get("raw_data", "")),
            weight=float(sig.get("weight", 1.0)),
        )
    return chain


async def note_add(
    vector: str,
    target: str,
    observation: str,
    stance: str = "untested",
    confidence: int = 5,
    tags: list[str] | None = None,
    refs: list[str] | None = None,
    note_id: str = "",
    evidence_signals: list[dict] | None = None,
) -> dict[str, Any]:
    """Record a vector-tagged observation in the per-session notes store.

    The claimed ``stance`` is reconciled with ``evidence_signals``: evidence is
    the authority. If the claim outruns the evidence it is capped to the
    evidence-supported level and a caveat is returned; a strong claim with no
    evidence is recorded but flagged as a hunch. Re-adding with the same
    ``note_id`` progresses an existing note (latest wins).

    Args:
        vector: attack vector — one of the AttackVector taxonomy (sqli, idor, ssrf, ...).
        target: asset/endpoint the note is about.
        observation: the note text.
        stance: untested | suspected | probing | confirmed | ruled_out.
        confidence: 1-10 gut feel that this vector pays off on this target.
        tags: free-form labels.
        refs: finding ids, URLs, ticket links.
        note_id: stable id; reuse to update/progress the same note.
        evidence_signals: [{signal, source, raw_data, weight}] backing the stance.
    """
    try:
        vec = AttackVector(vector.lower())
    except ValueError:
        return {"error": f"unknown vector '{vector}'", "valid_vectors": _valid_values(AttackVector)}
    try:
        claimed = VectorStance(stance.lower())
    except ValueError:
        return {"error": f"unknown stance '{stance}'", "valid_stances": _valid_values(VectorStance)}

    chain = _build_chain(evidence_signals)
    evidence_summary: dict[str, Any] = {}
    caveat: str | None = None
    effective = claimed

    if evidence_signals:
        floor = _EVIDENCE_FLOOR[chain.confidence]
        evidence_summary = chain.summary()
        if stance_rank(claimed) > stance_rank(floor):
            effective = floor
            caveat = (
                f"stance capped '{claimed.value}' → '{floor.value}': evidence "
                f"(weight {chain.total_weight:.2f}, {chain.confidence.value}) does "
                f"not support the stronger claim"
            )
    elif claimed in _STRONG_STANCES:
        caveat = (
            f"'{claimed.value}' recorded as a hunch — no evidence_signals attached; "
            f"add signals to make the stance defensible"
        )

    note = Note(
        vector=vec,
        target=target,
        observation=observation,
        stance=effective,
        confidence=max(1, min(10, int(confidence))),
        tags=tags or [],
        refs=refs or [],
        evidence=evidence_summary,
        evidence_signals=evidence_signals or [],
        id=note_id,
    )
    store = get_notes_store()
    store.add(note)

    return {
        "status": "noted",
        "ephemeral": store.is_ephemeral,
        "note": note.model_dump(mode="json"),
        "evidence_backed_stance": effective.value,
        "caveat": caveat,
        "session_total": store.count(),
    }


async def note_query(
    mode: str = "list",
    vector: str = "",
    target: str = "",
    stance: str = "",
    keyword: str = "",
    min_confidence: int = 1,
    limit: int = 50,
    order: str = "attention",
) -> dict[str, Any]:
    """Read the per-session notes through an attack-vector lens.

    Modes:
        list      — flat filtered notes, newest first.
        by_vector — pivot: one summary per vector (count, strongest stance, targets).
        board     — progress board, with vector-specific next steps and an ROI
                    priority score per row. ``order`` = "attention" (default) or
                    "roi" (rank by expected value of advancing).
        coverage  — blind-spot view: touched vs untouched vectors.
        playbook  — the full stance-by-stance progression for one ``vector`` (no
                    notes needed): how to push it untested → confirmed.

    Filters (``vector``, ``target``, ``stance``, ``keyword``, ``min_confidence``)
    apply in ``list`` mode; ``target``/``min_confidence`` also scope the pivots.
    """
    store = get_notes_store()
    meta = {"ephemeral": store.is_ephemeral, "session_total": store.count(), "mode": mode}

    if mode == "board":
        rows = store.board(target=target or None)
        for r in rows:
            r["roi"] = _roi_for(r["vector"], r["stance"], r["max_confidence"])
        if order == "roi":
            rows.sort(key=lambda r: r["roi"]["priority_score"], reverse=True)
        return {**meta, "order": order, "board": rows}
    if mode == "by_vector":
        return {**meta, "by_vector": store.by_vector(target=target or None, min_confidence=min_confidence)}
    if mode == "coverage":
        return {**meta, "coverage": store.coverage(target=target or None)}
    if mode == "playbook":
        if not vector:
            return {"error": "playbook mode requires a 'vector'", "valid_vectors": _valid_values(AttackVector)}
        try:
            AttackVector(vector.lower())
        except ValueError:
            return {"error": f"unknown vector '{vector}'", "valid_vectors": _valid_values(AttackVector)}
        vec = vector.lower()
        ladder = {s.value: next_action_for(vec, s) for s in VectorStance}
        return {**meta, "vector": vec, "playbook": ladder}
    if mode != "list":
        return {"error": f"unknown mode '{mode}'", "valid_modes": ["list", "by_vector", "board", "coverage", "playbook"]}

    # Validate optional enum filters before querying.
    if vector:
        try:
            AttackVector(vector.lower())
        except ValueError:
            return {"error": f"unknown vector '{vector}'", "valid_vectors": _valid_values(AttackVector)}
    if stance:
        try:
            VectorStance(stance.lower())
        except ValueError:
            return {"error": f"unknown stance '{stance}'", "valid_stances": _valid_values(VectorStance)}

    notes = store.query(
        vector=vector.lower() or None,
        target=target or None,
        stance=stance.lower() or None,
        keyword=keyword or None,
        min_confidence=min_confidence,
        limit=limit,
    )
    return {**meta, "count": len(notes), "notes": notes}


async def note_promote(
    note_id: str,
    severity: str,
    title: str = "",
    impact: str = "",
    remediation: str = "",
    cvss: float | None = None,
    references: list[str] | None = None,
    allow_unconfirmed: bool = False,
) -> dict[str, Any]:
    """Graduate a confirmed note into a reportable Finding.

    Closes the loop observation → finding: rebuilds the note's evidence chain
    and hands it to ``report_finding`` (which persists to the gitignored
    findings workspace, never the repo). The Finding's confidence is derived
    honestly from the rebuilt chain — a note with no evidence can never become
    a CONFIRMED finding. The source note stays in the ephemeral session store.

    Args:
        note_id: stable id of the note to promote (set via note_add(note_id=...)).
        severity: critical | high | medium | low | info.
        title: finding title (default derived from vector + target).
        impact: business/technical impact statement.
        remediation: fix recommendation.
        cvss: CVSS 3.1 score.
        references: CWE/OWASP/URLs (default: the note's refs).
        allow_unconfirmed: promote a note that is not yet at the 'confirmed' stance.
    """
    try:
        Severity(severity.lower())
    except ValueError:
        return {"error": f"unknown severity '{severity}'", "valid_severities": _valid_values(Severity)}

    store = get_notes_store()
    note = store.get(note_id)
    if note is None:
        return {
            "error": f"no note with id '{note_id}'",
            "hint": "promotable notes need a stable id — record one via note_add(note_id=...)",
        }

    if note.stance != VectorStance.CONFIRMED and not allow_unconfirmed:
        return {
            "error": f"note stance is '{note.stance.value}', not 'confirmed'",
            "hint": "advance the note to confirmed (with evidence) or pass allow_unconfirmed=true",
        }

    # Honest confidence: rebuild the chain from the note's raw signals. No
    # signals → cannot claim better than tentative, regardless of stance.
    chain = _build_chain(note.evidence_signals)
    confidence = chain.confidence.value if note.evidence_signals else Confidence.TENTATIVE.value

    finding = await reporting.report_finding(
        title=title or f"{note.vector.value.upper()} — {note.target}",
        severity=severity.lower(),
        target=note.target,
        description=note.observation,
        confidence=confidence,
        impact=impact,
        remediation=remediation,
        cvss=cvss,
        references=references or note.refs,
        tools_used=["kambo-notes"],
        evidence_signals=note.evidence_signals,
    )

    return {
        "status": "promoted",
        "from_note": note_id,
        "vector": note.vector.value,
        "finding_confidence": confidence,
        "note_remains_ephemeral": store.is_ephemeral,
        "finding": finding,
    }
