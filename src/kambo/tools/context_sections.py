"""Section builders for :mod:`kambo.tools.context`.

Each function turns one already-fetched source (or its failure reason) into a
briefing section: scope-projected, budget-capped, and wrapped in an honest
envelope. Nothing here performs I/O — the caller fetches, these assemble — so
the scope projection and the truncation accounting stay testable in isolation.
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import ValidationError

from kambo.hunt_context import (
    _PIPELINE_BASE_SCORE,
    _PIPELINE_STEP_DECAY,
    ScopeFilterResult,
    combine,
    evidence_gap,
    filter_scope,
    infer_phase,
    list_section,
    map_section,
    source_failure,
    unavailable,
)
from kambo.models import Confidence, Context, EvidenceChain, Phase
from kambo.notes import AttackVector, VectorStance, next_action_for
from kambo.pipeline import get_pipeline
from kambo.resources.scope_resource import get_scope_data
from kambo.scope import PENTEST_ONLY_TOOLS

PAYOUTS_REASON = (
    "program payout/tier data is not fetched by hunt_context (offline by design) "
    "— call platform_fetch_program(platform, handle)"
)

# Engagement contexts in which the pentest-only capability family is unlocked.
_EXPLOITATION_CONTEXTS = {Context.PENTEST.value, Context.CTF.value}


def scope_block(limits: dict[str, int]) -> tuple[dict[str, Any], int]:
    """The engagement identity — authorised targets are the scope itself, so
    they are listed, not filtered."""
    try:
        data = get_scope_data()
    except Exception as exc:  # pragma: no cover - defensive
        return source_failure("scope resource", exc, as_map=True), 0

    targets = [str(t.get("target", "")) for t in data.get("targets", []) or []]
    kept = targets[: limits["scope_targets"]]
    payload = {
        "engagement_id": str(data.get("engagement_id", "")),
        "context": str(data.get("context", "")),
        "platform": str(data.get("platform", "")),
        "target_count": len(targets),
        "targets": kept,
        "exclusion_count": len(data.get("exclusions", []) or []),
    }
    return map_section(payload), len(targets) - len(kept)


def surface_block(
    state: dict[str, Any], error: str, limits: dict[str, int]
) -> tuple[dict[str, Any], int, ScopeFilterResult]:
    """Discovered surface, scope-projected and capped.

    Only locational fields are validated: ``technologies``, ``parameters`` and
    ``asset_counts`` are not hosts, and running them through the scope check
    would suppress ``nginx`` as out-of-scope and corrupt the counter.
    """
    if error:
        return unavailable(error, as_map=True), 0, ScopeFilterResult()

    summary = state["summary"]
    values = state["values"]
    limit = limits["surface"]
    omitted = 0
    filters: list[ScopeFilterResult] = []

    def take(items: list[str]) -> list[str]:
        nonlocal omitted
        omitted += max(0, len(items) - limit)
        return items[:limit]

    projected: dict[str, list[str]] = {}
    for key in ("subdomains", "urls", "endpoints", "open_ports"):
        result = filter_scope(values[key])
        filters.append(result)
        projected[key] = take(result.kept)

    data = {
        "inferred_phase": infer_phase(summary),
        "inferred": True,
        "total_assets": int(summary.get("total_assets", 0) or 0),
        "tools_run_count": int(summary.get("tools_run_count", 0) or 0),
        "asset_counts": dict(summary.get("asset_counts", {}) or {}),
        "subdomains": projected["subdomains"],
        "urls": projected["urls"],
        "endpoints": projected["endpoints"],
        "open_ports": projected["open_ports"],
        "parameters": take(list(values["parameters"])),
        "technologies": take(list(values["technologies"])),
    }
    return map_section(data), omitted, combine(*filters)


def board_item(row: dict[str, Any], limits: dict[str, int]) -> dict[str, Any]:
    """One board row. ``targets`` is capped by the budget, so ``target_count``
    carries the real number — a truncated target list is self-describing rather
    than silently short (``count`` is the note count, not the target count)."""
    roi = row.get("roi") or {}
    targets = list(row.get("targets", []) or [])
    return {
        "vector": str(row.get("vector", "")),
        "stance": str(row.get("stance", "")),
        "max_confidence": int(row.get("max_confidence", 0) or 0),
        "count": int(row.get("count", 0) or 0),
        "targets": targets[: limits["surface"]],
        "target_count": len(targets),
        "next_action": str(row.get("next_action", "")),
        "priority_score": int(roi.get("priority_score", 0) or 0),
        "active": bool(row.get("active", False)),
    }


def project_board(
    rows: list[dict[str, Any]], error: str, limits: dict[str, int], *, active_only: bool = False
) -> tuple[dict[str, Any], int, ScopeFilterResult, list[dict[str, Any]]]:
    """Scope-project the board: a row whose targets are all out of scope is
    removed entirely (and counted), not blanked."""
    if error:
        return unavailable(error), 0, ScopeFilterResult(), []

    filters: list[ScopeFilterResult] = []
    kept_rows: list[dict[str, Any]] = []
    for row in rows:
        targets = list(row.get("targets", []) or [])
        result = filter_scope(targets)
        filters.append(result)
        if targets and not result.kept:
            continue
        kept_rows.append({**row, "targets": result.kept})

    visible = [r for r in kept_rows if r.get("active")] if active_only else kept_rows
    items = [board_item(row, limits) for row in visible]
    section, omitted = list_section(items, limits["board"])
    return section, omitted, combine(*filters), kept_rows


def coverage_block(
    rows: list[dict[str, Any]], error: str, limits: dict[str, int]
) -> tuple[dict[str, Any], int]:
    """Blind-spot view recomputed over scope-clean rows — a vector only touched
    outside the scope was never touched *here*."""
    if error:
        return unavailable(error, as_map=True), 0

    all_vectors = [v.value for v in AttackVector]
    touched = {str(row.get("vector", "")) for row in rows}
    confirmed = sorted(
        str(row.get("vector", ""))
        for row in rows
        if str(row.get("stance", "")) == VectorStance.CONFIRMED.value
    )
    untouched = [v for v in all_vectors if v not in touched]
    touched_sorted = sorted(touched)

    kept_touched = touched_sorted[: limits["board"]]
    kept_untouched = untouched[: limits["untouched"]]
    kept_confirmed = confirmed[: limits["board"]]
    omitted = (
        (len(touched_sorted) - len(kept_touched))
        + (len(untouched) - len(kept_untouched))
        + (len(confirmed) - len(kept_confirmed))  # proven vectors are never cut in silence
    )

    data = {
        "total_vectors": len(all_vectors),
        "touched_count": len(touched),
        "coverage_pct": round(100 * len(touched) / len(all_vectors)) if all_vectors else 0,
        "touched": kept_touched,
        "untouched": kept_untouched,
        "confirmed": kept_confirmed,
        "confirmed_count": len(confirmed),
    }
    return map_section(data), omitted


def findings_block(
    rows: list[dict[str, Any]], error: str, limits: dict[str, int]
) -> tuple[dict[str, Any], int, ScopeFilterResult]:
    """Findings headline only — description, evidence and raw output stay in
    the database where they belong.

    ``severity_counts``, ``confidence_counts`` and ``report_ready`` are attached
    on both paths: a consumer must not hit a ``KeyError`` exactly when the db is
    the thing that broke.
    """
    if error:
        section = unavailable(error)
        section.update({"severity_counts": {}, "confidence_counts": {}, "report_ready": False})
        return section, 0, ScopeFilterResult()

    filters: list[ScopeFilterResult] = []
    kept: list[dict[str, Any]] = []
    for row in rows:
        result = filter_scope([str(row.get("target", ""))])
        filters.append(result)
        if not result.kept:
            continue
        kept.append(row)

    severity_counts: dict[str, int] = {}
    confidence_counts: dict[str, int] = {}
    items: list[dict[str, Any]] = []
    for row in kept:
        severity = str(row.get("severity", "info"))
        confidence = str(row.get("confidence", "tentative"))
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        confidence_counts[confidence] = confidence_counts.get(confidence, 0) + 1
        items.append({
            "id": str(row.get("id", "")),
            "title": str(row.get("title", "")),
            "severity": severity,
            "confidence": confidence,
            "target": str(row.get("target", "")),
            "phase": str(row.get("phase", "")),
        })

    section, omitted = list_section(items, limits["findings"])
    solid = confidence_counts.get("confirmed", 0) + confidence_counts.get("firm", 0)
    section["severity_counts"] = severity_counts
    section["confidence_counts"] = confidence_counts
    section["report_ready"] = bool(kept) and solid >= 1 and solid / len(kept) >= 0.5
    return section, omitted, combine(*filters)


def next_moves(
    rows: list[dict[str, Any]],
    notes_error: str,
    state: dict[str, Any],
    pipeline_error: str,
    limits: dict[str, int],
) -> tuple[dict[str, Any], int, ScopeFilterResult]:
    """Two ranked sources in one list: notes ROI (what is worth advancing) and
    the pipeline's phase graph (what has not been run yet). Each item declares
    which basis produced its score — the two are not the same currency.

    Health is reported per source. Half a ranking is not a healthy ranking: when
    one source fails the section still renders what the other produced, but
    ``degraded`` is true and ``sources`` names which half is missing — an empty
    list from a broken source is never dressed up as "nothing left to do".
    """
    sources = {
        "notes": {"available": not notes_error, "reason": notes_error},
        "pipeline": {"available": not pipeline_error, "reason": pipeline_error},
    }
    degraded = bool(notes_error or pipeline_error)
    if notes_error and pipeline_error:
        section = unavailable(f"{notes_error}; {pipeline_error}")
        section.update({"sources": sources, "degraded": True})
        return section, 0, ScopeFilterResult()

    limit = limits["next_moves"]
    filters: list[ScopeFilterResult] = []
    items: list[dict[str, Any]] = []

    for row in rows:
        roi = row.get("roi") or {}
        row_targets = list(row.get("targets", []) or [])
        result = filter_scope(row_targets)
        filters.append(result)
        if row_targets and not result.kept:
            continue  # the whole thread lives outside the scope — not a move
        items.append({
            "source": "notes",
            "action": str(row.get("next_action", "")),
            "vector": str(row.get("vector", "")),
            "targets": result.kept[:limit],
            "target_count": len(result.kept),
            "priority_score": int(roi.get("priority_score", 0) or 0),
            "score_basis": "roi",
            "why": (
                f"{row.get('stance', '')} at confidence "
                f"{row.get('max_confidence', 0)}/10 across "
                f"{row.get('count', 0)} note(s)"
            ),
        })

    if not pipeline_error:
        try:
            steps = get_pipeline().suggest_next_steps(
                Phase(infer_phase(state["summary"])), max_steps=limit
            )
        except Exception:  # pragma: no cover - defensive
            steps = []
        for step in steps:
            result = filter_scope(step.targets)
            filters.append(result)
            items.append({
                "source": "pipeline",
                "action": str(step.tool),
                "vector": "",
                "targets": result.kept[:limit],
                "target_count": len(result.kept),
                "priority_score": max(
                    0, _PIPELINE_BASE_SCORE - step.priority * _PIPELINE_STEP_DECAY
                ),
                "score_basis": "pipeline_order",
                "why": str(step.reason),
            })

    items.sort(key=lambda item: item["priority_score"], reverse=True)
    section, omitted = list_section(items, limit)
    section.update({"sources": sources, "degraded": degraded})
    return section, omitted, combine(*filters)


def findings_gap_block(
    rows: list[dict[str, Any]], error: str, limits: dict[str, int]
) -> tuple[dict[str, Any], int, ScopeFilterResult]:
    """Per unconfirmed finding: which signal is missing to raise confidence."""
    if error:
        return unavailable(error), 0, ScopeFilterResult()

    filters: list[ScopeFilterResult] = []
    items: list[dict[str, Any]] = []
    for row in rows:
        if str(row.get("confidence", "")) == "confirmed":
            continue
        result = filter_scope([str(row.get("target", ""))])
        filters.append(result)
        if not result.kept:
            continue
        summary = chain_summary(row.get("evidence_chain"))
        items.append({
            "id": str(row.get("id", "")),
            "title": str(row.get("title", "")),
            "severity": str(row.get("severity", "info")),
            "target": str(row.get("target", "")),
            "confidence": str(row.get("confidence", "tentative")),
            "confidence_pct": int(summary.get("confidence_pct", 0) or 0),
            "total_weight": float(summary.get("total_weight", 0.0) or 0.0),
            "signal_count": int(summary.get("signal_count", 0) or 0),
            "chain_unreadable": summary.get("parsed", True) is False,
            "chain_parse_error": str(summary.get("parse_error", "")),
            "gap": evidence_gap(summary),
        })

    section, omitted = list_section(items, limits["evidence"])
    return section, omitted, combine(*filters)


def _unreadable_chain(error: str) -> dict[str, Any]:
    """Summary for a chain that could not be rebuilt.

    A default ``EvidenceChain`` would claim ``ceiling: confirmed`` and no gates —
    it would turn a gated finding into an ungated one and invite the operator to
    pile on weight. An unknown ceiling fails closed at the lowest tier instead,
    and ``parsed: False`` says why.
    """
    return {
        **EvidenceChain(ceiling=Confidence.TENTATIVE).summary(),
        "parsed": False,
        "parse_error": error,
    }


def chain_summary(raw: Any) -> dict[str, Any]:
    """Evidence chains arrive from sqlite as a JSON *string*; rebuild the model
    so the gap is computed from the real weights, never guessed.

    "No chain recorded" (``None``, ``""``, ``"{}"``) is a healthy empty chain.
    "Chain unreadable" (corrupt JSON, a non-object payload, a drifted enum) is a
    different state and is reported as such — the two were byte-identical before.
    """
    if raw is None or raw == "":
        return {**EvidenceChain().summary(), "parsed": True}
    data: Any = raw
    if isinstance(raw, str):
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, ValueError) as exc:
            return _unreadable_chain(type(exc).__name__)
    if not isinstance(data, dict):
        return _unreadable_chain("TypeError")
    try:
        chain = EvidenceChain(**data)
    except (ValidationError, TypeError, ValueError) as exc:
        return _unreadable_chain(type(exc).__name__)
    return {**chain.summary(), "parsed": True}


def missing_signal(vector: str, stance: str) -> str:
    try:
        return next_action_for(vector, VectorStance(stance))
    except ValueError:  # pragma: no cover - defensive
        return "probe this vector — stance not recognised"


def scope_mode_sections(limits: dict[str, int]) -> tuple[dict[str, Any], dict[str, int]]:
    """The boundary itself: what is in, what is carved out, what is locked.

    The exclusion patterns are the only out-of-scope strings the payload may
    carry — they are operator *rules*, not discovered targets.
    """
    try:
        data = get_scope_data()
    except Exception as exc:  # pragma: no cover - defensive
        failed = source_failure("scope resource", exc)
        return {
            "in_scope": failed,
            "out_of_scope": failed,
            "rules": failed,
            "restrictions": source_failure("scope resource", exc, as_map=True),
            "payouts": unavailable(PAYOUTS_REASON, as_map=True),
        }, {}

    targets = data.get("targets", []) or []
    in_scope_items = [{
        "target": str(t.get("target", "")),
        "target_type": str(t.get("target_type", "domain")),
        "exclusions": list(t.get("exclusions", []) or []),
        "notes": str(t.get("notes", "")),
    } for t in targets]

    out_items = [{"pattern": str(p), "origin": "global"} for p in data.get("exclusions", []) or []]
    for t in targets:
        origin = f"target:{t.get('target', '')}"
        out_items.extend(
            {"pattern": str(p), "origin": origin} for p in t.get("exclusions", []) or []
        )

    context = str(data.get("context", ""))
    locked = context not in _EXPLOITATION_CONTEXTS
    locked_tools = sorted(PENTEST_ONLY_TOOLS) if locked else []
    shown_tools = locked_tools[: limits["surface"]]

    in_scope, in_omitted = list_section(in_scope_items, limits["scope_targets"])
    out_of_scope, out_omitted = list_section(out_items, limits["scope_targets"])
    rules, rules_omitted = list_section(list(data.get("rules", []) or []), limits["board"])

    restrictions = map_section({
        "context": context,
        "pentest_tools_locked": locked,
        "locked_tool_count": len(locked_tools),
        "locked_tools": shown_tools,
    })

    sections = {
        "in_scope": in_scope,
        "out_of_scope": out_of_scope,
        "rules": rules,
        "restrictions": restrictions,
        "payouts": unavailable(PAYOUTS_REASON, as_map=True),
    }
    truncated = {
        "in_scope": in_omitted,
        "out_of_scope": out_omitted,
        "rules": rules_omitted,
        "restrictions": len(locked_tools) - len(shown_tools),
    }
    return sections, truncated


def where_i_stopped(
    state: dict[str, Any],
    error: str,
    meta: dict[str, Any],
    limits: dict[str, int],
    notes_error: str = "",
) -> dict[str, Any]:
    """Session resume header. The pipeline drives the section envelope; the
    notes store contributes two fields only, so its failure is declared inline
    (``notes_available`` / ``notes_reason``) instead of being laundered into
    ``session_notes: 0`` — "no notes taken" and "notes unreachable" are not the
    same statement."""
    if error:
        return unavailable(error, as_map=True)
    summary = state["summary"]
    tools_run = list(summary.get("tools_run", []) or [])
    return map_section({
        "inferred_phase": infer_phase(summary),
        "inferred": True,
        "tools_run_count": int(summary.get("tools_run_count", 0) or 0),
        "last_tools": tools_run[-min(5, limits["next_moves"]):],
        "total_assets": int(summary.get("total_assets", 0) or 0),
        "findings_count": int(summary.get("findings_count", 0) or 0),
        "notes_available": not notes_error,
        "notes_reason": notes_error,
        "session_notes": int(meta.get("session_total", 0) or 0),
        "notes_ephemeral": bool(meta.get("ephemeral", True)),
    })
