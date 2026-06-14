"""Engagement notes — attack-vector-centric observation memory.

Where ``learnings.py`` distils *cross-session* insights keyed by tool/pattern,
this module captures *in-engagement* observations keyed by **attack vector**.

The whole point is a change of perspective: instead of a chronological journal
("what did I run, in what order"), notes are queried through the attacker's
mental model — "what do I know about IDOR on this target, and how far have I
pushed it?". The pivot/board/coverage queries turn a flat note stream into a
vector board that also surfaces *blind spots* (vectors never even considered).

Storage mirrors :class:`~kambo.learnings.LearningsStore`: an append-only JSONL
file, deduplicated at read time (latest entry per non-empty ``id`` wins). It is
sync and dependency-free so it is trivial to test and safe to call from any
context.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class AttackVector(str, Enum):
    """Canonical attack vectors — aligned with the validators in
    ``validation.py`` plus the bug-bounty reconnaissance categories.

    Used as the primary index for notes so the engagement can be reasoned
    about one vector at a time.
    """

    # Injection
    SQLI = "sqli"
    XSS = "xss"
    SSTI = "ssti"
    RCE = "rce"
    XXE = "xxe"
    DESERIALIZATION = "deserialization"
    PROTOTYPE_POLLUTION = "prototype_pollution"
    # Access / authorization
    IDOR = "idor"
    BOLA = "bola"
    ACCESS_CONTROL = "access_control"
    AUTH = "auth"
    JWT = "jwt"
    # Server-side request / file
    SSRF = "ssrf"
    LFI = "lfi"
    OPEN_REDIRECT = "open_redirect"
    # Logic / state
    BUSINESS_LOGIC = "business_logic"
    RACE = "race"
    CSRF = "csrf"
    # Config / exposure
    CORS = "cors"
    SUBDOMAIN_TAKEOVER = "subdomain_takeover"
    SECRETS = "secrets"
    INFO_DISCLOSURE = "info_disclosure"
    MISCONFIG = "misconfig"
    GRAPHQL = "graphql"
    # Non-vector observation
    RECON = "recon"
    OTHER = "other"


class VectorStance(str, Enum):
    """How far a vector has been pushed against a target — the engagement
    frontier per vector.

    UNTESTED:  noted as a candidate, not yet probed.
    SUSPECTED: signals suggest it but nothing is verified.
    PROBING:   actively testing right now.
    CONFIRMED: verified exploitable / vulnerable.
    RULED_OUT: tested and eliminated (a known negative, not a blind spot).
    """

    UNTESTED = "untested"
    SUSPECTED = "suspected"
    PROBING = "probing"
    CONFIRMED = "confirmed"
    RULED_OUT = "ruled_out"


# Progress ordering — higher rank = stronger outcome reached. RULED_OUT sits
# just above UNTESTED: it is a closed negative, more progress than "never
# looked" but not a promising frontier.
_STANCE_RANK: dict[VectorStance, int] = {
    VectorStance.UNTESTED: 0,
    VectorStance.RULED_OUT: 1,
    VectorStance.SUSPECTED: 2,
    VectorStance.PROBING: 3,
    VectorStance.CONFIRMED: 4,
}

# Stances worth working on next — promising and in-flight.
_ACTIVE_STANCES = {VectorStance.SUSPECTED, VectorStance.PROBING}

# What to do next, by stance — surfaced on the vector board.
_NEXT_ACTION: dict[VectorStance, str] = {
    VectorStance.UNTESTED: "probe this vector — no testing recorded yet",
    VectorStance.SUSPECTED: "gather corroborating signals to confirm or rule out",
    VectorStance.PROBING: "push to confirmation or rule out — don't leave it open",
    VectorStance.CONFIRMED: "document evidence and move toward a report",
    VectorStance.RULED_OUT: "closed — revisit only if new information appears",
}


class Note(BaseModel):
    """A single attack-vector-tagged observation."""

    vector: AttackVector
    target: str  # asset / endpoint the note is about
    observation: str  # the note text
    stance: VectorStance = VectorStance.UNTESTED
    confidence: int = 5  # 1-10, operator's gut feel this vector pays off here
    tags: list[str] = Field(default_factory=list)
    refs: list[str] = Field(default_factory=list)  # finding ids, URLs, ticket links
    source: str = "operator"  # operator, tool, inferred
    id: str = ""  # optional stable id; same id => update (latest wins at query)
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    model_config = {"frozen": True}


class NotesStore:
    """Vector-tagged engagement notes — **ephemeral (per-session) by default**.

    Constructed with ``path=None`` (the default) the store lives entirely in
    memory: nothing is written to disk, so real engagement data (target names,
    vulnerabilities, internal hosts) never persists across sessions and can
    never leak into the project tree. The process *is* the session — when the
    MCP server stops, the notes are gone.

    Persistence is an explicit opt-in: pass a ``path`` (which must live outside
    the repository) and the store mirrors :class:`~kambo.learnings.LearningsStore`
    as an append-only JSONL file. Tests use a ``tmp_path``; an operator can set
    ``KAMBO_NOTES_PATH`` if they knowingly want cross-session continuity.

    Reads deduplicate by ``id`` (latest wins) so a note can be progressed
    (e.g. UNTESTED → CONFIRMED) by re-adding it with the same id. Notes with
    an empty id are kept as independent journal entries.
    """

    def __init__(self, path: Path | None = None) -> None:
        self._path = path
        self._ephemeral = path is None
        self._notes: list[Note] = []
        self._loaded = False

    @property
    def is_ephemeral(self) -> bool:
        """True when notes live in memory only (no disk persistence)."""
        return self._ephemeral

    # -- persistence -------------------------------------------------------

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        if self._ephemeral or self._path is None or not self._path.exists():
            return
        for line in self._path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                self._notes.append(Note(**json.loads(line)))
            except Exception:
                continue  # skip corrupt entries

    def add(self, note: Note) -> None:
        """Append a note. O(1) write; dedup happens at read time.

        In ephemeral mode the note is kept in memory only — no file is touched.
        """
        self._ensure_loaded()
        self._notes.append(note)
        if self._ephemeral or self._path is None:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(note.model_dump(mode="json")) + "\n")

    def clear(self) -> None:
        """Drop all in-memory notes (session reset). Does not delete a backing
        file — persistence, when opted in, is append-only and kept intact."""
        self._notes = []
        self._loaded = True

    def _effective(self) -> list[Note]:
        """Deduplicated view: latest entry per non-empty id, plus all
        empty-id journal notes. Ordered oldest → newest."""
        self._ensure_loaded()
        by_id: dict[str, Note] = {}
        journal: list[Note] = []
        for n in self._notes:
            if n.id:
                by_id[n.id] = n  # latest wins
            else:
                journal.append(n)
        merged = [*by_id.values(), *journal]
        merged.sort(key=lambda n: n.timestamp)
        return merged

    # -- queries -----------------------------------------------------------

    def query(
        self,
        vector: AttackVector | str | None = None,
        target: str | None = None,
        stance: VectorStance | str | None = None,
        keyword: str | None = None,
        min_confidence: int = 1,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Flat filtered note list, newest first."""
        vec = AttackVector(vector) if isinstance(vector, str) else vector
        stc = VectorStance(stance) if isinstance(stance, str) else stance

        out: list[dict[str, Any]] = []
        for n in self._effective():
            if vec is not None and n.vector != vec:
                continue
            if target is not None and target.lower() not in n.target.lower():
                continue
            if stc is not None and n.stance != stc:
                continue
            if keyword and keyword.lower() not in n.observation.lower():
                continue
            if n.confidence < min_confidence:
                continue
            out.append(n.model_dump(mode="json"))
        out.sort(key=lambda d: d["timestamp"], reverse=True)
        return out[:limit]

    def by_vector(
        self, target: str | None = None, min_confidence: int = 1
    ) -> dict[str, dict[str, Any]]:
        """The perspective pivot: collapse the note stream into a
        ``vector -> summary`` map. Each summary reports how far the vector has
        been pushed, on which targets, and the latest observation."""
        groups: dict[AttackVector, list[Note]] = {}
        for n in self._effective():
            if target is not None and target.lower() not in n.target.lower():
                continue
            if n.confidence < min_confidence:
                continue
            groups.setdefault(n.vector, []).append(n)

        summary: dict[str, dict[str, Any]] = {}
        for vec, notes in groups.items():
            strongest = max(notes, key=lambda n: _STANCE_RANK[n.stance])
            latest = max(notes, key=lambda n: n.timestamp)
            summary[vec.value] = {
                "vector": vec.value,
                "count": len(notes),
                "stance": strongest.stance.value,
                "max_confidence": max(n.confidence for n in notes),
                "targets": sorted({n.target for n in notes}),
                "latest": latest.observation,
                "latest_at": latest.timestamp,
            }
        return summary

    def board(self, target: str | None = None) -> list[dict[str, Any]]:
        """Engagement progress board — one row per touched vector with a
        next-action hint, ordered by what deserves attention first
        (active & high-confidence vectors lead; closed ones trail)."""
        rows: list[dict[str, Any]] = []
        for s in self.by_vector(target=target).values():
            stance = VectorStance(s["stance"])
            rows.append({
                **s,
                "active": stance in _ACTIVE_STANCES,
                "next_action": _NEXT_ACTION[stance],
            })

        # Staged stable sorts (last key applied first wins ties): newest first,
        # then strongest stance, then highest confidence, then active vectors on
        # top. Stable sort means earlier criteria survive within ties.
        rows.sort(key=lambda r: r["latest_at"], reverse=True)
        rows.sort(key=lambda r: _STANCE_RANK[VectorStance(r["stance"])], reverse=True)
        rows.sort(key=lambda r: r["max_confidence"], reverse=True)
        rows.sort(key=lambda r: 0 if r["active"] else 1)
        return rows

    def coverage(self, target: str | None = None) -> dict[str, Any]:
        """Blind-spot view: which vectors have been touched vs the full
        taxonomy. The ``untouched`` list is what the defender hopes you never
        look at — vectors with zero notes."""
        touched = set(self.by_vector(target=target).keys())
        all_vectors = [v.value for v in AttackVector]
        untouched = [v for v in all_vectors if v not in touched]
        confirmed = sorted(
            v for v, s in self.by_vector(target=target).items()
            if s["stance"] == VectorStance.CONFIRMED.value
        )
        return {
            "total_vectors": len(all_vectors),
            "touched_count": len(touched),
            "touched": sorted(touched),
            "untouched": untouched,
            "confirmed": confirmed,
            "coverage_pct": round(100 * len(touched) / len(all_vectors)),
        }

    def count(self) -> int:
        self._ensure_loaded()
        return len(self._notes)

    def get_all(self) -> list[Note]:
        """Raw notes, no dedup (insertion order)."""
        self._ensure_loaded()
        return list(self._notes)


# Session-scoped singleton. Default is ephemeral (in-memory): engagement note
# data does not persist and cannot compromise the project. Persistence is
# opt-in via an explicit ``path`` or the ``KAMBO_NOTES_PATH`` env var (config).
_store: NotesStore | None = None


def get_notes_store(path: Path | None = None) -> NotesStore:
    global _store
    if _store is None:
        if path is None:
            # Honor an explicit opt-in only; otherwise stay ephemeral.
            try:
                from kambo.config import get_config

                path = get_config().notes_path
            except Exception:
                path = None
        _store = NotesStore(path)
    return _store
