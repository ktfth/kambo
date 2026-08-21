"""hunt_context — single-call, scope-clean, token-budgeted engagement briefing.

Replaces the usual chain of ``scope`` + ``pipeline_status`` +
``note_query(board/coverage)`` + ``report_metrics`` + findings with one call
that answers a specific question (``mode``) inside a token ceiling
(``budget``).

Three rules govern this surface:

* **Nothing leaves that the scope cannot justify.** Every host/URL derived from
  session state is validated before it is emitted; suppressed values are counted
  by reason code, never echoed. Without a scope the tool refuses to emit surface
  at all and returns a degraded briefing pointing at ``set_scope``.
* **Every source degrades on its own.** One broken source turns its own section
  into ``available: false`` with a stated reason; the rest of the briefing still
  renders. An empty-but-healthy source stays ``available: true`` with
  ``count: 0`` — silence is never dressed up as data.
* **Offline by construction.** No program/payout fetching happens here; that
  section is declared unavailable rather than silently omitted.
"""

from __future__ import annotations

from typing import Any

from kambo.hunt_context import (
    BUDGETS,
    MODES,
    ScopeFilterResult,
    budget_limits,
    combine,
    filter_scope,
    finalize,
    list_section,
    map_section,
    merge_suppression,
    source_failure,
    unavailable,
)
from kambo.notes import VectorStance
from kambo.pipeline import AssetType, get_pipeline
from kambo.resources.findings_resource import get_findings_data
from kambo.scope import get_scope_manager
from kambo.tools import notes, reporting
from kambo.tools.context_sections import (
    coverage_block,
    findings_block,
    findings_gap_block,
    missing_signal,
    next_moves,
    project_board,
    scope_block,
    scope_mode_sections,
    surface_block,
    where_i_stopped,
)

_NO_SCOPE_INSTRUCTION = (
    "No engagement scope configured. Call set_scope(engagement_id, context, "
    "targets[, platform, exclusions]) before requesting context — hunt_context "
    "refuses to emit surface it cannot scope-check."
)

_EMPTY_SCOPE_INSTRUCTION = (
    "The engagement scope authorises no targets (targets=[]). Every asset would "
    "be suppressed, so an empty briefing would read as 'nothing discovered' when "
    "the truth is 'nothing is authorised'. Call set_scope again with the "
    "programme's in-scope targets."
)

# Stances still in play — a vector at one of these has an evidence gap worth
# naming; confirmed and ruled_out are settled.
_UNSETTLED_STANCES = {
    VectorStance.UNTESTED.value,
    VectorStance.SUSPECTED.value,
    VectorStance.PROBING.value,
}

_FALLBACK_HINT = "recon_subdomains"

# First page size when reading the notes store; a larger session is re-read in
# full rather than sampled (see ``_notes_gap_block``).
_NOTES_PROBE = 50


# ── argument validation ──────────────────────────────────────────────────────


def _validate_args(mode: str, budget: str) -> dict[str, Any] | None:
    """Error dict for bad input, or ``None`` when the arguments are usable.
    Invalid input is answered, never raised."""
    if mode not in MODES:
        return {"error": f"unknown mode '{mode}'", "valid_modes": list(MODES)}
    if budget not in BUDGETS:
        return {"error": f"unknown budget '{budget}'", "valid_budgets": list(BUDGETS)}
    return None


# ── sources ──────────────────────────────────────────────────────────────────


def _pipeline_state() -> tuple[dict[str, Any], str]:
    """Untruncated pipeline surface plus its aggregate summary, or a reason.

    ``summary()`` caps every list at 20, which would silently defeat the deep
    budget — the lists are read from ``get_values()`` instead and the summary is
    used only for counts.
    """
    try:
        pipeline = get_pipeline()
        summary = pipeline.summary()
        values = {
            "subdomains": pipeline.get_values(AssetType.SUBDOMAIN),
            "urls": pipeline.get_values(AssetType.URL),
            "endpoints": pipeline.get_values(AssetType.ENDPOINT),
            "open_ports": pipeline.get_values(AssetType.PORT),
            "parameters": pipeline.get_values(AssetType.PARAMETER),
            "technologies": pipeline.get_values(AssetType.TECHNOLOGY),
        }
    except Exception as exc:  # pragma: no cover - defensive
        return {}, f"pipeline unavailable: {type(exc).__name__}: {exc}"
    return {"summary": summary, "values": values}, ""


async def _fetch_board(target: str) -> tuple[list[dict[str, Any]], dict[str, Any], str]:
    """ROI-ranked notes board rows plus session meta, or a failure reason."""
    try:
        res = await notes.note_query(mode="board", order="roi", target=target)
    except Exception as exc:
        return [], {}, f"notes store unavailable: {type(exc).__name__}: {exc}"
    if "error" in res:
        return [], {}, f"notes store unavailable: {res['error']}"
    meta = {
        "ephemeral": bool(res.get("ephemeral", True)),
        "session_total": int(res.get("session_total", 0) or 0),
    }
    return list(res.get("board", []) or []), meta, ""


async def _fetch_findings() -> tuple[list[dict[str, Any]], str]:
    """Raw findings rows from the workspace db, or a failure reason."""
    try:
        data = await get_findings_data()
    except Exception as exc:
        return [], f"findings db unavailable: {type(exc).__name__}: {exc}"
    return list(data.get("findings", []) or []), ""


# ── async section builders (sources that must be awaited) ────────────────────


async def _metrics_block(limits: dict[str, int]) -> tuple[dict[str, Any], int]:
    """Session quality metrics, projected — ``per_tool`` is dropped: it is the
    largest token sink in the aggregate and is not actionable in a briefing.

    An empty tracker is *healthy-empty*, not a failure: it reports
    ``total_tools_used: 0`` under ``available: true`` like every other empty
    section, and ``available: false`` is reserved for a source that raised.

    ``warnings`` is one entry per high-FP tool and grows with the registry, so
    it is capped like every other list; ``warning_count`` keeps the true total
    and the drop is reported in ``truncated["metrics"]``.
    """
    try:
        aggregate = await reporting.report_metrics()
    except Exception as exc:
        return source_failure("metrics db", exc, as_map=True), 0

    warnings = dict(aggregate.get("warnings", {}) or {})
    limit = max(0, limits["board"])
    shown = dict(sorted(warnings.items())[:limit])

    return map_section({
        "total_tools_used": int(aggregate.get("total_tools_used", 0) or 0),
        "total_findings": int(aggregate.get("total_findings", 0) or 0),
        "confidence_distribution": dict(aggregate.get("confidence_distribution", {}) or {}),
        "quality_metrics": dict(aggregate.get("quality_metrics", {}) or {}),
        "warnings": shown,
        "warning_count": len(warnings),
        "recommendation": str(aggregate.get("recommendation", "")),
    }), len(warnings) - len(shown)


async def _notes_gap_block(
    vector: str, limits: dict[str, int]
) -> tuple[dict[str, Any], int, ScopeFilterResult]:
    """Per unsettled note: the next experiment that would move its stance.

    The whole session is read before the unsettled filter runs. Capping the
    fetch first sampled the newest notes only, so a board whose recent rows are
    all settled reported ``count: 0`` while high-confidence suspected vectors sat
    in the store — a silent zero the truncation report could not even see.
    """
    try:
        res = await notes.note_query(mode="list", limit=max(_NOTES_PROBE, limits["evidence"] * 4))
        session_total = int(res.get("session_total", 0) or 0)
        if session_total > len(res.get("notes", []) or []):
            res = await notes.note_query(mode="list", limit=session_total)
    except Exception as exc:
        return source_failure("notes store", exc), 0, ScopeFilterResult()
    if "error" in res:
        return unavailable(f"notes store unavailable: {res['error']}"), 0, ScopeFilterResult()

    wanted = vector.strip().lower()
    filters: list[ScopeFilterResult] = []
    items: list[dict[str, Any]] = []
    for note in res.get("notes", []) or []:
        stance = str(note.get("stance", ""))
        note_vector = str(note.get("vector", ""))
        if stance not in _UNSETTLED_STANCES:
            continue
        if wanted and note_vector != wanted:
            continue
        result = filter_scope([str(note.get("target", ""))])
        filters.append(result)
        if not result.kept:
            continue
        items.append({
            "note_id": str(note.get("id", "")),
            "vector": note_vector,
            "target": str(note.get("target", "")),
            "stance": stance,
            "confidence": int(note.get("confidence", 0) or 0),
            "missing_signal": missing_signal(note_vector, stance),
            "evidence_signal_count": len(note.get("evidence_signals", []) or []),
        })

    section, omitted = list_section(items, limits["evidence"])
    return section, omitted, combine(*filters)


# ── public surface ───────────────────────────────────────────────────────────


def _degraded(
    mode: str,
    budget: str,
    *,
    status: str = "degraded_no_scope",
    instruction: str = "",
) -> dict[str, Any]:
    """No usable scope, no surface: nothing is read — not the db, not the
    pipeline.  ``status`` names *why* the scope is unusable so the operator can
    tell an unset scope from one that authorises nothing."""
    return finalize({
        "status": status,
        "mode": mode,
        "budget": budget,
        "scope_set": False,
        "out_of_scope_suppressed": {"count": 0, "reasons": {}},
        "sections": {},
        "instruction": instruction or _NO_SCOPE_INSTRUCTION,
        "next_call_hint": "set_scope",
    }, {})


def _first_action(section: dict[str, Any]) -> str:
    items = section.get("items") or []
    return str(items[0].get("action", "")) if items else ""


def _resume_hint(notes_error: str, meta: dict[str, Any]) -> str:
    """Fallback hint when no move was ranked. A broken notes store must never
    produce ``note_add`` — that would send the operator straight back into the
    source that just failed."""
    if notes_error:
        return _FALLBACK_HINT
    return "note_add" if not meta.get("session_total") else _FALLBACK_HINT


async def hunt_context(
    mode: str = "brief",
    budget: str = "normal",
    target: str = "",
    vector: str = "",
) -> dict[str, Any]:
    """Assemble the engagement briefing for ``mode`` within ``budget``.

    Args:
        mode: brief (aggregate state) | resume (where I stopped / what next) |
            scope (the boundary) | evidence (what signal is missing).
        budget: tight | normal | deep — caps items per section.
        target: optional substring filter scoping notes to one asset.
        vector: optional attack-vector filter (evidence mode).
    """
    invalid = _validate_args(mode, budget)
    if invalid is not None:
        return invalid

    active_scope = get_scope_manager().scope
    if active_scope is None:
        return _degraded(mode, budget)
    if not active_scope.targets:
        # A scope that authorises nothing suppresses everything; saying so beats
        # emitting an empty briefing that reads as a clean recon result.
        return _degraded(
            mode, budget,
            status="degraded_empty_scope",
            instruction=_EMPTY_SCOPE_INSTRUCTION,
        )

    limits = budget_limits(budget)
    sections: dict[str, dict[str, Any]] = {}
    truncated: dict[str, int] = {}
    suppression: list[ScopeFilterResult] = []
    hint = _FALLBACK_HINT

    if mode == "scope":
        sections, truncated = scope_mode_sections(limits)
        hint = "platform_fetch_program"

    elif mode == "evidence":
        rows, findings_error = await _fetch_findings()
        findings_gap, gap_omitted, gap_filter = findings_gap_block(rows, findings_error, limits)
        notes_gap, notes_omitted, notes_filter = await _notes_gap_block(vector, limits)
        sections = {"findings_gap": findings_gap, "notes_gap": notes_gap}
        truncated = {"findings_gap": gap_omitted, "notes_gap": notes_omitted}
        suppression = [gap_filter, notes_filter]
        hint = "note_add" if notes_gap.get("available") else _FALLBACK_HINT

    else:
        board_rows, meta, notes_error = await _fetch_board(target)
        state, pipeline_error = _pipeline_state()
        moves, moves_omitted, moves_filter = next_moves(
            board_rows, notes_error, state, pipeline_error, limits
        )

        if mode == "resume":
            threads, threads_omitted, board_filter, _ = project_board(
                board_rows, notes_error, limits, active_only=True
            )
            sections = {
                "where_i_stopped": where_i_stopped(
                    state, pipeline_error, meta, limits, notes_error
                ),
                "open_threads": threads,
                "next_moves": moves,
            }
            truncated = {"open_threads": threads_omitted, "next_moves": moves_omitted}
            suppression = [board_filter, moves_filter]
            hint = _first_action(moves) or _resume_hint(notes_error, meta)
        else:
            scope_summary, scope_omitted = scope_block(limits)
            surface, surface_omitted, surface_filter = surface_block(
                state, pipeline_error, limits
            )
            board, board_omitted, board_filter, kept_rows = project_board(
                board_rows, notes_error, limits
            )
            coverage, coverage_omitted = coverage_block(kept_rows, notes_error, limits)
            rows, findings_error = await _fetch_findings()
            findings, findings_omitted, findings_filter = findings_block(
                rows, findings_error, limits
            )
            metrics, metrics_omitted = await _metrics_block(limits)
            sections = {
                "scope_summary": scope_summary,
                "surface": surface,
                "coverage": coverage,
                "board": board,
                "findings": findings,
                "metrics": metrics,
                "next_moves": moves,
            }
            truncated = {
                "scope_summary": scope_omitted,
                "surface": surface_omitted,
                "coverage": coverage_omitted,
                "board": board_omitted,
                "findings": findings_omitted,
                "metrics": metrics_omitted,
                "next_moves": moves_omitted,
            }
            suppression = [surface_filter, board_filter, findings_filter, moves_filter]
            hint = _first_action(moves) or _FALLBACK_HINT

    payload = {
        "status": "ok",
        "mode": mode,
        "budget": budget,
        "scope_set": True,
        "out_of_scope_suppressed": merge_suppression(*suppression),
        "sections": sections,
        "next_call_hint": hint or _FALLBACK_HINT,
    }
    return finalize(payload, truncated)
