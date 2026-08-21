"""Tests for the hunt_context MCP tool — modes, shape, scope projection.

Reserved domains only. The findings database is an AsyncMock throughout: the
briefing must never touch the real workspace db during tests.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

import kambo.metrics as metrics_module
import kambo.notes as notes_module
from kambo.hunt_context import _BUDGET_LIMITS
from kambo.notes import AttackVector, Note, VectorStance, get_notes_store
from kambo.models import Context, EngagementScope, ScopeTarget
from kambo.pipeline import get_pipeline, reset_pipeline
from kambo.scope import PENTEST_ONLY_TOOLS, get_scope_manager
from kambo.tools.context import hunt_context
from kambo.tools.notes import note_add

MODES = ("brief", "resume", "scope", "evidence")


@pytest.fixture(autouse=True)
def _fresh_session():
    """Clean per-session singletons and a disk-free findings db on both sides."""
    notes_module._store = None
    metrics_module._tracker = None
    reset_pipeline()
    mock_db = AsyncMock()
    mock_db.get_findings.return_value = []
    with patch("kambo.resources.findings_resource.get_database", return_value=mock_db):
        yield mock_db
    notes_module._store = None
    metrics_module._tracker = None
    reset_pipeline()


def _finding_row(**overrides: Any) -> dict[str, Any]:
    """A findings row shaped like the sqlite layer returns it — JSON columns
    arrive as strings, not structures."""
    row = {
        "id": "FIND-001",
        "title": "Reflected marker in search parameter",
        "severity": "medium",
        "confidence": "firm",
        "phase": "vulnerability_analysis",
        "target": "https://app.example.com/search",
        "description": "long description that must never reach the briefing",
        "evidence": "{}",
        "evidence_chain": json.dumps({
            "items": [{"signal": "marker reflected", "source": "vuln_xss",
                       "raw_data": "x" * 500, "weight": 1.5}],
            "baseline": {},
            "false_positive_checks": [],
            "ceiling": "firm",
            "gates": ["no out-of-band callback observed"],
            "flags": [],
        }),
        "references_json": "[]",
        "tools_used": "[]",
        "timestamp": "2026-06-14T10:00:00+00:00",
    }
    row.update(overrides)
    return row


def _ingest_subdomains(values: list[str]) -> None:
    get_pipeline().ingest("recon_subdomains", {"target": "example.com", "subdomains": values})


def _walk(node: Any):
    """Yield every value in a nested payload."""
    yield node
    if isinstance(node, dict):
        for value in node.values():
            yield from _walk(value)
    elif isinstance(node, list):
        for value in node:
            yield from _walk(value)


class TestDegradedNoScope:
    async def test_no_scope_returns_degraded_and_no_surface(self) -> None:
        _ingest_subdomains(["secret.example.com"])
        get_scope_manager().clear_scope()
        res = await hunt_context()
        assert res["status"] == "degraded_no_scope"
        assert res["scope_set"] is False
        assert res["sections"] == {}
        assert "instruction" in res
        assert res["next_call_hint"] == "set_scope"
        assert "secret.example.com" not in json.dumps(res)

    async def test_no_scope_degraded_for_every_mode(self) -> None:
        get_scope_manager().clear_scope()
        for mode in MODES:
            res = await hunt_context(mode=mode)
            assert res["status"] == "degraded_no_scope", mode
            assert res["sections"] == {}, mode
            assert res["mode"] == mode


class TestDegradedEmptyScope:
    """A scope with no authorised targets authorises nothing. Emitting an empty
    surface under ``scope_set: true`` would read as "recon found nothing" when
    the truth is "the scope is broken" — the silent zero this tool exists to
    prevent, in its scope dimension."""

    @staticmethod
    def _set_empty_scope() -> None:
        get_scope_manager().set_scope(EngagementScope(
            engagement_id="empty-scope",
            context=Context.BUG_BOUNTY,
            targets=[],
        ))

    async def test_empty_scope_is_degraded_not_silently_empty(self) -> None:
        _ingest_subdomains(["api.example.com", "www.example.com"])
        self._set_empty_scope()
        res = await hunt_context()
        assert res["status"] == "degraded_empty_scope"
        assert res["scope_set"] is False
        assert res["sections"] == {}
        assert res["next_call_hint"] == "set_scope"
        assert "authoris" in res["instruction"].lower() or "authoriz" in res["instruction"].lower()

    async def test_empty_scope_leaks_no_surface_in_any_mode(self) -> None:
        _ingest_subdomains(["secret.example.com"])
        self._set_empty_scope()
        for mode in MODES:
            res = await hunt_context(mode=mode)
            assert res["status"] == "degraded_empty_scope", mode
            assert res["sections"] == {}, mode
            assert "secret.example.com" not in json.dumps(res), mode

    async def test_populated_scope_is_not_degraded(self) -> None:
        get_scope_manager().set_scope(EngagementScope(
            engagement_id="real", context=Context.BUG_BOUNTY,
            targets=[ScopeTarget(target="*.example.com")],
        ))
        res = await hunt_context()
        assert res["status"] == "ok"
        assert res["scope_set"] is True


class TestSectionKeys:
    async def test_brief_has_stable_section_keys(self) -> None:
        res = await hunt_context(mode="brief")
        assert set(res["sections"]) == {
            "scope_summary", "surface", "coverage", "board", "findings",
            "metrics", "next_moves",
        }

    async def test_resume_has_stable_section_keys(self) -> None:
        res = await hunt_context(mode="resume")
        assert set(res["sections"]) == {"where_i_stopped", "open_threads", "next_moves"}

    async def test_scope_mode_has_stable_section_keys(self) -> None:
        res = await hunt_context(mode="scope")
        assert set(res["sections"]) == {
            "in_scope", "out_of_scope", "rules", "restrictions", "payouts",
        }

    async def test_evidence_mode_has_stable_section_keys(self) -> None:
        res = await hunt_context(mode="evidence")
        assert set(res["sections"]) == {"findings_gap", "notes_gap"}

    async def test_common_spine_present_in_every_mode(self) -> None:
        for mode in MODES:
            res = await hunt_context(mode=mode)
            for key in ("status", "mode", "budget", "scope_set",
                        "out_of_scope_suppressed", "sections", "truncated",
                        "estimated_tokens", "next_call_hint"):
                assert key in res, (mode, key)
            assert res["next_call_hint"] != ""
            assert set(res["out_of_scope_suppressed"]) == {"count", "reasons"}


class TestScopeProjection:
    async def test_out_of_scope_asset_suppressed_from_surface(self) -> None:
        _ingest_subdomains(["api.example.com", "evil.invalid"])
        res = await hunt_context(mode="brief")
        assert "evil.invalid" not in json.dumps(res)
        assert res["out_of_scope_suppressed"]["count"] >= 1
        assert "api.example.com" in res["sections"]["surface"]["data"]["subdomains"]

    async def test_out_of_scope_note_row_dropped_from_board(self) -> None:
        await note_add("idor", "evil.invalid", "looks juicy", stance="suspected")
        await note_add("xss", "app.example.com", "reflected marker", stance="suspected")
        res = await hunt_context(mode="brief")
        vectors = [row["vector"] for row in res["sections"]["board"]["items"]]
        assert vectors == ["xss"]
        assert "evil.invalid" not in json.dumps(res)

    async def test_coverage_recomputed_from_scope_clean_rows(self) -> None:
        await note_add("idor", "evil.invalid", "out of bounds", stance="suspected")
        res = await hunt_context(mode="brief")
        coverage = res["sections"]["coverage"]["data"]
        assert coverage["touched_count"] == 0
        assert coverage["coverage_pct"] == 0
        assert coverage["touched"] == []

    async def test_next_moves_targets_are_scope_filtered(self) -> None:
        _ingest_subdomains(["api.example.com", "evil.invalid"])
        res = await hunt_context(mode="resume")
        moves = res["sections"]["next_moves"]["items"]
        assert moves
        assert "evil.invalid" not in json.dumps(moves)

    async def test_board_row_targets_are_scope_filtered(self) -> None:
        await note_add("xss", "app.example.com", "one", stance="suspected", note_id="n1")
        res = await hunt_context(mode="brief")
        row = res["sections"]["board"]["items"][0]
        assert row["targets"] == ["app.example.com"]
        assert set(row) == {"vector", "stance", "max_confidence", "count", "targets",
                            "target_count", "next_action", "priority_score", "active"}


class TestBudget:
    @pytest.mark.parametrize("budget", ["tight", "normal", "deep"])
    async def test_every_budget_caps_items(self, budget: str) -> None:
        _ingest_subdomains([f"host{i}.example.com" for i in range(60)])
        res = await hunt_context(mode="brief", budget=budget)
        subs = res["sections"]["surface"]["data"]["subdomains"]
        assert len(subs) == _BUDGET_LIMITS[budget]["surface"]
        assert res["truncated"]["surface"] > 0

    async def test_tight_payload_smaller_than_deep(self) -> None:
        _ingest_subdomains([f"host{i}.example.com" for i in range(60)])
        tight = await hunt_context(budget="tight")
        deep = await hunt_context(budget="deep")
        assert tight["estimated_tokens"] < deep["estimated_tokens"]

    async def test_estimated_tokens_present_all_modes(self) -> None:
        for mode in MODES:
            for budget in ("tight", "normal", "deep"):
                res = await hunt_context(mode=mode, budget=budget)
                assert isinstance(res["estimated_tokens"], int)
                assert res["estimated_tokens"] > 0

    async def test_truncated_keys_subset_of_sections(self) -> None:
        _ingest_subdomains([f"host{i}.example.com" for i in range(60)])
        await note_add("xss", "app.example.com", "reflected", stance="suspected")
        for mode in MODES:
            res = await hunt_context(mode=mode, budget="tight")
            assert set(res["truncated"]) <= set(res["sections"]), mode

    async def test_truncated_empty_when_nothing_cut(self) -> None:
        res = await hunt_context(mode="evidence")
        assert res["truncated"] == {}


class TestSourceHonesty:
    async def test_findings_source_failure_reports_unavailable(self) -> None:
        with patch("kambo.tools.context.get_findings_data",
                   side_effect=RuntimeError("db gone")):
            res = await hunt_context(mode="brief")
        section = res["sections"]["findings"]
        assert section["available"] is False
        assert section["reason"] != ""
        assert "db gone" in section["reason"]
        assert section["count"] == 0
        assert res["status"] == "ok"

    async def test_empty_source_is_available_true_not_a_failure(self) -> None:
        res = await hunt_context(mode="brief")
        section = res["sections"]["findings"]
        assert section["available"] is True
        assert section["count"] == 0
        assert section["reason"] == ""

    async def test_metrics_empty_tracker_is_available_not_a_failure(self) -> None:
        """An empty metrics tracker is healthy-empty, like every other section —
        only a source that raised may be ``available: false``."""
        res = await hunt_context(mode="brief")
        section = res["sections"]["metrics"]
        assert section["available"] is True
        assert section["reason"] == ""
        assert section["data"]["total_tools_used"] == 0

    async def test_metrics_source_failure_is_distinguishable_from_empty(self) -> None:
        with patch("kambo.tools.context.reporting.report_metrics",
                   side_effect=RuntimeError("metrics gone")):
            broken = await hunt_context(mode="brief")
        healthy = await hunt_context(mode="brief")
        assert broken["sections"]["metrics"]["available"] is False
        assert "metrics gone" in broken["sections"]["metrics"]["reason"]
        assert healthy["sections"]["metrics"]["available"] is True

    async def test_metrics_never_includes_per_tool(self) -> None:
        metrics_module.get_metrics().record_run("recon_subdomains")
        res = await hunt_context(mode="brief")
        section = res["sections"]["metrics"]
        assert section["available"] is True
        assert "per_tool" not in section["data"]
        assert section["data"]["total_tools_used"] == 1

    async def test_no_none_anywhere_in_payload(self) -> None:
        _ingest_subdomains(["api.example.com"])
        await note_add("xss", "app.example.com", "reflected", stance="suspected")
        for mode in MODES:
            res = await hunt_context(mode=mode)
            assert all(value is not None for value in _walk(res)), mode

    async def test_available_false_implies_reason_nonempty(self) -> None:
        for mode in MODES:
            res = await hunt_context(mode=mode)
            for section in res["sections"].values():
                if section["available"] is False:
                    assert section["reason"] != ""
                else:
                    assert section["reason"] == ""


class TestArgumentErrors:
    async def test_invalid_mode_returns_error_dict(self) -> None:
        res = await hunt_context(mode="nope")
        assert set(res) == {"error", "valid_modes"}
        assert res["valid_modes"] == ["brief", "resume", "scope", "evidence"]

    async def test_invalid_budget_returns_error_dict(self) -> None:
        res = await hunt_context(budget="nope")
        assert set(res) == {"error", "valid_budgets"}
        assert res["valid_budgets"] == ["tight", "normal", "deep"]


class TestEvidenceMode:
    async def test_evidence_mode_skips_confirmed_findings(self, _fresh_session) -> None:
        _fresh_session.get_findings.return_value = [
            _finding_row(id="FIND-001", confidence="confirmed"),
            _finding_row(id="FIND-002", confidence="tentative"),
        ]
        res = await hunt_context(mode="evidence")
        ids = [item["id"] for item in res["sections"]["findings_gap"]["items"]]
        assert ids == ["FIND-002"]

    async def test_evidence_mode_parses_json_string_evidence_chain(self, _fresh_session) -> None:
        _fresh_session.get_findings.return_value = [_finding_row()]
        res = await hunt_context(mode="evidence")
        item = res["sections"]["findings_gap"]["items"][0]
        assert item["total_weight"] == 1.5
        assert item["signal_count"] == 1
        assert item["gap"]["blocked_by_ceiling"] is True
        assert item["gap"]["ceiling"] == "firm"
        assert "x" * 500 not in json.dumps(res)

    async def test_evidence_mode_notes_gap_lists_unsettled_vectors(self) -> None:
        await note_add("xss", "app.example.com", "reflected", stance="suspected")
        await note_add("cors", "api.example.com", "closed", stance="ruled_out")
        res = await hunt_context(mode="evidence")
        items = res["sections"]["notes_gap"]["items"]
        assert [item["vector"] for item in items] == ["xss"]
        assert items[0]["missing_signal"] != ""

    async def test_evidence_mode_vector_filter(self) -> None:
        await note_add("xss", "app.example.com", "reflected", stance="suspected")
        await note_add("idor", "api.example.com", "sequential ids", stance="suspected")
        res = await hunt_context(mode="evidence", vector="idor")
        assert [item["vector"] for item in res["sections"]["notes_gap"]["items"]] == ["idor"]


class TestScopeMode:
    async def test_scope_mode_lists_exclusions_as_rules(self) -> None:
        get_scope_manager().set_scope(EngagementScope(
            engagement_id="SCOPE-001",
            targets=[ScopeTarget(target="*.example.com", exclusions=["beta.example.com"])],
            exclusions=["admin.example.com"],
            rules=["no automated scanning during business hours"],
        ))
        res = await hunt_context(mode="scope")
        items = res["sections"]["out_of_scope"]["items"]
        assert all(set(item) == {"pattern", "origin"} for item in items)
        assert {"pattern": "admin.example.com", "origin": "global"} in items
        assert {"pattern": "beta.example.com", "origin": "target:*.example.com"} in items
        assert res["sections"]["rules"]["items"] == ["no automated scanning during business hours"]

    async def test_scope_mode_flags_pentest_lock_in_bug_bounty(self) -> None:
        get_scope_manager().set_scope(EngagementScope(
            engagement_id="BB-001",
            context=Context.BUG_BOUNTY,
            targets=[ScopeTarget(target="*.example.com")],
        ))
        res = await hunt_context(mode="scope", budget="deep")
        data = res["sections"]["restrictions"]["data"]
        assert data["pentest_tools_locked"] is True
        assert data["locked_tool_count"] == 13
        assert data["locked_tool_count"] == len(PENTEST_ONLY_TOOLS)
        assert data["context"] == "bug_bounty"

    async def test_scope_mode_pentest_context_unlocked(self) -> None:
        res = await hunt_context(mode="scope")  # conftest scope defaults to pentest
        data = res["sections"]["restrictions"]["data"]
        assert data["pentest_tools_locked"] is False
        assert data["locked_tools"] == []

    async def test_payouts_declared_unavailable_offline(self) -> None:
        res = await hunt_context(mode="scope")
        payouts = res["sections"]["payouts"]
        assert payouts["available"] is False
        assert "platform_fetch_program" in payouts["reason"]


class TestNextMoves:
    async def test_next_moves_items_carry_score_basis(self) -> None:
        _ingest_subdomains(["api.example.com"])
        await note_add("xss", "app.example.com", "reflected", stance="suspected")
        res = await hunt_context(mode="resume")
        items = res["sections"]["next_moves"]["items"]
        assert items
        for item in items:
            assert item["source"] in {"notes", "pipeline"}
            assert item["score_basis"] in {"roi", "pipeline_order"}
            assert set(item) == {"source", "action", "vector", "targets",
                                 "target_count", "priority_score", "score_basis",
                                 "why"}

    async def test_next_moves_sorted_by_priority_desc(self) -> None:
        _ingest_subdomains(["api.example.com"])
        await note_add("sqli", "app.example.com", "error string", stance="probing")
        res = await hunt_context(mode="resume")
        scores = [item["priority_score"] for item in res["sections"]["next_moves"]["items"]]
        assert scores == sorted(scores, reverse=True)

    async def test_resume_hint_is_first_move(self) -> None:
        res = await hunt_context(mode="resume")
        moves = res["sections"]["next_moves"]["items"]
        assert res["next_call_hint"] == moves[0]["action"]

    async def test_resume_open_threads_only_active_rows(self) -> None:
        await note_add("xss", "app.example.com", "reflected", stance="suspected")
        await note_add("cors", "api.example.com", "closed", stance="ruled_out")
        res = await hunt_context(mode="resume")
        rows = res["sections"]["open_threads"]["items"]
        assert [row["vector"] for row in rows] == ["xss"]
        assert all(row["active"] is True for row in rows)

    async def test_where_i_stopped_reports_session_notes(self) -> None:
        _ingest_subdomains(["api.example.com"])
        await note_add("xss", "app.example.com", "reflected", stance="suspected")
        data = (await hunt_context(mode="resume"))["sections"]["where_i_stopped"]["data"]
        assert data["session_notes"] == 1
        assert data["notes_ephemeral"] is True
        assert data["inferred_phase"] == "scanning"
        assert data["inferred"] is True
        assert data["tools_run_count"] == 1


class TestServerRegistration:
    async def test_hunt_context_in_pipeline_skip_tools(self) -> None:
        from kambo import server

        assert "hunt_context" in server._PIPELINE_SKIP_TOOLS

    async def test_hunt_context_registered(self) -> None:
        from kambo import server

        assert "hunt_context" in server._TOOL_REGISTRY
        listed = {tool.name for tool in await server.list_tools()}
        assert "hunt_context" in listed

    async def test_dispatch_defaults_mirror_function_defaults(self) -> None:
        from kambo import server

        res = await server._TOOL_REGISTRY["hunt_context"].dispatch({})
        assert res["mode"] == "brief"
        assert res["budget"] == "normal"


def _ingest_endpoints(paths: list[str]) -> None:
    get_pipeline().ingest(
        "scan_api_endpoints",
        {"target": "example.com", "endpoints": [{"path": p} for p in paths]},
    )


def _seed_note(vector: str, target: str, stance: str, timestamp: str) -> None:
    """Write straight to the store so the timestamp (and therefore the
    newest-first ordering) is deterministic."""
    get_notes_store().add(Note(
        vector=AttackVector(vector),
        target=target,
        observation="seeded",
        stance=VectorStance(stance),
        confidence=8,
        timestamp=timestamp,
    ))


class TestScopeLeaksClosed:
    """Regression: values whose locality was guessed from string shape reached
    the payload unvalidated and uncounted."""

    async def test_protocol_relative_endpoint_is_suppressed(self) -> None:
        _ingest_endpoints(["//telemetry.attacker.test/v1/collect", "/api/v1/users"])
        res = await hunt_context(mode="brief")
        assert "attacker.test" not in json.dumps(res)
        assert res["sections"]["surface"]["data"]["endpoints"] == ["/api/v1/users"]
        assert res["out_of_scope_suppressed"]["count"] == 1

    async def test_ipv6_subdomain_is_suppressed(self) -> None:
        _ingest_subdomains(["api.example.com", "2001:db8::1"])
        res = await hunt_context(mode="brief")
        assert "2001:db8::1" not in json.dumps(res)
        assert res["sections"]["surface"]["data"]["subdomains"] == ["api.example.com"]
        assert res["out_of_scope_suppressed"]["count"] == 1

    async def test_note_target_with_embedded_in_scope_url_is_dropped(self) -> None:
        await note_add("idor", "attacker.test/redir?to=https://api.example.com/",
                       "open redirect chain", stance="suspected")
        res = await hunt_context(mode="brief")
        assert "attacker.test" not in json.dumps(res)
        assert res["sections"]["board"]["items"] == []


class TestSuppressionCounterIsValueBased:
    """Regression: one suppressed asset was counted once per section builder
    that touched it, inflating the only visibility into what was removed."""

    async def test_single_out_of_scope_asset_counts_once_in_brief(self) -> None:
        _ingest_subdomains(["a.example.com", "evil.invalid"])
        res = await hunt_context(mode="brief")
        assert res["out_of_scope_suppressed"] == {"count": 1, "reasons": {"not_in_scope": 1}}

    async def test_single_out_of_scope_asset_counts_once_in_resume(self) -> None:
        _ingest_subdomains(["a.example.com", "evil.invalid"])
        res = await hunt_context(mode="resume")
        assert res["out_of_scope_suppressed"]["count"] == 1

    async def test_single_out_of_scope_note_counts_once(self) -> None:
        await note_add("xss", "evil.invalid", "looks juicy", stance="suspected")
        for mode in ("brief", "resume"):
            res = await hunt_context(mode=mode)
            assert res["out_of_scope_suppressed"]["count"] == 1, mode


class TestNotesGapReadsTheWholeBoard:
    """Regression: the fetch was capped before the unsettled filter ran, so
    unsettled notes older than the cap vanished with ``count: 0``."""

    async def test_unsettled_notes_behind_the_fetch_cap_are_found(self) -> None:
        for i in range(5):
            _seed_note("idor", f"old{i}.example.com", "suspected",
                       f"2026-01-01T00:00:{i:02d}+00:00")
        for i in range(60):
            _seed_note("cors", f"new{i}.example.com", "ruled_out",
                       f"2026-06-01T00:{i // 60:02d}:{i % 60:02d}+00:00")
        res = await hunt_context(mode="evidence", budget="normal")
        section = res["sections"]["notes_gap"]
        assert section["available"] is True
        assert section["count"] == 5
        assert {item["vector"] for item in section["items"]} == {"idor"}


class TestPartialSourceFailureIsDeclared:
    """Regression: ``next_moves`` merged two sources but only declared itself
    unavailable when both failed — half a ranking looked healthy."""

    async def test_broken_notes_store_degrades_next_moves(self) -> None:
        _ingest_subdomains(["api.example.com"])
        with patch("kambo.tools.notes.note_query",
                   side_effect=RuntimeError("notes db locked")):
            res = await hunt_context(mode="resume")
        moves = res["sections"]["next_moves"]
        assert moves["degraded"] is True
        assert moves["sources"]["notes"]["available"] is False
        assert "notes db locked" in moves["sources"]["notes"]["reason"]
        assert moves["sources"]["pipeline"]["available"] is True

    async def test_healthy_run_is_not_degraded(self) -> None:
        _ingest_subdomains(["api.example.com"])
        res = await hunt_context(mode="resume")
        moves = res["sections"]["next_moves"]
        assert moves["degraded"] is False
        assert moves["sources"]["notes"]["available"] is True

    async def test_next_moves_keys_stable_across_total_failure(self) -> None:
        healthy = (await hunt_context(mode="resume"))["sections"]["next_moves"]
        with patch("kambo.tools.notes.note_query", side_effect=RuntimeError("down")), \
                patch("kambo.tools.context._pipeline_state",
                      return_value=({}, "pipeline unavailable: RuntimeError: down")):
            broken = (await hunt_context(mode="resume"))["sections"]["next_moves"]
        assert set(healthy) == set(broken)
        assert broken["available"] is False

    async def test_hint_never_points_at_the_broken_notes_store(self) -> None:
        with patch("kambo.tools.notes.note_query",
                   side_effect=RuntimeError("notes db locked")), \
                patch("kambo.tools.context._pipeline_state",
                      return_value=({}, "pipeline unavailable: RuntimeError: down")):
            res = await hunt_context(mode="resume")
        assert res["next_call_hint"] != "note_add"

    async def test_evidence_hint_never_points_at_the_broken_notes_store(self) -> None:
        with patch("kambo.tools.notes.note_query",
                   side_effect=RuntimeError("notes db locked")):
            res = await hunt_context(mode="evidence")
        assert res["sections"]["notes_gap"]["available"] is False
        assert res["next_call_hint"] != "note_add"

    async def test_where_i_stopped_declares_a_broken_notes_store(self) -> None:
        _ingest_subdomains(["api.example.com"])
        await note_add("xss", "app.example.com", "reflected", stance="suspected")
        with patch("kambo.tools.notes.note_query",
                   side_effect=RuntimeError("notes db locked")):
            res = await hunt_context(mode="resume")
        data = res["sections"]["where_i_stopped"]["data"]
        assert data["notes_available"] is False
        assert "notes db locked" in data["notes_reason"]

    async def test_where_i_stopped_healthy_notes_are_marked_available(self) -> None:
        _ingest_subdomains(["api.example.com"])
        await note_add("xss", "app.example.com", "reflected", stance="suspected")
        data = (await hunt_context(mode="resume"))["sections"]["where_i_stopped"]["data"]
        assert data["notes_available"] is True
        assert data["notes_reason"] == ""
        assert data["session_notes"] == 1


class TestUnreadableEvidenceChain:
    """Regression: an unparseable chain was replaced by a default one, erasing
    the ceiling and its gates and advising the operator to add weight."""

    async def test_drifted_enum_is_declared_not_defaulted(self, _fresh_session) -> None:
        _fresh_session.get_findings.return_value = [_finding_row(
            id="FIND-007",
            confidence="tentative",
            evidence_chain=json.dumps({
                "items": [{"signal": "5xx delta", "source": "vuln_ssrf", "weight": 1.5}],
                "ceiling": "high",  # not a Confidence value — the chain is unreadable
                "gates": ["blind SSRF with no out-of-band callback"],
            }),
        )]
        res = await hunt_context(mode="evidence")
        item = res["sections"]["findings_gap"]["items"][0]
        assert item["chain_unreadable"] is True
        assert item["chain_parse_error"] != ""
        assert item["gap"]["blocked_by_ceiling"] is True
        assert item["gap"]["ceiling"] != "confirmed"
        assert "unreadable" in item["gap"]["advice"]
        assert "more evidence weight" not in item["gap"]["advice"]

    async def test_corrupt_json_column_is_declared(self, _fresh_session) -> None:
        _fresh_session.get_findings.return_value = [
            _finding_row(id="FIND-008", confidence="tentative",
                         evidence_chain='{"items":[{"signal":"s1"'),
        ]
        item = (await hunt_context(mode="evidence"))["sections"]["findings_gap"]["items"][0]
        assert item["chain_unreadable"] is True
        assert item["gap"]["chain_unreadable"] is True

    async def test_no_chain_recorded_is_not_unreadable(self, _fresh_session) -> None:
        _fresh_session.get_findings.return_value = [
            _finding_row(id="FIND-009", confidence="tentative", evidence_chain="{}"),
        ]
        item = (await hunt_context(mode="evidence"))["sections"]["findings_gap"]["items"][0]
        assert item["chain_unreadable"] is False
        assert item["gap"]["blocked_by_ceiling"] is False


class TestMetricsHonourTheBudget:
    """Regression: the per-tool warnings dict escaped the budget entirely and
    could dominate a 'tight' briefing without appearing in ``truncated``."""

    async def test_warnings_are_capped_and_the_drop_is_reported(self) -> None:
        tracker = metrics_module.get_metrics()
        for i in range(40):
            tool = f"tool_{i:02d}"
            tracker.record_run(tool)
            for _ in range(4):
                tracker.record_user_feedback(tool, is_true_positive=False)
        res = await hunt_context(mode="brief", budget="tight")
        data = res["sections"]["metrics"]["data"]
        assert data["warning_count"] == 40
        assert len(data["warnings"]) == _BUDGET_LIMITS["tight"]["board"]
        assert res["truncated"]["metrics"] == 40 - _BUDGET_LIMITS["tight"]["board"]


class TestTruncationAccounting:
    """Regression: budget cuts that were not reported in ``truncated``."""

    async def test_dropped_confirmed_vectors_are_counted(self) -> None:
        for vector in ("xss", "sqli", "ssrf", "idor", "cors", "jwt"):
            await note_add(vector, "a.example.com", "proven", stance="confirmed")
        res = await hunt_context(mode="brief", budget="tight")
        data = res["sections"]["coverage"]["data"]
        dropped_confirmed = data["confirmed_count"] - len(data["confirmed"])
        dropped_touched = data["touched_count"] - len(data["touched"])
        dropped_untouched = (
            data["total_vectors"] - data["touched_count"] - len(data["untouched"])
        )
        assert dropped_confirmed == 3
        assert res["truncated"]["coverage"] == (
            dropped_confirmed + dropped_touched + dropped_untouched
        )

    async def test_board_row_declares_its_full_target_count(self) -> None:
        for i in range(12):
            await note_add("xss", f"h{i:02d}.example.com", "reflected", stance="suspected")
        res = await hunt_context(mode="brief", budget="tight")
        row = res["sections"]["board"]["items"][0]
        assert len(row["targets"]) == _BUDGET_LIMITS["tight"]["surface"]
        assert row["target_count"] == 12

    async def test_next_move_declares_its_full_target_count(self) -> None:
        _ingest_subdomains([f"h{i:02d}.example.com" for i in range(12)])
        res = await hunt_context(mode="resume", budget="tight")
        move = next(m for m in res["sections"]["next_moves"]["items"]
                    if m["source"] == "pipeline" and m["targets"])
        assert move["target_count"] >= len(move["targets"])


class TestSectionShapeIsStable:
    """Regression: the findings section changed key set when the db failed —
    ``report_ready`` raised ``KeyError`` exactly in the failure path."""

    async def test_findings_keys_identical_available_and_unavailable(self) -> None:
        healthy = (await hunt_context(mode="brief"))["sections"]["findings"]
        with patch("kambo.tools.context.get_findings_data",
                   side_effect=RuntimeError("db locked")):
            broken = (await hunt_context(mode="brief"))["sections"]["findings"]
        assert set(healthy) == set(broken)
        assert broken["report_ready"] is False
        assert broken["severity_counts"] == {}


class TestTokenEstimateMatchesTransport:
    """Regression: the estimate ignored the ``indent=2`` the transport writes."""

    async def test_estimate_matches_the_serialized_payload(self) -> None:
        _ingest_subdomains([f"host{i}.example.com" for i in range(60)])
        await note_add("xss", "app.example.com", "reflected", stance="suspected")
        res = await hunt_context(mode="brief", budget="deep")
        wire = len(json.dumps(res, indent=2, default=str)) // 4
        assert abs(res["estimated_tokens"] - wire) <= 30

    async def test_hunt_context_skips_the_historical_warning_injection(self) -> None:
        from kambo import server

        assert "hunt_context" in server._WARNING_SKIP_TOOLS
