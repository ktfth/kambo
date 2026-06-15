"""Tests for the note_add / note_query MCP tools (ephemeral session store)."""

from __future__ import annotations

import pytest

from unittest.mock import AsyncMock, patch

import kambo.notes as notes_module
from kambo.notes import VectorStance
from kambo.tools.notes import note_add, note_promote, note_query


def _mock_findings_db():
    """AsyncMock DB that report_finding can write to without touching disk."""
    mock_db = AsyncMock()
    mock_db.get_findings.return_value = []
    return mock_db


@pytest.fixture(autouse=True)
def _fresh_session():
    """Reset the per-session notes singleton to a clean ephemeral store."""
    notes_module._store = None
    yield
    notes_module._store = None


class TestNoteAdd:
    async def test_basic_add_is_ephemeral(self) -> None:
        res = await note_add("idor", "api.example.com", "sequential ids, no ownership check")
        assert res["status"] == "noted"
        assert res["ephemeral"] is True
        assert res["note"]["vector"] == "idor"
        assert res["session_total"] == 1

    async def test_unknown_vector_errors(self) -> None:
        res = await note_add("nope", "example.com", "x")
        assert "error" in res
        assert "idor" in res["valid_vectors"]

    async def test_unknown_stance_errors(self) -> None:
        res = await note_add("xss", "example.com", "x", stance="winning")
        assert "error" in res
        assert "confirmed" in res["valid_stances"]

    async def test_evidence_caps_overclaimed_stance(self) -> None:
        # Claim CONFIRMED but attach only weak evidence (weight 0.5 → TENTATIVE).
        res = await note_add(
            "sqli", "example.com", "error on quote",
            stance="confirmed",
            evidence_signals=[{"signal": "db error string", "source": "manual", "weight": 0.5}],
        )
        assert res["evidence_backed_stance"] == "suspected"
        assert res["note"]["stance"] == "suspected"
        assert res["caveat"] is not None and "capped" in res["caveat"]

    async def test_evidence_supports_strong_stance(self) -> None:
        # Two solid signals (weight 1.0 + 1.0 = 2.0 → CONFIRMED).
        res = await note_add(
            "sqli", "example.com", "extracted db version via UNION",
            stance="confirmed",
            evidence_signals=[
                {"signal": "UNION reflected", "source": "manual", "weight": 1.0},
                {"signal": "version() output in response", "source": "manual", "weight": 1.0},
            ],
        )
        assert res["evidence_backed_stance"] == "confirmed"
        assert res["note"]["stance"] == "confirmed"
        assert res["caveat"] is None
        assert res["note"]["evidence"]["confidence"] == "confirmed"

    async def test_strong_stance_without_evidence_is_flagged(self) -> None:
        res = await note_add("ssrf", "example.com", "feels exploitable", stance="confirmed")
        assert res["note"]["stance"] == "confirmed"  # kept, but...
        assert res["caveat"] is not None and "hunch" in res["caveat"]

    async def test_confidence_clamped(self) -> None:
        res = await note_add("xss", "example.com", "x", confidence=99)
        assert res["note"]["confidence"] == 10

    async def test_note_id_progression(self) -> None:
        await note_add("idor", "example.com", "candidate", stance="suspected", note_id="i1")
        await note_add("idor", "example.com", "exploited", stance="confirmed", note_id="i1")
        listed = await note_query(mode="list")
        assert listed["count"] == 1
        assert listed["notes"][0]["stance"] == "confirmed"


class TestNoteQuery:
    async def _seed(self) -> None:
        await note_add("idor", "api.example.com", "a", stance="probing", confidence=8)
        await note_add("xss", "www.example.com", "b", stance="confirmed", confidence=6,
                       evidence_signals=[{"signal": "alert fired", "source": "browser", "weight": 2.0}])
        await note_add("ssrf", "api.example.com", "c", stance="ruled_out", confidence=3)

    async def test_list_mode(self) -> None:
        await self._seed()
        res = await note_query(mode="list")
        assert res["ephemeral"] is True
        assert res["count"] == 3

    async def test_list_filter_by_vector(self) -> None:
        await self._seed()
        res = await note_query(mode="list", vector="idor")
        assert res["count"] == 1
        assert res["notes"][0]["vector"] == "idor"

    async def test_by_vector_pivot(self) -> None:
        await self._seed()
        res = await note_query(mode="by_vector")
        assert set(res["by_vector"].keys()) == {"idor", "xss", "ssrf"}
        assert res["by_vector"]["xss"]["stance"] == "confirmed"

    async def test_board_orders_active_first(self) -> None:
        await self._seed()
        res = await note_query(mode="board")
        # PROBING (idor) is active → leads over confirmed/ruled_out.
        assert res["board"][0]["vector"] == "idor"
        assert "next_action" in res["board"][0]

    async def test_coverage_blind_spots(self) -> None:
        await self._seed()
        res = await note_query(mode="coverage")
        cov = res["coverage"]
        assert set(cov["touched"]) == {"idor", "xss", "ssrf"}
        assert "jwt" in cov["untouched"]
        assert cov["confirmed"] == ["xss"]

    async def test_board_has_vector_specific_next_step(self) -> None:
        await note_add("idor", "api.example.com", "a", stance="untested")
        res = await note_query(mode="board")
        assert "object id" in res["board"][0]["next_action"]

    async def test_playbook_mode(self) -> None:
        res = await note_query(mode="playbook", vector="ssrf")
        assert res["vector"] == "ssrf"
        ladder = res["playbook"]
        # Full stance ladder present, untested step is vector-specific.
        assert set(ladder.keys()) == {s.value for s in VectorStance}
        assert "OOB" in ladder["untested"]

    async def test_playbook_mode_requires_vector(self) -> None:
        res = await note_query(mode="playbook")
        assert "error" in res

    async def test_playbook_mode_unknown_vector_errors(self) -> None:
        res = await note_query(mode="playbook", vector="bogus")
        assert "error" in res

    async def test_unknown_mode_errors(self) -> None:
        res = await note_query(mode="bogus")
        assert "error" in res
        assert "board" in res["valid_modes"]

    async def test_unknown_vector_filter_errors(self) -> None:
        res = await note_query(mode="list", vector="bogus")
        assert "error" in res

    async def test_empty_session(self) -> None:
        res = await note_query(mode="list")
        assert res["count"] == 0
        assert res["session_total"] == 0


class TestBoardROI:
    async def test_board_rows_have_roi(self) -> None:
        await note_add("sqli", "example.com", "x", stance="probing", confidence=9)
        row = (await note_query(mode="board"))["board"][0]
        assert "roi" in row
        assert set(row["roi"].keys()) == {"acceptance", "stance_weight", "priority_score"}
        assert 0 <= row["roi"]["priority_score"] <= 100

    async def test_ruled_out_scores_zero(self) -> None:
        await note_add("sqli", "example.com", "x", stance="ruled_out", confidence=9)
        row = (await note_query(mode="board"))["board"][0]
        assert row["roi"]["priority_score"] == 0

    async def test_order_roi_reranks_vs_attention(self) -> None:
        # rce untested @10 has high ROI but is not "active";
        # open_redirect probing @2 is active but low ROI.
        await note_add("rce", "example.com", "high upside", stance="untested", confidence=10)
        await note_add("open_redirect", "example.com", "weak lead", stance="probing", confidence=2)

        attention = await note_query(mode="board")  # default order
        assert attention["order"] == "attention"
        assert attention["board"][0]["vector"] == "open_redirect"  # active leads

        roi = await note_query(mode="board", order="roi")
        assert roi["order"] == "roi"
        assert roi["board"][0]["vector"] == "rce"  # highest priority_score leads

    async def test_advisory_vector_gets_score(self) -> None:
        # graphql has no pricing-table entry → advisory acceptance still applies.
        await note_add("graphql", "example.com", "introspection open", stance="suspected", confidence=8)
        row = (await note_query(mode="board"))["board"][0]
        assert row["roi"]["acceptance"] == 0.7
        assert row["roi"]["priority_score"] > 0


class TestNotePromote:
    async def test_promote_confirmed_note(self) -> None:
        await note_add(
            "sqli", "api.example.com", "extracted db version via UNION",
            stance="confirmed", note_id="p1",
            evidence_signals=[
                {"signal": "UNION reflected", "source": "manual", "weight": 1.0},
                {"signal": "version() in response", "source": "manual", "weight": 1.0},
            ],
        )
        mock_db = _mock_findings_db()
        with patch("kambo.tools.reporting.get_database", return_value=mock_db):
            res = await note_promote("p1", "high", impact="cross-account data read")
        assert res["status"] == "promoted"
        assert res["from_note"] == "p1"
        assert res["finding_confidence"] == "confirmed"
        assert res["finding"]["id"] == "FIND-001"
        assert res["finding"]["finding"]["target"] == "api.example.com"
        mock_db.save_finding.assert_awaited_once()

    async def test_promote_unknown_note_errors(self) -> None:
        res = await note_promote("ghost", "high")
        assert "error" in res and "no note" in res["error"]

    async def test_promote_unconfirmed_blocked(self) -> None:
        await note_add("xss", "example.com", "maybe", stance="suspected", note_id="p2")
        res = await note_promote("p2", "medium")
        assert "error" in res and "not 'confirmed'" in res["error"]

    async def test_promote_unconfirmed_with_override(self) -> None:
        await note_add("xss", "example.com", "lead", stance="suspected", note_id="p3")
        mock_db = _mock_findings_db()
        with patch("kambo.tools.reporting.get_database", return_value=mock_db):
            res = await note_promote("p3", "low", allow_unconfirmed=True)
        assert res["status"] == "promoted"
        # No evidence signals → honest confidence is tentative.
        assert res["finding_confidence"] == "tentative"

    async def test_confirmed_hunch_promotes_as_tentative(self) -> None:
        # 'confirmed' stance recorded without evidence (a hunch) is honestly
        # downgraded to a TENTATIVE finding.
        await note_add("ssrf", "example.com", "gut feeling", stance="confirmed", note_id="p4")
        mock_db = _mock_findings_db()
        with patch("kambo.tools.reporting.get_database", return_value=mock_db):
            res = await note_promote("p4", "high")
        assert res["status"] == "promoted"
        assert res["finding_confidence"] == "tentative"

    async def test_promote_invalid_severity_errors(self) -> None:
        await note_add("idor", "example.com", "x", stance="confirmed", note_id="p5")
        res = await note_promote("p5", "catastrophic")
        assert "error" in res and "severity" in res["error"]

    async def test_promote_default_title_from_vector(self) -> None:
        await note_add("idor", "api.example.com", "x", stance="confirmed", note_id="p6")
        mock_db = _mock_findings_db()
        with patch("kambo.tools.reporting.get_database", return_value=mock_db):
            res = await note_promote("p6", "high")
        assert res["finding"]["finding"]["title"] == "IDOR — api.example.com"
