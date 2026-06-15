"""Tests for the note_add / note_query MCP tools (ephemeral session store)."""

from __future__ import annotations

import pytest

import kambo.notes as notes_module
from kambo.notes import VectorStance
from kambo.tools.notes import note_add, note_query


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
