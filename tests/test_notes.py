"""Tests for the attack-vector-centric engagement notes store."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from kambo.notes import (
    AttackVector,
    Note,
    NotesStore,
    VectorStance,
    get_notes_store,
    next_action_for,
)
from kambo.notes_playbooks import PLAYBOOKS, playbook_action


def _ts(offset_seconds: int = 0) -> str:
    """Deterministic ISO timestamp helper for ordering assertions."""
    base = datetime(2026, 6, 14, 12, 0, 0, tzinfo=timezone.utc)
    return (base + timedelta(seconds=offset_seconds)).isoformat()


class TestNoteModel:
    def test_create_note(self) -> None:
        n = Note(
            vector=AttackVector.IDOR,
            target="api.example.com/users/1",
            observation="Sequential numeric ids, no ownership check seen",
            stance=VectorStance.SUSPECTED,
            confidence=7,
            tags=["api", "rest"],
        )
        assert n.vector is AttackVector.IDOR
        assert n.stance is VectorStance.SUSPECTED
        assert n.confidence == 7

    def test_defaults(self) -> None:
        n = Note(vector=AttackVector.XSS, target="example.com", observation="reflects q param")
        assert n.stance is VectorStance.UNTESTED
        assert n.confidence == 5
        assert n.source == "operator"
        assert n.id == ""

    def test_note_is_frozen(self) -> None:
        n = Note(vector=AttackVector.SQLI, target="example.com", observation="o")
        with pytest.raises(Exception):
            n.observation = "changed"  # type: ignore

    def test_string_coercion_to_enum(self) -> None:
        n = Note(vector="ssrf", target="example.com", observation="o", stance="probing")  # type: ignore[arg-type]
        assert n.vector is AttackVector.SSRF
        assert n.stance is VectorStance.PROBING

    def test_json_round_trip_serializes_enums_as_strings(self) -> None:
        n = Note(vector=AttackVector.JWT, target="example.com", observation="alg none?")
        dumped = n.model_dump(mode="json")
        assert dumped["vector"] == "jwt"
        assert dumped["stance"] == "untested"
        # Survives a JSON round trip.
        restored = Note(**json.loads(json.dumps(dumped)))
        assert restored.vector is AttackVector.JWT


class TestAddAndQuery:
    def _store(self, tmp_path: Path) -> NotesStore:
        return NotesStore(tmp_path / "notes.jsonl")

    def test_add_and_query(self, tmp_path: Path) -> None:
        store = self._store(tmp_path)
        store.add(Note(vector=AttackVector.IDOR, target="example.com", observation="found"))
        results = store.query()
        assert len(results) == 1
        assert results[0]["vector"] == "idor"

    def test_filter_by_vector(self, tmp_path: Path) -> None:
        store = self._store(tmp_path)
        store.add(Note(vector=AttackVector.IDOR, target="example.com", observation="a"))
        store.add(Note(vector=AttackVector.XSS, target="example.com", observation="b"))
        results = store.query(vector="idor")
        assert len(results) == 1
        assert results[0]["vector"] == "idor"

    def test_filter_by_target_substring(self, tmp_path: Path) -> None:
        store = self._store(tmp_path)
        store.add(Note(vector=AttackVector.IDOR, target="api.example.com", observation="a"))
        store.add(Note(vector=AttackVector.IDOR, target="www.other.test", observation="b"))
        results = store.query(target="example")
        assert len(results) == 1
        assert "example" in results[0]["target"]

    def test_filter_by_stance(self, tmp_path: Path) -> None:
        store = self._store(tmp_path)
        store.add(Note(vector=AttackVector.SQLI, target="example.com", observation="a", stance=VectorStance.CONFIRMED))
        store.add(Note(vector=AttackVector.SQLI, target="example.com", observation="b", stance=VectorStance.UNTESTED))
        results = store.query(stance="confirmed")
        assert len(results) == 1
        assert results[0]["stance"] == "confirmed"

    def test_filter_by_keyword(self, tmp_path: Path) -> None:
        store = self._store(tmp_path)
        store.add(Note(vector=AttackVector.SSRF, target="example.com", observation="metadata endpoint reachable"))
        store.add(Note(vector=AttackVector.SSRF, target="example.com", observation="blocked by allowlist"))
        results = store.query(keyword="metadata")
        assert len(results) == 1
        assert "metadata" in results[0]["observation"]

    def test_filter_by_min_confidence(self, tmp_path: Path) -> None:
        store = self._store(tmp_path)
        store.add(Note(vector=AttackVector.XSS, target="example.com", observation="strong", confidence=9))
        store.add(Note(vector=AttackVector.XSS, target="example.com", observation="weak", confidence=2))
        results = store.query(min_confidence=5)
        assert len(results) == 1
        assert results[0]["observation"] == "strong"

    def test_limit(self, tmp_path: Path) -> None:
        store = self._store(tmp_path)
        for i in range(10):
            store.add(Note(vector=AttackVector.RECON, target="example.com", observation=f"n{i}"))
        assert len(store.query(limit=3)) == 3

    def test_newest_first(self, tmp_path: Path) -> None:
        store = self._store(tmp_path)
        store.add(Note(vector=AttackVector.RECON, target="example.com", observation="old", timestamp=_ts(0)))
        store.add(Note(vector=AttackVector.RECON, target="example.com", observation="new", timestamp=_ts(10)))
        results = store.query()
        assert results[0]["observation"] == "new"


class TestDedup:
    def _store(self, tmp_path: Path) -> NotesStore:
        return NotesStore(tmp_path / "notes.jsonl")

    def test_same_id_latest_wins(self, tmp_path: Path) -> None:
        store = self._store(tmp_path)
        store.add(Note(vector=AttackVector.IDOR, target="example.com", observation="candidate",
                       stance=VectorStance.UNTESTED, id="idor-1", timestamp=_ts(0)))
        store.add(Note(vector=AttackVector.IDOR, target="example.com", observation="exploited!",
                       stance=VectorStance.CONFIRMED, id="idor-1", timestamp=_ts(10)))
        results = store.query()
        assert len(results) == 1
        assert results[0]["stance"] == "confirmed"
        assert results[0]["observation"] == "exploited!"

    def test_empty_id_notes_kept_separately(self, tmp_path: Path) -> None:
        store = self._store(tmp_path)
        store.add(Note(vector=AttackVector.RECON, target="example.com", observation="a"))
        store.add(Note(vector=AttackVector.RECON, target="example.com", observation="b"))
        assert len(store.query()) == 2

    def test_count_is_raw_not_deduped(self, tmp_path: Path) -> None:
        store = self._store(tmp_path)
        store.add(Note(vector=AttackVector.IDOR, target="example.com", observation="a", id="k"))
        store.add(Note(vector=AttackVector.IDOR, target="example.com", observation="b", id="k"))
        assert store.count() == 2
        assert len(store.query()) == 1


class TestByVectorPivot:
    def _store(self, tmp_path: Path) -> NotesStore:
        return NotesStore(tmp_path / "notes.jsonl")

    def test_pivot_groups_by_vector(self, tmp_path: Path) -> None:
        store = self._store(tmp_path)
        store.add(Note(vector=AttackVector.IDOR, target="a.example.com", observation="x"))
        store.add(Note(vector=AttackVector.IDOR, target="b.example.com", observation="y"))
        store.add(Note(vector=AttackVector.XSS, target="a.example.com", observation="z"))
        pivot = store.by_vector()
        assert pivot["idor"]["count"] == 2
        assert pivot["idor"]["targets"] == ["a.example.com", "b.example.com"]
        assert pivot["xss"]["count"] == 1

    def test_pivot_reports_strongest_stance(self, tmp_path: Path) -> None:
        store = self._store(tmp_path)
        store.add(Note(vector=AttackVector.SQLI, target="example.com", observation="a", stance=VectorStance.SUSPECTED))
        store.add(Note(vector=AttackVector.SQLI, target="example.com", observation="b", stance=VectorStance.CONFIRMED))
        store.add(Note(vector=AttackVector.SQLI, target="example.com", observation="c", stance=VectorStance.UNTESTED))
        assert store.by_vector()["sqli"]["stance"] == "confirmed"

    def test_pivot_reports_latest_observation(self, tmp_path: Path) -> None:
        store = self._store(tmp_path)
        store.add(Note(vector=AttackVector.SSRF, target="example.com", observation="first", timestamp=_ts(0)))
        store.add(Note(vector=AttackVector.SSRF, target="example.com", observation="second", timestamp=_ts(10)))
        assert store.by_vector()["ssrf"]["latest"] == "second"

    def test_pivot_target_filter(self, tmp_path: Path) -> None:
        store = self._store(tmp_path)
        store.add(Note(vector=AttackVector.IDOR, target="keep.example.com", observation="a"))
        store.add(Note(vector=AttackVector.XSS, target="drop.example.com", observation="b"))
        pivot = store.by_vector(target="keep")
        assert "idor" in pivot
        assert "xss" not in pivot


class TestBoard:
    def _store(self, tmp_path: Path) -> NotesStore:
        return NotesStore(tmp_path / "notes.jsonl")

    def test_active_vectors_lead(self, tmp_path: Path) -> None:
        store = self._store(tmp_path)
        store.add(Note(vector=AttackVector.SQLI, target="example.com", observation="done",
                       stance=VectorStance.CONFIRMED, confidence=9))
        store.add(Note(vector=AttackVector.XSS, target="example.com", observation="working",
                       stance=VectorStance.PROBING, confidence=4))
        board = store.board()
        # PROBING is active and should lead despite lower confidence.
        assert board[0]["vector"] == "xss"
        assert board[0]["active"] is True

    def test_next_action_is_vector_specific(self, tmp_path: Path) -> None:
        store = self._store(tmp_path)
        store.add(Note(vector=AttackVector.IDOR, target="example.com", observation="o",
                       stance=VectorStance.UNTESTED))
        row = store.board()[0]
        # IDOR untested → the playbook step, not the generic stance hint.
        assert "object id" in row["next_action"]
        assert "probe this vector" not in row["next_action"]

    def test_next_action_falls_back_to_generic(self, tmp_path: Path) -> None:
        store = self._store(tmp_path)
        # RECON has no playbook → generic hint.
        store.add(Note(vector=AttackVector.RECON, target="example.com", observation="o",
                       stance=VectorStance.UNTESTED))
        assert "probe this vector" in store.board()[0]["next_action"]

    def test_confirmed_ranks_above_ruled_out(self, tmp_path: Path) -> None:
        store = self._store(tmp_path)
        store.add(Note(vector=AttackVector.SQLI, target="example.com", observation="a",
                       stance=VectorStance.RULED_OUT, confidence=5))
        store.add(Note(vector=AttackVector.IDOR, target="example.com", observation="b",
                       stance=VectorStance.CONFIRMED, confidence=5))
        order = [r["vector"] for r in store.board()]
        assert order.index("idor") < order.index("sqli")


class TestPlaybooks:
    def test_catalog_keys_are_valid(self) -> None:
        valid_vectors = {v.value for v in AttackVector}
        valid_stances = {s.value for s in VectorStance}
        for vec, ladder in PLAYBOOKS.items():
            assert vec in valid_vectors, f"unknown vector key: {vec}"
            for stance, action in ladder.items():
                assert stance in valid_stances, f"unknown stance key: {stance}"
                assert action.strip(), f"empty action for {vec}/{stance}"

    def test_playbook_action_hit(self) -> None:
        assert "object id" in playbook_action("idor", "untested")

    def test_playbook_action_miss_returns_none(self) -> None:
        assert playbook_action("recon", "untested") is None
        assert playbook_action("idor", "confirmed") is None  # not authored → generic

    def test_next_action_for_uses_playbook(self) -> None:
        assert next_action_for("ssrf", VectorStance.UNTESTED) == playbook_action("ssrf", "untested")

    def test_next_action_for_falls_back(self) -> None:
        # confirmed isn't authored per-vector → generic non-empty hint.
        action = next_action_for("idor", VectorStance.CONFIRMED)
        assert action and "object id" not in action


class TestCoverage:
    def _store(self, tmp_path: Path) -> NotesStore:
        return NotesStore(tmp_path / "notes.jsonl")

    def test_coverage_reports_blind_spots(self, tmp_path: Path) -> None:
        store = self._store(tmp_path)
        store.add(Note(vector=AttackVector.IDOR, target="example.com", observation="a"))
        cov = store.coverage()
        assert "idor" in cov["touched"]
        assert "ssrf" in cov["untouched"]
        assert cov["touched_count"] == 1
        assert cov["total_vectors"] == len(list(AttackVector))

    def test_coverage_lists_confirmed(self, tmp_path: Path) -> None:
        store = self._store(tmp_path)
        store.add(Note(vector=AttackVector.JWT, target="example.com", observation="forged",
                       stance=VectorStance.CONFIRMED))
        store.add(Note(vector=AttackVector.XSS, target="example.com", observation="maybe",
                       stance=VectorStance.SUSPECTED))
        cov = store.coverage()
        assert cov["confirmed"] == ["jwt"]

    def test_coverage_pct(self, tmp_path: Path) -> None:
        store = self._store(tmp_path)
        store.add(Note(vector=AttackVector.IDOR, target="example.com", observation="a"))
        cov = store.coverage()
        expected = round(100 / len(list(AttackVector)))
        assert cov["coverage_pct"] == expected


class TestPersistence:
    def test_persists_across_instances(self, tmp_path: Path) -> None:
        path = tmp_path / "notes.jsonl"
        s1 = NotesStore(path)
        s1.add(Note(vector=AttackVector.IDOR, target="example.com", observation="persisted"))
        s2 = NotesStore(path)
        assert len(s2.query()) == 1

    def test_corrupt_lines_skipped(self, tmp_path: Path) -> None:
        path = tmp_path / "notes.jsonl"
        path.write_text("not json\n{bad json\n", encoding="utf-8")
        store = NotesStore(path)
        assert store.query() == []

    def test_empty_store(self, tmp_path: Path) -> None:
        store = NotesStore(tmp_path / "absent.jsonl")
        assert store.query() == []
        assert store.by_vector() == {}
        assert store.board() == []
        assert store.coverage()["touched_count"] == 0


class TestEphemeralSessionScope:
    """The data must stay per-session and never touch the project — the store
    is in-memory by default and only persists when a path is explicitly given."""

    def test_default_constructor_is_ephemeral(self) -> None:
        store = NotesStore()
        assert store.is_ephemeral is True

    def test_explicit_path_is_persistent(self, tmp_path: Path) -> None:
        store = NotesStore(tmp_path / "notes.jsonl")
        assert store.is_ephemeral is False

    def test_ephemeral_writes_no_file(self, tmp_path: Path, monkeypatch) -> None:
        # Run from an empty cwd so a stray relative write would be visible.
        monkeypatch.chdir(tmp_path)
        store = NotesStore()
        store.add(Note(vector=AttackVector.IDOR, target="example.com", observation="kept in ram"))
        assert len(store.query()) == 1
        # Nothing was written anywhere under the session dir.
        assert list(tmp_path.iterdir()) == []

    def test_ephemeral_does_not_persist_across_instances(self) -> None:
        s1 = NotesStore()
        s1.add(Note(vector=AttackVector.SSRF, target="example.com", observation="gone after session"))
        s2 = NotesStore()
        assert s2.query() == []

    def test_clear_resets_session(self, tmp_path: Path) -> None:
        store = NotesStore()
        store.add(Note(vector=AttackVector.XSS, target="example.com", observation="o"))
        store.clear()
        assert store.query() == []

    def test_clear_keeps_backing_file_when_persistent(self, tmp_path: Path) -> None:
        path = tmp_path / "notes.jsonl"
        store = NotesStore(path)
        store.add(Note(vector=AttackVector.XSS, target="example.com", observation="persisted"))
        store.clear()
        # File untouched; a fresh store still reads the note back.
        assert NotesStore(path).query()[0]["observation"] == "persisted"


class TestSingleton:
    def test_get_notes_store_is_singleton(self, tmp_path: Path) -> None:
        import kambo.notes as notes_module
        notes_module._store = None  # reset for test isolation
        s1 = get_notes_store(tmp_path / "notes.jsonl")
        s2 = get_notes_store()
        assert s1 is s2
        notes_module._store = None

    def test_default_singleton_is_ephemeral(self, monkeypatch) -> None:
        import kambo.notes as notes_module
        notes_module._store = None
        monkeypatch.delenv("KAMBO_NOTES_PATH", raising=False)
        store = get_notes_store()
        assert store.is_ephemeral is True
        notes_module._store = None

    def test_config_opt_in_persists(self, tmp_path: Path, monkeypatch) -> None:
        import kambo.notes as notes_module
        notes_module._store = None
        monkeypatch.setenv("KAMBO_NOTES_PATH", str(tmp_path / "opt-in.jsonl"))
        store = get_notes_store()
        assert store.is_ephemeral is False
        notes_module._store = None
