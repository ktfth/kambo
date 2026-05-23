"""Tests for learnings persistence system."""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

from kambo.learnings import Learning, LearningsStore, _decayed_confidence


class TestLearning:
    def test_create_learning(self) -> None:
        l = Learning(
            type="pattern",
            key="sqli_php_high_rate",
            insight="SQLi on PHP apps yields CONFIRMED 80% of the time",
            confidence=8,
            source="observed",
            skill="pattern_analyzer",
        )
        assert l.type == "pattern"
        assert l.confidence == 8

    def test_learning_is_frozen(self) -> None:
        l = Learning(type="pattern", key="test", insight="test")
        with pytest.raises(Exception):
            l.type = "pitfall"  # type: ignore


class TestConfidenceDecay:
    def test_no_decay_within_30_days(self) -> None:
        now = datetime.now(timezone.utc)
        l = Learning(
            type="pattern", key="k", insight="i", confidence=8,
            timestamp=(now - timedelta(days=15)).isoformat(),
        )
        assert _decayed_confidence(l, now) == 8

    def test_one_point_decay_after_30_days(self) -> None:
        now = datetime.now(timezone.utc)
        l = Learning(
            type="pattern", key="k", insight="i", confidence=8,
            timestamp=(now - timedelta(days=35)).isoformat(),
        )
        assert _decayed_confidence(l, now) == 7

    def test_two_points_decay_after_60_days(self) -> None:
        now = datetime.now(timezone.utc)
        l = Learning(
            type="pattern", key="k", insight="i", confidence=8,
            timestamp=(now - timedelta(days=65)).isoformat(),
        )
        assert _decayed_confidence(l, now) == 6

    def test_minimum_confidence_is_1(self) -> None:
        now = datetime.now(timezone.utc)
        l = Learning(
            type="pattern", key="k", insight="i", confidence=2,
            timestamp=(now - timedelta(days=365)).isoformat(),
        )
        assert _decayed_confidence(l, now) >= 1


class TestLearningsStore:
    def _make_store(self, tmp_path: Path) -> LearningsStore:
        return LearningsStore(tmp_path / "learnings.jsonl")

    def test_log_and_search(self, tmp_path: Path) -> None:
        store = self._make_store(tmp_path)
        store.log(Learning(type="pattern", key="k1", insight="test insight", confidence=7))
        results = store.search()
        assert len(results) == 1
        assert results[0]["key"] == "k1"

    def test_dedup_latest_wins(self, tmp_path: Path) -> None:
        store = self._make_store(tmp_path)
        store.log(Learning(type="pattern", key="k1", insight="old", confidence=5))
        store.log(Learning(type="pattern", key="k1", insight="new", confidence=8))
        results = store.search()
        assert len(results) == 1
        assert results[0]["insight"] == "new"
        assert results[0]["original_confidence"] == 8

    def test_type_filter(self, tmp_path: Path) -> None:
        store = self._make_store(tmp_path)
        store.log(Learning(type="pattern", key="k1", insight="pattern"))
        store.log(Learning(type="pitfall", key="k2", insight="pitfall"))
        results = store.search(type_filter="pitfall")
        assert len(results) == 1
        assert results[0]["type"] == "pitfall"

    def test_keyword_search(self, tmp_path: Path) -> None:
        store = self._make_store(tmp_path)
        store.log(Learning(type="pattern", key="k1", insight="SQLi on PHP apps"))
        store.log(Learning(type="pattern", key="k2", insight="XSS on React apps"))
        results = store.search(keyword="PHP")
        assert len(results) == 1
        assert "PHP" in results[0]["insight"]

    def test_min_confidence_filter(self, tmp_path: Path) -> None:
        store = self._make_store(tmp_path)
        store.log(Learning(type="pattern", key="k1", insight="strong", confidence=9))
        store.log(Learning(type="pattern", key="k2", insight="weak", confidence=2))
        results = store.search(min_confidence=5)
        assert len(results) == 1
        assert results[0]["key"] == "k1"

    def test_persistence_across_instances(self, tmp_path: Path) -> None:
        path = tmp_path / "learnings.jsonl"
        store1 = LearningsStore(path)
        store1.log(Learning(type="pattern", key="k1", insight="persisted"))

        store2 = LearningsStore(path)
        results = store2.search()
        assert len(results) == 1

    def test_prune_low_confidence(self, tmp_path: Path) -> None:
        now = datetime.now(timezone.utc)
        store = self._make_store(tmp_path)
        # This one will decay below threshold
        store.log(Learning(
            type="pattern", key="old",
            insight="very old", confidence=2,
            timestamp=(now - timedelta(days=120)).isoformat(),
        ))
        store.log(Learning(type="pattern", key="new", insight="fresh", confidence=8))
        removed = store.prune(min_confidence=2)
        assert removed == 1
        assert store.count() == 1

    def test_corrupt_lines_skipped(self, tmp_path: Path) -> None:
        path = tmp_path / "learnings.jsonl"
        path.write_text("not json\n{bad json\n", encoding="utf-8")
        store = LearningsStore(path)
        results = store.search()
        assert len(results) == 0

    def test_limit(self, tmp_path: Path) -> None:
        store = self._make_store(tmp_path)
        for i in range(10):
            store.log(Learning(type="pattern", key=f"k{i}", insight=f"insight {i}", confidence=5))
        results = store.search(limit=3)
        assert len(results) == 3
