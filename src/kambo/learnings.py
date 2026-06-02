"""Learnings persistence — cross-session pattern memory.

Inspired by gstack's learnings system: append-only JSONL store with
confidence scoring, decay over time, and deduplication by key+type.

Learning types:
  - pattern: positive patterns observed (e.g., "SQLi on PHP apps yields CONFIRMED 80%")
  - pitfall: risks or gotchas (e.g., "CORS on CDN domains always FP")
  - calibration: weight/threshold adjustments from user feedback
  - operational: workflow improvements (e.g., "run recon_dns before subdomain enum")
  - tool_perf: tool-specific performance data (e.g., "nuclei avg 45s on large scope")
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class Learning(BaseModel):
    """A single learned insight."""

    type: str  # pattern, pitfall, calibration, operational, tool_perf
    key: str  # dedup key (e.g., "sqli_php_confirmed_rate")
    insight: str  # human-readable description
    confidence: int = 5  # 1-10, decays over time
    source: str = "observed"  # observed, inferred, user_feedback, calibration
    skill: str = ""  # which skill/tool produced this
    data: dict[str, Any] = Field(default_factory=dict)  # structured evidence
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    model_config = {"frozen": True}


# Confidence decay: lose 1 point per 30 days of inactivity
_DECAY_DAYS = 30


def _decayed_confidence(learning: Learning, now: datetime | None = None) -> int:
    """Apply time-based confidence decay."""
    now = now or datetime.now(timezone.utc)
    try:
        ts = datetime.fromisoformat(learning.timestamp)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        age_days = (now - ts).days
        decay = age_days // _DECAY_DAYS
        return max(1, learning.confidence - decay)
    except (ValueError, TypeError):
        return learning.confidence


class LearningsStore:
    """Append-only JSONL store with deduplication and decay."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._learnings: list[Learning] = []
        self._loaded = False

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        if not self._path.exists():
            return
        for line in self._path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                self._learnings.append(Learning(**data))
            except (json.JSONDecodeError, Exception):
                continue  # skip corrupt entries

    def log(self, learning: Learning) -> None:
        """Append a learning entry. Deduplicates by key+type at read time."""
        self._ensure_loaded()
        self._learnings.append(learning)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(learning.model_dump(), default=str) + "\n")

    def search(
        self,
        type_filter: str | None = None,
        keyword: str | None = None,
        min_confidence: int = 1,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Search learnings with dedup (latest per key+type wins) and decay."""
        self._ensure_loaded()
        now = datetime.now(timezone.utc)

        # Dedup: last entry per (key, type) wins
        deduped: dict[tuple[str, str], Learning] = {}
        for l in self._learnings:
            deduped[(l.key, l.type)] = l

        results = []
        for l in deduped.values():
            conf = _decayed_confidence(l, now)
            if conf < min_confidence:
                continue
            if type_filter and l.type != type_filter:
                continue
            if keyword and keyword.lower() not in l.insight.lower():
                continue
            results.append({
                "type": l.type,
                "key": l.key,
                "insight": l.insight,
                "confidence": conf,
                "original_confidence": l.confidence,
                "source": l.source,
                "skill": l.skill,
                "data": l.data,
                "timestamp": l.timestamp,
            })

        # Sort by confidence desc, then recency (newest first for same confidence)
        results.sort(key=lambda r: (r["confidence"], r["timestamp"]), reverse=True)
        return results[:limit]

    def get_all(self) -> list[Learning]:
        """Get all raw learnings (no dedup/decay)."""
        self._ensure_loaded()
        return list(self._learnings)

    def count(self) -> int:
        self._ensure_loaded()
        return len(self._learnings)

    def prune(self, min_confidence: int = 2) -> int:
        """Remove entries below min_confidence after decay. Returns count removed."""
        self._ensure_loaded()
        now = datetime.now(timezone.utc)
        before = len(self._learnings)
        self._learnings = [
            l for l in self._learnings
            if _decayed_confidence(l, now) >= min_confidence
        ]
        removed = before - len(self._learnings)
        if removed > 0:
            self._rewrite()
        return removed

    def _rewrite(self) -> None:
        """Rewrite the JSONL file from in-memory state."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("w", encoding="utf-8") as f:
            for l in self._learnings:
                f.write(json.dumps(l.model_dump(), default=str) + "\n")


# Project-scoped singleton
_store: LearningsStore | None = None
_LEARNINGS_PATH = Path.home() / ".kambo" / "learnings.jsonl"


def get_learnings_store(path: Path | None = None) -> LearningsStore:
    global _store
    if _store is None:
        _store = LearningsStore(path or _LEARNINGS_PATH)
    return _store
