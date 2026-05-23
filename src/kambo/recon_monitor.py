"""Continuous recon monitoring — detect changes in attack surface over time.

Stores snapshots of discovered assets and computes diffs between scans.
New subdomains, ports, or endpoints are flagged as opportunities.

Snapshots are persisted in the session database for cross-session comparison.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class ReconSnapshot(BaseModel):
    """A point-in-time snapshot of discovered assets."""

    target: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    subdomains: list[str] = Field(default_factory=list)
    ports: list[str] = Field(default_factory=list)  # "host:port" format
    urls: list[str] = Field(default_factory=list)
    endpoints: list[str] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    certificates: list[str] = Field(default_factory=list)

    model_config = {"frozen": True}


class ReconDiff(BaseModel):
    """Differences between two recon snapshots."""

    target: str
    baseline_time: datetime
    current_time: datetime
    new_subdomains: list[str] = Field(default_factory=list)
    removed_subdomains: list[str] = Field(default_factory=list)
    new_ports: list[str] = Field(default_factory=list)
    closed_ports: list[str] = Field(default_factory=list)
    new_urls: list[str] = Field(default_factory=list)
    new_endpoints: list[str] = Field(default_factory=list)
    new_technologies: list[str] = Field(default_factory=list)
    new_certificates: list[str] = Field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(
            self.new_subdomains
            or self.removed_subdomains
            or self.new_ports
            or self.closed_ports
            or self.new_urls
            or self.new_endpoints
            or self.new_technologies
            or self.new_certificates
        )

    @property
    def total_new(self) -> int:
        return (
            len(self.new_subdomains)
            + len(self.new_ports)
            + len(self.new_urls)
            + len(self.new_endpoints)
            + len(self.new_technologies)
            + len(self.new_certificates)
        )

    @property
    def opportunity_score(self) -> int:
        """Score new discoveries by potential value (0-100)."""
        score = 0
        score += len(self.new_subdomains) * 10  # new subdomains are high value
        score += len(self.new_ports) * 5
        score += len(self.new_urls) * 3
        score += len(self.new_endpoints) * 8  # new API endpoints are valuable
        score += len(self.new_technologies) * 2
        return min(100, score)

    def summary(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "target": self.target,
            "baseline": self.baseline_time.isoformat(),
            "current": self.current_time.isoformat(),
            "has_changes": self.has_changes,
            "total_new": self.total_new,
            "opportunity_score": self.opportunity_score,
        }
        if self.new_subdomains:
            result["new_subdomains"] = self.new_subdomains
        if self.removed_subdomains:
            result["removed_subdomains"] = self.removed_subdomains
        if self.new_ports:
            result["new_ports"] = self.new_ports
        if self.closed_ports:
            result["closed_ports"] = self.closed_ports
        if self.new_urls:
            result["new_urls"] = self.new_urls
        if self.new_endpoints:
            result["new_endpoints"] = self.new_endpoints
        if self.new_technologies:
            result["new_technologies"] = self.new_technologies
        if self.new_certificates:
            result["new_certificates"] = self.new_certificates
        return result


def diff_snapshots(baseline: ReconSnapshot, current: ReconSnapshot) -> ReconDiff:
    """Compute the difference between two snapshots."""
    baseline_subs = set(baseline.subdomains)
    current_subs = set(current.subdomains)
    baseline_ports = set(baseline.ports)
    current_ports = set(current.ports)

    return ReconDiff(
        target=current.target,
        baseline_time=baseline.timestamp,
        current_time=current.timestamp,
        new_subdomains=sorted(current_subs - baseline_subs),
        removed_subdomains=sorted(baseline_subs - current_subs),
        new_ports=sorted(current_ports - baseline_ports),
        closed_ports=sorted(baseline_ports - current_ports),
        new_urls=sorted(set(current.urls) - set(baseline.urls)),
        new_endpoints=sorted(set(current.endpoints) - set(baseline.endpoints)),
        new_technologies=sorted(set(current.technologies) - set(baseline.technologies)),
        new_certificates=sorted(set(current.certificates) - set(baseline.certificates)),
    )


def snapshot_from_pipeline(target: str) -> ReconSnapshot:
    """Create a snapshot from the current session pipeline state."""
    from kambo.pipeline import AssetType, get_pipeline

    pipeline = get_pipeline()

    return ReconSnapshot(
        target=target,
        subdomains=pipeline.get_values(AssetType.SUBDOMAIN),
        ports=pipeline.get_values(AssetType.PORT),
        urls=pipeline.get_values(AssetType.URL),
        endpoints=pipeline.get_values(AssetType.ENDPOINT),
        technologies=pipeline.get_values(AssetType.TECHNOLOGY),
    )


class ReconMonitor:
    """Stores and compares recon snapshots over time."""

    def __init__(self) -> None:
        self._snapshots: dict[str, list[ReconSnapshot]] = {}

    def store_snapshot(self, snapshot: ReconSnapshot) -> None:
        """Store a snapshot for a target."""
        if snapshot.target not in self._snapshots:
            self._snapshots[snapshot.target] = []
        self._snapshots[snapshot.target].append(snapshot)

    def get_latest(self, target: str) -> ReconSnapshot | None:
        """Get the most recent snapshot for a target."""
        snaps = self._snapshots.get(target, [])
        return snaps[-1] if snaps else None

    def get_baseline(self, target: str) -> ReconSnapshot | None:
        """Get the first (baseline) snapshot for a target."""
        snaps = self._snapshots.get(target, [])
        return snaps[0] if snaps else None

    def diff_latest(self, target: str) -> ReconDiff | None:
        """Diff the latest snapshot against the previous one."""
        snaps = self._snapshots.get(target, [])
        if len(snaps) < 2:
            return None
        return diff_snapshots(snaps[-2], snaps[-1])

    def diff_from_baseline(self, target: str) -> ReconDiff | None:
        """Diff the latest snapshot against the first baseline."""
        snaps = self._snapshots.get(target, [])
        if len(snaps) < 2:
            return None
        return diff_snapshots(snaps[0], snaps[-1])

    def snapshot_count(self, target: str) -> int:
        return len(self._snapshots.get(target, []))

    def all_targets(self) -> list[str]:
        return list(self._snapshots.keys())

    def to_json(self) -> str:
        """Serialize all snapshots for persistence."""
        data = {}
        for target, snaps in self._snapshots.items():
            data[target] = [s.model_dump(mode="json") for s in snaps]
        return json.dumps(data, default=str)

    @classmethod
    def from_json(cls, raw: str) -> ReconMonitor:
        """Restore from serialized data."""
        monitor = cls()
        data = json.loads(raw)
        for target, snaps in data.items():
            for s in snaps:
                monitor.store_snapshot(ReconSnapshot(**s))
        return monitor


# Singleton
_monitor: ReconMonitor | None = None


def get_monitor() -> ReconMonitor:
    global _monitor
    if _monitor is None:
        _monitor = ReconMonitor()
    return _monitor


def reset_monitor() -> ReconMonitor:
    global _monitor
    _monitor = ReconMonitor()
    return _monitor
