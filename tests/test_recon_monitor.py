"""Tests for continuous recon monitoring and diff detection."""

from __future__ import annotations

from datetime import datetime, timezone

from kambo.recon_monitor import (
    ReconDiff,
    ReconMonitor,
    ReconSnapshot,
    diff_snapshots,
    get_monitor,
    reset_monitor,
    snapshot_from_pipeline,
)


class TestReconSnapshot:
    def test_create_snapshot(self) -> None:
        snap = ReconSnapshot(
            target="example.com",
            subdomains=["a.example.com", "b.example.com"],
            ports=["example.com:80", "example.com:443"],
        )
        assert snap.target == "example.com"
        assert len(snap.subdomains) == 2


class TestDiffSnapshots:
    def test_new_subdomains(self) -> None:
        baseline = ReconSnapshot(
            target="example.com",
            subdomains=["a.example.com", "b.example.com"],
        )
        current = ReconSnapshot(
            target="example.com",
            subdomains=["a.example.com", "b.example.com", "c.example.com"],
        )
        diff = diff_snapshots(baseline, current)
        assert diff.new_subdomains == ["c.example.com"]
        assert diff.removed_subdomains == []
        assert diff.has_changes is True

    def test_removed_subdomains(self) -> None:
        baseline = ReconSnapshot(
            target="example.com",
            subdomains=["a.example.com", "b.example.com"],
        )
        current = ReconSnapshot(
            target="example.com",
            subdomains=["a.example.com"],
        )
        diff = diff_snapshots(baseline, current)
        assert diff.removed_subdomains == ["b.example.com"]

    def test_new_ports(self) -> None:
        baseline = ReconSnapshot(target="example.com", ports=["example.com:80"])
        current = ReconSnapshot(target="example.com", ports=["example.com:80", "example.com:8080"])
        diff = diff_snapshots(baseline, current)
        assert diff.new_ports == ["example.com:8080"]

    def test_no_changes(self) -> None:
        snap = ReconSnapshot(
            target="example.com",
            subdomains=["a.example.com"],
            ports=["example.com:80"],
        )
        diff = diff_snapshots(snap, snap)
        assert diff.has_changes is False
        assert diff.total_new == 0
        assert diff.opportunity_score == 0

    def test_new_endpoints(self) -> None:
        baseline = ReconSnapshot(target="example.com", endpoints=["/api/v1/users"])
        current = ReconSnapshot(target="example.com", endpoints=["/api/v1/users", "/api/v2/admin"])
        diff = diff_snapshots(baseline, current)
        assert diff.new_endpoints == ["/api/v2/admin"]

    def test_opportunity_score(self) -> None:
        baseline = ReconSnapshot(target="example.com")
        current = ReconSnapshot(
            target="example.com",
            subdomains=["new1.example.com", "new2.example.com"],
            endpoints=["/api/secret"],
        )
        diff = diff_snapshots(baseline, current)
        # 2 subdomains * 10 + 1 endpoint * 8 = 28
        assert diff.opportunity_score == 28

    def test_summary_keys(self) -> None:
        baseline = ReconSnapshot(target="example.com")
        current = ReconSnapshot(target="example.com", subdomains=["new.example.com"])
        diff = diff_snapshots(baseline, current)
        summary = diff.summary()
        assert "target" in summary
        assert "has_changes" in summary
        assert "total_new" in summary
        assert "opportunity_score" in summary
        assert "new_subdomains" in summary


class TestReconMonitor:
    def test_store_and_retrieve(self) -> None:
        monitor = ReconMonitor()
        snap = ReconSnapshot(target="example.com", subdomains=["a.example.com"])
        monitor.store_snapshot(snap)
        assert monitor.get_latest("example.com") == snap
        assert monitor.snapshot_count("example.com") == 1

    def test_diff_latest(self) -> None:
        monitor = ReconMonitor()
        snap1 = ReconSnapshot(target="example.com", subdomains=["a.example.com"])
        snap2 = ReconSnapshot(target="example.com", subdomains=["a.example.com", "b.example.com"])
        monitor.store_snapshot(snap1)
        monitor.store_snapshot(snap2)
        diff = monitor.diff_latest("example.com")
        assert diff is not None
        assert diff.new_subdomains == ["b.example.com"]

    def test_diff_latest_not_enough_snapshots(self) -> None:
        monitor = ReconMonitor()
        snap = ReconSnapshot(target="example.com")
        monitor.store_snapshot(snap)
        assert monitor.diff_latest("example.com") is None

    def test_diff_from_baseline(self) -> None:
        monitor = ReconMonitor()
        snap1 = ReconSnapshot(target="example.com", subdomains=["a.example.com"])
        snap2 = ReconSnapshot(target="example.com", subdomains=["a.example.com", "b.example.com"])
        snap3 = ReconSnapshot(target="example.com", subdomains=["a.example.com", "b.example.com", "c.example.com"])
        monitor.store_snapshot(snap1)
        monitor.store_snapshot(snap2)
        monitor.store_snapshot(snap3)
        diff = monitor.diff_from_baseline("example.com")
        assert diff is not None
        assert set(diff.new_subdomains) == {"b.example.com", "c.example.com"}

    def test_all_targets(self) -> None:
        monitor = ReconMonitor()
        monitor.store_snapshot(ReconSnapshot(target="a.com"))
        monitor.store_snapshot(ReconSnapshot(target="b.com"))
        assert set(monitor.all_targets()) == {"a.com", "b.com"}

    def test_json_roundtrip(self) -> None:
        monitor = ReconMonitor()
        snap = ReconSnapshot(
            target="example.com",
            subdomains=["a.example.com"],
            ports=["example.com:80"],
        )
        monitor.store_snapshot(snap)
        raw = monitor.to_json()
        restored = ReconMonitor.from_json(raw)
        assert restored.snapshot_count("example.com") == 1
        latest = restored.get_latest("example.com")
        assert latest is not None
        assert latest.subdomains == ["a.example.com"]


class TestSnapshotFromPipeline:
    def test_creates_from_pipeline(self) -> None:
        from kambo.pipeline import SessionPipeline, reset_pipeline
        pipeline = reset_pipeline()
        pipeline.ingest("recon_subdomains", {"subdomains": ["a.example.com", "b.example.com"]})
        pipeline.ingest("recon_ports_fast", {"target": "example.com", "ports": [80, 443]})
        snap = snapshot_from_pipeline("example.com")
        assert snap.target == "example.com"
        assert len(snap.subdomains) == 2
        assert len(snap.ports) == 2


class TestSingleton:
    def test_get_monitor(self) -> None:
        m1 = get_monitor()
        m2 = get_monitor()
        assert m1 is m2

    def test_reset_monitor(self) -> None:
        m1 = get_monitor()
        m2 = reset_monitor()
        assert m1 is not m2
