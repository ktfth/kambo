"""Tests for discovery timer — phase/tool timing and ROI tracking."""

from __future__ import annotations

import time
from datetime import datetime, timezone

from kambo.discovery_timer import (
    DiscoveryTimer,
    PhaseStats,
    TimerEvent,
    get_timer,
    reset_timer,
)


class TestTimerEvent:
    def test_frozen_model(self) -> None:
        now = datetime.now(timezone.utc)
        event = TimerEvent(phase="recon", started_at=now)
        assert event.phase == "recon"
        assert event.tool_name == ""
        assert event.ended_at is None
        assert event.duration_seconds == 0

    def test_event_with_tool(self) -> None:
        now = datetime.now(timezone.utc)
        event = TimerEvent(
            phase="recon",
            tool_name="recon_subdomains",
            target="example.com",
            started_at=now,
            ended_at=now,
            duration_seconds=5.5,
        )
        assert event.tool_name == "recon_subdomains"
        assert event.target == "example.com"
        assert event.duration_seconds == 5.5


class TestPhaseStats:
    def test_total_minutes(self) -> None:
        stats = PhaseStats(phase="recon", total_seconds=120)
        assert stats.total_minutes == 2.0

    def test_total_hours(self) -> None:
        stats = PhaseStats(phase="recon", total_seconds=3600)
        assert stats.total_hours == 1.0

    def test_defaults(self) -> None:
        stats = PhaseStats(phase="vuln_analysis")
        assert stats.tool_count == 0
        assert stats.tools_used == []
        assert stats.findings_during == 0


class TestDiscoveryTimer:
    def test_start_and_end_phase(self) -> None:
        timer = DiscoveryTimer()
        timer.start_phase("recon")
        time.sleep(0.01)
        duration = timer.end_phase()
        assert duration > 0
        assert len(timer.events) == 1
        assert timer.events[0].phase == "recon"
        assert timer.events[0].tool_name == ""

    def test_start_and_end_tool(self) -> None:
        timer = DiscoveryTimer()
        timer.start_phase("recon")
        timer.start_tool("recon_dns", target="example.com")
        time.sleep(0.01)
        duration = timer.end_tool()
        assert duration > 0
        # Tool event recorded
        tool_events = [e for e in timer.events if e.tool_name]
        assert len(tool_events) == 1
        assert tool_events[0].tool_name == "recon_dns"
        assert tool_events[0].target == "example.com"

    def test_switching_phases_ends_previous(self) -> None:
        timer = DiscoveryTimer()
        timer.start_phase("recon")
        time.sleep(0.01)
        timer.start_phase("vuln_analysis")
        # First phase should have been ended automatically
        phase_events = [e for e in timer.events if not e.tool_name]
        assert len(phase_events) == 1
        assert phase_events[0].phase == "recon"

    def test_switching_tools_ends_previous(self) -> None:
        timer = DiscoveryTimer()
        timer.start_phase("recon")
        timer.start_tool("tool_a")
        time.sleep(0.01)
        timer.start_tool("tool_b")
        tool_events = [e for e in timer.events if e.tool_name]
        assert len(tool_events) == 1
        assert tool_events[0].tool_name == "tool_a"

    def test_end_phase_also_ends_active_tool(self) -> None:
        timer = DiscoveryTimer()
        timer.start_phase("recon")
        timer.start_tool("recon_dns")
        time.sleep(0.01)
        timer.end_phase()
        # Both tool and phase events should be recorded
        assert len(timer.events) == 2
        tool_events = [e for e in timer.events if e.tool_name]
        phase_events = [e for e in timer.events if not e.tool_name]
        assert len(tool_events) == 1
        assert len(phase_events) == 1

    def test_end_tool_noop_when_no_active(self) -> None:
        timer = DiscoveryTimer()
        result = timer.end_tool()
        assert result == 0

    def test_end_phase_noop_when_no_active(self) -> None:
        timer = DiscoveryTimer()
        result = timer.end_phase()
        assert result == 0

    def test_total_seconds_prefers_tool_events(self) -> None:
        timer = DiscoveryTimer()
        timer.start_phase("recon")
        timer.start_tool("tool_a")
        time.sleep(0.01)
        timer.end_tool()
        timer.end_phase()
        # total_seconds should use tool events (not double-count with phase events)
        total = timer.total_seconds
        tool_total = sum(e.duration_seconds for e in timer.events if e.tool_name)
        assert total == tool_total

    def test_total_seconds_falls_back_to_phase_events(self) -> None:
        timer = DiscoveryTimer()
        timer.start_phase("recon")
        time.sleep(0.01)
        timer.end_phase()
        # No tool events, should use phase events
        assert timer.total_seconds > 0

    def test_total_hours(self) -> None:
        timer = DiscoveryTimer()
        timer.start_phase("recon")
        time.sleep(0.01)
        timer.end_phase()
        assert timer.total_hours >= 0

    def test_phase_stats_aggregation(self) -> None:
        timer = DiscoveryTimer()
        timer.start_phase("recon")
        timer.start_tool("tool_a")
        time.sleep(0.01)
        timer.end_tool()
        timer.start_tool("tool_b")
        time.sleep(0.01)
        timer.end_tool()
        timer.end_phase()

        stats = timer.phase_stats()
        assert "recon" in stats
        recon = stats["recon"]
        assert recon.tool_count == 2
        assert "tool_a" in recon.tools_used
        assert "tool_b" in recon.tools_used
        assert recon.total_seconds > 0

    def test_tool_stats_aggregation(self) -> None:
        timer = DiscoveryTimer()
        timer.start_phase("recon")
        # Run same tool twice
        timer.start_tool("recon_dns")
        time.sleep(0.01)
        timer.end_tool()
        timer.start_tool("recon_dns")
        time.sleep(0.01)
        timer.end_tool()
        timer.end_phase()

        stats = timer.tool_stats()
        assert "recon_dns" in stats
        dns = stats["recon_dns"]
        assert dns["runs"] == 2
        assert dns["total_seconds"] > 0
        assert dns["avg_seconds"] > 0
        assert dns["slowest_seconds"] > 0

    def test_summary_structure(self) -> None:
        timer = DiscoveryTimer()
        timer.start_phase("recon")
        timer.start_tool("recon_dns", target="example.com")
        time.sleep(0.01)
        timer.end_tool()
        timer.end_phase()

        summary = timer.summary()
        assert "session_start" in summary
        assert "wall_clock_hours" in summary
        assert "active_hours" in summary
        assert "total_events" in summary
        assert "phases" in summary
        assert "tools" in summary
        assert "slowest_tool" in summary
        assert summary["slowest_tool"]["name"] == "recon_dns"

    def test_summary_no_tools(self) -> None:
        timer = DiscoveryTimer()
        summary = timer.summary()
        assert summary["total_events"] == 0
        assert summary["slowest_tool"] is None

    def test_to_db_rows(self) -> None:
        timer = DiscoveryTimer()
        timer.start_phase("recon")
        timer.start_tool("recon_dns", target="example.com")
        time.sleep(0.01)
        timer.end_tool()
        timer.end_phase()

        rows = timer.to_db_rows()
        # Only completed events (with ended_at)
        assert len(rows) == 2
        for row in rows:
            assert "phase" in row
            assert "started_at" in row
            assert "ended_at" in row
            assert row["ended_at"] is not None

    def test_to_db_rows_excludes_incomplete(self) -> None:
        timer = DiscoveryTimer()
        timer.start_phase("recon")
        timer.start_tool("recon_dns")
        # Don't end tool — should not appear in db rows
        # But we need at least one completed event
        timer.end_tool()
        # Start another without ending
        timer.start_tool("recon_ports")

        rows = timer.to_db_rows()
        assert len(rows) == 1
        assert rows[0]["tool_name"] == "recon_dns"


class TestSingleton:
    def test_get_timer_returns_same_instance(self) -> None:
        t1 = get_timer()
        t2 = get_timer()
        assert t1 is t2

    def test_reset_timer_creates_new(self) -> None:
        t1 = get_timer()
        t2 = reset_timer()
        assert t1 is not t2
        # Next get_timer should return the reset one
        t3 = get_timer()
        assert t3 is t2
