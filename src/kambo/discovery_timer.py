"""Discovery timer — track time spent per phase and tool.

Provides real-time ROI calculations when combined with bounty pricing.
Persists timing data to allow cross-session analysis.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class TimerEvent(BaseModel):
    """A single timing record."""

    phase: str
    tool_name: str = ""
    target: str = ""
    started_at: datetime
    ended_at: datetime | None = None
    duration_seconds: float = 0

    model_config = {"frozen": True}


class PhaseStats(BaseModel):
    """Aggregated stats for a single phase."""

    phase: str
    total_seconds: float = 0
    tool_count: int = 0
    tools_used: list[str] = Field(default_factory=list)
    findings_during: int = 0

    @property
    def total_minutes(self) -> float:
        return round(self.total_seconds / 60, 1)

    @property
    def total_hours(self) -> float:
        return round(self.total_seconds / 3600, 2)


class DiscoveryTimer(BaseModel):
    """Tracks time across phases and tools for ROI calculation."""

    events: list[TimerEvent] = Field(default_factory=list)
    session_start: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    _active_phase: str | None = None
    _phase_start: datetime | None = None
    _active_tool: str | None = None
    _tool_start: datetime | None = None

    model_config = {"arbitrary_types_allowed": True}

    def start_phase(self, phase: str) -> None:
        """Begin timing a new phase. Ends the previous phase if active."""
        now = datetime.now(timezone.utc)
        if self._active_phase is not None:
            self._end_current_phase(now)
        object.__setattr__(self, "_active_phase", phase)
        object.__setattr__(self, "_phase_start", now)

    def start_tool(self, tool_name: str, target: str = "") -> None:
        """Begin timing a tool execution within the current phase."""
        now = datetime.now(timezone.utc)
        if self._active_tool is not None:
            self._end_current_tool(now)
        object.__setattr__(self, "_active_tool", tool_name)
        object.__setattr__(self, "_tool_start", now)
        object.__setattr__(self, "_active_target", target)

    def end_tool(self) -> float:
        """End timing the current tool. Returns duration in seconds."""
        now = datetime.now(timezone.utc)
        return self._end_current_tool(now)

    def end_phase(self) -> float:
        """End timing the current phase. Returns duration in seconds."""
        now = datetime.now(timezone.utc)
        return self._end_current_phase(now)

    def _end_current_tool(self, now: datetime) -> float:
        if self._active_tool is None or self._tool_start is None:
            return 0
        duration = (now - self._tool_start).total_seconds()
        target = getattr(self, "_active_target", "")
        event = TimerEvent(
            phase=self._active_phase or "unknown",
            tool_name=self._active_tool,
            target=target,
            started_at=self._tool_start,
            ended_at=now,
            duration_seconds=round(duration, 2),
        )
        self.events.append(event)
        object.__setattr__(self, "_active_tool", None)
        object.__setattr__(self, "_tool_start", None)
        object.__setattr__(self, "_active_target", "")
        return duration

    def _end_current_phase(self, now: datetime) -> float:
        # End any active tool first
        if self._active_tool is not None:
            self._end_current_tool(now)
        if self._active_phase is None or self._phase_start is None:
            return 0
        duration = (now - self._phase_start).total_seconds()
        # Record a phase-level event (no tool_name)
        event = TimerEvent(
            phase=self._active_phase,
            started_at=self._phase_start,
            ended_at=now,
            duration_seconds=round(duration, 2),
        )
        self.events.append(event)
        object.__setattr__(self, "_active_phase", None)
        object.__setattr__(self, "_phase_start", None)
        return duration

    @property
    def total_seconds(self) -> float:
        """Total time tracked across all events (tool-level only to avoid double counting)."""
        tool_events = [e for e in self.events if e.tool_name]
        if tool_events:
            return sum(e.duration_seconds for e in tool_events)
        # Fallback to phase events if no tool events
        return sum(e.duration_seconds for e in self.events)

    @property
    def total_hours(self) -> float:
        return round(self.total_seconds / 3600, 2)

    def phase_stats(self) -> dict[str, PhaseStats]:
        """Get aggregated stats per phase."""
        phases: dict[str, PhaseStats] = {}
        for event in self.events:
            if event.phase not in phases:
                phases[event.phase] = PhaseStats(phase=event.phase)
            stats = phases[event.phase]
            if event.tool_name:
                stats.total_seconds += event.duration_seconds
                stats.tool_count += 1
                if event.tool_name not in stats.tools_used:
                    stats.tools_used.append(event.tool_name)
        return phases

    def tool_stats(self) -> dict[str, dict[str, Any]]:
        """Get aggregated stats per tool."""
        tools: dict[str, dict[str, Any]] = {}
        for event in self.events:
            if not event.tool_name:
                continue
            if event.tool_name not in tools:
                tools[event.tool_name] = {
                    "tool": event.tool_name,
                    "total_seconds": 0,
                    "runs": 0,
                    "avg_seconds": 0,
                    "slowest_seconds": 0,
                }
            t = tools[event.tool_name]
            t["total_seconds"] += event.duration_seconds
            t["runs"] += 1
            t["avg_seconds"] = round(t["total_seconds"] / t["runs"], 2)
            t["slowest_seconds"] = max(t["slowest_seconds"], event.duration_seconds)
        return tools

    def summary(self) -> dict[str, Any]:
        """Full timing summary for the session."""
        now = datetime.now(timezone.utc)
        wall_clock = (now - self.session_start).total_seconds()

        phase_data = {}
        for name, stats in self.phase_stats().items():
            phase_data[name] = {
                "total_minutes": stats.total_minutes,
                "total_hours": stats.total_hours,
                "tools_used": stats.tools_used,
                "tool_runs": stats.tool_count,
            }

        tool_data = self.tool_stats()

        # Find slowest tool
        slowest = max(tool_data.values(), key=lambda t: t["slowest_seconds"]) if tool_data else None

        return {
            "session_start": self.session_start.isoformat(),
            "wall_clock_hours": round(wall_clock / 3600, 2),
            "active_hours": self.total_hours,
            "total_events": len(self.events),
            "phases": phase_data,
            "tools": {k: {
                "runs": v["runs"],
                "total_minutes": round(v["total_seconds"] / 60, 1),
                "avg_seconds": v["avg_seconds"],
            } for k, v in tool_data.items()},
            "slowest_tool": {
                "name": slowest["tool"],
                "seconds": slowest["slowest_seconds"],
            } if slowest else None,
        }

    def to_db_rows(self) -> list[dict[str, Any]]:
        """Serialize events for database persistence."""
        return [
            {
                "phase": e.phase,
                "tool_name": e.tool_name,
                "target": e.target,
                "started_at": e.started_at.isoformat(),
                "ended_at": e.ended_at.isoformat() if e.ended_at else None,
                "duration_seconds": e.duration_seconds,
            }
            for e in self.events
            if e.ended_at is not None  # only persist completed events
        ]


# Singleton
_timer: DiscoveryTimer | None = None


def get_timer() -> DiscoveryTimer:
    global _timer
    if _timer is None:
        _timer = DiscoveryTimer()
    return _timer


def reset_timer() -> DiscoveryTimer:
    """Reset the timer for a new session."""
    global _timer
    _timer = DiscoveryTimer()
    return _timer
