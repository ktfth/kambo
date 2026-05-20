"""Session resource — quantified session intelligence."""

from __future__ import annotations

from collections import Counter

from kambo.database import get_database
from kambo.metrics import get_metrics


async def get_session_data(limit: int = 50) -> dict:
    """Return session log with tool execution stats and metrics."""
    db = await get_database()
    logs = await db.get_session_log(limit)
    metrics = get_metrics()

    # Compute tool execution stats
    tool_counter: Counter[str] = Counter()
    phase_counter: Counter[str] = Counter()
    total_duration = 0.0
    error_count = 0
    success_count = 0

    for log in logs:
        tool_counter[log.get("tool_name", "unknown")] += 1
        phase_counter[log.get("phase", "unknown")] += 1
        total_duration += log.get("duration_seconds", 0)
        if log.get("exit_code", 0) == 0:
            success_count += 1
        else:
            error_count += 1

    total = success_count + error_count
    slowest = max(logs, key=lambda l: l.get("duration_seconds", 0)) if logs else None

    return {
        "total_actions": len(logs),
        "stats": {
            "success_rate": f"{success_count / total:.0%}" if total > 0 else "N/A",
            "error_count": error_count,
            "total_duration_seconds": round(total_duration, 1),
            "avg_duration_seconds": round(total_duration / total, 1) if total > 0 else 0,
            "slowest_tool": {
                "name": slowest.get("tool_name", ""),
                "duration": slowest.get("duration_seconds", 0),
            } if slowest else None,
        },
        "by_tool": dict(tool_counter.most_common(20)),
        "by_phase": dict(phase_counter),
        "quality_metrics": metrics.aggregate_summary(),
        "recent_actions": logs[:20],
    }
