"""Session resource — exposes session log and current phase."""

from __future__ import annotations

from kambo.database import get_database


async def get_session_data(limit: int = 50) -> dict:
    """Return session log for MCP resource."""
    db = await get_database()
    logs = await db.get_session_log(limit)

    return {
        "total_actions": len(logs),
        "recent_actions": logs,
    }
