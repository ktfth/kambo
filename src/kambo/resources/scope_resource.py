"""Scope resource — exposes current engagement scope."""

from __future__ import annotations

from kambo.models import EngagementScope
from kambo.scope import get_scope_manager


def get_scope_data() -> dict:
    """Return current scope as a dictionary for MCP resource."""
    manager = get_scope_manager()
    scope = manager.scope

    if scope is None:
        return {"status": "no_scope_configured", "targets": []}

    return {
        "status": "active",
        "engagement_id": scope.engagement_id,
        "context": scope.context.value,
        "platform": scope.platform,
        "targets": [t.model_dump() for t in scope.targets],
        "exclusions": scope.exclusions,
        "rules": scope.rules,
        "created_at": scope.created_at.isoformat(),
    }
