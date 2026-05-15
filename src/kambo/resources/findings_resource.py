"""Findings resource — exposes discovered vulnerabilities."""

from __future__ import annotations

from kambo.database import get_database


async def get_findings_data(severity: str | None = None) -> dict:
    """Return findings for MCP resource."""
    db = await get_database()
    findings = await db.get_findings(severity)

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return {
        "total": len(findings),
        "severity_counts": severity_counts,
        "findings": findings,
    }
