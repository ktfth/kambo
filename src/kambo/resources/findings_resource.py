"""Findings resource — quantified vulnerability intelligence."""

from __future__ import annotations

from kambo.database import get_database


async def get_findings_data(severity: str | None = None) -> dict:
    """Return findings with confidence distribution and phase breakdown."""
    db = await get_database()
    findings = await db.get_findings(severity)

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    confidence_counts = {"confirmed": 0, "firm": 0, "tentative": 0}
    phase_counts: dict[str, int] = {}
    tool_counts: dict[str, int] = {}

    for f in findings:
        sev = f.get("severity", "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

        conf = f.get("confidence", "tentative")
        confidence_counts[conf] = confidence_counts.get(conf, 0) + 1

        phase = f.get("phase", "unknown")
        phase_counts[phase] = phase_counts.get(phase, 0) + 1

        import json
        tools = f.get("tools_used", "[]")
        if isinstance(tools, str):
            try:
                tools = json.loads(tools)
            except json.JSONDecodeError:
                tools = []
        for tool in tools:
            tool_counts[tool] = tool_counts.get(tool, 0) + 1

    # Report-readiness indicator
    confirmed_firm = confidence_counts["confirmed"] + confidence_counts["firm"]
    total = len(findings)
    report_ready = confirmed_firm >= 1 and (confirmed_firm / total >= 0.5 if total > 0 else False)

    return {
        "total": total,
        "severity_counts": severity_counts,
        "confidence_counts": confidence_counts,
        "phase_counts": phase_counts,
        "tool_counts": tool_counts,
        "report_ready": report_ready,
        "report_ready_reason": (
            f"{confirmed_firm}/{total} findings are CONFIRMED or FIRM"
            if total > 0 else "No findings yet"
        ),
        "findings": findings,
    }
