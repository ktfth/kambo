"""Parser for Nuclei JSON output."""

from __future__ import annotations

import json


def parse_nuclei(raw: str) -> dict:
    """Parse nuclei JSONL output into structured findings.

    Nuclei outputs one JSON object per line when using -json flag.
    """
    findings = []

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue

        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        finding = {
            "template_id": entry.get("template-id", ""),
            "template_name": entry.get("info", {}).get("name", ""),
            "severity": entry.get("info", {}).get("severity", "unknown"),
            "host": entry.get("host", ""),
            "matched_at": entry.get("matched-at", ""),
            "type": entry.get("type", ""),
            "matcher_name": entry.get("matcher-name", ""),
            "extracted_results": entry.get("extracted-results", []),
            "description": entry.get("info", {}).get("description", ""),
            "references": entry.get("info", {}).get("reference", []),
            "tags": entry.get("info", {}).get("tags", []),
            "curl_command": entry.get("curl-command", ""),
        }
        findings.append(finding)

    # Group by severity
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f["severity"].lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    return {
        "findings": findings,
        "total": len(findings),
        "severity_counts": severity_counts,
    }
