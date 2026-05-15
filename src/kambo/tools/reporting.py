"""Phase 6: Reporting tools."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from kambo.database import get_database
from kambo.models import Finding, Phase, Severity


async def report_finding(
    title: str,
    severity: str,
    target: str,
    description: str,
    reproduction_steps: list[str] | None = None,
    impact: str = "",
    remediation: str = "",
    cvss: float | None = None,
    cvss_vector: str = "",
    references: list[str] | None = None,
    tools_used: list[str] | None = None,
    evidence: dict | None = None,
) -> dict:
    """Create and store a security finding.

    Args:
        title: Finding title (e.g., "SQL Injection in /api/users")
        severity: critical, high, medium, low, info
        target: Affected target/endpoint
        description: Technical description of the vulnerability
        reproduction_steps: Steps to reproduce
        impact: Business/technical impact statement
        remediation: Fix recommendation
        cvss: CVSS 3.1 score
        cvss_vector: CVSS vector string
        references: CWE, OWASP references
        tools_used: Tools used to discover
        evidence: Request/response evidence
    """
    db = await get_database()

    # Generate ID
    existing = await db.get_findings()
    finding_id = f"FIND-{len(existing) + 1:03d}"

    finding = Finding(
        id=finding_id,
        title=title,
        severity=Severity(severity.lower()),
        cvss=cvss,
        cvss_vector=cvss_vector,
        phase=Phase.VULN_ANALYSIS,
        target=target,
        description=description,
        reproduction_steps=reproduction_steps or [],
        impact=impact,
        remediation=remediation,
        references=references or [],
        tools_used=tools_used or [],
        evidence=evidence or {},
    )

    await db.save_finding(finding)

    return {
        "id": finding_id,
        "status": "saved",
        "finding": finding.model_dump(mode="json"),
    }


async def report_cvss(
    attack_vector: str = "N",
    attack_complexity: str = "L",
    privileges_required: str = "N",
    user_interaction: str = "N",
    scope: str = "U",
    confidentiality: str = "H",
    integrity: str = "H",
    availability: str = "H",
) -> dict:
    """Calculate CVSS 3.1 score from metrics.

    Args:
        attack_vector: N(etwork), A(djacent), L(ocal), P(hysical)
        attack_complexity: L(ow), H(igh)
        privileges_required: N(one), L(ow), H(igh)
        user_interaction: N(one), R(equired)
        scope: U(nchanged), C(hanged)
        confidentiality: N(one), L(ow), H(igh)
        integrity: N(one), L(ow), H(igh)
        availability: N(one), L(ow), H(igh)
    """
    # CVSS 3.1 base score calculation
    av_scores = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    ac_scores = {"L": 0.77, "H": 0.44}
    pr_scores_unchanged = {"N": 0.85, "L": 0.62, "H": 0.27}
    pr_scores_changed = {"N": 0.85, "L": 0.68, "H": 0.50}
    ui_scores = {"N": 0.85, "R": 0.62}
    cia_scores = {"N": 0, "L": 0.22, "H": 0.56}

    pr_scores = pr_scores_changed if scope == "C" else pr_scores_unchanged

    exploitability = 8.22 * av_scores[attack_vector] * ac_scores[attack_complexity] * pr_scores[privileges_required] * ui_scores[user_interaction]

    isc_base = 1 - ((1 - cia_scores[confidentiality]) * (1 - cia_scores[integrity]) * (1 - cia_scores[availability]))

    if scope == "U":
        impact_score = 6.42 * isc_base
    else:
        impact_score = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15

    if impact_score <= 0:
        base_score = 0.0
    elif scope == "U":
        base_score = min(exploitability + impact_score, 10.0)
        base_score = round(base_score * 10) / 10  # round up to 1 decimal
    else:
        base_score = min(1.08 * (exploitability + impact_score), 10.0)
        base_score = round(base_score * 10) / 10

    vector_string = f"CVSS:3.1/AV:{attack_vector}/AC:{attack_complexity}/PR:{privileges_required}/UI:{user_interaction}/S:{scope}/C:{confidentiality}/I:{integrity}/A:{availability}"

    # Severity rating
    if base_score == 0:
        rating = "none"
    elif base_score < 4.0:
        rating = "low"
    elif base_score < 7.0:
        rating = "medium"
    elif base_score < 9.0:
        rating = "high"
    else:
        rating = "critical"

    return {
        "score": base_score,
        "vector": vector_string,
        "severity": rating,
        "exploitability_score": round(exploitability, 1),
        "impact_score": round(impact_score, 1),
    }


async def report_export(
    format: str = "markdown",
    template: str = "pentest",
) -> dict:
    """Export all findings as a report.

    Args:
        format: Output format — markdown, json
        template: Report template — pentest, bug_bounty, api_assessment
    """
    db = await get_database()
    findings = await db.get_findings()

    if format == "json":
        return {"format": "json", "findings": findings, "total": len(findings)}

    # Markdown report
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# Security Assessment Report",
        f"\n**Generated**: {now}",
        f"\n**Total Findings**: {len(findings)}",
        "\n## Summary\n",
    ]

    # Severity counts
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev, count in severity_counts.items():
        if count > 0:
            lines.append(f"| {sev.capitalize()} | {count} |")

    lines.append("\n## Findings\n")

    for f in findings:
        lines.append(f"### {f['id']}: {f['title']}")
        lines.append(f"\n**Severity**: {f['severity'].capitalize()}")
        if f.get("cvss"):
            lines.append(f"**CVSS**: {f['cvss']}")
        lines.append(f"**Target**: {f['target']}")
        lines.append(f"\n{f['description']}")

        steps = json.loads(f.get("reproduction_steps", "[]")) if isinstance(f.get("reproduction_steps"), str) else f.get("reproduction_steps", [])
        if steps:
            lines.append("\n**Steps to Reproduce**:")
            for i, step in enumerate(steps, 1):
                lines.append(f"{i}. {step}")

        if f.get("impact"):
            lines.append(f"\n**Impact**: {f['impact']}")
        if f.get("remediation"):
            lines.append(f"\n**Remediation**: {f['remediation']}")
        lines.append("\n---\n")

    report_content = "\n".join(lines)

    return {
        "format": "markdown",
        "template": template,
        "content": report_content,
        "total_findings": len(findings),
    }


async def report_bounty_template(
    title: str,
    severity: str,
    target: str,
    description: str,
    steps: list[str],
    poc: str,
    impact: str,
    fix: str = "",
) -> dict:
    """Generate a bug bounty report from findings.

    Args:
        title: Vulnerability title
        severity: Severity level
        target: Affected endpoint
        description: Brief description
        steps: Steps to reproduce
        poc: Proof of concept (curl command, screenshot path)
        impact: Impact statement
        fix: Suggested fix
    """
    steps_md = "\n".join(f"{i}. {s}" for i, s in enumerate(steps, 1))

    report = f"""## {title}

**Severity**: {severity.capitalize()}
**Target**: {target}

### Description
{description}

### Steps to Reproduce
{steps_md}

### Proof of Concept
```
{poc}
```

### Impact
{impact}

### Suggested Fix
{fix or "N/A"}
"""

    return {
        "report": report,
        "format": "bug_bounty",
    }
