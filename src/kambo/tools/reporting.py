"""Phase 6: Reporting tools — with confidence levels and metrics."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from kambo.database import get_database
from kambo.hunt_context import filter_scope
from kambo.metrics import get_metrics
from kambo.models import Confidence, EvidenceChain, Finding, Phase, Severity
from kambo.scope import active_engagement_key, get_scope_manager


async def report_finding(
    title: str,
    severity: str,
    target: str,
    description: str,
    confidence: str = "tentative",
    reproduction_steps: list[str] | None = None,
    impact: str = "",
    remediation: str = "",
    cvss: float | None = None,
    cvss_vector: str = "",
    references: list[str] | None = None,
    tools_used: list[str] | None = None,
    evidence: dict | None = None,
    evidence_signals: list[dict] | None = None,
) -> dict:
    """Create and store a security finding with confidence level.

    Args:
        title: Finding title (e.g., "SQL Injection in /api/users")
        severity: critical, high, medium, low, info
        target: Affected target/endpoint
        description: Technical description of the vulnerability
        confidence: confirmed, firm, tentative — evidence-based confidence
        reproduction_steps: Steps to reproduce
        impact: Business/technical impact statement
        remediation: Fix recommendation
        cvss: CVSS 3.1 score
        cvss_vector: CVSS vector string
        references: CWE, OWASP references
        tools_used: Tools used to discover
        evidence: Request/response evidence (legacy dict format)
        evidence_signals: Structured evidence signals [{signal, source, raw_data, weight}]
    """
    db = await get_database()

    existing = await db.get_findings()
    finding_id = f"FIND-{len(existing) + 1:03d}"

    # Build evidence chain from signals if provided
    chain = EvidenceChain()
    if evidence_signals:
        for sig in evidence_signals:
            chain = chain.add(
                signal=sig.get("signal", ""),
                source=sig.get("source", ""),
                raw_data=sig.get("raw_data", ""),
                weight=sig.get("weight", 1.0),
            )

    conf = Confidence(confidence.lower())

    finding = Finding(
        id=finding_id,
        title=title,
        severity=Severity(severity.lower()),
        confidence=conf,
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
        evidence_chain=chain,
    )

    await db.save_finding(finding)

    return {
        "id": finding_id,
        "status": "saved",
        "confidence": conf.value,
        "evidence_summary": chain.summary(),
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
        base_score = round(base_score * 10) / 10
    else:
        base_score = min(1.08 * (exploitability + impact_score), 10.0)
        base_score = round(base_score * 10) / 10

    vector_string = f"CVSS:3.1/AV:{attack_vector}/AC:{attack_complexity}/PR:{privileges_required}/UI:{user_interaction}/S:{scope}/C:{confidentiality}/I:{integrity}/A:{availability}"

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
    min_confidence: str = "tentative",
) -> dict:
    """Export findings as a report with confidence filtering.

    Args:
        format: Output format — markdown, json
        template: Report template — pentest, bug_bounty, api_assessment
        min_confidence: Minimum confidence to include — confirmed, firm, tentative
    """
    # The findings store is one file shared by every engagement this machine has
    # run, so an unfiltered export puts another customer's unfixed vulnerability
    # — title, host, PoC, reproduction steps — inside the report written for the
    # current program. Export is therefore scoped to the active engagement, and
    # refuses outright when there is no engagement to scope it to.
    scope = get_scope_manager().scope
    if scope is None:
        return {
            "error": (
                "No engagement scope configured. Exporting without a scope would mix "
                "findings from every engagement in the store into one report. Call "
                "set_scope first."
            ),
            "format": format,
            "findings": [],
            "total": 0,
        }

    db = await get_database()
    findings = await db.get_findings(engagement_key=active_engagement_key())
    metrics = get_metrics()

    # Filter by confidence
    confidence_order = {"confirmed": 3, "firm": 2, "tentative": 1}
    min_level = confidence_order.get(min_confidence, 0)
    filtered = [
        f for f in findings
        if confidence_order.get(f.get("confidence", "tentative"), 1) >= min_level
    ]

    # Defence in depth: even inside the right engagement, a finding whose target
    # is not in the authorised scope does not belong in this report.
    off_scope = 0
    in_scope_findings = []
    for f in filtered:
        if filter_scope([str(f.get("target", ""))]).kept:
            in_scope_findings.append(f)
        else:
            off_scope += 1
    filtered = in_scope_findings

    if format == "json":
        return {
            "format": "json",
            "findings": filtered,
            "total": len(filtered),
            "filtered_from": len(findings),
            "min_confidence": min_confidence,
            "engagement": scope.engagement_id or "(unnamed engagement)",
            "withheld_out_of_scope": off_scope,
            "metrics": metrics.aggregate_summary(),
        }

    # Markdown report
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Confidence emoji mapping for visual scanning
    conf_badge = {"confirmed": "[CONFIRMED]", "firm": "[FIRM]", "tentative": "[TENTATIVE]"}

    lines = [
        "# Security Assessment Report",
        f"\n**Generated**: {now}",
        f"\n**Total Findings**: {len(filtered)} (filtered from {len(findings)}, min confidence: {min_confidence})",
        "\n## Quality Metrics\n",
    ]

    # Metrics summary
    agg = metrics.aggregate_summary()
    quality = agg.get("quality_metrics", {})
    conf_dist = agg.get("confidence_distribution", {})
    lines.append(f"- **Precision**: {quality.get('precision', 'no feedback')}")
    lines.append(f"- **FP Rate**: {quality.get('fp_rate', 'no feedback')}")
    lines.append(f"- **Confirmed**: {conf_dist.get('confirmed', 0)} | **Firm**: {conf_dist.get('firm', 0)} | **Tentative**: {conf_dist.get('tentative', 0)}")
    lines.append(f"- **Recommendation**: {agg.get('recommendation', '')}")

    # Severity counts
    lines.append("\n## Summary\n")
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in filtered:
        sev = f.get("severity", "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev, count in severity_counts.items():
        if count > 0:
            lines.append(f"| {sev.capitalize()} | {count} |")

    # Findings grouped by confidence
    for conf_level in ("confirmed", "firm", "tentative"):
        conf_findings = [f for f in filtered if f.get("confidence", "tentative") == conf_level]
        if not conf_findings:
            continue

        lines.append(f"\n## {conf_badge.get(conf_level, '')} Findings — {conf_level.capitalize()}\n")

        for f in conf_findings:
            lines.append(f"### {f['id']}: {f['title']}")
            lines.append(f"\n**Severity**: {f['severity'].capitalize()} | **Confidence**: {f.get('confidence', 'tentative').capitalize()}")
            if f.get("cvss"):
                lines.append(f"**CVSS**: {f['cvss']}")
            lines.append(f"**Target**: {f['target']}")
            lines.append(f"\n{f['description']}")

            # Evidence chain summary
            evidence_chain = f.get("evidence_chain")
            if evidence_chain and isinstance(evidence_chain, dict):
                signals = evidence_chain.get("items", [])
                if signals:
                    lines.append("\n**Evidence Chain**:")
                    for sig in signals:
                        lines.append(f"- [{sig.get('source', '')}] {sig.get('signal', '')} (weight: {sig.get('weight', 0)})")

                fp_checks = evidence_chain.get("false_positive_checks", [])
                if fp_checks:
                    lines.append("\n**FP Checks Performed**:")
                    for check in fp_checks:
                        lines.append(f"- {check}")

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
        "total_findings": len(filtered),
        "filtered_from": len(findings),
        "min_confidence": min_confidence,
        "engagement": scope.engagement_id or "(unnamed engagement)",
        "withheld_out_of_scope": off_scope,
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
    confidence: str = "tentative",
    evidence_signals: list[str] | None = None,
) -> dict:
    """Generate a bug bounty report template with confidence metadata.

    Args:
        title: Vulnerability title
        severity: Severity level
        target: Affected endpoint
        description: Brief description
        steps: Steps to reproduce
        poc: Proof of concept (curl command, screenshot path)
        impact: Impact statement
        fix: Suggested fix
        confidence: confirmed, firm, tentative
        evidence_signals: List of evidence signal descriptions
    """
    steps_md = "\n".join(f"{i}. {s}" for i, s in enumerate(steps, 1))
    signals_md = ""
    if evidence_signals:
        signals_md = "\n### Evidence Chain\n" + "\n".join(f"- {s}" for s in evidence_signals)

    conf_note = ""
    if confidence == "tentative":
        conf_note = "\n> **Note**: This finding has TENTATIVE confidence. Manual verification recommended before submission.\n"
    elif confidence == "firm":
        conf_note = "\n> **Note**: This finding has FIRM confidence based on multiple technical indicators.\n"

    report = f"""## {title}

**Severity**: {severity.capitalize()}
**Target**: {target}
**Confidence**: {confidence.capitalize()}
{conf_note}
### Description
{description}

### Steps to Reproduce
{steps_md}

### Proof of Concept
```
{poc}
```
{signals_md}
### Impact
{impact}

### Suggested Fix
{fix or "N/A"}
"""

    return {
        "report": report,
        "format": "bug_bounty",
        "confidence": confidence,
    }


async def report_metrics() -> dict:
    """Return current session metrics — precision, FP rates, confidence distribution.

    Use this to evaluate the quality of findings before submitting reports.
    """
    metrics = get_metrics()
    return metrics.aggregate_summary()


def _coerce_tools_used(raw: object) -> list[str]:
    """Normalize a finding's ``tools_used`` into a list of tool names.

    ``get_findings`` returns raw DB rows, so ``tools_used`` arrives as the JSON
    string it was stored as (e.g. ``"[]"`` or ``'["vuln_xss"]'``) rather than a
    list. Iterating that string directly walks it character by character and
    records feedback against ``"["`` / ``"]"`` — corrupting per-tool metrics.
    Coerce JSON or bare strings into a proper list; anything unusable → ``[]``
    so the empty-list fallback can attribute the feedback instead.
    """
    if isinstance(raw, list):
        return [str(t) for t in raw]
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except (ValueError, TypeError):
            parsed = raw
        if isinstance(parsed, list):
            return [str(t) for t in parsed]
        if isinstance(parsed, str) and parsed.strip():
            return [parsed]
    return []


async def report_confirm_finding(
    finding_id: str,
    is_true_positive: bool,
) -> dict:
    """Record user feedback on a finding to improve metrics.

    Args:
        finding_id: Finding ID (e.g., FIND-001)
        is_true_positive: True if the finding is a real vulnerability
    """
    db = await get_database()
    findings = await db.get_findings()
    metrics = get_metrics()

    matching = [f for f in findings if f.get("id") == finding_id]
    if not matching:
        return {"error": f"Finding {finding_id} not found"}

    finding = matching[0]
    tools = _coerce_tools_used(finding.get("tools_used", []))

    warning = ""
    if not tools:
        # Derive a synthetic tool name so feedback is not silently lost.
        severity = finding.get("severity", "unknown")
        fallback_tool = f"unattributed_{severity}"
        tools = [fallback_tool]
        warning = (
            f"Finding {finding_id} has no tools_used — "
            f"feedback recorded against '{fallback_tool}'"
        )

    for tool in tools:
        metrics.record_user_feedback(tool, is_true_positive)

    result: dict = {
        "finding_id": finding_id,
        "feedback": "true_positive" if is_true_positive else "false_positive",
        "updated_metrics": metrics.aggregate_summary(),
    }
    if warning:
        result["warning"] = warning
    return result
