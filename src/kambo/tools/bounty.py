"""Bug Bounty intelligence tools — classify, score, rank, price, time."""

from __future__ import annotations

from kambo.bounty_intel import (
    AssetType,
    BountyProgram,
    rank_programs,
    score_program,
)
from kambo.bounty_pricing import (
    PricingEstimate,
    ProgramPayouts,
    ReportReadiness,
    estimate_finding_value,
    estimate_session_value,
)
from kambo.discovery_timer import get_timer, reset_timer
from kambo.metrics import get_metrics
from kambo.models import Confidence, Severity


async def bounty_classify(
    name: str,
    platform: str = "",
    domains: list[str] | None = None,
    wildcards: list[str] | None = None,
    asset_types: list[str] | None = None,
    exclusions: list[str] | None = None,
    payout_critical: float = 0,
    payout_high: float = 0,
    payout_medium: float = 0,
    payout_low: float = 0,
    bounty_type: str = "cash",
    bonus_active: bool = False,
    managed: bool = False,
    vdp_only: bool = False,
    launched_date: str = "",
    response_time_days: float = 30,
    tech_stack: list[str] | None = None,
    waf_detected: bool = False,
    waf_name: str = "",
    subdomains_count: int = 0,
    open_ports_count: int = 0,
    api_endpoints_count: int = 0,
    has_swagger: bool = False,
) -> dict:
    """Classify and score a single bug bounty program.

    Analyzes across 5 dimensions (payout, surface, opportunity, effort)
    and returns a tier (S/A/B/C/D) with recommended hunting approach.

    Args:
        name: Program name (e.g., "Uber", "Shopify")
        platform: Bug bounty platform (hackerone, bugcrowd, intigriti)
        domains: In-scope domains
        wildcards: Wildcard scopes (e.g., ["*.uber.com"])
        asset_types: Asset types in scope (web, api, mobile, infrastructure)
        exclusions: Out-of-scope items
        payout_critical: Max payout for critical severity ($)
        payout_high: Max payout for high severity ($)
        payout_medium: Max payout for medium severity ($)
        payout_low: Max payout for low severity ($)
        bounty_type: cash, swag, points, hall_of_fame
        bonus_active: Whether a bonus multiplier is currently active
        managed: Whether this is a managed/private program
        vdp_only: Vulnerability disclosure program (no cash)
        launched_date: When the program launched (ISO date)
        response_time_days: Average first response time in days
        tech_stack: Known technologies (e.g., ["PHP", "WordPress", "MySQL"])
        waf_detected: Whether a WAF was detected
        waf_name: WAF product name
        subdomains_count: Number of subdomains found during recon
        open_ports_count: Number of open ports found
        api_endpoints_count: Number of API endpoints discovered
        has_swagger: Whether Swagger/OpenAPI spec was found
    """
    metrics = get_metrics()

    # Parse asset types
    valid_types = []
    for t in (asset_types or ["web"]):
        try:
            valid_types.append(AssetType(t.lower()))
        except ValueError:
            pass

    program = BountyProgram(
        name=name,
        platform=platform,
        domains=domains or [],
        wildcards=wildcards or [],
        asset_types=valid_types,
        exclusions=exclusions or [],
        payout_critical=payout_critical,
        payout_high=payout_high,
        payout_medium=payout_medium,
        payout_low=payout_low,
        bounty_type=bounty_type,
        bonus_active=bonus_active,
        managed=managed,
        vdp_only=vdp_only,
        launched_date=launched_date,
        response_time_days=response_time_days,
        tech_stack=tech_stack or [],
        waf_detected=waf_detected,
        waf_name=waf_name,
        subdomains_count=subdomains_count,
        open_ports_count=open_ports_count,
        api_endpoints_count=api_endpoints_count,
        has_swagger=has_swagger,
    )

    result = score_program(program)
    metrics.record_run("bounty_classify")

    return {
        "program": name,
        "tier": result.tier.value,
        "roi_score": result.roi_score,
        "breakdown": {
            "payout": result.payout_score,
            "attack_surface": result.surface_score,
            "opportunity": result.opportunity_score,
            "effort": result.effort_score,
        },
        "signals": result.signals,
        "recommended_approach": result.recommended_approach,
        "priority_vulns": result.priority_vulns,
        "estimated_hours": result.estimated_hours,
    }


async def bounty_rank(programs: list[dict]) -> dict:
    """Rank multiple bug bounty programs by ROI score.

    Compare programs side-by-side and get a prioritized hunting order.

    Args:
        programs: List of program objects, each with the same fields as bounty_classify
    """
    metrics = get_metrics()

    parsed_programs = []
    for p in programs:
        asset_types = []
        for t in p.get("asset_types", ["web"]):
            try:
                asset_types.append(AssetType(t.lower()))
            except ValueError:
                pass

        parsed_programs.append(BountyProgram(
            name=p.get("name", "Unknown"),
            platform=p.get("platform", ""),
            domains=p.get("domains", []),
            wildcards=p.get("wildcards", []),
            asset_types=asset_types,
            exclusions=p.get("exclusions", []),
            payout_critical=p.get("payout_critical", 0),
            payout_high=p.get("payout_high", 0),
            payout_medium=p.get("payout_medium", 0),
            payout_low=p.get("payout_low", 0),
            bounty_type=p.get("bounty_type", "cash"),
            bonus_active=p.get("bonus_active", False),
            managed=p.get("managed", False),
            vdp_only=p.get("vdp_only", False),
            launched_date=p.get("launched_date", ""),
            response_time_days=p.get("response_time_days", 30),
            tech_stack=p.get("tech_stack", []),
            waf_detected=p.get("waf_detected", False),
            waf_name=p.get("waf_name", ""),
            subdomains_count=p.get("subdomains_count", 0),
            open_ports_count=p.get("open_ports_count", 0),
            api_endpoints_count=p.get("api_endpoints_count", 0),
            has_swagger=p.get("has_swagger", False),
        ))

    ranked = rank_programs(parsed_programs)
    metrics.record_run("bounty_rank")

    return {
        "total_programs": len(ranked),
        "ranking": [
            {
                "rank": i + 1,
                "program": r.program_name,
                "tier": r.tier.value,
                "roi_score": r.roi_score,
                "payout_score": r.payout_score,
                "surface_score": r.surface_score,
                "recommended_approach": r.recommended_approach,
                "priority_vulns": r.priority_vulns,
                "estimated_hours": r.estimated_hours,
                "top_signals": r.signals[:5],
            }
            for i, r in enumerate(ranked)
        ],
        "recommendation": _pick_recommendation(ranked),
    }


def _pick_recommendation(ranked: list) -> str:
    if not ranked:
        return "No programs to rank."
    top = ranked[0]
    if top.tier.value == "S":
        return f"Hunt {top.program_name} immediately — elite ROI ({top.roi_score}/100)."
    if top.tier.value == "A":
        return f"Prioritize {top.program_name} — high value ({top.roi_score}/100)."
    if top.tier.value == "B":
        return f"{top.program_name} is moderate value. Consider if you have niche expertise in {', '.join(top.priority_vulns[:2])}."
    return f"All programs scored low. Consider finding new programs or waiting for bonus events."


# ---------------------------------------------------------------------------
# Pricing
# ---------------------------------------------------------------------------

async def bounty_estimate_value(
    title: str,
    severity: str,
    confidence: str = "tentative",
    vuln_type: str = "xss",
    program_name: str = "",
    payout_critical: float = 0,
    payout_high: float = 0,
    payout_medium: float = 0,
    payout_low: float = 0,
    bonus_active: bool = False,
    bonus_multiplier: float = 1.0,
    managed: bool = False,
    has_poc: bool = False,
    has_reproduction_steps: bool = False,
    evidence_signals_count: int = 0,
    hours_spent: float = 0,
) -> dict:
    """Estimate monetary value of a single finding.

    Calculates expected payout considering severity, confidence discount,
    vulnerability acceptance rates, and program payout structure.

    Args:
        title: Finding title
        severity: critical, high, medium, low, info
        confidence: confirmed, firm, tentative
        vuln_type: Vulnerability type (sqli, xss, idor, ssrf, cors, etc.)
        program_name: Bug bounty program name
        payout_critical: Program's max critical payout ($)
        payout_high: Program's max high payout ($)
        payout_medium: Program's max medium payout ($)
        payout_low: Program's max low payout ($)
        bonus_active: Whether bonus multiplier is active
        bonus_multiplier: Bonus multiplier value (e.g., 2.0)
        managed: Whether this is a managed/private program
        has_poc: Whether proof of concept exists
        has_reproduction_steps: Whether reproduction steps are documented
        evidence_signals_count: Number of evidence signals
        hours_spent: Hours spent discovering this finding
    """
    metrics = get_metrics()

    payouts = ProgramPayouts(
        program_name=program_name,
        payout_critical=payout_critical,
        payout_high=payout_high,
        payout_medium=payout_medium,
        payout_low=payout_low,
        bonus_active=bonus_active,
        bonus_multiplier=bonus_multiplier,
        managed=managed,
    )

    # Use timer data if hours not explicitly provided
    if hours_spent <= 0:
        timer = get_timer()
        hours_spent = timer.total_hours

    estimate = estimate_finding_value(
        title=title,
        severity=Severity(severity.lower()),
        confidence=Confidence(confidence.lower()),
        vuln_type=vuln_type,
        payouts=payouts,
        has_poc=has_poc,
        has_reproduction_steps=has_reproduction_steps,
        evidence_signals_count=evidence_signals_count,
        hours_spent=hours_spent,
    )

    metrics.record_run("bounty_estimate_value")

    return {
        "finding": estimate.finding_title,
        "severity": estimate.severity.value,
        "confidence": estimate.confidence.value,
        "vuln_type": estimate.vuln_type,
        "pricing": {
            "base_payout": estimate.base_payout,
            "expected_value": estimate.expected_value,
            "range_min": estimate.payout_range_min,
            "range_max": estimate.payout_range_max,
        },
        "factors": {
            "confidence_factor": estimate.confidence_factor,
            "acceptance_factor": estimate.acceptance_factor,
            "downgrade_factor": estimate.downgrade_factor,
            "bonus_multiplier": estimate.bonus_multiplier,
        },
        "readiness": {
            "status": estimate.readiness.value,
            "blockers": estimate.readiness_blockers,
        },
        "roi": {
            "hours_spent": estimate.hours_spent,
            "dollar_per_hour": estimate.dollar_per_hour,
        },
    }


async def bounty_session_value(
    findings: list[dict],
    program_name: str = "",
    payout_critical: float = 0,
    payout_high: float = 0,
    payout_medium: float = 0,
    payout_low: float = 0,
    bonus_active: bool = False,
    bonus_multiplier: float = 1.0,
    managed: bool = False,
) -> dict:
    """Calculate total session value across all findings.

    Aggregates expected value, readiness status, and ROI metrics.

    Args:
        findings: List of finding dicts with keys: title, severity, confidence,
                  vuln_type, has_poc, has_reproduction_steps, evidence_signals_count
        program_name: Bug bounty program name
        payout_critical/high/medium/low: Program payout tiers ($)
        bonus_active: Whether bonus is active
        bonus_multiplier: Bonus multiplier value
        managed: Whether managed/private program
    """
    metrics = get_metrics()
    timer = get_timer()
    total_hours = timer.total_hours

    payouts = ProgramPayouts(
        program_name=program_name,
        payout_critical=payout_critical,
        payout_high=payout_high,
        payout_medium=payout_medium,
        payout_low=payout_low,
        bonus_active=bonus_active,
        bonus_multiplier=bonus_multiplier,
        managed=managed,
    )

    estimates: list[PricingEstimate] = []
    for f in findings:
        est = estimate_finding_value(
            title=f.get("title", ""),
            severity=Severity(f.get("severity", "medium").lower()),
            confidence=Confidence(f.get("confidence", "tentative").lower()),
            vuln_type=f.get("vuln_type", "xss"),
            payouts=payouts,
            has_poc=f.get("has_poc", False),
            has_reproduction_steps=f.get("has_reproduction_steps", False),
            evidence_signals_count=f.get("evidence_signals_count", 0),
        )
        estimates.append(est)

    result = estimate_session_value(estimates, total_hours)
    metrics.record_run("bounty_session_value")

    # Add individual finding breakdowns
    result["findings"] = [
        {
            "title": e.finding_title,
            "severity": e.severity.value,
            "expected_value": e.expected_value,
            "readiness": e.readiness.value,
        }
        for e in estimates
    ]
    result["timer"] = timer.summary()

    return result


# ---------------------------------------------------------------------------
# Discovery Timer
# ---------------------------------------------------------------------------

async def bounty_timer_start(phase: str) -> dict:
    """Start timing a discovery phase.

    Call at the beginning of each phase (recon, scanning, vuln_analysis, etc.)
    to track time investment for ROI calculation.

    Args:
        phase: Phase name (recon, scanning, vulnerability_analysis, exploitation, reporting)
    """
    timer = get_timer()
    timer.start_phase(phase)
    return {
        "status": "started",
        "phase": phase,
        "session_start": timer.session_start.isoformat(),
        "active_hours_so_far": timer.total_hours,
    }


async def bounty_timer_tool(tool_name: str, target: str = "") -> dict:
    """Record a tool execution within the current phase.

    Call before running each tool to track per-tool timing.

    Args:
        tool_name: Name of the tool being executed
        target: Target being tested
    """
    timer = get_timer()
    timer.start_tool(tool_name, target)
    return {
        "status": "tracking",
        "tool": tool_name,
        "target": target,
    }


async def bounty_timer_stop() -> dict:
    """Stop the current timer and get full timing summary.

    Returns breakdown by phase and tool with ROI metrics.
    """
    timer = get_timer()
    timer.end_phase()
    return timer.summary()


async def bounty_timer_reset() -> dict:
    """Reset the timer for a new hunting session."""
    timer = reset_timer()
    return {
        "status": "reset",
        "session_start": timer.session_start.isoformat(),
    }
