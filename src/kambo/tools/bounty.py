"""Bug Bounty intelligence tools — classify, score, rank programs."""

from __future__ import annotations

from kambo.bounty_intel import (
    AssetType,
    BountyProgram,
    rank_programs,
    score_program,
)
from kambo.metrics import get_metrics


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
