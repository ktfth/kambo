"""Bug Bounty target intelligence — classify, score, and rank programs.

Evaluates programs across 5 dimensions:
  1. Payout potential (reward range, bonus programs)
  2. Attack surface (scope breadth, asset diversity)
  3. Opportunity (program age, researcher saturation, response time)
  4. Technical profile (tech stack complexity, known vuln patterns)
  5. Effort estimate (WAF presence, auth complexity, scope restrictions)

Final ROI score = (payout × attack_surface × opportunity) / effort
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ProgramTier(str, Enum):
    """Program quality tier based on ROI score."""
    S = "S"  # Elite — hunt immediately
    A = "A"  # High value — prioritize
    B = "B"  # Moderate — if capacity allows
    C = "C"  # Low value — skip unless niche expertise
    D = "D"  # Avoid — poor ROI


class AssetType(str, Enum):
    WEB = "web"
    API = "api"
    MOBILE = "mobile"
    INFRASTRUCTURE = "infrastructure"
    IOT = "iot"
    THICK_CLIENT = "thick_client"


class BountyProgram(BaseModel):
    """Bug bounty program metadata for classification."""

    name: str
    platform: str = ""  # hackerone, bugcrowd, intigriti, yeswehack, self-hosted
    url: str = ""  # program page URL
    domains: list[str] = Field(default_factory=list)  # in-scope domains
    wildcards: list[str] = Field(default_factory=list)  # wildcard scopes (*.example.com)
    asset_types: list[AssetType] = Field(default_factory=list)
    exclusions: list[str] = Field(default_factory=list)

    # Payout info
    payout_critical: float = 0  # max payout for critical
    payout_high: float = 0
    payout_medium: float = 0
    payout_low: float = 0
    bounty_type: str = "cash"  # cash, swag, points, hall_of_fame
    bonus_active: bool = False  # temporary bonus multiplier

    # Program metadata
    managed: bool = False  # managed/private program
    vdp_only: bool = False  # vulnerability disclosure only (no cash)
    launched_date: str = ""  # ISO date when program launched
    response_time_days: float = 30  # avg time to first response
    resolution_time_days: float = 90  # avg time to resolution

    # Technical context (filled after recon)
    tech_stack: list[str] = Field(default_factory=list)
    waf_detected: bool = False
    waf_name: str = ""
    cdn_detected: bool = False
    subdomains_count: int = 0
    open_ports_count: int = 0
    api_endpoints_count: int = 0
    has_swagger: bool = False


class TargetScore(BaseModel):
    """Detailed scoring breakdown for a bounty target."""

    program_name: str
    tier: ProgramTier
    roi_score: float  # 0-100 composite score

    payout_score: float = 0  # 0-25
    surface_score: float = 0  # 0-25
    opportunity_score: float = 0  # 0-25
    effort_score: float = 0  # 0-25 (lower effort = higher score)

    signals: list[str] = Field(default_factory=list)  # reasoning
    recommended_approach: str = ""
    estimated_hours: float = 0
    priority_vulns: list[str] = Field(default_factory=list)  # what to hunt first


# ---------------------------------------------------------------------------
# Scoring engine
# ---------------------------------------------------------------------------

def score_program(program: BountyProgram) -> TargetScore:
    """Score a bug bounty program across all dimensions.

    Returns a TargetScore with tier, ROI score, and recommended approach.
    """
    signals: list[str] = []

    # --- Payout Score (0-25) ---
    payout_score = _score_payout(program, signals)

    # --- Attack Surface Score (0-25) ---
    surface_score = _score_surface(program, signals)

    # --- Opportunity Score (0-25) ---
    opportunity_score = _score_opportunity(program, signals)

    # --- Effort Score (0-25, inverted: low effort = high score) ---
    effort_score = _score_effort(program, signals)

    # --- Composite ROI ---
    roi_score = payout_score + surface_score + opportunity_score + effort_score

    # --- Tier Classification ---
    tier = _classify_tier(roi_score, program)

    # --- Recommended Approach ---
    approach, priority_vulns, hours = _recommend_approach(program, surface_score, effort_score)

    return TargetScore(
        program_name=program.name,
        tier=tier,
        roi_score=round(roi_score, 1),
        payout_score=round(payout_score, 1),
        surface_score=round(surface_score, 1),
        opportunity_score=round(opportunity_score, 1),
        effort_score=round(effort_score, 1),
        signals=signals,
        recommended_approach=approach,
        estimated_hours=hours,
        priority_vulns=priority_vulns,
    )


def _score_payout(program: BountyProgram, signals: list[str]) -> float:
    """Score payout potential (0-25)."""
    if program.vdp_only:
        signals.append("VDP only — no cash payout")
        return 2.0

    if program.bounty_type != "cash":
        signals.append(f"Non-cash bounty ({program.bounty_type})")
        return 3.0

    score = 0.0
    crit = program.payout_critical

    if crit >= 50000:
        score = 25.0
        signals.append(f"Elite payout: ${crit:,.0f} critical")
    elif crit >= 15000:
        score = 20.0
        signals.append(f"High payout: ${crit:,.0f} critical")
    elif crit >= 5000:
        score = 15.0
        signals.append(f"Good payout: ${crit:,.0f} critical")
    elif crit >= 1000:
        score = 10.0
        signals.append(f"Moderate payout: ${crit:,.0f} critical")
    elif crit > 0:
        score = 5.0
        signals.append(f"Low payout: ${crit:,.0f} critical")
    else:
        score = 3.0
        signals.append("Payout amounts not specified")

    if program.bonus_active:
        score = min(25.0, score * 1.3)
        signals.append("Bonus multiplier active — increased payout")

    if program.managed:
        score = min(25.0, score * 1.15)
        signals.append("Managed/private program — less competition")

    return score


def _score_surface(program: BountyProgram, signals: list[str]) -> float:
    """Score attack surface breadth (0-25)."""
    score = 0.0

    # Wildcard scopes = large attack surface
    wc = len(program.wildcards)
    if wc >= 3:
        score += 10.0
        signals.append(f"{wc} wildcard scopes — massive attack surface")
    elif wc >= 1:
        score += 6.0
        signals.append(f"{wc} wildcard scope(s) — expandable surface")

    # Explicit domains
    d = len(program.domains)
    if d >= 10:
        score += 5.0
    elif d >= 3:
        score += 3.0
    elif d >= 1:
        score += 1.0

    # Asset diversity
    types = set(program.asset_types)
    if len(types) >= 3:
        score += 5.0
        signals.append(f"Diverse asset types: {', '.join(t.value for t in types)}")
    elif AssetType.API in types:
        score += 4.0
        signals.append("API in scope — high-value target for auth bugs")
    elif len(types) >= 1:
        score += 2.0

    # Recon-derived surface metrics
    if program.subdomains_count >= 100:
        score += 3.0
        signals.append(f"{program.subdomains_count} subdomains — large enumeration surface")
    elif program.subdomains_count >= 20:
        score += 1.5

    if program.has_swagger:
        score += 2.0
        signals.append("Swagger/OpenAPI spec found — full API map available")

    if program.api_endpoints_count >= 20:
        score += 1.5
        signals.append(f"{program.api_endpoints_count} API endpoints discovered")

    return min(25.0, score)


def _score_opportunity(program: BountyProgram, signals: list[str]) -> float:
    """Score opportunity based on program maturity and competition (0-25)."""
    score = 12.5  # neutral baseline

    # New programs have more low-hanging fruit
    if program.launched_date:
        try:
            launched = datetime.fromisoformat(program.launched_date)
            now = datetime.now(timezone.utc)
            age_days = (now - launched).days

            if age_days <= 30:
                score += 10.0
                signals.append("New program (<30 days) — high probability of low-hanging fruit")
            elif age_days <= 90:
                score += 6.0
                signals.append("Recent program (<90 days) — good opportunity window")
            elif age_days <= 365:
                score += 2.0
            elif age_days > 1095:
                score -= 3.0
                signals.append("Mature program (3+ years) — most easy bugs found")
        except (ValueError, TypeError):
            pass

    # Response time affects ROI
    if program.response_time_days <= 7:
        score += 3.0
        signals.append(f"Fast response ({program.response_time_days:.0f} days) — quick feedback loop")
    elif program.response_time_days >= 60:
        score -= 3.0
        signals.append(f"Slow response ({program.response_time_days:.0f} days) — cash flow bottleneck")

    # Exclusions narrow opportunity
    if len(program.exclusions) >= 10:
        score -= 3.0
        signals.append(f"{len(program.exclusions)} exclusions — heavily restricted scope")

    return max(0.0, min(25.0, score))


def _score_effort(program: BountyProgram, signals: list[str]) -> float:
    """Score effort required — lower effort = higher score (0-25)."""
    score = 20.0  # start optimistic, subtract for difficulty

    if program.waf_detected:
        score -= 5.0
        signals.append(f"WAF detected ({program.waf_name or 'unknown'}) — scanning will be slower")

    if program.cdn_detected:
        score -= 2.0
        signals.append("CDN in front — direct access limited")

    # Tech stack complexity
    complex_stacks = ["java", "spring", "asp.net", ".net", "golang"]
    easy_stacks = ["php", "wordpress", "laravel", "rails", "node", "express", "django"]

    stack_lower = [t.lower() for t in program.tech_stack]
    has_complex = any(cs in s for s in stack_lower for cs in complex_stacks)
    has_easy = any(es in s for s in stack_lower for es in easy_stacks)

    if has_easy and not has_complex:
        score += 3.0
        signals.append("Tech stack favors common vulnerability patterns")
    elif has_complex and not has_easy:
        score -= 3.0
        signals.append("Complex tech stack — requires deeper analysis")

    # Open ports indicate more services to test
    if program.open_ports_count >= 10:
        score += 2.0
        signals.append(f"{program.open_ports_count} open ports — multiple service attack vectors")

    return max(0.0, min(25.0, score))


def _classify_tier(roi_score: float, program: BountyProgram) -> ProgramTier:
    """Map ROI score to program tier."""
    if program.vdp_only:
        return ProgramTier.D

    if roi_score >= 75:
        return ProgramTier.S
    if roi_score >= 60:
        return ProgramTier.A
    if roi_score >= 40:
        return ProgramTier.B
    if roi_score >= 25:
        return ProgramTier.C
    return ProgramTier.D


def _recommend_approach(
    program: BountyProgram,
    surface_score: float,
    effort_score: float,
) -> tuple[str, list[str], float]:
    """Generate hunting strategy, priority vulns, and time estimate."""
    priority_vulns: list[str] = []
    hours = 8.0  # baseline

    # API-heavy targets
    if AssetType.API in program.asset_types or program.has_swagger:
        priority_vulns.extend(["BOLA (API1)", "BFLA (API5)", "IDOR", "Mass Assignment"])
        approach_type = "API-first"
        hours = 6.0
    # Large wildcard surface
    elif len(program.wildcards) >= 2:
        priority_vulns.extend(["Subdomain Takeover", "Exposed Admin Panels", "SSRF", "Information Disclosure"])
        approach_type = "Recon-heavy"
        hours = 12.0
    # Standard web
    else:
        priority_vulns.extend(["SQLi", "XSS", "SSRF", "Auth Bypass"])
        approach_type = "Standard web"
        hours = 8.0

    # Adjust for effort
    if effort_score < 10:
        hours *= 1.5
    elif effort_score > 20:
        hours *= 0.7

    # Build approach text
    approach = f"{approach_type} hunting. "
    if program.waf_detected:
        approach += "Use evasion techniques due to WAF. "
    if program.has_swagger:
        approach += "Start with API spec analysis. "
    if len(program.wildcards) >= 1:
        approach += "Heavy subdomain enumeration recommended. "
    if program.managed:
        approach += "Private program — less competition, take time to be thorough."

    return approach.strip(), priority_vulns, round(hours, 1)


def rank_programs(programs: list[BountyProgram]) -> list[TargetScore]:
    """Score and rank multiple programs by ROI. Returns sorted list (best first)."""
    scores = [score_program(p) for p in programs]
    return sorted(scores, key=lambda s: s.roi_score, reverse=True)
