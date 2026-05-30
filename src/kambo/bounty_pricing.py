"""Bounty finding pricing — estimate monetary value before reporting.

Maps findings to expected payout based on:
  1. Severity → program payout tier (critical/high/medium/low)
  2. Confidence → acceptance probability discount
  3. Vulnerability type → historical acceptance multiplier
  4. Program characteristics → bonus/managed adjustments

Output: estimated payout range (min/max), expected value, and report-readiness.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field

from kambo.models import Confidence, Severity


class ReportReadiness(str, Enum):
    """How ready a finding is for submission."""
    READY = "ready"           # CONFIRMED + good evidence → submit now
    NEEDS_POC = "needs_poc"   # FIRM but missing reproduction steps
    NEEDS_VERIFY = "needs_verify"  # TENTATIVE → manual verification first
    NOT_READY = "not_ready"   # Insufficient evidence


# Historical acceptance rates by vuln type (from public bounty data).
# These represent the probability a valid finding of this type gets accepted.
#
# Evidence-backed: vuln types that have a corresponding validate_*() in
# validation.py.  The evidence chain produces confidence levels that
# feed into the pricing formula.
#
# Advisory-only: vuln types WITHOUT a validator.  Pricing estimates are
# less reliable because findings are not graded by evidence chains.
# These are kept for bounty_estimate_value() to give ballpark numbers
# even when no validator exists yet.

_VULN_ACCEPTANCE_RATES: dict[str, float] = {
    # --- Evidence-backed (have validate_*) ---
    # High acceptance — clear impact, easy to verify
    "sqli": 0.95,
    "rce": 0.97,
    "ssrf": 0.90,
    "idor": 0.88,
    "bola": 0.88,
    "bfla": 0.85,
    "subdomain_takeover": 0.80,
    "jwt": 0.85,
    "ssti": 0.86,
    "path_traversal": 0.82,
    "xxe": 0.83,
    "insecure_deserialization": 0.85,
    "prototype_pollution": 0.80,
    "graphql": 0.80,
    "race_condition": 0.82,

    # Medium acceptance — sometimes disputed or downgraded
    "xss": 0.75,
    "cors": 0.60,
    "csrf": 0.70,
    "open_redirect": 0.50,

    # --- Advisory-only (NO validate_*, estimates less reliable) ---
    "auth_bypass": 0.92,
    "credential_exposure": 0.90,
    "hardcoded_credentials": 0.88,
    "information_disclosure": 0.55,
    "default_credentials": 0.65,
    "misconfig": 0.60,

    # Low acceptance — often marked informational or duplicate
    "rate_limiting": 0.10,
    "missing_headers": 0.06,
    "version_disclosure": 0.15,
}

# Confidence → probability the finding is real (not FP)
_CONFIDENCE_MULTIPLIERS: dict[Confidence, float] = {
    Confidence.CONFIRMED: 0.95,  # 95% chance it's real
    Confidence.FIRM: 0.75,       # 75% — 2+ independent signals
    Confidence.TENTATIVE: 0.30,  # 30% — single signal, high FP risk
}

# Severity downgrade probability — bounty programs often downgrade severity
_SEVERITY_DOWNGRADE: dict[Severity, dict[str, float]] = {
    Severity.CRITICAL: {"kept": 0.70, "downgraded_to": "high", "factor": 0.85},
    Severity.HIGH: {"kept": 0.80, "downgraded_to": "medium", "factor": 0.90},
    Severity.MEDIUM: {"kept": 0.85, "downgraded_to": "low", "factor": 0.92},
    Severity.LOW: {"kept": 0.90, "downgraded_to": "info", "factor": 0.95},
    Severity.INFO: {"kept": 1.0, "downgraded_to": "info", "factor": 1.0},
}


class PricingEstimate(BaseModel):
    """Estimated monetary value of a bounty finding."""

    finding_title: str
    severity: Severity
    confidence: Confidence
    vuln_type: str

    # Payout estimates
    base_payout: float = 0         # raw payout for this severity
    expected_value: float = 0      # base × confidence × acceptance × downgrade
    payout_range_min: float = 0    # pessimistic (downgraded + low confidence)
    payout_range_max: float = 0    # optimistic (kept severity + high acceptance)

    # Factors applied
    confidence_factor: float = 0   # probability finding is real
    acceptance_factor: float = 0   # probability program accepts this vuln type
    downgrade_factor: float = 0    # probability severity is kept
    bonus_multiplier: float = 1.0  # bonus/managed adjustments

    # Readiness
    readiness: ReportReadiness = ReportReadiness.NOT_READY
    readiness_blockers: list[str] = Field(default_factory=list)

    # Time-adjusted ROI (filled when timer data available)
    hours_spent: float = 0
    dollar_per_hour: float = 0


class ProgramPayouts(BaseModel):
    """Payout structure for a specific program."""

    program_name: str = ""
    payout_critical: float = 0
    payout_high: float = 0
    payout_medium: float = 0
    payout_low: float = 0
    bonus_active: bool = False
    bonus_multiplier: float = 1.0  # e.g., 2x during bonus events
    managed: bool = False


def estimate_finding_value(
    title: str,
    severity: Severity,
    confidence: Confidence,
    vuln_type: str,
    payouts: ProgramPayouts,
    has_poc: bool = False,
    has_reproduction_steps: bool = False,
    evidence_signals_count: int = 0,
    hours_spent: float = 0,
) -> PricingEstimate:
    """Estimate the monetary value of a finding.

    Args:
        title: Finding title
        severity: Assessed severity (critical/high/medium/low/info)
        confidence: Evidence-based confidence level
        vuln_type: Vulnerability type key (e.g., "sqli", "xss", "idor")
        payouts: Program payout structure
        has_poc: Whether a proof of concept exists
        has_reproduction_steps: Whether reproduction steps are documented
        evidence_signals_count: Number of evidence signals collected
        hours_spent: Hours spent on this finding (for ROI calculation)
    """
    # Base payout for this severity
    payout_map = {
        Severity.CRITICAL: payouts.payout_critical,
        Severity.HIGH: payouts.payout_high,
        Severity.MEDIUM: payouts.payout_medium,
        Severity.LOW: payouts.payout_low,
        Severity.INFO: 0,
    }
    base_payout = payout_map.get(severity, 0)

    # Factor 1: Confidence (is it real?)
    confidence_factor = _CONFIDENCE_MULTIPLIERS.get(confidence, 0.25)

    # Factor 2: Acceptance (will the program accept this type?)
    vuln_key = vuln_type.lower().replace(" ", "_").replace("-", "_")
    acceptance_factor = _VULN_ACCEPTANCE_RATES.get(vuln_key, 0.50)

    # Factor 3: Downgrade probability
    downgrade_info = _SEVERITY_DOWNGRADE.get(severity, {"factor": 1.0})
    downgrade_factor = downgrade_info["factor"]

    # Factor 4: Bonus/managed adjustments
    bonus_mult = 1.0
    if payouts.bonus_active:
        bonus_mult = max(1.0, payouts.bonus_multiplier)
    if payouts.managed:
        bonus_mult *= 1.1  # managed programs slightly more generous

    # Expected value = base × all factors
    expected_value = base_payout * confidence_factor * acceptance_factor * downgrade_factor * bonus_mult

    # Range: pessimistic assumes downgrade + lower acceptance
    payout_min = base_payout * confidence_factor * acceptance_factor * 0.5 * bonus_mult
    # Range: optimistic assumes no downgrade + full acceptance
    payout_max = base_payout * confidence_factor * acceptance_factor * 1.2 * bonus_mult

    # Report readiness assessment
    readiness, blockers = _assess_readiness(
        confidence, has_poc, has_reproduction_steps, evidence_signals_count
    )

    # ROI calculation
    dollar_per_hour = expected_value / hours_spent if hours_spent > 0 else 0

    return PricingEstimate(
        finding_title=title,
        severity=severity,
        confidence=confidence,
        vuln_type=vuln_type,
        base_payout=round(base_payout, 2),
        expected_value=round(expected_value, 2),
        payout_range_min=round(payout_min, 2),
        payout_range_max=round(payout_max, 2),
        confidence_factor=round(confidence_factor, 3),
        acceptance_factor=round(acceptance_factor, 3),
        downgrade_factor=round(downgrade_factor, 3),
        bonus_multiplier=round(bonus_mult, 3),
        readiness=readiness,
        readiness_blockers=blockers,
        hours_spent=round(hours_spent, 2),
        dollar_per_hour=round(dollar_per_hour, 2),
    )


def estimate_session_value(
    findings: list[PricingEstimate],
    total_hours: float = 0,
) -> dict:
    """Aggregate value estimates across all findings in a session.

    Returns total expected value, breakdown by severity, and ROI metrics.
    """
    if not findings:
        return {
            "total_expected_value": 0,
            "total_findings": 0,
            "ready_to_report": 0,
            "needs_work": 0,
            "dollar_per_hour": 0,
            "recommendation": "No findings to price.",
        }

    total_ev = sum(f.expected_value for f in findings)
    total_max = sum(f.payout_range_max for f in findings)
    ready = sum(1 for f in findings if f.readiness == ReportReadiness.READY)
    needs_poc = sum(1 for f in findings if f.readiness == ReportReadiness.NEEDS_POC)
    needs_verify = sum(1 for f in findings if f.readiness == ReportReadiness.NEEDS_VERIFY)

    by_severity = {}
    for sev in Severity:
        sev_findings = [f for f in findings if f.severity == sev]
        if sev_findings:
            by_severity[sev.value] = {
                "count": len(sev_findings),
                "expected_value": round(sum(f.expected_value for f in sev_findings), 2),
                "max_value": round(sum(f.payout_range_max for f in sev_findings), 2),
            }

    dollar_per_hour = total_ev / total_hours if total_hours > 0 else 0

    # Recommendation
    if ready >= 1 and total_ev > 0:
        rec = f"Submit {ready} finding(s) now — estimated ${total_ev:,.0f} expected value."
    elif needs_poc > 0:
        rec = f"{needs_poc} finding(s) need PoC documentation before submission."
    elif needs_verify > 0:
        rec = f"{needs_verify} finding(s) need manual verification — high FP risk."
    else:
        rec = "No findings ready for submission."

    if dollar_per_hour > 0:
        rec += f" Session ROI: ${dollar_per_hour:,.0f}/hour."

    return {
        "total_expected_value": round(total_ev, 2),
        "total_max_value": round(total_max, 2),
        "total_findings": len(findings),
        "ready_to_report": ready,
        "needs_poc": needs_poc,
        "needs_verification": needs_verify,
        "by_severity": by_severity,
        "total_hours": round(total_hours, 2),
        "dollar_per_hour": round(dollar_per_hour, 2),
        "recommendation": rec,
    }


def _assess_readiness(
    confidence: Confidence,
    has_poc: bool,
    has_reproduction_steps: bool,
    evidence_signals_count: int,
) -> tuple[ReportReadiness, list[str]]:
    """Determine if a finding is ready for bounty submission."""
    blockers: list[str] = []

    if confidence == Confidence.TENTATIVE:
        blockers.append("Confidence is TENTATIVE — manual verification required")
        return ReportReadiness.NEEDS_VERIFY, blockers

    if confidence == Confidence.CONFIRMED and has_poc and has_reproduction_steps:
        return ReportReadiness.READY, []

    if confidence == Confidence.CONFIRMED and not has_poc:
        blockers.append("Missing proof of concept")
        return ReportReadiness.NEEDS_POC, blockers

    if confidence == Confidence.CONFIRMED and not has_reproduction_steps:
        blockers.append("Missing reproduction steps")
        return ReportReadiness.NEEDS_POC, blockers

    if confidence == Confidence.FIRM:
        if not has_poc:
            blockers.append("Missing proof of concept")
        if not has_reproduction_steps:
            blockers.append("Missing reproduction steps")
        if evidence_signals_count < 2:
            blockers.append(f"Only {evidence_signals_count} evidence signal(s) — need at least 2")
        if blockers:
            return ReportReadiness.NEEDS_POC, blockers
        return ReportReadiness.READY, []

    blockers.append("Insufficient evidence for submission")
    return ReportReadiness.NOT_READY, blockers
