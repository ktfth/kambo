"""Self-calibration engine — adjust weights from evidence.

Closes the loop between prediction and reality:
  1. Reads historical user feedback (confirmed/rejected findings)
  2. Compares against predicted confidence levels
  3. Generates weight adjustments for validators
  4. Generates acceptance rate adjustments for pricing
  5. Persists adjustments as learnings for cross-session memory

The system does NOT auto-apply changes — it recommends adjustments
that can be reviewed before adoption. Elite-grade: evidence before action.
"""

from __future__ import annotations

from typing import Any

from kambo.learnings import Learning, get_learnings_store
from kambo.metrics import MetricsTracker, get_metrics


# Default weights for evidence signals (from validation.py)
_DEFAULT_SIGNAL_WEIGHTS: dict[str, dict[str, float]] = {
    "vuln_sqli": {
        "injectable_param": 1.5,
        "dbms_detected": 0.5,
        "dba_access": 0.5,
    },
    "vuln_xss": {
        "payload_reflected": 0.5,
        "context_script": 1.0,
        "context_body": 0.5,
    },
    "vuln_cors": {
        "origin_reflected": 0.5,
        "credentials_allowed": 1.0,
    },
    "vuln_ssrf": {
        "internal_content": 1.5,
        "status_code_200": 0.2,
    },
    "vuln_idor": {
        "different_response": 0.8,
        "user_specific_data": 1.0,
    },
    "vuln_jwt": {
        "secret_cracked": 1.5,
        "algo_confusion": 1.0,
    },
}

# Default acceptance rates (from bounty_pricing.py)
_DEFAULT_ACCEPTANCE_RATES: dict[str, float] = {
    "sqli": 0.95,
    "rce": 0.98,
    "ssrf": 0.90,
    "auth_bypass": 0.92,
    "idor": 0.88,
    "bola": 0.88,
    "bfla": 0.85,
    "subdomain_takeover": 0.80,
    "jwt": 0.85,
    "xss": 0.75,
    "cors": 0.60,
    "csrf": 0.70,
    "information_disclosure": 0.55,
    "open_redirect": 0.50,
}


def calibrate_confidence_weights(
    tracker: MetricsTracker | None = None,
) -> list[dict[str, Any]]:
    """Generate weight adjustment recommendations based on real outcomes.

    For each tool with sufficient feedback, compares:
    - Predicted precision (from confidence weights)
    - Actual precision (from user confirmations)

    Returns adjustment recommendations, NOT auto-applied changes.
    """
    tracker = tracker or get_metrics()
    adjustments: list[dict[str, Any]] = []

    for name, m in tracker.tools.items():
        total_reviewed = m.user_confirmed + m.user_rejected
        if total_reviewed < 5:  # need sufficient sample
            continue

        actual_precision = m.precision or 0
        total_findings = max(1, m.total_findings)

        # Expected precision from our weight system
        expected = (
            m.confirmed_count * 0.95
            + m.firm_count * 0.65
            + m.tentative_count * 0.25
        ) / total_findings

        drift = actual_precision - expected

        if abs(drift) < 0.10:
            # Within acceptable margin — no adjustment needed
            continue

        # Calculate recommended adjustment factor
        # If actual > expected: our weights are too conservative → increase
        # If actual < expected: our weights are too aggressive → decrease
        adjustment_factor = 1.0 + (drift * 0.5)  # damped correction

        default_weights = _DEFAULT_SIGNAL_WEIGHTS.get(name, {})
        adjusted_weights = {
            signal: round(weight * adjustment_factor, 3)
            for signal, weight in default_weights.items()
        }

        adjustments.append({
            "tool": name,
            "direction": "increase" if drift > 0 else "decrease",
            "actual_precision": round(actual_precision, 3),
            "expected_precision": round(expected, 3),
            "drift": round(drift, 3),
            "adjustment_factor": round(adjustment_factor, 3),
            "current_weights": default_weights,
            "recommended_weights": adjusted_weights,
            "sample_size": total_reviewed,
            "confidence_in_adjustment": min(10, total_reviewed),
        })

    return adjustments


def calibrate_acceptance_rates(
    tracker: MetricsTracker | None = None,
) -> list[dict[str, Any]]:
    """Adjust bounty acceptance rate predictions based on actual outcomes.

    Maps tool names to vuln types and compares predicted acceptance
    against actual user confirmation rate.
    """
    tracker = tracker or get_metrics()
    _tool_to_vuln = {
        "vuln_sqli": "sqli",
        "exploit_sqli": "sqli",
        "vuln_xss": "xss",
        "vuln_ssrf": "ssrf",
        "exploit_ssrf": "ssrf",
        "vuln_cors": "cors",
        "vuln_idor": "idor",
        "api_test_bola": "bola",
        "api_test_bfla": "bfla",
        "vuln_jwt": "jwt",
        "vuln_subdomain_takeover": "subdomain_takeover",
    }

    rate_adjustments: list[dict[str, Any]] = []

    for tool_name, vuln_type in _tool_to_vuln.items():
        m = tracker.tools.get(tool_name)
        if m is None:
            continue

        total_reviewed = m.user_confirmed + m.user_rejected
        if total_reviewed < 3:
            continue

        actual_rate = m.precision or 0
        default_rate = _DEFAULT_ACCEPTANCE_RATES.get(vuln_type, 0.50)
        drift = actual_rate - default_rate

        if abs(drift) < 0.10:
            continue

        recommended_rate = round(
            default_rate + (drift * 0.3),  # damped
            3,
        )
        # Clamp to [0.05, 0.99]
        recommended_rate = max(0.05, min(0.99, recommended_rate))

        rate_adjustments.append({
            "vuln_type": vuln_type,
            "tool": tool_name,
            "current_rate": default_rate,
            "actual_rate": round(actual_rate, 3),
            "recommended_rate": recommended_rate,
            "drift": round(drift, 3),
            "sample_size": total_reviewed,
        })

    return rate_adjustments


def generate_calibration_report(
    tracker: MetricsTracker | None = None,
) -> dict[str, Any]:
    """Full calibration report with all adjustments and learnings.

    This is the main output of the self-calibration system.
    """
    tracker = tracker or get_metrics()

    weight_adjustments = calibrate_confidence_weights(tracker)
    rate_adjustments = calibrate_acceptance_rates(tracker)

    # Overall calibration health
    total_adjustments = len(weight_adjustments) + len(rate_adjustments)
    needs_recalibration = any(
        abs(a["drift"]) > 0.20 for a in weight_adjustments
    ) or any(
        abs(a["drift"]) > 0.20 for a in rate_adjustments
    )

    health = "calibrated"
    if needs_recalibration:
        health = "needs_recalibration"
    elif total_adjustments == 0:
        health = "insufficient_data"

    return {
        "health": health,
        "total_adjustments": total_adjustments,
        "weight_adjustments": weight_adjustments,
        "acceptance_rate_adjustments": rate_adjustments,
        "needs_recalibration": needs_recalibration,
        "recommendation": (
            "Apply recommended adjustments to improve prediction accuracy."
            if needs_recalibration
            else "System is well-calibrated." if health == "calibrated"
            else "Need more user feedback data (confirm/reject findings)."
        ),
    }


def persist_calibration_learnings(
    tracker: MetricsTracker | None = None,
) -> int:
    """Save calibration insights as learnings for cross-session memory."""
    tracker = tracker or get_metrics()
    store = get_learnings_store()
    count = 0

    for adj in calibrate_confidence_weights(tracker):
        store.log(Learning(
            type="calibration",
            key=f"weight_adj_{adj['tool']}",
            insight=(
                f"{adj['tool']}: {adj['direction']} weights by {adj['adjustment_factor']:.2f}x "
                f"(actual={adj['actual_precision']:.0%} vs expected={adj['expected_precision']:.0%})"
            ),
            confidence=min(9, adj["sample_size"]),
            source="calibration",
            skill="calibration_engine",
            data={
                "recommended_weights": adj["recommended_weights"],
                "adjustment_factor": adj["adjustment_factor"],
            },
        ))
        count += 1

    for adj in calibrate_acceptance_rates(tracker):
        store.log(Learning(
            type="calibration",
            key=f"acceptance_adj_{adj['vuln_type']}",
            insight=(
                f"{adj['vuln_type']}: adjust acceptance rate {adj['current_rate']:.0%} → "
                f"{adj['recommended_rate']:.0%} (actual={adj['actual_rate']:.0%})"
            ),
            confidence=min(9, adj["sample_size"]),
            source="calibration",
            skill="calibration_engine",
            data={
                "current_rate": adj["current_rate"],
                "recommended_rate": adj["recommended_rate"],
            },
        ))
        count += 1

    return count
