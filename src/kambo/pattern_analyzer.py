"""Pattern analyzer — extract elite patterns from historical data.

Analyzes metrics, findings, and session logs to detect:
  1. High-yield tool chains (which sequence of tools produces CONFIRMED findings)
  2. FP hotspots (which vuln types on which tech stacks always produce FPs)
  3. Efficiency patterns (fastest path to confirmed findings)
  4. Calibration signals (where our predictions diverge from reality)
"""

from __future__ import annotations

from typing import Any

from kambo.learnings import Learning, get_learnings_store
from kambo.metrics import MetricsTracker, get_metrics


def analyze_tool_performance(tracker: MetricsTracker | None = None) -> list[dict[str, Any]]:
    """Identify elite and underperforming tools from metrics data.

    Returns a list of insight dicts, each with:
      - tool: tool name
      - category: "elite" | "reliable" | "noisy" | "broken"
      - reason: why this classification
      - action: recommended action
    """
    tracker = tracker or get_metrics()
    insights: list[dict[str, Any]] = []

    for name, m in tracker.tools.items():
        if m.total_runs < 2:
            continue

        total_reviewed = m.user_confirmed + m.user_rejected
        finding_rate = m.total_findings / m.total_runs if m.total_runs > 0 else 0

        # Elite: high precision + high finding rate
        if total_reviewed >= 3 and m.precision is not None and m.precision >= 0.70:
            insights.append({
                "tool": name,
                "category": "elite",
                "reason": f"Precision {m.precision:.0%} with {finding_rate:.1f} findings/run",
                "action": "Prioritize this tool. High confidence in results.",
                "data": {"precision": m.precision, "finding_rate": finding_rate},
            })
        # Broken: consistently high FP
        elif total_reviewed >= 3 and m.fp_rate is not None and m.fp_rate >= 0.7:
            insights.append({
                "tool": name,
                "category": "broken",
                "reason": f"FP rate {m.fp_rate:.0%} — {m.user_rejected}/{total_reviewed} rejected",
                "action": "Cross-validate with second tool before reporting. Consider skipping.",
                "data": {"fp_rate": m.fp_rate, "rejected": m.user_rejected},
            })
        # Noisy: many findings but low confirmed ratio (use reviewed count if available)
        elif m.total_findings > 5:
            effective_total = total_reviewed if total_reviewed >= 3 else m.total_findings
            confirmed_ratio = m.confirmed_count / max(1, effective_total)
            if confirmed_ratio < 0.25:
                insights.append({
                    "tool": name,
                    "category": "noisy",
                    "reason": f"Only {m.confirmed_count}/{effective_total} findings are CONFIRMED",
                    "action": "Increase evidence threshold or add validation step.",
                    "data": {"confirmed_ratio": confirmed_ratio},
                })
        # Reliable: decent precision, consistent
        elif total_reviewed >= 2 and m.precision is not None and m.precision >= 0.5:
            insights.append({
                "tool": name,
                "category": "reliable",
                "reason": f"Precision {m.precision:.0%} — solid but not elite",
                "action": "Use normally. FIRM findings worth investigating.",
                "data": {"precision": m.precision},
            })

    return insights


def analyze_confidence_distribution(tracker: MetricsTracker | None = None) -> dict[str, Any]:
    """Analyze overall confidence distribution to identify quality gaps.

    Returns actionable recommendations based on the ratio of
    CONFIRMED vs FIRM vs TENTATIVE findings.
    """
    tracker = tracker or get_metrics()
    summary = tracker.aggregate_summary()
    dist = summary.get("confidence_distribution", {})

    confirmed = dist.get("confirmed", 0)
    firm = dist.get("firm", 0)
    tentative = dist.get("tentative", 0)
    total = confirmed + firm + tentative

    if total == 0:
        return {"status": "no_data", "recommendation": "Run tools to collect data."}

    if total < 5:
        return {
            "status": "low_sample",
            "recommendation": f"Only {total} findings — need at least 5 for reliable quality assessment.",
            "distribution": {"confirmed": confirmed, "firm": firm, "tentative": tentative},
        }

    confirmed_pct = confirmed / total
    tentative_pct = tentative / total

    recommendations: list[str] = []
    quality_tier = "unknown"

    if confirmed_pct >= 0.5:
        quality_tier = "elite"
        recommendations.append("Excellent — majority confirmed. Focus on reporting.")
    elif confirmed_pct >= 0.25:
        quality_tier = "solid"
        recommendations.append("Good quality. Promote FIRM findings to CONFIRMED via exploitation.")
    elif tentative_pct >= 0.7:
        quality_tier = "weak"
        recommendations.append("HIGH TENTATIVE ratio — most findings unverified.")
        recommendations.append("Run exploitation tools on FIRM findings before reporting.")
        recommendations.append("Consider re-running with deeper validation.")
    else:
        quality_tier = "moderate"
        recommendations.append("Mixed quality. Prioritize CONFIRMED and FIRM for reporting.")

    return {
        "quality_tier": quality_tier,
        "distribution": {"confirmed": confirmed, "firm": firm, "tentative": tentative},
        "percentages": {
            "confirmed": round(confirmed_pct * 100, 1),
            "firm": round(firm / total * 100, 1) if total > 0 else 0,
            "tentative": round(tentative_pct * 100, 1),
        },
        "recommendations": recommendations,
    }


def analyze_efficiency_patterns(tracker: MetricsTracker | None = None) -> dict[str, Any]:
    """Identify which tools give the best findings-per-run ratio.

    Helps optimize hunting strategy by focusing on high-yield tools.
    """
    tracker = tracker or get_metrics()
    tool_efficiency: list[dict[str, Any]] = []

    for name, m in tracker.tools.items():
        if m.total_runs == 0:
            continue
        finding_rate = m.total_findings / m.total_runs
        confirmed_rate = m.confirmed_count / m.total_runs
        avg_weight = m.avg_evidence_weight

        tool_efficiency.append({
            "tool": name,
            "runs": m.total_runs,
            "findings_per_run": round(finding_rate, 2),
            "confirmed_per_run": round(confirmed_rate, 2),
            "avg_evidence_weight": round(avg_weight, 2),
        })

    # Sort by confirmed_per_run desc
    tool_efficiency.sort(key=lambda t: -t["confirmed_per_run"])

    top_3 = [t["tool"] for t in tool_efficiency[:3] if t["confirmed_per_run"] > 0]
    bottom_3 = [t["tool"] for t in tool_efficiency[-3:] if t["findings_per_run"] == 0]

    return {
        "tool_efficiency": tool_efficiency,
        "top_performers": top_3,
        "zero_yield": bottom_3,
        "recommendation": (
            f"Focus on {', '.join(top_3)}." if top_3
            else "Not enough data to recommend."
        ),
    }


def detect_calibration_drift(tracker: MetricsTracker | None = None) -> list[dict[str, Any]]:
    """Detect where our confidence predictions diverge from reality.

    Compares predicted confidence distribution against user feedback
    to find tools that are systematically over- or under-confident.
    """
    tracker = tracker or get_metrics()
    drifts: list[dict[str, Any]] = []

    for name, m in tracker.tools.items():
        total_reviewed = m.user_confirmed + m.user_rejected
        if total_reviewed < 3:
            continue

        precision = m.precision or 0
        # Expected precision based on confidence distribution
        total_findings = m.total_findings or 1
        expected_precision = (
            m.confirmed_count * 0.95 + m.firm_count * 0.65 + m.tentative_count * 0.25
        ) / total_findings

        drift = precision - expected_precision

        if abs(drift) > 0.15:
            direction = "over-confident" if drift < 0 else "under-confident"
            drifts.append({
                "tool": name,
                "direction": direction,
                "actual_precision": round(precision, 3),
                "expected_precision": round(expected_precision, 3),
                "drift": round(drift, 3),
                "action": (
                    f"Reduce confidence weights — tool is {direction} by {abs(drift):.0%}"
                    if drift < 0
                    else f"Increase confidence weights — tool is {direction} by {abs(drift):.0%}"
                ),
            })

    return drifts


def generate_learnings_from_analysis(
    tracker: MetricsTracker | None = None,
) -> list[Learning]:
    """Run all analyzers and generate learnings for persistence.

    This is the main entry point for autonomous self-improvement.
    Called periodically to extract patterns from accumulated data.
    """
    tracker = tracker or get_metrics()
    learnings: list[Learning] = []

    # Tool performance patterns
    for insight in analyze_tool_performance(tracker):
        learnings.append(Learning(
            type="pattern" if insight["category"] in ("elite", "reliable") else "pitfall",
            key=f"tool_perf_{insight['tool']}",
            insight=f"{insight['tool']}: {insight['reason']} → {insight['action']}",
            confidence=8 if insight["category"] == "elite" else 6,
            source="observed",
            skill="pattern_analyzer",
            data=insight["data"],
        ))

    # Calibration drift
    for drift in detect_calibration_drift(tracker):
        learnings.append(Learning(
            type="calibration",
            key=f"drift_{drift['tool']}",
            insight=f"{drift['tool']} is {drift['direction']}: actual={drift['actual_precision']:.0%} vs expected={drift['expected_precision']:.0%}",
            confidence=7,
            source="calibration",
            skill="pattern_analyzer",
            data=drift,
        ))

    # Quality tier
    quality = analyze_confidence_distribution(tracker)
    if quality.get("quality_tier") in ("weak", "moderate"):
        learnings.append(Learning(
            type="operational",
            key="quality_tier_warning",
            insight=f"Session quality is {quality['quality_tier']}: {'; '.join(quality.get('recommendations', []))}",
            confidence=6,
            source="observed",
            skill="pattern_analyzer",
            data=quality.get("percentages", {}),
        ))

    return learnings


def persist_learnings(tracker: MetricsTracker | None = None) -> int:
    """Analyze, generate learnings, and persist them. Returns count saved."""
    store = get_learnings_store()
    learnings = generate_learnings_from_analysis(tracker)
    for l in learnings:
        store.log(l)
    return len(learnings)
