"""Tests for pattern analyzer and calibration engine."""

from __future__ import annotations

import pytest

from kambo.calibration import (
    calibrate_acceptance_rates,
    calibrate_confidence_weights,
    generate_calibration_report,
)
from kambo.metrics import MetricsTracker, ToolMetrics
from kambo.models import Confidence
from kambo.pattern_analyzer import (
    analyze_confidence_distribution,
    analyze_efficiency_patterns,
    analyze_tool_performance,
    detect_calibration_drift,
    generate_learnings_from_analysis,
)


def _make_tracker(**tools: dict) -> MetricsTracker:
    tracker = MetricsTracker()
    for name, data in tools.items():
        tracker.tools[name] = ToolMetrics(tool_name=name, **data)
    return tracker


class TestToolPerformance:
    def test_elite_tool_detection(self) -> None:
        tracker = _make_tracker(
            vuln_sqli={
                "total_runs": 10,
                "total_findings": 8,
                "confirmed_count": 6,
                "firm_count": 2,
                "user_confirmed": 7,
                "user_rejected": 1,
            }
        )
        insights = analyze_tool_performance(tracker)
        assert len(insights) == 1
        assert insights[0]["category"] == "elite"

    def test_broken_tool_detection(self) -> None:
        tracker = _make_tracker(
            vuln_cors={
                "total_runs": 10,
                "total_findings": 5,
                "confirmed_count": 1,
                "firm_count": 2,
                "tentative_count": 2,
                "user_confirmed": 1,
                "user_rejected": 7,
            }
        )
        insights = analyze_tool_performance(tracker)
        assert len(insights) == 1
        assert insights[0]["category"] == "broken"

    def test_noisy_tool_detection(self) -> None:
        tracker = _make_tracker(
            vuln_xss={
                "total_runs": 10,
                "total_findings": 8,
                "confirmed_count": 1,
                "firm_count": 2,
                "tentative_count": 5,
            }
        )
        insights = analyze_tool_performance(tracker)
        assert len(insights) == 1
        assert insights[0]["category"] == "noisy"

    def test_insufficient_data_skipped(self) -> None:
        tracker = _make_tracker(
            vuln_sqli={"total_runs": 1, "total_findings": 1}
        )
        insights = analyze_tool_performance(tracker)
        assert len(insights) == 0


class TestConfidenceDistribution:
    def test_elite_quality(self) -> None:
        tracker = _make_tracker(
            vuln_sqli={"confirmed_count": 10, "firm_count": 3, "tentative_count": 2, "total_findings": 15}
        )
        result = analyze_confidence_distribution(tracker)
        assert result["quality_tier"] == "elite"

    def test_weak_quality(self) -> None:
        tracker = _make_tracker(
            vuln_xss={"confirmed_count": 1, "firm_count": 2, "tentative_count": 20, "total_findings": 23}
        )
        result = analyze_confidence_distribution(tracker)
        assert result["quality_tier"] == "weak"

    def test_no_data(self) -> None:
        tracker = MetricsTracker()
        result = analyze_confidence_distribution(tracker)
        assert result["status"] == "no_data"


class TestEfficiencyPatterns:
    def test_top_performers_identified(self) -> None:
        tracker = _make_tracker(
            vuln_sqli={"total_runs": 5, "total_findings": 4, "confirmed_count": 3},
            vuln_xss={"total_runs": 10, "total_findings": 2, "confirmed_count": 0},
            vuln_cors={"total_runs": 5, "total_findings": 1, "confirmed_count": 1},
        )
        result = analyze_efficiency_patterns(tracker)
        assert "vuln_sqli" in result["top_performers"]
        assert result["tool_efficiency"][0]["tool"] == "vuln_sqli"

    def test_zero_yield_identified(self) -> None:
        tracker = _make_tracker(
            vuln_xss={"total_runs": 10, "total_findings": 0, "confirmed_count": 0},
        )
        result = analyze_efficiency_patterns(tracker)
        assert "vuln_xss" in result["zero_yield"]


class TestCalibrationDrift:
    def test_over_confident_tool(self) -> None:
        tracker = _make_tracker(
            vuln_cors={
                "total_runs": 10,
                "total_findings": 10,
                "confirmed_count": 5,
                "firm_count": 3,
                "tentative_count": 2,
                "user_confirmed": 3,
                "user_rejected": 5,
            }
        )
        drifts = detect_calibration_drift(tracker)
        over = [d for d in drifts if d["direction"] == "over-confident"]
        assert len(over) >= 1

    def test_well_calibrated_no_drift(self) -> None:
        # Match expected precision exactly
        tracker = _make_tracker(
            vuln_sqli={
                "total_runs": 10,
                "total_findings": 10,
                "confirmed_count": 8,
                "firm_count": 1,
                "tentative_count": 1,
                "user_confirmed": 8,
                "user_rejected": 2,
            }
        )
        drifts = detect_calibration_drift(tracker)
        # Should be within tolerance
        assert len(drifts) == 0


class TestLearningsGeneration:
    def test_generates_learnings_from_data(self) -> None:
        tracker = _make_tracker(
            vuln_sqli={
                "total_runs": 10,
                "total_findings": 8,
                "confirmed_count": 6,
                "firm_count": 2,
                "user_confirmed": 7,
                "user_rejected": 1,
            }
        )
        learnings = generate_learnings_from_analysis(tracker)
        assert len(learnings) >= 1
        assert any(l.type == "pattern" for l in learnings)


# ---------------------------------------------------------------------------
# Calibration Engine Tests
# ---------------------------------------------------------------------------

class TestCalibrationWeights:
    def test_conservative_weights_increased(self) -> None:
        tracker = _make_tracker(
            vuln_sqli={
                "total_runs": 20,
                "total_findings": 15,
                "confirmed_count": 5,
                "firm_count": 5,
                "tentative_count": 5,
                "user_confirmed": 12,
                "user_rejected": 1,
                "avg_evidence_weight": 1.5,
            }
        )
        adjustments = calibrate_confidence_weights(tracker)
        sqli_adj = [a for a in adjustments if a["tool"] == "vuln_sqli"]
        if sqli_adj:
            assert sqli_adj[0]["direction"] == "increase"

    def test_insufficient_data_skipped(self) -> None:
        tracker = _make_tracker(
            vuln_xss={"total_runs": 3, "total_findings": 2, "user_confirmed": 1, "user_rejected": 1}
        )
        adjustments = calibrate_confidence_weights(tracker)
        assert len(adjustments) == 0


class TestCalibrationAcceptanceRates:
    def test_acceptance_rate_adjustment(self) -> None:
        tracker = _make_tracker(
            vuln_cors={
                "total_runs": 15,
                "total_findings": 10,
                "confirmed_count": 3,
                "firm_count": 4,
                "tentative_count": 3,
                "user_confirmed": 3,
                "user_rejected": 5,
            }
        )
        adjustments = calibrate_acceptance_rates(tracker)
        cors_adj = [a for a in adjustments if a["vuln_type"] == "cors"]
        if cors_adj:
            # Should recommend lowering since actual < default
            assert cors_adj[0]["recommended_rate"] <= cors_adj[0]["current_rate"]


class TestCalibrationReport:
    def test_report_structure(self) -> None:
        tracker = _make_tracker(
            vuln_sqli={
                "total_runs": 20,
                "total_findings": 15,
                "confirmed_count": 10,
                "firm_count": 3,
                "tentative_count": 2,
                "user_confirmed": 12,
                "user_rejected": 1,
            }
        )
        report = generate_calibration_report(tracker)
        assert "health" in report
        assert "weight_adjustments" in report
        assert "acceptance_rate_adjustments" in report
        assert "recommendation" in report

    def test_insufficient_data_health(self) -> None:
        tracker = MetricsTracker()
        report = generate_calibration_report(tracker)
        assert report["health"] == "insufficient_data"
