"""Tests for the metrics tracker."""

from __future__ import annotations

from kambo.metrics import MetricsTracker
from kambo.models import Confidence


class TestMetricsTracker:
    def test_empty_tracker(self) -> None:
        tracker = MetricsTracker()
        summary = tracker.aggregate_summary()
        assert summary["total_findings"] == 0
        assert summary["total_tools_used"] == 0

    def test_record_run(self) -> None:
        tracker = MetricsTracker()
        tracker.record_run("vuln_sqli")
        tracker.record_run("vuln_sqli")
        tracker.record_run("vuln_xss")

        assert tracker.tools["vuln_sqli"].total_runs == 2
        assert tracker.tools["vuln_xss"].total_runs == 1

    def test_record_finding_confidence_distribution(self) -> None:
        tracker = MetricsTracker()
        tracker.record_finding("vuln_sqli", Confidence.CONFIRMED, 2.5)
        tracker.record_finding("vuln_sqli", Confidence.FIRM, 1.2)
        tracker.record_finding("vuln_sqli", Confidence.TENTATIVE, 0.3)

        metrics = tracker.tools["vuln_sqli"]
        assert metrics.confirmed_count == 1
        assert metrics.firm_count == 1
        assert metrics.tentative_count == 1
        assert metrics.total_findings == 3

    def test_precision_no_feedback(self) -> None:
        tracker = MetricsTracker()
        tracker.record_finding("vuln_sqli", Confidence.CONFIRMED, 2.0)

        assert tracker.tools["vuln_sqli"].precision is None

    def test_precision_with_feedback(self) -> None:
        tracker = MetricsTracker()
        tracker.record_user_feedback("vuln_sqli", is_true_positive=True)
        tracker.record_user_feedback("vuln_sqli", is_true_positive=True)
        tracker.record_user_feedback("vuln_sqli", is_true_positive=False)

        precision = tracker.tools["vuln_sqli"].precision
        assert precision is not None
        assert abs(precision - 0.6667) < 0.01

    def test_fp_rate(self) -> None:
        tracker = MetricsTracker()
        tracker.record_user_feedback("vuln_cors", is_true_positive=False)
        tracker.record_user_feedback("vuln_cors", is_true_positive=False)
        tracker.record_user_feedback("vuln_cors", is_true_positive=True)

        fp_rate = tracker.tools["vuln_cors"].fp_rate
        assert fp_rate is not None
        assert abs(fp_rate - 0.6667) < 0.01

    def test_avg_evidence_weight(self) -> None:
        tracker = MetricsTracker()
        tracker.record_finding("vuln_sqli", Confidence.CONFIRMED, 3.0)
        tracker.record_finding("vuln_sqli", Confidence.FIRM, 1.0)

        avg = tracker.tools["vuln_sqli"].avg_evidence_weight
        assert abs(avg - 2.0) < 0.01

    def test_aggregate_summary(self) -> None:
        tracker = MetricsTracker()
        tracker.record_finding("vuln_sqli", Confidence.CONFIRMED, 2.5)
        tracker.record_finding("vuln_xss", Confidence.TENTATIVE, 0.3)
        tracker.record_user_feedback("vuln_sqli", is_true_positive=True)

        summary = tracker.aggregate_summary()
        assert summary["total_findings"] == 2
        assert summary["confidence_distribution"]["confirmed"] == 1
        assert summary["confidence_distribution"]["tentative"] == 1
        assert summary["quality_metrics"]["precision"] == "100%"
        assert summary["total_tools_used"] == 2

    def test_tool_summary(self) -> None:
        tracker = MetricsTracker()
        tracker.record_run("vuln_sqli")
        tracker.record_finding("vuln_sqli", Confidence.CONFIRMED, 2.0)

        tool_summary = tracker.tools["vuln_sqli"].summary()
        assert tool_summary["runs"] == 1
        assert tool_summary["findings"] == 1
        assert tool_summary["confidence_distribution"]["confirmed"] == 1

    def test_quality_recommendation_high(self) -> None:
        tracker = MetricsTracker()
        tracker.record_finding("t1", Confidence.CONFIRMED, 2.0)
        tracker.record_finding("t2", Confidence.CONFIRMED, 2.5)

        summary = tracker.aggregate_summary()
        assert "High quality" in summary["recommendation"]

    def test_quality_recommendation_low(self) -> None:
        tracker = MetricsTracker()
        for i in range(5):
            tracker.record_finding(f"t{i}", Confidence.TENTATIVE, 0.2)

        summary = tracker.aggregate_summary()
        assert "Low quality" in summary["recommendation"]
