"""Tests for the metrics tracker — in-memory and persistence."""

from __future__ import annotations

import pytest

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


# ---------------------------------------------------------------------------
# FP Warnings
# ---------------------------------------------------------------------------

class TestFPWarnings:
    def test_no_warning_without_feedback(self) -> None:
        tracker = MetricsTracker()
        tracker.record_finding("vuln_cors", Confidence.TENTATIVE, 0.3)
        assert tracker.get_fp_warning("vuln_cors") is None

    def test_no_warning_with_few_reviews(self) -> None:
        tracker = MetricsTracker()
        tracker.record_user_feedback("vuln_cors", is_true_positive=False)
        tracker.record_user_feedback("vuln_cors", is_true_positive=False)
        # Only 2 reviews — need at least 3 for warning
        assert tracker.get_fp_warning("vuln_cors") is None

    def test_high_fp_warning(self) -> None:
        tracker = MetricsTracker()
        tracker.record_user_feedback("vuln_cors", is_true_positive=False)
        tracker.record_user_feedback("vuln_cors", is_true_positive=False)
        tracker.record_user_feedback("vuln_cors", is_true_positive=False)
        tracker.record_user_feedback("vuln_cors", is_true_positive=True)

        warning = tracker.get_fp_warning("vuln_cors")
        assert warning is not None
        assert "HIGH FP RATE" in warning

    def test_moderate_fp_warning(self) -> None:
        tracker = MetricsTracker()
        tracker.record_user_feedback("vuln_xss", is_true_positive=False)
        tracker.record_user_feedback("vuln_xss", is_true_positive=True)
        tracker.record_user_feedback("vuln_xss", is_true_positive=False)

        warning = tracker.get_fp_warning("vuln_xss")
        assert warning is not None
        assert "MODERATE FP RATE" in warning

    def test_no_warning_good_precision(self) -> None:
        tracker = MetricsTracker()
        tracker.record_user_feedback("vuln_sqli", is_true_positive=True)
        tracker.record_user_feedback("vuln_sqli", is_true_positive=True)
        tracker.record_user_feedback("vuln_sqli", is_true_positive=True)

        assert tracker.get_fp_warning("vuln_sqli") is None

    def test_warnings_in_aggregate_summary(self) -> None:
        tracker = MetricsTracker()
        for _ in range(4):
            tracker.record_user_feedback("vuln_cors", is_true_positive=False)

        summary = tracker.aggregate_summary()
        assert "vuln_cors" in summary["warnings"]


# ---------------------------------------------------------------------------
# Persistence (save/load cycle)
# ---------------------------------------------------------------------------

class TestMetricsPersistence:
    def test_to_db_dict(self) -> None:
        tracker = MetricsTracker()
        tracker.record_run("vuln_sqli")
        tracker.record_finding("vuln_sqli", Confidence.CONFIRMED, 2.5)
        tracker.record_user_feedback("vuln_sqli", is_true_positive=True)

        db_dict = tracker.tools["vuln_sqli"].to_db_dict()
        assert db_dict["total_runs"] == 1
        assert db_dict["total_findings"] == 1
        assert db_dict["confirmed_count"] == 1
        assert db_dict["user_confirmed"] == 1

    def test_dirty_tracking(self) -> None:
        tracker = MetricsTracker()
        assert tracker.get_dirty_tools() == {}

        tracker.record_run("vuln_sqli")
        dirty = tracker.get_dirty_tools()
        assert "vuln_sqli" in dirty

        tracker.clear_dirty()
        assert tracker.get_dirty_tools() == {}

    def test_load_from_db(self) -> None:
        rows = [
            {
                "tool_name": "vuln_sqli",
                "total_runs": 50,
                "total_findings": 12,
                "confirmed_count": 8,
                "firm_count": 3,
                "tentative_count": 1,
                "user_confirmed": 10,
                "user_rejected": 2,
                "avg_evidence_weight": 2.1,
                "last_run": "2026-05-20T10:00:00+00:00",
            },
            {
                "tool_name": "vuln_cors",
                "total_runs": 30,
                "total_findings": 15,
                "confirmed_count": 2,
                "firm_count": 3,
                "tentative_count": 10,
                "user_confirmed": 3,
                "user_rejected": 7,
                "avg_evidence_weight": 0.5,
                "last_run": None,
            },
        ]

        tracker = MetricsTracker()
        tracker.load_from_db(rows)

        assert len(tracker.tools) == 2
        assert tracker.tools["vuln_sqli"].total_runs == 50
        assert tracker.tools["vuln_sqli"].confirmed_count == 8
        assert tracker.tools["vuln_cors"].fp_rate is not None
        assert tracker.tools["vuln_cors"].fp_rate > 0.5

    def test_cross_session_accumulation(self) -> None:
        """Simulate: load from previous session, add new data, verify merge."""
        # Session 1 data
        rows = [{
            "tool_name": "vuln_sqli",
            "total_runs": 10,
            "total_findings": 5,
            "confirmed_count": 3,
            "firm_count": 1,
            "tentative_count": 1,
            "user_confirmed": 4,
            "user_rejected": 1,
            "avg_evidence_weight": 2.0,
            "last_run": None,
        }]

        tracker = MetricsTracker()
        tracker.load_from_db(rows)

        # Session 2: new run and finding
        tracker.record_run("vuln_sqli")
        tracker.record_finding("vuln_sqli", Confidence.CONFIRMED, 3.0)

        metrics = tracker.tools["vuln_sqli"]
        assert metrics.total_runs == 11  # 10 + 1
        assert metrics.total_findings == 6  # 5 + 1
        assert metrics.confirmed_count == 4  # 3 + 1
        assert metrics.user_confirmed == 4  # unchanged

    @pytest.mark.asyncio
    async def test_db_round_trip(self, tmp_path) -> None:
        """Full save → load → verify cycle via database."""
        from kambo.database import Database

        db = Database(tmp_path / "metrics_test.db")
        await db.connect()

        # Save metrics
        tracker = MetricsTracker()
        tracker.record_run("vuln_sqli")
        tracker.record_finding("vuln_sqli", Confidence.CONFIRMED, 2.5)
        tracker.record_user_feedback("vuln_sqli", is_true_positive=True)

        for tool_name in tracker.tools:
            await db.save_tool_metrics(tool_name, tracker.tools[tool_name].to_db_dict())

        # Load into fresh tracker
        rows = await db.load_all_tool_metrics()
        tracker2 = MetricsTracker()
        tracker2.load_from_db(rows)

        assert tracker2.tools["vuln_sqli"].total_runs == 1
        assert tracker2.tools["vuln_sqli"].confirmed_count == 1
        assert tracker2.tools["vuln_sqli"].user_confirmed == 1

        await db.close()
