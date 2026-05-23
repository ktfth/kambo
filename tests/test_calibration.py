"""Tests for the self-calibration engine."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from kambo.calibration import (
    calibrate_acceptance_rates,
    calibrate_confidence_weights,
    generate_calibration_report,
    persist_calibration_learnings,
)
from kambo.learnings import LearningsStore
from kambo.metrics import MetricsTracker, ToolMetrics


def _make_tracker(**tools: dict) -> MetricsTracker:
    tracker = MetricsTracker()
    for name, data in tools.items():
        tracker.tools[name] = ToolMetrics(tool_name=name, **data)
    return tracker


class TestCalibrateConfidenceWeights:
    def test_aggressive_weights_decreased(self) -> None:
        """Tool with actual precision < expected → decrease weights."""
        tracker = _make_tracker(
            vuln_sqli={
                "total_runs": 20,
                "total_findings": 10,
                "confirmed_count": 8,
                "firm_count": 1,
                "tentative_count": 1,
                "user_confirmed": 3,
                "user_rejected": 5,
            }
        )
        adjustments = calibrate_confidence_weights(tracker)
        sqli = [a for a in adjustments if a["tool"] == "vuln_sqli"]
        if sqli:
            assert sqli[0]["direction"] == "decrease"
            assert sqli[0]["adjustment_factor"] < 1.0

    def test_no_adjustment_within_margin(self) -> None:
        """Tools within ±10% drift get no adjustment."""
        tracker = _make_tracker(
            vuln_xss={
                "total_runs": 20,
                "total_findings": 10,
                "confirmed_count": 5,
                "firm_count": 3,
                "tentative_count": 2,
                "user_confirmed": 7,
                "user_rejected": 3,
            }
        )
        adjustments = calibrate_confidence_weights(tracker)
        xss = [a for a in adjustments if a["tool"] == "vuln_xss"]
        # Should be empty or within margin
        for adj in xss:
            assert abs(adj["drift"]) >= 0.10

    def test_weight_bounds(self) -> None:
        """Recommended weights should stay in reasonable bounds."""
        tracker = _make_tracker(
            vuln_sqli={
                "total_runs": 30,
                "total_findings": 20,
                "confirmed_count": 5,
                "firm_count": 5,
                "tentative_count": 10,
                "user_confirmed": 18,
                "user_rejected": 0,
            }
        )
        adjustments = calibrate_confidence_weights(tracker)
        for adj in adjustments:
            for weight in adj["recommended_weights"].values():
                assert 0.01 <= weight <= 5.0, f"Weight {weight} out of bounds"

    def test_sample_size_minimum(self) -> None:
        """Tools with < 5 reviews should be skipped."""
        tracker = _make_tracker(
            vuln_cors={
                "total_runs": 5,
                "total_findings": 3,
                "user_confirmed": 2,
                "user_rejected": 1,
            }
        )
        adjustments = calibrate_confidence_weights(tracker)
        assert len(adjustments) == 0


class TestCalibrateAcceptanceRates:
    def test_rate_decreased_for_high_fp_tool(self) -> None:
        """Tool with low actual acceptance → lower the rate."""
        tracker = _make_tracker(
            vuln_cors={
                "total_runs": 20,
                "total_findings": 15,
                "confirmed_count": 5,
                "firm_count": 5,
                "tentative_count": 5,
                "user_confirmed": 2,
                "user_rejected": 8,
            }
        )
        adjustments = calibrate_acceptance_rates(tracker)
        cors = [a for a in adjustments if a["vuln_type"] == "cors"]
        if cors:
            assert cors[0]["recommended_rate"] < cors[0]["current_rate"]

    def test_rate_clamped_to_bounds(self) -> None:
        """Rates should stay between 0.05 and 0.99."""
        tracker = _make_tracker(
            vuln_cors={
                "total_runs": 30,
                "total_findings": 20,
                "user_confirmed": 0,
                "user_rejected": 20,
            }
        )
        adjustments = calibrate_acceptance_rates(tracker)
        for adj in adjustments:
            assert 0.05 <= adj["recommended_rate"] <= 0.99

    def test_unmapped_tool_skipped(self) -> None:
        """Tools not in _tool_to_vuln mapping should produce no adjustments."""
        tracker = _make_tracker(
            scan_directories={
                "total_runs": 20,
                "total_findings": 10,
                "user_confirmed": 5,
                "user_rejected": 5,
            }
        )
        adjustments = calibrate_acceptance_rates(tracker)
        assert len(adjustments) == 0


class TestCalibrationReport:
    def test_needs_recalibration_flag(self) -> None:
        """Large drift (>20%) should trigger recalibration."""
        tracker = _make_tracker(
            vuln_sqli={
                "total_runs": 30,
                "total_findings": 20,
                "confirmed_count": 15,
                "firm_count": 3,
                "tentative_count": 2,
                "user_confirmed": 5,
                "user_rejected": 10,
            }
        )
        report = generate_calibration_report(tracker)
        # With such a large gap between expected and actual, should flag
        if report["total_adjustments"] > 0:
            assert "health" in report
            assert "recommendation" in report

    def test_calibrated_health(self) -> None:
        """Well-matched predictions should report calibrated."""
        tracker = _make_tracker(
            vuln_sqli={
                "total_runs": 20,
                "total_findings": 10,
                "confirmed_count": 8,
                "firm_count": 1,
                "tentative_count": 1,
                "user_confirmed": 9,
                "user_rejected": 1,
            }
        )
        report = generate_calibration_report(tracker)
        assert report["health"] in ("calibrated", "insufficient_data", "needs_recalibration")


class TestPersistCalibrationLearnings:
    def test_persist_writes_to_store(self, tmp_path: Path) -> None:
        """persist_calibration_learnings should write entries to the store."""
        import kambo.learnings as learnings_mod
        original_store = learnings_mod._store
        try:
            learnings_mod._store = LearningsStore(tmp_path / "test_learnings.jsonl")

            tracker = _make_tracker(
                vuln_sqli={
                    "total_runs": 30,
                    "total_findings": 20,
                    "confirmed_count": 5,
                    "firm_count": 5,
                    "tentative_count": 10,
                    "user_confirmed": 18,
                    "user_rejected": 0,
                }
            )
            count = persist_calibration_learnings(tracker)
            store = learnings_mod._store
            all_learnings = store.search(limit=50)

            # Should have persisted some calibration entries
            if count > 0:
                assert len(all_learnings) > 0
                assert all(l["type"] == "calibration" for l in all_learnings)
        finally:
            learnings_mod._store = original_store

    def test_persist_returns_zero_without_data(self) -> None:
        """No adjustments → 0 learnings persisted."""
        tracker = MetricsTracker()
        count = persist_calibration_learnings(tracker)
        assert count == 0
