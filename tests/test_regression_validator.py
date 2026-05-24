"""Tests for the regression validator itself."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.regression_validator import (
    CaseRecord,
    build_parser,
    classify,
    load_report,
    render_markdown,
    render_text,
)


def _write_report(path: Path, tests: list[dict]) -> None:
    path.write_text(json.dumps({"tests": tests}))


def _t(nodeid: str, outcome: str, duration: float = 0.01) -> dict:
    return {
        "nodeid": nodeid,
        "outcome": outcome,
        "call": {"duration": duration},
    }


def test_load_report_sums_phases(tmp_path: Path) -> None:
    path = tmp_path / "r.json"
    path.write_text(json.dumps({
        "tests": [
            {
                "nodeid": "tests/test_a.py::test_one",
                "outcome": "passed",
                "setup": {"duration": 0.1},
                "call": {"duration": 0.2},
                "teardown": {"duration": 0.05},
            }
        ]
    }))
    records = load_report(path)
    assert "tests/test_a.py::test_one" in records
    rec = records["tests/test_a.py::test_one"]
    assert rec.outcome == "passed"
    assert rec.duration == pytest.approx(0.35)


def test_load_report_missing_file_returns_empty(tmp_path: Path) -> None:
    assert load_report(tmp_path / "missing.json") == {}


def test_classify_detects_regression() -> None:
    baseline = {"t::a": CaseRecord("t::a", "passed", 0.1)}
    current = {"t::a": CaseRecord("t::a", "failed", 0.1)}
    report = classify(current, baseline)
    assert report.has_regression
    assert report.exit_code == 2
    assert report.by_category("regression")[0].nodeid == "t::a"


def test_classify_detects_recovered() -> None:
    baseline = {"t::a": CaseRecord("t::a", "failed", 0.1)}
    current = {"t::a": CaseRecord("t::a", "passed", 0.1)}
    report = classify(current, baseline)
    assert not report.has_regression
    assert report.by_category("recovered")[0].nodeid == "t::a"
    assert report.exit_code == 0


def test_classify_detects_flaky_when_rerun_differs() -> None:
    baseline = {"t::a": CaseRecord("t::a", "passed", 0.1)}
    current = {"t::a": CaseRecord("t::a", "failed", 0.1)}
    rerun = {"t::a": CaseRecord("t::a", "passed", 0.1)}
    report = classify(current, baseline, rerun)
    # Flaky takes precedence over regression
    assert not report.has_regression
    assert report.by_category("flaky")[0].nodeid == "t::a"


def test_classify_marks_new_failing_tests_as_failed_not_regression() -> None:
    current = {"t::new": CaseRecord("t::new", "failed", 0.1)}
    report = classify(current, baseline={})
    assert not report.has_regression
    assert report.exit_code == 1  # failed but not regression
    assert report.by_category("failed")[0].nodeid == "t::new"


def test_classify_marks_new_passing_tests_as_new() -> None:
    current = {"t::new": CaseRecord("t::new", "passed", 0.1)}
    report = classify(current, baseline={})
    assert report.by_category("new")[0].nodeid == "t::new"
    assert report.exit_code == 0


def test_classify_detects_removed() -> None:
    baseline = {"t::gone": CaseRecord("t::gone", "passed", 0.1)}
    current: dict[str, CaseRecord] = {}
    report = classify(current, baseline)
    assert report.by_category("removed")[0].nodeid == "t::gone"


def test_classify_detects_slow_by_ratio() -> None:
    baseline = {"t::a": CaseRecord("t::a", "passed", 0.5)}
    current = {"t::a": CaseRecord("t::a", "passed", 1.5)}
    report = classify(current, baseline)
    assert report.by_category("slow")[0].nodeid == "t::a"


def test_classify_detects_slow_by_absolute_threshold() -> None:
    current = {"t::a": CaseRecord("t::a", "passed", 6.0)}
    report = classify(current, baseline={"t::a": CaseRecord("t::a", "passed", 5.5)})
    # 6.0 hits the absolute SLOW_ABSOLUTE_SECONDS threshold
    assert report.by_category("slow")[0].nodeid == "t::a"


def test_classify_does_not_flag_slow_when_baseline_tiny() -> None:
    # 0.01s -> 0.05s shouldn't trip the alarm even though 5x
    baseline = {"t::a": CaseRecord("t::a", "passed", 0.01)}
    current = {"t::a": CaseRecord("t::a", "passed", 0.05)}
    report = classify(current, baseline)
    assert report.by_category("slow") == []
    assert report.by_category("passed")[0].nodeid == "t::a"


def test_classify_skipped_stays_skipped() -> None:
    baseline = {"t::a": CaseRecord("t::a", "passed", 0.1)}
    current = {"t::a": CaseRecord("t::a", "skipped", 0.0)}
    report = classify(current, baseline)
    assert report.by_category("skipped")[0].nodeid == "t::a"


def test_classify_consistent_failure_is_not_regression() -> None:
    baseline = {"t::a": CaseRecord("t::a", "failed", 0.1)}
    current = {"t::a": CaseRecord("t::a", "failed", 0.1)}
    report = classify(current, baseline)
    assert not report.has_regression
    assert report.by_category("failed")[0].nodeid == "t::a"
    assert report.exit_code == 1


def test_exit_code_zero_when_all_pass() -> None:
    current = {"t::a": CaseRecord("t::a", "passed", 0.1)}
    baseline = {"t::a": CaseRecord("t::a", "passed", 0.1)}
    assert classify(current, baseline).exit_code == 0


def test_render_text_includes_regression_section() -> None:
    report = classify(
        current={"t::a": CaseRecord("t::a", "failed", 0.1)},
        baseline={"t::a": CaseRecord("t::a", "passed", 0.1)},
    )
    text = render_text(report)
    assert "REGRESSION" in text
    assert "t::a" in text


def test_render_markdown_includes_table_and_no_regression_message() -> None:
    report = classify(
        current={"t::a": CaseRecord("t::a", "passed", 0.1)},
        baseline={"t::a": CaseRecord("t::a", "passed", 0.1)},
    )
    md = render_markdown(report)
    assert "| Category | Count |" in md
    assert "No regressions" in md


def test_render_markdown_lists_regressions() -> None:
    report = classify(
        current={"t::a": CaseRecord("t::a", "failed", 0.1)},
        baseline={"t::a": CaseRecord("t::a", "passed", 0.1)},
    )
    md = render_markdown(report)
    assert "Regressions" in md
    assert "`t::a`" in md


def test_cli_analyze_returns_regression_exit_code(tmp_path: Path) -> None:
    cur = tmp_path / "current.json"
    base = tmp_path / "baseline.json"
    _write_report(cur, [_t("t::a", "failed")])
    _write_report(base, [_t("t::a", "passed")])

    parser = build_parser()
    args = parser.parse_args([
        "analyze", "--current", str(cur), "--baseline", str(base),
    ])
    assert args.func(args) == 2


def test_cli_analyze_writes_markdown(tmp_path: Path) -> None:
    cur = tmp_path / "current.json"
    base = tmp_path / "baseline.json"
    md = tmp_path / "summary.md"
    _write_report(cur, [_t("t::a", "passed")])
    _write_report(base, [_t("t::a", "passed")])

    parser = build_parser()
    args = parser.parse_args([
        "analyze", "--current", str(cur), "--baseline", str(base),
        "--markdown", str(md),
    ])
    assert args.func(args) == 0
    assert md.exists()
    assert "| Category | Count |" in md.read_text()


def test_cli_promote_copies_current_to_baseline(tmp_path: Path) -> None:
    cur = tmp_path / "current.json"
    base = tmp_path / "baseline.json"
    _write_report(cur, [_t("t::a", "passed")])

    parser = build_parser()
    args = parser.parse_args([
        "promote", "--current", str(cur), "--baseline", str(base),
    ])
    assert args.func(args) == 0
    assert base.exists()
    assert json.loads(base.read_text()) == json.loads(cur.read_text())


def test_cli_promote_fails_when_current_missing(tmp_path: Path) -> None:
    parser = build_parser()
    args = parser.parse_args([
        "promote",
        "--current", str(tmp_path / "missing.json"),
        "--baseline", str(tmp_path / "baseline.json"),
    ])
    assert args.func(args) == 1
