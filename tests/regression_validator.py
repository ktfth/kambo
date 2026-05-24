"""Regression validator — discriminate test results to prevent regressions.

Reads a pytest JSON report (produced by `pytest --json-report`) and compares it
against a stored baseline, classifying every test into one of:

  - passed      : passing in current run
  - failed      : failing in current AND failing (or absent) in baseline
  - regression  : passing in baseline but failing in current (the bug)
  - recovered   : failing in baseline but passing in current (the fix)
  - flaky       : current status differs from a rerun of the same test
  - slow        : duration grew significantly vs baseline (or absolute threshold)
  - new         : test did not exist in baseline
  - removed     : test existed in baseline, no longer present

The validator exits non-zero only when there is a real regression, so flaky
or new failures don't auto-break the build. Slow / new / recovered are
reported but informational.

Usage:
    # Analyze an already-produced report
    python -m tests.regression_validator analyze \\
        --current .pytest-report.json \\
        --baseline baseline.json \\
        --markdown summary.md

    # Run pytest + analyze in one shot
    python -m tests.regression_validator run \\
        --baseline baseline.json

    # Promote the current report as the new baseline
    python -m tests.regression_validator promote \\
        --current .pytest-report.json \\
        --baseline baseline.json
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

Status = Literal["passed", "failed", "skipped", "error", "xfailed", "xpassed"]
Category = Literal[
    "passed",
    "failed",
    "regression",
    "recovered",
    "flaky",
    "slow",
    "new",
    "removed",
    "skipped",
]

SLOW_ABSOLUTE_SECONDS = 5.0
SLOW_RATIO = 2.0
SLOW_MIN_BASELINE_SECONDS = 0.2


@dataclass(frozen=True)
class CaseRecord:
    nodeid: str
    outcome: Status
    duration: float


@dataclass
class CaseVerdict:
    nodeid: str
    category: Category
    current_outcome: Status | None
    baseline_outcome: Status | None
    current_duration: float | None
    baseline_duration: float | None
    note: str = ""


@dataclass
class ValidationReport:
    verdicts: list[CaseVerdict] = field(default_factory=list)

    def by_category(self, category: Category) -> list[CaseVerdict]:
        return [v for v in self.verdicts if v.category == category]

    @property
    def counts(self) -> dict[Category, int]:
        out: dict[Category, int] = {}
        for v in self.verdicts:
            out[v.category] = out.get(v.category, 0) + 1
        return out

    @property
    def has_regression(self) -> bool:
        return any(v.category == "regression" for v in self.verdicts)

    @property
    def exit_code(self) -> int:
        if self.has_regression:
            return 2
        if self.by_category("failed"):
            return 1
        return 0


def load_report(path: Path) -> dict[str, CaseRecord]:
    """Parse a pytest-json-report file into {nodeid: CaseRecord}."""
    if not path.exists():
        return {}
    data = json.loads(path.read_text())
    tests = data.get("tests", [])
    records: dict[str, CaseRecord] = {}
    for t in tests:
        nodeid = t.get("nodeid")
        if not nodeid:
            continue
        outcome = t.get("outcome", "failed")
        # Sum duration across setup/call/teardown phases when available
        call = t.get("call") or {}
        setup = t.get("setup") or {}
        teardown = t.get("teardown") or {}
        duration = (
            float(call.get("duration", 0))
            + float(setup.get("duration", 0))
            + float(teardown.get("duration", 0))
        )
        records[nodeid] = CaseRecord(
            nodeid=nodeid, outcome=outcome, duration=duration
        )
    return records


def _is_slow(current: float, baseline: float | None) -> bool:
    if current >= SLOW_ABSOLUTE_SECONDS:
        return True
    if baseline is None or baseline < SLOW_MIN_BASELINE_SECONDS:
        return False
    return current > baseline * SLOW_RATIO


def classify(
    current: dict[str, CaseRecord],
    baseline: dict[str, CaseRecord],
    rerun: dict[str, CaseRecord] | None = None,
) -> ValidationReport:
    """Apply the classification rules in priority order.

    Priority: regression > flaky > recovered > new > failed > slow > passed.
    Each test gets exactly one category.
    """
    rerun = rerun or {}
    report = ValidationReport()
    seen: set[str] = set()

    for nodeid, cur in current.items():
        seen.add(nodeid)
        base = baseline.get(nodeid)
        rer = rerun.get(nodeid)

        cur_dur = cur.duration
        base_dur = base.duration if base else None

        # 1. Flaky — same test gave a different outcome on rerun
        if rer is not None and rer.outcome != cur.outcome:
            report.verdicts.append(CaseVerdict(
                nodeid=nodeid,
                category="flaky",
                current_outcome=cur.outcome,
                baseline_outcome=base.outcome if base else None,
                current_duration=cur_dur,
                baseline_duration=base_dur,
                note=f"rerun outcome: {rer.outcome}",
            ))
            continue

        # 2. Regression — was passing, now failing
        if base and base.outcome == "passed" and cur.outcome in ("failed", "error"):
            report.verdicts.append(CaseVerdict(
                nodeid=nodeid,
                category="regression",
                current_outcome=cur.outcome,
                baseline_outcome=base.outcome,
                current_duration=cur_dur,
                baseline_duration=base_dur,
            ))
            continue

        # 3. Recovered — was failing, now passing
        if base and base.outcome in ("failed", "error") and cur.outcome == "passed":
            report.verdicts.append(CaseVerdict(
                nodeid=nodeid,
                category="recovered",
                current_outcome=cur.outcome,
                baseline_outcome=base.outcome,
                current_duration=cur_dur,
                baseline_duration=base_dur,
            ))
            continue

        # 4. New — not present in baseline
        if base is None:
            cat: Category = "new" if cur.outcome == "passed" else "failed"
            report.verdicts.append(CaseVerdict(
                nodeid=nodeid,
                category=cat,
                current_outcome=cur.outcome,
                baseline_outcome=None,
                current_duration=cur_dur,
                baseline_duration=None,
                note="no baseline entry",
            ))
            continue

        # 5. Skipped passes straight through
        if cur.outcome == "skipped":
            report.verdicts.append(CaseVerdict(
                nodeid=nodeid,
                category="skipped",
                current_outcome=cur.outcome,
                baseline_outcome=base.outcome,
                current_duration=cur_dur,
                baseline_duration=base_dur,
            ))
            continue

        # 6. Failed — still failing (consistent failure)
        if cur.outcome in ("failed", "error"):
            report.verdicts.append(CaseVerdict(
                nodeid=nodeid,
                category="failed",
                current_outcome=cur.outcome,
                baseline_outcome=base.outcome,
                current_duration=cur_dur,
                baseline_duration=base_dur,
            ))
            continue

        # 7. Slow — passing but significantly slower
        if _is_slow(cur_dur, base_dur):
            ratio = (cur_dur / base_dur) if base_dur else None
            note = (
                f"{cur_dur:.2f}s vs {base_dur:.2f}s ({ratio:.1f}x)"
                if ratio
                else f"{cur_dur:.2f}s (absolute threshold)"
            )
            report.verdicts.append(CaseVerdict(
                nodeid=nodeid,
                category="slow",
                current_outcome=cur.outcome,
                baseline_outcome=base.outcome,
                current_duration=cur_dur,
                baseline_duration=base_dur,
                note=note,
            ))
            continue

        # 8. Passed cleanly
        report.verdicts.append(CaseVerdict(
            nodeid=nodeid,
            category="passed",
            current_outcome=cur.outcome,
            baseline_outcome=base.outcome,
            current_duration=cur_dur,
            baseline_duration=base_dur,
        ))

    for nodeid, base in baseline.items():
        if nodeid in seen:
            continue
        report.verdicts.append(CaseVerdict(
            nodeid=nodeid,
            category="removed",
            current_outcome=None,
            baseline_outcome=base.outcome,
            current_duration=None,
            baseline_duration=base.duration,
        ))

    return report


def render_text(report: ValidationReport) -> str:
    counts = report.counts
    order: list[Category] = [
        "regression",
        "failed",
        "flaky",
        "slow",
        "recovered",
        "new",
        "removed",
        "skipped",
        "passed",
    ]
    lines = ["Test regression summary", "=" * 40]
    for cat in order:
        n = counts.get(cat, 0)
        if n:
            lines.append(f"  {cat:<11s} {n}")
    lines.append("")

    for cat in ("regression", "failed", "flaky", "slow"):
        items = report.by_category(cat)
        if not items:
            continue
        lines.append(f"-- {cat.upper()} --")
        for v in items:
            extra = f"  [{v.note}]" if v.note else ""
            lines.append(f"  {v.nodeid}{extra}")
        lines.append("")

    return "\n".join(lines)


def render_markdown(report: ValidationReport) -> str:
    counts = report.counts
    badge_order: list[Category] = [
        "regression", "failed", "flaky", "slow",
        "recovered", "new", "removed", "passed",
    ]
    lines = ["## Regression validator", ""]
    lines.append("| Category | Count |")
    lines.append("|---|---|")
    for cat in badge_order:
        n = counts.get(cat, 0)
        if n:
            lines.append(f"| `{cat}` | {n} |")
    lines.append("")

    for cat, header in (
        ("regression", "Regressions (passed in baseline, failing now)"),
        ("failed", "Failures (failing in baseline and now)"),
        ("flaky", "Flaky (different outcome on rerun)"),
        ("slow", "Slow (significantly slower than baseline)"),
    ):
        items = report.by_category(cat)
        if not items:
            continue
        lines.append(f"### {header}")
        for v in items:
            extra = f" — {v.note}" if v.note else ""
            lines.append(f"- `{v.nodeid}`{extra}")
        lines.append("")

    if not report.has_regression and not report.by_category("failed"):
        lines.append("No regressions or failures detected.")
    return "\n".join(lines)


def run_pytest(report_path: Path, extra_args: list[str] | None = None) -> int:
    """Invoke pytest with the JSON report plugin and return its exit code.

    Always uses `sys.executable -m pytest` to ensure the subprocess shares the
    interpreter (and therefore the installed packages) of the caller.
    """
    cmd = [
        sys.executable, "-m", "pytest",
        "--json-report",
        f"--json-report-file={report_path}",
        "-q",
    ]
    if extra_args:
        # argparse.REMAINDER may keep a leading "--" separator — strip it.
        if extra_args and extra_args[0] == "--":
            extra_args = extra_args[1:]
        cmd += extra_args
    completed = subprocess.run(cmd, check=False)
    return completed.returncode


def _cmd_analyze(args: argparse.Namespace) -> int:
    current = load_report(Path(args.current))
    baseline = load_report(Path(args.baseline)) if args.baseline else {}
    rerun = load_report(Path(args.rerun)) if args.rerun else {}
    report = classify(current, baseline, rerun)
    print(render_text(report))
    if args.markdown:
        Path(args.markdown).write_text(render_markdown(report))
    return report.exit_code


def _cmd_run(args: argparse.Namespace) -> int:
    report_path = Path(args.current)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    run_pytest(report_path, args.pytest_args)
    return _cmd_analyze(args)


def _cmd_promote(args: argparse.Namespace) -> int:
    src = Path(args.current)
    dst = Path(args.baseline)
    if not src.exists():
        print(f"current report not found: {src}", file=sys.stderr)
        return 1
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dst)
    print(f"promoted {src} -> {dst}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="regression_validator")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="Compare an existing report against baseline")
    a.add_argument("--current", required=True)
    a.add_argument("--baseline", default=None)
    a.add_argument("--rerun", default=None, help="Optional second run for flake detection")
    a.add_argument("--markdown", default=None, help="Write markdown summary to this path")
    a.set_defaults(func=_cmd_analyze)

    r = sub.add_parser("run", help="Run pytest and analyze")
    r.add_argument("--current", default=".pytest-report.json")
    r.add_argument("--baseline", default=None)
    r.add_argument("--rerun", default=None)
    r.add_argument("--markdown", default=None)
    r.add_argument("pytest_args", nargs=argparse.REMAINDER)
    r.set_defaults(func=_cmd_run)

    pr = sub.add_parser("promote", help="Promote current report as new baseline")
    pr.add_argument("--current", required=True)
    pr.add_argument("--baseline", required=True)
    pr.set_defaults(func=_cmd_promote)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
