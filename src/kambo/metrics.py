"""Metrics tracker — persisted across sessions via SQLite.

Tracks per-tool and aggregate statistics:
- Findings by confidence level (CONFIRMED/FIRM/TENTATIVE)
- User confirmations vs rejections (when user marks findings)
- Estimated precision per tool
- Evidence weight distribution
- Historical FP warnings for high-FP tools
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from kambo.models import Confidence


class ToolMetrics(BaseModel):
    """Metrics for a single tool."""

    tool_name: str
    total_runs: int = 0
    total_findings: int = 0
    confirmed_count: int = 0
    firm_count: int = 0
    tentative_count: int = 0
    user_confirmed: int = 0
    user_rejected: int = 0
    avg_evidence_weight: float = 0.0
    last_run: datetime | None = None

    @property
    def precision(self) -> float | None:
        total_reviewed = self.user_confirmed + self.user_rejected
        if total_reviewed == 0:
            return None
        return self.user_confirmed / total_reviewed

    @property
    def fp_rate(self) -> float | None:
        total_reviewed = self.user_confirmed + self.user_rejected
        if total_reviewed == 0:
            return None
        return self.user_rejected / total_reviewed

    @property
    def confidence_distribution(self) -> dict[str, int]:
        return {
            "confirmed": self.confirmed_count,
            "firm": self.firm_count,
            "tentative": self.tentative_count,
        }

    @property
    def fp_warning(self) -> str | None:
        """Return a warning if this tool has high historical FP rate."""
        fp = self.fp_rate
        total_reviewed = self.user_confirmed + self.user_rejected
        if fp is None or total_reviewed < 3:
            return None
        if fp >= 0.7:
            return f"HIGH FP RATE ({fp:.0%}) — {self.user_rejected}/{total_reviewed} findings were false positives. Consider skipping or cross-validating."
        if fp >= 0.5:
            return f"MODERATE FP RATE ({fp:.0%}) — manual verification recommended before reporting."
        return None

    def to_db_dict(self) -> dict[str, Any]:
        """Serialize for database storage."""
        return {
            "total_runs": self.total_runs,
            "total_findings": self.total_findings,
            "confirmed_count": self.confirmed_count,
            "firm_count": self.firm_count,
            "tentative_count": self.tentative_count,
            "user_confirmed": self.user_confirmed,
            "user_rejected": self.user_rejected,
            "avg_evidence_weight": self.avg_evidence_weight,
            "last_run": self.last_run.isoformat() if self.last_run else None,
        }

    def summary(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "tool": self.tool_name,
            "runs": self.total_runs,
            "findings": self.total_findings,
            "confidence_distribution": self.confidence_distribution,
            "precision": f"{self.precision:.0%}" if self.precision is not None else "no feedback",
            "fp_rate": f"{self.fp_rate:.0%}" if self.fp_rate is not None else "no feedback",
            "avg_evidence_weight": round(self.avg_evidence_weight, 2),
        }
        warning = self.fp_warning
        if warning:
            result["warning"] = warning
        return result


class MetricsTracker(BaseModel):
    """Aggregate metrics across all tools — persists to database."""

    tools: dict[str, ToolMetrics] = Field(default_factory=dict)
    session_start: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    _dirty_tools: set[str] = set()  # tools modified since last flush

    model_config = {"arbitrary_types_allowed": True}

    def _mark_dirty(self, tool_name: str) -> None:
        if not hasattr(self, "_dirty_tools") or not isinstance(self._dirty_tools, set):
            object.__setattr__(self, "_dirty_tools", set())
        self._dirty_tools.add(tool_name)

    def record_run(self, tool_name: str) -> None:
        metrics = self.tools.setdefault(tool_name, ToolMetrics(tool_name=tool_name))
        metrics.total_runs += 1
        metrics.last_run = datetime.now(timezone.utc)
        self._mark_dirty(tool_name)

    def record_finding(
        self,
        tool_name: str,
        confidence: Confidence,
        evidence_weight: float,
    ) -> None:
        metrics = self.tools.setdefault(tool_name, ToolMetrics(tool_name=tool_name))
        metrics.total_findings += 1

        if confidence == Confidence.CONFIRMED:
            metrics.confirmed_count += 1
        elif confidence == Confidence.FIRM:
            metrics.firm_count += 1
        else:
            metrics.tentative_count += 1

        n = metrics.total_findings
        metrics.avg_evidence_weight = (
            (metrics.avg_evidence_weight * (n - 1) + evidence_weight) / n
        )
        self._mark_dirty(tool_name)

    def record_user_feedback(self, tool_name: str, is_true_positive: bool) -> None:
        metrics = self.tools.setdefault(tool_name, ToolMetrics(tool_name=tool_name))
        if is_true_positive:
            metrics.user_confirmed += 1
        else:
            metrics.user_rejected += 1
        self._mark_dirty(tool_name)

    def get_fp_warning(self, tool_name: str) -> str | None:
        """Get historical FP warning for a tool, if any."""
        metrics = self.tools.get(tool_name)
        if metrics is None:
            return None
        return metrics.fp_warning

    def get_dirty_tools(self) -> dict[str, dict[str, Any]]:
        """Return metrics for tools modified since last flush."""
        if not hasattr(self, "_dirty_tools"):
            return {}
        result = {}
        for name in self._dirty_tools:
            if name in self.tools:
                result[name] = self.tools[name].to_db_dict()
        return result

    def clear_dirty(self) -> None:
        """Mark all tools as flushed."""
        if hasattr(self, "_dirty_tools"):
            self._dirty_tools.clear()

    def load_from_db(self, rows: list[dict]) -> None:
        """Load historical metrics from database rows."""
        for row in rows:
            name = row["tool_name"]
            last_run = None
            if row.get("last_run"):
                try:
                    last_run = datetime.fromisoformat(row["last_run"])
                except (ValueError, TypeError):
                    pass

            self.tools[name] = ToolMetrics(
                tool_name=name,
                total_runs=row.get("total_runs", 0),
                total_findings=row.get("total_findings", 0),
                confirmed_count=row.get("confirmed_count", 0),
                firm_count=row.get("firm_count", 0),
                tentative_count=row.get("tentative_count", 0),
                user_confirmed=row.get("user_confirmed", 0),
                user_rejected=row.get("user_rejected", 0),
                avg_evidence_weight=row.get("avg_evidence_weight", 0.0),
                last_run=last_run,
            )

    def aggregate_summary(self) -> dict[str, Any]:
        total_findings = sum(m.total_findings for m in self.tools.values())
        total_confirmed = sum(m.confirmed_count for m in self.tools.values())
        total_firm = sum(m.firm_count for m in self.tools.values())
        total_tentative = sum(m.tentative_count for m in self.tools.values())
        total_user_confirmed = sum(m.user_confirmed for m in self.tools.values())
        total_user_rejected = sum(m.user_rejected for m in self.tools.values())
        total_reviewed = total_user_confirmed + total_user_rejected

        # Collect warnings for high-FP tools
        warnings = {
            name: m.fp_warning
            for name, m in self.tools.items()
            if m.fp_warning is not None
        }

        return {
            "session_start": self.session_start.isoformat(),
            "total_tools_used": len(self.tools),
            "total_findings": total_findings,
            "confidence_distribution": {
                "confirmed": total_confirmed,
                "firm": total_firm,
                "tentative": total_tentative,
            },
            "quality_metrics": {
                "precision": f"{total_user_confirmed / total_reviewed:.0%}" if total_reviewed > 0 else "no feedback",
                "fp_rate": f"{total_user_rejected / total_reviewed:.0%}" if total_reviewed > 0 else "no feedback",
                "total_reviewed": total_reviewed,
            },
            "warnings": warnings,
            "recommendation": _quality_recommendation(total_confirmed, total_firm, total_tentative),
            "per_tool": {name: m.summary() for name, m in self.tools.items()},
        }


def _quality_recommendation(confirmed: int, firm: int, tentative: int) -> str:
    total = confirmed + firm + tentative
    if total == 0:
        return "No findings yet."
    confirmed_ratio = confirmed / total
    tentative_ratio = tentative / total
    if confirmed_ratio >= 0.5:
        return "High quality — majority of findings are exploit-confirmed."
    if tentative_ratio >= 0.7:
        return "Low quality — most findings are tentative. Manual verification needed before reporting."
    return "Moderate quality — mix of firm and tentative findings. Prioritize CONFIRMED and FIRM for reporting."


# Singleton
_tracker: MetricsTracker | None = None


def get_metrics() -> MetricsTracker:
    global _tracker
    if _tracker is None:
        _tracker = MetricsTracker()
    return _tracker


async def flush_metrics() -> None:
    """Persist dirty metrics to database."""
    tracker = get_metrics()
    dirty = tracker.get_dirty_tools()
    if not dirty:
        return

    from kambo.database import get_database
    db = await get_database()
    for tool_name, metrics_dict in dirty.items():
        await db.save_tool_metrics(tool_name, metrics_dict)
    tracker.clear_dirty()


async def load_metrics() -> None:
    """Load historical metrics from database into the tracker."""
    from kambo.database import get_database
    db = await get_database()
    rows = await db.load_all_tool_metrics()
    tracker = get_metrics()
    tracker.load_from_db(rows)
