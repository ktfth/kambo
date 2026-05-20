"""Metrics tracker for monitoring finding quality and false-positive rates.

Tracks per-tool and aggregate statistics:
- Findings by confidence level (CONFIRMED/FIRM/TENTATIVE)
- User confirmations vs rejections (when user marks findings)
- Estimated precision per tool
- Evidence weight distribution
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
    confirmed_count: int = 0  # CONFIRMED confidence
    firm_count: int = 0  # FIRM confidence
    tentative_count: int = 0  # TENTATIVE confidence
    user_confirmed: int = 0  # user marked as true positive
    user_rejected: int = 0  # user marked as false positive
    avg_evidence_weight: float = 0.0
    last_run: datetime | None = None

    @property
    def precision(self) -> float | None:
        """Estimated precision based on user confirmations.

        Returns None if no user feedback yet.
        """
        total_reviewed = self.user_confirmed + self.user_rejected
        if total_reviewed == 0:
            return None
        return self.user_confirmed / total_reviewed

    @property
    def fp_rate(self) -> float | None:
        """False positive rate from user feedback."""
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

    def summary(self) -> dict[str, Any]:
        return {
            "tool": self.tool_name,
            "runs": self.total_runs,
            "findings": self.total_findings,
            "confidence_distribution": self.confidence_distribution,
            "precision": f"{self.precision:.0%}" if self.precision is not None else "no feedback",
            "fp_rate": f"{self.fp_rate:.0%}" if self.fp_rate is not None else "no feedback",
            "avg_evidence_weight": round(self.avg_evidence_weight, 2),
        }


class MetricsTracker(BaseModel):
    """Aggregate metrics across all tools."""

    tools: dict[str, ToolMetrics] = Field(default_factory=dict)
    session_start: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def record_run(self, tool_name: str) -> None:
        """Record that a tool was executed."""
        metrics = self.tools.setdefault(tool_name, ToolMetrics(tool_name=tool_name))
        metrics.total_runs += 1
        metrics.last_run = datetime.now(timezone.utc)

    def record_finding(
        self,
        tool_name: str,
        confidence: Confidence,
        evidence_weight: float,
    ) -> None:
        """Record a finding with its confidence level."""
        metrics = self.tools.setdefault(tool_name, ToolMetrics(tool_name=tool_name))
        metrics.total_findings += 1

        if confidence == Confidence.CONFIRMED:
            metrics.confirmed_count += 1
        elif confidence == Confidence.FIRM:
            metrics.firm_count += 1
        else:
            metrics.tentative_count += 1

        # Rolling average of evidence weight
        n = metrics.total_findings
        metrics.avg_evidence_weight = (
            (metrics.avg_evidence_weight * (n - 1) + evidence_weight) / n
        )

    def record_user_feedback(self, tool_name: str, is_true_positive: bool) -> None:
        """Record user confirmation or rejection of a finding."""
        metrics = self.tools.setdefault(tool_name, ToolMetrics(tool_name=tool_name))
        if is_true_positive:
            metrics.user_confirmed += 1
        else:
            metrics.user_rejected += 1

    def aggregate_summary(self) -> dict[str, Any]:
        """Get aggregate metrics across all tools."""
        total_findings = sum(m.total_findings for m in self.tools.values())
        total_confirmed = sum(m.confirmed_count for m in self.tools.values())
        total_firm = sum(m.firm_count for m in self.tools.values())
        total_tentative = sum(m.tentative_count for m in self.tools.values())
        total_user_confirmed = sum(m.user_confirmed for m in self.tools.values())
        total_user_rejected = sum(m.user_rejected for m in self.tools.values())
        total_reviewed = total_user_confirmed + total_user_rejected

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
