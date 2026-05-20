"""Domain models for Kambo."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Phase(str, Enum):
    RECON = "recon"
    SCANNING = "scanning"
    VULN_ANALYSIS = "vulnerability_analysis"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    """Evidence-based confidence level for findings.

    CONFIRMED: Exploited and verified with concrete proof (e.g., data extracted,
               command executed, token forged). Equivalent to a real bug bounty finding.
    FIRM: Strong technical indicators from multiple signals, but not fully exploited.
          High probability of being real — worth reporting with caveats.
    TENTATIVE: Single signal or heuristic match. Needs manual verification before
               reporting. High false-positive risk.
    """
    CONFIRMED = "confirmed"
    FIRM = "firm"
    TENTATIVE = "tentative"


class Context(str, Enum):
    PENTEST = "pentest"
    BUG_BOUNTY = "bug_bounty"
    CTF = "ctf"


class EvidenceItem(BaseModel):
    """A single piece of evidence supporting a finding."""

    signal: str  # what was observed (e.g., "sqlmap detected injectable param")
    source: str  # tool or technique that produced it
    raw_data: str = ""  # truncated raw output proving this signal
    weight: float = 1.0  # how much this contributes to confidence (0.0-1.0)

    model_config = {"frozen": True}


class EvidenceChain(BaseModel):
    """Structured evidence chain that supports or refutes a finding.

    Confidence is computed from the weighted evidence items:
    - Total weight >= 2.0 → CONFIRMED
    - Total weight >= 1.0 → FIRM
    - Total weight > 0.0  → TENTATIVE
    """

    items: list[EvidenceItem] = Field(default_factory=list)
    baseline: dict[str, Any] = Field(default_factory=dict)  # baseline response for comparison
    false_positive_checks: list[str] = Field(default_factory=list)  # checks performed to rule out FP

    @property
    def total_weight(self) -> float:
        return sum(item.weight for item in self.items)

    @property
    def confidence(self) -> Confidence:
        w = self.total_weight
        if w >= 2.0:
            return Confidence.CONFIRMED
        if w >= 1.0:
            return Confidence.FIRM
        return Confidence.TENTATIVE

    @property
    def confidence_pct(self) -> int:
        """0-100 percentage representing confidence strength."""
        return min(100, int(self.total_weight * 40))

    def add(self, signal: str, source: str, raw_data: str = "", weight: float = 1.0) -> EvidenceChain:
        """Return a new chain with the evidence item appended (immutable)."""
        new_item = EvidenceItem(signal=signal, source=source, raw_data=raw_data[:2000], weight=weight)
        return self.model_copy(update={"items": [*self.items, new_item]})

    def add_fp_check(self, check: str) -> EvidenceChain:
        """Record a false-positive check that was performed."""
        return self.model_copy(update={"false_positive_checks": [*self.false_positive_checks, check]})

    def set_baseline(self, baseline: dict[str, Any]) -> EvidenceChain:
        """Set the baseline response used for comparison."""
        return self.model_copy(update={"baseline": baseline})

    def summary(self) -> dict[str, Any]:
        return {
            "confidence": self.confidence.value,
            "confidence_pct": self.confidence_pct,
            "total_weight": round(self.total_weight, 2),
            "signal_count": len(self.items),
            "signals": [item.signal for item in self.items],
            "fp_checks_performed": self.false_positive_checks,
        }


class ToolResult(BaseModel):
    """Immutable result from a tool execution."""

    tool_name: str
    command: str
    target: str
    phase: Phase
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    duration_seconds: float = 0.0
    exit_code: int = 0
    raw_output: str = ""
    parsed: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None

    model_config = {"frozen": True}


class Finding(BaseModel):
    """A security finding discovered during assessment."""

    id: str
    title: str
    severity: Severity
    confidence: Confidence = Confidence.TENTATIVE
    cvss: float | None = None
    cvss_vector: str | None = None
    phase: Phase
    target: str
    description: str
    reproduction_steps: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)
    evidence_chain: EvidenceChain = Field(default_factory=EvidenceChain)
    impact: str = ""
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    tools_used: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ScopeTarget(BaseModel):
    """A target within the authorized scope."""

    target: str  # domain, IP, CIDR
    target_type: str = "domain"  # domain, ip, cidr, url
    exclusions: list[str] = Field(default_factory=list)
    notes: str = ""


class EngagementScope(BaseModel):
    """Full engagement scope definition."""

    engagement_id: str = ""
    context: Context = Context.PENTEST
    platform: str = ""  # hackerone, bugcrowd, intigriti, etc.
    targets: list[ScopeTarget] = Field(default_factory=list)
    exclusions: list[str] = Field(default_factory=list)
    rate_limit: int | None = None  # override default
    rules: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
