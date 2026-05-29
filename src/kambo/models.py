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


# Strict ordering of confidence tiers — used by the ceiling/gate mechanism to
# compare and cap tiers. Higher rank = stronger confidence.
_CONFIDENCE_RANK: dict[Confidence, int] = {
    Confidence.TENTATIVE: 0,
    Confidence.FIRM: 1,
    Confidence.CONFIRMED: 2,
}


def confidence_meets(value: Confidence, minimum: Confidence) -> bool:
    """True iff ``value`` is at least as strong as ``minimum``.

    Use this for verdicts ("is it vulnerable?") so a gated ceiling is honored —
    never decide off raw weight, which ignores caps (doctrine §3/§6).
    """
    return _CONFIDENCE_RANK[value] >= _CONFIDENCE_RANK[minimum]


def chain_rank(chain: "EvidenceChain") -> tuple[int, float]:
    """Comparable key for picking the strongest of several chains: effective
    confidence first (so gates are honored), then accumulated weight as a
    tie-breaker. Use instead of comparing raw ``total_weight`` (doctrine §6)."""
    return (_CONFIDENCE_RANK[chain.confidence], chain.total_weight)


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

    Confidence is computed from the weighted evidence items, then **capped** by
    any gates that apply (doctrine §3 — "sinais que CAPEIAM, não que somam"):

    Weight-derived tier:
    - Total weight >= 2.0 → CONFIRMED
    - Total weight >= 1.0 → FIRM
    - Total weight > 0.0  → TENTATIVE

    Effective confidence = min(weight-derived tier, ``ceiling``). A gate lowers
    the ceiling regardless of how much positive weight accumulated. This is how
    the invariants are enforced structurally: e.g. a blind class with no OOB hit
    is capped at TENTATIVE even if keyword signals piled up weight.
    """

    items: list[EvidenceItem] = Field(default_factory=list)
    baseline: dict[str, Any] = Field(default_factory=dict)  # baseline response for comparison
    false_positive_checks: list[str] = Field(default_factory=list)  # checks performed to rule out FP
    ceiling: Confidence = Confidence.CONFIRMED  # hard cap on confidence tier (default: no cap)
    gates: list[str] = Field(default_factory=list)  # reasons the ceiling was lowered
    flags: list[str] = Field(default_factory=list)  # actionable flags, e.g. needs-browser-verification

    @property
    def total_weight(self) -> float:
        return sum(item.weight for item in self.items)

    @property
    def weight_confidence(self) -> Confidence:
        """Tier derived purely from accumulated weight, ignoring gates."""
        w = self.total_weight
        if w >= 2.0:
            return Confidence.CONFIRMED
        if w >= 1.0:
            return Confidence.FIRM
        return Confidence.TENTATIVE

    @property
    def confidence(self) -> Confidence:
        """Effective confidence — weight-derived tier capped by the ceiling."""
        weight_tier = self.weight_confidence
        if _CONFIDENCE_RANK[weight_tier] <= _CONFIDENCE_RANK[self.ceiling]:
            return weight_tier
        return self.ceiling

    @property
    def is_capped(self) -> bool:
        """True when a gate lowered the effective confidence below its weight tier."""
        return _CONFIDENCE_RANK[self.weight_confidence] > _CONFIDENCE_RANK[self.ceiling]

    @property
    def confidence_pct(self) -> int:
        """0-100 percentage representing confidence strength within the effective tier.

        Mapping (before capping):
          TENTATIVE (weight 0.0–0.99): 10–39%   — single signal, high FP risk
          FIRM      (weight 1.0–1.99): 50–79%   — multiple signals, reportable with caveats
          CONFIRMED (weight 2.0+):     85–99%   — exploit-grade, ready to submit

        When a gate caps the tier, the percentage is clamped to the top of the
        capped tier's band (FIRM → max 79, TENTATIVE → max 39) so the number can
        never imply a confidence the gate has forbidden.
        """
        w = self.total_weight
        if w >= 2.0:
            pct = min(99, 85 + int((w - 2.0) * 7))
        elif w >= 1.0:
            pct = 50 + int((w - 1.0) * 29)
        elif w == 0:
            pct = 0
        else:
            pct = max(10, min(39, 10 + int(w * 29)))

        # Clamp into the effective (capped) tier's band.
        if self.ceiling == Confidence.FIRM:
            pct = min(pct, 79)
        elif self.ceiling == Confidence.TENTATIVE:
            pct = min(pct, 39)
        return pct

    def add(self, signal: str, source: str, raw_data: str = "", weight: float = 1.0) -> EvidenceChain:
        """Return a new chain with the evidence item appended (immutable)."""
        new_item = EvidenceItem(signal=signal, source=source, raw_data=raw_data[:2000], weight=weight)
        return self.model_copy(update={"items": [*self.items, new_item]})

    def add_fp_check(self, check: str) -> EvidenceChain:
        """Record a false-positive check that was performed."""
        return self.model_copy(update={"false_positive_checks": [*self.false_positive_checks, check]})

    def cap(self, level: Confidence, reason: str) -> EvidenceChain:
        """Lower the confidence ceiling to ``level`` (a gate).

        The ceiling only ever moves *down*. Applying a stricter-or-equal cap than
        the default CONFIRMED records the gate reason (so the audit trail keeps
        every gate that constrained the finding, including a weaker cap layered
        after a stronger one). Capping to CONFIRMED is meaningless — it can never
        constrain anything — so it is a true no-op and is not recorded. §3.
        """
        if level == Confidence.CONFIRMED:
            return self  # no-op: CONFIRMED is the default ceiling, caps nothing
        new_ceiling = self.ceiling
        if _CONFIDENCE_RANK[level] < _CONFIDENCE_RANK[self.ceiling]:
            new_ceiling = level
        return self.model_copy(
            update={"ceiling": new_ceiling, "gates": [*self.gates, reason]}
        )

    def add_flag(self, flag: str) -> EvidenceChain:
        """Attach an actionable flag (e.g. 'needs-browser-verification')."""
        if flag in self.flags:
            return self
        return self.model_copy(update={"flags": [*self.flags, flag]})

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
            "ceiling": self.ceiling.value,
            "is_capped": self.is_capped,
            "gates": self.gates,
            "flags": self.flags,
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
