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


class Context(str, Enum):
    PENTEST = "pentest"
    BUG_BOUNTY = "bug_bounty"
    CTF = "ctf"


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
    cvss: float | None = None
    cvss_vector: str | None = None
    phase: Phase
    target: str
    description: str
    reproduction_steps: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)
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
