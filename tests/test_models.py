"""Tests for core domain models."""

from __future__ import annotations

import pytest

from kambo.models import (
    Confidence,
    Context,
    EvidenceChain,
    EvidenceItem,
    Finding,
    Phase,
    Severity,
    ToolResult,
)


class TestEvidenceItem:
    def test_frozen(self) -> None:
        item = EvidenceItem(signal="test", source="unit", weight=1.0)
        with pytest.raises(Exception):
            item.signal = "changed"  # type: ignore

    def test_raw_data_default_empty(self) -> None:
        item = EvidenceItem(signal="s", source="src")
        assert item.raw_data == ""
        assert item.weight == 1.0


class TestEvidenceChain:
    def test_empty_chain_tentative(self) -> None:
        chain = EvidenceChain()
        assert chain.confidence == Confidence.TENTATIVE
        assert chain.total_weight == 0.0
        assert chain.confidence_pct == 0

    def test_add_returns_new_chain(self) -> None:
        chain = EvidenceChain()
        new_chain = chain.add("signal", "source", weight=1.0)
        assert len(chain.items) == 0  # original unchanged
        assert len(new_chain.items) == 1

    def test_firm_threshold(self) -> None:
        chain = EvidenceChain()
        chain = chain.add("s1", "src", weight=0.5)
        chain = chain.add("s2", "src", weight=0.5)
        assert chain.confidence == Confidence.FIRM
        assert chain.total_weight == 1.0

    def test_confirmed_threshold(self) -> None:
        chain = EvidenceChain()
        chain = chain.add("s1", "src", weight=1.0)
        chain = chain.add("s2", "src", weight=1.0)
        assert chain.confidence == Confidence.CONFIRMED
        assert chain.total_weight == 2.0

    def test_confidence_pct_confirmed_never_reaches_100(self) -> None:
        # Certainty is never absolute — CONFIRMED caps at 99% (not 100)
        chain = EvidenceChain()
        chain = chain.add("s1", "src", weight=1.5)
        chain = chain.add("s2", "src", weight=1.5)
        pct = chain.confidence_pct
        assert pct >= 85, f"CONFIRMED should be >= 85%, got {pct}%"
        assert pct <= 99, f"CONFIRMED should never reach 100%, got {pct}%"

    def test_add_fp_check_returns_new_chain(self) -> None:
        chain = EvidenceChain()
        new_chain = chain.add_fp_check("checked encoding")
        assert len(chain.false_positive_checks) == 0
        assert len(new_chain.false_positive_checks) == 1
        assert "checked encoding" in new_chain.false_positive_checks

    def test_set_baseline_returns_new_chain(self) -> None:
        chain = EvidenceChain()
        new_chain = chain.set_baseline({"status": 200, "length": 1024})
        assert chain.baseline == {}
        assert new_chain.baseline["status"] == 200

    def test_summary_structure(self) -> None:
        chain = EvidenceChain()
        chain = chain.add("injection found", "sqlmap", weight=1.5)
        chain = chain.add_fp_check("verified not encoded")
        s = chain.summary()
        assert s["confidence"] == "firm"
        assert s["total_weight"] == 1.5
        assert s["signal_count"] == 1
        assert "injection found" in s["signals"]
        assert "verified not encoded" in s["fp_checks_performed"]

    def test_raw_data_truncated_at_2000(self) -> None:
        chain = EvidenceChain()
        chain = chain.add("s", "src", raw_data="x" * 5000)
        assert len(chain.items[0].raw_data) == 2000


class TestEvidenceChainGating:
    """Doctrine §3 — gates that CAP the tier, not just add weight."""

    def test_default_ceiling_is_confirmed_no_cap(self) -> None:
        chain = EvidenceChain().add("s", "src", weight=2.0)
        assert chain.confidence == Confidence.CONFIRMED
        assert not chain.is_capped
        assert chain.ceiling == Confidence.CONFIRMED

    def test_cap_to_firm_overrides_high_weight(self) -> None:
        chain = EvidenceChain().add("s", "src", weight=3.0)
        assert chain.weight_confidence == Confidence.CONFIRMED
        capped = chain.cap(Confidence.FIRM, "WAF present, curl-only")
        assert capped.confidence == Confidence.FIRM
        assert capped.is_capped
        assert "WAF present, curl-only" in capped.gates

    def test_cap_to_tentative_overrides_high_weight(self) -> None:
        chain = EvidenceChain().add("s", "src", weight=2.5).cap(
            Confidence.TENTATIVE, "no OOB hit"
        )
        assert chain.confidence == Confidence.TENTATIVE
        assert chain.is_capped

    def test_cap_is_immutable(self) -> None:
        chain = EvidenceChain().add("s", "src", weight=2.0)
        capped = chain.cap(Confidence.FIRM, "reason")
        assert chain.ceiling == Confidence.CONFIRMED  # original untouched
        assert capped.ceiling == Confidence.FIRM

    def test_ceiling_only_moves_down(self) -> None:
        chain = (
            EvidenceChain()
            .add("s", "src", weight=3.0)
            .cap(Confidence.TENTATIVE, "strict gate")
            .cap(Confidence.FIRM, "weaker gate")  # must not raise the ceiling
        )
        assert chain.ceiling == Confidence.TENTATIVE
        # Both gate reasons are retained for the audit trail.
        assert len(chain.gates) == 2

    def test_cap_does_not_raise_confidence(self) -> None:
        # Capping a low-weight chain to CONFIRMED never invents confidence.
        chain = EvidenceChain().add("s", "src", weight=0.3)
        assert chain.confidence == Confidence.TENTATIVE

    def test_confidence_pct_clamped_to_firm_band(self) -> None:
        chain = EvidenceChain().add("s", "src", weight=3.0)  # would be ~92%
        capped = chain.cap(Confidence.FIRM, "gate")
        assert capped.confidence_pct <= 79

    def test_confidence_pct_clamped_to_tentative_band(self) -> None:
        chain = EvidenceChain().add("s", "src", weight=3.0).cap(
            Confidence.TENTATIVE, "gate"
        )
        assert chain.confidence_pct <= 39

    def test_add_flag(self) -> None:
        chain = EvidenceChain().add_flag("needs-browser-verification")
        assert "needs-browser-verification" in chain.flags

    def test_add_flag_dedups(self) -> None:
        chain = (
            EvidenceChain()
            .add_flag("needs-browser-verification")
            .add_flag("needs-browser-verification")
        )
        assert chain.flags.count("needs-browser-verification") == 1

    def test_summary_includes_gates_and_flags(self) -> None:
        chain = (
            EvidenceChain()
            .add("s", "src", weight=2.5)
            .cap(Confidence.FIRM, "WAF gate")
            .add_flag("needs-browser-verification")
        )
        s = chain.summary()
        assert s["ceiling"] == "firm"
        assert s["is_capped"] is True
        assert "WAF gate" in s["gates"]
        assert "needs-browser-verification" in s["flags"]


class TestToolResult:
    def test_frozen(self) -> None:
        result = ToolResult(
            tool_name="nmap", command="nmap -sV", target="10.0.0.1", phase=Phase.SCANNING
        )
        with pytest.raises(Exception):
            result.tool_name = "changed"  # type: ignore

    def test_default_values(self) -> None:
        result = ToolResult(
            tool_name="test", command="cmd", target="t", phase=Phase.RECON
        )
        assert result.exit_code == 0
        assert result.raw_output == ""
        assert result.error is None
        assert result.duration_seconds == 0.0


class TestEnums:
    def test_phase_values(self) -> None:
        assert Phase.RECON.value == "recon"
        assert Phase.REPORTING.value == "reporting"
        assert len(Phase) == 6

    def test_severity_values(self) -> None:
        assert Severity.CRITICAL.value == "critical"
        assert Severity.INFO.value == "info"
        assert len(Severity) == 5

    def test_confidence_values(self) -> None:
        assert Confidence.CONFIRMED.value == "confirmed"
        assert Confidence.TENTATIVE.value == "tentative"
        assert len(Confidence) == 3

    def test_context_values(self) -> None:
        assert Context.BUG_BOUNTY.value == "bug_bounty"
        assert len(Context) == 3
