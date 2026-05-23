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

    def test_confidence_pct_capped_at_100(self) -> None:
        chain = EvidenceChain()
        chain = chain.add("s1", "src", weight=1.5)
        chain = chain.add("s2", "src", weight=1.5)
        assert chain.confidence_pct == 100  # capped

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
