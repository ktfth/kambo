"""Tests for bounty pricing and discovery timer."""

from __future__ import annotations

import pytest

from kambo.bounty_pricing import (
    ProgramPayouts,
    ReportReadiness,
    estimate_finding_value,
    estimate_session_value,
)
from kambo.models import Confidence, Severity


# ---------------------------------------------------------------------------
# Pricing core
# ---------------------------------------------------------------------------

class TestPricingBasics:
    def test_critical_sqli_high_payout(self) -> None:
        payouts = ProgramPayouts(payout_critical=50000)
        est = estimate_finding_value(
            title="SQL Injection in login",
            severity=Severity.CRITICAL,
            confidence=Confidence.CONFIRMED,
            vuln_type="sqli",
            payouts=payouts,
            has_poc=True,
            has_reproduction_steps=True,
        )
        # Expected = 50000 * 0.95 (confidence) * 0.95 (acceptance) * 0.85 (downgrade)
        assert est.expected_value > 30000
        assert est.base_payout == 50000
        assert est.readiness == ReportReadiness.READY

    def test_tentative_xss_discounted(self) -> None:
        payouts = ProgramPayouts(payout_high=5000)
        est = estimate_finding_value(
            title="Reflected XSS",
            severity=Severity.HIGH,
            confidence=Confidence.TENTATIVE,
            vuln_type="xss",
            payouts=payouts,
        )
        # TENTATIVE = 0.30 confidence factor, heavily discounted
        assert est.expected_value < 1500
        assert est.confidence_factor == 0.30
        assert est.readiness == ReportReadiness.NEEDS_VERIFY

    def test_info_severity_zero_value(self) -> None:
        payouts = ProgramPayouts(payout_critical=10000)
        est = estimate_finding_value(
            title="Version Disclosure",
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            vuln_type="version_disclosure",
            payouts=payouts,
            has_poc=True,
            has_reproduction_steps=True,
        )
        assert est.expected_value == 0
        assert est.base_payout == 0

    def test_bonus_multiplier_increases_value(self) -> None:
        base = ProgramPayouts(payout_critical=10000)
        bonus = ProgramPayouts(payout_critical=10000, bonus_active=True, bonus_multiplier=2.0)

        est_base = estimate_finding_value(
            "SQLi", Severity.CRITICAL, Confidence.CONFIRMED, "sqli", base,
        )
        est_bonus = estimate_finding_value(
            "SQLi", Severity.CRITICAL, Confidence.CONFIRMED, "sqli", bonus,
        )
        assert est_bonus.expected_value > est_base.expected_value
        assert est_bonus.bonus_multiplier == 2.0

    def test_managed_program_boost(self) -> None:
        regular = ProgramPayouts(payout_high=5000)
        managed = ProgramPayouts(payout_high=5000, managed=True)

        est_reg = estimate_finding_value(
            "IDOR", Severity.HIGH, Confidence.CONFIRMED, "idor", regular,
        )
        est_managed = estimate_finding_value(
            "IDOR", Severity.HIGH, Confidence.CONFIRMED, "idor", managed,
        )
        assert est_managed.expected_value > est_reg.expected_value

    def test_payout_range_min_less_than_max(self) -> None:
        payouts = ProgramPayouts(payout_critical=20000)
        est = estimate_finding_value(
            "RCE", Severity.CRITICAL, Confidence.FIRM, "rce", payouts,
        )
        assert est.payout_range_min < est.payout_range_max

    def test_unknown_vuln_type_gets_default_acceptance(self) -> None:
        payouts = ProgramPayouts(payout_high=5000)
        est = estimate_finding_value(
            "Weird Bug", Severity.HIGH, Confidence.CONFIRMED, "unknown_type", payouts,
        )
        assert est.acceptance_factor == 0.50  # default


# ---------------------------------------------------------------------------
# Readiness
# ---------------------------------------------------------------------------

class TestReadiness:
    def test_confirmed_with_poc_is_ready(self) -> None:
        payouts = ProgramPayouts(payout_critical=10000)
        est = estimate_finding_value(
            "SQLi", Severity.CRITICAL, Confidence.CONFIRMED, "sqli", payouts,
            has_poc=True, has_reproduction_steps=True,
        )
        assert est.readiness == ReportReadiness.READY
        assert est.readiness_blockers == []

    def test_confirmed_without_poc_needs_poc(self) -> None:
        payouts = ProgramPayouts(payout_high=5000)
        est = estimate_finding_value(
            "SSRF", Severity.HIGH, Confidence.CONFIRMED, "ssrf", payouts,
            has_poc=False, has_reproduction_steps=True,
        )
        assert est.readiness == ReportReadiness.NEEDS_POC
        assert any("proof of concept" in b.lower() for b in est.readiness_blockers)

    def test_tentative_always_needs_verify(self) -> None:
        payouts = ProgramPayouts(payout_medium=1000)
        est = estimate_finding_value(
            "CORS", Severity.MEDIUM, Confidence.TENTATIVE, "cors", payouts,
            has_poc=True, has_reproduction_steps=True,
        )
        assert est.readiness == ReportReadiness.NEEDS_VERIFY

    def test_firm_with_insufficient_evidence(self) -> None:
        payouts = ProgramPayouts(payout_high=5000)
        est = estimate_finding_value(
            "XSS", Severity.HIGH, Confidence.FIRM, "xss", payouts,
            has_poc=True, has_reproduction_steps=True, evidence_signals_count=1,
        )
        assert est.readiness == ReportReadiness.NEEDS_POC
        assert any("evidence" in b.lower() for b in est.readiness_blockers)

    def test_firm_with_full_evidence_is_ready(self) -> None:
        payouts = ProgramPayouts(payout_high=5000)
        est = estimate_finding_value(
            "IDOR", Severity.HIGH, Confidence.FIRM, "idor", payouts,
            has_poc=True, has_reproduction_steps=True, evidence_signals_count=3,
        )
        assert est.readiness == ReportReadiness.READY


# ---------------------------------------------------------------------------
# ROI calculation
# ---------------------------------------------------------------------------

class TestROI:
    def test_dollar_per_hour_calculation(self) -> None:
        payouts = ProgramPayouts(payout_critical=30000)
        est = estimate_finding_value(
            "RCE", Severity.CRITICAL, Confidence.CONFIRMED, "rce", payouts,
            hours_spent=5.0,
        )
        assert est.dollar_per_hour > 0
        assert est.dollar_per_hour == round(est.expected_value / 5.0, 2)

    def test_zero_hours_no_division_error(self) -> None:
        payouts = ProgramPayouts(payout_high=5000)
        est = estimate_finding_value(
            "XSS", Severity.HIGH, Confidence.FIRM, "xss", payouts,
            hours_spent=0,
        )
        assert est.dollar_per_hour == 0


# ---------------------------------------------------------------------------
# Session aggregation
# ---------------------------------------------------------------------------

class TestSessionValue:
    def test_aggregate_multiple_findings(self) -> None:
        payouts = ProgramPayouts(payout_critical=20000, payout_high=5000, payout_medium=1000)

        findings = [
            estimate_finding_value("SQLi", Severity.CRITICAL, Confidence.CONFIRMED, "sqli", payouts, has_poc=True, has_reproduction_steps=True),
            estimate_finding_value("XSS", Severity.HIGH, Confidence.FIRM, "xss", payouts),
            estimate_finding_value("CORS", Severity.MEDIUM, Confidence.TENTATIVE, "cors", payouts),
        ]

        result = estimate_session_value(findings, total_hours=8.0)
        assert result["total_findings"] == 3
        assert result["total_expected_value"] > 0
        assert result["ready_to_report"] >= 1
        assert result["dollar_per_hour"] > 0
        assert "critical" in result["by_severity"]

    def test_empty_session(self) -> None:
        result = estimate_session_value([], total_hours=2.0)
        assert result["total_findings"] == 0
        assert result["total_expected_value"] == 0
        assert "No findings" in result["recommendation"]

    def test_all_ready_recommendation(self) -> None:
        payouts = ProgramPayouts(payout_critical=10000)
        findings = [
            estimate_finding_value("SQLi", Severity.CRITICAL, Confidence.CONFIRMED, "sqli", payouts, has_poc=True, has_reproduction_steps=True),
        ]
        result = estimate_session_value(findings, total_hours=4.0)
        assert "Submit" in result["recommendation"]


# ---------------------------------------------------------------------------
# Discovery Timer
# ---------------------------------------------------------------------------

class TestDiscoveryTimer:
    def test_phase_timing(self) -> None:
        from kambo.discovery_timer import DiscoveryTimer
        timer = DiscoveryTimer()
        timer.start_phase("recon")
        timer.start_tool("subfinder")
        dur = timer.end_tool()
        assert dur >= 0
        timer.end_phase()
        stats = timer.phase_stats()
        assert "recon" in stats

    def test_multiple_tools_in_phase(self) -> None:
        from kambo.discovery_timer import DiscoveryTimer
        timer = DiscoveryTimer()
        timer.start_phase("scanning")
        timer.start_tool("nmap")
        timer.end_tool()
        timer.start_tool("ffuf")
        timer.end_tool()
        timer.end_phase()

        stats = timer.phase_stats()
        assert stats["scanning"].tool_count == 2
        assert "nmap" in stats["scanning"].tools_used
        assert "ffuf" in stats["scanning"].tools_used

    def test_tool_stats_aggregation(self) -> None:
        from kambo.discovery_timer import DiscoveryTimer
        timer = DiscoveryTimer()
        timer.start_phase("recon")
        timer.start_tool("subfinder")
        timer.end_tool()
        timer.start_tool("subfinder")
        timer.end_tool()
        timer.end_phase()

        tools = timer.tool_stats()
        assert tools["subfinder"]["runs"] == 2

    def test_summary_structure(self) -> None:
        from kambo.discovery_timer import DiscoveryTimer
        timer = DiscoveryTimer()
        timer.start_phase("recon")
        timer.start_tool("amass")
        timer.end_tool()
        timer.end_phase()

        summary = timer.summary()
        assert "session_start" in summary
        assert "wall_clock_hours" in summary
        assert "active_hours" in summary
        assert "phases" in summary
        assert "tools" in summary

    def test_auto_end_previous_phase(self) -> None:
        from kambo.discovery_timer import DiscoveryTimer
        timer = DiscoveryTimer()
        timer.start_phase("recon")
        timer.start_tool("subfinder")
        timer.end_tool()
        # Starting new phase auto-ends previous
        timer.start_phase("scanning")
        timer.end_phase()

        stats = timer.phase_stats()
        assert "recon" in stats
        assert "scanning" in stats

    def test_db_serialization(self) -> None:
        from kambo.discovery_timer import DiscoveryTimer
        timer = DiscoveryTimer()
        timer.start_phase("recon")
        timer.start_tool("nmap")
        timer.end_tool()
        timer.end_phase()

        rows = timer.to_db_rows()
        assert len(rows) >= 1
        assert all("phase" in r for r in rows)
        assert all("duration_seconds" in r for r in rows)


# ---------------------------------------------------------------------------
# MCP tool wrappers
# ---------------------------------------------------------------------------

class TestBountyPricingTools:
    @pytest.mark.asyncio
    async def test_estimate_value_tool(self) -> None:
        from kambo.tools.bounty import bounty_estimate_value
        result = await bounty_estimate_value(
            title="SQL Injection in /api/users",
            severity="critical",
            confidence="confirmed",
            vuln_type="sqli",
            payout_critical=25000,
            payout_high=10000,
            has_poc=True,
            has_reproduction_steps=True,
            hours_spent=3.0,
        )
        assert result["finding"] == "SQL Injection in /api/users"
        assert result["pricing"]["expected_value"] > 0
        assert result["pricing"]["base_payout"] == 25000
        assert result["readiness"]["status"] == "ready"
        assert result["roi"]["dollar_per_hour"] > 0

    @pytest.mark.asyncio
    async def test_session_value_tool(self) -> None:
        from kambo.tools.bounty import bounty_session_value
        result = await bounty_session_value(
            findings=[
                {"title": "SQLi", "severity": "critical", "confidence": "confirmed", "vuln_type": "sqli", "has_poc": True, "has_reproduction_steps": True},
                {"title": "XSS", "severity": "high", "confidence": "firm", "vuln_type": "xss"},
            ],
            payout_critical=20000,
            payout_high=5000,
        )
        assert result["total_findings"] == 2
        assert result["total_expected_value"] > 0
        assert "findings" in result
        assert "timer" in result

    @pytest.mark.asyncio
    async def test_timer_start_stop(self) -> None:
        from kambo.tools.bounty import bounty_timer_start, bounty_timer_stop, bounty_timer_reset
        await bounty_timer_reset()
        start_result = await bounty_timer_start(phase="recon")
        assert start_result["status"] == "started"
        assert start_result["phase"] == "recon"

        stop_result = await bounty_timer_stop()
        assert "session_start" in stop_result
        assert "phases" in stop_result

    @pytest.mark.asyncio
    async def test_timer_reset(self) -> None:
        from kambo.tools.bounty import bounty_timer_reset
        result = await bounty_timer_reset()
        assert result["status"] == "reset"
