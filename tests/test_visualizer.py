"""Tests for the Mermaid.js visualization engine."""

from __future__ import annotations

from kambo.visualizer import (
    attack_surface,
    confidence_tree,
    finding_flow,
    render_html,
    roi_waterfall,
    session_timeline,
    tool_scorecard,
)


class TestAttackSurface:
    def test_basic_target(self) -> None:
        result = attack_surface("example.com")
        assert "mindmap" in result
        assert "example.com" in result

    def test_with_subdomains_and_waf(self) -> None:
        result = attack_surface(
            "example.com",
            subdomains=["api.example.com", "mail.example.com"],
            waf="Cloudflare",
            ports=[{"port": 443, "service": "https"}],
            technologies=["nginx", "PHP"],
        )
        assert "Cloudflare" in result
        assert "Subdomains" in result
        assert "api" in result
        assert "nginx" in result

    def test_caps_subdomains(self) -> None:
        subs = [f"s{i}.example.com" for i in range(20)]
        result = attack_surface("example.com", subdomains=subs)
        assert "+5 more" in result


class TestFindingFlow:
    def test_empty_flow(self) -> None:
        result = finding_flow()
        assert "flowchart LR" in result
        assert "Recon" in result
        assert "Reporting" in result

    def test_with_findings(self) -> None:
        findings = [
            {"title": "SQLi in login", "severity": "critical", "confidence": "confirmed", "phase": "vulnerability_analysis"},
            {"title": "XSS reflected", "severity": "high", "confidence": "firm", "phase": "vulnerability_analysis"},
        ]
        result = finding_flow(findings=findings, current_phase="vulnerability_analysis")
        assert "SQLi in login" in result
        assert "ACTIVE" in result
        assert "classDef critical" in result

    def test_active_phase_highlighted(self) -> None:
        result = finding_flow(current_phase="scanning")
        assert "ACTIVE" in result


class TestConfidenceTree:
    def test_grouped_findings(self) -> None:
        findings = [
            {"title": "SQLi", "severity": "critical", "confidence": "confirmed", "evidence": {"total_weight": 2.5, "signal_count": 3}},
            {"title": "XSS", "severity": "high", "confidence": "firm", "evidence": {"total_weight": 1.2, "signal_count": 2}},
            {"title": "CORS", "severity": "medium", "confidence": "tentative", "evidence": {"total_weight": 0.5, "signal_count": 1}},
        ]
        result = confidence_tree(findings)
        assert "CONFIRMED (1)" in result
        assert "FIRM (1)" in result
        assert "TENTATIVE (1)" in result

    def test_empty_findings(self) -> None:
        result = confidence_tree([])
        assert "flowchart TD" in result


class TestSessionTimeline:
    def test_with_phases(self) -> None:
        phases = {
            "recon": {"total_minutes": 15, "tools_used": ["subfinder", "nmap"]},
            "scanning": {"total_minutes": 30, "tools_used": ["ffuf"]},
        }
        tools = {
            "subfinder": {"total_minutes": 5},
            "nmap": {"total_minutes": 8},
            "ffuf": {"total_minutes": 20},
        }
        result = session_timeline(phases, tools, total_hours=0.75)
        assert "gantt" in result
        assert "recon" in result
        assert "scanning" in result

    def test_no_data(self) -> None:
        result = session_timeline()
        assert "No Data" in result or "No phases" in result


class TestRoiWaterfall:
    def test_with_findings(self) -> None:
        findings = [
            {"title": "SQLi", "expected_value": 15000, "readiness": "ready"},
            {"title": "XSS", "expected_value": 3000, "readiness": "needs_poc"},
        ]
        result = roi_waterfall(findings, total_hours=4.0)
        assert "TOTAL: $18,000" in result
        assert "$/hr" in result

    def test_empty(self) -> None:
        result = roi_waterfall([])
        assert "No findings" in result


class TestToolScorecard:
    def test_with_tools(self) -> None:
        tools = {
            "vuln_sqli": {"runs": 10, "findings": 8, "precision": 0.85},
            "vuln_cors": {"runs": 10, "findings": 3, "precision": 0.30},
        }
        result = tool_scorecard(tools)
        assert "quadrantChart" in result
        assert "sqli" in result
        assert "cors" in result


class TestRenderHtml:
    def test_wraps_in_html(self) -> None:
        mermaid = "flowchart LR\n  A --> B"
        html = render_html(mermaid, title="Test")
        assert "<!DOCTYPE html>" in html
        assert "mermaid" in html
        assert "Test" in html
        assert "A --> B" in html
        assert "cdn.jsdelivr.net" in html
