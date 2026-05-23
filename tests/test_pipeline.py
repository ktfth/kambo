"""Tests for session pipeline — context accumulation and tool chaining."""

from __future__ import annotations

from kambo.models import Phase
from kambo.pipeline import (
    AssetType,
    DiscoveredAsset,
    SessionPipeline,
    get_pipeline,
    reset_pipeline,
)


class TestIngestion:
    def test_ingest_subdomains(self) -> None:
        pipeline = SessionPipeline()
        result = {
            "subdomains": ["sub1.example.com", "sub2.example.com", "api.example.com"],
        }
        new = pipeline.ingest("recon_subdomains", result)
        assert len(new) == 3
        assert all(a.asset_type == AssetType.SUBDOMAIN for a in new)
        assert pipeline.get_values(AssetType.SUBDOMAIN) == [
            "sub1.example.com", "sub2.example.com", "api.example.com"
        ]

    def test_ingest_deduplicates(self) -> None:
        pipeline = SessionPipeline()
        result = {"subdomains": ["sub1.example.com", "sub2.example.com"]}
        pipeline.ingest("recon_subdomains", result)
        new = pipeline.ingest("recon_subdomains", result)
        assert len(new) == 0
        assert len(pipeline.get_values(AssetType.SUBDOMAIN)) == 2

    def test_ingest_ports(self) -> None:
        pipeline = SessionPipeline()
        result = {
            "target": "example.com",
            "ports": [
                {"port": 80, "service": "http", "state": "open"},
                {"port": 443, "service": "https", "state": "open"},
            ],
        }
        new = pipeline.ingest("recon_ports_fast", result)
        assert len(new) == 2
        assert all(a.asset_type == AssetType.PORT for a in new)
        assert "example.com:80" in pipeline.get_values(AssetType.PORT)

    def test_ingest_directories(self) -> None:
        pipeline = SessionPipeline()
        result = {
            "target": "http://example.com",
            "results": [
                {"url": "http://example.com/admin", "status": 200, "length": 1234},
                {"url": "http://example.com/api", "status": 301, "length": 0},
                {"url": "http://example.com/secret", "status": 403, "length": 0},
            ],
        }
        new = pipeline.ingest("scan_directories", result)
        # Only 200 and 301 should be captured (< 400)
        assert len(new) == 2
        urls = pipeline.get_values(AssetType.URL)
        assert "http://example.com/admin" in urls

    def test_ingest_api_endpoints(self) -> None:
        pipeline = SessionPipeline()
        result = {
            "endpoints": [
                {"path": "/api/users", "method": "GET"},
                {"path": "/api/admin", "method": "POST"},
            ],
        }
        new = pipeline.ingest("scan_api_endpoints", result)
        assert len(new) == 2
        assert all(a.asset_type == AssetType.ENDPOINT for a in new)

    def test_ingest_parameters(self) -> None:
        pipeline = SessionPipeline()
        result = {
            "parameters": [
                {"name": "id", "url": "http://example.com/user", "type": "query"},
                {"name": "token", "url": "http://example.com/auth"},
            ],
        }
        new = pipeline.ingest("scan_parameters", result)
        assert len(new) == 2
        assert "id" in pipeline.get_values(AssetType.PARAMETER)

    def test_ingest_tech_stack(self) -> None:
        pipeline = SessionPipeline()
        result = {
            "technologies": [
                {"name": "nginx", "version": "1.18", "category": "web-server"},
                {"name": "PHP", "version": "7.4"},
            ],
        }
        new = pipeline.ingest("recon_tech_stack", result)
        assert len(new) == 2
        techs = pipeline.get_values(AssetType.TECHNOLOGY)
        assert "nginx" in techs

    def test_ingest_vhosts(self) -> None:
        pipeline = SessionPipeline()
        result = {"vhosts": [{"host": "secret.example.com"}, {"host": "dev.example.com"}]}
        new = pipeline.ingest("scan_vhosts", result)
        assert len(new) == 2
        assert all(a.asset_type == AssetType.VHOST for a in new)

    def test_ingest_finding(self) -> None:
        pipeline = SessionPipeline()
        result = {
            "vulnerable": True,
            "confidence": "confirmed",
            "target": "http://example.com/user?id=1",
        }
        new = pipeline.ingest("vuln_sqli", result)
        findings = pipeline.get_assets(asset_type=AssetType.FINDING)
        assert len(findings) == 1
        assert findings[0].metadata["vuln_type"] == "sqli"

    def test_ingest_dns_records(self) -> None:
        pipeline = SessionPipeline()
        result = {
            "records": [
                {"type": "A", "value": "10.0.0.1"},
                {"type": "CNAME", "value": "cdn.example.com"},
            ],
        }
        new = pipeline.ingest("recon_dns", result)
        assert len(new) == 2
        ips = pipeline.get_values(AssetType.IP)
        assert "10.0.0.1" in ips

    def test_ingest_string_lists(self) -> None:
        """Tools may return simple string lists instead of dicts."""
        pipeline = SessionPipeline()
        result = {"subdomains": ["a.example.com", "b.example.com"]}
        new = pipeline.ingest("recon_subdomains", result)
        assert len(new) == 2

    def test_ingest_ports_as_integers(self) -> None:
        pipeline = SessionPipeline()
        result = {"target": "10.0.0.1", "ports": [80, 443, 8080]}
        new = pipeline.ingest("scan_ports_full", result)
        assert len(new) == 3

    def test_ingest_unknown_tool(self) -> None:
        """Unknown tools should not crash, just skip parsing."""
        pipeline = SessionPipeline()
        result = {"something": "data"}
        new = pipeline.ingest("unknown_tool", result)
        assert len(new) == 0

    def test_tracks_tools_run(self) -> None:
        pipeline = SessionPipeline()
        pipeline.ingest("recon_subdomains", {"subdomains": ["a.example.com"]})
        pipeline.ingest("recon_dns", {"records": []})
        assert pipeline.tools_run == ["recon_subdomains", "recon_dns"]


class TestTargetsForPhase:
    def test_scanning_targets(self) -> None:
        pipeline = SessionPipeline()
        pipeline.ingest("recon_subdomains", {"subdomains": ["a.example.com", "b.example.com"]})
        pipeline.ingest("recon_dns", {"records": [{"type": "A", "value": "10.0.0.1"}]})
        targets = pipeline.targets_for_phase(Phase.SCANNING)
        assert "a.example.com" in targets
        assert "10.0.0.1" in targets

    def test_vuln_analysis_targets(self) -> None:
        pipeline = SessionPipeline()
        pipeline.ingest("scan_directories", {
            "results": [{"url": "http://example.com/admin", "status": 200}]
        })
        pipeline.ingest("scan_api_endpoints", {
            "endpoints": [{"path": "/api/users", "method": "GET"}]
        })
        targets = pipeline.targets_for_phase(Phase.VULN_ANALYSIS)
        assert "http://example.com/admin" in targets
        assert "/api/users" in targets

    def test_exploitation_targets_only_confirmed(self) -> None:
        pipeline = SessionPipeline()
        pipeline.ingest("vuln_sqli", {
            "vulnerable": True, "confidence": "confirmed", "target": "http://example.com/vuln"
        })
        pipeline.ingest("vuln_xss", {
            "vulnerable": True, "confidence": "tentative", "target": "http://example.com/xss"
        })
        targets = pipeline.targets_for_phase(Phase.EXPLOITATION)
        assert "http://example.com/vuln" in targets
        assert "http://example.com/xss" not in targets

    def test_empty_pipeline_returns_empty(self) -> None:
        pipeline = SessionPipeline()
        assert pipeline.targets_for_phase(Phase.SCANNING) == []


class TestNextSteps:
    def test_initial_suggestions(self) -> None:
        pipeline = SessionPipeline()
        steps = pipeline.suggest_next_steps(Phase.RECON)
        # Should suggest initial recon tools (no needs)
        tool_names = [s.tool for s in steps]
        assert "recon_subdomains" in tool_names
        assert "recon_dns" in tool_names

    def test_suggestions_after_recon(self) -> None:
        pipeline = SessionPipeline()
        pipeline.ingest("recon_subdomains", {"subdomains": ["a.example.com"]})
        steps = pipeline.suggest_next_steps(Phase.RECON)
        # Should suggest tools that need subdomains
        tool_names = [s.tool for s in steps]
        assert "recon_subdomains" not in tool_names  # already run
        assert "recon_tech_stack" in tool_names  # needs subdomains

    def test_suggestions_include_next_phase(self) -> None:
        pipeline = SessionPipeline()
        pipeline.ingest("recon_subdomains", {"subdomains": ["a.example.com"]})
        steps = pipeline.suggest_next_steps(Phase.RECON)
        phases = {s.phase for s in steps}
        # Should include scanning suggestions since we have subdomains
        assert Phase.SCANNING in phases

    def test_exploit_suggestions_need_findings(self) -> None:
        pipeline = SessionPipeline()
        pipeline.ingest("recon_subdomains", {"subdomains": ["a.example.com"]})
        steps = pipeline.suggest_next_steps(Phase.VULN_ANALYSIS)
        tool_names = [s.tool for s in steps]
        assert "exploit_sqli" not in tool_names  # no SQLi finding yet

    def test_exploit_suggested_after_finding(self) -> None:
        pipeline = SessionPipeline()
        pipeline.ingest("vuln_sqli", {
            "vulnerable": True, "confidence": "confirmed", "target": "http://example.com"
        })
        steps = pipeline.suggest_next_steps(Phase.VULN_ANALYSIS)
        tool_names = [s.tool for s in steps]
        assert "exploit_sqli" in tool_names

    def test_suggestions_have_targets(self) -> None:
        pipeline = SessionPipeline()
        pipeline.ingest("recon_subdomains", {"subdomains": ["a.example.com"]})
        steps = pipeline.suggest_next_steps(Phase.RECON)
        tech_step = next((s for s in steps if s.tool == "recon_tech_stack"), None)
        assert tech_step is not None
        assert "a.example.com" in tech_step.targets

    def test_max_steps_limit(self) -> None:
        pipeline = SessionPipeline()
        steps = pipeline.suggest_next_steps(Phase.RECON, max_steps=2)
        assert len(steps) <= 2


class TestSummary:
    def test_summary_structure(self) -> None:
        pipeline = SessionPipeline()
        pipeline.ingest("recon_subdomains", {"subdomains": ["a.example.com"]})
        pipeline.ingest("recon_ports_fast", {"target": "a.example.com", "ports": [80]})
        summary = pipeline.summary()
        assert summary["total_assets"] == 2
        assert "subdomain" in summary["asset_counts"]
        assert "port" in summary["asset_counts"]
        assert summary["tools_run_count"] == 2
        assert "a.example.com" in summary["subdomains"]


class TestReset:
    def test_reset_clears_state(self) -> None:
        pipeline = SessionPipeline()
        pipeline.ingest("recon_subdomains", {"subdomains": ["a.example.com"]})
        assert len(pipeline.assets) > 0
        pipeline.reset()
        assert len(pipeline.assets) == 0
        assert len(pipeline.tools_run) == 0


class TestSingleton:
    def test_get_pipeline_returns_same(self) -> None:
        p1 = get_pipeline()
        p2 = get_pipeline()
        assert p1 is p2

    def test_reset_creates_new(self) -> None:
        p1 = get_pipeline()
        p2 = reset_pipeline()
        assert p1 is not p2
