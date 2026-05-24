"""Tests for new pipeline parsers — recon_waf, recon_certs, recon_asn, scan_tls,
scan_services, vuln_subdomain_takeover, vuln_ssti, scan_vulns."""

from __future__ import annotations

import pytest

from kambo.pipeline import AssetType, SessionPipeline


def fresh_pipeline() -> SessionPipeline:
    return SessionPipeline()


class TestReconWafParser:
    def test_waf_detected_creates_technology_asset(self) -> None:
        p = fresh_pipeline()
        assets = p.ingest("recon_waf", {"target": "example.com", "waf": "Cloudflare", "waf_name": "Cloudflare"})
        assert any(a.asset_type == AssetType.TECHNOLOGY for a in assets)
        tech_asset = next(a for a in assets if a.asset_type == AssetType.TECHNOLOGY)
        assert "cloudflare" in tech_asset.value.lower()

    def test_no_waf_produces_no_assets(self) -> None:
        p = fresh_pipeline()
        assets = p.ingest("recon_waf", {"target": "example.com", "waf": "none"})
        assert assets == []

    def test_empty_waf_produces_no_assets(self) -> None:
        p = fresh_pipeline()
        assets = p.ingest("recon_waf", {"target": "example.com"})
        assert assets == []


class TestReconCertsParser:
    def test_domains_from_cert_transparency(self) -> None:
        p = fresh_pipeline()
        assets = p.ingest("recon_certs", {
            "target": "example.com",
            "domains": ["sub1.example.com", "sub2.example.com", "*.example.com"],
        })
        # Wildcards excluded
        non_wildcard = [a for a in assets if "*" not in a.value]
        assert len(non_wildcard) == 2
        assert all(a.asset_type == AssetType.SUBDOMAIN for a in non_wildcard)

    def test_sans_field_also_parsed(self) -> None:
        p = fresh_pipeline()
        assets = p.ingest("recon_certs", {"sans": ["api.example.com"]})
        assert any(a.value == "api.example.com" for a in assets)

    def test_wildcards_excluded(self) -> None:
        p = fresh_pipeline()
        assets = p.ingest("recon_certs", {"domains": ["*.example.com", "exact.example.com"]})
        assert all("*" not in a.value for a in assets)


class TestReconAsnParser:
    def test_cidr_ranges_become_ip_assets(self) -> None:
        p = fresh_pipeline()
        assets = p.ingest("recon_asn", {
            "asn": "AS12345",
            "org": "Example Corp",
            "cidrs": ["1.2.3.0/24", "10.0.0.0/8"],
        })
        assert len(assets) == 2
        assert all(a.asset_type == AssetType.IP for a in assets)

    def test_ip_ranges_field(self) -> None:
        p = fresh_pipeline()
        assets = p.ingest("recon_asn", {"ip_ranges": ["192.168.1.0/24"]})
        assert len(assets) == 1

    def test_empty_cidrs(self) -> None:
        p = fresh_pipeline()
        assets = p.ingest("recon_asn", {"asn": "AS999"})
        assert assets == []


class TestScanTlsParser:
    def test_weak_protocols_become_technology_assets(self) -> None:
        p = fresh_pipeline()
        assets = p.ingest("scan_tls", {
            "target": "example.com",
            "weak_protocols": ["TLSv1.0", "SSLv3"],
        })
        tech_assets = [a for a in assets if a.asset_type == AssetType.TECHNOLOGY]
        assert len(tech_assets) == 2
        assert any("TLSv1.0" in a.value for a in tech_assets)

    def test_sans_from_cert_become_subdomains(self) -> None:
        p = fresh_pipeline()
        assets = p.ingest("scan_tls", {
            "target": "example.com",
            "sans": ["api.example.com", "*.example.com"],
        })
        sub_assets = [a for a in assets if a.asset_type == AssetType.SUBDOMAIN]
        assert len(sub_assets) == 1  # wildcard excluded
        assert sub_assets[0].value == "api.example.com"

    def test_no_weak_protocols(self) -> None:
        p = fresh_pipeline()
        assets = p.ingest("scan_tls", {"target": "example.com", "weak_protocols": []})
        assert assets == []


class TestScanServicesParser:
    def test_services_become_port_and_tech_assets(self) -> None:
        p = fresh_pipeline()
        assets = p.ingest("scan_services", {
            "target": "example.com",
            "services": [
                {"port": 80, "service": "http", "version": "Apache/2.4"},
                {"port": 443, "service": "https", "version": "nginx/1.18"},
            ],
        })
        port_assets = [a for a in assets if a.asset_type == AssetType.PORT]
        tech_assets = [a for a in assets if a.asset_type == AssetType.TECHNOLOGY]
        assert len(port_assets) == 2
        assert len(tech_assets) == 2

    def test_service_without_version(self) -> None:
        p = fresh_pipeline()
        assets = p.ingest("scan_services", {
            "services": [{"port": 22, "service": "ssh"}],
        })
        assert any(a.asset_type == AssetType.PORT for a in assets)


class TestVulnSubdomainTakeoverParser:
    """The generic finding tracker handles vuln_subdomain_takeover results.

    Any result with `confidence` field is tracked as a FINDING regardless of
    confidence level — filtering happens at the reporting stage.
    """

    def test_confirmed_takeover_tracked_as_finding(self) -> None:
        p = fresh_pipeline()
        assets = p.ingest("vuln_subdomain_takeover", {
            "target": "dead.example.com",
            "vulnerable": True,
            "confidence": "confirmed",
            "cname": "example.azurewebsites.net",
        })
        finding_assets = [a for a in assets if a.asset_type == AssetType.FINDING]
        assert len(finding_assets) >= 1
        assert any("vuln_subdomain_takeover" in a.value for a in finding_assets)

    def test_all_confidence_levels_tracked(self) -> None:
        """Pipeline tracks all confidence levels — caller filters at reporting time."""
        p = fresh_pipeline()
        assets = p.ingest("vuln_subdomain_takeover", {
            "target": "maybe.example.com",
            "vulnerable": True,
            "confidence": "tentative",
        })
        # Generic tracker fires because result has 'confidence' field
        finding_assets = [a for a in assets if a.asset_type == AssetType.FINDING]
        assert len(finding_assets) >= 1

    def test_finding_metadata_has_confidence(self) -> None:
        p = fresh_pipeline()
        assets = p.ingest("vuln_subdomain_takeover", {
            "target": "dead.example.com",
            "vulnerable": True,
            "confidence": "confirmed",
        })
        finding = next(a for a in assets if a.asset_type == AssetType.FINDING)
        assert finding.metadata.get("confidence") == "confirmed"


class TestVulnSstiParser:
    """Generic finding tracker handles vuln_ssti. No specific parser needed."""

    def test_ssti_result_tracked_as_finding(self) -> None:
        p = fresh_pipeline()
        assets = p.ingest("vuln_ssti", {
            "target": "https://example.com/search",
            "vulnerable": True,
            "confidence": "confirmed",
            "parameter": "q",
        })
        finding_assets = [a for a in assets if a.asset_type == AssetType.FINDING]
        assert len(finding_assets) >= 1
        assert any("vuln_ssti" in a.value for a in finding_assets)

    def test_finding_metadata_has_vuln_type(self) -> None:
        p = fresh_pipeline()
        assets = p.ingest("vuln_ssti", {
            "target": "https://example.com/search",
            "vulnerable": True,
            "confidence": "confirmed",
        })
        finding = next(a for a in assets if a.asset_type == AssetType.FINDING)
        assert finding.metadata.get("vuln_type") == "ssti"


class TestScanVulnsParser:
    def test_critical_nuclei_finding_ingested(self) -> None:
        p = fresh_pipeline()
        assets = p.ingest("scan_vulns", {
            "target": "example.com",
            "findings": [
                {"template_id": "CVE-2021-44228", "severity": "critical", "matched_at": "https://example.com/"},
                {"template_id": "CVE-2023-1234", "severity": "high", "matched_at": "https://example.com/api"},
            ],
        })
        assert len(assets) == 2
        assert all(a.asset_type == AssetType.FINDING for a in assets)

    def test_info_severity_not_ingested(self) -> None:
        p = fresh_pipeline()
        assets = p.ingest("scan_vulns", {
            "target": "example.com",
            "findings": [
                {"template_id": "info-disclosure", "severity": "info"},
                {"template_id": "low-finding", "severity": "low"},
            ],
        })
        assert assets == []

    def test_no_findings(self) -> None:
        p = fresh_pipeline()
        assets = p.ingest("scan_vulns", {"target": "example.com", "findings": []})
        assert assets == []
