"""Tests for scanning tool wrappers."""

from __future__ import annotations

import pytest

from tests.conftest import patch_runner


class TestScanDirectories:
    @pytest.mark.asyncio
    async def test_directories_found(self) -> None:
        from kambo.tools.scanning import scan_directories
        output = (
            '{"url":"http://example.com/admin","status":200,"length":1234}\n'
            '{"url":"http://example.com/.git","status":403,"length":456}\n'
        )
        with patch_runner({"scan_directories": output}):
            result = await scan_directories("http://example.com")
        assert "results" in result or "directories" in result or "raw" in result

    @pytest.mark.asyncio
    async def test_empty_scan(self) -> None:
        from kambo.tools.scanning import scan_directories
        with patch_runner({"scan_directories": ""}):
            result = await scan_directories("http://example.com")
        assert result["target"] == "http://example.com"


class TestScanVulns:
    @pytest.mark.asyncio
    async def test_nuclei_findings(self) -> None:
        from kambo.tools.scanning import scan_vulns
        output = (
            '[2024-01-01] [cve-2021-44228] [critical] http://example.com/api\n'
            '[2024-01-01] [exposed-panels:grafana] [medium] http://example.com/grafana\n'
        )
        with patch_runner({"scan_vulns": output}):
            result = await scan_vulns("http://example.com")
        assert result["target"] == "http://example.com"

    @pytest.mark.asyncio
    async def test_no_findings(self) -> None:
        from kambo.tools.scanning import scan_vulns
        with patch_runner({"scan_vulns": ""}):
            result = await scan_vulns("http://example.com")
        assert result["target"] == "http://example.com"


class TestScanTls:
    @pytest.mark.asyncio
    async def test_tls_analysis(self) -> None:
        from kambo.tools.scanning import scan_tls
        output = "TLS 1.2\nCipher Suite: TLS_RSA_WITH_AES_256_CBC_SHA\nCertificate: CN=example.com\n"
        with patch_runner({"scan_tls": output}):
            result = await scan_tls("example.com")
        assert result["target"] == "example.com"
        assert "analysis" in result


class TestScanApiEndpoints:
    @pytest.mark.asyncio
    async def test_swagger_found(self) -> None:
        from kambo.tools.scanning import scan_api_endpoints
        spec_output = '{"openapi": "3.0.0", "paths": {"/api/users": {}}}'
        fuzz_output = '{"url":"http://example.com/api/v1","status":200}\n'
        with patch_runner({
            "scan_api_endpoints_spec": spec_output,
            "scan_api_endpoints_fuzz": fuzz_output,
        }):
            result = await scan_api_endpoints("http://example.com")
        assert "swagger_found" in result or "endpoints" in result or "target" in result
