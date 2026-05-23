"""Tests for vulnerability analysis tool wrappers."""

from __future__ import annotations

import pytest

from tests.conftest import patch_runner


class TestVulnSqli:
    @pytest.mark.asyncio
    async def test_injectable_target(self) -> None:
        from kambo.tools.vulns import vuln_sqli
        output = (
            "Parameter: id (GET)\n"
            "Type: boolean-based blind\n"
            "Title: AND boolean-based blind\n"
            "back-end DBMS: MySQL\n"
            "available databases [2]:\n"
            "[*] information_schema\n"
            "[*] app_db\n"
        )
        with patch_runner({"vuln_sqli": output}):
            result = await vuln_sqli("http://example.com/page?id=1", "id")
        assert result["vulnerable"] is True
        assert result["confidence"] in ("confirmed", "firm")
        assert result["evidence"]["signal_count"] >= 2

    @pytest.mark.asyncio
    async def test_not_injectable(self) -> None:
        from kambo.tools.vulns import vuln_sqli
        output = "all tested parameters do not appear to be injectable"
        with patch_runner({"vuln_sqli": output}):
            result = await vuln_sqli("http://example.com/page?id=1")
        assert result["vulnerable"] is False
        assert result["confidence"] == "tentative"


class TestVulnXss:
    @pytest.mark.asyncio
    async def test_reflected_in_script(self) -> None:
        from kambo.tools.vulns import vuln_xss
        payload = "<script>alert(1)</script>"
        output = f"<html><body><script>{payload}</script></body></html>"
        with patch_runner({"vuln_xss": output}):
            result = await vuln_xss("http://example.com/search", "q")
        assert result["confidence"] in ("confirmed", "firm")
        assert result["evidence"]["signal_count"] >= 1

    @pytest.mark.asyncio
    async def test_encoded_payload(self) -> None:
        from kambo.tools.vulns import vuln_xss
        output = "<html>&lt;script&gt;alert(1)&lt;/script&gt;</html>"
        with patch_runner({"vuln_xss": output}):
            result = await vuln_xss("http://example.com/search")
        assert result["confidence"] == "tentative"


class TestVulnCors:
    @pytest.mark.asyncio
    async def test_permissive_cors(self) -> None:
        from kambo.tools.vulns import vuln_cors
        output = (
            "access-control-allow-origin: https://evil.com\r\n"
            "access-control-allow-credentials: true\r\n"
        )
        with patch_runner({"vuln_cors": output}):
            result = await vuln_cors("http://example.com/api")
        assert result["evidence"]["signal_count"] >= 1

    @pytest.mark.asyncio
    async def test_wildcard_no_credentials(self) -> None:
        from kambo.tools.vulns import vuln_cors
        output = "access-control-allow-origin: *\r\n"
        with patch_runner({"vuln_cors": output}):
            result = await vuln_cors("http://example.com/api")
        assert result["confidence"] == "tentative"


class TestVulnSsrf:
    @pytest.mark.asyncio
    async def test_internal_content_detected(self) -> None:
        from kambo.tools.vulns import vuln_ssrf
        output = "HTTP/1.1 200 OK\r\n\r\nami-id\ninstance-type\nlocal-ipv4"
        with patch_runner({"vuln_ssrf": output}):
            result = await vuln_ssrf("http://example.com/fetch", "url")
        assert result["evidence"]["signal_count"] >= 1

    @pytest.mark.asyncio
    async def test_empty_response(self) -> None:
        from kambo.tools.vulns import vuln_ssrf
        with patch_runner({"vuln_ssrf": ""}):
            result = await vuln_ssrf("http://example.com/fetch", "url")
        assert result["confidence"] == "tentative"


class TestVulnJwt:
    @pytest.mark.asyncio
    async def test_weak_secret_found(self) -> None:
        from kambo.tools.vulns import vuln_jwt
        analyze_output = "Algorithm: HS256\nPayload: {\"sub\":\"1234\"}"
        crack_output = "[#] FOUND! secret 'secret123'"
        with patch_runner({"vuln_jwt_analyze": analyze_output, "vuln_jwt_crack": crack_output}):
            result = await vuln_jwt("http://example.com", "eyJhbGciOiJIUzI1NiJ9.test.sig")
        assert result["evidence"]["signal_count"] >= 1

    @pytest.mark.asyncio
    async def test_no_weakness_found(self) -> None:
        from kambo.tools.vulns import vuln_jwt
        with patch_runner({"vuln_jwt_analyze": "Algorithm: HS256", "vuln_jwt_crack": "no matches found"}):
            result = await vuln_jwt("http://example.com", "eyJhbGciOiJIUzI1NiJ9.test.sig")
        assert result["confidence"] == "tentative"
