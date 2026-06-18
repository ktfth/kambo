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


class TestVulnPathTraversal:
    @pytest.mark.asyncio
    async def test_passwd_file_found(self) -> None:
        from kambo.tools.vulns import vuln_path_traversal
        output = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
        with patch_runner({"vuln_path_traversal": output, "vuln_path_traversal_baseline": "normal page content"}):
            result = await vuln_path_traversal("http://example.com/view", "file")
        assert result["vulnerable"] is True
        assert result["confidence"] in ("confirmed", "firm")

    @pytest.mark.asyncio
    async def test_no_traversal(self) -> None:
        from kambo.tools.vulns import vuln_path_traversal
        with patch_runner({"vuln_path_traversal": "404 Not Found", "vuln_path_traversal_baseline": "404 Not Found"}):
            result = await vuln_path_traversal("http://example.com/view", "file")
        assert result["vulnerable"] is False


class TestVulnXxe:
    @pytest.mark.asyncio
    async def test_file_content_exfiltrated(self) -> None:
        from kambo.tools.vulns import vuln_xxe
        output = "root:x:0:0:root:/root:/bin/bash\n"
        with patch_runner({"vuln_xxe": output, "vuln_xxe_baseline": "<root>ok</root>"}):
            result = await vuln_xxe("http://example.com/parse")
        assert result["vulnerable"] is True
        assert result["confidence"] in ("confirmed", "firm")

    @pytest.mark.asyncio
    async def test_xxe_blocked(self) -> None:
        from kambo.tools.vulns import vuln_xxe
        output = "External entities are disabled"
        with patch_runner({"vuln_xxe": output, "vuln_xxe_baseline": ""}):
            result = await vuln_xxe("http://example.com/parse")
        assert result["vulnerable"] is False


class TestVulnCsrf:
    @pytest.mark.asyncio
    async def test_no_csrf_token_no_samesite(self) -> None:
        from kambo.tools.vulns import vuln_csrf
        headers = "HTTP/1.1 200 OK\r\nSet-Cookie: session=abc\r\n\r\n"
        body = "<form method='post' action='/transfer'><input name='amount'></form>"
        with patch_runner({"vuln_csrf": headers + body}):
            result = await vuln_csrf("http://example.com", "/transfer")
        assert result["has_csrf_token"] is False
        assert result["samesite_cookie"] == ""
        assert result["evidence"]["signal_count"] >= 1

    @pytest.mark.asyncio
    async def test_csrf_token_present(self) -> None:
        from kambo.tools.vulns import vuln_csrf
        headers = "HTTP/1.1 200 OK\r\nSet-Cookie: session=abc; SameSite=Strict\r\n\r\n"
        body = "<form><input name='csrf_token' value='abc123'></form>"
        with patch_runner({"vuln_csrf": headers + body}):
            result = await vuln_csrf("http://example.com")
        assert result["has_csrf_token"] is True
        assert result["evidence"]["signal_count"] == 0


class TestVulnOpenRedirect:
    @pytest.mark.asyncio
    async def test_redirect_to_evil(self) -> None:
        from kambo.tools.vulns import vuln_open_redirect
        output = "HTTP/1.1 302 Found\r\nLocation: https://evil.com/\r\n\r\n"
        with patch_runner({"vuln_open_redirect": output, "vuln_open_redirect_baseline": "HTTP/1.1 302 Found\r\nLocation: /home\r\n\r\n"}):
            result = await vuln_open_redirect("http://example.com/redirect", "url")
        assert result["vulnerable"] is True
        assert result["confidence"] in ("confirmed", "firm")

    @pytest.mark.asyncio
    async def test_no_redirect(self) -> None:
        from kambo.tools.vulns import vuln_open_redirect
        with patch_runner({"vuln_open_redirect": "HTTP/1.1 200 OK\r\n\r\nOK", "vuln_open_redirect_baseline": ""}):
            result = await vuln_open_redirect("http://example.com/redirect", "next")
        assert result["vulnerable"] is False


class TestVulnPrototypePollution:
    @pytest.mark.asyncio
    async def test_injected_value_reflected(self) -> None:
        from kambo.tools.vulns import vuln_prototype_pollution
        output = '{"id": 1, "polluted": "kambo_pp_canary_31337"}'
        with patch_runner({"vuln_prototype_pollution": output, "vuln_pp_baseline": '{"id": 1}'}):
            result = await vuln_prototype_pollution("http://example.com", "/api/user")
        assert result["evidence"]["signal_count"] >= 1

    @pytest.mark.asyncio
    async def test_no_pollution(self) -> None:
        from kambo.tools.vulns import vuln_prototype_pollution
        with patch_runner({"vuln_prototype_pollution": '{"id": 1, "name": "test"}', "vuln_pp_baseline": '{"id": 1, "name": "test"}'}):
            result = await vuln_prototype_pollution("http://example.com")
        assert result["evidence"]["signal_count"] == 0


class TestVulnGraphql:
    @pytest.mark.asyncio
    async def test_introspection_enabled(self) -> None:
        from kambo.tools.vulns import vuln_graphql
        intro_output = '{"data": {"__schema": {"queryType": {"name": "Query"}, "types": [{"name": "User"}, {"name": "Post"}], "directives": []}}}'
        with patch_runner({
            "vuln_graphql_baseline": '{"data": {"__typename": "Query"}}',
            "vuln_graphql_introspection": intro_output,
            "vuln_graphql_error": '{"errors": [{"message": "Cannot query field nonExistentField123"}]}',
            "vuln_graphql_injection": '{"errors": [{"message": "syntax error"}]}',
        }):
            result = await vuln_graphql("http://example.com", "/graphql")
        assert result["vulnerable"] is True
        assert result["confidence"] in ("confirmed", "firm")

    @pytest.mark.asyncio
    async def test_graphql_not_exposed(self) -> None:
        from kambo.tools.vulns import vuln_graphql
        with patch_runner({
            "vuln_graphql_baseline": "404 Not Found",
            "vuln_graphql_introspection": "404 Not Found",
            "vuln_graphql_error": "404 Not Found",
            "vuln_graphql_injection": "404 Not Found",
        }):
            result = await vuln_graphql("http://example.com", "/graphql")
        assert result["vulnerable"] is False
