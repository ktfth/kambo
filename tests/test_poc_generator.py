"""Tests for automatic PoC generation."""

from __future__ import annotations

from kambo.poc_generator import generate_poc


class TestPythonPoc:
    def test_sqli_get(self) -> None:
        result = generate_poc(
            vuln_type="sqli",
            target="http://example.com/search",
            parameter="q",
            payload="' OR 1=1--",
            language="python",
        )
        assert result["language"] == "python"
        assert "requests" in result["poc_script"]
        assert "SQL syntax" in result["poc_script"]
        assert "PAYLOAD" in result["poc_script"]

    def test_sqli_post(self) -> None:
        result = generate_poc(
            vuln_type="sqli",
            target="http://example.com/login",
            method="POST",
            parameter="username",
            payload="admin'--",
            language="python",
        )
        assert "requests.post" in result["poc_script"]

    def test_xss(self) -> None:
        result = generate_poc(
            vuln_type="xss",
            target="http://example.com/search",
            parameter="q",
            payload="<script>alert(1)</script>",
            language="python",
        )
        assert "reflected" in result["poc_script"].lower()
        assert "PAYLOAD" in result["poc_script"]

    def test_ssrf(self) -> None:
        result = generate_poc(
            vuln_type="ssrf",
            target="http://example.com/proxy",
            parameter="url",
            language="python",
        )
        assert "169.254.169.254" in result["poc_script"]

    def test_cors(self) -> None:
        result = generate_poc(
            vuln_type="cors",
            target="http://example.com/api/data",
            language="python",
        )
        assert "Origin" in result["poc_script"]
        assert "evil.com" in result["poc_script"]

    def test_idor(self) -> None:
        result = generate_poc(
            vuln_type="idor",
            target="http://example.com/api/users",
            token="test-token",
            language="python",
        )
        assert "Authorization" in result["poc_script"]
        assert "range" in result["poc_script"]

    def test_csrf(self) -> None:
        result = generate_poc(
            vuln_type="csrf",
            target="http://example.com/change-email",
            method="POST",
            body="email=attacker@evil.com",
            language="python",
        )
        assert "csrf_poc.html" in result["poc_script"]
        assert "<form" in result["poc_script"]

    def test_open_redirect(self) -> None:
        result = generate_poc(
            vuln_type="open_redirect",
            target="http://example.com/redirect",
            parameter="url",
            payload="https://evil.com",
            language="python",
        )
        assert "Location" in result["poc_script"]
        assert "allow_redirects=False" in result["poc_script"]

    def test_xxe(self) -> None:
        result = generate_poc(
            vuln_type="xxe",
            target="http://example.com/api/xml",
            language="python",
        )
        assert "DOCTYPE" in result["poc_script"]
        assert "ENTITY" in result["poc_script"]

    def test_rce(self) -> None:
        result = generate_poc(
            vuln_type="rce",
            target="http://example.com/exec",
            parameter="cmd",
            payload="; id",
            language="python",
        )
        assert "uid=" in result["poc_script"]

    def test_generic_fallback(self) -> None:
        result = generate_poc(
            vuln_type="unknown_vuln",
            target="http://example.com/test",
            parameter="p",
            payload="test",
            language="python",
        )
        assert "requests" in result["poc_script"]


class TestCurlPoc:
    def test_curl_get(self) -> None:
        result = generate_poc(
            vuln_type="sqli",
            target="http://example.com/search",
            parameter="q",
            payload="' OR 1=1--",
            language="curl",
        )
        assert result["language"] == "curl"
        assert "curl" in result["poc_script"]
        assert "q=" in result["poc_script"]

    def test_curl_post(self) -> None:
        result = generate_poc(
            vuln_type="sqli",
            target="http://example.com/login",
            method="POST",
            parameter="username",
            payload="admin'--",
            language="curl",
        )
        assert "-X POST" in result["poc_script"]
        assert "-d" in result["poc_script"]

    def test_curl_with_token(self) -> None:
        result = generate_poc(
            vuln_type="idor",
            target="http://example.com/api/users/1",
            token="abc123",
            language="curl",
        )
        assert "Authorization" in result["poc_script"]

    def test_curl_with_headers(self) -> None:
        result = generate_poc(
            vuln_type="xss",
            target="http://example.com",
            headers={"X-Custom": "test"},
            language="curl",
        )
        assert "X-Custom" in result["poc_script"]


class TestJsPoc:
    def test_js_fetch(self) -> None:
        result = generate_poc(
            vuln_type="sqli",
            target="http://example.com/search",
            parameter="q",
            payload="' OR 1=1--",
            language="javascript",
        )
        assert result["language"] == "javascript"
        assert "fetch" in result["poc_script"]

    def test_js_post(self) -> None:
        result = generate_poc(
            vuln_type="sqli",
            target="http://example.com/login",
            method="POST",
            parameter="username",
            payload="admin'--",
            language="javascript",
        )
        assert "method: 'POST'" in result["poc_script"]
        assert "body:" in result["poc_script"]


class TestMetadata:
    def test_usage_instructions(self) -> None:
        for lang in ["python", "curl", "javascript"]:
            result = generate_poc(
                vuln_type="sqli",
                target="http://example.com",
                language=lang,
            )
            assert result["usage"]
            assert result["vuln_type"] == "sqli"

    def test_description_in_poc(self) -> None:
        result = generate_poc(
            vuln_type="sqli",
            target="http://example.com",
            description="SQL injection in login form",
            language="python",
        )
        assert "SQL injection in login form" in result["poc_script"]
