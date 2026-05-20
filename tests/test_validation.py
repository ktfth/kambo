"""Tests for the evidence-based validation engine."""

from kambo.models import Confidence, EvidenceChain
from kambo.validation import (
    HttpResponse,
    validate_bfla,
    validate_cors,
    validate_idor,
    validate_jwt,
    validate_sqli,
    validate_ssrf,
    validate_subdomain_takeover,
    validate_xss,
)


# ---------------------------------------------------------------------------
# EvidenceChain model tests
# ---------------------------------------------------------------------------

class TestEvidenceChain:
    def test_empty_chain_is_tentative(self) -> None:
        chain = EvidenceChain()
        assert chain.confidence == Confidence.TENTATIVE
        assert chain.total_weight == 0.0

    def test_add_produces_new_chain(self) -> None:
        chain = EvidenceChain()
        new_chain = chain.add("sig", "src", weight=1.0)
        assert len(chain.items) == 0  # original unchanged
        assert len(new_chain.items) == 1

    def test_confidence_firm(self) -> None:
        chain = EvidenceChain().add("sig1", "src", weight=0.5).add("sig2", "src", weight=0.6)
        assert chain.confidence == Confidence.FIRM

    def test_confidence_confirmed(self) -> None:
        chain = EvidenceChain().add("sig1", "src", weight=1.0).add("sig2", "src", weight=1.5)
        assert chain.confidence == Confidence.CONFIRMED

    def test_fp_checks_recorded(self) -> None:
        chain = EvidenceChain().add_fp_check("check1").add_fp_check("check2")
        assert len(chain.false_positive_checks) == 2

    def test_summary_structure(self) -> None:
        chain = EvidenceChain().add("sig", "src", weight=0.5)
        s = chain.summary()
        assert "confidence" in s
        assert "signal_count" in s
        assert s["signal_count"] == 1


# ---------------------------------------------------------------------------
# SQLi validation
# ---------------------------------------------------------------------------

class TestSqliValidation:
    def test_not_injectable(self) -> None:
        output = "all tested parameters do not appear to be injectable"
        chain = validate_sqli(output)
        assert chain.total_weight == 0.0
        assert len(chain.false_positive_checks) > 0

    def test_confirmed_injectable(self) -> None:
        output = """
        sqlmap identified the following injection point(s):
        Parameter: id (GET)
            Type: boolean-based blind
        back-end DBMS: MySQL
        available databases [3]:
        [*] information_schema
        [*] mydb
        [*] test
        """
        chain = validate_sqli(output)
        assert chain.confidence == Confidence.CONFIRMED
        assert chain.total_weight >= 2.0

    def test_partial_detection(self) -> None:
        output = "back-end DBMS: PostgreSQL"
        chain = validate_sqli(output)
        assert chain.total_weight > 0
        assert chain.confidence == Confidence.TENTATIVE

    def test_timeout_is_fp(self) -> None:
        output = "connection timed out to the target URL"
        chain = validate_sqli(output)
        assert chain.total_weight == 0.0


# ---------------------------------------------------------------------------
# XSS validation
# ---------------------------------------------------------------------------

class TestXssValidation:
    def test_no_reflection(self) -> None:
        chain = validate_xss("no payload here", "<script>alert(1)</script>", "q")
        assert chain.total_weight == 0.0
        assert len(chain.false_positive_checks) > 0

    def test_encoded_only_is_fp(self) -> None:
        payload = "<script>alert(1)</script>"
        response = "the value is &lt;script&gt;alert(1)&lt;/script&gt;"
        chain = validate_xss(response, payload, "q")
        # Payload not reflected raw — should be FP
        assert chain.total_weight == 0.0
        assert len(chain.false_positive_checks) > 0

    def test_both_encoded_and_raw_is_vuln(self) -> None:
        payload = "<script>alert(1)</script>"
        response = f"encoded: &lt;script&gt; but also raw: {payload}"
        chain = validate_xss(response, payload, "q")
        # Raw payload IS present — this is a real reflection
        assert chain.total_weight > 0

    def test_unencoded_reflection_in_body(self) -> None:
        payload = "<script>alert(1)</script>"
        response = f"<html><body>Hello {payload}</body></html>"
        chain = validate_xss(response, payload, "q")
        assert chain.total_weight > 0

    def test_reflection_in_script_context(self) -> None:
        payload = "'-alert(1)-'"
        response = f"<html><script>var x = '{payload}';</script></html>"
        chain = validate_xss(response, payload, "q")
        assert chain.total_weight >= 1.0


# ---------------------------------------------------------------------------
# CORS validation
# ---------------------------------------------------------------------------

class TestCorsValidation:
    def test_no_acao_header(self) -> None:
        chain = validate_cors("https://evil.com", "HTTP/1.1 200 OK\r\nContent-Type: text/html", "example.com")
        assert chain.total_weight == 0.0

    def test_wildcard_no_creds(self) -> None:
        headers = "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *"
        chain = validate_cors("https://evil.com", headers, "example.com")
        assert chain.total_weight <= 0.2  # low impact

    def test_wildcard_with_creds_is_fp(self) -> None:
        headers = "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Credentials: true"
        chain = validate_cors("https://evil.com", headers, "example.com")
        # Browsers block this — should be flagged as FP
        assert len(chain.false_positive_checks) > 0
        assert chain.total_weight == 0.0

    def test_reflected_origin_with_creds(self) -> None:
        headers = "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: https://evil.com\r\nAccess-Control-Allow-Credentials: true"
        chain = validate_cors("https://evil.com", headers, "example.com")
        assert chain.confidence in (Confidence.FIRM, Confidence.CONFIRMED)
        assert chain.total_weight >= 1.0

    def test_reflected_origin_without_creds(self) -> None:
        headers = "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: https://evil.com"
        chain = validate_cors("https://evil.com", headers, "example.com")
        assert chain.total_weight > 0
        assert chain.total_weight < 1.0  # not high impact without creds

    def test_null_origin(self) -> None:
        headers = "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: null\r\nAccess-Control-Allow-Credentials: true"
        chain = validate_cors("null", headers, "example.com")
        assert chain.total_weight >= 1.0


# ---------------------------------------------------------------------------
# SSRF validation
# ---------------------------------------------------------------------------

class TestSsrfValidation:
    def test_blocked_status(self) -> None:
        chain = validate_ssrf("http://169.254.169.254/", "403", "Forbidden")
        assert chain.total_weight == 0.0

    def test_200_but_empty(self) -> None:
        chain = validate_ssrf("http://169.254.169.254/", "200", "")
        assert chain.total_weight == 0.0

    def test_200_with_cloud_metadata(self) -> None:
        body = "ami-id\ninstance-id\nsecurity-credentials\niam"
        chain = validate_ssrf("http://169.254.169.254/", "200", body)
        assert chain.confidence in (Confidence.FIRM, Confidence.CONFIRMED)
        assert chain.total_weight >= 1.0

    def test_200_with_internal_content(self) -> None:
        body = "root:x:0:0:root:/root:/bin/bash"
        chain = validate_ssrf("file:///etc/passwd", "200", body)
        assert chain.total_weight >= 0.8


# ---------------------------------------------------------------------------
# IDOR validation
# ---------------------------------------------------------------------------

class TestIdorValidation:
    def test_all_same_response_is_fp(self) -> None:
        baseline = HttpResponse(status=200, body="generic response")
        test_responses = [
            ("1", HttpResponse(status=200, body="generic response")),
            ("2", HttpResponse(status=200, body="generic response")),
            ("3", HttpResponse(status=200, body="generic response")),
        ]
        chain = validate_idor(baseline, test_responses)
        assert chain.total_weight == 0.0
        assert len(chain.false_positive_checks) > 0

    def test_different_responses_is_real(self) -> None:
        baseline = HttpResponse(status=200, body='{"id": 1, "name": "Alice"}')
        test_responses = [
            ("1", HttpResponse(status=200, body='{"id": 1, "name": "Alice"}')),
            ("2", HttpResponse(status=200, body='{"id": 2, "name": "Bob"}')),
            ("3", HttpResponse(status=200, body='{"id": 3, "name": "Charlie"}')),
        ]
        chain = validate_idor(baseline, test_responses)
        assert chain.total_weight >= 1.0

    def test_mixed_status_codes(self) -> None:
        baseline = HttpResponse(status=200, body="data")
        test_responses = [
            ("1", HttpResponse(status=200, body="data")),
            ("2", HttpResponse(status=403, body="forbidden")),
            ("3", HttpResponse(status=200, body="other data")),
        ]
        chain = validate_idor(baseline, test_responses)
        assert chain.total_weight > 0


# ---------------------------------------------------------------------------
# BFLA validation
# ---------------------------------------------------------------------------

class TestBflaValidation:
    def test_403_is_not_vuln(self) -> None:
        chain = validate_bfla("/api/admin", "403", "Forbidden", None)
        assert chain.total_weight == 0.0

    def test_200_with_error_body_is_fp(self) -> None:
        chain = validate_bfla("/api/admin", "200", "You are not authorized to access this resource", None)
        assert chain.total_weight == 0.0
        assert len(chain.false_positive_checks) > 0

    def test_200_with_admin_data(self) -> None:
        body = '{"users": [{"email": "admin@test.com", "role": "admin"}]}'
        chain = validate_bfla("/api/admin/users", "200", body, None)
        assert chain.total_weight >= 1.0

    def test_200_identical_to_unauth_baseline(self) -> None:
        body = "generic error page"
        baseline = HttpResponse(status=200, body="generic error page")
        chain = validate_bfla("/api/admin", "200", body, baseline)
        assert chain.total_weight == 0.0


# ---------------------------------------------------------------------------
# JWT validation
# ---------------------------------------------------------------------------

class TestJwtValidation:
    def test_no_findings(self) -> None:
        chain = validate_jwt("JWT decoded successfully. exp: 1700000000", "no matches found")
        assert chain.total_weight == 0.0

    def test_weak_secret_found(self) -> None:
        chain = validate_jwt("", "[#] FOUND secret: 'password123'")
        assert chain.total_weight >= 1.0

    def test_none_algorithm(self) -> None:
        chain = validate_jwt("alg: none detected", "")
        assert chain.total_weight >= 1.0


# ---------------------------------------------------------------------------
# Subdomain takeover validation
# ---------------------------------------------------------------------------

class TestSubdomainTakeoverValidation:
    def test_no_cname(self) -> None:
        chain = validate_subdomain_takeover("", True)
        assert chain.total_weight == 0.0

    def test_cname_resolves(self) -> None:
        chain = validate_subdomain_takeover("target.github.io.", True)
        assert chain.total_weight == 0.0  # resolves = not dangling

    def test_dangling_cname_claimable(self) -> None:
        chain = validate_subdomain_takeover("myapp.herokuapp.com.", False, "No such app")
        assert chain.total_weight >= 1.5  # dangling + fingerprint + claimable service

    def test_dangling_cname_unknown_service(self) -> None:
        chain = validate_subdomain_takeover("something.custom.com.", False)
        assert chain.total_weight > 0
        assert chain.total_weight < 1.0  # dangling but no fingerprint
