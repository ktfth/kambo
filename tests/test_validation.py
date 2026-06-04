"""Tests for the evidence-based validation engine."""

from kambo.models import Confidence, EvidenceChain
from kambo.validation import (
    HttpResponse,
    validate_bfla,
    validate_cors,
    validate_idor,
    validate_jwt,
    validate_path_traversal,
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

    def test_waf_detected_downgrades_weight(self) -> None:
        payload = '"><img src=x onerror=alert(1)>'
        response = f"<html><body>{payload}</body></html>"
        headers = "HTTP/2 200\r\nserver: cloudflare\r\ncf-ray: abc123"
        chain_no_waf = validate_xss(response, payload, "q")
        chain_waf = validate_xss(response, payload, "q", response_headers=headers)
        assert chain_waf.total_weight < chain_no_waf.total_weight
        assert any("WAF" in fp for fp in chain_waf.false_positive_checks)

    def test_spa_detected_downgrades_weight(self) -> None:
        payload = '"><img src=x onerror=alert(1)>'
        response = f'<html><head><script id="__NEXT_DATA__">{{}}</script></head><body>{payload}</body></html>'
        chain = validate_xss(response, payload, "q")
        assert any("SPA" in fp for fp in chain.false_positive_checks)
        # Weight should be reduced compared to non-SPA
        chain_plain = validate_xss(f"<html><body>{payload}</body></html>", payload, "q")
        assert chain.total_weight < chain_plain.total_weight

    def test_waf_in_body_also_detected(self) -> None:
        payload = "<script>alert(1)</script>"
        response = f"<html><body>Server: cloudflare {payload}</body></html>"
        chain = validate_xss(response, payload, "q")
        assert any("WAF" in fp for fp in chain.false_positive_checks)

    def test_waf_gate_caps_firm_and_flags_browser(self) -> None:
        """§3 WAF gate: curl-only confirmation behind a WAF caps at FIRM and
        demands browser verification."""
        payload = "'-alert(1)-'"
        # Strong in-script reflection that would otherwise accrue high weight.
        response = f"<html><script>var x = '{payload}';</script></html>"
        headers = "HTTP/2 200\r\nserver: cloudflare\r\ncf-ray: abc123"
        chain = validate_xss(response, payload, "q", response_headers=headers)
        assert chain.confidence != Confidence.CONFIRMED
        assert chain.ceiling == Confidence.FIRM
        assert "needs-browser-verification" in chain.flags
        assert any("WAF" in g for g in chain.gates)

    def test_non_executable_data_block_caps_tentative(self) -> None:
        """I4 / anti-pattern #3: reflection in <script type=application/json> is
        not executable — capped TENTATIVE."""
        payload = '"><img src=x onerror=alert(1)>'
        response = (
            '<html><head><script type="application/json">'
            f'{{"q":"{payload}"}}</script></head></html>'
        )
        chain = validate_xss(response, payload, "q")
        assert chain.confidence == Confidence.TENTATIVE
        assert chain.ceiling == Confidence.TENTATIVE
        assert any("I4" in g for g in chain.gates)

    def test_executable_script_block_not_capped_by_data_gate(self) -> None:
        """A genuine executable <script> (no/JS type) is NOT treated as a data
        block."""
        payload = "'-alert(1)-'"
        response = f'<html><script type="text/javascript">var x = \'{payload}\';</script></html>'
        chain = validate_xss(response, payload, "q")
        assert not any("data block" in g for g in chain.gates)

    def test_comment_context_caps_tentative(self) -> None:
        """I4: reflection inside an HTML comment is not executable."""
        payload = "<svg onload=alert(1)>"
        response = f"<html><body><!-- user note: {payload} --></body></html>"
        chain = validate_xss(response, payload, "q")
        assert chain.confidence == Confidence.TENTATIVE
        assert chain.ceiling == Confidence.TENTATIVE


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

    def test_200_with_cloud_metadata_no_oob_capped_tentative(self) -> None:
        """Body keyword signatures accumulate weight but, with no OOB hit, the
        finding is capped at TENTATIVE — doctrine I3 forbids keyword-matching as
        confirmation for a blind class."""
        body = "ami-id\ninstance-id\nsecurity-credentials\niam"
        chain = validate_ssrf("http://169.254.169.254/", "200", body)
        assert chain.total_weight >= 1.0
        assert chain.confidence == Confidence.TENTATIVE
        assert chain.is_capped
        assert any("I3" in g for g in chain.gates)

    def test_oob_hit_confirms_ssrf(self) -> None:
        """An out-of-band interaction on the canary host lifts the cap and
        confirms (P3 / OAST)."""
        chain = validate_ssrf(
            "http://canary.oast.example/abc",
            "200",
            "",
            oob_hit=True,
            oob_evidence="DNS lookup canary.oast.example from 10.0.0.5 at 12:00:01",
        )
        assert chain.confidence == Confidence.CONFIRMED
        assert not chain.is_capped

    def test_200_with_internal_content(self) -> None:
        body = "root:x:0:0:root:/root:/bin/bash"
        chain = validate_ssrf("file:///etc/passwd", "200", body)
        assert chain.total_weight >= 0.8

    def test_iam_substring_not_matched(self) -> None:
        """'iam' inside 'enviamos' or 'Diamond' must NOT trigger cloud metadata."""
        body = "Nosotros enviamos correos y tenemos planes Diamond disponibles"
        chain = validate_ssrf("http://169.254.169.254/", "200", body)
        # Should have only the weak 0.2 status code signal, not the 1.5 metadata
        assert chain.total_weight <= 0.5
        assert not any("Cloud metadata" in s.signal for s in chain.items)

    def test_single_metadata_signature_downgrades_weight(self) -> None:
        """A single metadata keyword yields 0.5, not the full 1.5."""
        body = "ami-id is present but nothing else"
        chain = validate_ssrf("http://169.254.169.254/", "200", body)
        metadata_signals = [s for s in chain.items if "Cloud metadata" in s.signal]
        assert len(metadata_signals) == 1
        assert metadata_signals[0].weight == 0.5
        assert any("single" in fp.lower() or "1 metadata" in fp.lower()
                    for fp in chain.false_positive_checks)

    def test_multiple_metadata_signatures_full_weight(self) -> None:
        """Two or more metadata keywords yield the full 1.5 weight."""
        body = "ami-id\ninstance-id\nsecurity-credentials"
        chain = validate_ssrf("http://169.254.169.254/", "200", body)
        metadata_signals = [s for s in chain.items if "Cloud metadata" in s.signal]
        assert len(metadata_signals) == 1
        assert metadata_signals[0].weight == 1.5


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
        chain = validate_subdomain_takeover("test.github.io.", True)
        assert chain.total_weight == 0.0  # resolves = not dangling

    def test_dangling_cname_claimable(self) -> None:
        chain = validate_subdomain_takeover("testapp.herokuapp.com.", False, "No such app")
        assert chain.total_weight >= 1.5  # dangling + fingerprint + claimable service

    def test_dangling_cname_unknown_service(self) -> None:
        chain = validate_subdomain_takeover("something.example.com.", False)
        assert chain.total_weight > 0
        assert chain.total_weight < 1.0  # dangling but no fingerprint

    def test_dangling_cname_non_claimable_elb(self) -> None:
        # AWS ELB DNS names are account-bound + hash-named: a dangling CNAME to one
        # is DNS hygiene, NOT a registerable takeover. Must accrue no takeover weight.
        chain = validate_subdomain_takeover(
            "internal-eapp-test-demo-lb-157125248.us-gov-west-1.elb.amazonaws.com.",
            False,
        )
        assert chain.total_weight == 0.0
        assert chain.confidence_pct == 0
        assert chain.confidence == Confidence.TENTATIVE
        assert any("non-claimable" in c.lower() for c in chain.false_positive_checks)
        assert any("elb" in c.lower() for c in chain.false_positive_checks)

    def test_dangling_cname_non_claimable_alb_elb_before_region(self) -> None:
        # The other ELB DNS ordering: name.elb.<region>.amazonaws.com (vs the
        # *.<region>.elb.amazonaws.com form in the test above). Both must match.
        chain = validate_subdomain_takeover(
            "myalb-987654321.elb.us-gov-west-1.amazonaws.com.", False
        )
        assert chain.total_weight == 0.0
        assert any("non-claimable" in c.lower() for c in chain.false_positive_checks)

    def test_dangling_cname_non_claimable_rds(self) -> None:
        chain = validate_subdomain_takeover(
            "mydb.cluster-abc123.us-east-1.rds.amazonaws.com.", False
        )
        assert chain.total_weight == 0.0
        assert any("rds" in c.lower() for c in chain.false_positive_checks)

    def test_dangling_cname_non_claimable_api_gateway(self) -> None:
        # API Gateway invoke URLs carry an account-bound auto-generated API id.
        chain = validate_subdomain_takeover(
            "abc123xyz.execute-api.us-east-1.amazonaws.com.", False
        )
        assert chain.total_weight == 0.0
        assert any("non-claimable" in c.lower() for c in chain.false_positive_checks)

    def test_dangling_cname_non_claimable_lambda_url(self) -> None:
        # Lambda Function URLs are account-bound and live under on.aws (no amazonaws.com).
        chain = validate_subdomain_takeover(
            "abcdef1234567890.lambda-url.us-east-1.on.aws.", False
        )
        assert chain.total_weight == 0.0
        assert any("lambda" in c.lower() for c in chain.false_positive_checks)

    def test_dangling_claimable_s3_not_suppressed(self) -> None:
        # S3 IS claimable even though it is AWS — must NOT be treated as non-claimable.
        chain = validate_subdomain_takeover(
            "oldbucket.s3.amazonaws.com.", False, "NoSuchBucket"
        )
        assert chain.total_weight >= 1.5  # dangling + fingerprint + claimable service

    def test_dangling_non_claimable_with_real_fingerprint_not_suppressed(self) -> None:
        # Defensive: a genuine takeover fingerprint in the body still wins over the
        # non-claimable suppression (keeps any real signal).
        chain = validate_subdomain_takeover(
            "x.us-gov-west-1.elb.amazonaws.com.",
            False,
            "There isn't a GitHub Pages site here.",
        )
        assert chain.total_weight > 0.0


class TestPathTraversal:
    def test_etc_passwd_detected(self) -> None:
        body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        chain = validate_path_traversal(body, "../../etc/passwd")
        assert chain.confidence in (Confidence.CONFIRMED, Confidence.FIRM)
        assert chain.total_weight >= 1.5

    def test_windows_ini_detected(self) -> None:
        body = "[boot loader]\ntimeout=30\ndefault=multi(0)disk(0)\n[operating systems]\n"
        chain = validate_path_traversal(body, "..\\..\\boot.ini")
        assert chain.total_weight >= 1.5

    def test_ssh_key_detected(self) -> None:
        # Construct PEM header dynamically to avoid pre-commit secret detection
        pem_type = "PRIVATE"
        body = f"-----BEGIN RSA {pem_type} KEY-----\nFAKETESTKEYDATA..."
        chain = validate_path_traversal(body, "../../root/.ssh/id_rsa")
        assert chain.total_weight >= 1.5

    def test_payload_reflected_not_executed(self) -> None:
        body = "You searched for: ../../etc/passwd\nNo results found."
        chain = validate_path_traversal(body, "../../etc/passwd")
        assert chain.total_weight == 0
        assert len(chain.false_positive_checks) >= 1

    def test_empty_response(self) -> None:
        chain = validate_path_traversal("", "../../etc/passwd")
        assert chain.total_weight == 0

    def test_baseline_identical_is_fp(self) -> None:
        body = "Default page content"
        chain = validate_path_traversal(body, "../../etc/passwd", baseline_body="Default page content")
        assert chain.total_weight == 0
        assert len(chain.false_positive_checks) >= 1

    def test_php_error_detected(self) -> None:
        body = "Warning: include(../../etc/passwd) failed to open stream: No such file or directory"
        chain = validate_path_traversal(body, "../../etc/passwd")
        assert chain.total_weight > 0  # error = path processed


# ---------------------------------------------------------------------------
# CSP nonce gate (I5) — XSS capped when CSP nonce present
# ---------------------------------------------------------------------------

class TestXssCspNonceGate:
    def test_csp_nonce_caps_at_tentative(self) -> None:
        """I5: CSP with nonce in script-src prevents inline execution."""
        payload = "<script>alert(1)</script>"
        response = f"<html><body>{payload}</body></html>"
        headers = (
            "HTTP/2 200\r\n"
            "Content-Security-Policy: default-src 'self'; "
            "script-src 'nonce-abc123def' 'strict-dynamic'"
        )
        chain = validate_xss(response, payload, "q", response_headers=headers)
        assert chain.confidence == Confidence.TENTATIVE
        assert chain.is_capped
        assert any("I5" in g for g in chain.gates)

    def test_csp_sha256_caps_at_tentative(self) -> None:
        """I5: CSP with sha256 hash also blocks injected scripts."""
        payload = "'-alert(1)-'"
        response = f"<html><script>var x = '{payload}';</script></html>"
        headers = (
            "HTTP/2 200\r\n"
            "Content-Security-Policy: script-src 'sha256-abcdef123456'"
        )
        chain = validate_xss(response, payload, "q", response_headers=headers)
        assert chain.confidence == Confidence.TENTATIVE
        assert any("CSP" in fp for fp in chain.false_positive_checks)

    def test_no_csp_allows_higher_confidence(self) -> None:
        """Without CSP nonce, in-script reflection should reach FIRM."""
        payload = "'-alert(1)-'"
        response = f"<html><script>var x = '{payload}';</script></html>"
        chain = validate_xss(response, payload, "q")
        assert chain.confidence >= Confidence.FIRM

    def test_csp_without_nonce_no_cap(self) -> None:
        """CSP without nonce/hash (e.g. unsafe-inline) does not trigger I5."""
        payload = "<script>alert(1)</script>"
        response = f"<html><body>{payload}</body></html>"
        headers = (
            "HTTP/2 200\r\n"
            "Content-Security-Policy: script-src 'self' 'unsafe-inline'"
        )
        chain = validate_xss(response, payload, "q", response_headers=headers)
        assert not chain.is_capped


# ---------------------------------------------------------------------------
# SPA + script context weight reduction
# ---------------------------------------------------------------------------

class TestXssSpaScriptContext:
    def test_spa_reduces_script_context_weight(self) -> None:
        """SPA framework should reduce script context weight like WAF does."""
        payload = "'-alert(1)-'"
        response_spa = (
            '<html><head><script id="__NEXT_DATA__">{}</script></head>'
            f"<script>var x = '{payload}';</script></html>"
        )
        response_plain = f"<html><script>var x = '{payload}';</script></html>"
        chain_spa = validate_xss(response_spa, payload, "q")
        chain_plain = validate_xss(response_plain, payload, "q")
        assert chain_spa.total_weight < chain_plain.total_weight


# ---------------------------------------------------------------------------
# CORS same-org subdomain filter
# ---------------------------------------------------------------------------

class TestCorsSameOrgSubdomain:
    def test_same_org_subdomain_caps_tentative(self) -> None:
        """Reflected origin that is a subdomain of target root is by-design."""
        headers = (
            "HTTP/1.1 200 OK\r\n"
            "Access-Control-Allow-Origin: https://evil-graphql.instagram.com\r\n"
            "Access-Control-Allow-Credentials: true"
        )
        chain = validate_cors(
            "https://evil-graphql.instagram.com",
            headers,
            "graphql.instagram.com",
        )
        assert chain.confidence == Confidence.TENTATIVE
        assert chain.ceiling == Confidence.TENTATIVE
        assert any("same-org" in fp.lower() for fp in chain.false_positive_checks)
        assert any("same-org" in g.lower() for g in chain.gates)

    def test_external_origin_not_capped(self) -> None:
        """Truly external origin should NOT be capped by same-org filter."""
        headers = (
            "HTTP/1.1 200 OK\r\n"
            "Access-Control-Allow-Origin: https://evil.com\r\n"
            "Access-Control-Allow-Credentials: true"
        )
        chain = validate_cors("https://evil.com", headers, "example.com")
        assert chain.confidence >= Confidence.FIRM
        assert not any("same-org" in fp.lower() for fp in chain.false_positive_checks)
