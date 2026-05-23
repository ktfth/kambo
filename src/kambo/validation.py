"""Evidence-based validation engine for reducing false positives.

Each validator function returns an EvidenceChain that accumulates weighted signals.
The chain's total weight determines confidence:
  >= 2.0 → CONFIRMED (exploit-grade proof)
  >= 1.0 → FIRM (strong indicators, multiple signals)
  >  0.0 → TENTATIVE (single signal, needs manual verification)
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from kambo.models import EvidenceChain


# ---------------------------------------------------------------------------
# HTTP Response helpers
# ---------------------------------------------------------------------------

class HttpResponse:
    """Lightweight HTTP response representation for comparison."""

    __slots__ = ("status", "body", "headers", "body_hash", "body_length")

    def __init__(self, status: int, body: str, headers: str = "") -> None:
        self.status = status
        self.body = body
        self.headers = headers
        self.body_length = len(body)
        self.body_hash = hashlib.md5(body.encode(errors="replace")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "body_length": self.body_length,
            "body_hash": self.body_hash,
            "body_preview": self.body[:500],
        }


def parse_curl_verbose(raw: str) -> HttpResponse:
    """Parse curl output that includes status code and body."""
    status = 0
    m = re.search(r"HTTP/\d\.?\d?\s+(\d{3})", raw)
    if m:
        status = int(m.group(1))
    return HttpResponse(status=status, body=raw, headers="")


def responses_differ(baseline: HttpResponse, test: HttpResponse, threshold: float = 0.1) -> bool:
    """Check if two responses differ significantly.

    Uses body hash for exact match, then falls back to length ratio.
    A small threshold (0.1 = 10%) catches meaningful differences
    while ignoring CSRF tokens, timestamps, etc.
    """
    if baseline.body_hash == test.body_hash:
        return False
    if baseline.body_length == 0:
        return test.body_length > 0
    ratio = abs(baseline.body_length - test.body_length) / max(baseline.body_length, 1)
    return ratio > threshold


# ---------------------------------------------------------------------------
# SQL Injection validation
# ---------------------------------------------------------------------------

# sqlmap outputs these when it confirms injection
_SQLI_CONFIRMED_PATTERNS = [
    r"parameter\s+'[^']+'\s+is\s+vulnerable",
    r"is\s+vulnerable.*injectable",
    r"available\s+databases\s*\[",
    r"back-end\s+DBMS:\s+\w+",
    r"fetched\s+data\s+logged",
    r"sqlmap\s+identified\s+the\s+following\s+injection\s+point",
]

# These appear in sqlmap output even for non-vulnerable targets
_SQLI_FALSE_POSITIVE_PATTERNS = [
    r"all\s+tested\s+parameters\s+do\s+not\s+appear\s+to\s+be\s+injectable",
    r"it\s+is\s+not\s+injectable",
    r"connection\s+timed\s+out",
    r"target\s+URL\s+content\s+is\s+not\s+stable",
]


def validate_sqli(raw_output: str) -> EvidenceChain:
    """Validate SQL injection findings from sqlmap output."""
    chain = EvidenceChain()
    lower = raw_output.lower()

    # FP check: empty or error output
    if not raw_output.strip():
        return chain.add_fp_check("No sqlmap output — tool may have failed or timed out")

    # FP check: connection errors
    if re.search(r"(connection refused|connection timed out|unable to connect)", lower):
        return chain.add_fp_check("sqlmap could not connect to target")

    # FP check: WAF/IPS blocking
    if re.search(r"(waf|ips|firewall).*(detected|block)", lower):
        chain = chain.add_fp_check("WAF/IPS detected — results may be unreliable")

    # Check for explicit non-vulnerable indicators first
    for pattern in _SQLI_FALSE_POSITIVE_PATTERNS:
        if re.search(pattern, lower):
            chain = chain.add_fp_check(f"FP pattern matched: {pattern}")
            return chain  # no evidence — early return

    # Look for confirmed injection signals
    for pattern in _SQLI_CONFIRMED_PATTERNS:
        if re.search(pattern, lower):
            chain = chain.add(
                signal=f"sqlmap confirmed: {pattern}",
                source="sqlmap",
                raw_data=_extract_context(raw_output, pattern),
                weight=0.8,
            )

    # Check for database enumeration (strong confirmation)
    db_match = re.search(r"available\s+databases\s*\[(\d+)\]", lower)
    if db_match:
        chain = chain.add(
            signal=f"Enumerated {db_match.group(1)} databases",
            source="sqlmap",
            raw_data=_extract_context(raw_output, r"available\s+databases"),
            weight=1.0,
        )

    # Check for DBMS identification
    dbms = re.search(r"back-end\s+DBMS:\s+(\w+)", raw_output, re.IGNORECASE)
    if dbms:
        chain = chain.add(
            signal=f"DBMS identified: {dbms.group(1)}",
            source="sqlmap",
            raw_data=dbms.group(0),
            weight=0.5,
        )

    # Check injection technique type (aggregate to avoid weight inflation)
    techniques = re.findall(r"Type:\s*(.+?)(?:\n|$)", raw_output)
    if techniques:
        unique_techs = sorted(set(t.strip() for t in techniques))
        chain = chain.add(
            signal=f"Injection techniques: {', '.join(unique_techs)}",
            source="sqlmap",
            raw_data="; ".join(unique_techs),
            weight=min(0.5, 0.2 + len(unique_techs) * 0.1),  # cap at 0.5
        )

    return chain


# ---------------------------------------------------------------------------
# XSS validation
# ---------------------------------------------------------------------------

def validate_xss(
    raw_output: str,
    payload: str,
    parameter: str,
    reflected_context: str = "",
) -> EvidenceChain:
    """Validate XSS based on reflection analysis.

    A reflection alone is not XSS. We need:
    1. Payload reflected in response (weight 0.3)
    2. Payload is in an executable context — not inside an attribute or comment (weight 0.7)
    3. No output encoding detected (weight 0.5)
    """
    chain = EvidenceChain()

    # Check if payload is actually reflected
    if payload not in raw_output:
        chain = chain.add_fp_check("Payload not reflected in response body")
        return chain

    chain = chain.add(
        signal=f"Payload reflected in response: {payload[:80]}",
        source="curl/reflection",
        raw_data=_extract_context(raw_output, re.escape(payload)),
        weight=0.3,
    )

    # Check if reflection is in an executable context
    # Only check encoding for payloads that contain HTML special chars
    if any(c in payload for c in "<>&\""):
        encoded_variants = [
            payload.replace("<", "&lt;").replace(">", "&gt;"),
            payload.replace("<", "%3C").replace(">", "%3E"),
            payload.replace('"', "&quot;"),
        ]

        # The encoded form must appear WITHOUT the raw form also appearing
        has_encoded = any(variant in raw_output for variant in encoded_variants)
        has_raw = payload in raw_output
        if has_encoded and not has_raw:
            chain = chain.add_fp_check("Payload appears HTML-encoded in response — likely sanitized")
            return chain

    chain = chain.add(
        signal="Payload reflected without encoding",
        source="encoding_check",
        weight=0.5,
    )

    # Check context: is it inside a tag, attribute, script block, or comment?
    payload_idx = raw_output.find(payload)
    if payload_idx < 0:
        return chain  # Payload was encoded after earlier check passed
    before_payload = raw_output[:payload_idx]
    in_script = "<script" in before_payload[max(0, len(before_payload) - 500):]
    in_comment = "<!--" in before_payload[max(0, len(before_payload) - 200):]

    if in_script:
        chain = chain.add(
            signal="Reflection occurs inside <script> block — high XSS probability",
            source="context_analysis",
            weight=0.7,
        )
    elif in_comment:
        chain = chain.add_fp_check("Reflection is inside HTML comment — not exploitable")
    else:
        chain = chain.add(
            signal="Reflection in HTML body context",
            source="context_analysis",
            weight=0.5,
        )

    return chain


# ---------------------------------------------------------------------------
# CORS validation
# ---------------------------------------------------------------------------

def validate_cors(
    origin_tested: str,
    response_headers: str,
    target_domain: str,
) -> EvidenceChain:
    """Validate CORS misconfiguration with proper policy analysis.

    Not every reflected origin is a vulnerability. We check:
    1. Is the evil origin reflected in Access-Control-Allow-Origin?
    2. Are credentials allowed (Access-Control-Allow-Credentials: true)?
    3. Is the wildcard (*) used with credentials? (browser blocks this, not vuln)
    """
    chain = EvidenceChain()
    headers_lower = response_headers.lower()

    # Extract ACAO header value
    acao_match = re.search(r"access-control-allow-origin:\s*(.+)", headers_lower)
    if not acao_match:
        chain = chain.add_fp_check("No Access-Control-Allow-Origin header present")
        return chain

    acao_value = acao_match.group(1).strip()

    # Wildcard is NOT a vulnerability (browsers block credentials with *)
    if acao_value == "*":
        acac_match = re.search(r"access-control-allow-credentials:\s*true", headers_lower)
        if acac_match:
            # Wildcard + credentials is blocked by browsers — NOT vuln
            chain = chain.add_fp_check("Wildcard ACAO with credentials — browsers block this, NOT vulnerable")
        else:
            chain = chain.add(
                signal="Wildcard ACAO without credentials — low impact (public data only)",
                source="cors_check",
                weight=0.1,
            )
        return chain

    # Check if our evil origin is reflected
    if origin_tested.lower() not in acao_value:
        chain = chain.add_fp_check(f"Origin {origin_tested} not reflected in ACAO: {acao_value}")
        return chain

    chain = chain.add(
        signal=f"Arbitrary origin {origin_tested} reflected in ACAO header",
        source="cors_check",
        raw_data=response_headers[:500],
        weight=0.5,
    )

    # Check for credentials — this is what makes it exploitable
    if "access-control-allow-credentials: true" in headers_lower:
        chain = chain.add(
            signal="Credentials allowed with reflected origin — full CORS exploitation possible",
            source="cors_check",
            weight=1.0,
        )
    else:
        chain = chain.add(
            signal="Reflected origin but no credentials — limited to public data theft",
            source="cors_check",
            weight=0.2,
        )

    # Check null origin (often exploitable via sandboxed iframe)
    if origin_tested == "null" and "null" in acao_value:
        chain = chain.add(
            signal="null origin accepted — exploitable via sandboxed iframe",
            source="cors_check",
            weight=0.5,
        )

    return chain


# ---------------------------------------------------------------------------
# SSRF validation
# ---------------------------------------------------------------------------

_CLOUD_METADATA_SIGNATURES = {
    "aws": ["ami-id", "instance-id", "iam", "security-credentials", "meta-data"],
    "gcp": ["computeMetadata", "project-id", "service-accounts"],
    "azure": ["compute", "vmId", "subscriptionId"],
}


def validate_ssrf(
    payload: str,
    status_code: str,
    response_body: str,
) -> EvidenceChain:
    """Validate SSRF with response content analysis.

    Status code alone is NOT sufficient. We check:
    1. Did the server actually fetch the internal resource?
    2. Does the response contain internal data (metadata, headers, etc.)?
    3. Is the response different from an error page?
    """
    chain = EvidenceChain()
    body_lower = response_body.lower()

    # FP check: common non-SSRF error responses
    if re.search(r"(invalid url|bad request|url not allowed|blocked)", body_lower):
        chain = chain.add_fp_check("Server rejected the URL — input validation in place")

    # Status code check (weak signal alone)
    if status_code in ("200", "301", "302"):
        chain = chain.add(
            signal=f"HTTP {status_code} returned for internal payload: {payload[:100]}",
            source="ssrf_probe",
            weight=0.2,
        )
    else:
        chain = chain.add_fp_check(f"Non-success status {status_code} — likely blocked")
        return chain

    # Check for cloud metadata content
    for provider, signatures in _CLOUD_METADATA_SIGNATURES.items():
        matches = [sig for sig in signatures if sig.lower() in body_lower]
        if matches:
            chain = chain.add(
                signal=f"Cloud metadata ({provider}) content detected: {', '.join(matches)}",
                source="ssrf_content_analysis",
                raw_data=response_body[:1000],
                weight=1.5,
            )
            break

    # Check for internal service indicators
    internal_indicators = [
        (r"server:\s*(apache|nginx|gunicorn)", "Internal web server header"),
        (r"x-powered-by:", "Internal X-Powered-By header"),
        (r"<title>.*dashboard.*</title>", "Internal dashboard page"),
        (r"(root|admin):.*(bash|sh)", "Internal /etc/passwd content"),
        (r"ssh-rsa\s+", "SSH key material"),
    ]

    for pattern, description in internal_indicators:
        if re.search(pattern, body_lower):
            chain = chain.add(
                signal=description,
                source="ssrf_content_analysis",
                raw_data=_extract_context(response_body, pattern),
                weight=0.8,
            )

    # Empty or error-like response is likely a false positive
    if len(response_body.strip()) < 10:
        return EvidenceChain().add_fp_check("Response body too short — likely error or blocked")

    return chain


# ---------------------------------------------------------------------------
# IDOR / BOLA validation
# ---------------------------------------------------------------------------

def validate_idor(
    baseline_response: HttpResponse,
    test_responses: list[tuple[str, HttpResponse]],
) -> EvidenceChain:
    """Validate IDOR/BOLA by comparing test responses against baseline.

    A true IDOR returns different data for different IDs using the same token.
    False positives: generic error pages that return 200, cached responses,
    default responses for all IDs.
    """
    chain = EvidenceChain(baseline=baseline_response.to_dict())

    if not test_responses:
        return chain

    # FP check: baseline itself returned error
    if baseline_response.status != 200:
        chain = chain.add_fp_check(f"Baseline returned {baseline_response.status} — endpoint may not exist")

    unique_hashes: set[str] = set()
    accessible_count = 0
    identical_count = 0

    for resource_id, resp in test_responses:
        if resp.status != 200:
            continue
        accessible_count += 1
        unique_hashes.add(resp.body_hash)

        if resp.body_hash == baseline_response.body_hash:
            identical_count += 1

    # If all 200 responses have the same body, it's likely a generic response
    if len(unique_hashes) <= 1 and accessible_count > 1:
        chain = chain.add_fp_check(
            f"All {accessible_count} accessible resources return identical content "
            f"(hash={next(iter(unique_hashes), 'none')}) — likely generic response, NOT IDOR"
        )
        return chain

    # If most responses are identical to baseline, suspicious
    if identical_count > accessible_count * 0.7 and accessible_count > 2:
        chain = chain.add_fp_check(
            f"{identical_count}/{accessible_count} responses identical to baseline — likely false positive"
        )
        return chain

    # Different content for different IDs = real IDOR
    if len(unique_hashes) > 1 and accessible_count > 0:
        chain = chain.add(
            signal=f"{accessible_count} resources accessible with {len(unique_hashes)} unique responses",
            source="idor_analysis",
            weight=0.6,
        )

        # Strong signal: content differs per ID
        if len(unique_hashes) >= min(3, accessible_count):
            chain = chain.add(
                signal="Response content varies per resource ID — confirms different user data returned",
                source="idor_diffing",
                weight=0.8,
            )

    # Check if baseline should have been 403/401
    if baseline_response.status == 200:
        chain = chain.add(
            signal="Baseline request succeeds — need to verify this isn't the user's own data",
            source="idor_baseline",
            weight=0.1,
        )

    return chain


# ---------------------------------------------------------------------------
# BFLA validation
# ---------------------------------------------------------------------------

def validate_bfla(
    endpoint: str,
    status_code: str,
    response_body: str,
    baseline_unauth: HttpResponse | None = None,
) -> EvidenceChain:
    """Validate Broken Function Level Authorization.

    Key insight: a 200 response doesn't mean the admin function executed.
    Many APIs return 200 with an error body, or a generic "not found" page.
    """
    chain = EvidenceChain()

    # Non-success status = properly blocked
    if status_code not in ("200", "201", "204"):
        chain = chain.add_fp_check(f"Status {status_code} — endpoint properly restricts access")
        return chain

    # 200 but need to check response content
    body_lower = response_body.lower()

    # Check for error indicators in body despite 200 status
    error_indicators = [
        "unauthorized", "forbidden", "access denied", "permission denied",
        "not authorized", "insufficient privileges", "admin required",
        "requires admin", "role required",
    ]
    for indicator in error_indicators:
        if indicator in body_lower:
            chain = chain.add_fp_check(f"Response body contains '{indicator}' despite HTTP 200 — soft denial")
            return chain

    # If we have an unauth baseline, compare
    if baseline_unauth and baseline_unauth.body_hash == hashlib.md5(response_body.encode()).hexdigest():
        chain = chain.add_fp_check("Response identical to unauthenticated baseline — likely generic error page")
        return chain

    chain = chain.add(
        signal=f"Admin endpoint {endpoint} returned {status_code} with regular user token",
        source="bfla_test",
        raw_data=response_body[:500],
        weight=0.5,
    )

    # Check if response contains admin-like data
    admin_indicators = [
        "users", "settings", "config", "admin", "logs", "audit",
        "permissions", "roles", "email", "password",
    ]
    found_indicators = [ind for ind in admin_indicators if ind in body_lower]
    if found_indicators:
        chain = chain.add(
            signal=f"Response contains admin data indicators: {', '.join(found_indicators)}",
            source="bfla_content",
            weight=0.7,
        )

    return chain


# ---------------------------------------------------------------------------
# JWT validation
# ---------------------------------------------------------------------------

def validate_jwt(raw_output: str, crack_output: str) -> EvidenceChain:
    """Validate JWT vulnerabilities from jwt_tool output."""
    chain = EvidenceChain()

    # FP check: empty or error output
    if not crack_output.strip() and not raw_output.strip():
        return chain.add_fp_check("No output from jwt_tool — tool may have failed")

    # FP check: token parsing failure
    if re.search(r"(invalid|malformed|not a valid).*token", raw_output, re.IGNORECASE):
        return chain.add_fp_check("JWT token is invalid/malformed — cannot assess")

    # FP check: wordlist exhausted without finding
    crack_lower = crack_output.lower()
    if any(neg in crack_lower for neg in ["no match", "not found", "no result", "0 found", "exhausted"]):
        chain = chain.add_fp_check("Wordlist exhausted without cracking secret")

    # Check for weak secret cracked
    if re.search(r"\[#\]\s*FOUND", crack_output, re.IGNORECASE):
        secret_match = re.search(r"secret.*?[\"']([^\"']+)[\"']", crack_output, re.IGNORECASE)
        secret = secret_match.group(1) if secret_match else "unknown"
        chain = chain.add(
            signal=f"JWT signing secret cracked: '{secret}'",
            source="jwt_tool",
            raw_data=crack_output[:500],
            weight=1.5,
        )

    # Check for algorithm confusion vulnerability
    if re.search(r"alg.*none", raw_output, re.IGNORECASE):
        chain = chain.add(
            signal="JWT accepts 'none' algorithm — token forgery possible",
            source="jwt_tool",
            weight=1.0,
        )

    # Check for missing expiry — only if jwt_tool explicitly reports it
    if re.search(r"no.*exp(iry|iration)?", raw_output, re.IGNORECASE):
        chain = chain.add(
            signal="JWT has no expiry (exp) claim",
            source="jwt_tool",
            weight=0.3,
        )

    # Generic "found" without specifics is weak — but exclude negative matches
    crack_lower = crack_output.lower()
    has_found = "found" in crack_lower
    has_negative = any(neg in crack_lower for neg in ["no match", "not found", "no result", "0 found"])
    if has_found and not has_negative and chain.total_weight == 0:
        chain = chain.add(
            signal="jwt_tool reports a finding (unspecified)",
            source="jwt_tool",
            raw_data=crack_output[:300],
            weight=0.3,
        )

    return chain


# ---------------------------------------------------------------------------
# Subdomain takeover validation
# ---------------------------------------------------------------------------

_TAKEOVER_FINGERPRINTS: dict[str, list[str]] = {
    "github_pages": ["there isn't a github pages site here", "for root urls"],
    "heroku": ["no such app", "herokucdn.com"],
    "aws_s3": ["nosuchbucket", "the specified bucket does not exist"],
    "shopify": ["sorry, this shop is currently unavailable"],
    "fastly": ["fastly error: unknown domain"],
    "pantheon": ["the gods are wise"],
    "tumblr": ["there's nothing here", "whatever you were looking for"],
    "wordpress": ["do you want to register"],
    "teamwork": ["oops - we didn't find your site"],
    "helpjuice": ["we could not find what you're looking for"],
    "helpscout": ["no settings were found for this company"],
    "cargo": ["if you're moving your domain away"],
    "statuspage": ["you are being redirected", "statuspage.io"],
    "uservoice": ["this uservoice subdomain is currently available"],
    "surge": ["project not found"],
    "intercom": ["this page is reserved for artistic dogs"],
    "webflow": ["the page you are looking for doesn't exist"],
    "kajabi": ["the page you were looking for doesn't exist"],
    "thinkific": ["you may have mistyped the address"],
    "tave": ["sorry, this page is no longer available"],
    "wishpond": ["https://www.wishpond.com/404"],
    "aftership": ["oops, page not found"],
    "aha": ["there is no portal here"],
    "tictail": ["to claim it, visit"],
    "brightcove": ["brightcove"],
    "bigcartel": ["<h1>oops! we couldn&#8217;t find that page"],
    "acquia": ["the site you are looking for could not be found"],
    "simplebooklet": ["simplebooklet"],
    "getresponse": ["with getresponse landing pages"],
    "vend": ["looks like you've traveled too far"],
    "jetbrains": ["is not a registered intellij platform"],
    "azure": ["404 web site not found", "microsoft azure"],
}


def validate_subdomain_takeover(
    cname: str,
    cname_resolves: bool,
    response_body: str = "",
) -> EvidenceChain:
    """Validate subdomain takeover with CNAME and fingerprint checking."""
    chain = EvidenceChain()

    if not cname:
        chain = chain.add_fp_check("No CNAME record found — not a takeover candidate")
        return chain

    # FP check: CNAME points to the same organization (internal redirect, not dangling)
    if cname_resolves and not response_body:
        chain = chain.add_fp_check("CNAME resolves with no error page — likely internal redirect")
        return chain

    if cname_resolves:
        chain = chain.add_fp_check("CNAME target resolves — not dangling")
        # Still check for service-level takeover via fingerprints
        if response_body:
            for service, fingerprints in _TAKEOVER_FINGERPRINTS.items():
                if any(fp in response_body.lower() for fp in fingerprints):
                    chain = chain.add(
                        signal=f"Service fingerprint matches {service} despite CNAME resolving — possible service-level takeover",
                        source="takeover_fingerprint",
                        weight=0.5,
                    )
        return chain

    # Dangling CNAME
    chain = chain.add(
        signal=f"Dangling CNAME: {cname} does not resolve",
        source="dns_check",
        weight=0.5,
    )

    # Check fingerprints for confirmation
    if response_body:
        for service, fingerprints in _TAKEOVER_FINGERPRINTS.items():
            if any(fp in response_body.lower() for fp in fingerprints):
                chain = chain.add(
                    signal=f"Takeover fingerprint confirmed for {service}",
                    source="takeover_fingerprint",
                    raw_data=response_body[:500],
                    weight=1.0,
                )
                break

    # Check if CNAME points to a claimable service
    claimable_cnames = [
        "github.io", "herokuapp.com", "s3.amazonaws.com", "azurewebsites.net",
        "cloudfront.net", "shopify.com", "fastly.net", "pantheonsite.io",
        "domains.tumblr.com", "wpengine.com", "ghost.io", "myshopify.com",
        "surge.sh", "bitbucket.io", "webflow.io",
    ]
    for svc in claimable_cnames:
        if svc in cname.lower():
            chain = chain.add(
                signal=f"CNAME points to claimable service: {svc}",
                source="cname_analysis",
                weight=0.5,
            )
            break

    return chain


# ---------------------------------------------------------------------------
# Path Traversal / LFI validation
# ---------------------------------------------------------------------------

# Known file content signatures that prove successful traversal
_TRAVERSAL_SIGNATURES: dict[str, list[str]] = {
    "unix_passwd": [r"root:.*:0:0:", r"daemon:.*:\d+:\d+:", r"nobody:.*:"],
    "unix_shadow": [r"\$\d\$.*\$", r"root:\$"],  # password hashes
    "unix_hosts": [r"127\.0\.0\.1\s+localhost"],
    "windows_ini": [r"\[boot loader\]", r"\[operating systems\]"],
    "windows_hosts": [r"127\.0\.0\.1\s+localhost"],
    "web_config": [r"<configuration>", r"connectionString"],
    "ssh_keys": [r"-----BEGIN.*PRIVATE KEY-----"],
}


def validate_path_traversal(
    response_body: str,
    payload: str,
    baseline_body: str = "",
) -> EvidenceChain:
    """Validate path traversal / LFI based on response content analysis.

    A successful traversal shows file contents that match known signatures.
    A false positive shows the payload reflected but no file content.

    Args:
        response_body: Response body from the traversal attempt
        payload: The traversal payload used (e.g., ../../etc/passwd)
        baseline_body: Normal response body for comparison
    """
    chain = EvidenceChain()

    if not response_body or len(response_body.strip()) < 10:
        return chain.add_fp_check("Response body too short — likely blocked")

    body_lower = response_body.lower()

    # Check for error indicators first — they prove the path was processed
    # even when the payload appears literally in the error message
    error_indicators = [
        (r"failed to open stream", "PHP file inclusion error"),
        (r"no such file or directory", "File not found error — path processed"),
        (r"permission denied", "Permission denied — path exists but not readable"),
        (r"include\(\).*failed", "PHP include() failed — LFI path processed"),
    ]
    has_error_indicator = False
    for pattern, description in error_indicators:
        if re.search(pattern, body_lower):
            chain = chain.add(
                signal=description,
                source="error_analysis",
                weight=0.4,
            )
            has_error_indicator = True

    # FP check: if payload is reflected literally without file content or error signals
    if payload in response_body and not has_error_indicator and not any(
        re.search(sigs[0], response_body) for sigs in _TRAVERSAL_SIGNATURES.values()
    ):
        chain = chain.add_fp_check("Payload reflected literally without file content signatures")
        return chain

    # Check for known file content signatures
    for file_type, patterns in _TRAVERSAL_SIGNATURES.items():
        for pattern in patterns:
            if re.search(pattern, response_body, re.IGNORECASE):
                chain = chain.add(
                    signal=f"File content signature matched: {file_type}",
                    source="traversal_content_analysis",
                    raw_data=_extract_context(response_body, pattern),
                    weight=1.5,
                )
                break  # one match per file type is enough

    # FP check: compare against baseline to filter generic responses
    if baseline_body:
        if response_body.strip() == baseline_body.strip():
            chain = chain.add_fp_check("Response identical to baseline — no traversal effect")
            return EvidenceChain().add_fp_check("Response identical to baseline")

        # If response differs significantly, that's an additional signal
        if abs(len(response_body) - len(baseline_body)) > 100:
            chain = chain.add(
                signal="Response length differs significantly from baseline",
                source="baseline_comparison",
                weight=0.3,
            )

    return chain


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_context(text: str, pattern: str, context_chars: int = 200) -> str:
    """Extract text surrounding a regex match for evidence."""
    m = re.search(pattern, text, re.IGNORECASE)
    if not m:
        return ""
    start = max(0, m.start() - context_chars)
    end = min(len(text), m.end() + context_chars)
    return text[start:end]


# ---------------------------------------------------------------------------
# validate_rce — Remote Code Execution / Command Injection
# ---------------------------------------------------------------------------

# Patterns that indicate command execution succeeded
_RCE_SIGNATURES: dict[str, list[str]] = {
    "os_identity": [
        r"uid=\d+\(\w+\)\s+gid=\d+",       # Linux id output
        r"(nt authority|system|administrator)", # Windows whoami
    ],
    "system_info": [
        r"Linux\s+\S+\s+\d+\.\d+",           # Linux uname
        r"Windows\s+(NT|Server|\d+)",          # Windows ver
        r"Darwin\s+\d+\.\d+",                 # macOS
    ],
    "time_based": [
        r"real\s+\d+m[\d.]+s",                # time command output
    ],
    "dns_oob": [
        r"(burpcollaborator|oastify|interact\.sh|canarytokens)", # OOB callbacks
    ],
}


def validate_rce(
    output: str,
    payload: str = "",
    expected_output: str = "",
    baseline_body: str = "",
    response_time_ms: float = 0,
    baseline_time_ms: float = 0,
) -> EvidenceChain:
    """Validate Remote Code Execution / Command Injection findings.

    Args:
        output: Tool output / HTTP response body
        payload: The injection payload used
        expected_output: Expected output from the injected command (e.g., "root")
        baseline_body: Response body without injection for comparison
        response_time_ms: Response time with payload
        baseline_time_ms: Response time without payload (for time-based detection)
    """
    chain = EvidenceChain()

    # FP check: empty output
    if not output or not output.strip():
        chain = chain.add_fp_check("Empty output — no command execution evidence")
        return chain

    # FP check: error messages that indicate blocked injection
    error_indicators = [
        r"(syntax error|command not found|not recognized|illegal|forbidden)",
        r"(waf|blocked|filtered|denied|rejected)",
        r"(security exception|access denied|permission denied)",
    ]
    for pattern in error_indicators:
        if re.search(pattern, output, re.IGNORECASE):
            chain = chain.add_fp_check(f"Error/block indicator detected: {pattern}")
            return chain

    # FP check: payload reflected literally without execution evidence
    if payload and payload in output:
        has_exec_evidence = False
        for sigs in _RCE_SIGNATURES.values():
            for sig in sigs:
                if re.search(sig, output, re.IGNORECASE):
                    has_exec_evidence = True
                    break
            if has_exec_evidence:
                break
        if not has_exec_evidence:
            chain = chain.add_fp_check("Payload reflected literally without execution evidence")
            return chain

    # Check for expected output (strongest signal)
    if expected_output and expected_output in output:
        chain = chain.add(
            signal=f"Expected command output found: {expected_output[:100]}",
            source="rce_output_match",
            raw_data=output[:500],
            weight=2.0,
        )

    # Check for OS identity signatures
    for sig_type, patterns in _RCE_SIGNATURES.items():
        for pattern in patterns:
            if re.search(pattern, output, re.IGNORECASE):
                chain = chain.add(
                    signal=f"RCE signature matched: {sig_type}",
                    source="rce_signature_analysis",
                    raw_data=_extract_context(output, pattern),
                    weight=1.5 if sig_type in ("os_identity", "dns_oob") else 0.8,
                )
                break  # one match per type

    # Time-based detection
    if response_time_ms > 0 and baseline_time_ms > 0:
        delay = response_time_ms - baseline_time_ms
        if delay > 4500:  # > 4.5s delay (typical sleep(5) injection)
            chain = chain.add(
                signal=f"Time-based delay detected: {delay:.0f}ms (baseline: {baseline_time_ms:.0f}ms)",
                source="rce_time_analysis",
                weight=1.0,
            )

    # Baseline comparison
    if baseline_body and output.strip() != baseline_body.strip():
        if abs(len(output) - len(baseline_body)) > 50:
            chain = chain.add(
                signal="Response differs significantly from baseline",
                source="rce_baseline_comparison",
                weight=0.3,
            )

    return chain


# ---------------------------------------------------------------------------
# validate_xxe — XML External Entity Injection
# ---------------------------------------------------------------------------

_XXE_SIGNATURES: dict[str, list[str]] = {
    "file_content": [
        r"root:.*:0:0:",                       # /etc/passwd
        r"\[boot loader\]",                    # Windows boot.ini
        r"<\?xml version=",                    # XML declaration in nested entity
    ],
    "error_disclosure": [
        r"(SAXParseException|XMLSyntaxError|xml\.parsers)",
        r"(SYSTEM|DOCTYPE|ENTITY).*not allowed",
        r"(external entity|entity reference)",
    ],
    "oob_callback": [
        r"(burpcollaborator|oastify|interact\.sh|canarytokens)",
        r"DNS lookup.*\d{1,3}\.\d{1,3}",
    ],
    "ssrf_via_xxe": [
        r"(169\.254\.169\.254|metadata\.google|metadata\.azure)",
        r"(ami-id|instance-id|compute/metadata)",
    ],
}


def validate_xxe(
    output: str,
    payload: str = "",
    expected_content: str = "",
    baseline_body: str = "",
) -> EvidenceChain:
    """Validate XML External Entity Injection findings.

    Args:
        output: Response body or tool output
        payload: The XXE payload used
        expected_content: Expected file content (e.g., "root:x:0:0")
        baseline_body: Normal response without XXE for comparison
    """
    chain = EvidenceChain()

    # FP check: empty output
    if not output or not output.strip():
        chain = chain.add_fp_check("Empty output — no XXE evidence")
        return chain

    # FP check: XML parsing disabled / entity rejected
    reject_patterns = [
        r"(external entities.*disabled|DTD.*not allowed|DOCTYPE.*disallowed)",
        r"(entity.*rejected|xml.*blocked|feature.*not supported)",
    ]
    for pattern in reject_patterns:
        if re.search(pattern, output, re.IGNORECASE):
            chain = chain.add_fp_check(f"XXE blocked/rejected: {pattern}")
            return chain

    # FP check: generic error page (not XML-specific)
    if re.search(r"(500 internal server error|service unavailable|bad request)", output, re.IGNORECASE):
        if not any(re.search(p, output, re.IGNORECASE) for sigs in _XXE_SIGNATURES.values() for p in sigs):
            chain = chain.add_fp_check("Generic error without XXE-specific content")
            return chain

    # Check for expected content (strongest signal)
    if expected_content and expected_content in output:
        chain = chain.add(
            signal=f"Expected entity content found: {expected_content[:100]}",
            source="xxe_content_match",
            raw_data=output[:500],
            weight=2.0,
        )

    # Check for XXE signatures
    for sig_type, patterns in _XXE_SIGNATURES.items():
        for pattern in patterns:
            if re.search(pattern, output, re.IGNORECASE):
                weight = 1.5 if sig_type in ("file_content", "oob_callback") else 0.8
                chain = chain.add(
                    signal=f"XXE signature: {sig_type}",
                    source="xxe_signature_analysis",
                    raw_data=_extract_context(output, pattern),
                    weight=weight,
                )
                break

    # Baseline comparison
    if baseline_body and output.strip() != baseline_body.strip():
        if abs(len(output) - len(baseline_body)) > 100:
            chain = chain.add(
                signal="Response differs significantly from baseline",
                source="xxe_baseline_comparison",
                weight=0.3,
            )

    return chain


# ---------------------------------------------------------------------------
# validate_csrf — Cross-Site Request Forgery
# ---------------------------------------------------------------------------

def validate_csrf(
    output: str,
    has_csrf_token: bool = False,
    samesite_cookie: str = "",
    content_type: str = "",
    method: str = "POST",
    cors_origin: str = "",
    state_change_confirmed: bool = False,
) -> EvidenceChain:
    """Validate CSRF vulnerability findings.

    Args:
        output: Tool output / response body
        has_csrf_token: Whether a CSRF token is present in the form/request
        samesite_cookie: SameSite cookie attribute value ("strict", "lax", "none", "")
        content_type: Response Content-Type header
        method: HTTP method tested
        cors_origin: CORS Allow-Origin header value
        state_change_confirmed: Whether the action caused a real state change
    """
    chain = EvidenceChain()

    # FP check: CSRF token is present and validated
    if has_csrf_token:
        chain = chain.add_fp_check("CSRF token present — likely validated server-side")
        return chain

    # FP check: SameSite=Strict cookies
    if samesite_cookie.lower() == "strict":
        chain = chain.add_fp_check("SameSite=Strict cookie — cross-origin requests blocked")
        return chain

    # FP check: JSON-only endpoints with proper content-type enforcement
    if "application/json" in content_type.lower() and method == "POST":
        if cors_origin not in ("*", "null"):
            chain = chain.add_fp_check("JSON Content-Type with restrictive CORS — CSRF unlikely")
            return chain

    # Missing CSRF token is the primary signal
    if not has_csrf_token:
        chain = chain.add(
            signal="No CSRF token in request/form",
            source="csrf_token_check",
            weight=0.8,
        )

    # SameSite=None or missing
    if not samesite_cookie or samesite_cookie.lower() == "none":
        chain = chain.add(
            signal=f"SameSite cookie not set or set to None: '{samesite_cookie}'",
            source="csrf_cookie_analysis",
            raw_data=f"SameSite={samesite_cookie}",
            weight=0.5,
        )

    # Permissive CORS increases exploitability
    if cors_origin in ("*", "null"):
        chain = chain.add(
            signal=f"Permissive CORS origin: {cors_origin}",
            source="csrf_cors_check",
            weight=0.4,
        )

    # State change confirmed (strongest signal)
    if state_change_confirmed:
        chain = chain.add(
            signal="State-changing action confirmed without CSRF protection",
            source="csrf_state_change",
            raw_data=output[:500] if output else "",
            weight=1.5,
        )

    # SameSite=Lax reduces risk for non-GET requests
    if samesite_cookie.lower() == "lax" and method != "GET":
        chain = chain.add(
            signal="SameSite=Lax mitigates top-level POST — but bypasses exist",
            source="csrf_samesite_analysis",
            weight=-0.3,  # reduce weight
        )

    return chain


# ---------------------------------------------------------------------------
# validate_open_redirect — Open Redirect
# ---------------------------------------------------------------------------

_REDIRECT_SIGNATURES: dict[str, list[str]] = {
    "redirect_header": [
        r"Location:\s*https?://(?:evil|attacker|external)",
        r"Location:\s*//",
    ],
    "javascript_redirect": [
        r"window\.location\s*=\s*['\"]https?://",
        r"document\.location\s*=",
        r"window\.open\s*\(",
    ],
    "meta_redirect": [
        r"<meta\s+http-equiv=['\"]refresh['\"].*url=https?://",
    ],
}


def validate_open_redirect(
    output: str,
    redirect_url: str = "",
    final_url: str = "",
    status_code: int = 0,
    baseline_redirect: str = "",
) -> EvidenceChain:
    """Validate Open Redirect findings.

    Args:
        output: Response body/headers
        redirect_url: The injected redirect URL
        final_url: The URL the browser would follow to
        status_code: HTTP status code (301, 302, 303, 307, 308)
        baseline_redirect: Normal redirect destination without injection
    """
    chain = EvidenceChain()

    # FP check: empty output
    if not output and not final_url:
        chain = chain.add_fp_check("Empty output — no redirect evidence")
        return chain

    # FP check: redirect stays on same domain as target (not as injected URL)
    # An open redirect means the target app redirects to an attacker-controlled domain
    # So we check if final_url goes to a DIFFERENT domain than the target app
    if final_url and redirect_url:
        from urllib.parse import urlparse
        try:
            final_domain = urlparse(final_url).netloc
            injected_domain = urlparse(redirect_url).netloc
            # If the final URL did NOT go to the injected domain, it's not an open redirect
            if final_domain and injected_domain and final_domain != injected_domain:
                chain = chain.add_fp_check("Redirect did not follow to injected domain — not an open redirect")
                return chain
        except Exception:
            pass

    # FP check: redirect to login/error page (common false positive)
    if final_url:
        safe_indicators = ["login", "error", "404", "denied", "forbidden"]
        if any(ind in final_url.lower() for ind in safe_indicators):
            chain = chain.add_fp_check("Redirect to login/error page — likely safe handler")
            return chain

    # FP check: not a redirect status code
    if status_code and status_code not in (301, 302, 303, 307, 308):
        if not any(re.search(p, output, re.IGNORECASE) for sigs in _REDIRECT_SIGNATURES.values() for p in sigs):
            chain = chain.add_fp_check(f"Status code {status_code} is not a redirect")
            return chain

    # HTTP redirect header match
    if status_code in (301, 302, 303, 307, 308) and redirect_url:
        if redirect_url in output:
            chain = chain.add(
                signal=f"HTTP {status_code} redirect to attacker-controlled URL",
                source="redirect_header_analysis",
                raw_data=output[:500],
                weight=1.5,
            )

    # Final URL matches injected destination
    if final_url and redirect_url and redirect_url in final_url:
        chain = chain.add(
            signal=f"Browser followed redirect to injected URL: {final_url[:200]}",
            source="redirect_follow_analysis",
            raw_data=final_url,
            weight=2.0,
        )

    # Check for redirect signatures in body
    for sig_type, patterns in _REDIRECT_SIGNATURES.items():
        for pattern in patterns:
            if re.search(pattern, output, re.IGNORECASE):
                chain = chain.add(
                    signal=f"Redirect signature: {sig_type}",
                    source="redirect_signature_analysis",
                    raw_data=_extract_context(output, pattern),
                    weight=0.8,
                )
                break

    # Baseline comparison
    if baseline_redirect and final_url and baseline_redirect != final_url:
        chain = chain.add(
            signal=f"Redirect destination changed from baseline: {baseline_redirect[:100]} → {final_url[:100]}",
            source="redirect_baseline_comparison",
            weight=0.5,
        )

    return chain
