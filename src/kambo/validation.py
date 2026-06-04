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

from kambo.canary import is_orthogonal_marker, make_arithmetic_canary
from kambo.models import Confidence, EvidenceChain


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


def cap_single_response_reflexive(
    chain: EvidenceChain,
    klass: str,
    *,
    has_differential: bool,
    oob_hit: bool = False,
) -> EvidenceChain:
    """Doctrine I1 — "causalidade ou nada".

    A reflexive finding (sqli/xss/ssti/ssrf/rce/xxe/deserialization/etc.) cannot
    reach CONFIRMED from a single response. Cap at FIRM unless one of two proofs
    of causality is present:

    * a baseline **differential** — the marker is present in the payload response
      and absent from a structurally-similar control, or
    * a correlated **OOB hit** (P3) for blind classes.

    No-op when the chain has no positive weight, or when a differential / OOB hit
    is already established.
    """
    if chain.total_weight > 0 and not has_differential and not oob_hit:
        return chain.cap(
            Confidence.FIRM,
            f"Single-response {klass} evidence with no baseline differential or "
            "correlated OOB hit — causality unproven (I1); re-test with a control",
        )
    return chain


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

_SPA_FRAMEWORK_MARKERS = [
    "__NEXT_DATA__",          # Next.js
    "__NUXT__",               # Nuxt.js
    "ng-app",                 # Angular
    "data-reactroot",         # React
    'id="__next"',            # Next.js root div
    'id="app"',               # Vue.js
    "window.__remixContext",  # Remix
]

_WAF_SIGNATURES = [
    "cloudflare",
    "akamai",
    "imperva",
    "incapsula",
    "sucuri",
    "aws-waf",
    "mod_security",
    "wordfence",
]

_CSP_NONCE_HASH_RE = re.compile(
    r"script-src[^;]*(?:nonce-|sha256-|sha384-|sha512-)", re.IGNORECASE
)


def validate_xss(
    raw_output: str,
    payload: str,
    parameter: str,
    reflected_context: str = "",
    response_headers: str = "",
) -> EvidenceChain:
    """Validate XSS based on reflection analysis.

    A reflection alone is not XSS. We need:
    1. Payload reflected in response (weight 0.3)
    2. Payload is in an executable context — not inside an attribute or comment (weight 0.7)
    3. No output encoding detected (weight 0.5)
    4. WAF not blocking execution (downgrade if WAF present)
    5. SPA framework not auto-escaping (warn if SPA detected)
    """
    chain = EvidenceChain()

    # Detect WAF from response headers or body
    headers_and_body = (response_headers + raw_output).lower()
    waf_detected = [w for w in _WAF_SIGNATURES if w in headers_and_body]
    if waf_detected:
        chain = chain.add_fp_check(
            f"WAF detected ({', '.join(waf_detected)}) — payload may be blocked"
            " in browser even if reflected in curl response"
        )
        # §3 WAF gate: confirmation here is curl-only (non-browser). A WAF can
        # block in-browser while letting the raw byte through to curl, and the
        # app may still sanitize on render. Cap at FIRM and demand a browser
        # verification before this can be treated as exploitable.
        chain = chain.cap(
            Confidence.FIRM,
            f"WAF present ({', '.join(waf_detected)}) and confirmation is "
            "curl-only — browser execution unproven",
        )
        chain = chain.add_flag("needs-browser-verification")

    # I5 gate: CSP with nonce/hash blocks injected inline scripts even if
    # the payload reflects unencoded. Cap at TENTATIVE — the XSS payload
    # cannot execute without a valid nonce.
    csp_header = response_headers.lower() if response_headers else ""
    csp_nonce_detected = bool(_CSP_NONCE_HASH_RE.search(csp_header))
    if csp_nonce_detected:
        chain = chain.add_fp_check(
            "CSP script-src with nonce/hash detected — inline script "
            "injection blocked by browser even if payload reflects"
        )
        chain = chain.cap(
            Confidence.TENTATIVE,
            "CSP nonce/hash in script-src prevents inline execution — "
            "reflected XSS not exploitable without nonce bypass (I5)",
        )

    # Detect SPA frameworks — they auto-escape by default
    spa_detected = [m for m in _SPA_FRAMEWORK_MARKERS if m in raw_output]
    if spa_detected:
        chain = chain.add_fp_check(
            f"SPA framework detected ({spa_detected[0]}) — modern frameworks"
            " auto-escape output. Verify execution in browser."
        )

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

    # Downgrade weight when WAF or SPA detected — curl reflection doesn't
    # prove browser exploitation behind WAF/auto-escape.
    encoding_weight = 0.2 if (waf_detected or spa_detected) else 0.5
    chain = chain.add(
        signal="Payload reflected without encoding",
        source="encoding_check",
        weight=encoding_weight,
    )

    # Check context: is it inside a tag, attribute, script block, or comment?
    payload_idx = raw_output.find(payload)
    if payload_idx < 0:
        return chain  # Payload was encoded after earlier check passed
    before_payload = raw_output[:payload_idx]
    window = before_payload[max(0, len(before_payload) - 500):]

    # Count unclosed <script> tags — a closed tag means the payload is NOT inside it
    script_opens = len(re.findall(r"<script\b", window, re.IGNORECASE))
    script_closes = len(re.findall(r"</script\s*>", window, re.IGNORECASE))
    in_script = script_opens > script_closes

    # Distinguish executable JS from a non-executable data block. A reflection
    # inside <script type="application/json"> (or ld+json, text/template, etc.)
    # is NOT executable — doctrine I4 / anti-pattern #3.
    in_data_block = False
    if in_script:
        last_script_open = re.search(
            r"<script\b([^>]*)>(?![\s\S]*<script\b)", window, re.IGNORECASE
        )
        if last_script_open:
            attrs = last_script_open.group(1).lower()
            type_match = re.search(r'type\s*=\s*["\']?([^"\'\s>]+)', attrs)
            if type_match and type_match.group(1) not in (
                "text/javascript",
                "application/javascript",
                "module",
            ):
                in_data_block = True

    # Comment detection: check if most recent <!-- is not closed by -->
    comment_window = before_payload[max(0, len(before_payload) - 200):]
    last_open = comment_window.rfind("<!--")
    last_close = comment_window.rfind("-->")
    in_comment = last_open > last_close

    context_weight = 0.5
    if waf_detected or spa_detected:
        context_weight = 0.2

    if in_data_block:
        # I4 gate: reflection in a non-executable data block is not a vuln.
        chain = chain.add_fp_check(
            "Reflection inside a non-executable <script> data block "
            "(type != javascript) — not executable"
        )
        chain = chain.cap(
            Confidence.TENTATIVE,
            "Reflection in non-executable context (script data block) — not a "
            "vuln until reflected in an executable context (I4)",
        )
    elif in_script:
        script_weight = 0.7
        if waf_detected or spa_detected:
            script_weight = 0.4
        chain = chain.add(
            signal="Reflection occurs inside <script> block — high XSS probability",
            source="context_analysis",
            weight=script_weight,
        )
    elif in_comment:
        # I4 gate: an HTML comment is not an executable context.
        chain = chain.add_fp_check("Reflection is inside HTML comment — not exploitable")
        chain = chain.cap(
            Confidence.TENTATIVE,
            "Reflection in non-executable context (HTML comment) — not a vuln (I4)",
        )
    else:
        chain = chain.add(
            signal="Reflection in HTML body context",
            source="context_analysis",
            weight=context_weight,
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

    # Same-org subdomain filter: if the reflected origin is a subdomain of the
    # target's root domain, the organisation controls all subdomains and this
    # is almost certainly by-design trust, not a misconfiguration.
    target_root = ".".join(target_domain.rsplit(".", 2)[-2:]).lower()
    origin_host = origin_tested.lower().replace("https://", "").replace("http://", "")
    if origin_host.endswith(f".{target_root}") and origin_host != target_root:
        chain = chain.add_fp_check(
            f"Reflected origin {origin_tested} is a subdomain of target root "
            f"({target_root}) — same-org trust, likely by-design"
        )
        chain = chain.cap(
            Confidence.TENTATIVE,
            f"Same-org subdomain reflection ({target_root}) — organisation "
            "controls all subdomains, not exploitable by external attacker",
        )
        return chain

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
    "aws": ["ami-id", "instance-id", "iam/", "security-credentials", "meta-data/"],
    "gcp": ["computeMetadata", "project-id", "service-accounts"],
    "azure": ["vmId", "subscriptionId", "azureenvironment"],
}

# Short tokens that cause FP via substring match (e.g. "iam" in "enviamos").
# These require word-boundary matching instead of simple `in`.
_SHORT_METADATA_TOKENS = frozenset({"iam", "compute"})


def validate_ssrf(
    payload: str,
    status_code: str,
    response_body: str,
    oob_hit: bool = False,
    oob_evidence: str = "",
) -> EvidenceChain:
    """Validate SSRF with response content analysis.

    SSRF is a *blind class* (doctrine I3): the only evidence that survives a
    target which returns a generic 200 for everything is an out-of-band hit on a
    controlled canary host. Keyword-matching the response body is explicitly
    forbidden as confirmation — ``iam`` matched ``enviamos``/``Diamond`` is the
    canonical field FP (anti-pattern #2).

    Therefore, without ``oob_hit`` the chain is capped at TENTATIVE no matter how
    many body signatures appear. An OOB hit lifts the cap and contributes the
    decisive signal.

    Args:
        payload: The SSRF payload sent (should point at a canary host).
        status_code: HTTP status of the probe response.
        response_body: Probe response body (used only for weak corroboration).
        oob_hit: True iff a DNS/HTTP interaction was received on the canary host
            and correlated to this request (P3 / OAST).
        oob_evidence: Raw OOB interaction record proving the hit.
    """
    chain = EvidenceChain()
    body_lower = response_body.lower()

    if oob_hit:
        chain = chain.add(
            signal="Out-of-band interaction received on canary host — server fetched attacker URL",
            source="oast_correlation",
            raw_data=(oob_evidence or payload)[:1000],
            weight=2.0,
        )
        chain = chain.add_fp_check("OOB hit correlated to request — keyword body match not relied upon (I3)")
    else:
        # I3 gate: blind class with no OOB hit can never exceed TENTATIVE.
        chain = chain.cap(
            Confidence.TENTATIVE,
            "No out-of-band hit on a canary host — SSRF is a blind class and "
            "response-body keywords are forbidden as confirmation (I3)",
        )

    # FP check: common non-SSRF error responses
    if re.search(r"(invalid url|bad request|url not allowed|blocked)", body_lower):
        chain = chain.add_fp_check("Server rejected the URL — input validation in place")

    # Status code check (weak signal alone) — 307/308 are permanent/temporary redirects
    # that can indicate the server is fetching and forwarding the internal resource
    if status_code in ("200", "301", "302", "307", "308"):
        redirect_note = " (redirect — may indicate server-side fetch)" if status_code in ("301", "302", "307", "308") else ""
        chain = chain.add(
            signal=f"HTTP {status_code} returned for internal payload: {payload[:100]}{redirect_note}",
            source="ssrf_probe",
            weight=0.2,
        )
    else:
        chain = chain.add_fp_check(f"Non-success status {status_code} — likely blocked")
        return chain

    # Check for cloud metadata content.
    # Use word-boundary matching for short tokens to avoid substring FPs
    # (e.g. "iam" matching "enviamos" in Portuguese pages).
    # Require ≥2 distinct signatures to reach high weight.
    for provider, signatures in _CLOUD_METADATA_SIGNATURES.items():
        matches: list[str] = []
        for sig in signatures:
            sig_lower = sig.lower()
            if sig_lower in _SHORT_METADATA_TOKENS:
                if re.search(rf"\b{re.escape(sig_lower)}\b", body_lower):
                    matches.append(sig)
            elif sig_lower in body_lower:
                matches.append(sig)
        if matches:
            weight = 1.5 if len(matches) >= 2 else 0.5
            chain = chain.add(
                signal=f"Cloud metadata ({provider}) content detected: {', '.join(matches)}",
                source="ssrf_content_analysis",
                raw_data=response_body[:1000],
                weight=weight,
            )
            if len(matches) < 2:
                chain = chain.add_fp_check(
                    f"Only {len(matches)} metadata signature(s) — weak signal, may be page content"
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

    # Empty or error-like response is likely a false positive — unless an OOB
    # hit already proved the fetch (a blind SSRF often returns no body at all).
    if len(response_body.strip()) < 10 and not oob_hit:
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
        # Build raw_data from first differing response for audit trail
        _first_diff = next(
            (r for _, r in test_responses if r.status == 200 and r.body_hash != baseline_response.body_hash),
            None,
        )
        _diff_preview = _first_diff.body[:500] if _first_diff else ""

        chain = chain.add(
            signal=f"{accessible_count} resources accessible with {len(unique_hashes)} unique responses",
            source="idor_analysis",
            raw_data=_diff_preview,
            weight=0.6,
        )

        # Strong signal: content differs per ID
        if len(unique_hashes) >= min(3, accessible_count):
            _hashes_sample = ", ".join(list(unique_hashes)[:5])
            chain = chain.add(
                signal="Response content varies per resource ID — confirms different user data returned",
                source="idor_diffing",
                raw_data=f"unique_hashes=[{_hashes_sample}]",
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


def _non_claimable_resource(cname: str) -> str | None:
    """Return the resource type if a dangling CNAME target is **non-claimable**.

    Some cloud resources publish DNS names that are account-bound and contain an
    auto-generated identifier (e.g. an AWS ELB/NLB, RDS, or ElastiCache endpoint).
    Even when such a name stops resolving, an attacker **cannot** re-register it —
    you can't create an ELB with someone else's generated hostname. A dangling
    CNAME to one of these is a DNS-hygiene issue (orphaned record), not a
    registerable subdomain takeover, so it must not accrue takeover confidence.

    Returns ``None`` for claimable targets (S3 buckets, CloudFront distributions,
    SaaS sites, …) so the normal takeover signals still apply.
    """
    c = cname.lower().rstrip(".")
    # Account-bound names that do not live under amazonaws.com:
    if ".lambda-url." in c and ".on.aws" in c:
        return "AWS Lambda Function URL"
    if "amazonaws.com" not in c:
        return None
    if ".elb." in c:  # covers both *.elb.<region>.amazonaws.com and *.<region>.elb.amazonaws.com
        return "AWS ELB/NLB"
    if ".execute-api." in c:
        return "AWS API Gateway endpoint"
    if ".rds.amazonaws.com" in c:
        return "AWS RDS endpoint"
    if ".cache.amazonaws.com" in c:
        return "AWS ElastiCache endpoint"
    if ".es.amazonaws.com" in c or ".aoss.amazonaws.com" in c:
        return "AWS OpenSearch endpoint"
    if ".compute.amazonaws.com" in c or ".compute-1.amazonaws.com" in c:
        return "AWS EC2 instance"
    if ".vpce.amazonaws.com" in c:
        return "AWS VPC endpoint"
    return None


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

    # FP check: a dangling CNAME to a non-claimable target (AWS ELB/NLB, RDS, …)
    # is a DNS-hygiene issue, not a registerable takeover. Record the orphaned
    # record but accrue no takeover weight, unless a real service fingerprint is
    # present in the body (defensive — keeps any genuine signal).
    non_claimable = _non_claimable_resource(cname)
    if non_claimable:
        body = response_body.lower()
        has_fingerprint = any(
            fp in body for fps in _TAKEOVER_FINGERPRINTS.values() for fp in fps
        )
        if not has_fingerprint:
            return chain.add_fp_check(
                f"Dangling CNAME: {cname} does not resolve — target is a "
                f"non-claimable {non_claimable} (account-bound, auto-generated "
                "DNS name) — DNS-hygiene issue, not a registerable subdomain takeover"
            )

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
    oob_hit: bool = False,
    oob_evidence: str = "",
) -> EvidenceChain:
    """Validate Remote Code Execution / Command Injection findings.

    Causality (doctrine I1/I3): direct command output reaches CONFIRMED only with
    a baseline differential or a correlated OOB hit; otherwise it is capped at
    FIRM. Blind RCE confirmation comes from ``oob_hit`` — a "burpcollaborator"
    string appearing in the *response body* is reflection, not a received
    callback, and must not confirm (I3).

    Args:
        output: Tool output / HTTP response body
        payload: The injection payload used
        expected_output: Expected output from the injected command (e.g., a canary)
        baseline_body: Response body without injection for comparison
        response_time_ms: Response time with payload
        baseline_time_ms: Response time without payload (for time-based detection)
        oob_hit: True iff a DNS/HTTP interaction was received on the canary host
            and correlated to this request (P3 / OAST).
        oob_evidence: Raw OOB interaction record proving the hit.
    """
    chain = EvidenceChain()
    has_differential = False

    # FP check: empty output (unless a blind OOB hit already proved execution)
    if (not output or not output.strip()) and not oob_hit:
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

    # FP check: payload reflected literally without execution evidence.
    # dns_oob is a body keyword (reflection), not execution evidence — exclude it
    # so a reflected payload that merely echoes an OOB token is still a pure FP.
    if payload and payload in output and not oob_hit:
        has_exec_evidence = any(
            re.search(sig, output, re.IGNORECASE)
            for sig_type, sigs in _RCE_SIGNATURES.items()
            if sig_type != "dns_oob"
            for sig in sigs
        )
        if not has_exec_evidence:
            chain = chain.add_fp_check("Payload reflected literally without execution evidence")
            return chain

    # Correlated OOB hit — the decisive proof for blind RCE (P3/I3).
    if oob_hit:
        chain = chain.add(
            signal="Correlated out-of-band interaction on canary host — code executed",
            source="oast_correlation",
            raw_data=(oob_evidence or payload)[:1000],
            weight=2.0,
        )

    # Check for expected output (strongest direct signal)
    if expected_output and expected_output in output:
        chain = chain.add(
            signal=f"Expected command output found: {expected_output[:100]}",
            source="rce_output_match",
            raw_data=output[:500],
            weight=2.0,
        )
        # A differential exists when the canary output is absent from a baseline.
        if baseline_body and expected_output not in baseline_body:
            has_differential = True

    # Check for OS identity / system signatures.
    for sig_type, patterns in _RCE_SIGNATURES.items():
        # I3: an OOB token in the *body* is reflection, not a received callback —
        # it cannot confirm. When a real oob_hit is already established, skip it
        # entirely (no contradictory annotation); otherwise record it as a weak,
        # non-confirming signal.
        if sig_type == "dns_oob":
            if oob_hit:
                continue
            if any(re.search(p, output, re.IGNORECASE) for p in patterns):
                chain = chain.add(
                    signal="OOB token echoed in response body — not a correlated hit",
                    source="rce_signature_analysis",
                    raw_data=_extract_context(output, patterns[0]),
                    weight=0.3,
                )
                chain = chain.add_fp_check(
                    "OOB token in body is reflection, not a received callback — "
                    "poll the collaborator and pass oob_hit=True to confirm (I3)"
                )
            continue
        for pattern in patterns:
            if re.search(pattern, output, re.IGNORECASE):
                chain = chain.add(
                    signal=f"RCE signature matched: {sig_type}",
                    source="rce_signature_analysis",
                    raw_data=_extract_context(output, pattern),
                    weight=1.5 if sig_type == "os_identity" else 0.8,
                )
                break  # one match per type

    # Time-based detection — inherently differential (payload time vs baseline).
    if response_time_ms > 0 and baseline_time_ms > 0:
        delay = response_time_ms - baseline_time_ms
        if delay > 4500:  # > 4.5s delay (typical sleep(5) injection)
            chain = chain.add(
                signal=f"Time-based delay detected: {delay:.0f}ms (baseline: {baseline_time_ms:.0f}ms)",
                source="rce_time_analysis",
                weight=1.0,
            )
            has_differential = True

    # Baseline comparison
    if baseline_body and output.strip() != baseline_body.strip():
        if abs(len(output) - len(baseline_body)) > 50:
            chain = chain.add(
                signal="Response differs significantly from baseline",
                source="rce_baseline_comparison",
                weight=0.3,
            )

    return cap_single_response_reflexive(
        chain, "RCE", has_differential=has_differential, oob_hit=oob_hit
    )


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
    oob_hit: bool = False,
    oob_evidence: str = "",
) -> EvidenceChain:
    """Validate XML External Entity Injection findings.

    Causality (doctrine I1/I3): in-band file exfiltration reaches CONFIRMED only
    with a baseline differential; blind XXE confirmation comes from a correlated
    ``oob_hit``. An OOB token echoed in the response body is reflection, not a
    received callback, and must not confirm (I3).

    Args:
        output: Response body or tool output
        payload: The XXE payload used
        expected_content: Expected file content (e.g., a canary or "root:x:0:0")
        baseline_body: Normal response without XXE for comparison
        oob_hit: True iff an OOB interaction was received and correlated (P3).
        oob_evidence: Raw OOB interaction record proving the hit.
    """
    chain = EvidenceChain()
    has_differential = False

    # FP check: empty output (unless a blind OOB hit already proved resolution)
    if (not output or not output.strip()) and not oob_hit:
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

    # Correlated OOB hit — the decisive proof for blind XXE (P3/I3).
    if oob_hit:
        chain = chain.add(
            signal="Correlated out-of-band interaction on canary host — entity resolved externally",
            source="oast_correlation",
            raw_data=(oob_evidence or payload)[:1000],
            weight=2.0,
        )

    # Check for expected content (strongest in-band signal)
    if expected_content and expected_content in output:
        chain = chain.add(
            signal=f"Expected entity content found: {expected_content[:100]}",
            source="xxe_content_match",
            raw_data=output[:500],
            weight=2.0,
        )
        if baseline_body and expected_content not in baseline_body:
            has_differential = True

    # Check for XXE signatures
    for sig_type, patterns in _XXE_SIGNATURES.items():
        # I3: an OOB token in the body is reflection, not a received callback —
        # only a real oob_hit confirms. Skip entirely when oob_hit is set (no
        # contradictory annotation); otherwise record it as a non-confirming signal.
        if sig_type == "oob_callback":
            if oob_hit:
                continue
            if any(re.search(p, output, re.IGNORECASE) for p in patterns):
                chain = chain.add(
                    signal="OOB token echoed in response body — not a correlated hit",
                    source="xxe_signature_analysis",
                    raw_data=_extract_context(output, patterns[0]),
                    weight=0.3,
                )
                chain = chain.add_fp_check(
                    "OOB token in body is reflection, not a received callback — "
                    "poll the collaborator and pass oob_hit=True to confirm (I3)"
                )
            continue
        for pattern in patterns:
            if re.search(pattern, output, re.IGNORECASE):
                weight = 1.5 if sig_type == "file_content" else 0.8
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

    return cap_single_response_reflexive(
        chain, "XXE", has_differential=has_differential, oob_hit=oob_hit
    )


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


# ---------------------------------------------------------------------------
# validate_ssti — Server-Side Template Injection
# ---------------------------------------------------------------------------

# Default orthogonal canary (doctrine I2/P1): improbable arithmetic whose product
# carries many distinct digits and cannot appear as organic page content. The old
# default `{{7*7}}` → `49` is the doctrine's headline anti-pattern (#8) — `49`
# occurs constantly in country IDs, prices, SVG paths.
_SSTI_CANARY = make_arithmetic_canary()
_SSTI_DEFAULT_PAYLOAD = "{{" + _SSTI_CANARY.expression + "}}"  # {{31337*1337}}
_SSTI_DEFAULT_RENDER = _SSTI_CANARY.expected_render            # 41897569

_SSTI_CONFIRMED_PATTERNS: list[str] = [
    r"<class 'str'>",               # Python object exposure
    r"warning.*template.*syntax",   # Twig/Smarty error
    r"undefined.*variable.*template",  # Smarty error
    r"org\.springframework",         # Spring EL
]

_SSTI_FP_PATTERNS: list[str] = [
    r"\{\{7\*7\}\}",   # payload reflected literally (not rendered)
    r"expression.*invalid",
    r"syntax.*error.*template",   # template engine rejected it (not vulnerable)
]


def validate_ssti(
    output: str,
    payload: str = _SSTI_DEFAULT_PAYLOAD,
    expected_render: str = _SSTI_DEFAULT_RENDER,
    baseline_body: str = "",
    error_based: bool = False,
) -> EvidenceChain:
    """Validate Server-Side Template Injection (SSTI).

    The gold standard (doctrine P1/I2): send an *orthogonal* arithmetic canary
    — ``{{31337*1337}}`` → ``41897569`` — and check the response renders it. The
    product carries many distinct digits and cannot occur as organic page
    content, unlike the banned ``{{7*7}}`` → ``49``.

    Confidence ceilings (doctrine I1 — "causalidade ou nada"):
    * Render confirmed against a baseline differential (present in payload
      response, absent in baseline) → CONFIRMED is permitted.
    * Render confirmed from a single response with no baseline → capped at FIRM:
      one response can't prove causality.
    * Non-orthogonal ``expected_render`` (small number, dictionary word) → capped
      at TENTATIVE: the marker itself is unsound (I2).

    Args:
        output: Response body
        payload: Template injection payload used
        expected_render: What the payload should render to (orthogonal marker)
        baseline_body: Normal response without payload for comparison
        error_based: Whether to detect error-based SSTI (verbose errors)
    """
    chain = EvidenceChain()

    if not output or not output.strip():
        return chain.add_fp_check("Empty output — no SSTI evidence")

    # I2 gate: an unsound marker can never confirm. Record it up front so the
    # ceiling applies no matter which signals fire below.
    marker_is_orthogonal = is_orthogonal_marker(expected_render)
    if expected_render and not marker_is_orthogonal:
        chain = chain.cap(
            Confidence.TENTATIVE,
            f"Non-orthogonal SSTI marker {expected_render!r} — occurs naturally in "
            "content (I2); use improbable arithmetic like {{31337*1337}}",
        )

    # FP check: payload reflected literally (not rendered)
    _render_pattern = rf"(?<!\d){re.escape(expected_render)}(?!\d)" if expected_render else ""
    if payload and payload in output:
        # If the payload appears as-is AND expected_render doesn't appear, it's a reflection, not render
        if _render_pattern and not re.search(_render_pattern, output):
            return chain.add_fp_check("Payload reflected literally — template not rendered")

    # FP check: template engine explicitly rejected the payload
    for pattern in _SSTI_FP_PATTERNS[1:]:  # skip literal reflection check (already handled)
        if re.search(pattern, output, re.IGNORECASE):
            return chain.add_fp_check(f"Template engine rejected payload: {pattern}")

    # Primary signal: expected render found.
    # CRITICAL: if the expected render already exists in the baseline response,
    # it's natural page content (e.g. "49" in product IDs, prices, SVG paths),
    # NOT evidence of template rendering.
    # Use word-boundary regex to avoid matching "149", "492", etc.
    if expected_render and re.search(_render_pattern, output):
        if baseline_body and re.search(_render_pattern, baseline_body):
            chain = chain.add_fp_check(
                f"Expected render {expected_render!r} already present in baseline"
                " — likely natural page content, not template evaluation"
            )
            return chain
        chain = chain.add(
            signal=f"Template expression rendered: {payload!r} → {expected_render!r}",
            source="ssti_render_analysis",
            raw_data=_extract_context(output, re.escape(expected_render)),
            weight=2.0,
        )

    # Secondary signal: Python object exposure (Jinja2/Tornado/Mako)
    python_exposure_patterns = [
        (r"<class '(str|int|dict|list|object)'", "Python class exposed in response"),
        (r"__class__.*__mro__", "Python MRO attribute exposed"),
        (r"<built-in", "Python built-in function exposed"),
    ]
    for pattern, description in python_exposure_patterns:
        if re.search(pattern, output, re.IGNORECASE):
            chain = chain.add(
                signal=description,
                source="ssti_python_exposure",
                raw_data=_extract_context(output, pattern),
                weight=1.5,
            )
            break

    # Error-based SSTI signals
    if error_based:
        for pattern in _SSTI_CONFIRMED_PATTERNS[1:]:  # error patterns (skip <class 'str'>)
            if re.search(pattern, output, re.IGNORECASE):
                chain = chain.add(
                    signal=f"Template engine error exposed: {pattern}",
                    source="ssti_error_analysis",
                    raw_data=_extract_context(output, pattern),
                    weight=0.8,
                )
                break

    # Baseline comparison: if response differs and expected render present
    if baseline_body and output.strip() != baseline_body.strip():
        if re.search(_render_pattern, output) and not re.search(_render_pattern, baseline_body):
            chain = chain.add(
                signal="Response differs from baseline and contains rendered payload",
                source="ssti_baseline_comparison",
                weight=0.5,
            )

    # I1 gate (covers ALL signal paths, not just the render branch): SSTI is a
    # reflexive class. The only differential proof we accept is the orthogonal
    # render present in the payload response and absent from a baseline. Any
    # other single-response evidence (Python-object exposure, error-based
    # exceptions, or a render with no baseline) proves the marker appeared, not
    # that the payload *caused* it — so it is capped at FIRM. Without this,
    # exposure(1.5) + error(0.8) = 2.3 would reach CONFIRMED from one response.
    render_in_output = bool(_render_pattern) and bool(re.search(_render_pattern, output))
    has_differential = (
        render_in_output
        and bool(baseline_body)
        and not re.search(_render_pattern, baseline_body)
    )
    if chain.total_weight > 0 and not has_differential:
        chain = chain.cap(
            Confidence.FIRM,
            "Single-response SSTI evidence with no baseline differential — "
            "causality unproven (I1); re-test with a benign control request",
        )

    return chain


# ---------------------------------------------------------------------------
# validate_prototype_pollution — Prototype Pollution (JavaScript)
# ---------------------------------------------------------------------------

def validate_prototype_pollution(
    output: str,
    payload: str = "__proto__",
    injected_value: str = "",
    baseline_body: str = "",
) -> EvidenceChain:
    """Validate Prototype Pollution findings.

    Checks if injected properties propagate to response fields or cause
    observable behavior changes.

    Args:
        output: Response body
        payload: Injection payload used (e.g., __proto__[polluted]=1)
        injected_value: The value that was injected (for confirmation check)
        baseline_body: Normal response for comparison
    """
    chain = EvidenceChain()
    has_differential = False

    if not output or not output.strip():
        return chain.add_fp_check("Empty output — no prototype pollution evidence")

    # FP check: JSON parse error (server rejected malformed input)
    if re.search(r"(invalid json|json parse|unexpected token|malformed)", output, re.IGNORECASE):
        return chain.add_fp_check("Server rejected input as malformed JSON — not polluted")

    # FP check: response identical to baseline — injection caused no observable change
    if baseline_body and output.strip() == baseline_body.strip():
        return chain.add_fp_check(
            "Response identical to baseline — prototype injection caused no observable change"
        )

    # Primary signal: injected value appears in unexpected response field
    if injected_value and injected_value in output:
        # Check it's not just reflected in an error
        if not re.search(r"(error|invalid|rejected|blocked)", output[:200], re.IGNORECASE):
            chain = chain.add(
                signal=f"Injected value '{injected_value[:50]}' found in response",
                source="prototype_pollution_value_check",
                raw_data=_extract_context(output, re.escape(injected_value[:30])),
                weight=1.5,
            )

    # Pollution signals in response
    pollution_signals = [
        (r'"polluted"\s*:', "Polluted key reflected in JSON response"),
        (r'"__proto__"\s*:', "Proto key reflected in JSON response"),
        (r'"constructor"\s*.*"prototype"', "Constructor/prototype exposed in response"),
        (r"Object\.prototype", "Object.prototype referenced in response"),
    ]
    for pattern, description in pollution_signals:
        if re.search(pattern, output, re.IGNORECASE):
            chain = chain.add(
                signal=description,
                source="prototype_pollution_signature",
                raw_data=_extract_context(output, pattern),
                weight=1.0,
            )
            break

    # Baseline comparison — the differential proof of causality.
    if baseline_body and output.strip() != baseline_body.strip():
        if injected_value and injected_value in output and injected_value not in baseline_body:
            chain = chain.add(
                signal="Injected value appears in response but not in baseline",
                source="prototype_pollution_baseline",
                weight=0.5,
            )
            has_differential = True

    return cap_single_response_reflexive(
        chain, "prototype pollution", has_differential=has_differential
    )


# ---------------------------------------------------------------------------
# validate_deserialization — Insecure Deserialization
# ---------------------------------------------------------------------------

_DESER_FP_PATTERNS: list[str] = [
    r"(deserialization.*not.*supported|serializ.*disabled)",
    r"(invalid.*serial.*format|corrupt.*object)",
]

_DESER_CONFIRMED_SIGNALS: list[tuple[str, str, float]] = [
    (r"uid=\d+\(", "OS command output (RCE via deserialization)", 2.0),
    (r"java\.lang\.Runtime", "Java Runtime class exposed — RCE possible", 1.5),
    (r"org\.apache\.commons\.collections", "Apache Commons gadget chain detected", 1.5),
    (r"ysoserial", "ysoserial gadget chain signature", 1.0),
    (r"java\.io\.NotSerializableException", "Java serialization error — endpoint processes Java objects", 0.8),
    (r"php.*unserialize.*error|__wakeup.*called", "PHP deserialization hook triggered", 1.0),
    (r"pickle.*protocol|_reduce_|__reduce__", "Python pickle deserialization signal", 1.5),
]

# OOB token in the body is reflection, not a received callback (I3) — handled
# separately from the confirming signals above.
_DESER_OOB_BODY_PATTERN = r"(dns.*callback|oob.*callback|burpcollaborator|interactsh)"


def validate_deserialization(
    output: str,
    payload_type: str = "java",
    expected_output: str = "",
    response_time_ms: float = 0,
    baseline_time_ms: float = 0,
    oob_hit: bool = False,
    oob_evidence: str = "",
) -> EvidenceChain:
    """Validate Insecure Deserialization findings.

    Detects Java (ysoserial), PHP (unserialize), and Python (pickle)
    deserialization vulnerabilities.

    Causality (doctrine I1/I3): single-response evidence is capped at FIRM unless
    a time-based differential or a correlated ``oob_hit`` proves the gadget ran.
    An OOB token in the response body is reflection, not a received callback (I3).

    Args:
        output: Response body or error output
        payload_type: Type of payload used — java, php, python
        expected_output: Expected command output for RCE-based detection (a canary)
        response_time_ms: Response time with sleep payload (for time-based detection)
        baseline_time_ms: Baseline response time
        oob_hit: True iff an OOB interaction was received and correlated (P3).
        oob_evidence: Raw OOB interaction record proving the hit.
    """
    chain = EvidenceChain()
    has_differential = False

    if not output and response_time_ms == 0 and not oob_hit:
        return chain.add_fp_check("No output and no timing data — cannot assess")

    # FP check: explicitly rejected
    for pattern in _DESER_FP_PATTERNS:
        if re.search(pattern, output, re.IGNORECASE):
            return chain.add_fp_check(f"Deserialization explicitly rejected: {pattern}")

    # Correlated OOB hit — decisive for blind deserialization (P3/I3).
    if oob_hit:
        chain = chain.add(
            signal="Correlated out-of-band interaction on canary host — gadget executed",
            source="oast_correlation",
            raw_data=(oob_evidence or expected_output)[:1000],
            weight=2.0,
        )

    # Primary signal: expected command output (RCE confirmation)
    if expected_output and expected_output in output:
        chain = chain.add(
            signal=f"Expected command output found: {expected_output[:100]}",
            source="deserialization_rce_confirm",
            raw_data=output[:500],
            weight=2.0,
        )

    # Check all confirmed signals
    for pattern, description, weight in _DESER_CONFIRMED_SIGNALS:
        if re.search(pattern, output, re.IGNORECASE):
            chain = chain.add(
                signal=description,
                source="deserialization_signature",
                raw_data=_extract_context(output, pattern),
                weight=weight,
            )
            break  # one strong signal is enough

    # I3: OOB token echoed in the body — reflection only, cannot confirm. Skipped
    # when a real oob_hit is already established (no contradictory annotation).
    if not oob_hit and re.search(_DESER_OOB_BODY_PATTERN, output, re.IGNORECASE):
        chain = chain.add(
            signal="OOB token echoed in response body — not a correlated hit",
            source="deserialization_signature",
            raw_data=_extract_context(output, _DESER_OOB_BODY_PATTERN),
            weight=0.3,
        )
        chain = chain.add_fp_check(
            "OOB token in body is reflection, not a received callback — "
            "poll the collaborator and pass oob_hit=True to confirm (I3)"
        )

    # Time-based detection (sleep payload) — inherently differential.
    if response_time_ms > 0 and baseline_time_ms > 0:
        delay = response_time_ms - baseline_time_ms
        if delay > 5000:  # 5+ second delay
            chain = chain.add(
                signal=f"Time-based delay: {delay:.0f}ms (baseline: {baseline_time_ms:.0f}ms)",
                source="deserialization_time_based",
                weight=1.5 if delay > 8000 else 1.0,
            )
            has_differential = True

    return cap_single_response_reflexive(
        chain, "deserialization", has_differential=has_differential, oob_hit=oob_hit
    )


# ---------------------------------------------------------------------------
# validate_graphql — GraphQL Introspection & Injection
# ---------------------------------------------------------------------------

_GRAPHQL_INTROSPECTION_SIGNATURES: list[str] = [
    r'"__schema"\s*:',                    # introspection response root
    r'"types"\s*:\s*\[',                  # types array under __schema (real GQL responses)
    r'"queryType"\s*:.*"name"',           # schema root types
    r'"mutationType"\s*:',                # mutation support exposed
    r'"directives"\s*:\s*\[',             # directives listing
]

_GRAPHQL_ERROR_SIGNATURES: list[tuple[str, str, float]] = [
    (r'"errors"\s*:.*"extensions"\s*:.*"code"', "GraphQL structured error with code — endpoint confirmed", 0.4),
    # Use \W+ to handle both plain quotes and JSON-escaped \" sequences in raw HTTP bodies
    (r"Cannot query field\W+(\w+)\W+on type", "Field-level error leaks schema info", 0.6),
    (r"Unknown argument\W+(\w+)", "Argument error reveals accepted fields", 0.5),
    (r"Variable.*must not be null", "Null variable error leaks input type", 0.3),
    (r"Did you mean\W+(\w+)", "Suggestion error fully leaks field names", 0.8),
]

_GRAPHQL_INJECTION_SIGNATURES: list[tuple[str, str, float]] = [
    (r"syntax error.*unexpected", "GraphQL syntax error from injected chars", 0.3),
    (r"Expected.*got.*<EOF>", "Incomplete query — injection point confirmed", 0.5),
    (r"(sql|mongo|redis).*error", "Database error via GraphQL injection", 1.2),
    (r"Internal\s+Server\s+Error.*graphql", "Internal error exposed via GraphQL", 0.6),
]


def validate_graphql(
    output: str,
    introspection_response: str = "",
    error_response: str = "",
    injection_response: str = "",
    baseline_body: str = "",
) -> EvidenceChain:
    """Validate GraphQL security issues: introspection enabled, info disclosure, injection.

    Three separate attack vectors:
    1. Introspection enabled — leaks full schema, used for targeted attacks
    2. Error verbosity — field names, types, and suggestions leak from errors
    3. Query injection — injected chars cause parse/DB errors

    Args:
        output: General tool output (combines all responses if not split)
        introspection_response: Response to an __schema introspection query
        error_response: Response to an intentionally malformed query
        injection_response: Response to an injection payload (e.g., ' OR 1=1)
        baseline_body: Normal query response for comparison
    """
    chain = EvidenceChain()

    # Combine all available response data
    all_output = "\n".join(filter(None, [output, introspection_response, error_response, injection_response]))

    if not all_output.strip():
        return chain.add_fp_check("No GraphQL response data — endpoint may not exist")

    # FP check: not a GraphQL endpoint
    if re.search(r"(404 not found|cannot (get|post)|method not allowed)", all_output, re.IGNORECASE):
        if not re.search(r'"data"\s*:|"errors"\s*:', all_output):
            return chain.add_fp_check("No GraphQL response structure — likely not a GraphQL endpoint")

    # FP check: introspection explicitly disabled
    if re.search(r"(introspection.*disabled|introspection.*not.*allowed|GraphQL introspection is not allowed)", all_output, re.IGNORECASE):
        chain = chain.add_fp_check("Introspection explicitly disabled — properly configured")

    # --- Introspection detection ---
    if introspection_response:
        for pattern in _GRAPHQL_INTROSPECTION_SIGNATURES:
            if re.search(pattern, introspection_response, re.IGNORECASE):
                chain = chain.add(
                    signal="GraphQL introspection enabled — full schema exposed",
                    source="graphql_introspection",
                    raw_data=introspection_response[:500],
                    weight=1.0,
                )
                # Count types exposed — more types = bigger attack surface
                type_count_match = re.findall(r'"name"\s*:\s*"[A-Z]\w+"', introspection_response)
                if len(type_count_match) > 5:
                    chain = chain.add(
                        signal=f"Schema exposes {len(type_count_match)} named types — large attack surface",
                        source="graphql_introspection",
                        weight=0.5,
                    )
                break

    # --- Error verbosity detection ---
    if error_response:
        for pattern, description, weight in _GRAPHQL_ERROR_SIGNATURES:
            if re.search(pattern, error_response, re.IGNORECASE):
                chain = chain.add(
                    signal=description,
                    source="graphql_error_analysis",
                    raw_data=_extract_context(error_response, pattern),
                    weight=weight,
                )

    # --- Injection detection ---
    if injection_response:
        for pattern, description, weight in _GRAPHQL_INJECTION_SIGNATURES:
            if re.search(pattern, injection_response, re.IGNORECASE):
                chain = chain.add(
                    signal=description,
                    source="graphql_injection",
                    raw_data=_extract_context(injection_response, pattern),
                    weight=weight,
                )
                break

    # Baseline comparison
    if baseline_body and output and output.strip() != baseline_body.strip():
        if abs(len(output) - len(baseline_body)) > 200:
            chain = chain.add(
                signal="Response differs significantly from baseline",
                source="graphql_baseline_comparison",
                weight=0.2,
            )

    return chain


# ---------------------------------------------------------------------------
# validate_race_condition — TOCTOU / Race Condition
# ---------------------------------------------------------------------------

def validate_race_condition(
    responses: list[tuple[str, int, str]],
    expected_unique: int = 1,
    action: str = "",
    baseline_count: int | None = None,
) -> EvidenceChain:
    """Validate race condition / TOCTOU findings.

    A race condition is confirmed when parallel requests cause a state change
    that should only happen once (e.g., coupon used twice, balance deducted once
    but credit applied multiple times).

    Args:
        responses: List of (status_code_str, body_hash_int, body_preview) tuples
                   from parallel requests sent simultaneously
        expected_unique: How many unique success responses are expected (usually 1)
        action: Description of the action being raced (for signal context)
        baseline_count: How many times the action should succeed (usually 1)
    """
    chain = EvidenceChain()

    if not responses:
        return chain.add_fp_check("No responses — race condition test produced no data")

    total = len(responses)
    success_responses = [r for r in responses if r[0] in ("200", "201", "204")]
    error_responses = [r for r in responses if r[0] in ("409", "429", "400", "403")]

    # FP check: all requests failed (server properly serialized)
    if not success_responses:
        chain = chain.add_fp_check(
            f"All {total} parallel requests failed — server properly handles concurrent requests"
        )
        return chain

    # FP check: exactly expected successes, rest failed — proper behavior
    if len(success_responses) <= expected_unique and len(error_responses) >= total - expected_unique - 1:
        chain = chain.add_fp_check(
            f"Only {len(success_responses)}/{total} requests succeeded — concurrency handled correctly"
        )
        return chain

    # Primary signal: more successes than expected
    extra_successes = len(success_responses) - expected_unique
    if extra_successes > 0:
        success_previews = ", ".join(
            f"[{r[0]}] {r[2][:60]}" for r in success_responses[:4]
        )
        chain = chain.add(
            signal=f"Race condition: {len(success_responses)}/{total} requests succeeded "
                   f"(expected max {expected_unique}){' for: ' + action if action else ''}",
            source="race_condition_analysis",
            raw_data=success_previews,
            weight=1.0 + min(1.0, extra_successes * 0.2),  # more extras = stronger signal
        )

    # Check response body variance — identical success bodies = same resource hit twice
    body_hashes = [r[1] for r in success_responses]
    unique_hashes = set(body_hashes)
    if len(unique_hashes) == 1 and len(success_responses) > 1:
        chain = chain.add(
            signal=f"All {len(success_responses)} success responses are identical — same state applied multiple times",
            source="race_condition_identity_check",
            raw_data=success_responses[0][2][:120] if success_responses else "",
            weight=0.8,
        )
    elif len(unique_hashes) > 1:
        chain = chain.add(
            signal=f"Varied responses across {len(success_responses)} successes — concurrent state mutation confirmed",
            source="race_condition_variance_check",
            raw_data=", ".join(f"[{r[0]}] {r[2][:40]}" for r in success_responses[:3]),
            weight=0.5,
        )

    # Baseline comparison: more successes than baseline implies race exploit
    if baseline_count is not None and len(success_responses) > baseline_count:
        chain = chain.add(
            signal=f"Parallel requests produced {len(success_responses)} successes vs baseline {baseline_count}",
            source="race_condition_baseline",
            weight=0.5,
        )

    return chain
