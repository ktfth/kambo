"""API Security testing tools — OWASP API Security Top 10.

Each tool captures baseline responses and uses evidence-based validation
to avoid false positives. A 200 status code alone is never treated as
proof of vulnerability.
"""

from __future__ import annotations

import hashlib
import re

from kambo.docker_runner import get_runner
from kambo.metrics import get_metrics
from kambo.models import EvidenceChain, Phase
from kambo.scope import validate_scope
from kambo.validation import HttpResponse, validate_bfla


async def _curl_full(runner, url: str, token: str, tool_name: str, target: str) -> tuple[str, str, str]:
    """Execute curl and return (status_code, body, raw_output)."""
    cmd = (
        f'curl -s -D - -H "Authorization: Bearer {token}" '
        f'"{url}" 2>/dev/null'
    )
    result = await runner.run(cmd, tool_name, target, Phase.VULN_ANALYSIS, timeout=15)
    raw = result.raw_output

    status_match = re.search(r"HTTP/\d\.?\d?\s+(\d{3})", raw)
    status = status_match.group(1) if status_match else "000"

    parts = raw.split("\r\n\r\n", 1)
    body = parts[1] if len(parts) > 1 else raw

    return status, body, raw


async def api_test_bola(
    target: str,
    user_a_token: str,
    user_b_token: str,
    endpoints: list[str] | None = None,
) -> dict:
    """Test for Broken Object Level Authorization (API1:2023).

    Validates by comparing: user A accessing their own resource vs. user B's resource.
    If responses are identical in structure but different in data, it's a true BOLA.
    If all responses are identical, it's likely a generic response.

    Args:
        target: API base URL
        user_a_token: Token for user A
        user_b_token: Token for user B
        endpoints: Endpoints with IDs to test (e.g., ["/api/users/1", "/api/orders/5"])
    """
    validate_scope(target)
    runner = get_runner()
    metrics = get_metrics()

    url = target if target.startswith("http") else f"https://{target}"
    endpoints = endpoints or ["/api/users/1", "/api/users/2", "/api/profile"]

    chain = EvidenceChain()
    results = []

    for endpoint in endpoints:
        # Step 1: Access with legitimate user (user B) for baseline
        status_b, body_b, _ = await _curl_full(runner, f"{url}{endpoint}", user_b_token, "api_test_bola_baseline", target)

        # Step 2: Access with user A (should be denied)
        status_a, body_a, _ = await _curl_full(runner, f"{url}{endpoint}", user_a_token, "api_test_bola", target)

        # Step 3: Validate — not just status code
        is_vulnerable = False
        fp_reason = ""

        if status_a not in ("200", "201"):
            fp_reason = f"Status {status_a} — access properly denied"
        elif not body_a.strip():
            fp_reason = "Empty response body despite 200 — likely error"
        elif body_a == body_b:
            # Same data returned — could be same resource or generic response
            # Check if it looks like user-specific data
            has_user_data = any(
                indicator in body_a.lower()
                for indicator in ["email", "name", "address", "phone", "account", "balance"]
            )
            if has_user_data:
                is_vulnerable = True
                chain = chain.add(
                    signal=f"User A can read user B's data at {endpoint} — responses contain user data",
                    source="bola_test",
                    raw_data=body_a[:500],
                    weight=1.0,
                )
            else:
                fp_reason = "Response identical but contains no user-specific data"
        else:
            # Different data — check if user A got different user data
            body_a_hash = hashlib.md5(body_a.encode()).hexdigest()
            body_b_hash = hashlib.md5(body_b.encode()).hexdigest()
            if body_a_hash != body_b_hash:
                is_vulnerable = True
                chain = chain.add(
                    signal=f"User A gets data at {endpoint} (different from user B) — cross-user access confirmed",
                    source="bola_test",
                    raw_data=body_a[:500],
                    weight=1.2,
                )

        if fp_reason:
            chain = chain.add_fp_check(f"{endpoint}: {fp_reason}")

        results.append({
            "endpoint": endpoint,
            "status_code_user_a": status_a,
            "status_code_user_b": status_b,
            "vulnerable": is_vulnerable,
            "fp_reason": fp_reason,
        })

    vulnerable_count = sum(1 for r in results if r["vulnerable"])

    metrics.record_run("api_test_bola")
    if chain.total_weight > 0:
        metrics.record_finding("api_test_bola", chain.confidence, chain.total_weight)

    return {
        "target": target,
        "vulnerability": "API1:2023 - BOLA",
        "vulnerable": chain.total_weight >= 1.0,
        "confidence": chain.confidence.value,
        "evidence": chain.summary(),
        "results": results,
        "vulnerable_endpoints": vulnerable_count,
        "total_tested": len(results),
    }


async def api_test_auth(
    target: str,
    checks: list[str] | None = None,
    token: str = "",
) -> dict:
    """Test for Broken Authentication (API2:2023).

    Args:
        target: API base URL
        checks: Specific checks — jwt_weak_secret, token_expiry, no_auth, brute_lockout
        token: JWT token to analyze (if applicable)
    """
    validate_scope(target)
    runner = get_runner()
    metrics = get_metrics()

    url = target if target.startswith("http") else f"https://{target}"
    checks = checks or ["no_auth", "jwt_weak_secret"]
    chain = EvidenceChain()
    check_results: dict = {}

    if "no_auth" in checks:
        # Test multiple endpoints without auth
        test_paths = ["/api/users", "/api/profile", "/api/me", "/api/account"]
        for path in test_paths:
            status, body, _ = await _curl_full(runner, f"{url}{path}", "", "api_test_auth_noauth", target)
            if status in ("200", "201") and len(body.strip()) > 20:
                # Check if response contains actual data vs. generic message
                error_words = ["unauthorized", "login", "authenticate", "forbidden"]
                if not any(w in body.lower() for w in error_words):
                    chain = chain.add(
                        signal=f"No-auth access to {path} returns data ({len(body)} bytes)",
                        source="auth_noauth",
                        raw_data=body[:500],
                        weight=0.8,
                    )
                else:
                    chain = chain.add_fp_check(f"{path}: 200 but body contains auth-related error words")

        check_results["no_auth"] = {
            "confidence": chain.confidence.value,
            "evidence": chain.summary(),
        }

    if "jwt_weak_secret" in checks and token:
        from kambo.validation import validate_jwt
        cmd = f"jwt_tool '{token}' -C -p 'secret' -p 'password' -p '123456' -p 'admin' 2>/dev/null"
        result = await runner.run(cmd, "api_test_auth_jwt", target, Phase.VULN_ANALYSIS, timeout=30)

        jwt_chain = validate_jwt("", result.raw_output)
        # Merge into main chain
        for item in jwt_chain.items:
            chain = chain.add(item.signal, item.source, item.raw_data, item.weight)

        check_results["jwt_weak_secret"] = {
            "confidence": jwt_chain.confidence.value,
            "evidence": jwt_chain.summary(),
        }

    metrics.record_run("api_test_auth")
    if chain.total_weight > 0:
        metrics.record_finding("api_test_auth", chain.confidence, chain.total_weight)

    return {
        "target": target,
        "vulnerability": "API2:2023 - Broken Authentication",
        "vulnerable": chain.total_weight >= 1.0,
        "confidence": chain.confidence.value,
        "evidence": chain.summary(),
        "checks": check_results,
    }


async def api_test_bfla(
    target: str,
    regular_token: str,
    admin_endpoints: list[str] | None = None,
) -> dict:
    """Test for Broken Function Level Authorization (API5:2023).

    Gets baseline unauthenticated response for each endpoint, then tests
    with regular user token. Validates response body for admin data indicators.

    Args:
        target: API base URL
        regular_token: Token from a non-admin user
        admin_endpoints: Admin endpoints to test
    """
    validate_scope(target)
    runner = get_runner()
    metrics = get_metrics()

    url = target if target.startswith("http") else f"https://{target}"
    admin_endpoints = admin_endpoints or [
        "/api/admin/users",
        "/api/admin/settings",
        "/api/admin/logs",
        "/api/users?role=admin",
        "/api/config",
    ]

    chain = EvidenceChain()
    results = []

    for endpoint in admin_endpoints:
        # Step 1: Baseline — unauthenticated request
        unauth_status, unauth_body, _ = await _curl_full(runner, f"{url}{endpoint}", "", "api_test_bfla_baseline", target)
        baseline_unauth = HttpResponse(status=int(unauth_status) if unauth_status.isdigit() else 0, body=unauth_body)

        # Step 2: Test with regular user token
        status, body, _ = await _curl_full(runner, f"{url}{endpoint}", regular_token, "api_test_bfla", target)

        # Step 3: Validate with proper body analysis
        endpoint_chain = validate_bfla(endpoint, status, body, baseline_unauth)

        for item in endpoint_chain.items:
            chain = chain.add(item.signal, item.source, item.raw_data, item.weight)
        for check in endpoint_chain.false_positive_checks:
            chain = chain.add_fp_check(check)

        results.append({
            "endpoint": endpoint,
            "status_code": status,
            "vulnerable": endpoint_chain.total_weight >= 0.5,
            "confidence": endpoint_chain.confidence.value,
            "evidence": endpoint_chain.summary(),
        })

    metrics.record_run("api_test_bfla")
    if chain.total_weight > 0:
        metrics.record_finding("api_test_bfla", chain.confidence, chain.total_weight)

    return {
        "target": target,
        "vulnerability": "API5:2023 - BFLA",
        "vulnerable": chain.total_weight >= 1.0,
        "confidence": chain.confidence.value,
        "evidence": chain.summary(),
        "results": results,
        "vulnerable_endpoints": sum(1 for r in results if r["vulnerable"]),
    }


async def api_test_bopla(
    target: str,
    endpoint: str,
    token: str,
    mass_assignment_fields: list[str] | None = None,
) -> dict:
    """Test for Broken Object Property Level Authorization (API3:2023).

    Tests mass assignment by injecting unexpected fields and checking
    if the response reflects the injected values.

    Args:
        target: API base URL
        endpoint: Endpoint to test (e.g., /api/users/profile)
        token: Valid auth token
        mass_assignment_fields: Fields to attempt injecting
    """
    validate_scope(target)
    runner = get_runner()
    metrics = get_metrics()

    url = target if target.startswith("http") else f"https://{target}"
    fields = mass_assignment_fields or ["role", "is_admin", "balance", "verified", "permissions"]

    chain = EvidenceChain()

    # Step 1: Get baseline — normal update without extra fields
    baseline_cmd = (
        f'curl -s -D - -X PUT -H "Authorization: Bearer {token}" '
        f'-H "Content-Type: application/json" '
        f'-d \'{{"name": "test"}}\' "{url}{endpoint}" 2>/dev/null'
    )
    baseline_result = await runner.run(baseline_cmd, "api_test_bopla_baseline", target, Phase.VULN_ANALYSIS, timeout=15)
    baseline_parts = baseline_result.raw_output.split("\r\n\r\n", 1)
    baseline_body = baseline_parts[1] if len(baseline_parts) > 1 else baseline_result.raw_output

    results = []
    for field in fields:
        payload = f'{{"name": "test", "{field}": "admin"}}'
        cmd = (
            f'curl -s -D - -X PUT -H "Authorization: Bearer {token}" '
            f'-H "Content-Type: application/json" '
            f"-d '{payload}' \"{url}{endpoint}\" 2>/dev/null"
        )
        result = await runner.run(cmd, "api_test_bopla", target, Phase.VULN_ANALYSIS, timeout=15)

        parts = result.raw_output.split("\r\n\r\n", 1)
        body = parts[1] if len(parts) > 1 else result.raw_output
        status_match = re.search(r"HTTP/\d\.?\d?\s+(\d{3})", result.raw_output)
        status = status_match.group(1) if status_match else "000"

        # Check if the injected field appears in the response
        accepted = False
        if status in ("200", "201"):
            # The field must appear in response AND the value must be reflected
            if f'"{field}"' in body and "admin" in body:
                accepted = True
                chain = chain.add(
                    signal=f"Mass assignment: field '{field}' accepted with value 'admin' reflected in response",
                    source="bopla_test",
                    raw_data=body[:500],
                    weight=1.0,
                )
            elif f'"{field}"' in body:
                # Field present but value not reflected — might be ignored
                chain = chain.add(
                    signal=f"Field '{field}' present in response but injected value not reflected",
                    source="bopla_test",
                    weight=0.2,
                )
            else:
                chain = chain.add_fp_check(f"Field '{field}' not present in response — likely ignored")

        results.append({
            "field": field,
            "status": status,
            "accepted": accepted,
            "response_preview": body[:300],
        })

    metrics.record_run("api_test_bopla")
    if chain.total_weight > 0:
        metrics.record_finding("api_test_bopla", chain.confidence, chain.total_weight)

    return {
        "target": target,
        "vulnerability": "API3:2023 - BOPLA",
        "endpoint": endpoint,
        "vulnerable": chain.total_weight >= 1.0,
        "confidence": chain.confidence.value,
        "evidence": chain.summary(),
        "results": results,
    }


async def api_test_resource(
    target: str,
    endpoint: str = "/api/search",
    bypass_headers: list[str] | None = None,
) -> dict:
    """Test for Unrestricted Resource Consumption (API4:2023).

    Args:
        target: API base URL
        endpoint: Endpoint to test rate limiting on
        bypass_headers: Headers to try for rate limit bypass
    """
    validate_scope(target)
    runner = get_runner()
    metrics = get_metrics()

    url = target if target.startswith("http") else f"https://{target}"
    bypass_headers = bypass_headers or [
        "X-Forwarded-For: 127.0.0.{i}",
        "X-Real-IP: 10.0.0.{i}",
        "X-Original-Forwarded-For: 192.168.1.{i}",
    ]

    chain = EvidenceChain()

    # Test baseline rate limit
    cmd = f'for i in $(seq 1 20); do curl -s -o /dev/null -w "%{{http_code}} " "{url}{endpoint}" 2>/dev/null; done'
    result = await runner.run(cmd, "api_test_resource_baseline", target, Phase.VULN_ANALYSIS, timeout=30)
    baseline_codes = result.raw_output.strip().split()

    rate_limited = "429" in baseline_codes

    if not rate_limited:
        chain = chain.add(
            signal=f"No rate limiting detected after 20 requests — all returned: {set(baseline_codes)}",
            source="rate_limit_test",
            weight=0.5,
        )

    # Try bypass if rate limited
    bypass_results = []
    if rate_limited:
        chain = chain.add_fp_check("Rate limiting is in place (429 returned)")
        for header_template in bypass_headers:
            header = header_template.format(i=1)
            cmd = f'curl -s -o /dev/null -w "%{{http_code}}" -H "{header}" "{url}{endpoint}" 2>/dev/null'
            result = await runner.run(cmd, "api_test_resource_bypass", target, Phase.VULN_ANALYSIS, timeout=10)
            status = result.raw_output.strip()
            bypassed = status not in ("429", "000")
            if bypassed:
                chain = chain.add(
                    signal=f"Rate limit bypass via header: {header} (got {status})",
                    source="rate_limit_bypass",
                    weight=0.8,
                )
            bypass_results.append({
                "header": header,
                "status": status,
                "bypassed": bypassed,
            })

    metrics.record_run("api_test_resource")
    if chain.total_weight > 0:
        metrics.record_finding("api_test_resource", chain.confidence, chain.total_weight)

    return {
        "target": target,
        "vulnerability": "API4:2023 - Unrestricted Resource Consumption",
        "rate_limited": rate_limited,
        "vulnerable": chain.total_weight >= 0.5,
        "confidence": chain.confidence.value,
        "evidence": chain.summary(),
        "status_codes": baseline_codes[:20],
        "bypass_results": bypass_results,
    }


async def api_test_misconfig(target: str) -> dict:
    """Test for Security Misconfiguration (API8:2023).

    Args:
        target: API base URL
    """
    validate_scope(target)
    runner = get_runner()
    metrics = get_metrics()

    url = target if target.startswith("http") else f"https://{target}"
    chain = EvidenceChain()
    checks: dict = {}

    # CORS — use the proper validation
    from kambo.validation import validate_cors as _validate_cors
    cmd = f'curl -s -I -H "Origin: https://evil.com" {url} 2>/dev/null'
    result = await runner.run(cmd, "api_test_misconfig_cors", target, Phase.VULN_ANALYSIS, timeout=10)

    domain_match = re.search(r"https?://([^/]+)", url)
    domain = domain_match.group(1) if domain_match else target
    cors_chain = _validate_cors("https://evil.com", result.raw_output, domain)
    checks["cors"] = {"confidence": cors_chain.confidence.value, "evidence": cors_chain.summary()}
    for item in cors_chain.items:
        chain = chain.add(item.signal, item.source, item.raw_data, item.weight)

    # HTTP Methods
    cmd = f'curl -s -X OPTIONS -I {url} 2>/dev/null | grep -i "allow:"'
    result = await runner.run(cmd, "api_test_misconfig_methods", target, Phase.VULN_ANALYSIS, timeout=10)
    allowed = result.raw_output.strip()
    dangerous_methods = [m for m in ["PUT", "DELETE", "PATCH", "TRACE"] if m in allowed.upper()]
    if dangerous_methods:
        chain = chain.add(
            signal=f"Dangerous HTTP methods allowed: {', '.join(dangerous_methods)}",
            source="http_methods",
            raw_data=allowed,
            weight=0.3,
        )
    checks["methods"] = {"allowed": allowed, "dangerous": dangerous_methods}

    # Security headers
    cmd = f'curl -s -I {url} 2>/dev/null'
    result = await runner.run(cmd, "api_test_misconfig_headers", target, Phase.VULN_ANALYSIS, timeout=10)
    headers_lower = result.raw_output.lower()

    missing_headers = []
    required = {
        "strict-transport-security": "HSTS",
        "x-content-type-options": "X-Content-Type-Options",
        "x-frame-options": "X-Frame-Options",
        "content-security-policy": "CSP",
    }
    for header, name in required.items():
        if header not in headers_lower:
            missing_headers.append(name)

    if missing_headers:
        chain = chain.add(
            signal=f"Missing security headers: {', '.join(missing_headers)}",
            source="security_headers",
            weight=0.2,
        )
    checks["security_headers"] = {"missing": missing_headers}

    # Error handling (trigger error)
    cmd = f'curl -s "{url}/nonexistent_endpoint_test_12345" 2>/dev/null | head -20'
    result = await runner.run(cmd, "api_test_misconfig_errors", target, Phase.VULN_ANALYSIS, timeout=10)
    verbose_indicators = ["traceback", "stack trace", "exception", "debug", "at line", "syntax error"]
    verbose_matches = [ind for ind in verbose_indicators if ind in result.raw_output.lower()]
    if verbose_matches:
        chain = chain.add(
            signal=f"Verbose error disclosure: {', '.join(verbose_matches)}",
            source="error_handling",
            raw_data=result.raw_output[:500],
            weight=0.5,
        )
    checks["error_handling"] = {
        "verbose": bool(verbose_matches),
        "indicators": verbose_matches,
        "response_preview": result.raw_output[:300],
    }

    metrics.record_run("api_test_misconfig")
    # Only record a finding at/above the `vulnerable` threshold. A lone missing
    # security header (weight 0.2) or a single permitted method (0.3) is low-value
    # noise — recording it as a tentative "finding" inflated the FP surface
    # (14 tentative/0 confirmed). Real signals (CORS reflection, verbose errors,
    # or stacked checks) clear 0.5 and are still recorded.
    if chain.total_weight >= 0.5:
        metrics.record_finding("api_test_misconfig", chain.confidence, chain.total_weight)

    return {
        "target": target,
        "vulnerability": "API8:2023 - Security Misconfiguration",
        "vulnerable": chain.total_weight >= 0.5,
        "confidence": chain.confidence.value,
        "evidence": chain.summary(),
        "checks": checks,
    }
