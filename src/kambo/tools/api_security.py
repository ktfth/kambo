"""API Security testing tools — OWASP API Security Top 10."""

from __future__ import annotations

from kambo.docker_runner import get_runner
from kambo.models import Phase
from kambo.scope import validate_scope


async def api_test_bola(
    target: str,
    user_a_token: str,
    user_b_token: str,
    endpoints: list[str] | None = None,
) -> dict:
    """Test for Broken Object Level Authorization (API1:2023).

    Tests if user A can access user B's resources.

    Args:
        target: API base URL
        user_a_token: Token for user A
        user_b_token: Token for user B
        endpoints: List of endpoints with IDs to test (e.g., ["/api/users/1", "/api/orders/5"])
    """
    validate_scope(target)
    runner = get_runner()

    url = target if target.startswith("http") else f"https://{target}"
    endpoints = endpoints or ["/api/users/1", "/api/users/2", "/api/profile"]

    results = []
    for endpoint in endpoints:
        # Access with user A's token targeting user B's resources
        cmd = f'curl -s -o /dev/null -w "%{{http_code}}" -H "Authorization: Bearer {user_a_token}" "{url}{endpoint}" 2>/dev/null'
        result = await runner.run(cmd, "api_test_bola", target, Phase.VULN_ANALYSIS, timeout=15)
        status = result.raw_output.strip()
        results.append({
            "endpoint": endpoint,
            "status_code": status,
            "vulnerable": status == "200",
        })

    vulnerable_count = sum(1 for r in results if r["vulnerable"])

    return {
        "target": target,
        "vulnerability": "API1:2023 - BOLA",
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

    url = target if target.startswith("http") else f"https://{target}"
    checks = checks or ["no_auth", "jwt_weak_secret"]
    results: dict = {"target": target, "vulnerability": "API2:2023 - Broken Authentication", "checks": {}}

    if "no_auth" in checks:
        cmd = f'curl -s -o /dev/null -w "%{{http_code}}" "{url}/api/users" 2>/dev/null'
        result = await runner.run(cmd, "api_test_auth_noauth", target, Phase.VULN_ANALYSIS, timeout=15)
        results["checks"]["no_auth"] = {
            "status": result.raw_output.strip(),
            "vulnerable": result.raw_output.strip() in ("200", "201"),
        }

    if "jwt_weak_secret" in checks and token:
        cmd = f"jwt_tool '{token}' -C -p 'secret' -p 'password' -p '123456' -p 'admin' 2>/dev/null"
        result = await runner.run(cmd, "api_test_auth_jwt", target, Phase.VULN_ANALYSIS, timeout=30)
        results["checks"]["jwt_weak_secret"] = {
            "output": result.raw_output[:2000],
            "vulnerable": "found" in result.raw_output.lower(),
        }

    return results


async def api_test_bfla(
    target: str,
    regular_token: str,
    admin_endpoints: list[str] | None = None,
) -> dict:
    """Test for Broken Function Level Authorization (API5:2023).

    Tests if a regular user can access admin-level functions.

    Args:
        target: API base URL
        regular_token: Token from a non-admin user
        admin_endpoints: Admin endpoints to test
    """
    validate_scope(target)
    runner = get_runner()

    url = target if target.startswith("http") else f"https://{target}"
    admin_endpoints = admin_endpoints or [
        "/api/admin/users",
        "/api/admin/settings",
        "/api/admin/logs",
        "/api/users?role=admin",
        "/api/config",
    ]

    results = []
    for endpoint in admin_endpoints:
        cmd = f'curl -s -o /dev/null -w "%{{http_code}}" -H "Authorization: Bearer {regular_token}" "{url}{endpoint}" 2>/dev/null'
        result = await runner.run(cmd, "api_test_bfla", target, Phase.VULN_ANALYSIS, timeout=15)
        status = result.raw_output.strip()
        results.append({
            "endpoint": endpoint,
            "status_code": status,
            "vulnerable": status in ("200", "201", "204"),
        })

    return {
        "target": target,
        "vulnerability": "API5:2023 - BFLA",
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

    Tests mass assignment by adding unexpected fields to requests.

    Args:
        target: API base URL
        endpoint: Endpoint to test (e.g., /api/users/profile)
        token: Valid auth token
        mass_assignment_fields: Fields to attempt injecting
    """
    validate_scope(target)
    runner = get_runner()

    url = target if target.startswith("http") else f"https://{target}"
    fields = mass_assignment_fields or ["role", "is_admin", "balance", "verified", "permissions"]

    results = []
    for field in fields:
        payload = f'{{"name": "test", "{field}": "admin"}}'
        cmd = f'curl -s -X PUT -H "Authorization: Bearer {token}" -H "Content-Type: application/json" -d \'{payload}\' "{url}{endpoint}" 2>/dev/null'
        result = await runner.run(cmd, "api_test_bopla", target, Phase.VULN_ANALYSIS, timeout=15)
        results.append({
            "field": field,
            "response": result.raw_output[:500],
            "accepted": "200" in result.raw_output or field in result.raw_output,
        })

    return {
        "target": target,
        "vulnerability": "API3:2023 - BOPLA",
        "endpoint": endpoint,
        "results": results,
    }


async def api_test_resource(
    target: str,
    endpoint: str = "/api/search",
    bypass_headers: list[str] | None = None,
) -> dict:
    """Test for Unrestricted Resource Consumption (API4:2023).

    Tests rate limiting and resource exhaustion.

    Args:
        target: API base URL
        endpoint: Endpoint to test rate limiting on
        bypass_headers: Headers to try for rate limit bypass
    """
    validate_scope(target)
    runner = get_runner()

    url = target if target.startswith("http") else f"https://{target}"
    bypass_headers = bypass_headers or [
        "X-Forwarded-For: 127.0.0.{i}",
        "X-Real-IP: 10.0.0.{i}",
        "X-Original-Forwarded-For: 192.168.1.{i}",
    ]

    # Test baseline rate limit
    cmd = f'for i in $(seq 1 20); do curl -s -o /dev/null -w "%{{http_code}} " "{url}{endpoint}" 2>/dev/null; done'
    result = await runner.run(cmd, "api_test_resource_baseline", target, Phase.VULN_ANALYSIS, timeout=30)
    baseline_codes = result.raw_output.strip().split()

    rate_limited = "429" in baseline_codes

    # Try bypass if rate limited
    bypass_results = []
    if rate_limited:
        for header_template in bypass_headers:
            header = header_template.format(i=1)
            cmd = f'curl -s -o /dev/null -w "%{{http_code}}" -H "{header}" "{url}{endpoint}" 2>/dev/null'
            result = await runner.run(cmd, "api_test_resource_bypass", target, Phase.VULN_ANALYSIS, timeout=10)
            bypass_results.append({
                "header": header,
                "status": result.raw_output.strip(),
                "bypassed": result.raw_output.strip() != "429",
            })

    return {
        "target": target,
        "vulnerability": "API4:2023 - Unrestricted Resource Consumption",
        "rate_limited": rate_limited,
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

    url = target if target.startswith("http") else f"https://{target}"
    checks: dict = {}

    # CORS
    cmd = f'curl -s -I -H "Origin: https://evil.com" {url} 2>/dev/null | grep -i access-control'
    result = await runner.run(cmd, "api_test_misconfig_cors", target, Phase.VULN_ANALYSIS, timeout=10)
    checks["cors"] = {"headers": result.raw_output.strip(), "misconfigured": "evil.com" in result.raw_output}

    # HTTP Methods
    cmd = f'curl -s -X OPTIONS -I {url} 2>/dev/null | grep -i "allow:"'
    result = await runner.run(cmd, "api_test_misconfig_methods", target, Phase.VULN_ANALYSIS, timeout=10)
    checks["methods"] = {"allowed": result.raw_output.strip()}

    # Security headers
    cmd = f'curl -s -I {url} 2>/dev/null | grep -iE "(x-frame|x-content-type|strict-transport|content-security|x-xss)"'
    result = await runner.run(cmd, "api_test_misconfig_headers", target, Phase.VULN_ANALYSIS, timeout=10)
    checks["security_headers"] = {"present": result.raw_output.strip()}

    # Error handling (trigger error)
    cmd = f'curl -s "{url}/nonexistent_endpoint_test_12345" 2>/dev/null | head -20'
    result = await runner.run(cmd, "api_test_misconfig_errors", target, Phase.VULN_ANALYSIS, timeout=10)
    verbose_error = any(kw in result.raw_output.lower() for kw in ["traceback", "stack trace", "exception", "debug"])
    checks["error_handling"] = {"verbose": verbose_error, "response": result.raw_output[:500]}

    return {
        "target": target,
        "vulnerability": "API8:2023 - Security Misconfiguration",
        "checks": checks,
    }
