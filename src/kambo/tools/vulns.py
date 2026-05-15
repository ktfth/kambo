"""Phase 3: Vulnerability Analysis tools."""

from __future__ import annotations

from kambo.docker_runner import get_runner
from kambo.models import Phase
from kambo.parsers.generic_parser import parse_json_output
from kambo.scope import validate_scope


async def vuln_sqli(
    target: str,
    parameter: str = "",
    method: str = "GET",
    level: int = 3,
    risk: int = 2,
) -> dict:
    """SQL Injection detection and validation with sqlmap.

    Args:
        target: URL with injectable parameter (e.g., http://target/page?id=1)
        parameter: Specific parameter to test (empty = auto-detect)
        method: HTTP method (GET/POST)
        level: sqlmap level (1-5)
        risk: sqlmap risk (1-3)
    """
    validate_scope(target)
    runner = get_runner()

    param_flag = f"-p {parameter}" if parameter else ""
    method_flag = f"--method={method}" if method != "GET" else ""
    cmd = f"sqlmap -u '{target}' {param_flag} {method_flag} --batch --level={level} --risk={risk} --dbs --threads=4 2>/dev/null | tail -80"

    result = await runner.run(cmd, "vuln_sqli", target, Phase.VULN_ANALYSIS, timeout=180)

    vulnerable = any(
        keyword in result.raw_output.lower()
        for keyword in ["parameter", "injectable", "available databases"]
    )

    return {
        "target": target,
        "vulnerable": vulnerable,
        "raw": result.raw_output,
    }


async def vuln_xss(
    target: str,
    parameter: str = "",
) -> dict:
    """XSS detection using reflection analysis.

    Args:
        target: URL to test
        parameter: Specific parameter to test
    """
    validate_scope(target)
    runner = get_runner()

    url = target if target.startswith("http") else f"https://{target}"
    # Use a basic reflection test
    probe = "<script>alert(1)</script>"
    cmd = f'curl -s "{url}" -d "{parameter}={probe}" 2>/dev/null | grep -i "<script>alert"'
    result = await runner.run(cmd, "vuln_xss", target, Phase.VULN_ANALYSIS, timeout=30)

    return {
        "target": target,
        "reflected": bool(result.raw_output.strip()),
        "raw": result.raw_output,
    }


async def vuln_ssrf(
    target: str,
    parameter: str = "url",
    callback_url: str = "",
) -> dict:
    """SSRF testing with callback detection.

    Args:
        target: URL with potential SSRF parameter
        parameter: Parameter name to inject into
        callback_url: Collaborator/interactsh URL for OOB detection
    """
    validate_scope(target)
    runner = get_runner()

    # Internal targets to test
    internal_targets = [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:80",
        "http://localhost:22",
        "http://[::1]",
    ]

    results_list = []
    for internal in internal_targets:
        cmd = f'curl -s -o /dev/null -w "%{{http_code}}" "{target}?{parameter}={internal}" 2>/dev/null'
        result = await runner.run(cmd, "vuln_ssrf", target, Phase.VULN_ANALYSIS, timeout=15)
        results_list.append({
            "payload": internal,
            "status_code": result.raw_output.strip(),
        })

    return {
        "target": target,
        "parameter": parameter,
        "results": results_list,
    }


async def vuln_jwt(
    target: str,
    token: str,
) -> dict:
    """JWT token analysis and attack testing.

    Args:
        target: Target application URL (for context)
        token: JWT token to analyze
    """
    validate_scope(target)
    runner = get_runner()

    # Analyze token
    cmd = f"jwt_tool '{token}' 2>/dev/null"
    result = await runner.run(cmd, "vuln_jwt_analyze", target, Phase.VULN_ANALYSIS, timeout=30)

    # Try common weak secrets
    cmd2 = f"jwt_tool '{token}' -C -d /wordlists/jwt-secrets.txt 2>/dev/null || jwt_tool '{token}' -C -p 'secret' 2>/dev/null"
    result2 = await runner.run(cmd2, "vuln_jwt_crack", target, Phase.VULN_ANALYSIS, timeout=60)

    cracked = "secret" in result2.raw_output.lower() and "found" in result2.raw_output.lower()

    return {
        "target": target,
        "analysis": result.raw_output,
        "weak_secret_found": cracked,
        "crack_output": result2.raw_output,
    }


async def vuln_cors(target: str) -> dict:
    """CORS misconfiguration testing.

    Args:
        target: URL to test CORS headers
    """
    validate_scope(target)
    runner = get_runner()

    url = target if target.startswith("http") else f"https://{target}"

    origins_to_test = [
        "https://evil.com",
        "null",
        f"https://{target}.evil.com",
        "https://subdomain.evil.com",
    ]

    results_list = []
    for origin in origins_to_test:
        cmd = f'curl -s -I -H "Origin: {origin}" {url} 2>/dev/null | grep -i "access-control"'
        result = await runner.run(cmd, "vuln_cors", target, Phase.VULN_ANALYSIS, timeout=15)
        if result.raw_output.strip():
            results_list.append({
                "origin": origin,
                "headers": result.raw_output.strip(),
            })

    misconfigured = any(
        "evil.com" in r.get("headers", "") or "null" in r.get("headers", "")
        for r in results_list
    )

    return {
        "target": target,
        "misconfigured": misconfigured,
        "results": results_list,
    }


async def vuln_idor(
    target: str,
    token: str,
    id_range: tuple[int, int] = (1, 20),
) -> dict:
    """IDOR/BOLA testing via sequential ID enumeration.

    Args:
        target: API endpoint with ID parameter (e.g., /api/users/{id})
        token: Authorization token
        id_range: Range of IDs to test (start, end)
    """
    validate_scope(target)
    runner = get_runner()

    start, end = id_range
    cmd = f'for i in $(seq {start} {end}); do echo -n "$i: "; curl -s -o /dev/null -w "%{{http_code}}" -H "Authorization: Bearer {token}" "{target}/$i" 2>/dev/null; echo; done'
    result = await runner.run(cmd, "vuln_idor", target, Phase.VULN_ANALYSIS, timeout=60)

    accessible = []
    for line in result.raw_output.splitlines():
        if ": 200" in line:
            accessible.append(line.split(":")[0].strip())

    return {
        "target": target,
        "accessible_ids": accessible,
        "total_accessible": len(accessible),
        "total_tested": end - start + 1,
        "raw": result.raw_output,
    }


async def vuln_nuclei_scan(
    target: str,
    templates: str = "cves,vulnerabilities",
    severity: str = "critical,high",
) -> dict:
    """Targeted Nuclei scan with specific templates.

    Args:
        target: URL to scan
        templates: Template categories (comma-separated)
        severity: Severity filter
    """
    validate_scope(target)
    runner = get_runner()

    url = target if target.startswith("http") else f"https://{target}"
    template_flags = " ".join(f"-t {t}/" for t in templates.split(","))
    cmd = f"nuclei -u {url} {template_flags} -severity {severity} -json 2>/dev/null"

    result = await runner.run(cmd, "vuln_nuclei_scan", target, Phase.VULN_ANALYSIS, timeout=300)

    from kambo.parsers import parse_nuclei
    parsed = parse_nuclei(result.raw_output)

    return {"target": target, **parsed}


async def vuln_subdomain_takeover(target: str) -> dict:
    """Check for subdomain takeover via dangling CNAME.

    Args:
        target: Domain to check subdomains for takeover
    """
    validate_scope(target)
    runner = get_runner()

    cmd = f"dig +short CNAME {target} 2>/dev/null"
    result = await runner.run(cmd, "vuln_subdomain_takeover", target, Phase.VULN_ANALYSIS, timeout=15)

    cname = result.raw_output.strip()
    vulnerable = False

    if cname:
        # Check if CNAME target resolves
        cmd2 = f"dig +short {cname} 2>/dev/null"
        result2 = await runner.run(cmd2, "vuln_subdomain_takeover_check", target, Phase.VULN_ANALYSIS, timeout=15)
        if not result2.raw_output.strip():
            vulnerable = True

    return {
        "target": target,
        "cname": cname,
        "vulnerable": vulnerable,
    }
