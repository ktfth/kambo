"""Phase 3: Vulnerability Analysis tools — evidence-based validation.

Every tool returns an evidence chain with weighted signals. Confidence levels:
  CONFIRMED (weight >= 2.0): Exploit-grade proof, ready to report.
  FIRM      (weight >= 1.0): Strong indicators, worth reporting with caveats.
  TENTATIVE (weight <  1.0): Single signal, needs manual verification.
"""

from __future__ import annotations

from kambo.docker_runner import get_runner
from kambo.metrics import get_metrics
from kambo.models import EvidenceChain, Phase
from kambo.parsers.generic_parser import parse_json_output
from kambo.scope import validate_scope
from kambo.validation import (
    HttpResponse,
    validate_cors,
    validate_idor,
    validate_jwt,
    validate_sqli,
    validate_ssrf,
    validate_subdomain_takeover,
    validate_xss,
)


async def vuln_sqli(
    target: str,
    parameter: str = "",
    method: str = "GET",
    level: int = 3,
    risk: int = 2,
) -> dict:
    """SQL Injection detection with multi-signal validation.

    Args:
        target: URL with injectable parameter (e.g., http://target/page?id=1)
        parameter: Specific parameter to test (empty = auto-detect)
        method: HTTP method (GET/POST)
        level: sqlmap level (1-5)
        risk: sqlmap risk (1-3)

    Returns evidence chain with confidence level instead of binary vulnerable flag.
    """
    validate_scope(target)
    runner = get_runner()
    metrics = get_metrics()

    param_flag = f"-p {parameter}" if parameter else ""
    method_flag = f"--method={method}" if method != "GET" else ""
    cmd = (
        f"sqlmap -u '{target}' {param_flag} {method_flag} --batch "
        f"--level={level} --risk={risk} --dbs --threads=4 "
        f"--output-dir=/tmp/sqlmap 2>/dev/null | tail -120"
    )

    result = await runner.run(cmd, "vuln_sqli", target, Phase.VULN_ANALYSIS, timeout=180)
    metrics.record_run("vuln_sqli")

    chain = validate_sqli(result.raw_output)

    if chain.total_weight > 0:
        metrics.record_finding("vuln_sqli", chain.confidence, chain.total_weight)

    return {
        "target": target,
        "parameter": parameter or "auto-detect",
        "vulnerable": chain.total_weight >= 1.0,
        "confidence": chain.confidence.value,
        "evidence": chain.summary(),
        "raw": result.raw_output,
    }


async def vuln_xss(
    target: str,
    parameter: str = "",
) -> dict:
    """XSS detection with reflection analysis and context validation.

    Tests multiple payloads and validates that reflection occurs in an
    executable context (not HTML-encoded, not inside comments).

    Args:
        target: URL to test
        parameter: Specific parameter to test
    """
    validate_scope(target)
    runner = get_runner()
    metrics = get_metrics()

    url = target if target.startswith("http") else f"https://{target}"

    # Test multiple payloads — different contexts require different payloads
    payloads = [
        '<script>alert(1)</script>',
        '"><img src=x onerror=alert(1)>',
        "'-alert(1)-'",
        '<svg onload=alert(1)>',
    ]

    best_chain = EvidenceChain()

    for payload in payloads:
        # Use curl with full response to analyze context
        if parameter:
            cmd = f'curl -s -D - "{url}" -d "{parameter}={payload}" 2>/dev/null'
        else:
            # Try as query string
            sep = "&" if "?" in url else "?"
            cmd = f'curl -s -D - "{url}{sep}q={payload}" 2>/dev/null'

        result = await runner.run(cmd, "vuln_xss", target, Phase.VULN_ANALYSIS, timeout=30)
        chain = validate_xss(result.raw_output, payload, parameter or "q")

        if chain.total_weight > best_chain.total_weight:
            best_chain = chain

        # Stop if we already have strong evidence
        if best_chain.total_weight >= 1.5:
            break

    metrics.record_run("vuln_xss")
    if best_chain.total_weight > 0:
        metrics.record_finding("vuln_xss", best_chain.confidence, best_chain.total_weight)

    return {
        "target": target,
        "vulnerable": best_chain.total_weight >= 1.0,
        "confidence": best_chain.confidence.value,
        "evidence": best_chain.summary(),
        "raw": result.raw_output[:3000],
    }


async def vuln_ssrf(
    target: str,
    parameter: str = "url",
    callback_url: str = "",
) -> dict:
    """SSRF testing with response content analysis.

    Tests internal targets and validates by analyzing response content,
    not just status codes. A 200 status alone is NOT evidence of SSRF.

    Args:
        target: URL with potential SSRF parameter
        parameter: Parameter name to inject into
        callback_url: Collaborator/interactsh URL for OOB detection
    """
    validate_scope(target)
    runner = get_runner()
    metrics = get_metrics()

    # First, get a baseline response for comparison
    baseline_cmd = f'curl -s -D - "{target}?{parameter}=https://example.com" 2>/dev/null'
    baseline_result = await runner.run(baseline_cmd, "vuln_ssrf_baseline", target, Phase.VULN_ANALYSIS, timeout=15)
    baseline = HttpResponse(status=200, body=baseline_result.raw_output)

    internal_targets = [
        ("http://169.254.169.254/latest/meta-data/", "AWS IMDS"),
        ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure IMDS"),
        ("http://metadata.google.internal/computeMetadata/v1/", "GCP Metadata"),
        ("http://127.0.0.1:80", "Localhost HTTP"),
        ("http://127.0.0.1:22", "Localhost SSH"),
        ("http://[::1]", "IPv6 Localhost"),
        ("file:///etc/passwd", "Local file read"),
    ]

    results_list = []
    best_chain = EvidenceChain(baseline=baseline.to_dict())

    for internal_url, description in internal_targets:
        # Get full response including body for content analysis
        cmd = f'curl -s -D - "{target}?{parameter}={internal_url}" 2>/dev/null'
        result = await runner.run(cmd, "vuln_ssrf", target, Phase.VULN_ANALYSIS, timeout=15)

        # Extract status code from headers
        import re
        status_match = re.search(r"HTTP/\d\.?\d?\s+(\d{3})", result.raw_output)
        status = status_match.group(1) if status_match else "000"

        chain = validate_ssrf(internal_url, status, result.raw_output)

        results_list.append({
            "payload": internal_url,
            "description": description,
            "status_code": status,
            "confidence": chain.confidence.value,
            "evidence": chain.summary(),
        })

        if chain.total_weight > best_chain.total_weight:
            best_chain = chain

    # OOB callback test if URL provided
    if callback_url:
        cmd = f'curl -s "{target}?{parameter}={callback_url}" 2>/dev/null'
        await runner.run(cmd, "vuln_ssrf_oob", target, Phase.VULN_ANALYSIS, timeout=15)
        best_chain = best_chain.add(
            signal=f"OOB callback sent to {callback_url} — check collaborator for interaction",
            source="ssrf_oob",
            weight=0.3,  # only confirmed if callback received
        )

    metrics.record_run("vuln_ssrf")
    if best_chain.total_weight > 0:
        metrics.record_finding("vuln_ssrf", best_chain.confidence, best_chain.total_weight)

    return {
        "target": target,
        "parameter": parameter,
        "vulnerable": best_chain.total_weight >= 1.0,
        "confidence": best_chain.confidence.value,
        "evidence": best_chain.summary(),
        "results": results_list,
    }


async def vuln_jwt(
    target: str,
    token: str,
) -> dict:
    """JWT token analysis with structured vulnerability checks.

    Tests for: weak signing secrets, algorithm confusion, missing claims.

    Args:
        target: Target application URL (for context)
        token: JWT token to analyze
    """
    validate_scope(target)
    runner = get_runner()
    metrics = get_metrics()

    # Analyze token structure
    cmd = f"jwt_tool '{token}' 2>/dev/null"
    result = await runner.run(cmd, "vuln_jwt_analyze", target, Phase.VULN_ANALYSIS, timeout=30)

    # Try weak secrets with wordlist, then common passwords
    cmd2 = (
        f"jwt_tool '{token}' -C -d /wordlists/jwt-secrets.txt 2>/dev/null || "
        f"jwt_tool '{token}' -C -p 'secret' -p 'password' -p '123456' "
        f"-p 'admin' -p 'key' -p 'jwt_secret' 2>/dev/null"
    )
    result2 = await runner.run(cmd2, "vuln_jwt_crack", target, Phase.VULN_ANALYSIS, timeout=60)

    chain = validate_jwt(result.raw_output, result2.raw_output)

    metrics.record_run("vuln_jwt")
    if chain.total_weight > 0:
        metrics.record_finding("vuln_jwt", chain.confidence, chain.total_weight)

    return {
        "target": target,
        "vulnerable": chain.total_weight >= 1.0,
        "confidence": chain.confidence.value,
        "evidence": chain.summary(),
        "analysis": result.raw_output[:2000],
        "crack_output": result2.raw_output[:1000],
    }


async def vuln_cors(target: str) -> dict:
    """CORS misconfiguration testing with proper policy analysis.

    Tests multiple origin variations and validates that reflected origins
    are actually exploitable (credentials must be allowed for real impact).

    Args:
        target: URL to test CORS headers
    """
    validate_scope(target)
    runner = get_runner()
    metrics = get_metrics()

    url = target if target.startswith("http") else f"https://{target}"

    # Extract domain for subdomain-based tests
    import re
    domain_match = re.search(r"https?://([^/]+)", url)
    domain = domain_match.group(1) if domain_match else target

    origins_to_test = [
        ("https://evil.com", "arbitrary origin"),
        ("null", "null origin (sandboxed iframe)"),
        (f"https://{domain}.evil.com", "subdomain suffix confusion"),
        (f"https://evil-{domain}", "prefix confusion"),
    ]

    best_chain = EvidenceChain()
    results_list = []

    for origin, description in origins_to_test:
        # Get full headers to analyze ACAO + ACAC together
        cmd = f'curl -s -I -H "Origin: {origin}" {url} 2>/dev/null'
        result = await runner.run(cmd, "vuln_cors", target, Phase.VULN_ANALYSIS, timeout=15)

        chain = validate_cors(origin, result.raw_output, domain)

        results_list.append({
            "origin": origin,
            "description": description,
            "headers": result.raw_output.strip()[:500],
            "confidence": chain.confidence.value,
            "evidence": chain.summary(),
        })

        if chain.total_weight > best_chain.total_weight:
            best_chain = chain

    metrics.record_run("vuln_cors")
    if best_chain.total_weight > 0:
        metrics.record_finding("vuln_cors", best_chain.confidence, best_chain.total_weight)

    return {
        "target": target,
        "misconfigured": best_chain.total_weight >= 1.0,
        "confidence": best_chain.confidence.value,
        "evidence": best_chain.summary(),
        "results": results_list,
    }


async def vuln_idor(
    target: str,
    token: str,
    id_range: tuple[int, int] = (1, 20),
) -> dict:
    """IDOR/BOLA testing with baseline comparison and response diffing.

    Instead of just counting 200 responses, compares response bodies to detect
    whether different IDs return genuinely different user data vs. generic responses.

    Args:
        target: API endpoint with ID parameter (e.g., /api/users/{id})
        token: Authorization token
        id_range: Range of IDs to test (start, end)
    """
    validate_scope(target)
    runner = get_runner()
    metrics = get_metrics()

    start, end = id_range

    # Step 1: Get baseline — what does an invalid/non-existent ID return?
    baseline_cmd = (
        f'curl -s -D - -H "Authorization: Bearer {token}" '
        f'"{target}/999999999" 2>/dev/null'
    )
    baseline_result = await runner.run(baseline_cmd, "vuln_idor_baseline", target, Phase.VULN_ANALYSIS, timeout=15)

    import re
    status_match = re.search(r"HTTP/\d\.?\d?\s+(\d{3})", baseline_result.raw_output)
    baseline_status = int(status_match.group(1)) if status_match else 0
    # Split headers from body
    parts = baseline_result.raw_output.split("\r\n\r\n", 1)
    baseline_body = parts[1] if len(parts) > 1 else baseline_result.raw_output
    baseline = HttpResponse(status=baseline_status, body=baseline_body)

    # Step 2: Test each ID and capture full responses
    test_responses: list[tuple[str, HttpResponse]] = []
    for i in range(start, min(end + 1, start + 20)):  # cap at 20 to be respectful
        cmd = (
            f'curl -s -D - -H "Authorization: Bearer {token}" '
            f'"{target}/{i}" 2>/dev/null'
        )
        result = await runner.run(cmd, "vuln_idor", target, Phase.VULN_ANALYSIS, timeout=10)

        s_match = re.search(r"HTTP/\d\.?\d?\s+(\d{3})", result.raw_output)
        resp_status = int(s_match.group(1)) if s_match else 0
        resp_parts = result.raw_output.split("\r\n\r\n", 1)
        resp_body = resp_parts[1] if len(resp_parts) > 1 else result.raw_output

        test_responses.append((str(i), HttpResponse(status=resp_status, body=resp_body)))

    # Step 3: Validate with diffing
    chain = validate_idor(baseline, test_responses)

    accessible = [rid for rid, resp in test_responses if resp.status == 200]

    metrics.record_run("vuln_idor")
    if chain.total_weight > 0:
        metrics.record_finding("vuln_idor", chain.confidence, chain.total_weight)

    return {
        "target": target,
        "vulnerable": chain.total_weight >= 1.0,
        "confidence": chain.confidence.value,
        "evidence": chain.summary(),
        "accessible_ids": accessible,
        "total_accessible": len(accessible),
        "total_tested": min(end - start + 1, 20),
        "baseline_status": baseline_status,
    }


async def vuln_ssti(
    target: str,
    parameter: str = "",
    engine: str = "auto",
) -> dict:
    """Server-Side Template Injection detection.

    Tests template expression rendering — {{7*7}}→49 is the gold standard.
    Detects Jinja2, Twig, Smarty, Freemarker, Velocity, Pebble.

    Args:
        target: URL to test
        parameter: Parameter to inject into (empty = try all)
        engine: Template engine hint (auto, jinja2, twig, smarty, velocity)
    """
    validate_scope(target)
    runner = get_runner()
    metrics = get_metrics()

    from kambo.validation import validate_ssti

    url = target if target.startswith("http") else f"https://{target}"

    # Engine-specific payloads → expected output
    payloads: list[tuple[str, str, str]] = [
        ("{{7*7}}", "49", "jinja2/twig"),
        ("${7*7}", "49", "freemarker/velocity"),
        ("{{7*'7'}}", "7777777", "jinja2-python"),
        ("<%= 7*7 %>", "49", "erb/ejs"),
        ("#{7*7}", "49", "ruby-interpolation"),
    ]

    if engine != "auto":
        engine_map = {
            "jinja2": [("{{7*7}}", "49", "jinja2"), ("{{7*'7'}}", "7777777", "jinja2-python")],
            "twig": [("{{7*7}}", "49", "twig"), ("{{7*'7'}}", "49math", "twig")],
            "smarty": [("{$smarty.version}", "", "smarty"), ("{7*7}", "49", "smarty-math")],
            "velocity": [("${7*7}", "49", "velocity")],
        }
        payloads = engine_map.get(engine, payloads)

    # Get baseline first
    cmd_baseline = f'curl -s -m 15 "{url}" 2>/dev/null'
    baseline_result = await runner.run(cmd_baseline, "vuln_ssti_baseline", target, Phase.VULN_ANALYSIS, timeout=20)
    baseline_body = baseline_result.raw_output

    chain = EvidenceChain()
    chain = chain.set_baseline({"body_length": len(baseline_body)})

    results: list[dict] = []
    for payload, expected, engine_name in payloads:
        import urllib.parse
        encoded = urllib.parse.quote(payload)
        test_url = f"{url}{'&' if '?' in url else '?'}{parameter}={encoded}" if parameter else f"{url}?q={encoded}"
        cmd = f'curl -s -m 15 "{test_url}" 2>/dev/null'
        result = await runner.run(cmd, "vuln_ssti", target, Phase.VULN_ANALYSIS, timeout=20)

        ssti_chain = validate_ssti(
            output=result.raw_output,
            payload=payload,
            expected_render=expected,
            baseline_body=baseline_body,
        )
        if ssti_chain.total_weight > 0:
            chain = chain.add(
                signal=f"SSTI confirmed: {engine_name} — {payload!r} rendered to {expected!r}",
                source="vuln_ssti",
                raw_data=result.raw_output[:500],
                weight=ssti_chain.total_weight,
            )
            results.append({
                "payload": payload,
                "expected": expected,
                "engine": engine_name,
                "confidence": ssti_chain.confidence.value,
                "evidence": ssti_chain.summary(),
            })
            break  # one confirmed SSTI is enough

    metrics.record_run("vuln_ssti")
    if chain.total_weight > 0:
        metrics.record_finding("vuln_ssti", chain.confidence, chain.total_weight)

    return {
        "target": target,
        "parameter": parameter,
        "vulnerable": chain.total_weight >= 1.0,
        "confidence": chain.confidence.value,
        "evidence": chain.summary(),
        "ssti_results": results,
    }


async def vuln_nuclei_scan(
    target: str,
    templates: str = "cves,vulnerabilities",
    severity: str = "critical,high",
) -> dict:
    """Targeted Nuclei scan with confidence from template matchers.

    Nuclei's own matcher system provides evidence — we map its severity
    and matcher confidence to our evidence chain.

    Args:
        target: URL to scan
        templates: Template categories (comma-separated)
        severity: Severity filter
    """
    validate_scope(target)
    runner = get_runner()
    metrics = get_metrics()

    url = target if target.startswith("http") else f"https://{target}"
    template_flags = " ".join(f"-t {t}/" for t in templates.split(","))
    cmd = f"nuclei -u {url} {template_flags} -severity {severity} -json 2>/dev/null"

    result = await runner.run(cmd, "vuln_nuclei_scan", target, Phase.VULN_ANALYSIS, timeout=300)

    from kambo.parsers import parse_nuclei
    parsed = parse_nuclei(result.raw_output)

    # Build evidence from nuclei findings
    chain = EvidenceChain()
    for finding in parsed.get("findings", []):
        sev = finding.get("severity", "info")
        # Nuclei matchers are well-validated — weight by severity
        weight_map = {"critical": 1.5, "high": 1.0, "medium": 0.5, "low": 0.2, "info": 0.1}
        chain = chain.add(
            signal=f"Nuclei: {finding.get('template_id', 'unknown')} ({sev})",
            source="nuclei",
            raw_data=str(finding.get("matched_at", ""))[:500],
            weight=weight_map.get(sev, 0.1),
        )

    metrics.record_run("vuln_nuclei_scan")
    if chain.total_weight > 0:
        metrics.record_finding("vuln_nuclei_scan", chain.confidence, chain.total_weight)

    return {
        "target": target,
        "confidence": chain.confidence.value,
        "evidence": chain.summary(),
        **parsed,
    }


async def vuln_subdomain_takeover(target: str) -> dict:
    """Subdomain takeover detection with CNAME analysis and service fingerprinting.

    Goes beyond dangling CNAME detection — checks service-specific error pages
    to confirm the subdomain is actually claimable.

    Args:
        target: Domain to check for takeover
    """
    validate_scope(target)
    runner = get_runner()
    metrics = get_metrics()

    # Step 1: Check CNAME
    cmd = f"dig +short CNAME {target} 2>/dev/null"
    result = await runner.run(cmd, "vuln_subdomain_takeover", target, Phase.VULN_ANALYSIS, timeout=15)
    cname = result.raw_output.strip().rstrip(".")

    cname_resolves = False
    response_body = ""

    if cname:
        # Step 2: Check if CNAME target resolves
        cmd2 = f"dig +short {cname} 2>/dev/null"
        result2 = await runner.run(cmd2, "vuln_subdomain_takeover_resolve", target, Phase.VULN_ANALYSIS, timeout=15)
        cname_resolves = bool(result2.raw_output.strip())

        # Step 3: Fetch the page to check for service fingerprints
        cmd3 = f'curl -s -L -k "https://{target}" 2>/dev/null || curl -s -L -k "http://{target}" 2>/dev/null'
        result3 = await runner.run(cmd3, "vuln_subdomain_takeover_http", target, Phase.VULN_ANALYSIS, timeout=15)
        response_body = result3.raw_output

    chain = validate_subdomain_takeover(cname, cname_resolves, response_body)

    metrics.record_run("vuln_subdomain_takeover")
    if chain.total_weight > 0:
        metrics.record_finding("vuln_subdomain_takeover", chain.confidence, chain.total_weight)

    return {
        "target": target,
        "cname": cname,
        "cname_resolves": cname_resolves,
        "vulnerable": chain.total_weight >= 1.0,
        "confidence": chain.confidence.value,
        "evidence": chain.summary(),
    }
