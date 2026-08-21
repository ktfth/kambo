"""Phase 2: Scanning tools — port scanning, service detection, web fuzzing."""

from __future__ import annotations

from kambo.docker_runner import get_runner
from kambo.host_parse import is_request_path
from kambo.models import Phase
from kambo.parsers import parse_ffuf, parse_nmap
from kambo.parsers.generic_parser import parse_json_output
from kambo.rate_limiter import get_rate_limiter
from kambo.scope import ScopeViolationError, validate_scope


async def scan_ports_full(
    target: str,
    ports: str = "-",
    timing: int = 4,
    evasion: bool = False,
) -> dict:
    """Full TCP port scan.

    Args:
        target: IP, CIDR, or hostname
        ports: Port specification ('-' for all, or '1-1000')
        timing: Nmap timing template (0-5)
        evasion: Enable evasion techniques (-f, decoys)
    """
    validate_scope(target)
    runner = get_runner()

    cmd = f"nmap -sS -T{timing} -p {ports} --open -oX - {target} 2>/dev/null"
    if evasion:
        cmd = f"nmap -sS -T{min(timing, 2)} -p {ports} --open -f -D RND:5 --data-length 24 -oX - {target} 2>/dev/null"

    result = await runner.run(cmd, "scan_ports_full", target, Phase.SCANNING, timeout=600)
    parsed = parse_nmap(result.raw_output)

    return {
        "target": target,
        "scan_type": "full_tcp",
        "evasion": evasion,
        **parsed,
    }


async def scan_services(
    target: str,
    ports: str = "",
) -> dict:
    """Service and version detection on open ports.

    Args:
        target: IP or hostname
        ports: Specific ports to scan (e.g., '22,80,443'). Empty = top 1000.
    """
    validate_scope(target)
    runner = get_runner()

    port_flag = f"-p {ports}" if ports else ""
    cmd = f"nmap -sV -sC {port_flag} --open -oX - {target} 2>/dev/null"
    result = await runner.run(cmd, "scan_services", target, Phase.SCANNING, timeout=300)
    parsed = parse_nmap(result.raw_output)

    return {"target": target, "scan_type": "service_version", **parsed}


async def scan_udp(
    target: str,
    top_ports: int = 100,
) -> dict:
    """UDP port scan (top ports).

    Args:
        target: IP or hostname
        top_ports: Number of top UDP ports to scan
    """
    validate_scope(target)
    runner = get_runner()

    cmd = f"nmap -sU --top-ports {top_ports} --open -oX - {target} 2>/dev/null"
    result = await runner.run(cmd, "scan_udp", target, Phase.SCANNING, timeout=300)
    parsed = parse_nmap(result.raw_output)

    return {"target": target, "scan_type": "udp", **parsed}


async def scan_directories(
    target: str,
    wordlist: str = "/wordlists/seclists/Discovery/Web-Content/common.txt",
    extensions: str = "",
    match_codes: str = "200,301,302,403",
) -> dict:
    """Web directory and file fuzzing with ffuf.

    Integrates WAF detection and adaptive rate limiting — if a WAF is detected
    from a probe response, the scan rate is automatically reduced to avoid
    triggering blocks.

    Args:
        target: Base URL to fuzz (e.g., https://example.com)
        wordlist: Path to wordlist inside container
        extensions: Comma-separated extensions (e.g., 'php,bak,sql')
        match_codes: HTTP status codes to match
    """
    validate_scope(target)
    runner = get_runner()
    limiter = get_rate_limiter()

    url = target if target.startswith("http") else f"https://{target}"

    # WAF probe: check a known-good path before fuzzing at full speed
    probe_cmd = f'curl -s -D - "{url}/" 2>/dev/null | head -30'
    probe_result = await runner.run(probe_cmd, "scan_directories_waf_probe", target, Phase.SCANNING, timeout=10)

    # Record the probe response through the rate limiter to detect WAF/blocking
    probe_analysis = limiter.record_request(
        target,
        response_body=probe_result.raw_output,
        headers=probe_result.raw_output[:500],  # headers are in the first portion
    )

    # Adapt threading based on WAF detection
    threads = 10
    extra_flags = ""
    waf_name = probe_analysis.get("waf_detected") or ""
    if waf_name:
        threads = 2
        extra_flags = "-p 0.5"  # 500ms delay between requests — be polite to WAF
    elif probe_analysis.get("is_blocked"):
        threads = 3
        extra_flags = "-p 0.2"

    ext_flag = f"-e {extensions}" if extensions else ""
    cmd = (
        f"ffuf -u {url}/FUZZ -w {wordlist} -mc {match_codes} "
        f"{ext_flag} -t {threads} {extra_flags} "
        f"-o /tmp/ffuf_out.json -of json -s 2>/dev/null && cat /tmp/ffuf_out.json"
    )

    result = await runner.run(cmd, "scan_directories", target, Phase.SCANNING, timeout=120)
    parsed = parse_ffuf(result.raw_output)

    return {
        "target": target,
        "scan_type": "directory_fuzz",
        "waf_detected": bool(waf_name),
        "waf_name": waf_name,
        "rate_adapted": threads < 10,
        "evasion_tips": probe_analysis.get("evasion_tips", []),
        **parsed,
    }


async def scan_vhosts(
    target: str,
    wordlist: str = "/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    filter_size: int | None = None,
) -> dict:
    """Virtual host discovery via Host header fuzzing.

    Args:
        target: Base URL/IP
        wordlist: Subdomain wordlist
        filter_size: Response size to filter out (baseline)
    """
    validate_scope(target)
    runner = get_runner()

    url = target if target.startswith("http") else f"https://{target}"
    fs_flag = f"-fs {filter_size}" if filter_size else ""
    cmd = f'ffuf -u {url} -H "Host: FUZZ.{target}" -w {wordlist} -mc 200,301,302 {fs_flag} -o /tmp/vhost_out.json -of json -s 2>/dev/null && cat /tmp/vhost_out.json'

    result = await runner.run(cmd, "scan_vhosts", target, Phase.SCANNING, timeout=120)
    parsed = parse_ffuf(result.raw_output)

    return {"target": target, "scan_type": "vhost_fuzz", **parsed}


async def scan_parameters(
    target: str,
) -> dict:
    """Discover hidden parameters using Arjun.

    Args:
        target: URL to test for hidden parameters
    """
    validate_scope(target)
    runner = get_runner()

    url = target if target.startswith("http") else f"https://{target}"
    cmd = f"arjun -u {url} --stable 2>/dev/null"
    result = await runner.run(cmd, "scan_parameters", target, Phase.SCANNING, timeout=120)

    return {
        "target": target,
        "scan_type": "parameter_discovery",
        "raw": result.raw_output,
    }


async def scan_api_endpoints(
    target: str,
    swagger_paths: list[str] | None = None,
    wordlist: str = "/wordlists/api-common.txt",
) -> dict:
    """Discover API endpoints via Swagger/OpenAPI probing and fuzzing.

    Args:
        target: Base URL of the API
        swagger_paths: Paths to check for OpenAPI spec
        wordlist: API endpoint wordlist
    """
    validate_scope(target)
    runner = get_runner()

    url = target if target.startswith("http") else f"https://{target}"
    swagger_paths = swagger_paths or [
        "/swagger.json", "/openapi.json", "/api-docs", "/docs",
        "/swagger/v1/swagger.json", "/v1/swagger.json", "/v2/swagger.json",
    ]

    # Check common spec paths. Each path is caller-supplied and is concatenated
    # onto the validated base URL, so a value starting with "@" would demote the
    # validated host to URL userinfo and re-point the probe at another host —
    # and the same string lands inside a shell command. Every path is required
    # to be a plain request path and the assembled URL is re-validated.
    spec_urls = []
    for p in swagger_paths:
        if not is_request_path(p):
            raise ScopeViolationError(
                p,
                "swagger path must be a plain absolute request path — no scheme, "
                "no '@', no shell metacharacters",
            )
        spec_url = f"{url}{p}"
        validate_scope(spec_url)
        spec_urls.append(spec_url)

    checks = " ".join(f'"{u}"' for u in spec_urls)
    cmd = f"for u in {checks}; do code=$(curl -s -o /dev/null -w '%{{http_code}}' $u 2>/dev/null); echo \"$code $u\"; done"
    result = await runner.run(cmd, "scan_api_endpoints_spec", target, Phase.SCANNING, timeout=60)

    found_specs = []
    for line in result.raw_output.splitlines():
        if line.startswith("200 "):
            found_specs.append(line.split(" ", 1)[1])

    # Fuzz API paths
    cmd2 = f"ffuf -u {url}/FUZZ -w {wordlist} -mc 200,201,204,301,302,401,403,405 -o /tmp/api_out.json -of json -s 2>/dev/null && cat /tmp/api_out.json"
    result2 = await runner.run(cmd2, "scan_api_endpoints_fuzz", target, Phase.SCANNING, timeout=120)
    parsed = parse_ffuf(result2.raw_output)

    return {
        "target": target,
        "scan_type": "api_discovery",
        "swagger_specs_found": found_specs,
        "endpoints": parsed.get("results", []),
        "total_endpoints": parsed.get("total", 0),
    }


async def scan_vulns(
    target: str,
    severity: str = "critical,high,medium",
    templates: list[str] | None = None,
) -> dict:
    """Run Nuclei vulnerability scanner.

    Args:
        target: URL or list file to scan
        severity: Minimum severity filter
        templates: Specific template paths/tags
    """
    validate_scope(target)
    runner = get_runner()

    url = target if target.startswith("http") else f"https://{target}"
    template_flag = " ".join(f"-t {t}" for t in templates) if templates else ""
    cmd = f"nuclei -u {url} -severity {severity} {template_flag} -json 2>/dev/null"
    result = await runner.run(cmd, "scan_vulns", target, Phase.SCANNING, timeout=300)

    from kambo.parsers import parse_nuclei
    parsed = parse_nuclei(result.raw_output)

    return {"target": target, "scan_type": "nuclei", **parsed}


async def scan_cms(
    target: str,
) -> dict:
    """Detect and scan CMS (WordPress, Joomla, etc.).

    Args:
        target: URL to scan
    """
    validate_scope(target)
    runner = get_runner()

    url = target if target.startswith("http") else f"https://{target}"
    cmd = f"wpscan --url {url} --enumerate p,t,u --no-banner --format json 2>/dev/null"
    result = await runner.run(cmd, "scan_cms", target, Phase.SCANNING, timeout=180)
    parsed = parse_json_output(result.raw_output)

    return {
        "target": target,
        "scan_type": "cms",
        "data": parsed or {"raw": result.raw_output[:5000]},
    }


async def scan_tls(target: str) -> dict:
    """SSL/TLS configuration analysis.

    Args:
        target: Hostname:port to analyze
    """
    validate_scope(target)
    runner = get_runner()

    host = target.replace("https://", "").replace("http://", "").split("/")[0]
    if ":" not in host:
        host = f"{host}:443"

    cmd = f"testssl.sh --quiet --color 0 {host} 2>/dev/null | head -100"
    result = await runner.run(cmd, "scan_tls", target, Phase.SCANNING, timeout=120)

    return {
        "target": target,
        "scan_type": "tls",
        "analysis": result.raw_output,
    }
