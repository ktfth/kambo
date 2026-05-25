"""Phase 2: Scanning tools — port scanning, service detection, web fuzzing."""

from __future__ import annotations

from kambo.docker_runner import get_runner
from kambo.models import Phase
from kambo.parsers import parse_ffuf, parse_nmap
from kambo.parsers.generic_parser import parse_json_output
from kambo.sanitize import shell_quote, validate_port_spec, validate_severity, validate_timing
from kambo.scope import validate_scope


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

    timing = validate_timing(timing)
    ports = validate_port_spec(ports)
    qt = shell_quote(target)
    cmd = f"nmap -sS -T{timing} -p {ports} --open -oX - {qt} 2>/dev/null"
    if evasion:
        cmd = f"nmap -sS -T{min(timing, 2)} -p {ports} --open -f -D RND:5 --data-length 24 -oX - {qt} 2>/dev/null"

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

    port_flag = f"-p {validate_port_spec(ports)}" if ports else ""
    cmd = f"nmap -sV -sC {port_flag} --open -oX - {shell_quote(target)} 2>/dev/null"
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

    if not isinstance(top_ports, int) or top_ports < 1 or top_ports > 65535:
        raise ValueError(f"Invalid top_ports: {top_ports}")
    cmd = f"nmap -sU --top-ports {top_ports} --open -oX - {shell_quote(target)} 2>/dev/null"
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

    Args:
        target: Base URL to fuzz (e.g., https://example.com)
        wordlist: Path to wordlist inside container
        extensions: Comma-separated extensions (e.g., 'php,bak,sql')
        match_codes: HTTP status codes to match
    """
    validate_scope(target)
    runner = get_runner()

    url = target if target.startswith("http") else f"https://{target}"
    ext_flag = f"-e {shell_quote(extensions)}" if extensions else ""
    cmd = f"ffuf -u {shell_quote(url)}/FUZZ -w {shell_quote(wordlist)} -mc {shell_quote(match_codes)} {ext_flag} -o /tmp/ffuf_out.json -of json -s 2>/dev/null && cat /tmp/ffuf_out.json"

    result = await runner.run(cmd, "scan_directories", target, Phase.SCANNING, timeout=120)
    parsed = parse_ffuf(result.raw_output)

    return {"target": target, "scan_type": "directory_fuzz", **parsed}


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
    if filter_size is not None and (not isinstance(filter_size, int) or filter_size < 0):
        raise ValueError(f"Invalid filter_size: {filter_size}")
    fs_flag = f"-fs {filter_size}" if filter_size else ""
    qu = shell_quote(url)
    qt = shell_quote(target)
    cmd = f'ffuf -u {qu} -H "Host: FUZZ."{qt} -w {shell_quote(wordlist)} -mc 200,301,302 {fs_flag} -o /tmp/vhost_out.json -of json -s 2>/dev/null && cat /tmp/vhost_out.json'

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
    cmd = f"arjun -u {shell_quote(url)} --stable 2>/dev/null"
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

    qu = shell_quote(url)
    checks = " ".join(shell_quote(f"{url}{p}") for p in swagger_paths)
    cmd = f"for u in {checks}; do code=$(curl -s -o /dev/null -w '%{{http_code}}' \"$u\" 2>/dev/null); echo \"$code $u\"; done"
    result = await runner.run(cmd, "scan_api_endpoints_spec", target, Phase.SCANNING, timeout=60)

    found_specs = []
    for line in result.raw_output.splitlines():
        if line.startswith("200 "):
            found_specs.append(line.split(" ", 1)[1])

    cmd2 = f"ffuf -u {qu}/FUZZ -w {shell_quote(wordlist)} -mc 200,201,204,301,302,401,403,405 -o /tmp/api_out.json -of json -s 2>/dev/null && cat /tmp/api_out.json"
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
    severity = validate_severity(severity)
    template_flag = " ".join(f"-t {shell_quote(t)}" for t in templates) if templates else ""
    cmd = f"nuclei -u {shell_quote(url)} -severity {severity} {template_flag} -json 2>/dev/null"
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
    cmd = f"wpscan --url {shell_quote(url)} --enumerate p,t,u --no-banner --format json 2>/dev/null"
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

    cmd = f"testssl.sh --quiet --color 0 {shell_quote(host)} 2>/dev/null | head -100"
    result = await runner.run(cmd, "scan_tls", target, Phase.SCANNING, timeout=120)

    return {
        "target": target,
        "scan_type": "tls",
        "analysis": result.raw_output,
    }
