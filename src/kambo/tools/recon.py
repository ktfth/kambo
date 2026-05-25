"""Phase 1: Reconnaissance — quantified, source-attributed, wildcard-aware."""

from __future__ import annotations

import re

from kambo.docker_runner import get_runner
from kambo.metrics import get_metrics
from kambo.models import Phase, ToolResult
from kambo.parsers import parse_subfinder
from kambo.parsers.generic_parser import extract_domains, parse_json_output, parse_lines
from kambo.sanitize import shell_quote, validate_port_spec
from kambo.scope import validate_scope


async def recon_subdomains(
    target: str,
    methods: list[str] | None = None,
) -> dict:
    """Enumerate subdomains with source attribution and wildcard detection.

    Each subdomain is tagged with which source(s) found it. Wildcard DNS
    records are detected and flagged to prevent inflated counts.

    Args:
        target: Root domain to enumerate (e.g., example.com)
        methods: Sources to use. Options: crtsh, subfinder, amass, dnsenum
    """
    validate_scope(target)
    methods = methods or ["crtsh", "subfinder"]
    runner = get_runner()
    metrics = get_metrics()

    # Track which sources found each subdomain
    subdomain_sources: dict[str, list[str]] = {}
    results_by_source: dict[str, list[str]] = {}
    source_durations: dict[str, float] = {}

    for method in methods:
        cmd = _build_subdomain_command(shell_quote(target), method)
        result = await runner.run(cmd, f"recon_subdomains_{method}", target, Phase.RECON)
        source_durations[method] = result.duration_seconds

        if result.exit_code == 0 and result.raw_output:
            parsed = parse_subfinder(result.raw_output)
            subs = parsed.get("subdomains", [])
            results_by_source[method] = subs
            for sub in subs:
                subdomain_sources.setdefault(sub, []).append(method)

    # Wildcard detection: resolve a random subdomain
    wildcard_detected = False
    wildcard_ip = ""
    random_sub = f"kambo-wildcard-test-{id(target) % 99999}.{target}"
    wc_cmd = f"dig +short {shell_quote(random_sub)} 2>/dev/null"
    wc_result = await runner.run(wc_cmd, "recon_wildcard_check", target, Phase.RECON, timeout=10)
    if wc_result.raw_output.strip():
        wildcard_detected = True
        wildcard_ip = wc_result.raw_output.strip().splitlines()[0]

    # Cross-source confidence: subdomains found by multiple sources are more reliable
    multi_source = [sub for sub, sources in subdomain_sources.items() if len(sources) >= 2]
    single_source = [sub for sub, sources in subdomain_sources.items() if len(sources) == 1]

    all_subdomains = sorted(subdomain_sources.keys())

    metrics.record_run("recon_subdomains")

    return {
        "target": target,
        "subdomains": all_subdomains,
        "total": len(all_subdomains),
        "by_source": {k: len(v) for k, v in results_by_source.items()},
        "source_durations": {k: round(v, 1) for k, v in source_durations.items()},
        "cross_validated": {
            "multi_source_count": len(multi_source),
            "single_source_count": len(single_source),
            "multi_source_examples": multi_source[:10],
        },
        "wildcard": {
            "detected": wildcard_detected,
            "ip": wildcard_ip,
            "warning": "Wildcard DNS detected — subdomain count may be inflated" if wildcard_detected else "",
        },
        "attribution": {
            sub: sources for sub, sources in sorted(subdomain_sources.items())
        } if len(subdomain_sources) <= 100 else f"{len(subdomain_sources)} subdomains (attribution truncated)",
    }


async def recon_dns(
    target: str,
    checks: list[str] | None = None,
) -> dict:
    """DNS enumeration with quantified results.

    Args:
        target: Domain to enumerate
        checks: Types of checks. Options: axfr, records, brute
    """
    validate_scope(target)
    checks = checks or ["records", "axfr"]
    runner = get_runner()
    metrics = get_metrics()
    results: dict = {"target": target, "records": {}, "axfr": None, "brute": []}

    qt = shell_quote(target)

    if "records" in checks:
        cmd = f"dnsrecon -d {qt} -t std 2>/dev/null"
        result = await runner.run(cmd, "recon_dns_records", target, Phase.RECON)
        results["records"] = {"raw": result.raw_output}

    if "axfr" in checks:
        cmd = f"dnsrecon -d {qt} -t axfr 2>/dev/null"
        result = await runner.run(cmd, "recon_dns_axfr", target, Phase.RECON)
        axfr_success = "successful" in result.raw_output.lower()
        results["axfr"] = {
            "success": axfr_success,
            "data": result.raw_output if axfr_success else None,
            "note": "Zone transfer allowed — full DNS dump available" if axfr_success else "Zone transfer denied (expected)",
        }

    if "brute" in checks:
        cmd = f"dnsenum --noreverse -f /wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt {qt} 2>/dev/null | head -200"
        result = await runner.run(cmd, "recon_dns_brute", target, Phase.RECON)
        brute_domains = extract_domains(result.raw_output)
        results["brute"] = brute_domains
        results["brute_count"] = len(brute_domains)

    metrics.record_run("recon_dns")

    return results


async def recon_ports_fast(
    target: str,
    ports: str = "80,443,8080,8443,8000,3000,5000,9090,9443",
) -> dict:
    """Quick port discovery with service hints.

    Args:
        target: IP, CIDR, or domain to scan
        ports: Comma-separated ports or range
    """
    validate_scope(target)
    runner = get_runner()
    metrics = get_metrics()

    ports = validate_port_spec(ports)
    cmd = f"nmap -sS -T4 -p {ports} --open -oG - {shell_quote(target)} 2>/dev/null"
    result = await runner.run(cmd, "recon_ports_fast", target, Phase.RECON)

    open_ports: list[dict] = []
    for line in result.raw_output.splitlines():
        if "Ports:" in line:
            parts = line.split("Ports:")[1].strip()
            for port_info in parts.split(","):
                segments = port_info.strip().split("/")
                if len(segments) >= 3 and segments[1] == "open":
                    open_ports.append({
                        "port": int(segments[0]),
                        "protocol": segments[2],
                        "service": segments[4] if len(segments) > 4 else "",
                    })

    metrics.record_run("recon_ports_fast")

    return {
        "target": target,
        "open_ports": open_ports,
        "total": len(open_ports),
        "scan_duration": round(result.duration_seconds, 1),
    }


async def recon_tech_stack(target: str) -> dict:
    """Technology fingerprinting with structured output.

    Args:
        target: URL or domain to fingerprint
    """
    validate_scope(target)
    runner = get_runner()
    metrics = get_metrics()

    url = target if target.startswith("http") else f"https://{target}"
    cmd = f"whatweb -a 3 --color=never {shell_quote(url)} 2>/dev/null"
    result = await runner.run(cmd, "recon_tech_stack", target, Phase.RECON)

    # Extract technology names from whatweb output
    techs: list[str] = []
    for match in re.findall(r"\[([^\]]+)\]", result.raw_output):
        cleaned = match.strip()
        if cleaned and not cleaned.startswith("http") and len(cleaned) < 50:
            techs.append(cleaned)

    metrics.record_run("recon_tech_stack")

    return {
        "target": target,
        "technologies": list(dict.fromkeys(techs)),  # deduplicated, order preserved
        "tech_count": len(set(techs)),
        "raw": result.raw_output,
    }


async def recon_waf(target: str) -> dict:
    """WAF/CDN detection.

    Args:
        target: URL or domain to check
    """
    validate_scope(target)
    runner = get_runner()
    metrics = get_metrics()

    url = target if target.startswith("http") else f"https://{target}"
    cmd = f"wafw00f {shell_quote(url)} 2>/dev/null"
    result = await runner.run(cmd, "recon_waf", target, Phase.RECON)

    detected = "is behind" in result.raw_output
    waf_name = ""
    if detected:
        for line in result.raw_output.splitlines():
            if "is behind" in line:
                waf_name = line.split("is behind")[-1].strip().rstrip(".")
                break

    metrics.record_run("recon_waf")

    return {
        "target": target,
        "waf_detected": detected,
        "waf_name": waf_name,
        "impact": "Direct scanning may be blocked — consider evasion techniques" if detected else "No WAF detected — direct scanning viable",
        "raw": result.raw_output,
    }


async def recon_certs(target: str) -> dict:
    """Certificate transparency log enumeration.

    Args:
        target: Root domain to query
    """
    validate_scope(target)
    runner = get_runner()
    metrics = get_metrics()

    cmd = f'curl -s "https://crt.sh/?q=%25."{shell_quote(target)}"&output=json" 2>/dev/null | jq -r ".[].name_value" 2>/dev/null | sort -u'
    result = await runner.run(cmd, "recon_certs", target, Phase.RECON, timeout=60)

    domains = [d.strip() for d in result.raw_output.splitlines() if d.strip() and "." in d]
    unique_domains = sorted(set(domains))

    metrics.record_run("recon_certs")

    return {
        "target": target,
        "subdomains": unique_domains,
        "total": len(unique_domains),
        "source": "crt.sh",
    }


async def recon_asn(target: str) -> dict:
    """ASN and IP block enumeration.

    Args:
        target: Organization name or domain
    """
    validate_scope(target)
    runner = get_runner()
    metrics = get_metrics()

    cmd = f'curl -s "https://api.bgpview.io/search?query_term="{shell_quote(target)} 2>/dev/null | jq ".data" 2>/dev/null'
    result = await runner.run(cmd, "recon_asn", target, Phase.RECON, timeout=30)

    parsed = parse_json_output(result.raw_output)

    metrics.record_run("recon_asn")

    return {
        "target": target,
        "data": parsed or {},
        "raw": result.raw_output[:5000],
    }


def _build_subdomain_command(quoted_target: str, method: str) -> str:
    """Build shell command for a specific subdomain enumeration method.

    Args:
        quoted_target: Already shlex-quoted target string.
        method: Enumeration method name (validated against whitelist).
    """
    commands = {
        "subfinder": f"subfinder -d {quoted_target} -silent 2>/dev/null",
        "amass": f"amass enum -passive -d {quoted_target} 2>/dev/null",
        "crtsh": f'curl -s "https://crt.sh/?q=%25."{quoted_target}"&output=json" 2>/dev/null | jq -r ".[].name_value" 2>/dev/null | sort -u',
        "dnsenum": f"dnsenum --noreverse {quoted_target} 2>/dev/null | sort -u",
    }
    if method not in commands:
        return "echo 'Unknown method'"
    return commands[method]
