"""Phase 1: Reconnaissance / Information Gathering tools."""

from __future__ import annotations

from kambo.docker_runner import get_runner
from kambo.models import Phase, ToolResult
from kambo.parsers import parse_subfinder
from kambo.parsers.generic_parser import extract_domains, parse_json_output, parse_lines
from kambo.scope import validate_scope


async def recon_subdomains(
    target: str,
    methods: list[str] | None = None,
) -> dict:
    """Enumerate subdomains using multiple sources.

    Args:
        target: Root domain to enumerate (e.g., example.com)
        methods: Sources to use. Options: crtsh, subfinder, amass, dnsenum
    """
    validate_scope(target)
    methods = methods or ["crtsh", "subfinder"]
    runner = get_runner()
    all_subdomains: set[str] = set()
    results_by_source: dict[str, list[str]] = {}

    for method in methods:
        cmd = _build_subdomain_command(target, method)
        result = await runner.run(cmd, f"recon_subdomains_{method}", target, Phase.RECON)

        if result.exit_code == 0 and result.raw_output:
            parsed = parse_subfinder(result.raw_output)
            subs = parsed.get("subdomains", [])
            all_subdomains.update(subs)
            results_by_source[method] = subs

    return {
        "target": target,
        "subdomains": sorted(all_subdomains),
        "total": len(all_subdomains),
        "by_source": {k: len(v) for k, v in results_by_source.items()},
    }


async def recon_dns(
    target: str,
    checks: list[str] | None = None,
) -> dict:
    """DNS enumeration including zone transfer attempts, record queries, brute force.

    Args:
        target: Domain to enumerate
        checks: Types of checks. Options: axfr, records, brute
    """
    validate_scope(target)
    checks = checks or ["records", "axfr"]
    runner = get_runner()
    results: dict = {"target": target, "records": {}, "axfr": None, "brute": []}

    if "records" in checks:
        cmd = f"dnsrecon -d {target} -t std 2>/dev/null"
        result = await runner.run(cmd, "recon_dns_records", target, Phase.RECON)
        results["records"] = {"raw": result.raw_output}

    if "axfr" in checks:
        cmd = f"dnsrecon -d {target} -t axfr 2>/dev/null"
        result = await runner.run(cmd, "recon_dns_axfr", target, Phase.RECON)
        results["axfr"] = result.raw_output if "successful" in result.raw_output.lower() else None

    if "brute" in checks:
        cmd = f"dnsenum --noreverse -f /wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt {target} 2>/dev/null | head -200"
        result = await runner.run(cmd, "recon_dns_brute", target, Phase.RECON)
        results["brute"] = extract_domains(result.raw_output)

    return results


async def recon_ports_fast(
    target: str,
    ports: str = "80,443,8080,8443,8000,3000,5000,9090,9443",
) -> dict:
    """Quick port discovery using masscan or nmap fast mode.

    Args:
        target: IP, CIDR, or domain to scan
        ports: Comma-separated ports or range (e.g., '1-65535')
    """
    validate_scope(target)
    runner = get_runner()

    cmd = f"nmap -sS -T4 -p {ports} --open -oG - {target} 2>/dev/null"
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

    return {
        "target": target,
        "open_ports": open_ports,
        "total": len(open_ports),
    }


async def recon_tech_stack(target: str) -> dict:
    """Identify technology stack using whatweb and httpx.

    Args:
        target: URL or domain to fingerprint
    """
    validate_scope(target)
    runner = get_runner()

    url = target if target.startswith("http") else f"https://{target}"
    cmd = f"whatweb -a 3 --color=never {url} 2>/dev/null"
    result = await runner.run(cmd, "recon_tech_stack", target, Phase.RECON)

    return {
        "target": target,
        "technologies": result.raw_output,
        "raw": result.raw_output,
    }


async def recon_waf(target: str) -> dict:
    """Detect WAF/CDN in front of target.

    Args:
        target: URL or domain to check
    """
    validate_scope(target)
    runner = get_runner()

    url = target if target.startswith("http") else f"https://{target}"
    cmd = f"wafw00f {url} 2>/dev/null"
    result = await runner.run(cmd, "recon_waf", target, Phase.RECON)

    detected = "is behind" in result.raw_output
    waf_name = ""
    if detected:
        for line in result.raw_output.splitlines():
            if "is behind" in line:
                waf_name = line.split("is behind")[-1].strip().rstrip(".")
                break

    return {
        "target": target,
        "waf_detected": detected,
        "waf_name": waf_name,
        "raw": result.raw_output,
    }


async def recon_certs(target: str) -> dict:
    """Query certificate transparency logs (crt.sh) for subdomains.

    Args:
        target: Root domain to query
    """
    validate_scope(target)
    runner = get_runner()

    cmd = f'curl -s "https://crt.sh/?q=%25.{target}&output=json" 2>/dev/null | jq -r ".[].name_value" 2>/dev/null | sort -u'
    result = await runner.run(cmd, "recon_certs", target, Phase.RECON, timeout=60)

    domains = [d.strip() for d in result.raw_output.splitlines() if d.strip() and "." in d]
    unique_domains = sorted(set(domains))

    return {
        "target": target,
        "subdomains": unique_domains,
        "total": len(unique_domains),
        "source": "crt.sh",
    }


async def recon_asn(target: str) -> dict:
    """Enumerate ASN and IP blocks for an organization.

    Args:
        target: Organization name or domain
    """
    validate_scope(target)
    runner = get_runner()

    cmd = f'curl -s "https://api.bgpview.io/search?query_term={target}" 2>/dev/null | jq ".data" 2>/dev/null'
    result = await runner.run(cmd, "recon_asn", target, Phase.RECON, timeout=30)

    parsed = parse_json_output(result.raw_output)
    return {
        "target": target,
        "data": parsed or {},
        "raw": result.raw_output[:5000],
    }


def _build_subdomain_command(target: str, method: str) -> str:
    """Build shell command for a specific subdomain enumeration method."""
    commands = {
        "subfinder": f"subfinder -d {target} -silent 2>/dev/null",
        "amass": f"amass enum -passive -d {target} 2>/dev/null",
        "crtsh": f'curl -s "https://crt.sh/?q=%25.{target}&output=json" 2>/dev/null | jq -r ".[].name_value" 2>/dev/null | sort -u',
        "dnsenum": f"dnsenum --noreverse {target} 2>/dev/null | grep -oP '[\\w.-]+\\.{target}' | sort -u",
    }
    return commands.get(method, f"echo 'Unknown method: {method}'")
