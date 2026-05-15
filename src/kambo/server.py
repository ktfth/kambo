"""Kambo MCP Server — main entry point."""

from __future__ import annotations

import asyncio
import json

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    GetPromptResult,
    Prompt,
    PromptArgument,
    PromptMessage,
    Resource,
    TextContent,
    Tool,
)

from kambo.config import get_config
from kambo.database import get_database
from kambo.docker_runner import get_runner
from kambo.models import Context, EngagementScope, ScopeTarget
from kambo.prompts.api_assessment import get_api_assessment_prompt
from kambo.prompts.bug_bounty import get_bug_bounty_prompt
from kambo.prompts.full_pentest import get_full_pentest_prompt
from kambo.resources.findings_resource import get_findings_data
from kambo.resources.scope_resource import get_scope_data
from kambo.resources.session_resource import get_session_data
from kambo.scope import get_scope_manager
from kambo.tools import recon, scanning, vulns, exploit, post_exploit, reporting, api_security, cloud, containers, ad

# Create the MCP server
server = Server("kambo")


# === TOOLS ===

@server.list_tools()
async def list_tools() -> list[Tool]:
    """List all available pentest tools."""
    return [
        # Scope Management
        Tool(name="set_scope", description="Configure engagement scope (targets, exclusions, context)", inputSchema={
            "type": "object",
            "properties": {
                "targets": {"type": "array", "items": {"type": "string"}, "description": "List of in-scope targets (domains, IPs, CIDRs)"},
                "context": {"type": "string", "enum": ["pentest", "bug_bounty", "ctf"], "description": "Engagement context"},
                "platform": {"type": "string", "description": "Bug bounty platform (hackerone, bugcrowd, etc.)"},
                "exclusions": {"type": "array", "items": {"type": "string"}, "description": "Out-of-scope targets"},
                "engagement_id": {"type": "string", "description": "Engagement identifier"},
            },
            "required": ["targets", "context"],
        }),
        # Phase 1: Recon
        Tool(name="recon_subdomains", description="Enumerate subdomains using crt.sh, subfinder, amass", inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Root domain (e.g., example.com)"},
                "methods": {"type": "array", "items": {"type": "string"}, "description": "Sources: crtsh, subfinder, amass, dnsenum"},
            },
            "required": ["target"],
        }),
        Tool(name="recon_dns", description="DNS enumeration (zone transfer, records, brute force)", inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Domain to enumerate"},
                "checks": {"type": "array", "items": {"type": "string"}, "description": "Check types: axfr, records, brute"},
            },
            "required": ["target"],
        }),
        Tool(name="recon_ports_fast", description="Quick port discovery on common ports", inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP, CIDR, or domain"},
                "ports": {"type": "string", "description": "Port specification"},
            },
            "required": ["target"],
        }),
        Tool(name="recon_tech_stack", description="Technology fingerprinting (whatweb, httpx)", inputSchema={
            "type": "object",
            "properties": {"target": {"type": "string", "description": "URL or domain"}},
            "required": ["target"],
        }),
        Tool(name="recon_waf", description="WAF/CDN detection", inputSchema={
            "type": "object",
            "properties": {"target": {"type": "string", "description": "URL or domain"}},
            "required": ["target"],
        }),
        Tool(name="recon_certs", description="Certificate transparency log enumeration", inputSchema={
            "type": "object",
            "properties": {"target": {"type": "string", "description": "Root domain"}},
            "required": ["target"],
        }),
        Tool(name="recon_asn", description="ASN and IP block enumeration", inputSchema={
            "type": "object",
            "properties": {"target": {"type": "string", "description": "Organization or domain"}},
            "required": ["target"],
        }),
        # Phase 2: Scanning
        Tool(name="scan_ports_full", description="Full TCP port scan with nmap", inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "ports": {"type": "string", "description": "Port range (default: all)"},
                "timing": {"type": "integer", "description": "Nmap timing 0-5"},
                "evasion": {"type": "boolean", "description": "Enable evasion techniques"},
            },
            "required": ["target"],
        }),
        Tool(name="scan_services", description="Service/version detection on open ports", inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "ports": {"type": "string", "description": "Specific ports to scan"},
            },
            "required": ["target"],
        }),
        Tool(name="scan_directories", description="Web directory fuzzing with ffuf", inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Base URL"},
                "wordlist": {"type": "string"},
                "extensions": {"type": "string", "description": "File extensions to check"},
            },
            "required": ["target"],
        }),
        Tool(name="scan_api_endpoints", description="API endpoint discovery (Swagger, fuzzing)", inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "API base URL"},
                "swagger_paths": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["target"],
        }),
        Tool(name="scan_vulns", description="Nuclei vulnerability scanner", inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "severity": {"type": "string", "description": "Severity filter"},
                "templates": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["target"],
        }),
        Tool(name="scan_vhosts", description="Virtual host discovery via Host header", inputSchema={
            "type": "object",
            "properties": {"target": {"type": "string"}, "filter_size": {"type": "integer"}},
            "required": ["target"],
        }),
        Tool(name="scan_parameters", description="Hidden parameter discovery with Arjun", inputSchema={
            "type": "object",
            "properties": {"target": {"type": "string", "description": "URL to test"}},
            "required": ["target"],
        }),
        Tool(name="scan_tls", description="SSL/TLS configuration analysis", inputSchema={
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
        }),
        # Phase 3: Vulnerability Analysis
        Tool(name="vuln_sqli", description="SQL Injection detection with sqlmap", inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "URL with parameter"},
                "parameter": {"type": "string"},
                "level": {"type": "integer"},
                "risk": {"type": "integer"},
            },
            "required": ["target"],
        }),
        Tool(name="vuln_xss", description="XSS reflection detection", inputSchema={
            "type": "object",
            "properties": {"target": {"type": "string"}, "parameter": {"type": "string"}},
            "required": ["target"],
        }),
        Tool(name="vuln_ssrf", description="SSRF testing with internal target probing", inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "parameter": {"type": "string"},
                "callback_url": {"type": "string"},
            },
            "required": ["target"],
        }),
        Tool(name="vuln_jwt", description="JWT token analysis and weakness testing", inputSchema={
            "type": "object",
            "properties": {"target": {"type": "string"}, "token": {"type": "string"}},
            "required": ["target", "token"],
        }),
        Tool(name="vuln_cors", description="CORS misconfiguration testing", inputSchema={
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
        }),
        Tool(name="vuln_idor", description="IDOR/BOLA testing via ID enumeration", inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "API endpoint with {id}"},
                "token": {"type": "string"},
                "id_range": {"type": "array", "items": {"type": "integer"}, "description": "[start, end]"},
            },
            "required": ["target", "token"],
        }),
        Tool(name="vuln_subdomain_takeover", description="Subdomain takeover via dangling CNAME", inputSchema={
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
        }),
        # Phase 4: Exploitation
        Tool(name="exploit_sqli", description="SQL Injection exploitation (extract data)", inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "parameter": {"type": "string"},
                "action": {"type": "string", "enum": ["dbs", "tables", "dump", "current-user"]},
            },
            "required": ["target"],
        }),
        Tool(name="exploit_password_spray", description="Password spraying against services", inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "users": {"type": "array", "items": {"type": "string"}},
                "password": {"type": "string"},
                "service": {"type": "string", "enum": ["ssh", "smb", "ftp", "rdp"]},
            },
            "required": ["target", "password"],
        }),
        Tool(name="exploit_ssrf", description="SSRF exploitation for internal access", inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "parameter": {"type": "string"},
                "internal_target": {"type": "string"},
            },
            "required": ["target"],
        }),
        # Phase 5: Post-Exploitation
        Tool(name="post_privesc_linux", description="Linux privilege escalation enumeration", inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "method": {"type": "string", "enum": ["linpeas", "manual", "suid", "sudo", "capabilities"]},
            },
            "required": ["target"],
        }),
        Tool(name="post_ad_enum", description="Active Directory enumeration (BloodHound)", inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "DC IP"},
                "domain": {"type": "string"},
                "username": {"type": "string"},
                "password": {"type": "string"},
                "method": {"type": "string", "enum": ["bloodhound", "ldapsearch", "crackmapexec"]},
            },
            "required": ["target", "domain", "username", "password"],
        }),
        Tool(name="post_kerberoast", description="Kerberoasting — extract service ticket hashes", inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string"}, "domain": {"type": "string"},
                "username": {"type": "string"}, "password": {"type": "string"},
            },
            "required": ["target", "domain", "username", "password"],
        }),
        Tool(name="post_lateral_move", description="Lateral movement (PtH, WMI, PSExec)", inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "username": {"type": "string"},
                "ntlm_hash": {"type": "string"},
                "method": {"type": "string", "enum": ["pass_the_hash", "wmiexec", "psexec", "evil_winrm"]},
            },
            "required": ["target", "username"],
        }),
        # API Security
        Tool(name="api_test_bola", description="BOLA testing (API1:2023) — horizontal authz bypass", inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "user_a_token": {"type": "string"},
                "user_b_token": {"type": "string"},
                "endpoints": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["target", "user_a_token", "user_b_token"],
        }),
        Tool(name="api_test_bfla", description="BFLA testing (API5:2023) — vertical authz bypass", inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "regular_token": {"type": "string"},
                "admin_endpoints": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["target", "regular_token"],
        }),
        Tool(name="api_test_misconfig", description="API misconfiguration testing (API8:2023)", inputSchema={
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
        }),
        # Cloud
        Tool(name="cloud_imds_test", description="SSRF to cloud metadata service (AWS/Azure/GCP)", inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "parameter": {"type": "string"},
                "cloud_provider": {"type": "string", "enum": ["aws", "azure", "gcp"]},
            },
            "required": ["target"],
        }),
        Tool(name="cloud_storage_enum", description="Public cloud storage enumeration (S3/Blob/GCS)", inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "cloud_provider": {"type": "string", "enum": ["aws", "azure", "gcp"]},
            },
            "required": ["target"],
        }),
        Tool(name="cloud_secret_scan", description="Scan for exposed secrets in repos", inputSchema={
            "type": "object",
            "properties": {"target": {"type": "string"}, "repo_url": {"type": "string"}},
            "required": ["target"],
        }),
        # Reporting
        Tool(name="report_finding", description="Create and store a security finding", inputSchema={
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                "target": {"type": "string"},
                "description": {"type": "string"},
                "reproduction_steps": {"type": "array", "items": {"type": "string"}},
                "impact": {"type": "string"},
                "remediation": {"type": "string"},
                "cvss": {"type": "number"},
            },
            "required": ["title", "severity", "target", "description"],
        }),
        Tool(name="report_cvss", description="Calculate CVSS 3.1 score", inputSchema={
            "type": "object",
            "properties": {
                "attack_vector": {"type": "string", "enum": ["N", "A", "L", "P"]},
                "attack_complexity": {"type": "string", "enum": ["L", "H"]},
                "privileges_required": {"type": "string", "enum": ["N", "L", "H"]},
                "user_interaction": {"type": "string", "enum": ["N", "R"]},
                "scope": {"type": "string", "enum": ["U", "C"]},
                "confidentiality": {"type": "string", "enum": ["N", "L", "H"]},
                "integrity": {"type": "string", "enum": ["N", "L", "H"]},
                "availability": {"type": "string", "enum": ["N", "L", "H"]},
            },
        }),
        Tool(name="report_export", description="Export findings as markdown or JSON report", inputSchema={
            "type": "object",
            "properties": {
                "format": {"type": "string", "enum": ["markdown", "json"]},
                "template": {"type": "string", "enum": ["pentest", "bug_bounty", "api_assessment"]},
            },
        }),
        Tool(name="report_bounty_template", description="Generate bug bounty report template", inputSchema={
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "severity": {"type": "string"},
                "target": {"type": "string"},
                "description": {"type": "string"},
                "steps": {"type": "array", "items": {"type": "string"}},
                "poc": {"type": "string"},
                "impact": {"type": "string"},
                "fix": {"type": "string"},
            },
            "required": ["title", "severity", "target", "description", "steps", "poc", "impact"],
        }),
        # Container health
        Tool(name="container_status", description="Check Kali container health status", inputSchema={
            "type": "object", "properties": {},
        }),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Route tool calls to implementations."""
    try:
        result = await _dispatch_tool(name, arguments)
        return [TextContent(type="text", text=json.dumps(result, indent=2, default=str))]
    except Exception as e:
        return [TextContent(type="text", text=json.dumps({"error": str(e)}, indent=2))]


async def _dispatch_tool(name: str, args: dict) -> dict:
    """Dispatch tool call to the correct handler."""
    # Scope management
    if name == "set_scope":
        scope = EngagementScope(
            engagement_id=args.get("engagement_id", ""),
            context=Context(args["context"]),
            platform=args.get("platform", ""),
            targets=[ScopeTarget(target=t) for t in args["targets"]],
            exclusions=args.get("exclusions", []),
        )
        get_scope_manager().set_scope(scope)
        return {"status": "scope_configured", "targets": args["targets"], "context": args["context"]}

    if name == "container_status":
        runner = get_runner()
        healthy = await runner.is_healthy()
        return {"status": "running" if healthy else "stopped", "container": get_config().container_name}

    # Phase 1: Recon
    if name == "recon_subdomains":
        return await recon.recon_subdomains(args["target"], args.get("methods"))
    if name == "recon_dns":
        return await recon.recon_dns(args["target"], args.get("checks"))
    if name == "recon_ports_fast":
        return await recon.recon_ports_fast(args["target"], args.get("ports", "80,443,8080,8443"))
    if name == "recon_tech_stack":
        return await recon.recon_tech_stack(args["target"])
    if name == "recon_waf":
        return await recon.recon_waf(args["target"])
    if name == "recon_certs":
        return await recon.recon_certs(args["target"])
    if name == "recon_asn":
        return await recon.recon_asn(args["target"])

    # Phase 2: Scanning
    if name == "scan_ports_full":
        return await scanning.scan_ports_full(args["target"], args.get("ports", "-"), args.get("timing", 4), args.get("evasion", False))
    if name == "scan_services":
        return await scanning.scan_services(args["target"], args.get("ports", ""))
    if name == "scan_directories":
        return await scanning.scan_directories(args["target"], args.get("wordlist", "/wordlists/seclists/Discovery/Web-Content/common.txt"), args.get("extensions", ""))
    if name == "scan_api_endpoints":
        return await scanning.scan_api_endpoints(args["target"], args.get("swagger_paths"))
    if name == "scan_vulns":
        return await scanning.scan_vulns(args["target"], args.get("severity", "critical,high,medium"), args.get("templates"))
    if name == "scan_vhosts":
        return await scanning.scan_vhosts(args["target"], filter_size=args.get("filter_size"))
    if name == "scan_parameters":
        return await scanning.scan_parameters(args["target"])
    if name == "scan_tls":
        return await scanning.scan_tls(args["target"])

    # Phase 3: Vulns
    if name == "vuln_sqli":
        return await vulns.vuln_sqli(args["target"], args.get("parameter", ""), level=args.get("level", 3), risk=args.get("risk", 2))
    if name == "vuln_xss":
        return await vulns.vuln_xss(args["target"], args.get("parameter", ""))
    if name == "vuln_ssrf":
        return await vulns.vuln_ssrf(args["target"], args.get("parameter", "url"), args.get("callback_url", ""))
    if name == "vuln_jwt":
        return await vulns.vuln_jwt(args["target"], args["token"])
    if name == "vuln_cors":
        return await vulns.vuln_cors(args["target"])
    if name == "vuln_idor":
        id_range = tuple(args.get("id_range", [1, 20]))
        return await vulns.vuln_idor(args["target"], args["token"], id_range)
    if name == "vuln_subdomain_takeover":
        return await vulns.vuln_subdomain_takeover(args["target"])

    # Phase 4: Exploitation
    if name == "exploit_sqli":
        return await exploit.exploit_sqli(args["target"], args.get("parameter", ""), args.get("action", "dbs"))
    if name == "exploit_password_spray":
        return await exploit.exploit_password_spray(args["target"], users=args.get("users"), password=args["password"], service=args.get("service", "ssh"))
    if name == "exploit_ssrf":
        return await exploit.exploit_ssrf(args["target"], args.get("parameter", "url"), args.get("internal_target", "http://169.254.169.254/latest/meta-data/"))

    # Phase 5: Post-Exploitation
    if name == "post_privesc_linux":
        return await post_exploit.post_privesc_linux(args["target"], args.get("method", "manual"))
    if name == "post_ad_enum":
        return await post_exploit.post_ad_enum(args["target"], args["domain"], args["username"], args["password"], args.get("method", "bloodhound"))
    if name == "post_kerberoast":
        return await post_exploit.post_kerberoast(args["target"], args["domain"], args["username"], args["password"])
    if name == "post_lateral_move":
        return await post_exploit.post_lateral_move(args["target"], args.get("username", ""), args.get("password", ""), args.get("ntlm_hash", ""), args.get("method", "pass_the_hash"))

    # API Security
    if name == "api_test_bola":
        return await api_security.api_test_bola(args["target"], args["user_a_token"], args["user_b_token"], args.get("endpoints"))
    if name == "api_test_bfla":
        return await api_security.api_test_bfla(args["target"], args["regular_token"], args.get("admin_endpoints"))
    if name == "api_test_misconfig":
        return await api_security.api_test_misconfig(args["target"])

    # Cloud
    if name == "cloud_imds_test":
        return await cloud.cloud_imds_test(args["target"], args.get("parameter", "url"), args.get("cloud_provider", "aws"))
    if name == "cloud_storage_enum":
        return await cloud.cloud_storage_enum(args["target"], args.get("cloud_provider", "aws"))
    if name == "cloud_secret_scan":
        return await cloud.cloud_secret_scan(args["target"], args.get("repo_url", ""))

    # Reporting
    if name == "report_finding":
        return await reporting.report_finding(**args)
    if name == "report_cvss":
        return await reporting.report_cvss(**args)
    if name == "report_export":
        return await reporting.report_export(args.get("format", "markdown"), args.get("template", "pentest"))
    if name == "report_bounty_template":
        return await reporting.report_bounty_template(**args)

    return {"error": f"Unknown tool: {name}"}


# === RESOURCES ===

@server.list_resources()
async def list_resources() -> list[Resource]:
    return [
        Resource(uri="scope://targets", name="Engagement Scope", description="Current authorized targets and rules"),
        Resource(uri="findings://current", name="Current Findings", description="Vulnerabilities discovered in this session"),
        Resource(uri="session://log", name="Session Log", description="Complete log of all actions"),
    ]


@server.read_resource()
async def read_resource(uri: str) -> str:
    if uri == "scope://targets":
        return json.dumps(get_scope_data(), indent=2, default=str)
    if uri == "findings://current":
        data = await get_findings_data()
        return json.dumps(data, indent=2, default=str)
    if uri == "session://log":
        data = await get_session_data()
        return json.dumps(data, indent=2, default=str)
    return json.dumps({"error": f"Unknown resource: {uri}"})


# === PROMPTS ===

@server.list_prompts()
async def list_prompts() -> list[Prompt]:
    return [
        Prompt(
            name="full_pentest",
            description="Complete PTES pentest workflow (Phases 1-6)",
            arguments=[
                PromptArgument(name="target", description="Primary target", required=True),
                PromptArgument(name="engagement_id", description="Engagement ID", required=False),
            ],
        ),
        Prompt(
            name="bug_bounty_web",
            description="Bug bounty workflow optimized for web apps (speed + impact)",
            arguments=[
                PromptArgument(name="target", description="Target domain", required=True),
                PromptArgument(name="platform", description="Bug bounty platform", required=False),
            ],
        ),
        Prompt(
            name="api_assessment",
            description="OWASP API Security Top 10 assessment",
            arguments=[
                PromptArgument(name="target", description="API base URL", required=True),
            ],
        ),
    ]


@server.get_prompt()
async def get_prompt(name: str, arguments: dict | None = None) -> GetPromptResult:
    args = arguments or {}

    if name == "full_pentest":
        content = get_full_pentest_prompt(args.get("target", ""), args.get("engagement_id", ""))
    elif name == "bug_bounty_web":
        content = get_bug_bounty_prompt(args.get("target", ""), args.get("platform", ""))
    elif name == "api_assessment":
        content = get_api_assessment_prompt(args.get("target", ""))
    else:
        content = f"Unknown prompt: {name}"

    return GetPromptResult(
        description=f"Workflow: {name}",
        messages=[PromptMessage(role="user", content=TextContent(type="text", text=content))],
    )


# === MAIN ===

def main() -> None:
    """Run the Kambo MCP server via stdio."""
    async def run():
        db = await get_database()
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())
        await db.close()

    asyncio.run(run())


if __name__ == "__main__":
    main()
