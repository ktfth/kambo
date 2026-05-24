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
from kambo.models import Context, EngagementScope, Phase, ScopeTarget
from kambo.pipeline import get_pipeline, reset_pipeline
from kambo.prompts.api_assessment import get_api_assessment_prompt
from kambo.prompts.bug_bounty import get_bug_bounty_prompt
from kambo.prompts.full_pentest import get_full_pentest_prompt
from kambo.recon_monitor import get_monitor, snapshot_from_pipeline
from kambo.resources.findings_resource import get_findings_data
from kambo.resources.scope_resource import get_scope_data
from kambo.resources.session_resource import get_session_data
from kambo.scope import get_scope_manager
from kambo.tools import recon, scanning, vulns, exploit, post_exploit, reporting, api_security, cloud, containers, ad, bounty, platforms

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
        Tool(name="scan_udp", description="UDP port scan using nmap", inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP or host to scan"},
                "top_ports": {"type": "integer", "description": "Number of top UDP ports to scan (default: 100)"},
            },
            "required": ["target"],
        }),
        Tool(name="scan_cms", description="CMS detection and vulnerability scanning (WordPress, Joomla, Drupal)", inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "URL of target CMS"},
            },
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
        Tool(name="vuln_nuclei_scan", description="Nuclei-based vulnerability scan using CVE and vuln templates", inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL or host"},
                "templates": {"type": "string", "description": "Comma-separated template categories (default: cves,vulnerabilities)"},
                "severity": {"type": "string", "description": "Comma-separated severity filter (default: critical,high)"},
            },
            "required": ["target"],
        }),
        Tool(name="vuln_ssti", description="Server-Side Template Injection detection — tests {{7*7}}→49 across Jinja2, Twig, Freemarker, Velocity, ERB", inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "URL to test"},
                "parameter": {"type": "string", "description": "Parameter to inject into (empty = try query string)"},
                "engine": {"type": "string", "enum": ["auto", "jinja2", "twig", "smarty", "velocity"], "description": "Template engine hint (default: auto)"},
            },
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
        Tool(name="exploit_auth_bypass", description="Authentication bypass testing using default credentials, token forgery, or logic flaws", inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "method": {"type": "string", "description": "Bypass method: default_creds, token_forgery, logic_flaw"},
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
        Tool(name="post_privesc_windows", description="Windows privilege escalation enumeration (winPEAS, token abuse, service misconfigs)", inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target Windows host"},
            },
            "required": ["target"],
        }),
        Tool(name="post_cred_dump", description="Credential dumping via secretsdump or mimikatz (SAM, NTDS, LSA secrets)", inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target host"},
                "domain": {"type": "string", "description": "Domain name"},
                "username": {"type": "string", "description": "Username for authentication"},
                "password": {"type": "string", "description": "Password for authentication"},
                "ntlm_hash": {"type": "string", "description": "NTLM hash for pass-the-hash"},
            },
            "required": ["target"],
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
        Tool(name="api_test_auth", description="API authentication weakness testing — missing auth, broken token validation, improper session handling", inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "API base URL"},
                "checks": {"type": "array", "items": {"type": "string"}, "description": "Check types to run"},
                "token": {"type": "string", "description": "Auth token to include in requests"},
            },
            "required": ["target"],
        }),
        Tool(name="api_test_bopla", description="BOPLA/mass assignment testing — broken object property level authorization (API3:2023)", inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "API base URL"},
                "endpoint": {"type": "string", "description": "Specific endpoint to test"},
                "token": {"type": "string", "description": "Auth token"},
                "mass_assignment_fields": {"type": "array", "items": {"type": "string"}, "description": "Fields to attempt mass assignment on"},
            },
            "required": ["target", "endpoint", "token"],
        }),
        Tool(name="api_test_resource", description="API resource consumption and rate limiting tests (API4:2023)", inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "API base URL"},
                "endpoint": {"type": "string", "description": "Endpoint to test (default: /api/search)"},
                "bypass_headers": {"type": "array", "items": {"type": "string"}, "description": "Headers to test for rate limit bypass"},
            },
            "required": ["target"],
        }),
        # Container / Kubernetes
        Tool(name="container_escape_detect", description="Detect container escape vectors (privileged mode, host mounts, dangerous capabilities)", inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target host running containers"},
            },
            "required": ["target"],
        }),
        Tool(name="container_image_scan", description="Scan container image for vulnerabilities using Trivy", inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target host or registry"},
                "image": {"type": "string", "description": "Container image name and tag"},
            },
            "required": ["target", "image"],
        }),
        Tool(name="k8s_rbac_enum", description="Kubernetes RBAC enumeration — overprivileged roles, service accounts, cluster-admin abuse", inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Kubernetes API server URL or host"},
                "token": {"type": "string", "description": "Service account or user token"},
                "api_server": {"type": "string", "description": "API server URL (if different from target)"},
            },
            "required": ["target"],
        }),
        # Active Directory
        Tool(name="ad_bloodhound", description="BloodHound Active Directory attack path collection", inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Domain controller IP"},
                "domain": {"type": "string", "description": "AD domain name"},
                "username": {"type": "string", "description": "AD username"},
                "password": {"type": "string", "description": "AD password"},
                "collection": {"type": "string", "description": "Collection method (default: All)"},
            },
            "required": ["target", "domain", "username", "password"],
        }),
        Tool(name="ad_kerberoast", description="Kerberoasting — request and extract service ticket hashes for offline cracking", inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Domain controller IP"},
                "domain": {"type": "string", "description": "AD domain name"},
                "username": {"type": "string", "description": "AD username"},
                "password": {"type": "string", "description": "AD password"},
            },
            "required": ["target", "domain", "username", "password"],
        }),
        Tool(name="ad_asrep_roast", description="AS-REP Roasting — extract hashes for accounts with pre-auth disabled", inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Domain controller IP"},
                "domain": {"type": "string", "description": "AD domain name"},
                "users_file": {"type": "string", "description": "Path to file containing usernames"},
                "users": {"type": "array", "items": {"type": "string"}, "description": "List of usernames to test"},
            },
            "required": ["target", "domain"],
        }),
        Tool(name="ad_pass_the_hash", description="Pass-the-Hash attack — authenticate using NTLM hash without plaintext password", inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target host"},
                "username": {"type": "string", "description": "Username"},
                "ntlm_hash": {"type": "string", "description": "NTLM hash (LM:NT format)"},
                "domain": {"type": "string", "description": "Domain name"},
            },
            "required": ["target", "username", "ntlm_hash"],
        }),
        Tool(name="ad_dcsync", description="DCSync attack — extract domain credentials by simulating domain replication", inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Domain controller IP"},
                "domain": {"type": "string", "description": "AD domain name"},
                "username": {"type": "string", "description": "Username with replication rights"},
                "password": {"type": "string", "description": "Password for authentication"},
                "ntlm_hash": {"type": "string", "description": "NTLM hash (alternative to password)"},
                "target_user": {"type": "string", "description": "User to extract (default: krbtgt)"},
            },
            "required": ["target", "domain", "username"],
        }),
        Tool(name="ad_certify", description="AD CS (Active Directory Certificate Services) vulnerability enumeration — ESC1-ESC8", inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Domain controller or CA server IP"},
                "domain": {"type": "string", "description": "AD domain name"},
                "username": {"type": "string", "description": "AD username"},
                "password": {"type": "string", "description": "AD password"},
            },
            "required": ["target", "domain", "username", "password"],
        }),
        Tool(name="ad_ntlm_relay", description="NTLM relay attack — capture and relay authentication to gain access", inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target to capture NTLM from"},
                "relay_target": {"type": "string", "description": "Host to relay auth to"},
                "method": {"type": "string", "description": "Relay method: smb, ldap, http"},
            },
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
        Tool(name="report_finding", description="Create and store a security finding with confidence level", inputSchema={
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                "confidence": {"type": "string", "enum": ["confirmed", "firm", "tentative"], "description": "Evidence-based confidence level"},
                "target": {"type": "string"},
                "description": {"type": "string"},
                "reproduction_steps": {"type": "array", "items": {"type": "string"}},
                "impact": {"type": "string"},
                "remediation": {"type": "string"},
                "cvss": {"type": "number"},
                "evidence_signals": {"type": "array", "items": {"type": "object"}, "description": "Evidence signals [{signal, source, raw_data, weight}]"},
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
        Tool(name="report_export", description="Export findings as report with confidence filtering", inputSchema={
            "type": "object",
            "properties": {
                "format": {"type": "string", "enum": ["markdown", "json"]},
                "template": {"type": "string", "enum": ["pentest", "bug_bounty", "api_assessment"]},
                "min_confidence": {"type": "string", "enum": ["confirmed", "firm", "tentative"], "description": "Minimum confidence level to include"},
            },
        }),
        Tool(name="report_bounty_template", description="Generate bug bounty report template with confidence", inputSchema={
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
                "confidence": {"type": "string", "enum": ["confirmed", "firm", "tentative"]},
                "evidence_signals": {"type": "array", "items": {"type": "string"}, "description": "Evidence signal descriptions"},
            },
            "required": ["title", "severity", "target", "description", "steps", "poc", "impact"],
        }),
        Tool(name="report_metrics", description="View session quality metrics — precision, FP rates, confidence distribution", inputSchema={
            "type": "object",
            "properties": {},
        }),
        Tool(name="report_confirm_finding", description="Confirm or reject a finding to improve precision metrics", inputSchema={
            "type": "object",
            "properties": {
                "finding_id": {"type": "string", "description": "Finding ID (e.g., FIND-001)"},
                "is_true_positive": {"type": "boolean", "description": "True if the finding is a real vulnerability"},
            },
            "required": ["finding_id", "is_true_positive"],
        }),
        # Bounty Intelligence
        Tool(name="bounty_classify", description="Classify and score a bug bounty program (tier S/A/B/C/D, ROI, approach)", inputSchema={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Program name (e.g., Uber, Shopify)"},
                "platform": {"type": "string", "enum": ["hackerone", "bugcrowd", "intigriti", "yeswehack", "self-hosted"]},
                "domains": {"type": "array", "items": {"type": "string"}, "description": "In-scope domains"},
                "wildcards": {"type": "array", "items": {"type": "string"}, "description": "Wildcard scopes (*.example.com)"},
                "asset_types": {"type": "array", "items": {"type": "string", "enum": ["web", "api", "mobile", "infrastructure", "iot", "thick_client"]}},
                "exclusions": {"type": "array", "items": {"type": "string"}},
                "payout_critical": {"type": "number", "description": "Max payout for critical ($)"},
                "payout_high": {"type": "number"},
                "payout_medium": {"type": "number"},
                "payout_low": {"type": "number"},
                "bounty_type": {"type": "string", "enum": ["cash", "swag", "points", "hall_of_fame"]},
                "bonus_active": {"type": "boolean"},
                "managed": {"type": "boolean", "description": "Private/managed program"},
                "vdp_only": {"type": "boolean", "description": "No cash — disclosure only"},
                "launched_date": {"type": "string", "description": "ISO date when program launched"},
                "response_time_days": {"type": "number"},
                "tech_stack": {"type": "array", "items": {"type": "string"}},
                "waf_detected": {"type": "boolean"},
                "waf_name": {"type": "string"},
                "subdomains_count": {"type": "integer"},
                "open_ports_count": {"type": "integer"},
                "api_endpoints_count": {"type": "integer"},
                "has_swagger": {"type": "boolean"},
            },
            "required": ["name"],
        }),
        Tool(name="bounty_rank", description="Rank multiple bug bounty programs by ROI — returns prioritized hunting order", inputSchema={
            "type": "object",
            "properties": {
                "programs": {"type": "array", "items": {"type": "object"}, "description": "List of program objects (same fields as bounty_classify)"},
            },
            "required": ["programs"],
        }),
        Tool(name="bounty_estimate_value", description="Estimate monetary value of a finding — expected payout, readiness, ROI", inputSchema={
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Finding title"},
                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                "confidence": {"type": "string", "enum": ["confirmed", "firm", "tentative"]},
                "vuln_type": {"type": "string", "description": "Vulnerability type (sqli, xss, idor, ssrf, cors, bola, rce, etc.)"},
                "program_name": {"type": "string"},
                "payout_critical": {"type": "number", "description": "Program max critical payout ($)"},
                "payout_high": {"type": "number"},
                "payout_medium": {"type": "number"},
                "payout_low": {"type": "number"},
                "bonus_active": {"type": "boolean"},
                "bonus_multiplier": {"type": "number", "description": "Bonus multiplier (e.g., 2.0)"},
                "managed": {"type": "boolean"},
                "has_poc": {"type": "boolean", "description": "Whether PoC exists"},
                "has_reproduction_steps": {"type": "boolean"},
                "evidence_signals_count": {"type": "integer"},
                "hours_spent": {"type": "number", "description": "Hours spent on this finding (0 = use timer)"},
            },
            "required": ["title", "severity", "vuln_type"],
        }),
        Tool(name="bounty_session_value", description="Calculate total session value — aggregate all findings, ROI, readiness", inputSchema={
            "type": "object",
            "properties": {
                "findings": {"type": "array", "items": {"type": "object"}, "description": "List of findings [{title, severity, confidence, vuln_type, has_poc, has_reproduction_steps, evidence_signals_count}]"},
                "program_name": {"type": "string"},
                "payout_critical": {"type": "number"},
                "payout_high": {"type": "number"},
                "payout_medium": {"type": "number"},
                "payout_low": {"type": "number"},
                "bonus_active": {"type": "boolean"},
                "bonus_multiplier": {"type": "number"},
                "managed": {"type": "boolean"},
            },
            "required": ["findings"],
        }),
        # Discovery Timer
        Tool(name="bounty_timer_start", description="Start timing a discovery phase for ROI tracking", inputSchema={
            "type": "object",
            "properties": {
                "phase": {"type": "string", "description": "Phase name (recon, scanning, vulnerability_analysis, exploitation, reporting)"},
            },
            "required": ["phase"],
        }),
        Tool(name="bounty_timer_tool", description="Record a tool execution within the current timed phase", inputSchema={
            "type": "object",
            "properties": {
                "tool_name": {"type": "string", "description": "Tool being executed"},
                "target": {"type": "string", "description": "Target being tested"},
            },
            "required": ["tool_name"],
        }),
        Tool(name="bounty_timer_stop", description="Stop timer and get full timing breakdown by phase and tool", inputSchema={
            "type": "object",
            "properties": {},
        }),
        Tool(name="bounty_timer_reset", description="Reset the timer for a new hunting session", inputSchema={
            "type": "object",
            "properties": {},
        }),
        # Container health
        Tool(name="container_status", description="Check Kali container health status", inputSchema={
            "type": "object", "properties": {},
        }),
        # Session Pipeline
        Tool(name="pipeline_ingest", description="Ingest tool results into session pipeline for auto-chaining. Call after any recon/scan/vuln tool to accumulate context.", inputSchema={
            "type": "object",
            "properties": {
                "tool_name": {"type": "string", "description": "Name of the tool that produced the result"},
                "result": {"type": "object", "description": "The tool result to ingest"},
            },
            "required": ["tool_name", "result"],
        }),
        Tool(name="pipeline_status", description="Get accumulated session context — all discovered assets, tools run, findings", inputSchema={
            "type": "object", "properties": {},
        }),
        Tool(name="pipeline_next", description="Get recommended next steps based on accumulated context — what tools to run and on what targets", inputSchema={
            "type": "object",
            "properties": {
                "phase": {"type": "string", "enum": ["recon", "scanning", "vulnerability_analysis", "exploitation", "post_exploitation", "reporting"], "description": "Current phase"},
                "max_steps": {"type": "integer", "description": "Max suggestions (default 5)"},
            },
            "required": ["phase"],
        }),
        Tool(name="pipeline_targets", description="Get auto-resolved targets for a phase based on accumulated recon/scan data", inputSchema={
            "type": "object",
            "properties": {
                "phase": {"type": "string", "enum": ["recon", "scanning", "vulnerability_analysis", "exploitation", "post_exploitation", "reporting"]},
            },
            "required": ["phase"],
        }),
        Tool(name="pipeline_reset", description="Reset session pipeline for a new engagement", inputSchema={
            "type": "object", "properties": {},
        }),
        # Recon Monitoring
        Tool(name="recon_snapshot", description="Take a snapshot of current recon data for a target — used for change detection over time", inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target domain"},
            },
            "required": ["target"],
        }),
        Tool(name="recon_diff", description="Compare current recon data against previous snapshot — detect new subdomains, ports, endpoints", inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target domain"},
                "from_baseline": {"type": "boolean", "description": "Compare against first snapshot (true) or previous snapshot (false)", "default": False},
            },
            "required": ["target"],
        }),
        # Platform Integration
        Tool(name="platform_fetch_program", description="Fetch bug bounty program details from HackerOne or Bugcrowd", inputSchema={
            "type": "object",
            "properties": {
                "platform": {"type": "string", "enum": ["hackerone", "bugcrowd"], "description": "Platform name"},
                "handle": {"type": "string", "description": "Program handle/slug"},
            },
            "required": ["platform", "handle"],
        }),
        Tool(name="platform_fetch_scope", description="Fetch program scope (in-scope/out-of-scope assets) from platform API", inputSchema={
            "type": "object",
            "properties": {
                "platform": {"type": "string", "enum": ["hackerone", "bugcrowd"]},
                "handle": {"type": "string", "description": "Program handle/slug"},
            },
            "required": ["platform", "handle"],
        }),
        Tool(name="platform_check_duplicate", description="Check if a similar vulnerability was already reported/disclosed (HackerOne only)", inputSchema={
            "type": "object",
            "properties": {
                "platform": {"type": "string", "enum": ["hackerone"]},
                "handle": {"type": "string", "description": "Program handle/slug"},
                "title": {"type": "string", "description": "Finding title to check"},
                "vuln_type": {"type": "string", "description": "Vulnerability type keyword (sqli, xss, etc.)"},
            },
            "required": ["platform", "handle", "title"],
        }),
        Tool(name="platform_submit_report", description="Submit a vulnerability report to HackerOne or Bugcrowd", inputSchema={
            "type": "object",
            "properties": {
                "platform": {"type": "string", "enum": ["hackerone", "bugcrowd"]},
                "handle": {"type": "string", "description": "Program handle/slug"},
                "title": {"type": "string", "description": "Report title"},
                "body": {"type": "string", "description": "Full report body (markdown)"},
                "severity": {"type": "string", "description": "Severity (critical, high, medium, low)"},
                "impact": {"type": "string", "description": "Impact description"},
                "asset": {"type": "string", "description": "Affected asset from scope"},
                "weakness_id": {"type": "integer", "description": "CWE ID (HackerOne)"},
                "priority": {"type": "integer", "description": "Priority 1-5 (Bugcrowd, 1=critical)"},
                "vrt": {"type": "string", "description": "VRT classification (Bugcrowd)"},
                "steps": {"type": "string", "description": "Steps to reproduce (Bugcrowd)"},
            },
            "required": ["platform", "handle", "title", "body"],
        }),
    ]


_PIPELINE_SKIP_TOOLS = frozenset({
    "pipeline_ingest", "pipeline_status", "pipeline_next", "pipeline_targets",
    "pipeline_reset", "set_scope", "container_status",
    "recon_snapshot", "recon_diff",
})


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Route tool calls to implementations."""
    try:
        result = await _dispatch_tool(name, arguments)

        # Auto-ingest results into pipeline for context accumulation
        if isinstance(result, dict) and name not in _PIPELINE_SKIP_TOOLS:
            try:
                get_pipeline().ingest(name, result)
            except Exception:
                pass  # pipeline ingestion should never block tool execution

        # Inject historical FP warning if available
        from kambo.metrics import flush_metrics, get_metrics
        warning = get_metrics().get_fp_warning(name)
        if warning and isinstance(result, dict):
            result["_historical_warning"] = warning

        # Persist metrics after each tool call
        await flush_metrics()

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
    if name == "scan_udp":
        return await scanning.scan_udp(args["target"], args.get("top_ports", 100))
    if name == "scan_cms":
        return await scanning.scan_cms(args["target"])

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
    if name == "vuln_nuclei_scan":
        return await vulns.vuln_nuclei_scan(args["target"], args.get("templates", "cves,vulnerabilities"), args.get("severity", "critical,high"))
    if name == "vuln_ssti":
        return await vulns.vuln_ssti(args["target"], args.get("parameter", ""), args.get("engine", "auto"))

    # Phase 4: Exploitation
    if name == "exploit_sqli":
        return await exploit.exploit_sqli(args["target"], args.get("parameter", ""), args.get("action", "dbs"))
    if name == "exploit_password_spray":
        return await exploit.exploit_password_spray(args["target"], users=args.get("users"), password=args["password"], service=args.get("service", "ssh"))
    if name == "exploit_ssrf":
        return await exploit.exploit_ssrf(args["target"], args.get("parameter", "url"), args.get("internal_target", "http://169.254.169.254/latest/meta-data/"))
    if name == "exploit_auth_bypass":
        return await exploit.exploit_auth_bypass(args["target"], args.get("method", "default_creds"))

    # Phase 5: Post-Exploitation
    if name == "post_privesc_linux":
        return await post_exploit.post_privesc_linux(args["target"], args.get("method", "manual"))
    if name == "post_ad_enum":
        return await post_exploit.post_ad_enum(args["target"], args["domain"], args["username"], args["password"], args.get("method", "bloodhound"))
    if name == "post_kerberoast":
        return await post_exploit.post_kerberoast(args["target"], args["domain"], args["username"], args["password"])
    if name == "post_lateral_move":
        return await post_exploit.post_lateral_move(args["target"], args.get("username", ""), args.get("password", ""), args.get("ntlm_hash", ""), args.get("method", "pass_the_hash"))
    if name == "post_privesc_windows":
        return await post_exploit.post_privesc_windows(args["target"])
    if name == "post_cred_dump":
        return await post_exploit.post_cred_dump(args["target"], args.get("domain", ""), args.get("username", ""), args.get("password", ""), args.get("ntlm_hash", ""))

    # API Security
    if name == "api_test_bola":
        return await api_security.api_test_bola(args["target"], args["user_a_token"], args["user_b_token"], args.get("endpoints"))
    if name == "api_test_bfla":
        return await api_security.api_test_bfla(args["target"], args["regular_token"], args.get("admin_endpoints"))
    if name == "api_test_misconfig":
        return await api_security.api_test_misconfig(args["target"])
    if name == "api_test_auth":
        return await api_security.api_test_auth(args["target"], args.get("checks"), args.get("token", ""))
    if name == "api_test_bopla":
        return await api_security.api_test_bopla(args["target"], args["endpoint"], args["token"], args.get("mass_assignment_fields"))
    if name == "api_test_resource":
        return await api_security.api_test_resource(args["target"], args.get("endpoint", "/api/search"), args.get("bypass_headers"))

    # Container / Kubernetes
    if name == "container_escape_detect":
        return await containers.container_escape_detect(args["target"])
    if name == "container_image_scan":
        return await containers.container_image_scan(args["target"], args["image"])
    if name == "k8s_rbac_enum":
        return await containers.k8s_rbac_enum(args["target"], args.get("token", ""), args.get("api_server", ""))

    # Active Directory
    if name == "ad_bloodhound":
        return await ad.ad_bloodhound(args["target"], args["domain"], args["username"], args["password"], args.get("collection", "All"))
    if name == "ad_kerberoast":
        return await ad.ad_kerberoast(args["target"], args["domain"], args["username"], args["password"])
    if name == "ad_asrep_roast":
        return await ad.ad_asrep_roast(args["target"], args["domain"], args.get("users_file", ""), args.get("users", []))
    if name == "ad_pass_the_hash":
        return await ad.ad_pass_the_hash(args["target"], args["username"], args["ntlm_hash"], args.get("domain", ""))
    if name == "ad_dcsync":
        return await ad.ad_dcsync(args["target"], args["domain"], args["username"], args.get("password", ""), args.get("ntlm_hash", ""), args.get("target_user", "krbtgt"))
    if name == "ad_certify":
        return await ad.ad_certify(args["target"], args["domain"], args["username"], args["password"])
    if name == "ad_ntlm_relay":
        return await ad.ad_ntlm_relay(args["target"], args.get("relay_target", ""), args.get("method", "smb"))

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
        return await reporting.report_export(args.get("format", "markdown"), args.get("template", "pentest"), args.get("min_confidence", "tentative"))
    if name == "report_bounty_template":
        return await reporting.report_bounty_template(**args)
    if name == "report_metrics":
        return await reporting.report_metrics()
    if name == "report_confirm_finding":
        return await reporting.report_confirm_finding(args["finding_id"], args["is_true_positive"])

    # Bounty Intelligence
    if name == "bounty_classify":
        return await bounty.bounty_classify(**args)
    if name == "bounty_rank":
        return await bounty.bounty_rank(args["programs"])
    if name == "bounty_estimate_value":
        return await bounty.bounty_estimate_value(**args)
    if name == "bounty_session_value":
        return await bounty.bounty_session_value(**args)

    # Discovery Timer
    if name == "bounty_timer_start":
        return await bounty.bounty_timer_start(args["phase"])
    if name == "bounty_timer_tool":
        return await bounty.bounty_timer_tool(args["tool_name"], args.get("target", ""))
    if name == "bounty_timer_stop":
        return await bounty.bounty_timer_stop()
    if name == "bounty_timer_reset":
        return await bounty.bounty_timer_reset()

    # Session Pipeline
    if name == "pipeline_ingest":
        pipeline = get_pipeline()
        new_assets = pipeline.ingest(args["tool_name"], args["result"])
        return {
            "ingested": len(new_assets),
            "new_assets": [{"type": a.asset_type.value, "value": a.value} for a in new_assets[:20]],
            "total_assets": len(pipeline.assets),
        }
    if name == "pipeline_status":
        from kambo.pipeline import get_pipeline
        return get_pipeline().summary()
    if name == "pipeline_next":
        from kambo.pipeline import get_pipeline
        pipeline = get_pipeline()
        phase = Phase(args["phase"])
        steps = pipeline.suggest_next_steps(phase, args.get("max_steps", 5))
        return {
            "phase": args["phase"],
            "suggestions": [
                {"tool": s.tool, "reason": s.reason, "targets": s.targets, "phase": s.phase.value}
                for s in steps
            ],
        }
    if name == "pipeline_targets":
        from kambo.pipeline import get_pipeline
        from kambo.models import Phase as P
        pipeline = get_pipeline()
        targets = pipeline.targets_for_phase(P(args["phase"]))
        return {"phase": args["phase"], "targets": targets, "count": len(targets)}
    if name == "pipeline_reset":
        reset_pipeline()
        return {"status": "pipeline_reset"}

    # Recon Monitoring
    if name == "recon_snapshot":
        snap = snapshot_from_pipeline(args["target"])
        get_monitor().store_snapshot(snap)
        return {
            "status": "snapshot_stored",
            "target": args["target"],
            "subdomains": len(snap.subdomains),
            "ports": len(snap.ports),
            "urls": len(snap.urls),
            "endpoints": len(snap.endpoints),
            "snapshot_count": get_monitor().snapshot_count(args["target"]),
        }
    if name == "recon_diff":
        monitor = get_monitor()
        if args.get("from_baseline"):
            diff = monitor.diff_from_baseline(args["target"])
        else:
            diff = monitor.diff_latest(args["target"])
        if diff is None:
            return {"error": "Need at least 2 snapshots to compute diff", "snapshot_count": monitor.snapshot_count(args["target"])}
        return diff.summary()

    # Platform Integration
    if name == "platform_fetch_program":
        return await platforms.platform_fetch_program(args["platform"], args["handle"])
    if name == "platform_fetch_scope":
        return await platforms.platform_fetch_scope(args["platform"], args["handle"])
    if name == "platform_check_duplicate":
        return await platforms.platform_check_duplicate(args["platform"], args["handle"], args["title"], args.get("vuln_type", ""))
    if name == "platform_submit_report":
        return await platforms.platform_submit_report(args["platform"], args["handle"], args)

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

        # Load historical metrics from previous sessions
        from kambo.metrics import load_metrics, flush_metrics
        await load_metrics()

        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())

        # Persist metrics before shutdown
        await flush_metrics()
        await db.close()

    asyncio.run(run())


if __name__ == "__main__":
    main()
