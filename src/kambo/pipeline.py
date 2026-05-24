"""Session pipeline — accumulates context across tool runs and chains phases.

The pipeline collects discovered assets (subdomains, ports, URLs, parameters,
findings) from each tool execution, making them available as inputs for
subsequent tools without manual target passing.

Usage:
    pipeline = get_pipeline()
    pipeline.ingest("recon_subdomains", {...tool result...})
    next_targets = pipeline.targets_for_phase(Phase.SCANNING)
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from kambo.models import Confidence, Phase, Severity


class AssetType(str, Enum):
    SUBDOMAIN = "subdomain"
    IP = "ip"
    PORT = "port"
    URL = "url"
    PARAMETER = "parameter"
    ENDPOINT = "endpoint"
    TECHNOLOGY = "technology"
    CREDENTIAL = "credential"
    FINDING = "finding"
    VHOST = "vhost"
    CERTIFICATE = "certificate"


class DiscoveredAsset(BaseModel):
    """An asset discovered during the engagement."""

    asset_type: AssetType
    value: str
    source_tool: str
    phase: Phase
    metadata: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = {"frozen": True}


class PhaseSummary(BaseModel):
    """Summary of what was accomplished in a phase."""

    phase: Phase
    tools_run: list[str] = Field(default_factory=list)
    assets_discovered: int = 0
    findings_count: int = 0
    duration_seconds: float = 0


class NextStep(BaseModel):
    """A recommended next action based on accumulated context."""

    tool: str
    reason: str
    targets: list[str] = Field(default_factory=list)
    priority: int = 0  # 0=highest
    phase: Phase = Phase.RECON

    model_config = {"frozen": True}


# --- Ingestion parsers per tool ---

_TOOL_PARSERS: dict[str, str] = {}


def _register_parser(tool_prefix: str) -> Any:
    """Decorator to register a tool result parser."""

    def decorator(func: Any) -> Any:
        _TOOL_PARSERS[tool_prefix] = func
        return func

    return decorator


@_register_parser("recon_subdomains")
def _parse_subdomains(result: dict) -> list[DiscoveredAsset]:
    assets = []
    for sub in result.get("subdomains", []):
        if isinstance(sub, str):
            assets.append(DiscoveredAsset(
                asset_type=AssetType.SUBDOMAIN,
                value=sub,
                source_tool="recon_subdomains",
                phase=Phase.RECON,
            ))
    return assets


@_register_parser("recon_dns")
def _parse_dns(result: dict) -> list[DiscoveredAsset]:
    assets = []
    for record in result.get("records", []):
        if isinstance(record, dict):
            value = record.get("value", record.get("data", ""))
            if value:
                assets.append(DiscoveredAsset(
                    asset_type=AssetType.IP if _is_ip(value) else AssetType.SUBDOMAIN,
                    value=value,
                    source_tool="recon_dns",
                    phase=Phase.RECON,
                    metadata={"record_type": record.get("type", "")},
                ))
        elif isinstance(record, str):
            assets.append(DiscoveredAsset(
                asset_type=AssetType.SUBDOMAIN,
                value=record,
                source_tool="recon_dns",
                phase=Phase.RECON,
            ))
    return assets


@_register_parser("recon_ports_fast")
def _parse_ports_fast(result: dict) -> list[DiscoveredAsset]:
    return _parse_ports(result, "recon_ports_fast")


@_register_parser("scan_ports_full")
def _parse_ports_full(result: dict) -> list[DiscoveredAsset]:
    return _parse_ports(result, "scan_ports_full")


def _parse_ports(result: dict, source: str) -> list[DiscoveredAsset]:
    assets = []
    target = result.get("target", "")
    for port_info in result.get("ports", []):
        if isinstance(port_info, dict):
            port = str(port_info.get("port", ""))
            service = port_info.get("service", "")
            if port:
                assets.append(DiscoveredAsset(
                    asset_type=AssetType.PORT,
                    value=f"{target}:{port}",
                    source_tool=source,
                    phase=Phase.SCANNING,
                    metadata={"port": port, "service": service, "state": port_info.get("state", "open")},
                ))
        elif isinstance(port_info, (int, str)):
            assets.append(DiscoveredAsset(
                asset_type=AssetType.PORT,
                value=f"{target}:{port_info}",
                source_tool=source,
                phase=Phase.SCANNING,
                metadata={"port": str(port_info)},
            ))
    return assets


@_register_parser("scan_directories")
def _parse_directories(result: dict) -> list[DiscoveredAsset]:
    assets = []
    target = result.get("target", "")
    for entry in result.get("results", result.get("directories", [])):
        if isinstance(entry, dict):
            url = entry.get("url", "")
            status = entry.get("status", 0)
            if url and 200 <= status < 400:
                assets.append(DiscoveredAsset(
                    asset_type=AssetType.URL,
                    value=url,
                    source_tool="scan_directories",
                    phase=Phase.SCANNING,
                    metadata={"status": status, "size": entry.get("length", 0)},
                ))
        elif isinstance(entry, str):
            assets.append(DiscoveredAsset(
                asset_type=AssetType.URL,
                value=f"{target}/{entry.lstrip('/')}",
                source_tool="scan_directories",
                phase=Phase.SCANNING,
            ))
    return assets


@_register_parser("scan_api_endpoints")
def _parse_api_endpoints(result: dict) -> list[DiscoveredAsset]:
    assets = []
    for ep in result.get("endpoints", []):
        if isinstance(ep, dict):
            path = ep.get("path", ep.get("url", ""))
            if path:
                assets.append(DiscoveredAsset(
                    asset_type=AssetType.ENDPOINT,
                    value=path,
                    source_tool="scan_api_endpoints",
                    phase=Phase.SCANNING,
                    metadata={"method": ep.get("method", "GET")},
                ))
        elif isinstance(ep, str):
            assets.append(DiscoveredAsset(
                asset_type=AssetType.ENDPOINT,
                value=ep,
                source_tool="scan_api_endpoints",
                phase=Phase.SCANNING,
            ))
    return assets


@_register_parser("scan_parameters")
def _parse_parameters(result: dict) -> list[DiscoveredAsset]:
    assets = []
    for param in result.get("parameters", result.get("params", [])):
        if isinstance(param, dict):
            name = param.get("name", param.get("param", ""))
            url = param.get("url", "")
            if name:
                assets.append(DiscoveredAsset(
                    asset_type=AssetType.PARAMETER,
                    value=name,
                    source_tool="scan_parameters",
                    phase=Phase.SCANNING,
                    metadata={"url": url, "type": param.get("type", "query")},
                ))
        elif isinstance(param, str):
            assets.append(DiscoveredAsset(
                asset_type=AssetType.PARAMETER,
                value=param,
                source_tool="scan_parameters",
                phase=Phase.SCANNING,
            ))
    return assets


@_register_parser("recon_tech_stack")
def _parse_tech_stack(result: dict) -> list[DiscoveredAsset]:
    assets = []
    for tech in result.get("technologies", result.get("tech_stack", [])):
        if isinstance(tech, dict):
            name = tech.get("name", tech.get("technology", ""))
            if name:
                assets.append(DiscoveredAsset(
                    asset_type=AssetType.TECHNOLOGY,
                    value=name,
                    source_tool="recon_tech_stack",
                    phase=Phase.RECON,
                    metadata={"version": tech.get("version", ""), "category": tech.get("category", "")},
                ))
        elif isinstance(tech, str):
            assets.append(DiscoveredAsset(
                asset_type=AssetType.TECHNOLOGY,
                value=tech,
                source_tool="recon_tech_stack",
                phase=Phase.RECON,
            ))
    return assets


@_register_parser("scan_vhosts")
def _parse_vhosts(result: dict) -> list[DiscoveredAsset]:
    assets = []
    for vhost in result.get("vhosts", result.get("virtual_hosts", [])):
        if isinstance(vhost, dict):
            host = vhost.get("host", vhost.get("vhost", ""))
            if host:
                assets.append(DiscoveredAsset(
                    asset_type=AssetType.VHOST,
                    value=host,
                    source_tool="scan_vhosts",
                    phase=Phase.SCANNING,
                ))
        elif isinstance(vhost, str):
            assets.append(DiscoveredAsset(
                asset_type=AssetType.VHOST,
                value=vhost,
                source_tool="scan_vhosts",
                phase=Phase.SCANNING,
            ))
    return assets


@_register_parser("recon_waf")
def _parse_waf(result: dict) -> list[DiscoveredAsset]:
    assets = []
    waf = result.get("waf") or result.get("waf_name", "")
    if waf and waf != "none":
        target = result.get("target", "")
        assets.append(DiscoveredAsset(
            asset_type=AssetType.TECHNOLOGY,
            value=f"waf:{waf}",
            source_tool="recon_waf",
            phase=Phase.RECON,
            metadata={"target": target, "waf": waf},
        ))
    return assets


@_register_parser("recon_certs")
def _parse_certs(result: dict) -> list[DiscoveredAsset]:
    assets = []
    for domain in result.get("domains", result.get("sans", [])):
        if isinstance(domain, str) and domain and "*" not in domain:
            assets.append(DiscoveredAsset(
                asset_type=AssetType.SUBDOMAIN,
                value=domain,
                source_tool="recon_certs",
                phase=Phase.RECON,
                metadata={"source": "certificate_transparency"},
            ))
    return assets


@_register_parser("recon_asn")
def _parse_asn(result: dict) -> list[DiscoveredAsset]:
    assets = []
    for cidr in result.get("cidrs", result.get("ip_ranges", [])):
        if isinstance(cidr, str):
            assets.append(DiscoveredAsset(
                asset_type=AssetType.IP,
                value=cidr,
                source_tool="recon_asn",
                phase=Phase.RECON,
                metadata={"asn": result.get("asn", ""), "org": result.get("org", "")},
            ))
    return assets


@_register_parser("scan_tls")
def _parse_tls(result: dict) -> list[DiscoveredAsset]:
    assets = []
    target = result.get("target", "")
    # Extract weak protocols and ciphers as TECHNOLOGY signals
    for protocol in result.get("weak_protocols", []):
        assets.append(DiscoveredAsset(
            asset_type=AssetType.TECHNOLOGY,
            value=f"weak_tls:{protocol}",
            source_tool="scan_tls",
            phase=Phase.SCANNING,
            metadata={"target": target, "protocol": protocol},
        ))
    # Extract certificate SANs as subdomains
    for san in result.get("sans", []):
        if isinstance(san, str) and san and "*" not in san:
            assets.append(DiscoveredAsset(
                asset_type=AssetType.SUBDOMAIN,
                value=san,
                source_tool="scan_tls",
                phase=Phase.SCANNING,
            ))
    return assets


@_register_parser("scan_services")
def _parse_services(result: dict) -> list[DiscoveredAsset]:
    assets = []
    for svc in result.get("services", []):
        port = svc.get("port", "")
        service = svc.get("service", "")
        version = svc.get("version", "")
        target = result.get("target", svc.get("host", ""))
        if port and service:
            assets.append(DiscoveredAsset(
                asset_type=AssetType.PORT,
                value=str(port),
                source_tool="scan_services",
                phase=Phase.SCANNING,
                metadata={"service": service, "version": version, "target": target},
            ))
            if service:
                assets.append(DiscoveredAsset(
                    asset_type=AssetType.TECHNOLOGY,
                    value=f"{service}{':' + version if version else ''}",
                    source_tool="scan_services",
                    phase=Phase.SCANNING,
                    metadata={"port": port, "target": target},
                ))
    return assets


@_register_parser("scan_vulns")
def _parse_scan_vulns(result: dict) -> list[DiscoveredAsset]:
    """Parse nuclei scan_vulns results into FINDING assets."""
    assets = []
    target = result.get("target", "")
    for finding in result.get("findings", []):
        template_id = finding.get("template_id", finding.get("name", "unknown"))
        severity = finding.get("severity", "info")
        if severity in ("critical", "high", "medium"):
            assets.append(DiscoveredAsset(
                asset_type=AssetType.FINDING,
                value=f"nuclei:{template_id}",
                source_tool="scan_vulns",
                phase=Phase.SCANNING,
                metadata={
                    "severity": severity,
                    "matched_at": finding.get("matched_at", ""),
                    "target": target,
                },
            ))
    return assets


def _is_ip(value: str) -> bool:
    """Check if a string looks like an IP address."""
    return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value))


# --- Next step recommendation engine ---

_PHASE_TRANSITIONS: dict[Phase, list[dict[str, Any]]] = {
    Phase.RECON: [
        {
            "tool": "recon_subdomains",
            "needs": [],
            "produces": [AssetType.SUBDOMAIN],
            "reason": "Enumerate subdomains to expand attack surface",
        },
        {
            "tool": "recon_dns",
            "needs": [],
            "produces": [AssetType.IP, AssetType.SUBDOMAIN],
            "reason": "DNS enumeration for IPs and records",
        },
        {
            "tool": "recon_tech_stack",
            "needs": [AssetType.SUBDOMAIN],
            "produces": [AssetType.TECHNOLOGY],
            "reason": "Fingerprint technologies on discovered hosts",
        },
        {
            "tool": "recon_ports_fast",
            "needs": [AssetType.SUBDOMAIN, AssetType.IP],
            "produces": [AssetType.PORT],
            "reason": "Quick port scan on discovered hosts",
        },
        {
            "tool": "recon_waf",
            "needs": [AssetType.SUBDOMAIN],
            "produces": [AssetType.TECHNOLOGY],
            "reason": "Detect WAF/CDN to plan evasion",
        },
    ],
    Phase.SCANNING: [
        {
            "tool": "scan_ports_full",
            "needs": [AssetType.SUBDOMAIN, AssetType.IP],
            "produces": [AssetType.PORT],
            "reason": "Full port scan for comprehensive coverage",
        },
        {
            "tool": "scan_directories",
            "needs": [AssetType.SUBDOMAIN, AssetType.URL],
            "produces": [AssetType.URL],
            "reason": "Discover hidden directories and files",
        },
        {
            "tool": "scan_api_endpoints",
            "needs": [AssetType.SUBDOMAIN, AssetType.URL],
            "produces": [AssetType.ENDPOINT],
            "reason": "Find API endpoints for testing",
        },
        {
            "tool": "scan_parameters",
            "needs": [AssetType.URL, AssetType.ENDPOINT],
            "produces": [AssetType.PARAMETER],
            "reason": "Discover hidden parameters for injection testing",
        },
        {
            "tool": "scan_vhosts",
            "needs": [AssetType.IP],
            "produces": [AssetType.VHOST],
            "reason": "Find virtual hosts on discovered IPs",
        },
    ],
    Phase.VULN_ANALYSIS: [
        {
            "tool": "vuln_sqli",
            "needs": [AssetType.PARAMETER, AssetType.URL],
            "produces": [AssetType.FINDING],
            "reason": "Test parameters for SQL injection",
        },
        {
            "tool": "vuln_xss",
            "needs": [AssetType.PARAMETER, AssetType.URL],
            "produces": [AssetType.FINDING],
            "reason": "Test parameters for XSS",
        },
        {
            "tool": "vuln_ssrf",
            "needs": [AssetType.PARAMETER, AssetType.URL],
            "produces": [AssetType.FINDING],
            "reason": "Test URL parameters for SSRF",
        },
        {
            "tool": "vuln_cors",
            "needs": [AssetType.SUBDOMAIN, AssetType.URL],
            "produces": [AssetType.FINDING],
            "reason": "Test for CORS misconfigurations",
        },
        {
            "tool": "vuln_jwt",
            "needs": [AssetType.URL, AssetType.ENDPOINT],
            "produces": [AssetType.FINDING],
            "reason": "Analyze JWT tokens for weaknesses",
        },
        {
            "tool": "vuln_idor",
            "needs": [AssetType.ENDPOINT, AssetType.URL],
            "produces": [AssetType.FINDING],
            "reason": "Test endpoints for IDOR/BOLA",
        },
    ],
    Phase.EXPLOITATION: [
        {
            "tool": "exploit_sqli",
            "needs": [AssetType.FINDING],
            "produces": [AssetType.CREDENTIAL],
            "reason": "Exploit confirmed SQLi to extract data",
            "requires_finding": "sqli",
        },
        {
            "tool": "exploit_ssrf",
            "needs": [AssetType.FINDING],
            "produces": [AssetType.URL],
            "reason": "Exploit SSRF for internal access",
            "requires_finding": "ssrf",
        },
    ],
}


class SessionPipeline:
    """Accumulates discovered assets and chains tool outputs to inputs."""

    def __init__(self) -> None:
        self._assets: list[DiscoveredAsset] = []
        self._tools_run: list[str] = []
        self._findings: list[dict[str, Any]] = []

    @property
    def assets(self) -> list[DiscoveredAsset]:
        return list(self._assets)

    @property
    def tools_run(self) -> list[str]:
        return list(self._tools_run)

    def ingest(self, tool_name: str, result: dict[str, Any]) -> list[DiscoveredAsset]:
        """Ingest a tool result, extract and store discovered assets.

        Returns the list of newly discovered assets.
        """
        new_assets: list[DiscoveredAsset] = []

        # Try registered parsers
        for prefix, parser in _TOOL_PARSERS.items():
            if tool_name.startswith(prefix):
                parsed = parser(result)
                new_assets.extend(parsed)
                break

        # Track findings from any tool
        if result.get("vulnerable") or result.get("confidence"):
            finding_data = {
                "tool": tool_name,
                "confidence": result.get("confidence", "tentative"),
                "vuln_type": _infer_vuln_type(tool_name),
                "target": result.get("target", ""),
            }
            self._findings.append(finding_data)
            new_assets.append(DiscoveredAsset(
                asset_type=AssetType.FINDING,
                value=f"{tool_name}:{result.get('target', '')}",
                source_tool=tool_name,
                phase=Phase.VULN_ANALYSIS,
                metadata=finding_data,
            ))

        # Deduplicate before adding
        existing_values = {(a.asset_type, a.value) for a in self._assets}
        unique_new = [a for a in new_assets if (a.asset_type, a.value) not in existing_values]

        self._assets.extend(unique_new)
        if tool_name not in self._tools_run:
            self._tools_run.append(tool_name)

        return unique_new

    def get_assets(
        self,
        asset_type: AssetType | None = None,
        source_tool: str | None = None,
    ) -> list[DiscoveredAsset]:
        """Query accumulated assets with optional filters."""
        result = self._assets
        if asset_type is not None:
            result = [a for a in result if a.asset_type == asset_type]
        if source_tool is not None:
            result = [a for a in result if a.source_tool == source_tool]
        return result

    def get_values(self, asset_type: AssetType) -> list[str]:
        """Get unique values for a specific asset type."""
        seen: set[str] = set()
        result: list[str] = []
        for a in self._assets:
            if a.asset_type == asset_type and a.value not in seen:
                seen.add(a.value)
                result.append(a.value)
        return result

    def targets_for_phase(self, phase: Phase) -> list[str]:
        """Get the best target list for a given phase based on accumulated data."""
        if phase == Phase.RECON:
            return self.get_values(AssetType.SUBDOMAIN)

        if phase == Phase.SCANNING:
            subs = self.get_values(AssetType.SUBDOMAIN)
            ips = self.get_values(AssetType.IP)
            return subs + [ip for ip in ips if ip not in subs]

        if phase == Phase.VULN_ANALYSIS:
            urls = self.get_values(AssetType.URL)
            endpoints = self.get_values(AssetType.ENDPOINT)
            params = self.get_values(AssetType.PARAMETER)
            return urls + endpoints + params

        if phase == Phase.EXPLOITATION:
            return [f["target"] for f in self._findings if f.get("confidence") in ("confirmed", "firm")]

        return []

    def suggest_next_steps(self, current_phase: Phase, max_steps: int = 5) -> list[NextStep]:
        """Recommend next tools to run based on accumulated context."""
        suggestions: list[NextStep] = []
        available_types = {a.asset_type for a in self._assets}

        # Check current phase and next phase
        phases_to_check = [current_phase]
        phase_order = list(Phase)
        current_idx = phase_order.index(current_phase)
        if current_idx + 1 < len(phase_order):
            phases_to_check.append(phase_order[current_idx + 1])

        for phase in phases_to_check:
            transitions = _PHASE_TRANSITIONS.get(phase, [])
            for t in transitions:
                tool = t["tool"]
                if tool in self._tools_run:
                    continue

                # Check if we have the required asset types
                needs = t.get("needs", [])
                has_needs = not needs or any(n in available_types for n in needs)

                if not has_needs:
                    continue

                # Check finding-specific requirements
                req_finding = t.get("requires_finding", "")
                if req_finding:
                    matching = [f for f in self._findings if f.get("vuln_type") == req_finding]
                    if not matching:
                        continue

                # Get relevant targets
                targets = []
                for need_type in needs:
                    targets.extend(self.get_values(need_type)[:10])  # cap at 10

                suggestions.append(NextStep(
                    tool=tool,
                    reason=t["reason"],
                    targets=targets[:10],
                    priority=len(suggestions),
                    phase=phase,
                ))

        return suggestions[:max_steps]

    def summary(self) -> dict[str, Any]:
        """Full pipeline state summary."""
        type_counts: dict[str, int] = {}
        for a in self._assets:
            key = a.asset_type.value
            type_counts[key] = type_counts.get(key, 0) + 1

        return {
            "total_assets": len(self._assets),
            "asset_counts": type_counts,
            "tools_run": self._tools_run,
            "tools_run_count": len(self._tools_run),
            "findings_count": len(self._findings),
            "findings": self._findings,
            "subdomains": self.get_values(AssetType.SUBDOMAIN)[:20],
            "open_ports": self.get_values(AssetType.PORT)[:20],
            "urls": self.get_values(AssetType.URL)[:20],
            "endpoints": self.get_values(AssetType.ENDPOINT)[:20],
            "parameters": self.get_values(AssetType.PARAMETER)[:20],
            "technologies": self.get_values(AssetType.TECHNOLOGY)[:20],
        }

    def reset(self) -> None:
        """Clear all accumulated state."""
        self._assets.clear()
        self._tools_run.clear()
        self._findings.clear()


def _infer_vuln_type(tool_name: str) -> str:
    """Infer vulnerability type from tool name."""
    mapping = {
        "vuln_sqli": "sqli",
        "exploit_sqli": "sqli",
        "vuln_xss": "xss",
        "vuln_ssrf": "ssrf",
        "exploit_ssrf": "ssrf",
        "vuln_cors": "cors",
        "vuln_jwt": "jwt",
        "vuln_idor": "idor",
        "vuln_subdomain_takeover": "subdomain_takeover",
        "api_test_bola": "bola",
        "api_test_bfla": "bfla",
        "api_test_misconfig": "misconfig",
        "cloud_imds_test": "ssrf",
    }
    return mapping.get(tool_name, tool_name.replace("vuln_", "").replace("exploit_", ""))


# Singleton
_pipeline: SessionPipeline | None = None


def get_pipeline() -> SessionPipeline:
    global _pipeline
    if _pipeline is None:
        _pipeline = SessionPipeline()
    return _pipeline


def reset_pipeline() -> SessionPipeline:
    """Reset pipeline for a new session."""
    global _pipeline
    _pipeline = SessionPipeline()
    return _pipeline
