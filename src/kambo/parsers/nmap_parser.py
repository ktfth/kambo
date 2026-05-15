"""Parser for Nmap output (greppable and JSON formats)."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET


def parse_nmap(raw: str) -> dict:
    """Parse nmap output into structured data.

    Handles both normal output and greppable format.
    For best results, use -oX - (XML to stdout) or -oG - (greppable to stdout).
    """
    # Try XML first
    if raw.strip().startswith("<?xml") or "<nmaprun" in raw:
        return _parse_xml(raw)

    # Try greppable format
    if "Host:" in raw and "Ports:" in raw:
        return _parse_greppable(raw)

    # Fallback: parse normal output
    return _parse_normal(raw)


def _parse_xml(raw: str) -> dict:
    """Parse nmap XML output."""
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return {"error": "Failed to parse XML", "raw": raw[:1000]}

    hosts = []
    for host_elem in root.findall(".//host"):
        host_data: dict = {"addresses": [], "ports": [], "os": None, "status": "unknown"}

        # Status
        status = host_elem.find("status")
        if status is not None:
            host_data["status"] = status.get("state", "unknown")

        # Addresses
        for addr in host_elem.findall("address"):
            host_data["addresses"].append({
                "addr": addr.get("addr", ""),
                "type": addr.get("addrtype", ""),
            })

        # Ports
        for port in host_elem.findall(".//port"):
            port_data = {
                "port": int(port.get("portid", 0)),
                "protocol": port.get("protocol", "tcp"),
                "state": "unknown",
                "service": "",
                "version": "",
            }
            state = port.find("state")
            if state is not None:
                port_data["state"] = state.get("state", "unknown")
            service = port.find("service")
            if service is not None:
                port_data["service"] = service.get("name", "")
                port_data["version"] = f"{service.get('product', '')} {service.get('version', '')}".strip()
            host_data["ports"].append(port_data)

        # OS detection
        os_match = host_elem.find(".//osmatch")
        if os_match is not None:
            host_data["os"] = os_match.get("name", "")

        hosts.append(host_data)

    return {"hosts": hosts, "total_hosts": len(hosts)}


def _parse_greppable(raw: str) -> dict:
    """Parse nmap greppable (-oG) format."""
    hosts = []
    for line in raw.splitlines():
        if not line.startswith("Host:"):
            continue

        host_match = re.match(r"Host:\s+(\S+)\s+\(([^)]*)\)", line)
        if not host_match:
            continue

        ip = host_match.group(1)
        hostname = host_match.group(2)

        ports = []
        ports_section = re.search(r"Ports:\s+(.*?)(?:\t|$)", line)
        if ports_section:
            for port_str in ports_section.group(1).split(","):
                parts = port_str.strip().split("/")
                if len(parts) >= 5:
                    ports.append({
                        "port": int(parts[0]),
                        "state": parts[1],
                        "protocol": parts[2],
                        "service": parts[4],
                        "version": parts[6] if len(parts) > 6 else "",
                    })

        hosts.append({"ip": ip, "hostname": hostname, "ports": ports})

    return {"hosts": hosts, "total_hosts": len(hosts)}


def _parse_normal(raw: str) -> dict:
    """Parse standard nmap output text."""
    hosts = []
    current_host: dict | None = None

    for line in raw.splitlines():
        # Host line
        host_match = re.match(r"Nmap scan report for\s+(\S+)(?:\s+\((\S+)\))?", line)
        if host_match:
            if current_host:
                hosts.append(current_host)
            current_host = {
                "hostname": host_match.group(1),
                "ip": host_match.group(2) or host_match.group(1),
                "ports": [],
            }
            continue

        # Port line
        port_match = re.match(r"(\d+)/(tcp|udp)\s+(\S+)\s+(.+)", line)
        if port_match and current_host is not None:
            current_host["ports"].append({
                "port": int(port_match.group(1)),
                "protocol": port_match.group(2),
                "state": port_match.group(3),
                "service": port_match.group(4).strip(),
            })

    if current_host:
        hosts.append(current_host)

    return {"hosts": hosts, "total_hosts": len(hosts)}
