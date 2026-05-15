"""Parser for subfinder and subdomain enumeration tools."""

from __future__ import annotations

import json


def parse_subfinder(raw: str) -> dict:
    """Parse subfinder output (one domain per line or JSON).

    Works with: subfinder, amass, crt.sh output.
    """
    # Try JSON (subfinder -json)
    subdomains_json = []
    is_json = False
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
            is_json = True
            subdomains_json.append({
                "host": entry.get("host", ""),
                "source": entry.get("source", "unknown"),
            })
        except json.JSONDecodeError:
            break

    if is_json and subdomains_json:
        unique_hosts = list({s["host"] for s in subdomains_json})
        sources = list({s["source"] for s in subdomains_json})
        return {
            "subdomains": sorted(unique_hosts),
            "total": len(unique_hosts),
            "sources": sources,
        }

    # Plain text: one subdomain per line
    subdomains = set()
    for line in raw.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "." in line:
            # Clean any extra info (some tools add [source] after)
            domain = line.split()[0].rstrip(".")
            if domain:
                subdomains.add(domain.lower())

    return {
        "subdomains": sorted(subdomains),
        "total": len(subdomains),
        "sources": ["text_output"],
    }
