"""Generic output parsers for tools without structured output."""

from __future__ import annotations

import json
import re


def parse_lines(raw: str) -> list[str]:
    """Parse newline-separated output into a list of non-empty lines."""
    return [line.strip() for line in raw.splitlines() if line.strip()]


def parse_json_output(raw: str) -> dict | list | None:
    """Attempt to parse JSON from raw output. Returns None on failure."""
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        # Try to find JSON within the output
        json_match = re.search(r'[\[{].*[\]}]', raw, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group())
            except (json.JSONDecodeError, ValueError):
                pass
    return None


def parse_key_value(raw: str, separator: str = ":") -> dict[str, str]:
    """Parse key:value formatted output."""
    result = {}
    for line in raw.splitlines():
        if separator in line:
            key, _, value = line.partition(separator)
            key = key.strip()
            value = value.strip()
            if key:
                result[key] = value
    return result


def extract_ips(raw: str) -> list[str]:
    """Extract IPv4 addresses from raw output."""
    pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    return list(set(re.findall(pattern, raw)))


def extract_urls(raw: str) -> list[str]:
    """Extract URLs from raw output."""
    pattern = r'https?://[^\s<>"\'}\])]+'
    return list(set(re.findall(pattern, raw)))


def extract_domains(raw: str) -> list[str]:
    """Extract domain names from raw output."""
    pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    return list(set(re.findall(pattern, raw)))
