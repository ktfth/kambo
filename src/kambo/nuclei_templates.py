"""Custom Nuclei template generator — create templates from confirmed findings.

When a vulnerability is confirmed, generate a reusable Nuclei template
that can re-test the same pattern across targets or monitor for regression.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import yaml


def _make_template_id(vuln_type: str, finding_id: str) -> str:
    """Generate a consistent template ID."""
    return f"kambo-{vuln_type}-{finding_id.lower().replace('-', '')}"


def generate_template(
    finding_id: str,
    vuln_type: str,
    target: str,
    method: str = "GET",
    path: str = "/",
    parameter: str = "",
    payload: str = "",
    match_patterns: list[str] | None = None,
    status_codes: list[int] | None = None,
    severity: str = "high",
    description: str = "",
    tags: list[str] | None = None,
) -> str:
    """Generate a Nuclei YAML template from a confirmed finding.

    Args:
        finding_id: Kambo finding ID (e.g., FIND-001)
        vuln_type: Vulnerability type (sqli, xss, ssrf, etc.)
        target: Original target URL
        method: HTTP method
        path: URL path
        parameter: Vulnerable parameter name
        payload: Exploit payload
        match_patterns: Response patterns that confirm vulnerability
        status_codes: Expected status codes
        severity: Severity level
        description: Finding description
        tags: Additional tags
    """
    template_id = _make_template_id(vuln_type, finding_id)
    effective_tags = tags or [vuln_type, "kambo", "custom"]

    template: dict[str, Any] = {
        "id": template_id,
        "info": {
            "name": f"Kambo Custom - {vuln_type.upper()} ({finding_id})",
            "author": "kambo-mcp",
            "severity": severity,
            "description": description or f"Custom template generated from confirmed {vuln_type} finding",
            "tags": ",".join(effective_tags),
            "metadata": {
                "source": "kambo",
                "finding_id": finding_id,
                "generated_at": datetime.now(timezone.utc).isoformat(),
            },
        },
    }

    # Build the HTTP request
    request = _build_request(vuln_type, method, path, parameter, payload, match_patterns, status_codes)
    template["http"] = [request]

    return yaml.dump(template, default_flow_style=False, sort_keys=False)


def _build_request(
    vuln_type: str,
    method: str,
    path: str,
    parameter: str,
    payload: str,
    match_patterns: list[str] | None,
    status_codes: list[int] | None,
) -> dict[str, Any]:
    """Build the HTTP request section of a Nuclei template."""
    request: dict[str, Any] = {"method": method}

    # Build path with payload
    if parameter and payload:
        if method.upper() == "GET":
            sep = "&" if "?" in path else "?"
            request["path"] = [f"{{{{BaseURL}}}}{path}{sep}{parameter}={payload}"]
        else:
            request["path"] = [f"{{{{BaseURL}}}}{path}"]
            request["body"] = f"{parameter}={payload}"
    else:
        request["path"] = [f"{{{{BaseURL}}}}{path}"]

    # Add matchers based on vuln type
    matchers = _build_matchers(vuln_type, match_patterns, status_codes)
    if matchers:
        request["matchers-condition"] = "and"
        request["matchers"] = matchers

    return request


def _build_matchers(
    vuln_type: str,
    custom_patterns: list[str] | None,
    status_codes: list[int] | None,
) -> list[dict[str, Any]]:
    """Build matchers for a specific vulnerability type."""
    matchers: list[dict[str, Any]] = []

    # Status code matcher
    if status_codes:
        matchers.append({
            "type": "status",
            "status": status_codes,
        })

    # Custom pattern matchers
    if custom_patterns:
        matchers.append({
            "type": "word",
            "words": custom_patterns,
            "condition": "or",
        })
        return matchers

    # Default matchers by vuln type
    default_matchers = _default_matchers_for_type(vuln_type)
    matchers.extend(default_matchers)

    return matchers


def _default_matchers_for_type(vuln_type: str) -> list[dict[str, Any]]:
    """Get default detection matchers for common vulnerability types."""
    matchers_map: dict[str, list[dict[str, Any]]] = {
        "sqli": [
            {
                "type": "word",
                "words": ["SQL syntax", "mysql_fetch", "ORA-", "syntax error", "SQLSTATE"],
                "condition": "or",
            },
        ],
        "xss": [
            {
                "type": "word",
                "words": ["<script>", "javascript:", "onerror=", "onload="],
                "condition": "or",
            },
        ],
        "ssrf": [
            {
                "type": "word",
                "words": ["ami-id", "instance-id", "root:x:0:0", "compute/metadata"],
                "condition": "or",
            },
        ],
        "lfi": [
            {
                "type": "word",
                "words": ["root:x:0:0", "[boot loader]", "BEGIN RSA PRIVATE KEY"],
                "condition": "or",
            },
        ],
        "rce": [
            {
                "type": "regex",
                "regex": ["uid=\\d+\\(\\w+\\)\\s+gid=\\d+"],
            },
        ],
        "xxe": [
            {
                "type": "word",
                "words": ["root:x:0:0", "SYSTEM", "DOCTYPE"],
                "condition": "or",
            },
        ],
        "cors": [
            {
                "type": "word",
                "words": ["Access-Control-Allow-Origin: *", "Access-Control-Allow-Credentials: true"],
                "condition": "or",
                "part": "header",
            },
        ],
        "open_redirect": [
            {
                "type": "regex",
                "regex": ["(?i)Location:\\s*https?://evil"],
                "part": "header",
            },
        ],
    }

    return matchers_map.get(vuln_type, [])


def generate_template_from_finding(finding: dict[str, Any]) -> str:
    """Generate a template from a Kambo finding dict.

    Convenience wrapper that extracts fields from the finding structure.
    """
    return generate_template(
        finding_id=finding.get("id", "FIND-000"),
        vuln_type=finding.get("vuln_type", finding.get("type", "unknown")),
        target=finding.get("target", ""),
        method=finding.get("method", "GET"),
        path=finding.get("path", "/"),
        parameter=finding.get("parameter", ""),
        payload=finding.get("payload", ""),
        match_patterns=finding.get("match_patterns"),
        status_codes=finding.get("status_codes"),
        severity=finding.get("severity", "high"),
        description=finding.get("description", ""),
        tags=finding.get("tags"),
    )


class TemplateLibrary:
    """Manages a collection of generated templates."""

    def __init__(self) -> None:
        self._templates: dict[str, str] = {}  # id -> yaml content

    def add(self, template_id: str, yaml_content: str) -> None:
        self._templates[template_id] = yaml_content

    def get(self, template_id: str) -> str | None:
        return self._templates.get(template_id)

    def list_templates(self) -> list[str]:
        return list(self._templates.keys())

    @property
    def count(self) -> int:
        return len(self._templates)

    def generate_and_store(self, **kwargs: Any) -> str:
        """Generate a template and store it in the library."""
        yaml_content = generate_template(**kwargs)
        template_id = _make_template_id(kwargs.get("vuln_type", "unknown"), kwargs.get("finding_id", "FIND-000"))
        self.add(template_id, yaml_content)
        return yaml_content

    def export_all(self) -> str:
        """Export all templates as concatenated YAML."""
        return "\n---\n".join(self._templates.values())


# Singleton
_library: TemplateLibrary | None = None


def get_template_library() -> TemplateLibrary:
    global _library
    if _library is None:
        _library = TemplateLibrary()
    return _library
