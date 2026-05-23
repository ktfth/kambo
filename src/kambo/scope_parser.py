"""Scope parser — extract and expand scope from platform program pages.

Parses scope definitions from HackerOne/Bugcrowd API responses
and expands wildcards into actionable target lists.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from kambo.models import EngagementScope, ScopeTarget


def parse_scope_from_platform(
    platform_data: dict[str, Any],
    platform: str = "hackerone",
) -> EngagementScope:
    """Parse platform API response into EngagementScope.

    Args:
        platform_data: Response from platform_fetch_scope
        platform: Platform name
    """
    in_scope = platform_data.get("in_scope", [])
    out_of_scope = platform_data.get("out_of_scope", [])

    targets: list[ScopeTarget] = []
    exclusions: list[str] = []

    for item in in_scope:
        asset = _extract_asset(item, platform)
        if asset:
            targets.append(ScopeTarget(
                target=asset,
                target_type=_classify_target(asset),
                notes=item.get("instruction", item.get("category", "")),
            ))

    for item in out_of_scope:
        asset = _extract_asset(item, platform)
        if asset:
            exclusions.append(asset)

    return EngagementScope(
        platform=platform,
        targets=targets,
        exclusions=exclusions,
    )


def _extract_asset(item: dict[str, Any], platform: str) -> str:
    """Extract the asset identifier from a scope item."""
    if platform == "hackerone":
        return item.get("asset", item.get("asset_identifier", ""))
    if platform == "bugcrowd":
        return item.get("uri", item.get("name", ""))
    return item.get("asset", item.get("target", ""))


def _classify_target(target: str) -> str:
    """Classify a target string into a type."""
    if target.startswith("*."):
        return "wildcard"
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d+)?$", target):
        return "ip" if "/" not in target else "cidr"
    if target.startswith("http://") or target.startswith("https://"):
        return "url"
    if "." in target:
        return "domain"
    return "other"


def expand_wildcards(targets: list[ScopeTarget]) -> list[str]:
    """Extract wildcard patterns and base domains for enumeration.

    Returns a list of base domains that should be used for
    subdomain enumeration.
    """
    domains: list[str] = []
    for t in targets:
        if t.target.startswith("*."):
            base = t.target[2:]
            domains.append(base)
        elif t.target_type == "domain":
            domains.append(t.target)
        elif t.target_type == "url":
            parsed = urlparse(t.target)
            if parsed.netloc:
                domains.append(parsed.netloc)
    return sorted(set(domains))


def check_target_in_scope(
    target: str,
    scope: EngagementScope,
) -> dict[str, Any]:
    """Check if a target is in scope and return detailed analysis.

    Returns a dict with:
    - in_scope: bool
    - matched_target: the scope entry that matched
    - is_excluded: if target matches an exclusion
    - warnings: list of potential issues
    """
    warnings: list[str] = []
    matched = ""
    matched_exclusion = ""

    # Check exclusions first
    for excl in scope.exclusions:
        if _matches_scope_entry(target, excl):
            matched_exclusion = excl
            break

    if matched_exclusion:
        return {
            "target": target,
            "in_scope": False,
            "is_excluded": True,
            "matched_exclusion": matched_exclusion,
            "warnings": ["Target matches an exclusion pattern"],
        }

    # Check against scope targets
    for scope_target in scope.targets:
        if _matches_scope_entry(target, scope_target.target):
            matched = scope_target.target

            # Check per-target exclusions
            for excl in scope_target.exclusions:
                if _matches_scope_entry(target, excl):
                    return {
                        "target": target,
                        "in_scope": False,
                        "is_excluded": True,
                        "matched_exclusion": excl,
                        "warnings": [f"Target matches per-target exclusion: {excl}"],
                    }

            # Check for edge cases
            if scope_target.target_type == "wildcard":
                warnings.append("Matched via wildcard — verify subdomain is actively used")
            if "staging" in target.lower() or "dev" in target.lower():
                warnings.append("Target appears to be staging/dev — confirm it's in-scope")
            if "internal" in target.lower() or "admin" in target.lower():
                warnings.append("Target may be internal — proceed with caution")

            return {
                "target": target,
                "in_scope": True,
                "matched_target": matched,
                "is_excluded": False,
                "warnings": warnings,
            }

    return {
        "target": target,
        "in_scope": False,
        "is_excluded": False,
        "matched_target": None,
        "warnings": ["Target does not match any in-scope entry"],
    }


def _matches_scope_entry(target: str, pattern: str) -> bool:
    """Check if a target matches a scope pattern."""
    # Extract domain from URL
    parsed_target = target
    if target.startswith("http://") or target.startswith("https://"):
        parsed = urlparse(target)
        parsed_target = parsed.netloc or target

    parsed_pattern = pattern
    if pattern.startswith("http://") or pattern.startswith("https://"):
        parsed_p = urlparse(pattern)
        parsed_pattern = parsed_p.netloc or pattern

    # Wildcard match: *.example.com
    if parsed_pattern.startswith("*."):
        base = parsed_pattern[2:]
        return parsed_target == base or parsed_target.endswith(f".{base}")

    # Exact match
    return parsed_target == parsed_pattern


def scope_summary(scope: EngagementScope) -> dict[str, Any]:
    """Generate a summary of the scope for display."""
    wildcards = [t.target for t in scope.targets if t.target.startswith("*.")]
    domains = [t.target for t in scope.targets if t.target_type == "domain"]
    urls = [t.target for t in scope.targets if t.target_type == "url"]
    ips = [t.target for t in scope.targets if t.target_type in ("ip", "cidr")]
    enum_domains = expand_wildcards(scope.targets)

    return {
        "platform": scope.platform,
        "total_targets": len(scope.targets),
        "wildcards": wildcards,
        "domains": domains,
        "urls": urls,
        "ips": ips,
        "exclusions": scope.exclusions,
        "enumeration_targets": enum_domains,
        "has_wildcards": len(wildcards) > 0,
    }
