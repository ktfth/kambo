"""Bug bounty platform API integrations.

Supports HackerOne and Bugcrowd APIs for:
- Fetching program details and scope
- Checking for duplicate reports
- Submitting vulnerability reports

API credentials are read from environment variables:
  HACKERONE_API_USER / HACKERONE_API_TOKEN
  BUGCROWD_API_TOKEN
"""

from __future__ import annotations

import asyncio
import os
from typing import Any
from urllib.parse import quote

import requests

from kambo.host_parse import extract_host
from kambo.scope import (
    ScopeViolationError,
    active_engagement_key,
    get_scope_manager,
    validate_scope,
)


# ---------------------------------------------------------------------------
# HackerOne API
# ---------------------------------------------------------------------------

_H1_BASE = "https://api.hackerone.com/v1"


def _h1_auth() -> tuple[str, str]:
    """Get HackerOne API credentials from environment."""
    user = os.environ.get("HACKERONE_API_USER", "")
    token = os.environ.get("HACKERONE_API_TOKEN", "")
    if not user or not token:
        raise ValueError(
            "HackerOne API credentials not set. "
            "Export HACKERONE_API_USER and HACKERONE_API_TOKEN."
        )
    return (user, token)


def h1_fetch_program(handle: str) -> dict[str, Any]:
    """Fetch HackerOne program details by handle.

    Args:
        handle: Program handle (e.g., 'security' for hackerone.com/security)
    """
    auth = _h1_auth()
    resp = requests.get(
        f"{_H1_BASE}/hackers/programs/{quote(handle)}",
        auth=auth,
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json().get("data", {})
    attrs = data.get("attributes", {})

    return {
        "platform": "hackerone",
        "handle": handle,
        "name": attrs.get("name", handle),
        "state": attrs.get("state", ""),
        "offers_bounties": attrs.get("offers_bounties", False),
        "response_efficiency": attrs.get("response_efficiency_percentage"),
        "submission_state": attrs.get("submission_state", ""),
        "started_accepting": attrs.get("started_accepting_at", ""),
    }


def h1_fetch_scope(handle: str) -> dict[str, Any]:
    """Fetch structured assets (scope) for a HackerOne program.

    Paginates through all results to avoid missing assets.

    Args:
        handle: Program handle
    """
    auth = _h1_auth()
    raw_scopes: list[dict] = []
    page_number = 1
    max_pages = 10  # safety cap

    while page_number <= max_pages:
        resp = requests.get(
            f"{_H1_BASE}/hackers/programs/{quote(handle)}/structured_scopes",
            auth=auth,
            params={"page[size]": 100, "page[number]": page_number},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        page_data = data.get("data", [])
        raw_scopes.extend(page_data)

        # Check for next page
        next_link = data.get("links", {}).get("next")
        if not next_link or len(page_data) < 100:
            break
        page_number += 1

    in_scope = []
    out_of_scope = []

    for item in raw_scopes:
        attrs = item.get("attributes", {})
        entry = {
            "asset": attrs.get("asset_identifier", ""),
            "asset_type": attrs.get("asset_type", ""),
            "eligible_for_bounty": attrs.get("eligible_for_bounty", False),
            "eligible_for_submission": attrs.get("eligible_for_submission", True),
            "instruction": attrs.get("instruction", ""),
            "max_severity": attrs.get("max_severity", ""),
        }
        if attrs.get("eligible_for_submission", True):
            in_scope.append(entry)
        else:
            out_of_scope.append(entry)

    return {
        "platform": "hackerone",
        "handle": handle,
        "in_scope": in_scope,
        "out_of_scope": out_of_scope,
        "total_assets": len(in_scope),
    }


def h1_check_duplicate(handle: str, title: str, vuln_type: str = "") -> dict[str, Any]:
    """Check if a similar report already exists (via disclosed reports).

    Args:
        handle: Program handle
        title: Finding title to search for
        vuln_type: Vulnerability type keyword
    """
    auth = _h1_auth()

    # Search disclosed reports via the hacktivity endpoint
    search_term = vuln_type or title.split()[0] if title else ""
    resp = requests.get(
        f"{_H1_BASE}/hackers/programs/{quote(handle)}/reports",
        auth=auth,
        params={
            "filter[state][]": "disclosed",
            "page[size]": 25,
        },
        timeout=30,
    )

    # The Hacker REST API does not reliably expose other researchers' disclosed
    # reports at this endpoint — 401/403/404 are returned even with valid
    # credentials (disclosed reports live behind the Hacktivity GraphQL API).
    # Degrade gracefully instead of raising so hunt pipelines don't break on the
    # duplicate-check step.
    if resp.status_code != 200:
        return {
            "platform": "hackerone",
            "handle": handle,
            "possible_duplicates": [],
            "duplicate_risk": "unknown",
            "warning": (
                f"Duplicate check unavailable (HTTP {resp.status_code}). The Hacker "
                "API does not expose disclosed program reports at this endpoint — "
                f"review manually at https://hackerone.com/{handle}/hacktivity"
            ),
        }

    reports = resp.json().get("data", [])

    possible_dupes = []
    title_lower = title.lower()
    search_lower = search_term.lower()

    for report in reports:
        attrs = report.get("attributes", {})
        report_title = attrs.get("title", "").lower()
        if search_lower in report_title or any(word in report_title for word in title_lower.split()[:3]):
            possible_dupes.append({
                "id": report.get("id", ""),
                "title": attrs.get("title", ""),
                "state": attrs.get("state", ""),
                "severity": attrs.get("severity_rating", ""),
                "disclosed_at": attrs.get("disclosed_at", ""),
            })

    return {
        "platform": "hackerone",
        "handle": handle,
        "search_term": search_term,
        "possible_duplicates": possible_dupes[:10],
        "duplicate_risk": "high" if len(possible_dupes) > 2 else "low" if not possible_dupes else "medium",
    }


def h1_submit_report(
    handle: str,
    title: str,
    vulnerability_info: str,
    severity: str = "medium",
    weakness_id: int = 0,
    asset_identifier: str = "",
    impact: str = "",
) -> dict[str, Any]:
    """Submit a vulnerability report to HackerOne.

    Args:
        handle: Program handle
        title: Report title
        vulnerability_info: Full report body (markdown)
        severity: Severity rating (none, low, medium, high, critical)
        weakness_id: CWE weakness ID (optional)
        asset_identifier: Affected asset from scope
        impact: Impact description
    """
    auth = _h1_auth()

    payload: dict[str, Any] = {
        "data": {
            "type": "report",
            "attributes": {
                "team_handle": handle,
                "title": title,
                "vulnerability_information": vulnerability_info,
                "severity_rating": severity,
                "impact": impact,
            },
        }
    }

    if weakness_id:
        payload["data"]["relationships"] = {
            "weakness": {"data": {"type": "weakness", "id": weakness_id}}
        }

    if asset_identifier:
        payload["data"]["relationships"] = payload["data"].get("relationships", {})
        payload["data"]["relationships"]["structured_scope"] = {
            "data": {"type": "structured-scope", "attributes": {"asset_identifier": asset_identifier}}
        }

    resp = requests.post(
        f"{_H1_BASE}/hackers/reports",
        auth=auth,
        json=payload,
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json().get("data", {})

    return {
        "platform": "hackerone",
        "report_id": data.get("id", ""),
        "status": "submitted",
        "url": f"https://hackerone.com/reports/{data.get('id', '')}",
        "title": title,
    }


# ---------------------------------------------------------------------------
# Bugcrowd API
# ---------------------------------------------------------------------------

_BC_BASE = "https://api.bugcrowd.com"


def _bc_headers() -> dict[str, str]:
    """Get Bugcrowd API headers."""
    token = os.environ.get("BUGCROWD_API_TOKEN", "")
    if not token:
        raise ValueError("Bugcrowd API token not set. Export BUGCROWD_API_TOKEN.")
    return {
        "Authorization": f"Token {token}",
        "Accept": "application/vnd.bugcrowd+json",
    }


def bc_fetch_program(slug: str) -> dict[str, Any]:
    """Fetch Bugcrowd program details by slug.

    Args:
        slug: Program slug (from URL)
    """
    headers = _bc_headers()
    resp = requests.get(
        f"{_BC_BASE}/programs/{quote(slug)}",
        headers=headers,
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json().get("data", {})
    attrs = data.get("attributes", {})

    return {
        "platform": "bugcrowd",
        "slug": slug,
        "name": attrs.get("name", slug),
        "tagline": attrs.get("tagline", ""),
        "started_at": attrs.get("started_at", ""),
        "reward_range": attrs.get("reward_range", ""),
        "participation": attrs.get("participation", ""),
    }


def bc_fetch_scope(slug: str) -> dict[str, Any]:
    """Fetch scope/targets for a Bugcrowd program.

    Paginates through all results to avoid missing assets.

    Args:
        slug: Program slug
    """
    headers = _bc_headers()
    raw_targets: list[dict] = []
    offset = 0
    max_pages = 10

    for _ in range(max_pages):
        resp = requests.get(
            f"{_BC_BASE}/programs/{quote(slug)}/targets",
            headers=headers,
            params={"page[limit]": 100, "page[offset]": offset},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        page_data = data.get("data", [])
        raw_targets.extend(page_data)

        if len(page_data) < 100:
            break
        offset += 100

    targets = []
    for item in raw_targets:
        attrs = item.get("attributes", {})
        targets.append({
            "name": attrs.get("name", ""),
            "category": attrs.get("category", ""),
            "uri": attrs.get("uri", ""),
            "in_scope": attrs.get("in_scope", True),
        })

    in_scope = [t for t in targets if t.get("in_scope", True)]
    out_of_scope = [t for t in targets if not t.get("in_scope", True)]

    return {
        "platform": "bugcrowd",
        "slug": slug,
        "in_scope": in_scope,
        "out_of_scope": out_of_scope,
        "total_assets": len(in_scope),
    }


def bc_submit_report(
    slug: str,
    title: str,
    description: str,
    severity: int = 3,
    vrt: str = "",
    steps_to_reproduce: str = "",
) -> dict[str, Any]:
    """Submit a vulnerability report to Bugcrowd.

    Args:
        slug: Program slug
        title: Report title
        description: Full vulnerability description
        severity: Priority (1-5, where 1=critical)
        vrt: Vulnerability Rating Taxonomy classification
        steps_to_reproduce: Reproduction steps
    """
    headers = _bc_headers()

    payload = {
        "data": {
            "type": "submission",
            "attributes": {
                "title": title,
                "description": description,
                "severity": severity,
                "vrt_id": vrt,
                "steps_to_reproduce": steps_to_reproduce,
            },
            "relationships": {
                "program": {"data": {"type": "program", "id": slug}},
            },
        }
    }

    resp = requests.post(
        f"{_BC_BASE}/submissions",
        headers=headers,
        json=payload,
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json().get("data", {})

    return {
        "platform": "bugcrowd",
        "submission_id": data.get("id", ""),
        "status": "submitted",
        "title": title,
    }


# ---------------------------------------------------------------------------
# Unified interface for MCP tools
# ---------------------------------------------------------------------------

async def platform_fetch_program(platform: str, handle: str) -> dict[str, Any]:
    """Fetch program details from any platform."""
    if platform == "hackerone":
        return await asyncio.to_thread(h1_fetch_program, handle)
    if platform == "bugcrowd":
        return await asyncio.to_thread(bc_fetch_program, handle)
    return {"error": f"Unsupported platform: {platform}. Use 'hackerone' or 'bugcrowd'."}


async def platform_fetch_scope(platform: str, handle: str) -> dict[str, Any]:
    """Fetch program scope from any platform."""
    if platform == "hackerone":
        return await asyncio.to_thread(h1_fetch_scope, handle)
    if platform == "bugcrowd":
        return await asyncio.to_thread(bc_fetch_scope, handle)
    return {"error": f"Unsupported platform: {platform}"}


async def platform_check_duplicate(
    platform: str, handle: str, title: str, vuln_type: str = ""
) -> dict[str, Any]:
    """Check for duplicate reports on any platform."""
    if platform == "hackerone":
        return await asyncio.to_thread(h1_check_duplicate, handle, title, vuln_type)
    return {"error": f"Duplicate check not available for: {platform}", "platform": platform}


def _submission_refusal(platform: str, handle: str, report: dict[str, Any]) -> str:
    """Reason to refuse this submission, or ``""`` when it may proceed.

    Submitting is the only irreversible action in the server: it publishes a
    working exploit for someone else's asset, and it cannot be recalled. So it
    is gated like a network touch, not like a read. Every check below compares
    the submission against the *active engagement*, because the failure mode
    that matters is submitting program A's finding to program B — disclosing an
    unfixed vulnerability of one customer to another.
    """
    scope = get_scope_manager().scope
    if scope is None:
        return (
            "No engagement scope configured. Submitting a report without an active "
            "scope cannot be checked against the program it belongs to — refusing."
        )

    if scope.platform and scope.platform.strip().lower() != platform.strip().lower():
        return (
            f"Platform mismatch: the active engagement is on '{scope.platform}' but "
            f"this report is being submitted to '{platform}'. Refusing — set the "
            "scope for the program you are actually reporting to."
        )

    asset = str(report.get("asset", "")).strip()
    if asset:
        try:
            validate_scope(asset)
        except ScopeViolationError as exc:
            return (
                f"Asset '{asset}' is not part of the active engagement ({exc.reason}). "
                "Refusing — this is how one program's finding ends up filed against "
                "another."
            )

    return ""


async def _load_other_engagement_targets() -> set[str]:
    """Read the findings store and collect targets from other engagements."""
    try:
        from kambo.database import get_database

        db = await get_database()
        # Bounded: an unreachable or locked store must not stall a submission
        # indefinitely — the scope, platform and asset gates still apply.
        rows = await asyncio.wait_for(db.get_findings(), timeout=10)
    except Exception:  # pragma: no cover - store unavailable, other gates stand
        return set()

    active = active_engagement_key()
    hosts: set[str] = set()
    for row in rows:
        if str(row.get("engagement_key", "")) == active:
            continue
        host = extract_host(str(row.get("target", "")))
        if host:
            hosts.add(host)
    return hosts


async def platform_submit_report(platform: str, handle: str, report: dict[str, Any]) -> dict[str, Any]:
    """Submit a report to any platform.

    Gated: see :func:`_submission_refusal`. A refusal returns an error instead of
    submitting — there is no override flag, because the whole point is that the
    caller who wants to submit is the one who may be mistaken about which
    program this finding belongs to.
    """
    refusal = _submission_refusal(platform, handle, report)
    if not refusal:
        foreign = await _load_other_engagement_targets()
        text = f"{report.get('title', '')}\n{report.get('body', '')}\n{report.get('asset', '')}".lower()
        cited = {host for host in foreign if host in text}
        if cited:
            refusal = (
                "Report text references host(s) recorded under a different engagement: "
                f"{', '.join(sorted(cited))}. Refusing — submitting one program's "
                "finding to another discloses an unfixed vulnerability to a third party."
            )
    if refusal:
        return {"error": refusal, "status": "refused", "platform": platform, "handle": handle}

    if platform == "hackerone":
        return await asyncio.to_thread(
            h1_submit_report,
            handle, report["title"], report["body"],
            report.get("severity", "medium"),
            report.get("weakness_id", 0),
            report.get("asset", ""),
            report.get("impact", ""),
        )
    if platform == "bugcrowd":
        return await asyncio.to_thread(
            bc_submit_report,
            handle, report["title"], report["body"],
            report.get("priority", 3),
            report.get("vrt", ""),
            report.get("steps", ""),
        )
    return {"error": f"Unsupported platform: {platform}"}
