"""Intelligent rate limiting and WAF evasion for tool execution.

Provides:
- Adaptive throttling based on response patterns
- WAF detection from response signatures
- Request spacing with jitter
- Per-target rate tracking
- Evasion recommendations when WAF is detected

This module does NOT modify tool behavior automatically.
It provides signals that tools and the pipeline can use to adjust.
"""

from __future__ import annotations

import random
import time
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class WafSignature(BaseModel):
    """Known WAF/CDN signature pattern."""

    name: str
    patterns: list[str]  # regex patterns to match in response
    headers: list[str] = Field(default_factory=list)  # header names to check

    model_config = {"frozen": True}


# Known WAF signatures
WAF_SIGNATURES: list[WafSignature] = [
    WafSignature(name="Cloudflare", patterns=[r"cloudflare", r"cf-ray", r"__cfduid"], headers=["cf-ray", "cf-cache-status"]),
    WafSignature(name="AWS WAF", patterns=[r"awselb", r"x-amzn-requestid"], headers=["x-amzn-requestid"]),
    WafSignature(name="Akamai", patterns=[r"akamai", r"x-akamai-transformed"], headers=["x-akamai-transformed"]),
    WafSignature(name="Imperva/Incapsula", patterns=[r"incapsula", r"imperva", r"visid_incap"], headers=["x-iinfo"]),
    WafSignature(name="ModSecurity", patterns=[r"mod_security", r"modsecurity", r"NOYB"]),
    WafSignature(name="F5 BIG-IP", patterns=[r"bigipserver", r"f5-trafficshield"], headers=["x-cnection"]),
    WafSignature(name="Sucuri", patterns=[r"sucuri", r"x-sucuri-id"], headers=["x-sucuri-id"]),
    WafSignature(name="Barracuda", patterns=[r"barracuda", r"barra_counter_session"]),
    WafSignature(name="Fortinet/FortiWeb", patterns=[r"fortigate", r"fortiweb", r"FORTIWAFSID"]),
    WafSignature(name="Wordfence", patterns=[r"wordfence", r"wfwaf-authcookie"]),
]

# Response patterns that indicate rate limiting or blocking
BLOCK_PATTERNS: list[str] = [
    r"rate limit",
    r"too many requests",
    r"request rate too large",
    r"throttled",
    r"slow down",
    r"blocked",
    r"access denied",
    r"forbidden",
    r"captcha",
    r"challenge",
]


class RateState(BaseModel):
    """Per-target rate limiting state."""

    target: str
    requests_made: int = 0
    last_request_time: float = 0
    consecutive_blocks: int = 0
    waf_detected: str = ""
    current_delay_ms: float = 100  # start with 100ms
    max_delay_ms: float = 5000
    min_delay_ms: float = 50
    blocked_at: float = 0  # timestamp of last block

    def record_request(self) -> None:
        self.requests_made += 1
        self.last_request_time = time.time()

    def record_block(self) -> None:
        self.consecutive_blocks += 1
        self.blocked_at = time.time()
        # Exponential backoff
        self.current_delay_ms = min(
            self.max_delay_ms,
            self.current_delay_ms * 2,
        )

    def record_success(self) -> None:
        if self.consecutive_blocks > 0:
            self.consecutive_blocks = max(0, self.consecutive_blocks - 1)
        # Slowly reduce delay on success
        if self.current_delay_ms > self.min_delay_ms:
            self.current_delay_ms = max(
                self.min_delay_ms,
                self.current_delay_ms * 0.9,
            )

    @property
    def is_blocked(self) -> bool:
        return self.consecutive_blocks >= 3

    @property
    def delay_seconds(self) -> float:
        """Get the recommended delay with jitter."""
        base = self.current_delay_ms / 1000.0
        jitter = random.uniform(0, base * 0.3)
        return base + jitter

    @property
    def requests_per_minute(self) -> float:
        if self.last_request_time == 0 or self.requests_made <= 1:
            return 0
        elapsed = time.time() - (self.last_request_time - (self.requests_made * self.delay_seconds))
        if elapsed <= 0:
            return 0
        return (self.requests_made / elapsed) * 60


def detect_waf(response_body: str, response_headers: str = "") -> str | None:
    """Detect WAF from response content and headers.

    Returns the WAF name if detected, None otherwise.
    """
    import re

    combined = (response_body + " " + response_headers).lower()

    for sig in WAF_SIGNATURES:
        for pattern in sig.patterns:
            if re.search(pattern, combined, re.IGNORECASE):
                return sig.name

        for header in sig.headers:
            if header.lower() in response_headers.lower():
                return sig.name

    return None


def detect_block(response_body: str, status_code: int = 0) -> bool:
    """Detect if a response indicates rate limiting or blocking."""
    import re

    if status_code in (429, 503, 403):
        return True

    body_lower = response_body.lower()
    for pattern in BLOCK_PATTERNS:
        if re.search(pattern, body_lower):
            return True

    return False


def evasion_recommendations(waf_name: str) -> list[dict[str, str]]:
    """Get evasion technique recommendations for a specific WAF.

    Returns list of {technique, description, command_modifier} dicts.
    """
    generic = [
        {
            "technique": "request_spacing",
            "description": "Add delays between requests to avoid rate limiting",
            "command_modifier": "--delay 2",
        },
        {
            "technique": "user_agent_rotation",
            "description": "Rotate User-Agent headers to avoid fingerprinting",
            "command_modifier": "-H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)'",
        },
    ]

    waf_specific: dict[str, list[dict[str, str]]] = {
        "Cloudflare": [
            {
                "technique": "ip_rotation",
                "description": "Cloudflare rate-limits by IP. Use proxy rotation.",
                "command_modifier": "--proxy socks5://127.0.0.1:9050",
            },
            {
                "technique": "cf_clearance",
                "description": "Bypass Cloudflare JS challenge with cf-clearance cookie",
                "command_modifier": "-H 'Cookie: cf_clearance=<token>'",
            },
        ],
        "AWS WAF": [
            {
                "technique": "case_variation",
                "description": "AWS WAF rules are often case-sensitive",
                "command_modifier": "Use mixed-case payloads",
            },
            {
                "technique": "encoding",
                "description": "URL-encode or double-encode payloads",
                "command_modifier": "Use %2F, %252F for path traversal",
            },
        ],
        "ModSecurity": [
            {
                "technique": "comment_injection",
                "description": "Use SQL comments to bypass ModSecurity rules",
                "command_modifier": "Use /*!50000UNION*/ instead of UNION",
            },
            {
                "technique": "paranoia_level",
                "description": "ModSecurity paranoia level determines rule strictness",
                "command_modifier": "Test with gradually increasing payload complexity",
            },
        ],
    }

    return generic + waf_specific.get(waf_name, [])


class RateLimiter:
    """Global rate limiter tracking per-target state."""

    def __init__(self, default_delay_ms: float = 100) -> None:
        self._states: dict[str, RateState] = {}
        self._default_delay_ms = default_delay_ms

    def get_state(self, target: str) -> RateState:
        if target not in self._states:
            self._states[target] = RateState(
                target=target,
                current_delay_ms=self._default_delay_ms,
            )
        return self._states[target]

    def record_request(self, target: str, response_body: str = "", status_code: int = 200, headers: str = "") -> dict[str, Any]:
        """Record a request and analyze the response.

        Returns analysis dict with waf_detected, is_blocked, recommended_delay.
        """
        state = self.get_state(target)
        state.record_request()

        # Detect WAF
        waf = detect_waf(response_body, headers)
        if waf:
            state.waf_detected = waf

        # Detect blocking
        blocked = detect_block(response_body, status_code)
        if blocked:
            state.record_block()
        else:
            state.record_success()

        return {
            "target": target,
            "waf_detected": state.waf_detected or None,
            "is_blocked": state.is_blocked,
            "consecutive_blocks": state.consecutive_blocks,
            "recommended_delay_seconds": round(state.delay_seconds, 3),
            "requests_made": state.requests_made,
            "evasion_tips": evasion_recommendations(state.waf_detected) if state.waf_detected else [],
        }

    def should_wait(self, target: str) -> float:
        """Get the recommended wait time in seconds before next request."""
        state = self.get_state(target)
        return state.delay_seconds

    def summary(self) -> dict[str, Any]:
        """Get rate limiter state for all targets."""
        return {
            target: {
                "requests": s.requests_made,
                "waf": s.waf_detected or None,
                "blocked": s.is_blocked,
                "consecutive_blocks": s.consecutive_blocks,
                "delay_ms": round(s.current_delay_ms, 1),
            }
            for target, s in self._states.items()
        }

    def reset(self, target: str | None = None) -> None:
        if target:
            self._states.pop(target, None)
        else:
            self._states.clear()


# Singleton
_limiter: RateLimiter | None = None


def get_rate_limiter() -> RateLimiter:
    global _limiter
    if _limiter is None:
        _limiter = RateLimiter()
    return _limiter
