"""Input sanitization for shell commands.

All user-controlled values MUST be sanitized before interpolation into
shell commands passed to docker_runner.  This module provides the
canonical sanitization function.
"""

from __future__ import annotations

import re
import shlex


def shell_quote(value: str) -> str:
    """Safely quote a value for shell interpolation.

    Uses shlex.quote() which wraps the value in single quotes and escapes
    any embedded single quotes.  Returns an empty-string literal ('') for
    empty input to avoid generating a bare empty token.
    """
    return shlex.quote(value)


def validate_shell_arg(value: str, name: str = "argument", *, max_length: int = 4096) -> str:
    """Validate and quote a shell argument, rejecting obvious abuse.

    Raises ValueError for null bytes or values exceeding max_length.
    Returns the shlex-quoted value.
    """
    if "\x00" in value:
        raise ValueError(f"{name} contains null byte")
    if len(value) > max_length:
        raise ValueError(f"{name} exceeds maximum length ({len(value)} > {max_length})")
    return shell_quote(value)


_SAFE_PORT_SPEC = re.compile(r"^[\d,\- ]+$")


def validate_port_spec(ports: str) -> str:
    """Validate a port specification (e.g. '80,443' or '1-1024' or '-').

    Returns the original string if valid; raises ValueError otherwise.
    Port specs should NOT be shlex-quoted because nmap expects bare values.
    """
    stripped = ports.strip()
    if not stripped:
        raise ValueError("Empty port specification")
    if not _SAFE_PORT_SPEC.match(stripped):
        raise ValueError(f"Invalid port specification: {stripped!r}")
    return stripped


_SAFE_SEVERITY = re.compile(r"^[a-zA-Z,]+$")


def validate_severity(severity: str) -> str:
    """Validate a severity filter string (e.g. 'critical,high')."""
    stripped = severity.strip()
    if not _SAFE_SEVERITY.match(stripped):
        raise ValueError(f"Invalid severity filter: {stripped!r}")
    return stripped


_SAFE_TIMING = range(0, 6)


def validate_timing(timing: int) -> int:
    """Validate nmap timing template (0-5)."""
    if timing not in _SAFE_TIMING:
        raise ValueError(f"Invalid timing template: {timing}")
    return timing
