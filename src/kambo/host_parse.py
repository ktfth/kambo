"""Host extraction and normalisation — the single parser behind every locality
decision in Kambo.

Scope enforcement is the project's most important safety guarantee, and every
scope bypass found so far came from the same root cause: a hand-rolled regex
that *looked* like it extracted a host but stopped at the wrong delimiter. A
character class that does not stop at ``?`` swallows a query string; one that
stops at ``:`` mistakes URL userinfo (RFC 3986 allows a colon in it) for the
host. Both produce a string that ends with an in-scope domain while the request
goes somewhere else entirely.

So there is exactly one parser, it is built on :func:`urllib.parse.urlsplit`
plus explicit hostname validation, and it fails closed: anything from which a
well-formed host cannot be derived yields ``KIND_MALFORMED`` and an empty key,
never a "best effort" fragment.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

# Value kinds returned by :func:`classify_value`.
KIND_HOST = "host"            # locational — must be validated against the scope
KIND_FREE = "free"            # not locational (bare port, request path)
KIND_MALFORMED = "malformed"  # looks locational but no host can be extracted

_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://")
_AUTHORITY_SPLIT = re.compile(r"[/?#]")
_BRACKETED_V6 = re.compile(r"^\[(?P<v6>[0-9A-Fa-f:.]+)\](?::\d+)?$")
_HOST_PORT = re.compile(r"^(?P<host>[^:]+):\d+$")
_DIGITS = re.compile(r"^\d+$")
# A hostname label set: letters, digits, dot, hyphen, underscore (``_dmarc``).
_HOSTNAME = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9._\-]*[A-Za-z0-9_])?$")


def host_key(host: str) -> str:
    """The validated, normalised host of ``host``, or ``""`` when it is not a
    well-formed host.

    Normalisation is case- and trailing-dot-insensitive because DNS is: ``ADMIN.
    example.com.`` and ``admin.example.com`` are the same name, and an exclusion
    that only matches one spelling is not an exclusion.

    Accepts IPv4/IPv6 literals (via :mod:`ipaddress`, so every textual spelling
    of an address folds onto its canonical form) and hostnames restricted to the
    DNS charset. A leading ``*.`` wildcard label is dropped so a wildcard SAN is
    checked against its base domain. Anything else — a blob with spaces, an
    embedded URL, a stray delimiter — is rejected rather than compared, since a
    suffix comparison against such a blob is exactly the bypass this module
    exists to prevent.
    """
    candidate = host.strip().rstrip(".").lower()
    if candidate.startswith("*."):
        candidate = candidate[2:]
    if not candidate:
        return ""
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        pass
    return candidate if _HOSTNAME.match(candidate) else ""


def classify_value(value: str) -> tuple[str, str]:
    """Classify a surface value as ``(kind, key)``.

    * ``KIND_HOST`` — locational; ``key`` is the bare, normalised host.
    * ``KIND_FREE`` — not locational (a bare port, a request path); it passes
      free and is never counted, because validating ``443`` would suppress it as
      out-of-scope and corrupt the counter.
    * ``KIND_MALFORMED`` — it occupies a locational field but no host can be
      extracted from it. It is suppressed, never emitted: failing closed is the
      only safe answer for a value whose locality cannot be established.

    Locality is derived by parsing, not by string shape: a protocol-relative
    ``//host/path`` is a URL (not a path), an IPv6 literal is a host (not an
    opaque token), ``attacker.test/redir?to=https://in.scope/`` yields
    ``attacker.test`` (not the host embedded in its query string), and
    ``https://in.scope:pass@attacker.test/`` yields ``attacker.test`` (not the
    in-scope name sitting in the userinfo).
    """
    raw = value.strip()
    if not raw:
        return KIND_MALFORMED, raw
    if raw.startswith("//"):
        raw = "https:" + raw  # protocol-relative URL — locational, not a path
    elif raw.startswith("/"):
        return KIND_FREE, ""  # request path, not a host

    if _SCHEME.match(raw):
        try:
            hostname = urlsplit(raw).hostname or ""
        except ValueError:
            return KIND_MALFORMED, value.strip()
        key = host_key(hostname)
        return (KIND_HOST, key) if key else (KIND_MALFORMED, value.strip())

    authority = _AUTHORITY_SPLIT.split(raw, maxsplit=1)[0]
    if not authority:
        return KIND_MALFORMED, value.strip()
    if "@" in authority:
        # Schemeless userinfo (``in.scope:x@attacker.test``) — the host is what
        # follows the last ``@``, never what precedes it.
        authority = authority.rsplit("@", 1)[1]
        if not authority:
            return KIND_MALFORMED, value.strip()

    bracketed = _BRACKETED_V6.match(authority)
    if bracketed:
        key = host_key(bracketed.group("v6"))
        return (KIND_HOST, key) if key else (KIND_MALFORMED, value.strip())

    with_port = _HOST_PORT.match(authority)
    if with_port:
        authority = with_port.group("host")
    if _DIGITS.match(authority):
        return KIND_FREE, ""  # bare port number

    key = host_key(authority)
    return (KIND_HOST, key) if key else (KIND_MALFORMED, value.strip())


def extract_host(value: str) -> str:
    """The normalised host of ``value``, or ``""`` when none can be derived.

    ``""`` is the fail-closed answer: callers must treat it as "no locality
    established" and refuse, never as "matches anything".
    """
    kind, key = classify_value(value)
    return key if kind == KIND_HOST else ""


def has_path_component(value: str) -> bool:
    """True when ``value`` carries a path/query/fragment beyond a bare ``/``.

    A pattern like ``https://app.example.com/api`` names a *location inside* a
    host, not the host. Used to keep such a pattern from silently widening an
    allow-list to the whole host.
    """
    raw = value.strip()
    if not raw:
        return False
    if _SCHEME.match(raw):
        try:
            parts = urlsplit(raw)
        except ValueError:
            return False
        return bool(parts.path.strip("/") or parts.query or parts.fragment)
    remainder = _AUTHORITY_SPLIT.split(raw, maxsplit=1)
    return len(remainder) > 1 and bool(remainder[1].strip("/"))


# Characters that would end a quoted shell word, start a new command, open a
# substitution or trigger globbing. Values that become part of a command string
# (a URL, a request path) must not carry any of them: they are refused, never
# escaped, because "escape it correctly" is the assumption that keeps failing.
URL_UNSAFE_CHARS = frozenset("\"'`$;|&<>^*()[]{}\\ \t\r\n")


def is_shell_safe(value: str) -> bool:
    """True when ``value`` carries no shell metacharacter or whitespace."""
    return not any(ch in URL_UNSAFE_CHARS for ch in value)


def is_request_path(value: str) -> bool:
    """True when ``value`` is a plain absolute request path.

    Rejects ``//host`` (a protocol-relative URL), anything containing ``@`` (URL
    userinfo, which silently re-points the request at another host) and anything
    carrying a shell metacharacter.
    """
    return (
        value.startswith("/")
        and not value.startswith("//")
        and "@" not in value
        and is_shell_safe(value)
    )
