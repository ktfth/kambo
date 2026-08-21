"""Scope validation — ensures all operations target only authorized assets."""

from __future__ import annotations

import hashlib
import ipaddress
from functools import wraps
from typing import Any, Callable

from kambo.host_parse import extract_host, has_path_component, host_key
from kambo.models import Context, EngagementScope


def _as_network(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    """``value`` as an IP network, or ``None`` when it is not one.

    Only a value :mod:`ipaddress` actually parses counts as CIDR — a mere ``/``
    in the string does not, so ``example.com/wp-admin`` is treated as a host
    pattern with a path rather than silently falling through a failed CIDR
    branch.
    """
    if "/" not in value:
        return None
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def _as_address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """``value`` as an IP address, or ``None`` when it is not one."""
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


def engagement_key(scope: EngagementScope | None) -> str:
    """A stable identity for the engagement a piece of data belongs to.

    ``engagement_id`` is optional and frequently left blank, so a blank id must
    not make two different programs look like the same engagement. When it is
    absent the key falls back to a digest of the platform plus the authorised
    target list, which differs between programs by construction.
    """
    if scope is None:
        return ""
    if scope.engagement_id.strip():
        return f"id:{scope.engagement_id.strip().lower()}"
    basis = "|".join(sorted(t.target.strip().lower() for t in scope.targets))
    digest = hashlib.sha256(f"{scope.platform.strip().lower()}::{basis}".encode()).hexdigest()
    return f"fp:{digest[:16]}"


def active_engagement_key() -> str:
    """The engagement key of the currently configured scope (``""`` if none)."""
    return engagement_key(_scope_manager.scope)


class ScopeViolationError(Exception):
    """Raised when an operation targets an out-of-scope asset."""

    def __init__(self, target: str, reason: str = ""):
        self.target = target
        self.reason = reason
        msg = f"Target '{target}' is out of scope"
        if reason:
            msg += f": {reason}"
        super().__init__(msg)


# Pentest-only capability families (doctrine §5). In a bug bounty engagement,
# *merely running* these is a program violation and an account-ban risk — there
# is no post-exploitation, no Active Directory attack, no lateral movement, no
# credential dumping, no privilege escalation beyond detection. The ceiling is
# checked BEFORE dispatch, never after.
PENTEST_ONLY_TOOLS: frozenset[str] = frozenset(
    {
        # Active Directory attacks
        "ad_bloodhound",
        "ad_kerberoast",
        "ad_asrep_roast",
        "ad_pass_the_hash",
        "ad_dcsync",
        "ad_certify",
        "ad_ntlm_relay",
        # Post-exploitation (foothold-dependent — no foothold exists in bounty)
        "post_privesc_linux",
        "post_privesc_windows",
        "post_ad_enum",
        "post_kerberoast",
        "post_lateral_move",
        "post_cred_dump",
    }
)


class PentestModeRequiredError(Exception):
    """Raised when a pentest-only capability is invoked in a bug bounty engagement.

    Bug bounty is NOT pentest: the flow is locked deliberately. See doctrine §5.
    """

    def __init__(self, tool_name: str, context: Context | None):
        self.tool_name = tool_name
        self.context = context
        ctx = context.value if context else "no-scope"
        super().__init__(
            f"🔒 LOCKED: '{tool_name}' is a pentest-only capability and is "
            f"disabled in this engagement (context: {ctx}).\n"
            "Bug bounty ≠ pentest. Post-exploitation, Active Directory attacks, "
            "lateral movement, credential dumping and privilege escalation are "
            "program violations in bug bounty and risk an account ban (doctrine "
            "§5). They require an explicit PENTEST engagement with authorization.\n"
            "If you genuinely have a pentest engagement, set the scope context to "
            "'pentest' before invoking this tool."
        )


def require_pentest_mode(tool_name: str) -> None:
    """Enforce the §5 ceiling: block pentest-only tools outside a PENTEST context.

    Raises ``PentestModeRequiredError`` for bug bounty engagements (and when no
    scope/context is configured, since we cannot assert authorization). CTF and
    PENTEST contexts are allowed — exploitation is in-bounds there.
    """
    if tool_name not in PENTEST_ONLY_TOOLS:
        return
    scope = _scope_manager.scope
    context = scope.context if scope else None
    if context in (Context.PENTEST, Context.CTF):
        return  # explicit, authorized exploitation context
    raise PentestModeRequiredError(tool_name, context)


class ScopeManager:
    """Manages and validates engagement scope."""

    def __init__(self) -> None:
        self._scope: EngagementScope | None = None

    @property
    def scope(self) -> EngagementScope | None:
        return self._scope

    def set_scope(self, scope: EngagementScope) -> None:
        self._scope = scope

    def clear_scope(self) -> None:
        self._scope = None

    def validate(self, target: str) -> bool:
        """Validate that a target is within the authorized scope.

        Raises ScopeViolationError if target is not in scope.
        Returns True if valid.
        """
        if self._scope is None:
            raise ScopeViolationError(target, "No scope configured. Set scope first.")

        # A target from which no well-formed host can be derived is refused
        # before any pattern is consulted. There is no "compare the raw string
        # instead" fallback: every scope bypass found in this matcher came from
        # comparing a pattern against a blob that merely *contained* a host.
        host = extract_host(target)
        if not host:
            raise ScopeViolationError(
                target, "No well-formed host could be extracted — refusing (fail closed)."
            )

        # Check global exclusions
        for exclusion in self._scope.exclusions:
            if self._matches(target, exclusion, allow=False):
                raise ScopeViolationError(target, f"Matches global exclusion: {exclusion}")

        # Check if target matches any scope target
        for scope_target in self._scope.targets:
            if self._matches(target, scope_target.target, allow=True):
                # Check per-target exclusions
                for exclusion in scope_target.exclusions:
                    if self._matches(target, exclusion, allow=False):
                        raise ScopeViolationError(
                            target, f"Matches exclusion for {scope_target.target}: {exclusion}"
                        )
                return True

        raise ScopeViolationError(
            target, f"Not in scope. Authorized targets: {[t.target for t in self._scope.targets]}"
        )

    def _matches(self, target: str, pattern: str, *, allow: bool = True) -> bool:
        """Check if ``target`` matches a scope pattern (domain, CIDR, wildcard).

        Both sides are reduced to a normalised host first (see
        :mod:`kambo.host_parse`) so that DNS case-insensitivity, trailing root
        dots, ports, URL userinfo, query strings and fragments cannot change the
        answer. Everything that is not a host — a query string carrying an
        in-scope name, a userinfo label, an embedded redirect URL — is discarded
        by the parser instead of being suffix-matched.

        ``allow`` distinguishes the two roles a pattern can play, because the
        safe failure direction is opposite for each:

        * an *allow* pattern that names a location inside a host
          (``https://app.example.com/api``) must never be widened to the whole
          host — widening authorises traffic the program did not;
        * an *exclusion* pattern in the same shape is reduced to its host and
          blocks it entirely — over-blocking costs a finding, under-blocking
          costs the program.
        """
        host = extract_host(target)
        if not host:
            # Nothing locational to compare. Allow: no match (fail closed).
            # Exclude: also no match — validate() has already refused the
            # target outright, so this can never open a hole.
            return False

        pat = pattern.strip()
        if not pat:
            return False

        # Wildcard domain: *.example.com
        if pat.startswith("*."):
            base = host_key(pat[2:])
            if not base:
                return False
            return host == base or host.endswith(f".{base}")

        # CIDR notation
        network = _as_network(pat)
        if network is not None:
            ip = _as_address(host)
            if ip is None or ip.version != network.version:
                return False
            return ip in network

        # Bare IP literal — compared as an address, so every textual spelling of
        # the same IPv6 address (compressed, expanded, upper-cased) matches.
        addr = _as_address(pat)
        if addr is not None:
            ip = _as_address(host)
            return ip is not None and ip == addr

        # Host pattern. A URL-form pattern (``https://admin.example.com``) is
        # reduced to its host so a scope list pasted from a platform — where a
        # URL asset is literally ``https://host/path`` — actually enforces.
        if allow and has_path_component(pat):
            return False
        pat_host = extract_host(pat)
        return bool(pat_host) and host == pat_host


# Global scope manager instance
_scope_manager = ScopeManager()


def get_scope_manager() -> ScopeManager:
    return _scope_manager


def validate_scope(target: str) -> bool:
    """Validate target against current scope. Raises ScopeViolationError if invalid."""
    return _scope_manager.validate(target)


def scope_required(func: Callable) -> Callable:
    """Decorator that validates the 'target' parameter against scope before execution."""

    @wraps(func)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        target = kwargs.get("target") or (args[0] if args else None)
        if target:
            validate_scope(target)
        return await func(*args, **kwargs)

    return wrapper


def pentest_only(func: Callable) -> Callable:
    """Decorator that locks a pentest-only tool unless the engagement context is
    PENTEST or CTF. The check runs before the tool body executes — the §5 ceiling
    is enforced *before* dispatch, never after. The function name is used as the
    tool identifier, so it must match an entry in ``PENTEST_ONLY_TOOLS``.

    Fails fast at import time if the decorated function's name is not registered
    in ``PENTEST_ONLY_TOOLS`` — otherwise a rename would silently disable the
    gate (``require_pentest_mode`` is a no-op for unknown names).
    """
    if func.__name__ not in PENTEST_ONLY_TOOLS:
        raise ValueError(
            f"@pentest_only applied to '{func.__name__}', which is not in "
            "PENTEST_ONLY_TOOLS — the lock would never fire. Add it to the set."
        )

    @wraps(func)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        require_pentest_mode(func.__name__)
        return await func(*args, **kwargs)

    return wrapper
