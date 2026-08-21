"""Scope validation — ensures all operations target only authorized assets."""

from __future__ import annotations

import ipaddress
import re
from functools import wraps
from typing import Any, Callable

from kambo.models import Context, EngagementScope


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

        # Check global exclusions
        for exclusion in self._scope.exclusions:
            if self._matches(target, exclusion):
                raise ScopeViolationError(target, f"Matches global exclusion: {exclusion}")

        # Check if target matches any scope target
        for scope_target in self._scope.targets:
            if self._matches(target, scope_target.target):
                # Check per-target exclusions
                for exclusion in scope_target.exclusions:
                    if self._matches(target, exclusion):
                        raise ScopeViolationError(
                            target, f"Matches exclusion for {scope_target.target}: {exclusion}"
                        )
                return True

        raise ScopeViolationError(
            target, f"Not in scope. Authorized targets: {[t.target for t in self._scope.targets]}"
        )

    def _matches(self, target: str, pattern: str) -> bool:
        """Check if target matches a scope pattern (domain, CIDR, wildcard)."""
        # Extract the domain from a URL before any other check. The match is
        # anchored: an unanchored search would pick an in-scope host out of a
        # query string, so `attacker.test/redir?to=https://in.scope/` would
        # validate as in-scope.
        domain_match = re.match(r"https?://([^/:]+)", target)
        effective_target = domain_match.group(1) if domain_match else target

        # Wildcard domain: *.example.com
        if pattern.startswith("*."):
            base = pattern[2:]
            return effective_target == base or effective_target.endswith(f".{base}")

        # CIDR notation
        if "/" in pattern:
            try:
                network = ipaddress.ip_network(pattern, strict=False)
                ip = ipaddress.ip_address(effective_target)
                return ip in network
            except ValueError:
                pass

        # Exact match
        return effective_target == pattern or target == pattern


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
