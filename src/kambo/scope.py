"""Scope validation — ensures all operations target only authorized assets."""

from __future__ import annotations

import ipaddress
import re
from functools import wraps
from typing import Any, Callable

from kambo.models import EngagementScope, ScopeTarget


class ScopeViolationError(Exception):
    """Raised when an operation targets an out-of-scope asset."""

    def __init__(self, target: str, reason: str = ""):
        self.target = target
        self.reason = reason
        msg = f"Target '{target}' is out of scope"
        if reason:
            msg += f": {reason}"
        super().__init__(msg)


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
        # Wildcard domain: *.example.com
        if pattern.startswith("*."):
            base = pattern[2:]
            return target == base or target.endswith(f".{base}")

        # CIDR notation
        if "/" in pattern:
            try:
                network = ipaddress.ip_network(pattern, strict=False)
                ip = ipaddress.ip_address(target)
                return ip in network
            except ValueError:
                pass

        # Exact match
        if target == pattern:
            return True

        # URL contains domain
        domain_match = re.search(r"https?://([^/:]+)", target)
        if domain_match:
            return self._matches(domain_match.group(1), pattern)

        return False


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
