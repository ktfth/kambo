"""Tests for scope bypass prevention."""

from __future__ import annotations

import pytest

from kambo.models import EngagementScope, ScopeTarget, Context
from kambo.scope import ScopeManager, ScopeViolationError


@pytest.fixture
def scope_manager():
    mgr = ScopeManager()
    mgr.set_scope(EngagementScope(
        context=Context.BUG_BOUNTY,
        targets=[
            ScopeTarget(target="example.com"),
            ScopeTarget(target="*.example.com"),
        ],
    ))
    return mgr


class TestScopeBypassPrevention:
    def test_userinfo_bypass_rejected(self, scope_manager):
        """URL with @ in userinfo should be rejected to prevent scope bypass."""
        with pytest.raises(ScopeViolationError, match="userinfo"):
            scope_manager.validate("http://example.com@evil.com/path")

    def test_userinfo_with_password_rejected(self, scope_manager):
        with pytest.raises(ScopeViolationError, match="userinfo"):
            scope_manager.validate("http://user:pass@evil.com/path")

    def test_normal_url_accepted(self, scope_manager):
        assert scope_manager.validate("http://example.com/path") is True

    def test_subdomain_accepted(self, scope_manager):
        assert scope_manager.validate("http://sub.example.com") is True

    def test_out_of_scope_rejected(self, scope_manager):
        with pytest.raises(ScopeViolationError):
            scope_manager.validate("http://evil.com")

    def test_similar_domain_rejected(self, scope_manager):
        with pytest.raises(ScopeViolationError):
            scope_manager.validate("http://notexample.com")

    def test_bare_domain_accepted(self, scope_manager):
        assert scope_manager.validate("example.com") is True

    def test_bare_subdomain_accepted(self, scope_manager):
        assert scope_manager.validate("sub.example.com") is True
