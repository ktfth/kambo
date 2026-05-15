"""Tests for scope validation."""

import pytest

from kambo.models import Context, EngagementScope, ScopeTarget
from kambo.scope import ScopeManager, ScopeViolationError


@pytest.fixture
def scope_manager() -> ScopeManager:
    manager = ScopeManager()
    manager.set_scope(
        EngagementScope(
            engagement_id="TEST-001",
            context=Context.PENTEST,
            targets=[
                ScopeTarget(target="*.example.com"),
                ScopeTarget(target="192.168.1.0/24"),
                ScopeTarget(target="api.target.com", exclusions=["admin.target.com"]),
            ],
            exclusions=["production.example.com"],
        )
    )
    return manager


def test_valid_subdomain(scope_manager: ScopeManager) -> None:
    assert scope_manager.validate("sub.example.com") is True


def test_valid_root_domain(scope_manager: ScopeManager) -> None:
    assert scope_manager.validate("example.com") is True


def test_valid_ip_in_cidr(scope_manager: ScopeManager) -> None:
    assert scope_manager.validate("192.168.1.50") is True


def test_invalid_ip_outside_cidr(scope_manager: ScopeManager) -> None:
    with pytest.raises(ScopeViolationError):
        scope_manager.validate("10.0.0.1")


def test_global_exclusion(scope_manager: ScopeManager) -> None:
    with pytest.raises(ScopeViolationError):
        scope_manager.validate("production.example.com")


def test_target_exclusion(scope_manager: ScopeManager) -> None:
    # admin.target.com is excluded for api.target.com scope entry
    # but since it doesn't match any other target either, it's out of scope
    with pytest.raises(ScopeViolationError):
        scope_manager.validate("admin.target.com")


def test_no_scope_configured() -> None:
    manager = ScopeManager()
    with pytest.raises(ScopeViolationError, match="No scope configured"):
        manager.validate("anything.com")


def test_completely_out_of_scope(scope_manager: ScopeManager) -> None:
    with pytest.raises(ScopeViolationError):
        scope_manager.validate("evil.com")


def test_url_extraction(scope_manager: ScopeManager) -> None:
    assert scope_manager.validate("https://sub.example.com/path") is True
