"""Tests for scope parser — platform scope parsing and validation."""

from __future__ import annotations

from kambo.models import EngagementScope, ScopeTarget
from kambo.scope_parser import (
    check_target_in_scope,
    expand_wildcards,
    parse_scope_from_platform,
    scope_summary,
)


class TestParseScopeFromPlatform:
    def test_parse_hackerone_scope(self) -> None:
        data = {
            "in_scope": [
                {"asset": "*.example.com", "asset_type": "URL", "eligible_for_bounty": True},
                {"asset": "api.example.com", "asset_type": "URL"},
            ],
            "out_of_scope": [
                {"asset": "staging.example.com"},
            ],
        }
        scope = parse_scope_from_platform(data, "hackerone")
        assert len(scope.targets) == 2
        assert scope.targets[0].target == "*.example.com"
        assert len(scope.exclusions) == 1
        assert scope.platform == "hackerone"

    def test_parse_bugcrowd_scope(self) -> None:
        data = {
            "in_scope": [
                {"uri": "https://example.com", "name": "Main Site", "category": "website"},
            ],
            "out_of_scope": [
                {"uri": "https://staging.example.com"},
            ],
        }
        scope = parse_scope_from_platform(data, "bugcrowd")
        assert len(scope.targets) == 1
        assert scope.targets[0].target == "https://example.com"

    def test_classifies_target_types(self) -> None:
        data = {
            "in_scope": [
                {"asset": "*.example.com"},
                {"asset": "10.0.0.0/24"},
                {"asset": "https://app.example.com"},
                {"asset": "example.com"},
            ],
            "out_of_scope": [],
        }
        scope = parse_scope_from_platform(data)
        types = [t.target_type for t in scope.targets]
        assert types == ["wildcard", "cidr", "url", "domain"]


class TestExpandWildcards:
    def test_expand_wildcards(self) -> None:
        targets = [
            ScopeTarget(target="*.example.com", target_type="wildcard"),
            ScopeTarget(target="api.example.com", target_type="domain"),
            ScopeTarget(target="https://app.example.com/path", target_type="url"),
        ]
        domains = expand_wildcards(targets)
        assert "example.com" in domains
        assert "api.example.com" in domains
        assert "app.example.com" in domains

    def test_deduplicates(self) -> None:
        targets = [
            ScopeTarget(target="*.example.com", target_type="wildcard"),
            ScopeTarget(target="example.com", target_type="domain"),
        ]
        domains = expand_wildcards(targets)
        assert domains.count("example.com") == 1

    def test_empty_targets(self) -> None:
        assert expand_wildcards([]) == []


class TestCheckTargetInScope:
    def test_in_scope_domain(self) -> None:
        scope = EngagementScope(
            targets=[ScopeTarget(target="example.com", target_type="domain")],
        )
        result = check_target_in_scope("example.com", scope)
        assert result["in_scope"] is True

    def test_in_scope_wildcard(self) -> None:
        scope = EngagementScope(
            targets=[ScopeTarget(target="*.example.com", target_type="wildcard")],
        )
        result = check_target_in_scope("api.example.com", scope)
        assert result["in_scope"] is True
        assert any("wildcard" in w for w in result["warnings"])

    def test_out_of_scope(self) -> None:
        scope = EngagementScope(
            targets=[ScopeTarget(target="example.com", target_type="domain")],
        )
        result = check_target_in_scope("other.com", scope)
        assert result["in_scope"] is False

    def test_excluded(self) -> None:
        scope = EngagementScope(
            targets=[ScopeTarget(target="*.example.com", target_type="wildcard")],
            exclusions=["staging.example.com"],
        )
        result = check_target_in_scope("staging.example.com", scope)
        assert result["in_scope"] is False
        assert result["is_excluded"] is True

    def test_url_target(self) -> None:
        scope = EngagementScope(
            targets=[ScopeTarget(target="*.example.com", target_type="wildcard")],
        )
        result = check_target_in_scope("https://api.example.com/v1/users", scope)
        assert result["in_scope"] is True

    def test_staging_warning(self) -> None:
        scope = EngagementScope(
            targets=[ScopeTarget(target="*.example.com", target_type="wildcard")],
        )
        result = check_target_in_scope("staging.example.com", scope)
        assert result["in_scope"] is True
        assert any("staging" in w.lower() for w in result["warnings"])

    def test_per_target_exclusion(self) -> None:
        scope = EngagementScope(
            targets=[ScopeTarget(
                target="*.example.com",
                target_type="wildcard",
                exclusions=["admin.example.com"],
            )],
        )
        result = check_target_in_scope("admin.example.com", scope)
        assert result["in_scope"] is False
        assert result["is_excluded"] is True


class TestScopeSummary:
    def test_summary_structure(self) -> None:
        scope = EngagementScope(
            platform="hackerone",
            targets=[
                ScopeTarget(target="*.example.com", target_type="wildcard"),
                ScopeTarget(target="api.example.com", target_type="domain"),
                ScopeTarget(target="10.0.0.1", target_type="ip"),
            ],
            exclusions=["staging.example.com"],
        )
        summary = scope_summary(scope)
        assert summary["total_targets"] == 3
        assert summary["has_wildcards"] is True
        assert len(summary["wildcards"]) == 1
        assert len(summary["exclusions"]) == 1
        assert "example.com" in summary["enumeration_targets"]
