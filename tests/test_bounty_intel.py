"""Tests for bug bounty target intelligence and classification."""

from __future__ import annotations

import pytest

from kambo.bounty_intel import (
    AssetType,
    BountyProgram,
    ProgramTier,
    rank_programs,
    score_program,
)


# ---------------------------------------------------------------------------
# Payout scoring
# ---------------------------------------------------------------------------

class TestPayoutScoring:
    def test_elite_payout(self) -> None:
        p = BountyProgram(name="Big Corp", payout_critical=50000)
        score = score_program(p)
        assert score.payout_score >= 20

    def test_low_payout(self) -> None:
        p = BountyProgram(name="Small Co", payout_critical=500)
        score = score_program(p)
        assert score.payout_score <= 10

    def test_vdp_only_low_payout(self) -> None:
        p = BountyProgram(name="VDP Corp", vdp_only=True)
        score = score_program(p)
        assert score.payout_score <= 3
        assert score.tier == ProgramTier.D

    def test_bonus_active_boost(self) -> None:
        base = BountyProgram(name="Test", payout_critical=5000)
        bonus = BountyProgram(name="Test", payout_critical=5000, bonus_active=True)
        assert score_program(bonus).payout_score > score_program(base).payout_score

    def test_managed_program_boost(self) -> None:
        base = BountyProgram(name="Test", payout_critical=10000)
        managed = BountyProgram(name="Test", payout_critical=10000, managed=True)
        assert score_program(managed).payout_score >= score_program(base).payout_score

    def test_non_cash_bounty(self) -> None:
        p = BountyProgram(name="Swag Co", bounty_type="swag")
        score = score_program(p)
        assert score.payout_score <= 5


# ---------------------------------------------------------------------------
# Attack surface scoring
# ---------------------------------------------------------------------------

class TestSurfaceScoring:
    def test_multiple_wildcards(self) -> None:
        p = BountyProgram(name="Wide Corp", wildcards=["*.a.com", "*.b.com", "*.c.com"])
        score = score_program(p)
        assert score.surface_score >= 10

    def test_api_in_scope(self) -> None:
        p = BountyProgram(name="API Co", asset_types=[AssetType.API])
        score = score_program(p)
        assert any("API" in s for s in score.signals)

    def test_swagger_found(self) -> None:
        p = BountyProgram(name="Swagger Co", has_swagger=True)
        score = score_program(p)
        assert any("Swagger" in s for s in score.signals)

    def test_large_subdomain_count(self) -> None:
        p = BountyProgram(name="Huge Corp", subdomains_count=200)
        score = score_program(p)
        assert any("subdomain" in s.lower() for s in score.signals)

    def test_no_scope_low_surface(self) -> None:
        p = BountyProgram(name="Tiny")
        score = score_program(p)
        assert score.surface_score < 10


# ---------------------------------------------------------------------------
# Opportunity scoring
# ---------------------------------------------------------------------------

class TestOpportunityScoring:
    def test_new_program_boost(self) -> None:
        from datetime import datetime, timedelta, timezone
        recent = (datetime.now(timezone.utc) - timedelta(days=15)).isoformat()
        p = BountyProgram(name="New Co", launched_date=recent)
        score = score_program(p)
        assert any("New program" in s for s in score.signals)
        assert score.opportunity_score > 15

    def test_old_program_penalty(self) -> None:
        p = BountyProgram(name="Old Co", launched_date="2020-01-01T00:00:00+00:00")
        score = score_program(p)
        assert any("Mature" in s for s in score.signals)

    def test_fast_response_boost(self) -> None:
        p = BountyProgram(name="Fast Co", response_time_days=3)
        score = score_program(p)
        assert any("Fast response" in s for s in score.signals)

    def test_slow_response_penalty(self) -> None:
        p = BountyProgram(name="Slow Co", response_time_days=90)
        score = score_program(p)
        assert any("Slow response" in s for s in score.signals)

    def test_many_exclusions_penalty(self) -> None:
        p = BountyProgram(name="Restricted", exclusions=[f"ex{i}" for i in range(15)])
        score = score_program(p)
        assert any("exclusion" in s.lower() for s in score.signals)


# ---------------------------------------------------------------------------
# Effort scoring
# ---------------------------------------------------------------------------

class TestEffortScoring:
    def test_waf_increases_effort(self) -> None:
        no_waf = BountyProgram(name="No WAF")
        with_waf = BountyProgram(name="With WAF", waf_detected=True, waf_name="Cloudflare")
        assert score_program(with_waf).effort_score < score_program(no_waf).effort_score

    def test_easy_stack_reduces_effort(self) -> None:
        p = BountyProgram(name="PHP Co", tech_stack=["PHP", "WordPress", "MySQL"])
        score = score_program(p)
        assert any("common vulnerability" in s.lower() for s in score.signals)

    def test_complex_stack_increases_effort(self) -> None:
        p = BountyProgram(name="Java Co", tech_stack=["Java", "Spring Boot"])
        score = score_program(p)
        assert any("Complex" in s for s in score.signals)


# ---------------------------------------------------------------------------
# Tier classification
# ---------------------------------------------------------------------------

class TestTierClassification:
    def test_s_tier(self) -> None:
        p = BountyProgram(
            name="Elite",
            payout_critical=50000,
            wildcards=["*.elite.com", "*.elite.io", "*.elite.dev"],
            asset_types=[AssetType.WEB, AssetType.API, AssetType.MOBILE],
            launched_date="2026-05-01T00:00:00+00:00",
            response_time_days=5,
            managed=True,
        )
        score = score_program(p)
        assert score.tier in (ProgramTier.S, ProgramTier.A)
        assert score.roi_score >= 60

    def test_d_tier_vdp(self) -> None:
        p = BountyProgram(name="VDP Only", vdp_only=True)
        score = score_program(p)
        assert score.tier == ProgramTier.D


# ---------------------------------------------------------------------------
# Recommendations
# ---------------------------------------------------------------------------

class TestRecommendations:
    def test_api_approach(self) -> None:
        p = BountyProgram(name="API Co", asset_types=[AssetType.API], payout_critical=5000)
        score = score_program(p)
        assert "API-first" in score.recommended_approach
        assert any("BOLA" in v for v in score.priority_vulns)

    def test_recon_heavy_approach(self) -> None:
        p = BountyProgram(name="Wide", wildcards=["*.a.com", "*.b.com"], payout_critical=5000)
        score = score_program(p)
        assert "Recon-heavy" in score.recommended_approach
        assert "Subdomain Takeover" in score.priority_vulns

    def test_waf_evasion_advice(self) -> None:
        p = BountyProgram(name="WAF Co", waf_detected=True, payout_critical=5000)
        score = score_program(p)
        assert "evasion" in score.recommended_approach.lower()


# ---------------------------------------------------------------------------
# Ranking
# ---------------------------------------------------------------------------

class TestRanking:
    def test_rank_by_roi(self) -> None:
        programs = [
            BountyProgram(name="Low", payout_critical=100),
            BountyProgram(name="High", payout_critical=30000, wildcards=["*.high.com"]),
            BountyProgram(name="Mid", payout_critical=5000),
        ]
        ranked = rank_programs(programs)
        assert ranked[0].program_name == "High"
        assert ranked[-1].program_name == "Low"

    def test_rank_empty(self) -> None:
        ranked = rank_programs([])
        assert ranked == []

    def test_rank_preserves_all(self) -> None:
        programs = [BountyProgram(name=f"P{i}") for i in range(5)]
        ranked = rank_programs(programs)
        assert len(ranked) == 5


# ---------------------------------------------------------------------------
# Bounty tools (MCP interface)
# ---------------------------------------------------------------------------

class TestBountyTools:
    @pytest.mark.asyncio
    async def test_bounty_classify_tool(self) -> None:
        from kambo.tools.bounty import bounty_classify
        result = await bounty_classify(
            name="TestCorp",
            platform="hackerone",
            payout_critical=10000,
            wildcards=["*.testcorp.com"],
            asset_types=["web", "api"],
        )

        assert result["program"] == "TestCorp"
        assert result["tier"] in ("S", "A", "B", "C", "D")
        assert result["roi_score"] > 0
        assert "payout" in result["breakdown"]
        assert len(result["priority_vulns"]) > 0

    @pytest.mark.asyncio
    async def test_bounty_rank_tool(self) -> None:
        from kambo.tools.bounty import bounty_rank
        result = await bounty_rank([
            {"name": "HighPay", "payout_critical": 25000, "wildcards": ["*.hp.com"]},
            {"name": "LowPay", "payout_critical": 200},
        ])

        assert result["total_programs"] == 2
        assert result["ranking"][0]["program"] == "HighPay"
        assert result["ranking"][0]["rank"] == 1
        assert "recommendation" in result
