"""Tests for bounty tool wrappers (classify, rank)."""

from __future__ import annotations

import pytest


class TestBountyClassify:
    @pytest.mark.asyncio
    async def test_high_value_program(self) -> None:
        from kambo.tools.bounty import bounty_classify
        result = await bounty_classify(
            name="TestCorp",
            platform="hackerone",
            domains=["testcorp.com", "api.testcorp.com"],
            wildcards=["*.testcorp.com"],
            asset_types=["web", "api"],
            payout_critical=50000,
            payout_high=10000,
            payout_medium=2000,
            payout_low=500,
            bounty_type="cash",
            managed=True,
            subdomains_count=150,
            has_swagger=True,
        )
        assert result["program"] == "TestCorp"
        assert result["tier"] in ("S", "A", "B", "C", "D")
        assert result["roi_score"] > 0
        assert "breakdown" in result
        assert "recommended_approach" in result
        assert "priority_vulns" in result

    @pytest.mark.asyncio
    async def test_low_value_vdp(self) -> None:
        from kambo.tools.bounty import bounty_classify
        result = await bounty_classify(
            name="SmallCo",
            vdp_only=True,
            domains=["smallco.com"],
        )
        assert result["tier"] in ("C", "D")
        assert result["roi_score"] < 40

    @pytest.mark.asyncio
    async def test_minimal_input(self) -> None:
        from kambo.tools.bounty import bounty_classify
        result = await bounty_classify(name="Unknown")
        assert result["program"] == "Unknown"
        assert "tier" in result


class TestBountyRank:
    @pytest.mark.asyncio
    async def test_rank_multiple_programs(self) -> None:
        from kambo.tools.bounty import bounty_rank
        programs = [
            {"name": "BigCorp", "payout_critical": 50000, "wildcards": ["*.bigcorp.com"]},
            {"name": "SmallCo", "payout_critical": 500, "vdp_only": True},
            {"name": "MidSize", "payout_critical": 5000, "domains": ["mid.com"]},
        ]
        result = await bounty_rank(programs)
        assert result["total_programs"] == 3
        assert len(result["ranking"]) == 3
        # First ranked should have highest ROI
        assert result["ranking"][0]["roi_score"] >= result["ranking"][-1]["roi_score"]
        assert "recommendation" in result

    @pytest.mark.asyncio
    async def test_rank_empty(self) -> None:
        from kambo.tools.bounty import bounty_rank
        result = await bounty_rank([])
        assert result["total_programs"] == 0
