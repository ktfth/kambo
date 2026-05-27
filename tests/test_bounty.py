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


class TestReportConfirmFinding:
    """Tests for report_confirm_finding feedback recording."""

    @pytest.mark.asyncio
    async def test_feedback_with_tools_used(self) -> None:
        """Feedback records correctly when tools_used is populated."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from kambo.tools.reporting import report_confirm_finding

        mock_db = AsyncMock()
        mock_db.get_findings.return_value = [
            {"id": "FIND-001", "tools_used": ["vuln_sqli", "vuln_xss"], "severity": "high"}
        ]
        mock_metrics = MagicMock()

        with patch("kambo.tools.reporting.get_database", return_value=mock_db), \
             patch("kambo.tools.reporting.get_metrics", return_value=mock_metrics):
            result = await report_confirm_finding("FIND-001", is_true_positive=True)

        assert result["finding_id"] == "FIND-001"
        assert result["feedback"] == "true_positive"
        assert mock_metrics.record_user_feedback.call_count == 2
        mock_metrics.record_user_feedback.assert_any_call("vuln_sqli", True)
        mock_metrics.record_user_feedback.assert_any_call("vuln_xss", True)

    @pytest.mark.asyncio
    async def test_feedback_with_empty_tools_used(self) -> None:
        """Feedback must NOT be silently lost when tools_used is empty."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from kambo.tools.reporting import report_confirm_finding

        mock_db = AsyncMock()
        mock_db.get_findings.return_value = [
            {"id": "FIND-002", "tools_used": [], "severity": "high", "title": "SQLi on login"}
        ]
        mock_metrics = MagicMock()

        with patch("kambo.tools.reporting.get_database", return_value=mock_db), \
             patch("kambo.tools.reporting.get_metrics", return_value=mock_metrics):
            result = await report_confirm_finding("FIND-002", is_true_positive=False)

        assert result["finding_id"] == "FIND-002"
        # Must record feedback against a fallback tool name
        assert mock_metrics.record_user_feedback.call_count >= 1
        # Must include a warning about unattributed feedback
        assert "warning" in result

    @pytest.mark.asyncio
    async def test_feedback_with_missing_tools_used_key(self) -> None:
        """Feedback must NOT be silently lost when tools_used key is absent."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from kambo.tools.reporting import report_confirm_finding

        mock_db = AsyncMock()
        mock_db.get_findings.return_value = [
            {"id": "FIND-003", "severity": "medium"}  # no tools_used key at all
        ]
        mock_metrics = MagicMock()

        with patch("kambo.tools.reporting.get_database", return_value=mock_db), \
             patch("kambo.tools.reporting.get_metrics", return_value=mock_metrics):
            result = await report_confirm_finding("FIND-003", is_true_positive=True)

        assert mock_metrics.record_user_feedback.call_count >= 1
        assert "warning" in result

    @pytest.mark.asyncio
    async def test_feedback_not_found(self) -> None:
        """Returns error for non-existent finding."""
        from unittest.mock import AsyncMock, patch

        from kambo.tools.reporting import report_confirm_finding

        mock_db = AsyncMock()
        mock_db.get_findings.return_value = []

        with patch("kambo.tools.reporting.get_database", return_value=mock_db):
            result = await report_confirm_finding("FIND-999", is_true_positive=True)

        assert "error" in result
