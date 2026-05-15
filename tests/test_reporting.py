"""Tests for reporting tools."""

import pytest

from kambo.tools.reporting import report_cvss


@pytest.mark.asyncio
async def test_cvss_critical() -> None:
    """RCE with no auth should be critical."""
    result = await report_cvss(
        attack_vector="N",
        attack_complexity="L",
        privileges_required="N",
        user_interaction="N",
        scope="U",
        confidentiality="H",
        integrity="H",
        availability="H",
    )
    assert result["severity"] == "critical"
    assert result["score"] >= 9.0


@pytest.mark.asyncio
async def test_cvss_low() -> None:
    """Physical access, high complexity, low impact."""
    result = await report_cvss(
        attack_vector="P",
        attack_complexity="H",
        privileges_required="H",
        user_interaction="R",
        scope="U",
        confidentiality="L",
        integrity="N",
        availability="N",
    )
    assert result["severity"] == "low"
    assert result["score"] < 4.0


@pytest.mark.asyncio
async def test_cvss_vector_string() -> None:
    result = await report_cvss(
        attack_vector="N",
        attack_complexity="L",
        privileges_required="L",
        user_interaction="N",
        scope="U",
        confidentiality="H",
        integrity="N",
        availability="N",
    )
    assert result["vector"].startswith("CVSS:3.1/")
    assert "AV:N" in result["vector"]
