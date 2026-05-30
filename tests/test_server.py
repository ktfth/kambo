"""Tests for server.py — tool dispatch routing, metrics lifecycle, FP warning injection."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestDispatchToolRouting:
    """Verify _dispatch_tool routes known tool names to the correct handler."""

    @pytest.mark.asyncio
    async def test_set_scope(self) -> None:
        from kambo.server import _dispatch_tool

        result = await _dispatch_tool("set_scope", {
            "targets": ["10.0.0.1"],
            "context": "bug_bounty",
        })
        assert result["status"] == "scope_configured"
        assert result["targets"] == ["10.0.0.1"]
        assert result["context"] == "bug_bounty"

    @pytest.mark.asyncio
    async def test_container_status(self) -> None:
        from kambo.server import _dispatch_tool

        with patch("kambo.server.get_runner") as mock_runner:
            mock_runner.return_value.is_healthy = AsyncMock(return_value=True)
            result = await _dispatch_tool("container_status", {})

        assert result["status"] == "running"

    @pytest.mark.asyncio
    async def test_unknown_tool_returns_error(self) -> None:
        from kambo.server import _dispatch_tool

        result = await _dispatch_tool("nonexistent_tool_xyz", {})
        assert "error" in result
        assert "Unknown tool" in result["error"]


class TestToolDispatchConsistency:
    """Guard against dual-dispatch drift between list_tools() and _dispatch_tool().

    The two halves (schema in list_tools(), routing in _dispatch_tool()/registry)
    must stay in lockstep: every advertised tool must be dispatchable, and every
    dispatch handler must be advertised. Static check — no tool execution.
    """

    def _handled_names(self) -> set[str]:
        import inspect
        import re

        from kambo import server

        # _dispatch_tool body only (ends at the "Unknown tool" sentinel) — keeps
        # prompt handlers and resource routing out of the comparison.
        disp_src = inspect.getsource(server._dispatch_tool)
        if_names = set(re.findall(r'if name == "([^"]+)"', disp_src))
        return set(server._TOOL_REGISTRY) | if_names

    @pytest.mark.asyncio
    async def test_every_listed_tool_has_a_handler(self) -> None:
        from kambo.server import list_tools

        listed = {t.name for t in await list_tools()}
        missing = listed - self._handled_names()
        assert not missing, f"Advertised but not dispatchable: {sorted(missing)}"

    @pytest.mark.asyncio
    async def test_every_handler_is_listed(self) -> None:
        from kambo.server import list_tools

        listed = {t.name for t in await list_tools()}
        orphan = self._handled_names() - listed
        assert not orphan, f"Dispatchable but not advertised: {sorted(orphan)}"

    @pytest.mark.asyncio
    async def test_no_duplicate_tool_names(self) -> None:
        from kambo.server import list_tools

        names = [t.name for t in await list_tools()]
        dupes = sorted({n for n in names if names.count(n) > 1})
        assert not dupes, f"Duplicate tool names advertised: {dupes}"


class TestCallToolMetrics:
    """Verify call_tool injects FP warnings and flushes metrics."""

    @pytest.mark.asyncio
    async def test_historical_warning_injected(self) -> None:
        from kambo.server import call_tool

        mock_metrics = MagicMock()
        mock_metrics.get_fp_warning.return_value = "HIGH FP RATE — 75%"
        mock_metrics.aggregate_summary.return_value = {}

        with patch("kambo.server._dispatch_tool", new_callable=AsyncMock) as mock_dispatch, \
             patch("kambo.metrics.get_metrics", return_value=mock_metrics), \
             patch("kambo.metrics.flush_metrics", new_callable=AsyncMock), \
             patch("kambo.server.get_pipeline") as mock_pipeline:
            mock_dispatch.return_value = {"target": "10.0.0.1", "vulnerable": False}
            mock_pipeline.return_value.ingest = MagicMock()

            contents = await call_tool("vuln_sqli", {"target": "10.0.0.1"})

        result = json.loads(contents[0].text)
        assert result["_historical_warning"] == "HIGH FP RATE — 75%"

    @pytest.mark.asyncio
    async def test_flush_metrics_called(self) -> None:
        from kambo.server import call_tool

        mock_metrics = MagicMock()
        mock_metrics.get_fp_warning.return_value = None

        with patch("kambo.server._dispatch_tool", new_callable=AsyncMock) as mock_dispatch, \
             patch("kambo.metrics.get_metrics", return_value=mock_metrics), \
             patch("kambo.metrics.flush_metrics", new_callable=AsyncMock) as mock_flush, \
             patch("kambo.server.get_pipeline") as mock_pipeline:
            mock_dispatch.return_value = {"ok": True}
            mock_pipeline.return_value.ingest = MagicMock()

            await call_tool("set_scope", {"targets": ["10.0.0.1"], "context": "pentest"})

        mock_flush.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_call_tool_handles_error(self) -> None:
        from kambo.server import call_tool

        with patch("kambo.server._dispatch_tool", new_callable=AsyncMock) as mock_dispatch, \
             patch("kambo.metrics.flush_metrics", new_callable=AsyncMock):
            mock_dispatch.side_effect = RuntimeError("boom")

            contents = await call_tool("vuln_sqli", {"target": "10.0.0.1"})

        result = json.loads(contents[0].text)
        assert "error" in result
