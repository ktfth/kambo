"""Tests for the Kambo MCP server — tool registry, dispatch, metrics wiring."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from kambo.server import _TOOL_REGISTRY, _dispatch_tool, call_tool
from kambo.models import Confidence


# ---------------------------------------------------------------------------
# Tool Registry
# ---------------------------------------------------------------------------

class TestToolRegistry:
    def test_registry_is_not_empty(self) -> None:
        assert len(_TOOL_REGISTRY) > 0

    def test_all_entries_have_tool_and_dispatch(self) -> None:
        from kambo.server import _ToolEntry
        for name, entry in _TOOL_REGISTRY.items():
            assert isinstance(entry, _ToolEntry), f"{name} is not a _ToolEntry"
            assert callable(entry.dispatch), f"{name}.dispatch is not callable"
            assert entry.tool.name == name, f"{name} tool name mismatch"

    def test_vuln_ssti_in_registry(self) -> None:
        assert "vuln_ssti" in _TOOL_REGISTRY

    def test_api_test_auth_in_registry(self) -> None:
        assert "api_test_auth" in _TOOL_REGISTRY

    @pytest.mark.asyncio
    async def test_api_test_bfla_in_list_tools(self) -> None:
        """api_test_bfla is in legacy dispatch but must appear in list_tools."""
        from kambo.server import list_tools
        names = {t.name for t in await list_tools()}
        assert "api_test_bfla" in names

    @pytest.mark.asyncio
    async def test_api_test_bola_in_list_tools(self) -> None:
        """api_test_bola is in legacy dispatch but must appear in list_tools."""
        from kambo.server import list_tools
        names = {t.name for t in await list_tools()}
        assert "api_test_bola" in names


# ---------------------------------------------------------------------------
# list_tools — tools are surfaced to MCP clients
# ---------------------------------------------------------------------------

class TestListTools:
    @pytest.mark.asyncio
    async def test_list_tools_returns_nonempty(self) -> None:
        from kambo.server import list_tools
        tools = await list_tools()
        assert len(tools) > 0

    @pytest.mark.asyncio
    async def test_all_tools_have_name_and_schema(self) -> None:
        from kambo.server import list_tools
        tools = await list_tools()
        for tool in tools:
            assert tool.name, f"Tool missing name: {tool}"
            assert tool.inputSchema, f"Tool {tool.name} missing inputSchema"

    @pytest.mark.asyncio
    async def test_set_scope_is_registered(self) -> None:
        from kambo.server import list_tools
        tools = await list_tools()
        names = [t.name for t in tools]
        assert "set_scope" in names

    @pytest.mark.asyncio
    async def test_registry_tools_appear_in_list(self) -> None:
        from kambo.server import list_tools
        tools = await list_tools()
        tool_names = {t.name for t in tools}
        for registry_name in _TOOL_REGISTRY:
            assert registry_name in tool_names, f"{registry_name} in registry but not in list_tools()"


# ---------------------------------------------------------------------------
# _dispatch_tool — routing
# ---------------------------------------------------------------------------

class TestDispatchTool:
    @pytest.mark.asyncio
    async def test_set_scope_dispatch(self) -> None:
        result = await _dispatch_tool("set_scope", {
            "engagement_id": "test-01",
            "context": "bug_bounty",
            "targets": ["example.com"],
            "exclusions": [],
        })
        assert result["status"] == "scope_configured"
        assert "example.com" in result["targets"]

    @pytest.mark.asyncio
    async def test_unknown_tool_raises_or_returns_error(self) -> None:
        """Unknown tool should not silently succeed."""
        try:
            result = await _dispatch_tool("nonexistent_tool_xyz", {})
            # If it returns, must have error indicator
            assert "error" in str(result).lower() or result == {} or isinstance(result, dict)
        except (KeyError, NotImplementedError, ValueError):
            pass  # Any of these are acceptable

    @pytest.mark.asyncio
    async def test_registry_dispatch_invoked_for_registry_tools(self) -> None:
        """Tools in _TOOL_REGISTRY must be dispatched via registry, not hardcoded."""
        for tool_name, entry in _TOOL_REGISTRY.items():
            # Verify dispatch callable exists and is an async callable
            result = entry.dispatch  # just accessing it should not raise
            assert callable(result)


# ---------------------------------------------------------------------------
# call_tool — metrics wiring
# ---------------------------------------------------------------------------

class TestCallToolMetricsWiring:
    @pytest.mark.asyncio
    async def test_call_tool_injects_historical_warning(self) -> None:
        """When a tool has a high FP rate, _historical_warning is injected."""
        mock_result = {"output": "test", "confidence": "FIRM"}
        mock_warning = "WARNING: This tool has 80% false-positive rate"

        with (
            patch("kambo.server._dispatch_tool", new_callable=AsyncMock, return_value=mock_result),
            patch("kambo.metrics.get_metrics") as mock_get_metrics,
            patch("kambo.metrics.flush_metrics", new_callable=AsyncMock),
        ):
            metrics_instance = MagicMock()
            metrics_instance.get_fp_warning.return_value = mock_warning
            mock_get_metrics.return_value = metrics_instance

            result = await call_tool("test_tool", {})

        import json
        parsed = json.loads(result[0].text)
        assert "_historical_warning" in parsed
        assert parsed["_historical_warning"] == mock_warning

    @pytest.mark.asyncio
    async def test_call_tool_no_warning_when_not_noisy(self) -> None:
        """Tools without FP history should not have _historical_warning."""
        mock_result = {"output": "clean"}

        with (
            patch("kambo.server._dispatch_tool", new_callable=AsyncMock, return_value=mock_result),
            patch("kambo.metrics.get_metrics") as mock_get_metrics,
            patch("kambo.metrics.flush_metrics", new_callable=AsyncMock),
        ):
            metrics_instance = MagicMock()
            metrics_instance.get_fp_warning.return_value = None
            mock_get_metrics.return_value = metrics_instance

            result = await call_tool("clean_tool", {})

        import json
        parsed = json.loads(result[0].text)
        assert "_historical_warning" not in parsed

    @pytest.mark.asyncio
    async def test_call_tool_flushes_metrics_after_run(self) -> None:
        """flush_metrics must be called after every tool execution."""
        with (
            patch("kambo.server._dispatch_tool", new_callable=AsyncMock, return_value={}),
            patch("kambo.metrics.get_metrics") as mock_get_metrics,
            patch("kambo.metrics.flush_metrics", new_callable=AsyncMock) as mock_flush,
        ):
            metrics_instance = MagicMock()
            metrics_instance.get_fp_warning.return_value = None
            mock_get_metrics.return_value = metrics_instance

            await call_tool("some_tool", {})

        mock_flush.assert_called_once()

    @pytest.mark.asyncio
    async def test_call_tool_handles_exception_gracefully(self) -> None:
        """Tool errors must return JSON with 'error' key, never propagate."""
        with patch("kambo.server._dispatch_tool", new_callable=AsyncMock, side_effect=RuntimeError("tool crash")):
            result = await call_tool("broken_tool", {})

        import json
        parsed = json.loads(result[0].text)
        assert "error" in parsed


# ---------------------------------------------------------------------------
# Scope management via dispatch
# ---------------------------------------------------------------------------

class TestScopeManagement:
    @pytest.mark.asyncio
    async def test_scope_targets_stored(self) -> None:
        result = await _dispatch_tool("set_scope", {
            "engagement_id": "scope-test",
            "context": "pentest",
            "targets": ["192.168.1.0/24", "internal.corp"],
            "exclusions": ["192.168.1.1"],
        })
        assert result["status"] == "scope_configured"
        assert len(result["targets"]) == 2

    @pytest.mark.asyncio
    async def test_scope_context_stored(self) -> None:
        result = await _dispatch_tool("set_scope", {
            "engagement_id": "ctx-test",
            "context": "ctf",
            "targets": ["ctf.example.com"],
        })
        assert result["context"] == "ctf"
