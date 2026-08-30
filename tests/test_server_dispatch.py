"""Full routing coverage for server.py — dispatch, resources, prompts, main().

server.py is a routing layer, and routing bugs are silent: an `if` branch that
sends a tool name to a neighbouring implementation raises nothing, it just runs
the wrong scan. These tests walk every advertised tool name through
`_dispatch_tool` with *every* tool implementation stubbed by a self-identifying
double, so a mis-wired branch comes back naming the wrong function instead of
launching real traffic.

The remaining handlers (resources, prompts, the stdio entry point) are covered
here too — they had no tests at all, which is how the SDK break stayed
invisible outside the tool half of the module.
"""

from __future__ import annotations

import asyncio
import inspect
import json
from contextlib import ExitStack
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from kambo import server
from kambo.models import Phase
from kambo.tools import (
    ad,
    api_security,
    bounty,
    cloud,
    containers,
    context,
    exploit,
    notes,
    platforms,
    post_exploit,
    recon,
    reporting,
    scanning,
    vulns,
)

_TOOL_MODULES = (
    recon, scanning, vulns, exploit, post_exploit, reporting, api_security,
    cloud, containers, ad, bounty, platforms, notes, context,
)

# Tools whose handler is written inline in _dispatch_tool instead of delegating
# to a same-named coroutine in a tool module. Each one is covered explicitly by
# TestInlineHandlers below; the matrix skips them because there is no
# implementation function to stub.
_INLINE_HANDLED = frozenset({
    "set_scope",
    "container_status",
    "pipeline_ingest",
    "pipeline_status",
    "pipeline_next",
    "pipeline_targets",
    "pipeline_reset",
    "recon_snapshot",
    "recon_diff",
})

_ADVERTISED = {t.name: t for t in asyncio.run(server.list_tools())}
_ROUTED = sorted(name for name in _ADVERTISED if name not in _INLINE_HANDLED)

_SYNTH_BY_TYPE = {
    "string": "example.com",
    "integer": 1,
    "number": 1.0,
    "boolean": True,
    "array": [],
    "object": {},
}


def _impl_module(name: str):
    """The single tool module exposing a coroutine named `name`, if unique."""
    hits = [m for m in _TOOL_MODULES if inspect.iscoroutinefunction(getattr(m, name, None))]
    return hits[0] if len(hits) == 1 else None


def _synth_args(tool) -> dict:
    """Smallest argument set satisfying a tool's declared `required` fields."""
    schema = tool.inputSchema or {}
    props = schema.get("properties", {})
    args: dict = {}
    for field in schema.get("required", []):
        spec = props.get(field, {})
        if spec.get("enum"):
            args[field] = spec["enum"][0]
        else:
            args[field] = _SYNTH_BY_TYPE.get(spec.get("type", "string"), "example.com")
    return args


@pytest.fixture
def stubbed_impls():
    """Replace every tool-module coroutine with a self-identifying stub.

    All implementations are stubbed, not just the expected one: a branch that
    routes to the wrong function then returns that function's name rather than
    executing a real scan against the network.
    """
    with ExitStack() as stack:
        for mod in _TOOL_MODULES:
            for fname, fn in list(vars(mod).items()):
                if fname.startswith("_") or not inspect.iscoroutinefunction(fn):
                    continue
                if getattr(fn, "__module__", None) != mod.__name__:
                    continue  # re-export, not this module's own implementation
                stack.enter_context(patch.object(
                    mod, fname,
                    AsyncMock(return_value={"_impl": f"{mod.__name__}.{fname}"}),
                ))
        yield


class TestDispatchMatrix:
    """Every advertised tool reaches its own implementation."""

    @pytest.mark.parametrize("name", _ROUTED)
    @pytest.mark.asyncio
    async def test_routes_to_its_own_implementation(self, name: str, stubbed_impls) -> None:
        mod = _impl_module(name)
        assert mod is not None, (
            f"{name} is advertised but no tool module exposes a coroutine of "
            f"that name. If its handler is inline in _dispatch_tool, add it to "
            f"_INLINE_HANDLED and give it an explicit test."
        )

        result = await server._dispatch_tool(name, _synth_args(_ADVERTISED[name]))

        assert result["_impl"] == f"{mod.__name__}.{name}", (
            f"{name} dispatched to {result['_impl']} instead of "
            f"{mod.__name__}.{name}"
        )

    def test_inline_handled_list_has_no_stale_entries(self) -> None:
        """_INLINE_HANDLED must not shadow a tool that gained a real module."""
        stale = sorted(n for n in _INLINE_HANDLED if _impl_module(n) is not None)
        assert not stale, (
            f"These are listed as inline-handled but now have a same-named "
            f"implementation — drop them from _INLINE_HANDLED so the matrix "
            f"covers them: {stale}"
        )

    def test_inline_handled_entries_are_all_advertised(self) -> None:
        ghosts = sorted(n for n in _INLINE_HANDLED if n not in _ADVERTISED)
        assert not ghosts, f"_INLINE_HANDLED names tools that no longer exist: {ghosts}"

    def test_matrix_covers_every_advertised_tool(self) -> None:
        assert set(_ROUTED) | _INLINE_HANDLED == set(_ADVERTISED)

    @pytest.mark.asyncio
    async def test_registry_tools_route_through_the_registry(self, stubbed_impls) -> None:
        """Registry entries dispatch without an if-branch of their own."""
        assert server._TOOL_REGISTRY, "registry unexpectedly empty"
        for name in server._TOOL_REGISTRY:
            result = await server._dispatch_tool(name, _synth_args(_ADVERTISED[name]))
            assert "_impl" in result, f"{name} did not reach a stubbed implementation"

    @pytest.mark.asyncio
    async def test_unknown_tool_is_reported_by_name(self) -> None:
        result = await server._dispatch_tool("recon_subdomain", {})
        assert result == {"error": "Unknown tool: recon_subdomain"}


class TestDispatchArgumentMapping:
    """Spot-check the branches that reshape arguments before delegating."""

    @pytest.mark.asyncio
    async def test_vuln_idor_passes_id_range_as_a_tuple(self, stubbed_impls) -> None:
        await server._dispatch_tool("vuln_idor", {
            "target": "https://example.com/api",
            "token": "t",
            "id_range": [5, 9],
        })
        vulns.vuln_idor.assert_awaited_once_with("https://example.com/api", "t", (5, 9))

    @pytest.mark.asyncio
    async def test_vuln_idor_defaults_the_id_range(self, stubbed_impls) -> None:
        await server._dispatch_tool("vuln_idor", {"target": "https://example.com", "token": "t"})
        vulns.vuln_idor.assert_awaited_once_with("https://example.com", "t", (1, 20))

    @pytest.mark.asyncio
    async def test_scan_ports_full_applies_its_defaults(self, stubbed_impls) -> None:
        await server._dispatch_tool("scan_ports_full", {"target": "example.com"})
        scanning.scan_ports_full.assert_awaited_once_with("example.com", "-", 4, False)

    @pytest.mark.asyncio
    async def test_report_export_applies_its_defaults(self, stubbed_impls) -> None:
        await server._dispatch_tool("report_export", {})
        reporting.report_export.assert_awaited_once_with("markdown", "pentest", "tentative")

    @pytest.mark.asyncio
    async def test_platform_submit_report_forwards_the_whole_payload(self, stubbed_impls) -> None:
        args = {"platform": "hackerone", "handle": "acme", "title": "t", "body": "b"}
        await server._dispatch_tool("platform_submit_report", args)
        platforms.platform_submit_report.assert_awaited_once_with("hackerone", "acme", args)


class TestInlineHandlers:
    """The nine handlers written inline in _dispatch_tool."""

    @pytest.mark.asyncio
    async def test_set_scope_records_the_full_engagement(self) -> None:
        result = await server._dispatch_tool("set_scope", {
            "engagement_id": "ENG-9",
            "context": "bug_bounty",
            "platform": "hackerone",
            "targets": ["10.0.0.1", "10.0.0.2"],
            "exclusions": ["10.0.0.99"],
        })

        assert result["status"] == "scope_configured"
        assert result["targets"] == ["10.0.0.1", "10.0.0.2"]

        from kambo.scope import get_scope_manager

        scope = get_scope_manager().scope
        assert scope.engagement_id == "ENG-9"
        assert scope.platform == "hackerone"
        assert scope.exclusions == ["10.0.0.99"]

    @pytest.mark.asyncio
    async def test_container_status_reports_stopped_when_unhealthy(self) -> None:
        with patch("kambo.server.get_runner") as mock_runner:
            mock_runner.return_value.is_healthy = AsyncMock(return_value=False)
            result = await server._dispatch_tool("container_status", {})

        assert result["status"] == "stopped"
        assert result["container"]

    @pytest.mark.asyncio
    async def test_pipeline_ingest_counts_new_assets(self) -> None:
        from kambo.pipeline import reset_pipeline

        reset_pipeline()
        result = await server._dispatch_tool("pipeline_ingest", {
            "tool_name": "recon_subdomains",
            "result": {"subdomains": ["a.example.com", "b.example.com"]},
        })

        assert result["ingested"] == 2
        assert result["total_assets"] == 2
        assert {a["value"] for a in result["new_assets"]} == {"a.example.com", "b.example.com"}

    @pytest.mark.asyncio
    async def test_pipeline_ingest_caps_the_new_asset_preview(self) -> None:
        from kambo.pipeline import reset_pipeline

        reset_pipeline()
        subs = [f"h{i}.example.com" for i in range(30)]
        result = await server._dispatch_tool("pipeline_ingest", {
            "tool_name": "recon_subdomains",
            "result": {"subdomains": subs},
        })

        assert result["ingested"] == 30
        assert len(result["new_assets"]) == 20

    @pytest.mark.asyncio
    async def test_pipeline_status_returns_the_summary(self) -> None:
        from kambo.pipeline import get_pipeline, reset_pipeline

        reset_pipeline()
        get_pipeline().ingest("recon_subdomains", {"subdomains": ["a.example.com"]})

        result = await server._dispatch_tool("pipeline_status", {})

        assert result == get_pipeline().summary()

    @pytest.mark.asyncio
    async def test_pipeline_next_suggests_steps_for_the_phase(self) -> None:
        from kambo.pipeline import get_pipeline, reset_pipeline

        reset_pipeline()
        get_pipeline().ingest("recon_subdomains", {"subdomains": ["a.example.com"]})

        result = await server._dispatch_tool("pipeline_next", {"phase": "recon", "max_steps": 2})

        assert result["phase"] == "recon"
        assert len(result["suggestions"]) <= 2
        for step in result["suggestions"]:
            assert {"tool", "reason", "targets", "phase"} == set(step)

    @pytest.mark.asyncio
    async def test_pipeline_targets_lists_assets_for_the_phase(self) -> None:
        from kambo.pipeline import get_pipeline, reset_pipeline

        reset_pipeline()
        pipeline = get_pipeline()
        pipeline.ingest("recon_subdomains", {"subdomains": ["a.example.com"]})

        result = await server._dispatch_tool("pipeline_targets", {"phase": "scanning"})

        assert result["phase"] == "scanning"
        assert result["count"] == len(result["targets"])
        assert result["targets"] == pipeline.targets_for_phase(Phase("scanning"))

    @pytest.mark.asyncio
    async def test_pipeline_reset_clears_accumulated_assets(self) -> None:
        from kambo.pipeline import get_pipeline, reset_pipeline

        reset_pipeline()
        get_pipeline().ingest("recon_subdomains", {"subdomains": ["a.example.com"]})

        result = await server._dispatch_tool("pipeline_reset", {})

        assert result == {"status": "pipeline_reset"}
        assert get_pipeline().assets == []

    @pytest.mark.asyncio
    async def test_recon_snapshot_stores_the_current_pipeline_state(self) -> None:
        from kambo.pipeline import get_pipeline, reset_pipeline
        from kambo.recon_monitor import reset_monitor

        reset_pipeline()
        reset_monitor()
        get_pipeline().ingest("recon_subdomains", {"subdomains": ["a.example.com", "b.example.com"]})

        result = await server._dispatch_tool("recon_snapshot", {"target": "example.com"})

        assert result["status"] == "snapshot_stored"
        assert result["target"] == "example.com"
        assert result["subdomains"] == 2
        assert result["snapshot_count"] == 1

    @pytest.mark.asyncio
    async def test_recon_diff_compares_the_last_two_snapshots(self) -> None:
        from kambo.pipeline import get_pipeline, reset_pipeline
        from kambo.recon_monitor import reset_monitor

        reset_pipeline()
        reset_monitor()
        get_pipeline().ingest("recon_subdomains", {"subdomains": ["a.example.com"]})
        await server._dispatch_tool("recon_snapshot", {"target": "example.com"})
        get_pipeline().ingest("recon_subdomains", {"subdomains": ["b.example.com"]})
        await server._dispatch_tool("recon_snapshot", {"target": "example.com"})

        result = await server._dispatch_tool("recon_diff", {"target": "example.com"})

        assert result["new_subdomains"] == ["b.example.com"]

    @pytest.mark.asyncio
    async def test_recon_diff_from_baseline_uses_the_first_snapshot(self) -> None:
        from kambo.pipeline import get_pipeline, reset_pipeline
        from kambo.recon_monitor import reset_monitor

        reset_pipeline()
        reset_monitor()
        get_pipeline().ingest("recon_subdomains", {"subdomains": ["a.example.com"]})
        await server._dispatch_tool("recon_snapshot", {"target": "example.com"})
        get_pipeline().ingest("recon_subdomains", {"subdomains": ["b.example.com"]})
        await server._dispatch_tool("recon_snapshot", {"target": "example.com"})
        get_pipeline().ingest("recon_subdomains", {"subdomains": ["c.example.com"]})
        await server._dispatch_tool("recon_snapshot", {"target": "example.com"})

        result = await server._dispatch_tool("recon_diff", {
            "target": "example.com",
            "from_baseline": True,
        })

        assert set(result["new_subdomains"]) == {"b.example.com", "c.example.com"}

    @pytest.mark.asyncio
    async def test_recon_diff_needs_two_snapshots(self) -> None:
        from kambo.recon_monitor import reset_monitor

        reset_monitor()

        result = await server._dispatch_tool("recon_diff", {"target": "example.com"})

        assert "error" in result
        assert result["snapshot_count"] == 0


class TestCallToolEnvelope:
    """call_tool wraps dispatch with ingestion, FP warnings and metrics."""

    @pytest.mark.asyncio
    async def test_result_is_serialized_as_json_text(self) -> None:
        with patch("kambo.server._dispatch_tool", new_callable=AsyncMock) as dispatch, \
             patch("kambo.metrics.flush_metrics", new_callable=AsyncMock), \
             patch("kambo.server.get_pipeline"):
            dispatch.return_value = {"target": "example.com", "findings": []}
            contents = await server.call_tool("recon_dns", {"target": "example.com"})

        assert len(contents) == 1
        assert contents[0].type == "text"
        assert json.loads(contents[0].text) == {"target": "example.com", "findings": []}

    @pytest.mark.asyncio
    async def test_results_are_ingested_into_the_pipeline(self) -> None:
        with patch("kambo.server._dispatch_tool", new_callable=AsyncMock) as dispatch, \
             patch("kambo.metrics.flush_metrics", new_callable=AsyncMock), \
             patch("kambo.server.get_pipeline") as get_pipeline:
            dispatch.return_value = {"subdomains": ["a.example.com"]}
            get_pipeline.return_value.ingest = MagicMock()

            await server.call_tool("recon_subdomains", {"target": "example.com"})

        get_pipeline.return_value.ingest.assert_called_once_with(
            "recon_subdomains", {"subdomains": ["a.example.com"]}
        )

    @pytest.mark.asyncio
    async def test_pipeline_tools_are_not_re_ingested(self) -> None:
        assert server._PIPELINE_SKIP_TOOLS, "skip list unexpectedly empty"
        skipped = sorted(server._PIPELINE_SKIP_TOOLS)[0]

        with patch("kambo.server._dispatch_tool", new_callable=AsyncMock) as dispatch, \
             patch("kambo.metrics.flush_metrics", new_callable=AsyncMock), \
             patch("kambo.server.get_pipeline") as get_pipeline:
            dispatch.return_value = {"ok": True}
            get_pipeline.return_value.ingest = MagicMock()

            await server.call_tool(skipped, {})

        get_pipeline.return_value.ingest.assert_not_called()

    @pytest.mark.asyncio
    async def test_ingestion_failure_never_blocks_the_tool_result(self) -> None:
        with patch("kambo.server._dispatch_tool", new_callable=AsyncMock) as dispatch, \
             patch("kambo.metrics.flush_metrics", new_callable=AsyncMock), \
             patch("kambo.server.get_pipeline") as get_pipeline:
            dispatch.return_value = {"ok": True}
            get_pipeline.return_value.ingest = MagicMock(side_effect=RuntimeError("pipeline down"))

            contents = await server.call_tool("recon_dns", {"target": "example.com"})

        assert json.loads(contents[0].text) == {"ok": True}

    @pytest.mark.asyncio
    async def test_no_warning_key_when_the_tool_has_no_fp_history(self) -> None:
        metrics = MagicMock()
        metrics.get_fp_warning.return_value = None

        with patch("kambo.server._dispatch_tool", new_callable=AsyncMock) as dispatch, \
             patch("kambo.metrics.get_metrics", return_value=metrics), \
             patch("kambo.metrics.flush_metrics", new_callable=AsyncMock), \
             patch("kambo.server.get_pipeline"):
            dispatch.return_value = {"ok": True}
            contents = await server.call_tool("vuln_xss", {"target": "example.com"})

        assert "_historical_warning" not in json.loads(contents[0].text)

    @pytest.mark.asyncio
    async def test_meta_tools_never_carry_an_fp_warning(self) -> None:
        assert server._WARNING_SKIP_TOOLS, "skip list unexpectedly empty"
        metrics = MagicMock()
        metrics.get_fp_warning.return_value = "HIGH FP RATE — 90%"

        for name in server._WARNING_SKIP_TOOLS:
            with patch("kambo.server._dispatch_tool", new_callable=AsyncMock) as dispatch, \
                 patch("kambo.metrics.get_metrics", return_value=metrics), \
                 patch("kambo.metrics.flush_metrics", new_callable=AsyncMock), \
                 patch("kambo.server.get_pipeline"):
                dispatch.return_value = {"ok": True}
                contents = await server.call_tool(name, {})

            assert "_historical_warning" not in json.loads(contents[0].text), name

    @pytest.mark.asyncio
    async def test_non_serializable_values_do_not_break_the_envelope(self) -> None:
        from datetime import datetime, timezone

        with patch("kambo.server._dispatch_tool", new_callable=AsyncMock) as dispatch, \
             patch("kambo.metrics.flush_metrics", new_callable=AsyncMock), \
             patch("kambo.server.get_pipeline"):
            dispatch.return_value = {"seen_at": datetime(2026, 1, 1, tzinfo=timezone.utc)}
            contents = await server.call_tool("recon_dns", {"target": "example.com"})

        assert "2026-01-01" in json.loads(contents[0].text)["seen_at"]

    @pytest.mark.asyncio
    async def test_dispatch_errors_come_back_as_an_error_payload(self) -> None:
        with patch("kambo.server._dispatch_tool", new_callable=AsyncMock) as dispatch, \
             patch("kambo.metrics.flush_metrics", new_callable=AsyncMock):
            dispatch.side_effect = KeyError("target")
            contents = await server.call_tool("recon_dns", {})

        assert json.loads(contents[0].text)["error"] == "'target'"


class TestResources:
    """The three MCP resources and their unknown-URI fallback."""

    @pytest.mark.asyncio
    async def test_list_resources_advertises_all_three(self) -> None:
        uris = {str(r.uri) for r in await server.list_resources()}
        assert uris == {"scope://targets", "findings://current", "session://log"}

    @pytest.mark.asyncio
    async def test_every_advertised_resource_is_readable(self) -> None:
        for resource in await server.list_resources():
            payload = json.loads(await server.read_resource(str(resource.uri)))
            assert "error" not in payload, f"{resource.uri} is advertised but unreadable"

    @pytest.mark.asyncio
    async def test_scope_resource_reflects_the_active_scope(self) -> None:
        payload = json.loads(await server.read_resource("scope://targets"))
        assert payload["engagement_id"] == "TEST-001"

    @pytest.mark.asyncio
    async def test_findings_resource_is_json(self) -> None:
        payload = json.loads(await server.read_resource("findings://current"))
        assert isinstance(payload, dict)

    @pytest.mark.asyncio
    async def test_session_resource_is_json(self) -> None:
        payload = json.loads(await server.read_resource("session://log"))
        assert isinstance(payload, dict)

    @pytest.mark.asyncio
    async def test_unknown_resource_is_reported_by_uri(self) -> None:
        payload = json.loads(await server.read_resource("scope://nope"))
        assert payload == {"error": "Unknown resource: scope://nope"}


class TestPrompts:
    """The three workflow prompts and their unknown-name fallback."""

    @pytest.mark.asyncio
    async def test_list_prompts_advertises_all_three(self) -> None:
        names = {p.name for p in await server.list_prompts()}
        assert names == {"full_pentest", "bug_bounty_web", "api_assessment"}

    @pytest.mark.asyncio
    async def test_required_arguments_are_declared(self) -> None:
        required = {
            p.name: {a.name for a in p.arguments if a.required}
            for p in await server.list_prompts()
        }
        assert required == {
            "full_pentest": {"target"},
            "bug_bounty_web": {"target"},
            "api_assessment": {"target"},
        }

    @pytest.mark.asyncio
    async def test_every_advertised_prompt_renders_its_target(self) -> None:
        for prompt in await server.list_prompts():
            result = await server.get_prompt(prompt.name, {"target": "example.com"})
            text = result.messages[0].content.text
            assert result.description == f"Workflow: {prompt.name}"
            assert "example.com" in text
            assert "Unknown prompt" not in text

    @pytest.mark.asyncio
    async def test_full_pentest_carries_the_engagement_id(self) -> None:
        result = await server.get_prompt("full_pentest", {
            "target": "example.com",
            "engagement_id": "ENG-42",
        })
        assert "ENG-42" in result.messages[0].content.text

    @pytest.mark.asyncio
    async def test_bug_bounty_carries_the_platform(self) -> None:
        result = await server.get_prompt("bug_bounty_web", {
            "target": "example.com",
            "platform": "intigriti",
        })
        assert "intigriti" in result.messages[0].content.text

    @pytest.mark.asyncio
    async def test_prompt_without_arguments_still_renders(self) -> None:
        result = await server.get_prompt("api_assessment", None)
        assert result.messages[0].role == "user"
        assert result.messages[0].content.text

    @pytest.mark.asyncio
    async def test_unknown_prompt_is_reported_by_name(self) -> None:
        result = await server.get_prompt("nope", {})
        assert result.messages[0].content.text == "Unknown prompt: nope"


class TestMain:
    """The stdio entry point wires the session lifecycle in order."""

    def test_main_runs_the_server_and_persists_state(self) -> None:
        from contextlib import asynccontextmanager

        db = AsyncMock()
        streams = (MagicMock(), MagicMock())

        @asynccontextmanager
        async def fake_stdio():
            yield streams

        with patch("kambo.env_loader.load_dotenv") as load_dotenv, \
             patch("kambo.server.get_database", new_callable=AsyncMock, return_value=db), \
             patch("kambo.metrics.load_metrics", new_callable=AsyncMock) as load_metrics, \
             patch("kambo.metrics.flush_metrics", new_callable=AsyncMock) as flush_metrics, \
             patch("kambo.server.stdio_server", fake_stdio), \
             patch.object(server.server, "run", new_callable=AsyncMock) as run:
            server.main()

        load_dotenv.assert_called_once()
        load_metrics.assert_awaited_once()
        run.assert_awaited_once()
        assert run.await_args.args[:2] == streams
        flush_metrics.assert_awaited_once()
        db.close.assert_awaited_once()
