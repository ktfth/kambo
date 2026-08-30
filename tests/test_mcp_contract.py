"""Contract tests for the MCP SDK surface kambo.server is wired against.

The nightly matrix went red for weeks on a break nothing here described: the
SDK published a new major that removed the low-level decorator API, and the
only signal was thirteen `AttributeError: 'Server' object has no attribute
'list_tools'` in tests that look like they are about tool dispatch.

These tests state the dependency explicitly. When the SDK moves out from under
the server again, one test fails and names exactly what went missing.
"""

from __future__ import annotations

import tomllib
from importlib.metadata import version
from pathlib import Path

import pytest

# Decorator factories kambo.server calls at import time. Losing any one of them
# makes the whole module unimportable.
_REQUIRED_DECORATORS = (
    "list_tools",
    "call_tool",
    "list_resources",
    "read_resource",
    "list_prompts",
    "get_prompt",
)

_SUPPORTED_MAJOR = 1

_PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def _declared_mcp_requirement() -> str | None:
    """The `mcp` requirement string as declared in pyproject, if readable."""
    if not _PYPROJECT.is_file():
        return None
    data = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    for dep in data.get("project", {}).get("dependencies", []):
        if dep.split("[")[0].split(">")[0].split("=")[0].strip() == "mcp":
            return dep
    return None


class TestLowLevelServerApi:
    """kambo.server builds on mcp.server.Server's decorator API."""

    @pytest.mark.parametrize("decorator", _REQUIRED_DECORATORS)
    def test_server_exposes_decorator(self, decorator: str) -> None:
        from mcp.server import Server

        probe = Server("kambo-contract-probe")
        assert hasattr(probe, decorator), (
            f"The installed MCP SDK ({version('mcp')}) has no "
            f"Server.{decorator}(). kambo.server registers its handlers with "
            f"@server.{decorator}() — porting server.py to the new SDK API is "
            f"a prerequisite for this version."
        )
        assert callable(getattr(probe, decorator))

    def test_server_run_helpers_exist(self) -> None:
        from mcp.server import Server

        probe = Server("kambo-contract-probe")
        assert callable(probe.run)
        assert callable(probe.create_initialization_options)

    def test_stdio_transport_importable(self) -> None:
        from mcp.server.stdio import stdio_server

        assert callable(stdio_server)

    def test_types_used_by_the_server_are_importable(self) -> None:
        from mcp.types import (  # noqa: F401
            GetPromptResult,
            Prompt,
            PromptArgument,
            PromptMessage,
            Resource,
            TextContent,
            Tool,
        )


class TestSdkVersionPin:
    """The supported SDK major is declared, not discovered in production."""

    def test_installed_sdk_is_on_the_supported_major(self) -> None:
        installed = version("mcp")
        major = int(installed.split(".")[0])
        assert major == _SUPPORTED_MAJOR, (
            f"mcp {installed} is installed, but kambo.server is written "
            f"against the {_SUPPORTED_MAJOR}.x low-level API. Port server.py "
            f"before raising the pin in pyproject.toml."
        )

    def test_pyproject_caps_the_sdk_major(self) -> None:
        requirement = _declared_mcp_requirement()
        if requirement is None:
            pytest.skip("pyproject.toml not available (non-editable install)")
        assert "<2" in requirement, (
            "pyproject.toml must cap mcp below 2.0 — the 2.x SDK drops the "
            "decorator API server.py registers its handlers with, and an "
            "uncapped requirement lets CI resolve it silently. "
            f"Declared: {requirement!r}"
        )


class TestServerImports:
    """The server module itself must import cleanly under the pinned SDK."""

    def test_server_module_imports(self) -> None:
        import kambo.server as srv

        assert srv.server.name == "kambo"

    def test_every_handler_kind_is_registered_with_the_sdk(self) -> None:
        """The decorators must actually take effect, not just be callable."""
        from mcp.types import (
            CallToolRequest,
            GetPromptRequest,
            ListPromptsRequest,
            ListResourcesRequest,
            ListToolsRequest,
            ReadResourceRequest,
        )

        import kambo.server as srv

        registered = set(srv.server.request_handlers)
        for request_type in (
            ListToolsRequest,
            CallToolRequest,
            ListResourcesRequest,
            ReadResourceRequest,
            ListPromptsRequest,
            GetPromptRequest,
        ):
            assert request_type in registered, (
                f"{request_type.__name__} has no handler registered — the "
                f"matching @server decorator in server.py did not take effect."
            )
