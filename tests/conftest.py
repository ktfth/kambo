"""Shared test fixtures — DockerRunner mock, scope setup, database."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from kambo.models import EngagementScope, Phase, ScopeTarget, ToolResult
from kambo.scope import ScopeManager, get_scope_manager, _scope_manager


# ---------------------------------------------------------------------------
# Scope fixture — sets up a permissive scope for all tool tests
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _setup_scope() -> None:
    """Configure a broad scope so tools don't raise ScopeViolationError."""
    # Access the module-level singleton directly
    import kambo.scope as scope_module
    scope_module._scope_manager.set_scope(EngagementScope(
        engagement_id="TEST-001",
        targets=[
            ScopeTarget(target="*.example.com"),
            ScopeTarget(target="*.target.com"),
            ScopeTarget(target="192.168.1.0/24"),
            ScopeTarget(target="10.0.0.0/8"),
        ],
    ))
    yield
    scope_module._scope_manager.clear_scope()


# ---------------------------------------------------------------------------
# MockRunner — replaces DockerRunner for unit tests
# ---------------------------------------------------------------------------

class MockRunner:
    """Fake DockerRunner that returns pre-configured responses.

    Usage in tests:
        runner = MockRunner({"tool_name": "output text"})
        # or with ToolResult objects for more control
        runner = MockRunner({"tool_name": ToolResult(...)})
    """

    def __init__(self, responses: dict[str, str | ToolResult] | None = None) -> None:
        self._responses = responses or {}
        self._calls: list[dict[str, Any]] = []

    async def run(
        self,
        command: str,
        tool_name: str,
        target: str,
        phase: Phase,
        timeout: int | None = None,
    ) -> ToolResult:
        self._calls.append({
            "command": command,
            "tool_name": tool_name,
            "target": target,
            "phase": phase.value,
        })

        response = self._responses.get(tool_name, "")

        if isinstance(response, ToolResult):
            return response

        return ToolResult(
            tool_name=tool_name,
            command=command,
            target=target,
            phase=phase,
            raw_output=str(response),
            exit_code=0,
            duration_seconds=0.5,
        )

    @property
    def call_count(self) -> int:
        return len(self._calls)

    def calls_for(self, tool_name: str) -> list[dict]:
        return [c for c in self._calls if c["tool_name"] == tool_name]

    async def ensure_container(self) -> None:
        pass

    async def is_healthy(self) -> bool:
        return True


@pytest.fixture
def mock_runner() -> MockRunner:
    """Provides a MockRunner instance. Configure responses before use."""
    return MockRunner()


def patch_runner(responses: dict[str, str | ToolResult]):
    """Context manager to replace the DockerRunner singleton with a MockRunner.

    Usage:
        with patch_runner({"vuln_sqli": "injectable..."}):
            result = await vuln_sqli("http://example.com/page?id=1")
    """
    runner = MockRunner(responses)

    class _PatchContext:
        def __enter__(self):
            import kambo.docker_runner as dr
            self._original = dr._runner
            dr._runner = runner
            return runner

        def __exit__(self, *args):
            import kambo.docker_runner as dr
            dr._runner = self._original

    return _PatchContext()


# ---------------------------------------------------------------------------
# Database fixture — in-memory SQLite for testing
# ---------------------------------------------------------------------------

@pytest.fixture
async def test_db(tmp_path):
    """Provides a temporary database for testing."""
    from kambo.database import Database
    db = Database(tmp_path / "test.db")
    await db.connect()
    yield db
    await db.close()
