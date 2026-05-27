"""Tests for DockerRunner — mock-based, no real Docker dependency."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from kambo.config import KamboConfig
from kambo.models import Phase


class TestDockerRunnerInit:
    def test_default_config(self) -> None:
        from kambo.docker_runner import DockerRunner

        runner = DockerRunner()
        assert runner._config.container_name == "kambo-kali"

    def test_custom_config(self) -> None:
        from kambo.docker_runner import DockerRunner

        cfg = KamboConfig(container_name="test-kali", docker_timeout=60)
        runner = DockerRunner(config=cfg)
        assert runner._config.container_name == "test-kali"
        assert runner._config.docker_timeout == 60

    def test_lazy_client(self) -> None:
        from kambo.docker_runner import DockerRunner

        runner = DockerRunner()
        assert runner._client is None  # not connected until first use


class TestDockerRunnerRun:
    @pytest.mark.asyncio
    async def test_run_returns_tool_result(self) -> None:
        from kambo.docker_runner import DockerRunner

        runner = DockerRunner()

        # Mock container exec
        mock_exec_result = MagicMock()
        mock_exec_result.exit_code = 0
        mock_exec_result.output = b"scan output here"

        mock_container = MagicMock()
        mock_container.status = "running"
        mock_container.exec_run.return_value = mock_exec_result

        mock_client = MagicMock()
        mock_client.containers.get.return_value = mock_container

        runner._client = mock_client
        runner._container = mock_container

        result = await runner.run(
            command="nmap -sV 10.0.0.1",
            tool_name="scan_ports",
            target="10.0.0.1",
            phase=Phase.SCANNING,
            timeout=30,
        )

        assert result.tool_name == "scan_ports"
        assert result.target == "10.0.0.1"
        assert result.exit_code == 0
        assert "scan output" in result.raw_output

    @pytest.mark.asyncio
    async def test_run_handles_exception(self) -> None:
        from kambo.docker_runner import DockerRunner

        runner = DockerRunner()

        mock_container = MagicMock()
        mock_container.status = "running"
        mock_container.exec_run.side_effect = RuntimeError("container died")

        mock_client = MagicMock()
        mock_client.containers.get.return_value = mock_container

        runner._client = mock_client
        runner._container = mock_container

        result = await runner.run(
            command="failing-command",
            tool_name="test_tool",
            target="10.0.0.1",
            phase=Phase.RECON,
        )

        assert result.exit_code == -1
        assert "container died" in result.error


class TestDockerRunnerHealth:
    @pytest.mark.asyncio
    async def test_healthy_container(self) -> None:
        from kambo.docker_runner import DockerRunner

        runner = DockerRunner()
        mock_container = MagicMock()
        mock_container.status = "running"

        mock_client = MagicMock()
        mock_client.containers.get.return_value = mock_container
        runner._client = mock_client

        assert await runner.is_healthy() is True

    @pytest.mark.asyncio
    async def test_unhealthy_not_found(self) -> None:
        import docker
        from kambo.docker_runner import DockerRunner

        runner = DockerRunner()
        mock_client = MagicMock()
        mock_client.containers.get.side_effect = docker.errors.NotFound("gone")
        runner._client = mock_client

        assert await runner.is_healthy() is False


class TestGetRunner:
    def test_singleton(self) -> None:
        from kambo.docker_runner import get_runner

        r1 = get_runner()
        r2 = get_runner()
        assert r1 is r2
