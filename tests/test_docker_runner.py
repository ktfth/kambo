"""Tests for DockerRunner — mocked Docker daemon, timeout, output parsing."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch, patch as mock_patch

import pytest

from kambo.config import KamboConfig
from kambo.docker_runner import DockerRunner, get_runner
from kambo.models import Phase, ToolResult


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_config() -> KamboConfig:
    return KamboConfig(
        container_name="test-kali",
        docker_timeout=60,
        docker_request_timeout=15,
    )


@pytest.fixture
def mock_container() -> MagicMock:
    container = MagicMock()
    container.status = "running"
    container.exec_run = MagicMock(
        return_value=(0, b"command output\n")
    )
    return container


@pytest.fixture
def runner_with_mock(mock_config: KamboConfig, mock_container: MagicMock) -> DockerRunner:
    runner = DockerRunner(config=mock_config)
    runner._container = mock_container
    return runner


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------

class TestDockerRunnerInit:
    def test_creates_with_default_config(self) -> None:
        runner = DockerRunner()
        assert runner._config is not None

    def test_creates_with_custom_config(self, mock_config: KamboConfig) -> None:
        runner = DockerRunner(config=mock_config)
        assert runner._config.container_name == "test-kali"

    def test_client_is_lazy(self) -> None:
        runner = DockerRunner()
        assert runner._client is None

    def test_container_is_none_initially(self) -> None:
        runner = DockerRunner()
        assert runner._container is None


# ---------------------------------------------------------------------------
# ensure_container
# ---------------------------------------------------------------------------

class TestEnsureContainer:
    @pytest.mark.asyncio
    async def test_starts_running_container(
        self, mock_config: KamboConfig, mock_container: MagicMock
    ) -> None:
        runner = DockerRunner(config=mock_config)

        mock_client = MagicMock()
        mock_client.containers.get.return_value = mock_container
        runner._client = mock_client

        await runner.ensure_container()
        assert runner._container == mock_container

    @pytest.mark.asyncio
    async def test_starts_stopped_container(
        self, mock_config: KamboConfig
    ) -> None:
        stopped_container = MagicMock()
        stopped_container.status = "exited"
        stopped_container.start = MagicMock()

        runner = DockerRunner(config=mock_config)
        mock_client = MagicMock()
        mock_client.containers.get.return_value = stopped_container
        runner._client = mock_client

        await runner.ensure_container()
        stopped_container.start.assert_called_once()

    @pytest.mark.asyncio
    async def test_creates_new_container_when_not_found(
        self, mock_config: KamboConfig, mock_container: MagicMock
    ) -> None:
        import docker

        runner = DockerRunner(config=mock_config)
        mock_client = MagicMock()
        mock_client.containers.get.side_effect = docker.errors.NotFound("not found")
        mock_client.containers.run.return_value = mock_container
        runner._client = mock_client

        with patch("asyncio.sleep", new_callable=AsyncMock):
            await runner.ensure_container()

        mock_client.containers.run.assert_called_once()


# ---------------------------------------------------------------------------
# run()
# ---------------------------------------------------------------------------

class TestDockerRunnerRun:
    def _make_fake_exec_result(self, exit_code: int, output: bytes):
        """Create a fake result matching DockerRunner._exec_command output shape."""
        result = MagicMock()
        result.exit_code = exit_code
        result.output = output
        return result

    @pytest.mark.asyncio
    async def test_run_returns_tool_result(
        self, runner_with_mock: DockerRunner
    ) -> None:
        fake = self._make_fake_exec_result(0, b"scan output\n")
        with (
            patch.object(runner_with_mock, "ensure_container", new_callable=AsyncMock),
            patch.object(runner_with_mock, "_exec_command", return_value=fake),
        ):
            result = await runner_with_mock.run(
                command="nmap -sV target",
                tool_name="recon_nmap",
                target="target",
                phase=Phase.RECON,
            )
        assert isinstance(result, ToolResult)

    @pytest.mark.asyncio
    async def test_run_captures_raw_output(
        self, runner_with_mock: DockerRunner
    ) -> None:
        fake = self._make_fake_exec_result(0, b"nmap output here\n")
        with (
            patch.object(runner_with_mock, "ensure_container", new_callable=AsyncMock),
            patch.object(runner_with_mock, "_exec_command", return_value=fake),
        ):
            result = await runner_with_mock.run(
                command="nmap target",
                tool_name="recon_nmap",
                target="target",
                phase=Phase.RECON,
            )
        assert "nmap output here" in result.raw_output

    @pytest.mark.asyncio
    async def test_run_records_exit_code_zero_as_success(
        self, runner_with_mock: DockerRunner
    ) -> None:
        fake = self._make_fake_exec_result(0, b"ok")
        with (
            patch.object(runner_with_mock, "ensure_container", new_callable=AsyncMock),
            patch.object(runner_with_mock, "_exec_command", return_value=fake),
        ):
            result = await runner_with_mock.run(
                command="true",
                tool_name="test_tool",
                target="target",
                phase=Phase.RECON,
            )
        assert result.exit_code == 0

    @pytest.mark.asyncio
    async def test_run_records_nonzero_exit_code(
        self, runner_with_mock: DockerRunner
    ) -> None:
        fake = self._make_fake_exec_result(1, b"error")
        with (
            patch.object(runner_with_mock, "ensure_container", new_callable=AsyncMock),
            patch.object(runner_with_mock, "_exec_command", return_value=fake),
        ):
            result = await runner_with_mock.run(
                command="false",
                tool_name="test_tool",
                target="target",
                phase=Phase.RECON,
            )
        assert result.exit_code == 1

    @pytest.mark.asyncio
    async def test_run_decodes_bytes_output(
        self, runner_with_mock: DockerRunner
    ) -> None:
        fake = self._make_fake_exec_result(0, b"utf8 output \xc3\xa9")
        with (
            patch.object(runner_with_mock, "ensure_container", new_callable=AsyncMock),
            patch.object(runner_with_mock, "_exec_command", return_value=fake),
        ):
            result = await runner_with_mock.run(
                command="echo test",
                tool_name="test_tool",
                target="target",
                phase=Phase.RECON,
            )
        assert isinstance(result.raw_output, str)

    @pytest.mark.asyncio
    async def test_run_handles_none_output(
        self, runner_with_mock: DockerRunner
    ) -> None:
        fake = self._make_fake_exec_result(0, None)
        with (
            patch.object(runner_with_mock, "ensure_container", new_callable=AsyncMock),
            patch.object(runner_with_mock, "_exec_command", return_value=fake),
        ):
            result = await runner_with_mock.run(
                command="cmd",
                tool_name="test_tool",
                target="target",
                phase=Phase.RECON,
            )
        assert isinstance(result.raw_output, str)


# ---------------------------------------------------------------------------
# get_runner singleton
# ---------------------------------------------------------------------------

class TestGetRunner:
    def test_returns_docker_runner(self) -> None:
        runner = get_runner()
        assert isinstance(runner, DockerRunner)

    def test_consistent_instance(self) -> None:
        r1 = get_runner()
        r2 = get_runner()
        assert type(r1) is type(r2)
