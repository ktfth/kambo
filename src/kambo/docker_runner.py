"""Docker integration — runs commands inside the Kali Linux container."""

from __future__ import annotations

import asyncio
import time
from typing import Any

import docker
import structlog

from kambo.config import KamboConfig, get_config
from kambo.models import Phase, ToolResult

logger = structlog.get_logger()


class DockerRunner:
    """Executes commands in the Kali container and returns structured results."""

    def __init__(self, config: KamboConfig | None = None) -> None:
        self._config = config or get_config()
        self._client: docker.DockerClient | None = None
        self._container: Any = None

    @property
    def client(self) -> docker.DockerClient:
        if self._client is None:
            self._client = docker.from_env()
        return self._client

    async def ensure_container(self) -> None:
        """Ensure the Kali container is running."""
        try:
            self._container = self.client.containers.get(self._config.container_name)
            if self._container.status != "running":
                self._container.start()
                await asyncio.sleep(1)
        except docker.errors.NotFound:
            await self._start_container()

    async def _start_container(self) -> None:
        """Start a new Kali container."""
        logger.info("starting_kali_container", name=self._config.container_name)

        run_kwargs: dict = {
            "command": "sleep infinity",
            "name": self._config.container_name,
            "detach": True,
            "cap_add": ["NET_RAW", "NET_ADMIN"],
            "volumes": {
                str(self._config.output_dir.resolve()): {"bind": "/output", "mode": "rw"},
                str(self._config.wordlists_dir.resolve()): {"bind": "/wordlists", "mode": "ro"},
            },
            "stdin_open": True,
            "tty": True,
        }
        # network_mode: host only works on Linux, skip on Windows/macOS
        import platform
        if platform.system() == "Linux" and self._config.network_mode:
            run_kwargs["network_mode"] = self._config.network_mode

        self._container = self.client.containers.run("kambo-kali", **run_kwargs)
        await asyncio.sleep(2)

    async def run(
        self,
        command: str,
        tool_name: str,
        target: str,
        phase: Phase,
        timeout: int | None = None,
    ) -> ToolResult:
        """Execute a command in the Kali container and return structured result.

        Args:
            command: Shell command to execute
            tool_name: Name of the tool being run
            target: Target being assessed
            phase: Current methodology phase
            timeout: Override default timeout (seconds)
        """
        await self.ensure_container()

        effective_timeout = timeout or self._config.docker_timeout
        start_time = time.time()

        logger.info(
            "executing_command",
            tool=tool_name,
            target=target,
            phase=phase.value,
            command=command[:200],
        )

        try:
            # Run command asynchronously, enforcing the timeout at the async level
            # (docker SDK's exec_run has no native timeout parameter)
            result = await asyncio.wait_for(
                asyncio.to_thread(self._exec_command, command, effective_timeout),
                timeout=effective_timeout,
            )

            duration = time.time() - start_time
            exit_code = result.exit_code
            output = result.output.decode("utf-8", errors="replace") if result.output else ""

            logger.info(
                "command_completed",
                tool=tool_name,
                duration=f"{duration:.1f}s",
                exit_code=exit_code,
                output_length=len(output),
            )

            return ToolResult(
                tool_name=tool_name,
                command=command,
                target=target,
                phase=phase,
                duration_seconds=duration,
                exit_code=exit_code,
                raw_output=output,
            )

        except Exception as e:
            duration = time.time() - start_time
            logger.error("command_failed", tool=tool_name, error=str(e))

            return ToolResult(
                tool_name=tool_name,
                command=command,
                target=target,
                phase=phase,
                duration_seconds=duration,
                exit_code=-1,
                error=str(e),
            )

    def _exec_command(self, command: str, timeout: int) -> Any:
        """Synchronous command execution in container."""
        assert self._container is not None
        return self._container.exec_run(
            cmd=["bash", "-c", command],
            demux=False,
            tty=False,
        )

    async def is_healthy(self) -> bool:
        """Check if the container is running and responsive."""
        try:
            container = self.client.containers.get(self._config.container_name)
            return container.status == "running"
        except (docker.errors.NotFound, docker.errors.APIError):
            return False

    async def stop(self) -> None:
        """Stop the Kali container."""
        try:
            container = self.client.containers.get(self._config.container_name)
            container.stop(timeout=10)
            logger.info("container_stopped", name=self._config.container_name)
        except docker.errors.NotFound:
            pass


# Singleton instance
_runner: DockerRunner | None = None


def get_runner() -> DockerRunner:
    global _runner
    if _runner is None:
        _runner = DockerRunner()
    return _runner
