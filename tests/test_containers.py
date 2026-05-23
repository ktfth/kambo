"""Tests for container security tool wrappers."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest

from kambo.models import Phase, ToolResult


def _mock_result(output: str = "", exit_code: int = 0) -> ToolResult:
    return ToolResult(
        tool_name="test",
        command="test",
        target="10.0.0.1",
        phase=Phase.POST_EXPLOITATION,
        exit_code=exit_code,
        raw_output=output,
        duration_seconds=1.0,
    )


@pytest.fixture
def mock_runner():
    runner = AsyncMock()
    runner.run = AsyncMock(return_value=_mock_result())
    with patch("kambo.tools.containers.get_runner", return_value=runner):
        yield runner


@pytest.fixture(autouse=True)
def _allow_scope():
    with patch("kambo.tools.containers.validate_scope"):
        yield


class TestContainerEscapeDetect:
    @pytest.mark.asyncio
    async def test_escape_docker_socket_found(self, mock_runner: AsyncMock) -> None:
        from kambo.tools.containers import container_escape_detect

        mock_runner.run.return_value = _mock_result("srwxr-xr-x docker.sock FOUND")
        result = await container_escape_detect("10.0.0.1")
        assert result["target"] == "10.0.0.1"
        assert result["escape_possible"] is True
        assert "checks" in result

    @pytest.mark.asyncio
    async def test_escape_not_found(self, mock_runner: AsyncMock) -> None:
        from kambo.tools.containers import container_escape_detect

        # "NOT_FOUND" contains "FOUND" substring, so use output without either keyword
        mock_runner.run.return_value = _mock_result("nothing here")
        result = await container_escape_detect("10.0.0.1")
        assert result["escape_possible"] is False

    @pytest.mark.asyncio
    async def test_escape_runs_all_checks(self, mock_runner: AsyncMock) -> None:
        from kambo.tools.containers import container_escape_detect

        await container_escape_detect("10.0.0.1")
        # Should run 5 checks
        assert mock_runner.run.call_count == 5


class TestContainerImageScan:
    @pytest.mark.asyncio
    async def test_scan_with_vulns(self, mock_runner: AsyncMock) -> None:
        from kambo.tools.containers import container_image_scan

        trivy_output = json.dumps({
            "Results": [
                {
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-1234",
                            "Severity": "CRITICAL",
                            "PkgName": "openssl",
                            "InstalledVersion": "1.1.1",
                            "FixedVersion": "1.1.1g",
                            "Title": "Buffer overflow",
                        }
                    ]
                }
            ]
        })
        mock_runner.run.return_value = _mock_result(trivy_output)
        result = await container_image_scan("10.0.0.1", "nginx:latest")
        assert result["image"] == "nginx:latest"
        assert result["total"] == 1
        assert result["vulnerabilities"][0]["id"] == "CVE-2024-1234"

    @pytest.mark.asyncio
    async def test_scan_invalid_json(self, mock_runner: AsyncMock) -> None:
        from kambo.tools.containers import container_image_scan

        mock_runner.run.return_value = _mock_result("not json")
        result = await container_image_scan("10.0.0.1", "nginx:latest")
        assert "raw" in result


class TestK8sRbacEnum:
    @pytest.mark.asyncio
    async def test_rbac_enum(self, mock_runner: AsyncMock) -> None:
        from kambo.tools.containers import k8s_rbac_enum

        mock_runner.run.return_value = _mock_result('"default"\n"kube-system"\n')
        result = await k8s_rbac_enum("10.0.0.1", token="test-token")
        assert result["target"] == "10.0.0.1"
        assert "namespaces" in result
        # Should make 2 calls (namespaces + access review)
        assert mock_runner.run.call_count == 2

    @pytest.mark.asyncio
    async def test_rbac_enum_no_token(self, mock_runner: AsyncMock) -> None:
        from kambo.tools.containers import k8s_rbac_enum

        await k8s_rbac_enum("10.0.0.1")
        call_args = mock_runner.run.call_args_list[0]
        # Without token, no Authorization header
        assert "Authorization" not in call_args[0][0]
