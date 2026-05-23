"""Tests for Active Directory tool wrappers."""

from __future__ import annotations

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
    with patch("kambo.tools.ad.get_runner", return_value=runner):
        yield runner


@pytest.fixture(autouse=True)
def _allow_scope():
    with patch("kambo.tools.ad.validate_scope"):
        yield


class TestBloodhound:
    @pytest.mark.asyncio
    async def test_bloodhound_basic(self, mock_runner: AsyncMock) -> None:
        from kambo.tools.ad import ad_bloodhound

        result = await ad_bloodhound("10.0.0.1", "test.local", "admin", "pass123")
        assert result["target"] == "10.0.0.1"
        assert result["domain"] == "test.local"
        assert result["collection"] == "All"
        mock_runner.run.assert_called_once()
        call_args = mock_runner.run.call_args
        assert "bloodhound-python" in call_args[0][0]
        assert call_args[0][3] == Phase.POST_EXPLOITATION


class TestKerberoast:
    @pytest.mark.asyncio
    async def test_kerberoast_with_hashes(self, mock_runner: AsyncMock) -> None:
        from kambo.tools.ad import ad_kerberoast

        mock_runner.run.return_value = _mock_result(
            "$krb5tgs$23$*svc_mssql$TEST.LOCAL$http/web01.test.local*$abc123\n"
            "$krb5tgs$23$*svc_iis$TEST.LOCAL$http/iis01.test.local*$def456\n"
        )
        result = await ad_kerberoast("10.0.0.1", "test.local", "admin", "pass123")
        assert result["hashes_found"] == 2
        assert len(result["hashes"]) == 2
        assert "hashcat" in result["crack_command"]

    @pytest.mark.asyncio
    async def test_kerberoast_no_hashes(self, mock_runner: AsyncMock) -> None:
        from kambo.tools.ad import ad_kerberoast

        mock_runner.run.return_value = _mock_result("No entries found")
        result = await ad_kerberoast("10.0.0.1", "test.local", "admin", "pass123")
        assert result["hashes_found"] == 0


class TestAsrepRoast:
    @pytest.mark.asyncio
    async def test_asrep_with_users_list(self, mock_runner: AsyncMock) -> None:
        from kambo.tools.ad import ad_asrep_roast

        mock_runner.run.return_value = _mock_result(
            "$krb5asrep$23$jsmith@TEST.LOCAL:abc123\n"
        )
        result = await ad_asrep_roast("10.0.0.1", "test.local", users=["jsmith", "admin"])
        assert result["hashes_found"] == 1
        assert "hashcat" in result["crack_command"]


class TestPassTheHash:
    @pytest.mark.asyncio
    async def test_pth_success(self, mock_runner: AsyncMock) -> None:
        from kambo.tools.ad import ad_pass_the_hash

        mock_runner.run.return_value = _mock_result("SMB 10.0.0.1 445 (Pwn3d!) admin")
        result = await ad_pass_the_hash("10.0.0.1", "admin", "aad3b435b51404ee:abc123")
        assert result["success"] is True
        assert result["admin_access"] is True

    @pytest.mark.asyncio
    async def test_pth_failure(self, mock_runner: AsyncMock) -> None:
        from kambo.tools.ad import ad_pass_the_hash

        mock_runner.run.return_value = _mock_result("STATUS_LOGON_FAILURE")
        result = await ad_pass_the_hash("10.0.0.1", "admin", "aad3b435b51404ee:abc123")
        assert result["success"] is False


class TestDcsync:
    @pytest.mark.asyncio
    async def test_dcsync_success(self, mock_runner: AsyncMock) -> None:
        from kambo.tools.ad import ad_dcsync

        mock_runner.run.return_value = _mock_result("krbtgt:502:aad3b435b51404ee:abc123:::")
        result = await ad_dcsync("10.0.0.1", "test.local", "admin", password="pass123")
        assert result["success"] is True
        assert result["target_user"] == "krbtgt"

    @pytest.mark.asyncio
    async def test_dcsync_with_hash_auth(self, mock_runner: AsyncMock) -> None:
        from kambo.tools.ad import ad_dcsync

        result = await ad_dcsync("10.0.0.1", "test.local", "admin", ntlm_hash="abc123")
        call_args = mock_runner.run.call_args
        assert "-hashes" in call_args[0][0]


class TestCertify:
    @pytest.mark.asyncio
    async def test_certify_vulnerable(self, mock_runner: AsyncMock) -> None:
        from kambo.tools.ad import ad_certify

        mock_runner.run.return_value = _mock_result("Template: WebServer\nESC1 - Vulnerable")
        result = await ad_certify("10.0.0.1", "test.local", "admin", "pass123")
        assert result["vulnerable_templates"] is True

    @pytest.mark.asyncio
    async def test_certify_clean(self, mock_runner: AsyncMock) -> None:
        from kambo.tools.ad import ad_certify

        mock_runner.run.return_value = _mock_result("No vulnerable templates found")
        result = await ad_certify("10.0.0.1", "test.local", "admin", "pass123")
        assert result["vulnerable_templates"] is False


class TestNtlmRelay:
    @pytest.mark.asyncio
    async def test_ntlm_relay_setup(self) -> None:
        from kambo.tools.ad import ad_ntlm_relay

        result = await ad_ntlm_relay("10.0.0.1", relay_target="10.0.0.2")
        assert result["relay_target"] == "10.0.0.2"
        assert "setup_commands" in result
        assert "responder" in result["setup_commands"]
        assert "ntlmrelayx_smb" in result["setup_commands"]
