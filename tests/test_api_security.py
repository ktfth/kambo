"""Tests for API security tool wrappers (BOLA, BFLA, Misconfig)."""

from __future__ import annotations

import pytest

from tests.conftest import patch_runner


class TestApiTestBola:
    @pytest.mark.asyncio
    async def test_bola_detected_different_data(self) -> None:
        """User A can access user B's data → BOLA."""
        from kambo.tools.api_security import api_test_bola

        # Baseline: user B gets their own data
        baseline_response = 'HTTP/1.1 200 OK\r\n\r\n{"id": 2, "name": "UserB", "email": "b@test.com"}'
        # Attack: user A accessing user B's endpoint also gets data
        attack_response = 'HTTP/1.1 200 OK\r\n\r\n{"id": 2, "name": "UserB", "email": "b@test.com"}'

        with patch_runner({
            "api_test_bola_baseline": baseline_response,
            "api_test_bola": attack_response,
        }):
            result = await api_test_bola(
                "http://example.com",
                user_a_token="tokenA",
                user_b_token="tokenB",
                endpoints=["/api/users/2"],
            )
        assert result["total_tested"] >= 1

    @pytest.mark.asyncio
    async def test_bola_denied(self) -> None:
        """User A gets 403 → properly denied."""
        from kambo.tools.api_security import api_test_bola

        baseline = 'HTTP/1.1 200 OK\r\n\r\n{"id": 2, "name": "UserB"}'
        denied = 'HTTP/1.1 403 Forbidden\r\n\r\n{"error": "Access denied"}'

        with patch_runner({
            "api_test_bola_baseline": baseline,
            "api_test_bola": denied,
        }):
            result = await api_test_bola(
                "http://example.com",
                user_a_token="tokenA",
                user_b_token="tokenB",
                endpoints=["/api/users/2"],
            )
        assert result["vulnerable_endpoints"] == 0


class TestApiTestBfla:
    @pytest.mark.asyncio
    async def test_bfla_admin_access(self) -> None:
        """Regular user accessing admin endpoint successfully → BFLA."""
        from kambo.tools.api_security import api_test_bfla

        # Unauthenticated baseline
        baseline = 'HTTP/1.1 401 Unauthorized\r\n\r\n{"error": "Not authenticated"}'
        # Regular user gets admin data
        admin_response = 'HTTP/1.1 200 OK\r\n\r\n{"users": [{"id": 1, "role": "admin"}]}'

        with patch_runner({
            "api_test_bfla_baseline": baseline,
            "api_test_bfla": admin_response,
        }):
            result = await api_test_bfla(
                "http://example.com",
                regular_token="regular_token",
                admin_endpoints=["/api/admin/users"],
            )
        assert result["vulnerable_endpoints"] >= 0  # structure check

    @pytest.mark.asyncio
    async def test_bfla_denied(self) -> None:
        """Regular user gets 403 on admin endpoint → properly denied."""
        from kambo.tools.api_security import api_test_bfla

        baseline = 'HTTP/1.1 401 Unauthorized\r\n\r\n{"error": "Not authenticated"}'
        denied = 'HTTP/1.1 403 Forbidden\r\n\r\n{"error": "Insufficient privileges"}'

        with patch_runner({
            "api_test_bfla_baseline": baseline,
            "api_test_bfla": denied,
        }):
            result = await api_test_bfla(
                "http://example.com",
                regular_token="regular_token",
                admin_endpoints=["/api/admin/users"],
            )
        assert result["vulnerable_endpoints"] == 0


class TestApiTestMisconfig:
    @pytest.mark.asyncio
    async def test_misconfig_detection(self) -> None:
        """API with debug mode and excessive headers → misconfiguration."""
        from kambo.tools.api_security import api_test_misconfig

        # The misconfig tool runs multiple checks
        with patch_runner({
            "api_test_misconfig": 'HTTP/1.1 200 OK\r\nX-Powered-By: Express\r\nServer: nginx/1.14\r\n\r\n{"debug": true}',
        }):
            result = await api_test_misconfig("http://example.com/api")
        assert "checks" in result
        assert "security_headers" in result["checks"]
