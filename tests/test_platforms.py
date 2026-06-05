"""Tests for bug bounty platform API integrations."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from kambo.tools.platforms import (
    bc_fetch_program,
    bc_fetch_scope,
    bc_submit_report,
    h1_check_duplicate,
    h1_fetch_program,
    h1_fetch_scope,
    h1_submit_report,
    platform_fetch_program,
    platform_fetch_scope,
)


@pytest.fixture
def mock_h1_env():
    with patch.dict("os.environ", {"HACKERONE_API_USER": "testuser", "HACKERONE_API_TOKEN": "testtoken"}):
        yield


@pytest.fixture
def mock_bc_env():
    with patch.dict("os.environ", {"BUGCROWD_API_TOKEN": "testtoken"}):
        yield


class TestH1Auth:
    def test_missing_credentials_raises(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            with pytest.raises(ValueError, match="HackerOne API credentials"):
                h1_fetch_program("test")


class TestH1FetchProgram:
    def test_fetch_program(self, mock_h1_env) -> None:
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "name": "Test Corp",
                    "state": "public_mode",
                    "offers_bounties": True,
                    "response_efficiency_percentage": 95,
                    "submission_state": "open",
                }
            }
        }
        mock_resp.raise_for_status = MagicMock()

        with patch("kambo.tools.platforms.requests.get", return_value=mock_resp):
            result = h1_fetch_program("testcorp")
            assert result["platform"] == "hackerone"
            assert result["name"] == "Test Corp"
            assert result["offers_bounties"] is True


class TestH1FetchScope:
    def test_fetch_scope(self, mock_h1_env) -> None:
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "data": [
                {
                    "attributes": {
                        "asset_identifier": "*.example.com",
                        "asset_type": "URL",
                        "eligible_for_bounty": True,
                        "eligible_for_submission": True,
                        "max_severity": "critical",
                    }
                },
                {
                    "attributes": {
                        "asset_identifier": "staging.example.com",
                        "asset_type": "URL",
                        "eligible_for_submission": False,
                    }
                },
            ]
        }
        mock_resp.raise_for_status = MagicMock()

        with patch("kambo.tools.platforms.requests.get", return_value=mock_resp):
            result = h1_fetch_scope("testcorp")
            assert len(result["in_scope"]) == 1
            assert len(result["out_of_scope"]) == 1
            assert result["in_scope"][0]["asset"] == "*.example.com"


class TestH1CheckDuplicate:
    def test_no_duplicates(self, mock_h1_env) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": []}
        mock_resp.raise_for_status = MagicMock()

        with patch("kambo.tools.platforms.requests.get", return_value=mock_resp):
            result = h1_check_duplicate("testcorp", "SQL Injection in login")
            assert result["duplicate_risk"] == "low"
            assert len(result["possible_duplicates"]) == 0

    def test_duplicates_found(self, mock_h1_env) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": [
                {
                    "id": "12345",
                    "attributes": {
                        "title": "SQL Injection in login form",
                        "state": "disclosed",
                        "severity_rating": "critical",
                        "disclosed_at": "2024-01-01",
                    },
                },
                {
                    "id": "12346",
                    "attributes": {
                        "title": "Blind SQL Injection in search",
                        "state": "disclosed",
                        "severity_rating": "high",
                    },
                },
            ]
        }
        mock_resp.raise_for_status = MagicMock()

        with patch("kambo.tools.platforms.requests.get", return_value=mock_resp):
            result = h1_check_duplicate("testcorp", "SQL Injection in login", "sqli")
            assert len(result["possible_duplicates"]) >= 1

    @pytest.mark.parametrize("status", [401, 403, 404])
    def test_unauthorized_degrades_gracefully(self, mock_h1_env, status) -> None:
        """Valid creds but a non-200 (the Hacker API blocks this endpoint) must
        NOT raise — return an 'unavailable' warning so the hunt pipeline survives."""
        mock_resp = MagicMock()
        mock_resp.status_code = status
        # raise_for_status would raise, but the code must short-circuit before it
        mock_resp.raise_for_status.side_effect = AssertionError("should not be called")

        with patch("kambo.tools.platforms.requests.get", return_value=mock_resp):
            result = h1_check_duplicate("indrive", "Exposed API key", "exposed_api_key")

        assert result["possible_duplicates"] == []
        assert result["duplicate_risk"] == "unknown"
        assert str(status) in result["warning"]
        assert "hacktivity" in result["warning"].lower()


class TestH1SubmitReport:
    def test_submit_report(self, mock_h1_env) -> None:
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"data": {"id": "99999"}}
        mock_resp.raise_for_status = MagicMock()

        with patch("kambo.tools.platforms.requests.post", return_value=mock_resp):
            result = h1_submit_report(
                handle="testcorp",
                title="SQLi in login",
                vulnerability_info="## Description\nSQL injection found...",
                severity="critical",
            )
            assert result["status"] == "submitted"
            assert result["report_id"] == "99999"


class TestBcFetchProgram:
    def test_fetch_program(self, mock_bc_env) -> None:
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "name": "Test Corp",
                    "tagline": "Find bugs in our app",
                    "reward_range": "$100 - $10,000",
                }
            }
        }
        mock_resp.raise_for_status = MagicMock()

        with patch("kambo.tools.platforms.requests.get", return_value=mock_resp):
            result = bc_fetch_program("testcorp")
            assert result["platform"] == "bugcrowd"
            assert result["name"] == "Test Corp"


class TestBcFetchScope:
    def test_fetch_scope(self, mock_bc_env) -> None:
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "data": [
                {"attributes": {"name": "Web App", "category": "website", "uri": "https://example.com", "in_scope": True}},
                {"attributes": {"name": "Staging", "category": "website", "uri": "https://staging.example.com", "in_scope": False}},
            ]
        }
        mock_resp.raise_for_status = MagicMock()

        with patch("kambo.tools.platforms.requests.get", return_value=mock_resp):
            result = bc_fetch_scope("testcorp")
            assert len(result["in_scope"]) == 1
            assert len(result["out_of_scope"]) == 1


class TestBcSubmitReport:
    def test_submit_report(self, mock_bc_env) -> None:
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"data": {"id": "sub-12345"}}
        mock_resp.raise_for_status = MagicMock()

        with patch("kambo.tools.platforms.requests.post", return_value=mock_resp):
            result = bc_submit_report(
                slug="testcorp",
                title="XSS in search",
                description="Reflected XSS...",
                severity=2,
            )
            assert result["status"] == "submitted"
            assert result["submission_id"] == "sub-12345"


class TestUnifiedInterface:
    @pytest.mark.asyncio
    async def test_unsupported_platform(self) -> None:
        result = await platform_fetch_program("unknown", "test")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_fetch_program_routes(self, mock_h1_env) -> None:
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"data": {"attributes": {"name": "Test"}}}
        mock_resp.raise_for_status = MagicMock()

        with patch("kambo.tools.platforms.requests.get", return_value=mock_resp):
            result = await platform_fetch_program("hackerone", "test")
            assert result["platform"] == "hackerone"

    @pytest.mark.asyncio
    async def test_fetch_scope_routes(self, mock_bc_env) -> None:
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"data": []}
        mock_resp.raise_for_status = MagicMock()

        with patch("kambo.tools.platforms.requests.get", return_value=mock_resp):
            result = await platform_fetch_scope("bugcrowd", "test")
            assert result["platform"] == "bugcrowd"
