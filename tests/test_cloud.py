"""Tests for Cloud Security tools."""

from __future__ import annotations

import json

import pytest

from tests.conftest import patch_runner


class TestCloudStorageEnum:
    @pytest.mark.asyncio
    async def test_public_s3_bucket(self) -> None:
        output = "HTTP/1.1 200 OK\r\n\r\n<ListBucketResult><Name>example-com</Name></ListBucketResult>"
        with patch_runner({"cloud_storage_enum": output}):
            from kambo.tools.cloud import cloud_storage_enum
            result = await cloud_storage_enum("example.com", cloud_provider="aws")

        assert result["vulnerable"] is True
        assert any(r.get("listable") for r in result["found"])

    @pytest.mark.asyncio
    async def test_private_s3_bucket(self) -> None:
        output = "HTTP/1.1 403 Forbidden\r\n\r\nAccessDenied"
        with patch_runner({"cloud_storage_enum": output}):
            from kambo.tools.cloud import cloud_storage_enum
            result = await cloud_storage_enum("example.com", cloud_provider="aws")

        assert result["vulnerable"] is False


class TestCloudSecretScan:
    @pytest.mark.asyncio
    async def test_verified_secret(self) -> None:
        secret_line = json.dumps({
            "DetectorName": "AWS",
            "Verified": True,
            "SourceMetadata": {"Data": {"Filesystem": {"file": "config.py"}}},
        })
        with patch_runner({"cloud_secret_scan": secret_line}):
            from kambo.tools.cloud import cloud_secret_scan
            result = await cloud_secret_scan("example.com")

        assert result["vulnerable"] is True
        assert result["verified_count"] == 1
        assert result["confidence"] == "confirmed"

    @pytest.mark.asyncio
    async def test_unverified_generic_secret(self) -> None:
        secret_line = json.dumps({
            "DetectorName": "Generic",
            "Verified": False,
            "SourceMetadata": {"Data": {"Filesystem": {"file": "test.txt"}}},
        })
        with patch_runner({"cloud_secret_scan": secret_line}):
            from kambo.tools.cloud import cloud_secret_scan
            result = await cloud_secret_scan("example.com")

        assert result["secrets_found"] == 1
        assert result["verified_count"] == 0
        assert result["confidence"] == "tentative"

    @pytest.mark.asyncio
    async def test_no_secrets(self) -> None:
        with patch_runner({"cloud_secret_scan": ""}):
            from kambo.tools.cloud import cloud_secret_scan
            result = await cloud_secret_scan("example.com")

        assert result["secrets_found"] == 0
        assert result["vulnerable"] is False
