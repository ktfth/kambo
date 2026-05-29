"""Tests for Cloud Security tools."""

from __future__ import annotations

import json

import pytest

from tests.conftest import patch_runner


class TestCloudImdsTest:
    @pytest.mark.asyncio
    async def test_imds_metadata_without_oob_not_vulnerable(self) -> None:
        """IMDS SSRF is a blind class — body metadata keywords without an OOB hit
        stay TENTATIVE and are not 'vulnerable' (I3). Also exercises the
        cloud_imds_test code path end-to-end."""
        output = "HTTP/1.1 200 OK\r\n\r\nami-id\ninstance-id\nsecurity-credentials"
        with patch_runner({"cloud_imds_test": output}):
            from kambo.tools.cloud import cloud_imds_test
            result = await cloud_imds_test("http://example.com/fetch?url=x", parameter="url")

        assert result["vulnerable"] is False
        assert result["confidence"] == "tentative"


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

    @pytest.mark.asyncio
    async def test_many_unverified_secrets_capped_tentative(self) -> None:
        """Liveness gate (§5): many unverified critical secrets accumulate weight
        but, with no liveness check, never exceed TENTATIVE."""
        lines = "\n".join(
            json.dumps({
                "DetectorName": "AWS",
                "Verified": False,
                "SourceMetadata": {"Data": {"Filesystem": {"file": f"f{i}.env"}}},
            })
            for i in range(8)  # 8 × 0.5 = 4.0 weight — would be CONFIRMED uncapped
        )
        with patch_runner({"cloud_secret_scan": lines}):
            from kambo.tools.cloud import cloud_secret_scan
            result = await cloud_secret_scan("example.com")

        assert result["secrets_found"] == 8
        assert result["verified_count"] == 0
        assert result["confidence"] == "tentative"
        assert result["vulnerable"] is False
        assert any("liveness" in g.lower() for g in result["evidence"]["gates"])
