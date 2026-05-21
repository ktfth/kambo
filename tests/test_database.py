"""Tests for database persistence layer."""

from __future__ import annotations

import json

import pytest

from kambo.database import Database
from kambo.models import (
    Confidence,
    EvidenceChain,
    Finding,
    Phase,
    Severity,
    ToolResult,
)


@pytest.fixture
async def db(tmp_path):
    database = Database(tmp_path / "test.db")
    await database.connect()
    yield database
    await database.close()


class TestFindingPersistence:
    @pytest.mark.asyncio
    async def test_save_and_retrieve_finding(self, db: Database) -> None:
        finding = Finding(
            id="FIND-001",
            title="Test SQLi",
            severity=Severity.CRITICAL,
            confidence=Confidence.CONFIRMED,
            phase=Phase.VULN_ANALYSIS,
            target="http://example.com",
            description="SQL injection in id parameter",
        )
        await db.save_finding(finding)
        results = await db.get_findings()

        assert len(results) == 1
        assert results[0]["id"] == "FIND-001"
        assert results[0]["confidence"] == "confirmed"
        assert results[0]["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_finding_with_evidence_chain(self, db: Database) -> None:
        chain = EvidenceChain()
        chain = chain.add("sqlmap confirmed injection", "sqlmap", weight=1.5)
        chain = chain.add("DBMS: MySQL", "sqlmap", weight=0.5)
        chain = chain.add_fp_check("No timeout detected")

        finding = Finding(
            id="FIND-002",
            title="Confirmed SQLi",
            severity=Severity.CRITICAL,
            confidence=chain.confidence,
            phase=Phase.VULN_ANALYSIS,
            target="http://example.com",
            description="Confirmed SQL injection",
            evidence_chain=chain,
        )
        await db.save_finding(finding)
        results = await db.get_findings()

        assert len(results) == 1
        stored_chain = json.loads(results[0]["evidence_chain"])
        assert len(stored_chain["items"]) == 2
        assert len(stored_chain["false_positive_checks"]) == 1

    @pytest.mark.asyncio
    async def test_filter_by_severity(self, db: Database) -> None:
        for i, sev in enumerate(["critical", "high", "low"]):
            await db.save_finding(Finding(
                id=f"FIND-{i:03d}",
                title=f"Finding {sev}",
                severity=Severity(sev),
                phase=Phase.VULN_ANALYSIS,
                target="http://example.com",
                description=f"Test {sev}",
            ))

        critical = await db.get_findings(severity="critical")
        assert len(critical) == 1
        assert critical[0]["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_upsert_finding(self, db: Database) -> None:
        finding = Finding(
            id="FIND-001",
            title="Original",
            severity=Severity.LOW,
            phase=Phase.VULN_ANALYSIS,
            target="http://example.com",
            description="First version",
        )
        await db.save_finding(finding)

        updated = Finding(
            id="FIND-001",
            title="Updated",
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            phase=Phase.VULN_ANALYSIS,
            target="http://example.com",
            description="Updated version",
        )
        await db.save_finding(updated)

        results = await db.get_findings()
        assert len(results) == 1
        assert results[0]["title"] == "Updated"
        assert results[0]["severity"] == "high"


class TestSessionLog:
    @pytest.mark.asyncio
    async def test_log_tool_result(self, db: Database) -> None:
        result = ToolResult(
            tool_name="vuln_sqli",
            command="sqlmap ...",
            target="http://example.com",
            phase=Phase.VULN_ANALYSIS,
            exit_code=0,
            raw_output="injectable",
            duration_seconds=5.2,
        )
        await db.log_result(result)
        logs = await db.get_session_log()

        assert len(logs) == 1
        assert logs[0]["tool_name"] == "vuln_sqli"
        assert logs[0]["exit_code"] == 0

    @pytest.mark.asyncio
    async def test_session_log_limit(self, db: Database) -> None:
        for i in range(10):
            await db.log_result(ToolResult(
                tool_name=f"tool_{i}",
                command="cmd",
                target="example.com",
                phase=Phase.RECON,
            ))

        logs = await db.get_session_log(limit=5)
        assert len(logs) == 5


class TestReconData:
    @pytest.mark.asyncio
    async def test_save_and_retrieve_recon(self, db: Database) -> None:
        await db.save_recon_data("subdomains", "example.com", "sub1.example.com", "subfinder")
        await db.save_recon_data("subdomains", "example.com", "sub2.example.com", "crtsh")

        results = await db.get_recon_data("subdomains", "example.com")
        assert len(results) == 2
