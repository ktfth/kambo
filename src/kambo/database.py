"""SQLite persistence for session state, findings, and logs."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import aiosqlite

from kambo.config import get_config
from kambo.models import Finding, Phase, ToolResult

_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL DEFAULT 'tentative',
    cvss REAL,
    cvss_vector TEXT,
    phase TEXT NOT NULL,
    target TEXT NOT NULL,
    description TEXT NOT NULL,
    reproduction_steps TEXT DEFAULT '[]',
    evidence TEXT DEFAULT '{}',
    evidence_chain TEXT DEFAULT '{}',
    impact TEXT DEFAULT '',
    remediation TEXT DEFAULT '',
    references_json TEXT DEFAULT '[]',
    tools_used TEXT DEFAULT '[]',
    timestamp TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS session_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool_name TEXT NOT NULL,
    command TEXT NOT NULL,
    target TEXT NOT NULL,
    phase TEXT NOT NULL,
    exit_code INTEGER NOT NULL,
    duration_seconds REAL NOT NULL,
    raw_output TEXT DEFAULT '',
    parsed TEXT DEFAULT '{}',
    error TEXT,
    timestamp TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS recon_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    data_type TEXT NOT NULL,
    target TEXT NOT NULL,
    data TEXT NOT NULL,
    source TEXT NOT NULL,
    timestamp TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tool_metrics (
    tool_name TEXT PRIMARY KEY,
    total_runs INTEGER NOT NULL DEFAULT 0,
    total_findings INTEGER NOT NULL DEFAULT 0,
    confirmed_count INTEGER NOT NULL DEFAULT 0,
    firm_count INTEGER NOT NULL DEFAULT 0,
    tentative_count INTEGER NOT NULL DEFAULT 0,
    user_confirmed INTEGER NOT NULL DEFAULT 0,
    user_rejected INTEGER NOT NULL DEFAULT 0,
    avg_evidence_weight REAL NOT NULL DEFAULT 0.0,
    last_run TEXT,
    updated_at TEXT NOT NULL
);
"""


class Database:
    """Async SQLite database for Kambo state."""

    def __init__(self, db_path: Path | None = None) -> None:
        self._path = db_path or get_config().db_path
        self._db: aiosqlite.Connection | None = None

    async def connect(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(str(self._path))
        await self._db.executescript(_SCHEMA)
        await self._db.commit()

    async def close(self) -> None:
        if self._db:
            await self._db.close()
            self._db = None

    async def log_result(self, result: ToolResult) -> None:
        """Persist a tool execution result."""
        assert self._db is not None
        await self._db.execute(
            """INSERT INTO session_log
               (tool_name, command, target, phase, exit_code, duration_seconds, raw_output, parsed, error, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                result.tool_name,
                result.command,
                result.target,
                result.phase.value,
                result.exit_code,
                result.duration_seconds,
                result.raw_output[:50000],  # cap storage
                json.dumps(result.parsed),
                result.error,
                result.timestamp.isoformat(),
            ),
        )
        await self._db.commit()

    async def save_finding(self, finding: Finding) -> None:
        """Persist a security finding."""
        assert self._db is not None
        await self._db.execute(
            """INSERT OR REPLACE INTO findings
               (id, title, severity, confidence, cvss, cvss_vector, phase, target, description,
                reproduction_steps, evidence, evidence_chain, impact, remediation, references_json, tools_used, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                finding.id,
                finding.title,
                finding.severity.value,
                finding.confidence.value,
                finding.cvss,
                finding.cvss_vector,
                finding.phase.value,
                finding.target,
                finding.description,
                json.dumps(finding.reproduction_steps),
                json.dumps(finding.evidence),
                json.dumps(finding.evidence_chain.model_dump(mode="json")),
                finding.impact,
                finding.remediation,
                json.dumps(finding.references),
                json.dumps(finding.tools_used),
                finding.timestamp.isoformat(),
            ),
        )
        await self._db.commit()

    async def get_findings(self, severity: str | None = None) -> list[dict]:
        """Retrieve all findings, optionally filtered by severity."""
        assert self._db is not None
        query = "SELECT * FROM findings"
        params: list = []
        if severity:
            query += " WHERE severity = ?"
            params.append(severity)
        query += " ORDER BY timestamp DESC"

        async with self._db.execute(query, params) as cursor:
            columns = [desc[0] for desc in cursor.description]
            rows = await cursor.fetchall()
            return [dict(zip(columns, row)) for row in rows]

    async def save_recon_data(self, data_type: str, target: str, data: str, source: str) -> None:
        """Store reconnaissance data (subdomains, ports, etc.)."""
        assert self._db is not None
        await self._db.execute(
            "INSERT INTO recon_data (data_type, target, data, source, timestamp) VALUES (?, ?, ?, ?, ?)",
            (data_type, target, data, source, datetime.now(timezone.utc).isoformat()),
        )
        await self._db.commit()

    async def get_recon_data(self, data_type: str, target: str) -> list[dict]:
        """Retrieve recon data by type and target."""
        assert self._db is not None
        async with self._db.execute(
            "SELECT * FROM recon_data WHERE data_type = ? AND target = ? ORDER BY timestamp DESC",
            (data_type, target),
        ) as cursor:
            columns = [desc[0] for desc in cursor.description]
            rows = await cursor.fetchall()
            return [dict(zip(columns, row)) for row in rows]

    async def get_session_log(self, limit: int = 50) -> list[dict]:
        """Retrieve recent session log entries."""
        assert self._db is not None
        async with self._db.execute(
            "SELECT * FROM session_log ORDER BY timestamp DESC LIMIT ?", (limit,)
        ) as cursor:
            columns = [desc[0] for desc in cursor.description]
            rows = await cursor.fetchall()
            return [dict(zip(columns, row)) for row in rows]

    # --- Tool Metrics Persistence ---

    async def save_tool_metrics(self, tool_name: str, metrics: dict) -> None:
        """Persist per-tool metrics (upsert)."""
        assert self._db is not None
        await self._db.execute(
            """INSERT INTO tool_metrics
               (tool_name, total_runs, total_findings, confirmed_count, firm_count,
                tentative_count, user_confirmed, user_rejected, avg_evidence_weight,
                last_run, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(tool_name) DO UPDATE SET
                total_runs = excluded.total_runs,
                total_findings = excluded.total_findings,
                confirmed_count = excluded.confirmed_count,
                firm_count = excluded.firm_count,
                tentative_count = excluded.tentative_count,
                user_confirmed = excluded.user_confirmed,
                user_rejected = excluded.user_rejected,
                avg_evidence_weight = excluded.avg_evidence_weight,
                last_run = excluded.last_run,
                updated_at = excluded.updated_at""",
            (
                tool_name,
                metrics.get("total_runs", 0),
                metrics.get("total_findings", 0),
                metrics.get("confirmed_count", 0),
                metrics.get("firm_count", 0),
                metrics.get("tentative_count", 0),
                metrics.get("user_confirmed", 0),
                metrics.get("user_rejected", 0),
                metrics.get("avg_evidence_weight", 0.0),
                metrics.get("last_run"),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        await self._db.commit()

    async def load_all_tool_metrics(self) -> list[dict]:
        """Load all persisted tool metrics."""
        assert self._db is not None
        async with self._db.execute("SELECT * FROM tool_metrics") as cursor:
            columns = [desc[0] for desc in cursor.description]
            rows = await cursor.fetchall()
            return [dict(zip(columns, row)) for row in rows]


# Singleton
_db: Database | None = None


async def get_database() -> Database:
    global _db
    if _db is None:
        _db = Database()
        await _db.connect()
    return _db
