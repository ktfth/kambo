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
    cvss REAL,
    cvss_vector TEXT,
    phase TEXT NOT NULL,
    target TEXT NOT NULL,
    description TEXT NOT NULL,
    reproduction_steps TEXT DEFAULT '[]',
    evidence TEXT DEFAULT '{}',
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
               (id, title, severity, cvss, cvss_vector, phase, target, description,
                reproduction_steps, evidence, impact, remediation, references_json, tools_used, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                finding.id,
                finding.title,
                finding.severity.value,
                finding.cvss,
                finding.cvss_vector,
                finding.phase.value,
                finding.target,
                finding.description,
                json.dumps(finding.reproduction_steps),
                json.dumps(finding.evidence),
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


# Singleton
_db: Database | None = None


async def get_database() -> Database:
    global _db
    if _db is None:
        _db = Database()
        await _db.connect()
    return _db
