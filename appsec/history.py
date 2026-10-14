"""Opt-in SQLite persistence for local project and scan history."""

import json
import re
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

_PROJECT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,63}$")


@contextmanager
def _database(path: Path) -> Iterator[sqlite3.Connection]:
    connection = _connect(path)
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def _timestamp() -> str:
    return datetime.now(UTC).isoformat()


def _connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=5)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE COLLATE NOCASE,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL REFERENCES projects(id),
            created_at TEXT NOT NULL,
            files_scanned INTEGER NOT NULL,
            finding_count INTEGER NOT NULL,
            dependency_count INTEGER NOT NULL,
            source_bytes INTEGER NOT NULL,
            result_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_scans_project_created
            ON scans(project_id, created_at DESC);
        """
    )
    return connection


def validate_project_name(name: Any) -> str:
    """Validate a project label without allowing control characters or excessive length."""
    if not isinstance(name, str):
        raise TypeError("Project name must be a string.")
    normalized = name.strip()
    if not _PROJECT_NAME.fullmatch(normalized):
        raise ValueError(
            "Project name must be 1-64 safe letters, numbers, spaces, '.', '_' or '-'."
        )
    return normalized


def create_project(path: Path, name: str) -> dict[str, Any]:
    """Create a project; duplicate names are rejected case-insensitively."""
    normalized = validate_project_name(name)
    with _database(path) as connection:
        cursor = connection.execute(
            "INSERT INTO projects(name, created_at) VALUES (?, ?)",
            (normalized, _timestamp()),
        )
        row = connection.execute(
            "SELECT id, name, created_at FROM projects WHERE id = ?", (cursor.lastrowid,)
        ).fetchone()
        if row is None:
            raise RuntimeError("Could not retrieve the created project.")
        return dict(row)


def list_projects(path: Path) -> list[dict[str, Any]]:
    """List projects with scan counts."""
    with _database(path) as connection:
        rows = connection.execute(
            """
            SELECT p.id, p.name, p.created_at, COUNT(s.id) AS scan_count
            FROM projects p LEFT JOIN scans s ON s.project_id = p.id
            GROUP BY p.id ORDER BY p.name COLLATE NOCASE
            """
        ).fetchall()
        return [dict(row) for row in rows]


def save_scan(
    path: Path, project_name: str, result: dict[str, Any], source_bytes: int
) -> int:
    """Persist scan metadata and redacted result JSON, never the submitted source files."""
    normalized = validate_project_name(project_name)
    created_at = _timestamp()
    with _database(path) as connection:
        connection.execute(
            "INSERT OR IGNORE INTO projects(name, created_at) VALUES (?, ?)",
            (normalized, created_at),
        )
        project = connection.execute(
            "SELECT id FROM projects WHERE name = ? COLLATE NOCASE", (normalized,)
        ).fetchone()
        if project is None:
            raise RuntimeError("Could not resolve scan project.")
        cursor = connection.execute(
            """
            INSERT INTO scans(
                project_id, created_at, files_scanned, finding_count,
                dependency_count, source_bytes, result_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                project["id"],
                created_at,
                int(result.get("files_scanned", 0)),
                len(result.get("findings", [])),
                len(result.get("dependencies", [])),
                source_bytes,
                json.dumps(result, separators=(",", ":"), ensure_ascii=False),
            ),
        )
        if cursor.lastrowid is None:
            raise RuntimeError("Could not retrieve the created scan ID.")
        return int(cursor.lastrowid)


def list_scans(
    path: Path, *, project_name: str | None = None, limit: int = 50
) -> list[dict[str, Any]]:
    """List recent scan summaries with a hard upper bound."""
    bounded_limit = max(1, min(int(limit), 100))
    with _database(path) as connection:
        if project_name is None:
            rows = connection.execute(
                """
                SELECT s.id, p.name AS project, s.created_at, s.files_scanned,
                       s.finding_count, s.dependency_count, s.source_bytes
                FROM scans s JOIN projects p ON p.id = s.project_id
                ORDER BY s.created_at DESC, s.id DESC LIMIT ?
                """,
                (bounded_limit,),
            ).fetchall()
        else:
            rows = connection.execute(
                """
                SELECT s.id, p.name AS project, s.created_at, s.files_scanned,
                       s.finding_count, s.dependency_count, s.source_bytes
                FROM scans s JOIN projects p ON p.id = s.project_id
                WHERE p.name = ? COLLATE NOCASE
                ORDER BY s.created_at DESC, s.id DESC LIMIT ?
                """,
                (project_name, bounded_limit),
            ).fetchall()
        return [dict(row) for row in rows]


def get_scan(path: Path, scan_id: int) -> dict[str, Any] | None:
    """Retrieve one persisted scan result by ID."""
    with _database(path) as connection:
        row = connection.execute(
            """
            SELECT s.id, p.name AS project, s.created_at, s.files_scanned,
                   s.finding_count, s.dependency_count, s.source_bytes, s.result_json
            FROM scans s JOIN projects p ON p.id = s.project_id WHERE s.id = ?
            """,
            (scan_id,),
        ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["result"] = json.loads(result.pop("result_json"))
        return result


def usage_summary(path: Path) -> dict[str, Any]:
    """Report local scan usage for the last 30 days."""
    cutoff = (datetime.now(UTC) - timedelta(days=30)).isoformat()
    with _database(path) as connection:
        row = connection.execute(
            """
            SELECT COUNT(*) AS scans, COALESCE(SUM(files_scanned), 0) AS files_scanned,
                   COALESCE(SUM(finding_count), 0) AS findings,
                   COALESCE(SUM(source_bytes), 0) AS source_bytes
            FROM scans WHERE created_at >= ?
            """,
            (cutoff,),
        ).fetchone()
        return {"period_days": 30, **dict(row)}
