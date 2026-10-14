"""Opt-in SQLite persistence for local projects, users, memberships, and scan history."""

import hashlib
import json
import re
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

_PROJECT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,63}$")
_USERNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_PROJECT_ROLES = {"admin", "editor", "viewer"}


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
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            token_hash TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS project_memberships (
            project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            role TEXT NOT NULL CHECK(role IN ('admin', 'editor', 'viewer')),
            created_at TEXT NOT NULL,
            PRIMARY KEY (project_id, user_id)
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
        CREATE INDEX IF NOT EXISTS idx_memberships_user
            ON project_memberships(user_id, project_id);
        """
    )
    return connection


@contextmanager
def _database(path: Path) -> Iterator[sqlite3.Connection]:
    connection = _connect(path)
    try:
        with connection:
            yield connection
    finally:
        connection.close()


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


def validate_username(username: Any) -> str:
    """Validate a user name used in local team membership."""
    if not isinstance(username, str):
        raise TypeError("Username must be a string.")
    normalized = username.strip()
    if not _USERNAME.fullmatch(normalized):
        raise ValueError("Username must be 1-64 letters, numbers, '.', '_' or '-'.")
    return normalized


def create_user(path: Path, username: str, token: str) -> dict[str, Any]:
    """Store a one-way token hash and return safe user metadata."""
    normalized = validate_username(username)
    if not isinstance(token, str) or len(token) < 32 or not token.isascii():
        raise ValueError("User token must contain at least 32 ASCII characters.")
    token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
    with _database(path) as connection:
        cursor = connection.execute(
            "INSERT INTO users(username, token_hash, created_at) VALUES (?, ?, ?)",
            (normalized, token_hash, _timestamp()),
        )
        row = connection.execute(
            "SELECT id, username, created_at FROM users WHERE id = ?", (cursor.lastrowid,)
        ).fetchone()
        if row is None:
            raise RuntimeError("Could not retrieve the created user.")
        return dict(row)



def delete_user(path: Path, username: str) -> bool:
    """Revoke a user token, preserving at least one administrator per project."""
    normalized = validate_username(username)
    with _database(path) as connection:
        user = connection.execute(
            "SELECT id FROM users WHERE username = ? COLLATE NOCASE", (normalized,)
        ).fetchone()
        if user is None:
            return False
        admin_projects = connection.execute(
            "SELECT project_id FROM project_memberships WHERE user_id = ? AND role = 'admin'",
            (user["id"],),
        ).fetchall()
        for membership in admin_projects:
            admins = connection.execute(
                "SELECT COUNT(*) FROM project_memberships WHERE project_id = ? AND role = 'admin'",
                (membership["project_id"],),
            ).fetchone()
            if admins is not None and int(admins[0]) <= 1:
                raise ValueError(
                    "Cannot delete the last project administrator; assign another admin first."
                )
        connection.execute("DELETE FROM users WHERE id = ?", (user["id"],))
        return True

def find_user_by_token(path: Path, token: str) -> dict[str, Any] | None:
    """Resolve a user from a bearer token without storing the raw token."""
    if not token or not token.isascii():
        return None
    token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
    with _database(path) as connection:
        row = connection.execute(
            "SELECT id, username, created_at FROM users WHERE token_hash = ?", (token_hash,)
        ).fetchone()
        return dict(row) if row is not None else None


def has_users(path: Path) -> bool:
    """Return whether user-token authentication has been bootstrapped."""
    with _database(path) as connection:
        row = connection.execute("SELECT 1 FROM users LIMIT 1").fetchone()
        return row is not None


def list_users(path: Path) -> list[dict[str, Any]]:
    """List user metadata without exposing token hashes."""
    with _database(path) as connection:
        rows = connection.execute(
            "SELECT id, username, created_at FROM users ORDER BY username COLLATE NOCASE"
        ).fetchall()
        return [dict(row) for row in rows]


def create_project(
    path: Path, name: str, *, owner_username: str | None = None
) -> dict[str, Any]:
    """Create a project and optionally grant its creator project-admin access."""
    normalized = validate_project_name(name)
    with _database(path) as connection:
        cursor = connection.execute(
            "INSERT INTO projects(name, created_at) VALUES (?, ?)",
            (normalized, _timestamp()),
        )
        if owner_username is not None:
            owner = connection.execute(
                "SELECT id FROM users WHERE username = ? COLLATE NOCASE",
                (validate_username(owner_username),),
            ).fetchone()
            if owner is None:
                raise ValueError("Project owner does not exist.")
            connection.execute(
                "INSERT INTO project_memberships(project_id, user_id, role, created_at) "
                "VALUES (?, ?, 'admin', ?)",
                (cursor.lastrowid, owner["id"], _timestamp()),
            )
        row = connection.execute(
            "SELECT id, name, created_at FROM projects WHERE id = ?", (cursor.lastrowid,)
        ).fetchone()
        if row is None:
            raise RuntimeError("Could not retrieve the created project.")
        return dict(row)


def add_project_member(
    path: Path, project_name: str, username: str, role: str = "viewer"
) -> dict[str, Any]:
    """Add or update a user's role while preserving at least one project admin."""
    project_name = validate_project_name(project_name)
    username = validate_username(username)
    if role not in _PROJECT_ROLES:
        raise ValueError("Role must be one of: admin, editor, viewer.")
    with _database(path) as connection:
        project = connection.execute(
            "SELECT id FROM projects WHERE name = ? COLLATE NOCASE", (project_name,)
        ).fetchone()
        user = connection.execute(
            "SELECT id FROM users WHERE username = ? COLLATE NOCASE", (username,)
        ).fetchone()
        if project is None:
            raise ValueError("Project does not exist.")
        if user is None:
            raise ValueError("User does not exist.")
        existing = connection.execute(
            "SELECT role FROM project_memberships WHERE project_id = ? AND user_id = ?",
            (project["id"], user["id"]),
        ).fetchone()
        if existing is not None and existing["role"] == "admin" and role != "admin":
            admins = connection.execute(
                "SELECT COUNT(*) FROM project_memberships WHERE project_id = ? AND role = 'admin'",
                (project["id"],),
            ).fetchone()
            if admins is not None and int(admins[0]) <= 1:
                raise ValueError("Cannot demote the last project administrator.")
        connection.execute(
            """
            INSERT INTO project_memberships(project_id, user_id, role, created_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(project_id, user_id) DO UPDATE SET role = excluded.role
            """,
            (project["id"], user["id"], role, _timestamp()),
        )
        return {"project": project_name, "username": username, "role": role}


def project_role(path: Path, project_name: str, username: str) -> str | None:
    """Get a user's role in a project, if membership exists."""
    with _database(path) as connection:
        row = connection.execute(
            """
            SELECT m.role FROM project_memberships m
            JOIN projects p ON p.id = m.project_id
            JOIN users u ON u.id = m.user_id
            WHERE p.name = ? COLLATE NOCASE AND u.username = ? COLLATE NOCASE
            """,
            (project_name, username),
        ).fetchone()
        return str(row["role"]) if row is not None else None


def list_project_members(path: Path, project_name: str) -> list[dict[str, Any]]:
    """List project membership without exposing authentication data."""
    with _database(path) as connection:
        rows = connection.execute(
            """
            SELECT u.username, m.role, m.created_at
            FROM project_memberships m
            JOIN projects p ON p.id = m.project_id
            JOIN users u ON u.id = m.user_id
            WHERE p.name = ? COLLATE NOCASE ORDER BY u.username COLLATE NOCASE
            """,
            (project_name,),
        ).fetchall()
        return [dict(row) for row in rows]


def remove_project_member(path: Path, project_name: str, username: str) -> bool:
    """Remove a member but never leave a project without an administrator."""
    with _database(path) as connection:
        member = connection.execute(
            """
            SELECT p.id AS project_id, u.id AS user_id, m.role
            FROM projects p JOIN project_memberships m ON m.project_id = p.id
            JOIN users u ON u.id = m.user_id
            WHERE p.name = ? COLLATE NOCASE AND u.username = ? COLLATE NOCASE
            """,
            (project_name, username),
        ).fetchone()
        if member is None:
            return False
        if member["role"] == "admin":
            admins = connection.execute(
                "SELECT COUNT(*) FROM project_memberships WHERE project_id = ? AND role = 'admin'",
                (member["project_id"],),
            ).fetchone()
            if admins is not None and int(admins[0]) <= 1:
                raise ValueError("Cannot remove the last project administrator.")
        connection.execute(
            "DELETE FROM project_memberships WHERE project_id = ? AND user_id = ?",
            (member["project_id"], member["user_id"]),
        )
        return True


def list_projects(path: Path, *, username: str | None = None) -> list[dict[str, Any]]:
    """List all projects for admins or only memberships for a named user."""
    with _database(path) as connection:
        if username is None:
            rows = connection.execute(
                """
                SELECT p.id, p.name, p.created_at, COUNT(s.id) AS scan_count
                FROM projects p LEFT JOIN scans s ON s.project_id = p.id
                GROUP BY p.id ORDER BY p.name COLLATE NOCASE
                """
            ).fetchall()
        else:
            rows = connection.execute(
                """
                SELECT p.id, p.name, p.created_at, COUNT(s.id) AS scan_count, m.role
                FROM projects p
                JOIN project_memberships m ON m.project_id = p.id
                JOIN users u ON u.id = m.user_id
                LEFT JOIN scans s ON s.project_id = p.id
                WHERE u.username = ? COLLATE NOCASE
                GROUP BY p.id, m.role ORDER BY p.name COLLATE NOCASE
                """,
                (username,),
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
    path: Path,
    *,
    project_name: str | None = None,
    username: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """List recent scan summaries, optionally filtered by project membership."""
    bounded_limit = max(1, min(int(limit), 100))
    with _database(path) as connection:
        joins = ""
        conditions: list[str] = []
        parameters: list[Any] = []
        if username is not None:
            joins += (
                " JOIN project_memberships m ON m.project_id = s.project_id"
                " JOIN users u ON u.id = m.user_id"
            )
            conditions.append("u.username = ? COLLATE NOCASE")
            parameters.append(username)
        if project_name is not None:
            conditions.append("p.name = ? COLLATE NOCASE")
            parameters.append(project_name)
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        parameters.append(bounded_limit)
        rows = connection.execute(
            """
            SELECT s.id, p.name AS project, s.created_at, s.files_scanned,
                   s.finding_count, s.dependency_count, s.source_bytes
            FROM scans s JOIN projects p ON p.id = s.project_id
            """
            + joins
            + where
            + " ORDER BY s.created_at DESC, s.id DESC LIMIT ?",
            parameters,
        ).fetchall()
        return [dict(row) for row in rows]


def get_scan(
    path: Path, scan_id: int, *, username: str | None = None
) -> dict[str, Any] | None:
    """Retrieve one scan result, enforcing project membership when a user is supplied."""
    with _database(path) as connection:
        membership = ""
        parameters: list[Any] = [scan_id]
        if username is not None:
            membership = (
                " AND EXISTS (SELECT 1 FROM project_memberships m "
                "JOIN users u ON u.id = m.user_id "
                "WHERE m.project_id = s.project_id AND u.username = ? COLLATE NOCASE)"
            )
            parameters.append(username)
        row = connection.execute(
            """
            SELECT s.id, p.name AS project, s.created_at, s.files_scanned,
                   s.finding_count, s.dependency_count, s.source_bytes, s.result_json
            FROM scans s JOIN projects p ON p.id = s.project_id
            WHERE s.id = ?
            """
            + membership,
            parameters,
        ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["result"] = json.loads(result.pop("result_json"))
        return result


def usage_summary(path: Path, *, username: str | None = None) -> dict[str, Any]:
    """Report local scan usage for the last 30 days, optionally by project membership."""
    cutoff = (datetime.now(UTC) - timedelta(days=30)).isoformat()
    with _database(path) as connection:
        joins = ""
        parameters: list[Any] = [cutoff]
        if username is not None:
            joins = (
                " JOIN project_memberships m ON m.project_id = scans.project_id"
                " JOIN users u ON u.id = m.user_id"
            )
        user_condition = ""
        if username is not None:
            user_condition = " AND u.username = ? COLLATE NOCASE"
            parameters.append(username)
        row = connection.execute(
            """
            SELECT COUNT(*) AS scans, COALESCE(SUM(files_scanned), 0) AS files_scanned,
                   COALESCE(SUM(finding_count), 0) AS findings,
                   COALESCE(SUM(source_bytes), 0) AS source_bytes
            FROM scans
            """
            + joins
            + " WHERE scans.created_at >= ?"
            + user_condition,
            parameters,
        ).fetchone()
        return {"period_days": 30, **dict(row)}


def has_membership(path: Path, project_name: str, username: str) -> bool:
    """Return whether a user belongs to a project."""
    return project_role(path, project_name, username) is not None
