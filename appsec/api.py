"""Local-only JSON API for scanning submitted source files."""

import argparse
import hmac
import ipaddress
import json
import os
import secrets
import sqlite3
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

from appsec.findings import normalize_findings
from appsec.history import (
    add_project_member,
    create_project,
    create_user,
    delete_user,
    find_user_by_token,
    get_scan,
    has_users,
    list_project_members,
    list_projects,
    list_scans,
    list_users,
    project_role,
    remove_project_member,
    save_scan,
    usage_summary,
)
from appsec.models import DependencyRisk, ScanResult
from appsec.risk import dependency_risk_score
from appsec.scanners import JavaScriptSecurityScanner, PythonSecurityScanner, SecretScanner
from appsec.scanners.base import iter_source_files
from appsec.scanners.dependencies import discover_dependencies

_MAX_REQUEST_BYTES = 1_000_000
_MAX_FILE_BYTES = 128_000
_MAX_FILES = 200
_SOURCE_EXTENSIONS = (
    SecretScanner._EXTENSIONS | JavaScriptSecurityScanner._EXTENSIONS | {".py"}
)


def _validate_files(payload: Any) -> dict[str, str]:
    """Validate the in-memory source payload before writing any files."""
    if not isinstance(payload, dict) or not isinstance(payload.get("files"), dict):
        raise TypeError("Request JSON must contain a 'files' object.")
    files = payload["files"]
    if not files or len(files) > _MAX_FILES:
        raise ValueError(f"'files' must contain between 1 and {_MAX_FILES} entries.")

    validated: dict[str, str] = {}
    total_bytes = 0
    for name, contents in files.items():
        if not isinstance(name, str) or not isinstance(contents, str):
            raise TypeError("File names and contents must be strings.")
        path = PurePosixPath(name)
        if (
            not name
            or path.is_absolute()
            or ".." in path.parts
            or "\\" in name
            or "\x00" in name
            or "\n" in name
            or "\r" in name
            or name.startswith(".git/")
        ):
            raise ValueError(f"Unsafe relative file path: {name!r}")
        size = len(contents.encode("utf-8"))
        if size > _MAX_FILE_BYTES:
            raise ValueError(f"File exceeds {_MAX_FILE_BYTES} byte limit: {name}")
        total_bytes += size
        validated[name] = contents
    if total_bytes > _MAX_REQUEST_BYTES:
        raise ValueError(f"Total source content exceeds {_MAX_REQUEST_BYTES} bytes.")
    return validated


def scan_files(files: dict[str, str]) -> dict[str, Any]:
    """Scan validated source content in an isolated temporary directory."""
    validated = _validate_files({"files": files})
    with tempfile.TemporaryDirectory(prefix="ai-appsec-api-") as temporary:
        root = Path(temporary).resolve()
        for name, contents in validated.items():
            target = (root / PurePosixPath(name)).resolve()
            if not target.is_relative_to(root):
                raise ValueError(f"Unsafe relative file path: {name!r}")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(contents, encoding="utf-8")

        scanners = (PythonSecurityScanner(), JavaScriptSecurityScanner(), SecretScanner())
        findings = normalize_findings(
            [finding for scanner in scanners for finding in scanner.scan(root)],
            root,
        )
        extensions = set(_SOURCE_EXTENSIONS)
        files_scanned = sum(1 for _ in iter_source_files(root, extensions))
        dependencies = discover_dependencies(root)
        dependency_risks: list[DependencyRisk] = []
        for dependency in dependencies:
            score, severity, rationale = dependency_risk_score(dependency, findings)
            dependency_risks.append(
                DependencyRisk(
                    name=dependency.name,
                    score=score,
                    severity=severity,
                    rationale=rationale,
                )
            )
        result = ScanResult(
            findings=findings,
            dependencies=dependencies,
            dependency_risks=dependency_risks,
            files_scanned=files_scanned,
            rules_run=sum(scanner.rule_count for scanner in scanners),
        )
        return result.model_dump(mode="json")


class _Handler(BaseHTTPRequestHandler):
    """Local JSON handler with project-scoped role checks."""

    server_version = "AIAppSecLocalAPI/0.1"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self._principal: dict[str, Any] = {}
        super().__init__(*args, **kwargs)

    def _send_json(
        self,
        status: int,
        payload: dict[str, Any],
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _authorize(self, route: str) -> bool:
        token = os.getenv("APPSEC_API_TOKEN")
        public_routes = {"/health", "/", "/assets/dashboard.css", "/assets/dashboard.js"}
        self._principal = {"is_admin": False, "shared_admin": False, "username": None}
        if route in public_routes:
            return True

        database = os.getenv("APPSEC_DB_PATH")
        provided_header = self.headers.get("Authorization", "")
        provided = provided_header[7:] if provided_header.startswith("Bearer ") else ""
        if token and provided and hmac.compare_digest(provided, token):
            self._principal = {"is_admin": True, "shared_admin": True, "username": None}
            return True

        if database and provided:
            try:
                user = find_user_by_token(Path(database).expanduser(), provided)
            except (OSError, sqlite3.Error):
                user = None
            if user is not None:
                self._principal = {
                    "is_admin": False,
                    "shared_admin": False,
                    "username": user["username"],
                }
                return True

        auth_required = bool(token)
        if database:
            try:
                auth_required = auth_required or has_users(Path(database).expanduser())
            except (OSError, sqlite3.Error):
                auth_required = True
        if auth_required:
            self._send_json(
                401,
                {"error": "Authentication required."},
                {"WWW-Authenticate": "Bearer"},
            )
            return False

        # Loopback-only single-user mode when no token/users are configured.
        self._principal = {"is_admin": True, "shared_admin": False, "username": None}
        return True

    def _can_manage_project(self, database: Path, project_name: str) -> bool:
        if self._principal.get("is_admin"):
            return True
        username = self._principal.get("username")
        return isinstance(username, str) and project_role(database, project_name, username) == "admin"

    def _send_asset(self, name: str) -> None:
        assets = {
            "/": ("web/index.html", "text/html; charset=utf-8"),
            "/assets/dashboard.css": ("web/dashboard.css", "text/css; charset=utf-8"),
            "/assets/dashboard.js": ("web/dashboard.js", "application/javascript; charset=utf-8"),
        }
        entry = assets.get(name)
        if entry is None:
            self._send_json(404, {"error": "Not found."})
            return
        relative_path, content_type = entry
        try:
            body = (Path(__file__).parent / relative_path).read_bytes()
        except OSError:
            self._send_json(500, {"error": "Dashboard asset is unavailable."})
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; "
            "object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        )
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        route = parsed.path
        if not self._authorize(route):
            return
        if route in {"/", "/assets/dashboard.css", "/assets/dashboard.js"}:
            self._send_asset(route)
            return
        if route == "/health":
            self._send_json(200, {"status": "ok", "service": "ai-appsec-platform"})
            return

        database = os.getenv("APPSEC_DB_PATH")
        member_route = route.strip("/").split("/")
        is_member_list = (
            len(member_route) == 3
            and member_route[0] == "projects"
            and member_route[2] == "members"
        )
        if route not in {"/users", "/projects", "/history", "/usage"} and not (
            route.startswith("/history/") or is_member_list
        ):
            self._send_json(404, {"error": "Not found."})
            return
        if not database:
            self._send_json(503, {"error": "Set APPSEC_DB_PATH to enable local project features."})
            return
        db_path = Path(database).expanduser()
        username = self._principal.get("username")
        username_filter = username if isinstance(username, str) else None
        try:
            if route == "/users":
                if not self._principal.get("shared_admin"):
                    self._send_json(403, {"error": "Only the configured administrator can list users."})
                    return
                self._send_json(200, {"users": list_users(db_path)})
            elif route == "/projects":
                self._send_json(
                    200,
                    {
                        "projects": list_projects(db_path, username=username_filter),
                        "is_admin": bool(self._principal.get("is_admin")),
                    },
                )
            elif route == "/history":
                query = parse_qs(parsed.query)
                project = query.get("project", [None])[0]
                limit = int(query.get("limit", ["50"])[0])
                scans = list_scans(
                    db_path,
                    project_name=project,
                    username=username_filter,
                    limit=limit,
                )
                self._send_json(200, {"scans": scans})
            elif route == "/usage":
                self._send_json(200, usage_summary(db_path, username=username_filter))
            elif route.startswith("/history/"):
                try:
                    scan_id = int(route.removeprefix("/history/"))
                except ValueError:
                    self._send_json(400, {"error": "Scan ID must be an integer."})
                    return
                scan = get_scan(db_path, scan_id, username=username_filter)
                if scan is None:
                    self._send_json(404, {"error": "Scan not found."})
                else:
                    self._send_json(200, scan)
            else:
                project_name = unquote(member_route[1])
                if not self._can_manage_project(db_path, project_name):
                    self._send_json(403, {"error": "Project administrator role required."})
                    return
                self._send_json(
                    200, {"members": list_project_members(db_path, project_name)}
                )
        except (OSError, sqlite3.Error, ValueError, TypeError):
            self._send_json(400, {"error": "Could not query local project data."})

    def do_POST(self) -> None:
        route = urlsplit(self.path).path
        parts = route.strip("/").split("/")
        is_member_route = (
            len(parts) == 3 and parts[0] == "projects" and parts[2] == "members"
        )
        if route not in {"/scan", "/projects", "/users"} and not is_member_route:
            self._send_json(404, {"error": "Not found."})
            return
        if not self._authorize(route):
            return
        if self.headers.get_content_type() != "application/json":
            self._send_json(415, {"error": "Content-Type must be application/json."})
            return
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self._send_json(400, {"error": "A valid Content-Length header is required."})
            return
        if length < 0:
            self._send_json(400, {"error": "Content-Length must be non-negative."})
            return
        if length > _MAX_REQUEST_BYTES:
            self._send_json(413, {"error": "Request body exceeds the size limit."})
            return

        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            database = os.getenv("APPSEC_DB_PATH")
            db_path = Path(database).expanduser() if database else None

            if route == "/users":
                if not self._principal.get("shared_admin"):
                    self._send_json(403, {"error": "Only the configured administrator can create users."})
                    return
                if db_path is None:
                    self._send_json(503, {"error": "Set APPSEC_DB_PATH to enable local users."})
                    return
                if not isinstance(payload, dict) or "username" not in payload:
                    self._send_json(400, {"error": "Request JSON must contain a username."})
                    return
                user_token = secrets.token_urlsafe(32)
                try:
                    user = create_user(db_path, payload["username"], user_token)
                except sqlite3.IntegrityError:
                    self._send_json(409, {"error": "A user with that username already exists."})
                    return
                self._send_json(201, {"user": user, "token": user_token})
                return

            if route == "/projects":
                if db_path is None:
                    self._send_json(503, {"error": "Set APPSEC_DB_PATH to enable local projects."})
                    return
                if not isinstance(payload, dict) or "name" not in payload:
                    self._send_json(400, {"error": "Request JSON must contain a project name."})
                    return
                owner = self._principal.get("username")
                try:
                    project = create_project(
                        db_path,
                        payload["name"],
                        owner_username=owner if isinstance(owner, str) else None,
                    )
                except sqlite3.IntegrityError:
                    self._send_json(409, {"error": "A project with that name already exists."})
                    return
                self._send_json(201, {"project": project})
                return

            if is_member_route:
                if db_path is None:
                    self._send_json(503, {"error": "Set APPSEC_DB_PATH to enable project teams."})
                    return
                project_name = unquote(parts[1])
                if not self._can_manage_project(db_path, project_name):
                    self._send_json(403, {"error": "Project administrator role required."})
                    return
                if not isinstance(payload, dict) or "username" not in payload:
                    self._send_json(400, {"error": "Request JSON must contain a username."})
                    return
                member = add_project_member(
                    db_path,
                    project_name,
                    payload["username"],
                    payload.get("role", "viewer"),
                )
                self._send_json(201, {"member": member})
                return

            files = _validate_files(payload)
            result = scan_files(files)
            if db_path is not None:
                project_name = (
                    payload.get("project", "default")
                    if isinstance(payload, dict)
                    else "default"
                )
                username = self._principal.get("username")
                if isinstance(username, str):
                    role = project_role(db_path, project_name, username)
                    if role not in {"admin", "editor"}:
                        self._send_json(
                            403,
                            {"error": "Project editor or administrator membership is required to scan."},
                        )
                        return
                scan_id = save_scan(
                    db_path,
                    project_name,
                    result,
                    sum(len(value.encode("utf-8")) for value in files.values()),
                )
                result["scan_id"] = scan_id
                result["project"] = project_name
            elif isinstance(payload, dict) and "project" in payload:
                self._send_json(
                    503, {"error": "Set APPSEC_DB_PATH to save scans under a project."}
                )
                return
            self._send_json(200, result)
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            self._send_json(400, {"error": str(exc)})
        except (OSError, sqlite3.Error):
            self._send_json(500, {"error": "Local project or scan persistence failed."})

    def do_DELETE(self) -> None:
        route = urlsplit(self.path).path
        parts = route.strip("/").split("/")
        if not self._authorize(route):
            return
        database = os.getenv("APPSEC_DB_PATH")
        if not database:
            self._send_json(503, {"error": "Set APPSEC_DB_PATH to enable local team management."})
            return
        db_path = Path(database).expanduser()

        if len(parts) == 2 and parts[0] == "users":
            if not self._principal.get("shared_admin"):
                self._send_json(403, {"error": "Only the configured administrator can delete users."})
                return
            username = unquote(parts[1])
            try:
                removed = delete_user(db_path, username)
            except ValueError as exc:
                self._send_json(409, {"error": str(exc)})
                return
            except (OSError, sqlite3.Error):
                self._send_json(500, {"error": "Could not revoke user access."})
                return
            if not removed:
                self._send_json(404, {"error": "User not found."})
                return
            self._send_json(200, {"removed": True, "username": username})
            return

        if not (
            len(parts) == 4
            and parts[0] == "projects"
            and parts[2] == "members"
        ):
            self._send_json(404, {"error": "Not found."})
            return
        project_name = unquote(parts[1])
        username = unquote(parts[3])
        if not self._can_manage_project(db_path, project_name):
            self._send_json(403, {"error": "Project administrator role required."})
            return
        try:
            removed = remove_project_member(db_path, project_name, username)
        except ValueError as exc:
            self._send_json(409, {"error": str(exc)})
            return
        except (OSError, sqlite3.Error):
            self._send_json(500, {"error": "Could not update project membership."})
            return
        if not removed:
            self._send_json(404, {"error": "Project member not found."})
            return
        self._send_json(200, {"removed": True, "project": project_name, "username": username})

    def log_message(self, format: str, *args: object) -> None:
        """Keep request logging concise and avoid reflecting request bodies."""


def create_server(host: str = "127.0.0.1", port: int = 8765) -> ThreadingHTTPServer:
    """Create the unauthenticated local API server, refusing non-loopback binds."""
    token = os.getenv("APPSEC_API_TOKEN")
    if token is not None and (len(token) < 32 or not token.isascii()):
        raise ValueError("APPSEC_API_TOKEN must be at least 32 ASCII characters long.")
    if host == "localhost":
        pass
    else:
        try:
            is_loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            is_loopback = False
        if not is_loopback:
            raise ValueError("The unauthenticated API may bind only to a loopback address.")
    return ThreadingHTTPServer((host, port), _Handler)


def main() -> None:
    """Run the local API server."""
    parser = argparse.ArgumentParser(description="Run the local AI AppSec JSON API.")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: loopback only).")
    parser.add_argument("--port", type=int, default=8765, help="TCP port (default: 8765).")
    args = parser.parse_args()
    server = create_server(args.host, args.port)
    print(f"AI AppSec API listening on http://{args.host}:{server.server_port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
