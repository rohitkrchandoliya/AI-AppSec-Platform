"""Local-only JSON API for scanning submitted source files."""

import argparse
import ipaddress
import json
import os
import sqlite3
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import parse_qs, urlsplit

from appsec.findings import normalize_findings
from appsec.history import (
    create_project,
    get_scan,
    list_projects,
    list_scans,
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
    """Small JSON handler with no filesystem-path input or write endpoint."""

    server_version = "AIAppSecLocalAPI/0.1"

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

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
        if route in {"/", "/assets/dashboard.css", "/assets/dashboard.js"}:
            self._send_asset(route)
            return
        if route == "/health":
            self._send_json(200, {"status": "ok", "service": "ai-appsec-platform"})
            return
        database = os.getenv("APPSEC_DB_PATH")
        if route in {"/projects", "/history", "/usage"} or route.startswith("/history/"):
            if not database:
                self._send_json(503, {"error": "Set APPSEC_DB_PATH to enable local history."})
                return
            db_path = Path(database).expanduser()
            try:
                if route == "/projects":
                    self._send_json(200, {"projects": list_projects(db_path)})
                elif route == "/history":
                    query = parse_qs(parsed.query)
                    project = query.get("project", [None])[0]
                    limit = int(query.get("limit", ["50"])[0])
                    scans = list_scans(db_path, project_name=project, limit=limit)
                    self._send_json(200, {"scans": scans})
                elif route == "/usage":
                    self._send_json(200, usage_summary(db_path))
                else:
                    try:
                        scan_id = int(route.removeprefix("/history/"))
                    except ValueError:
                        self._send_json(400, {"error": "Scan ID must be an integer."})
                        return
                    scan = get_scan(db_path, scan_id)
                    if scan is None:
                        self._send_json(404, {"error": "Scan not found."})
                    else:
                        self._send_json(200, scan)
            except (OSError, sqlite3.Error, ValueError, TypeError):
                self._send_json(400, {"error": "Could not query local scan history."})
            return
        self._send_json(404, {"error": "Not found."})

    def do_POST(self) -> None:
        route = urlsplit(self.path).path
        if route not in {"/scan", "/projects"}:
            self._send_json(404, {"error": "Not found."})
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
            if route == "/projects":
                database = os.getenv("APPSEC_DB_PATH")
                if not database:
                    self._send_json(
                        503, {"error": "Set APPSEC_DB_PATH to enable local projects."}
                    )
                    return
                if not isinstance(payload, dict) or "name" not in payload:
                    self._send_json(400, {"error": "Request JSON must contain a project name."})
                    return
                try:
                    project = create_project(Path(database).expanduser(), payload["name"])
                except sqlite3.IntegrityError:
                    self._send_json(409, {"error": "A project with that name already exists."})
                    return
                self._send_json(201, {"project": project})
                return
            files = _validate_files(payload)
            result = scan_files(files)
            database = os.getenv("APPSEC_DB_PATH")
            if database:
                project_name = (
                    payload.get("project", "default")
                    if isinstance(payload, dict)
                    else "default"
                )
                scan_id = save_scan(
                    Path(database).expanduser(),
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
            self._send_json(500, {"error": "Local scan persistence failed."})

    def log_message(self, format: str, *args: object) -> None:
        """Keep request logging concise and avoid reflecting request bodies."""


def create_server(host: str = "127.0.0.1", port: int = 8765) -> ThreadingHTTPServer:
    """Create the unauthenticated local API server, refusing non-loopback binds."""
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
