"""Local-only JSON API for scanning submitted source files."""

import argparse
import json
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from typing import Any

from appsec.findings import normalize_findings
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
        raise ValueError("Request JSON must contain a 'files' object.")
    files = payload["files"]
    if not files or len(files) > _MAX_FILES:
        raise ValueError(f"'files' must contain between 1 and {_MAX_FILES} entries.")

    validated: dict[str, str] = {}
    total_bytes = 0
    for name, contents in files.items():
        if not isinstance(name, str) or not isinstance(contents, str):
            raise ValueError("File names and contents must be strings.")
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

    def do_GET(self) -> None:
        if self.path == "/health":
            self._send_json(200, {"status": "ok", "service": "ai-appsec-platform"})
            return
        self._send_json(404, {"error": "Not found."})

    def do_POST(self) -> None:
        if self.path != "/scan":
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
            files = _validate_files(payload)
            self._send_json(200, scan_files(files))
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            self._send_json(400, {"error": str(exc)})

    def log_message(self, format: str, *args: object) -> None:
        """Keep request logging concise and avoid reflecting request bodies."""


def create_server(host: str = "127.0.0.1", port: int = 8765) -> ThreadingHTTPServer:
    """Create the API server; default binding is loopback-only."""
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
