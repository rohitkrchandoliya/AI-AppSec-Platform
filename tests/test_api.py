import json
import sqlite3
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from typing import Any

import pytest

from appsec.api import _Handler, scan_files
from appsec.history import (
    create_project,
    get_scan,
    list_projects,
    list_scans,
    save_scan,
    usage_summary,
)


def test_scan_files_returns_normalized_security_findings() -> None:
    result = scan_files({"src/unsafe.py": "eval(user_input)\n"})

    assert result["files_scanned"] == 1
    assert any(item["rule_id"] == "PYSEC-001" for item in result["findings"])
    assert result["findings"][0]["path"] == "src/unsafe.py"


@pytest.mark.parametrize(
    "name",
    ["../escape.py", "/absolute.py", "src\\escape.py", ".git/config", "bad\nname.py"],
)
def test_scan_files_rejects_unsafe_paths(name: str) -> None:
    with pytest.raises(ValueError, match="Unsafe relative file path"):
        scan_files({name: "print('safe')"})


def test_scan_files_enforces_file_count_and_size() -> None:
    with pytest.raises(ValueError, match="between 1 and"):
        scan_files({})
    with pytest.raises(ValueError, match="byte limit"):
        scan_files({"large.py": "x" * 128_001})


def _request(url: str, *, method: str = "GET", body: bytes | None = None,
             content_type: str = "application/json") -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={"Content-Type": content_type} if body is not None else {},
    )
    try:
        response = urllib.request.urlopen(request, timeout=3)
    except urllib.error.HTTPError as exc:
        response = exc
    with response:
        return response.status, json.loads(response.read().decode("utf-8"))


def test_api_health_and_scan_endpoints() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"
    try:
        status, health = _request(f"{base_url}/health")
        assert status == 200
        assert health["status"] == "ok"

        body = json.dumps({"files": {"unsafe.py": "eval(user_input)\n"}}).encode()
        status, result = _request(f"{base_url}/scan", method="POST", body=body)
        assert status == 200
        assert any(item["rule_id"] == "PYSEC-001" for item in result["findings"])

        status, error = _request(
            f"{base_url}/scan", method="POST", body=body, content_type="text/plain"
        )
        assert status == 415
        assert "Content-Type" in error["error"]

        status, error = _request(
            f"{base_url}/scan",
            method="POST",
            body=json.dumps({"files": {"../bad.py": "eval(x)"}}).encode(),
        )
        assert status == 400
        assert "Unsafe relative file path" in error["error"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_dashboard_assets_are_served_with_security_headers() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"
    try:
        with urllib.request.urlopen(base_url + "/", timeout=3) as response:
            html = response.read().decode("utf-8")
            assert response.status == 200
            assert response.headers["Content-Security-Policy"].startswith("default-src 'self'")
            assert response.headers["X-Frame-Options"] == "DENY"
            assert "Source security dashboard" in html
            assert "/assets/dashboard.js" in html

        with urllib.request.urlopen(base_url + "/assets/dashboard.js", timeout=3) as response:
            javascript = response.read().decode("utf-8")
            assert response.status == 200
            assert "textContent" in javascript
            assert "innerHTML" not in javascript

        with urllib.request.urlopen(base_url + "/assets/dashboard.css", timeout=3) as response:
            assert response.status == 200
            assert "Content-Type" in response.headers
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_local_history_storage_tracks_projects_scans_and_usage(tmp_path) -> None:
    database = tmp_path / "state" / "appsec.sqlite3"
    project = create_project(database, "demo-project")
    assert project["name"] == "demo-project"
    with pytest.raises(sqlite3.IntegrityError):
        create_project(database, "DEMO-PROJECT")

    result = scan_files({"src/unsafe.py": "eval(user_input)\n"})
    scan_id = save_scan(database, "demo-project", result, source_bytes=18)
    assert scan_id > 0
    assert list_projects(database)[0]["scan_count"] == 1
    assert list_scans(database, project_name="demo-project")[0]["id"] == scan_id
    saved = get_scan(database, scan_id)
    assert saved is not None
    assert saved["result"]["files_scanned"] == 1
    usage = usage_summary(database)
    assert usage["scans"] == 1
    assert usage["files_scanned"] == 1
    assert usage["source_bytes"] == 18


def test_api_persists_project_history_only_when_configured(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("APPSEC_DB_PATH", str(tmp_path / "appsec.sqlite3"))
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"
    try:
        status, created = _request(
            base_url + "/projects", method="POST", body=json.dumps({"name": "demo"}).encode()
        )
        assert status == 201
        assert created["project"]["name"] == "demo"

        status, conflict = _request(
            base_url + "/projects", method="POST", body=json.dumps({"name": "DEMO"}).encode()
        )
        assert status == 409
        assert "already exists" in conflict["error"]

        body = json.dumps(
            {"project": "demo", "files": {"unsafe.py": "eval(user_input)\n"}}
        ).encode()
        status, scan = _request(base_url + "/scan", method="POST", body=body)
        assert status == 200
        assert scan["project"] == "demo"
        scan_id = scan["scan_id"]

        status, history = _request(base_url + "/history?project=demo")
        assert status == 200
        assert history["scans"][0]["id"] == scan_id

        status, detail = _request(base_url + f"/history/{scan_id}")
        assert status == 200
        assert detail["result"]["files_scanned"] == 1

        status, projects = _request(base_url + "/projects")
        assert status == 200
        assert projects["projects"][0]["scan_count"] == 1

        status, usage = _request(base_url + "/usage")
        assert status == 200
        assert usage["scans"] == 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_history_endpoint_is_disabled_without_database(monkeypatch) -> None:
    monkeypatch.delenv("APPSEC_DB_PATH", raising=False)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, error = _request(f"http://127.0.0.1:{server.server_port}/history")
        assert status == 503
        assert "APPSEC_DB_PATH" in error["error"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)



def test_api_refuses_non_loopback_binding() -> None:
    from appsec.api import create_server

    with pytest.raises(ValueError, match="loopback"):
        create_server("0.0.0.0", 8765)
