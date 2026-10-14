import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from typing import Any

import pytest

from appsec.api import _Handler, scan_files


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
