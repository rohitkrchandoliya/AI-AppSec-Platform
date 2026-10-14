import json

import pytest

from appsec.github_check import _annotation, build_check_payload


def sarif_result(index: int, level: str = "error", path: str = "src/app.py") -> dict:
    return {
        "ruleId": f"PYSEC-{index:03}",
        "level": level,
        "message": {"text": f"Finding {index}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": path},
                    "region": {"startLine": index + 1},
                }
            }
        ],
    }


def test_check_payload_fails_for_error_findings_and_maps_annotations() -> None:
    document = {
        "version": "2.1.0",
        "runs": [{"results": [sarif_result(0), sarif_result(1, "warning"), sarif_result(2, "note")]}],
    }
    payload = build_check_payload(document, "a" * 40)
    assert payload["conclusion"] == "failure"
    assert payload["head_sha"] == "a" * 40
    assert len(payload["output"]["annotations"]) == 3
    assert payload["output"]["annotations"][0]["annotation_level"] == "failure"
    assert payload["output"]["annotations"][1]["annotation_level"] == "warning"
    assert payload["output"]["annotations"][2]["annotation_level"] == "notice"


def test_check_payload_caps_annotations_and_reports_omitted_findings() -> None:
    document = {"version": "2.1.0", "runs": [{"results": [sarif_result(i) for i in range(60)]}]}
    payload = build_check_payload(document, "b" * 40)
    assert len(payload["output"]["annotations"]) == 50
    assert "10 additional located findings" in payload["output"]["summary"]


@pytest.mark.parametrize("path", ["../secret.py", "/etc/passwd", r"C:\\secret.py", "C:/secret.py", "bad\npath.py"])
def test_annotation_rejects_unsafe_paths(path: str) -> None:
    assert _annotation(sarif_result(0, path=path)) is None


def test_check_payload_rejects_invalid_sarif_structure() -> None:
    with pytest.raises(TypeError, match="runs list"):
        build_check_payload({"version": "2.1.0"}, "c" * 40)


def test_check_payload_rejects_invalid_commit_sha() -> None:
    with pytest.raises(ValueError, match="40-character"):
        build_check_payload({"version": "2.1.0", "runs": []}, "not-a-sha")


def test_create_check_run_uses_scoped_token_and_head_sha(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from appsec import github_check

    sarif_path = tmp_path / "results.sarif"
    sarif_path.write_text(
        json.dumps({"version": "2.1.0", "runs": [{"results": [sarif_result(0)]}]}),
        encoding="utf-8",
    )
    monkeypatch.setenv("APPSEC_GITHUB_TOKEN", "app-token")
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("APPSEC_HEAD_SHA", "d" * 40)
    captured: dict[str, object] = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self) -> bytes:
            return b'{"html_url":"https://github.com/owner/repo/runs/1"}'

    def fake_urlopen(request, timeout: float):
        captured["url"] = request.full_url
        captured["headers"] = request.headers
        captured["payload"] = json.loads(request.data.decode("utf-8"))
        captured["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr(github_check, "urlopen", fake_urlopen)
    result = github_check.create_check_run(sarif_path)

    assert result["html_url"].endswith("/runs/1")
    assert captured["url"] == "https://api.github.com/repos/owner/repo/check-runs"
    assert captured["payload"]["head_sha"] == "d" * 40
    assert captured["payload"]["conclusion"] == "failure"
    assert captured["headers"]["Authorization"] == "Bearer app-token"


def test_create_check_run_publishes_failure_when_sarif_is_missing(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from appsec import github_check

    monkeypatch.setenv("APPSEC_GITHUB_TOKEN", "app-token")
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("APPSEC_HEAD_SHA", "e" * 40)
    captured: dict[str, object] = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self) -> bytes:
            return b'{"id":123}'

    def fake_urlopen(request, timeout: float):
        captured["payload"] = json.loads(request.data.decode("utf-8"))
        return FakeResponse()

    monkeypatch.setattr(github_check, "urlopen", fake_urlopen)
    github_check.create_check_run(tmp_path / "missing.sarif")
    assert captured["payload"]["conclusion"] == "failure"
    assert "not produced" in captured["payload"]["output"]["summary"]


def test_create_check_run_publishes_failure_when_sarif_is_malformed(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from appsec import github_check

    bad_path = tmp_path / "malformed.sarif"
    bad_path.write_text("{ not json", encoding="utf-8")
    monkeypatch.setenv("APPSEC_GITHUB_TOKEN", "app-token")
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("APPSEC_HEAD_SHA", "f" * 40)
    captured: dict[str, object] = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self) -> bytes:
            return b'{"id":456}'

    def fake_urlopen(request, timeout: float):
        captured["payload"] = json.loads(request.data.decode("utf-8"))
        return FakeResponse()

    monkeypatch.setattr(github_check, "urlopen", fake_urlopen)
    github_check.create_check_run(bad_path)
    assert captured["payload"]["conclusion"] == "failure"
    assert "malformed" in captured["payload"]["output"]["summary"]
