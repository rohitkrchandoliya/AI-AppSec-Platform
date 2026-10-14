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
    document = {"version": "2.1.0", "runs": [{"results": [
        sarif_result(0, "error"),
        sarif_result(1, "warning"),
        sarif_result(2, "note"),
    ]}]}

    payload = build_check_payload(document, "a" * 40)

    assert payload["conclusion"] == "failure"
    assert payload["head_sha"] == "a" * 40
    assert len(payload["output"]["annotations"]) == 3
    assert payload["output"]["annotations"][0]["annotation_level"] == "failure"
    assert payload["output"]["annotations"][1]["annotation_level"] == "warning"
    assert payload["output"]["annotations"][2]["annotation_level"] == "notice"


def test_check_payload_caps_annotations_at_github_limit() -> None:
    document = {"version": "2.1.0", "runs": [{"results": [sarif_result(i) for i in range(60)]}]}

    payload = build_check_payload(document, "b" * 40)

    assert len(payload["output"]["annotations"]) == 50
    assert "10 additional results" in payload["output"]["summary"]


def test_annotation_rejects_path_traversal() -> None:
    assert _annotation(sarif_result(0, path="../secret.py")) is None


def test_check_payload_rejects_invalid_sarif_structure() -> None:
    with pytest.raises(TypeError, match="runs list"):
        build_check_payload({}, "c" * 40)



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
