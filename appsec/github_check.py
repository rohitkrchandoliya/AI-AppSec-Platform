"""Create a GitHub App check run from a SARIF report."""

import json
import os
import sys
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

_CHECK_NAME = "AI AppSec Security Gate"
_MAX_ANNOTATIONS = 50


def _annotation(result: dict[str, Any]) -> dict[str, Any] | None:
    locations = result.get("locations", [])
    if not isinstance(locations, list) or not locations or not isinstance(locations[0], dict):
        return None
    physical = locations[0].get("physicalLocation", {})
    if not isinstance(physical, dict):
        return None
    artifact = physical.get("artifactLocation", {})
    region = physical.get("region", {})
    if not isinstance(artifact, dict) or not isinstance(region, dict):
        return None
    path = artifact.get("uri")
    line = region.get("startLine")
    if not isinstance(path, str) or not isinstance(line, int) or line < 1:
        return None
    normalized = PurePosixPath(path)
    if (
        normalized.is_absolute()
        or ".." in normalized.parts
        or "\\" in path
        or "\n" in path
        or "\r" in path
    ):
        return None
    level = result.get("level", "warning")
    annotation_level = "failure" if level == "error" else "warning" if level == "warning" else "notice"
    message_obj = result.get("message", {})
    message = message_obj.get("text", "Security finding") if isinstance(message_obj, dict) else "Security finding"
    rule_id = str(result.get("ruleId", "APPSEC"))
    return {
        "path": path,
        "start_line": line,
        "end_line": line,
        "annotation_level": annotation_level,
        "message": f"[{rule_id}] {message}"[:60000],
    }


def build_check_payload(document: dict[str, Any], head_sha: str) -> dict[str, Any]:
    """Build a bounded check-run payload from a SARIF report."""
    runs = document.get("runs")
    if not isinstance(runs, list):
        raise ValueError("SARIF document must contain a runs list.")
    results: list[dict[str, Any]] = []
    for run in runs:
        if not isinstance(run, dict) or not isinstance(run.get("results", []), list):
            raise ValueError("Each SARIF run must contain a results list.")
        results.extend(item for item in run.get("results", []) if isinstance(item, dict))

    failures = sum(1 for result in results if result.get("level") == "error")
    warnings = sum(1 for result in results if result.get("level") == "warning")
    notices = sum(1 for result in results if result.get("level") not in {"error", "warning"})
    annotations = [
        annotation
        for result in results
        if (annotation := _annotation(result)) is not None
    ][: _MAX_ANNOTATIONS]
    omitted = max(0, len(results) - len(annotations))
    conclusion = "failure" if failures else "success"
    summary = (
        f"Scanned source with AI AppSec. Findings: {len(results)} total "
        f"({failures} high/critical error-level, {warnings} warning-level, {notices} note-level). "
        f"Annotations attached: {len(annotations)}."
    )
    if omitted:
        summary += f" {omitted} additional results are not inline because GitHub accepts at most 50 annotations per request."
    return {
        "name": _CHECK_NAME,
        "head_sha": head_sha,
        "status": "completed",
        "conclusion": conclusion,
        "output": {
            "title": "AI AppSec scan failed" if failures else "AI AppSec scan passed",
            "summary": summary,
            "annotations": annotations,
        },
    }


def create_check_run(sarif_path: Path) -> dict[str, Any]:
    """Send a check-run payload to the GitHub Checks API using a scoped App token."""
    token = os.getenv("APPSEC_GITHUB_TOKEN")
    repository = os.getenv("GITHUB_REPOSITORY")
    head_sha = os.getenv("APPSEC_HEAD_SHA")
    if not token or not repository or not head_sha:
        raise ValueError("APPSEC_GITHUB_TOKEN, GITHUB_REPOSITORY, and APPSEC_HEAD_SHA are required.")
    document = json.loads(sarif_path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or document.get("version") != "2.1.0":
        raise ValueError("Expected a SARIF 2.1.0 document.")
    payload = build_check_payload(document, head_sha)
    request = Request(
        f"https://api.github.com/repos/{repository}/check-runs",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=20) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        raise RuntimeError(f"GitHub Checks API returned HTTP {exc.code}.") from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise RuntimeError("Could not reach the GitHub Checks API.") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("GitHub Checks API returned invalid JSON.") from exc


def main() -> int:
    """Create a GitHub check run for a SARIF report."""
    if len(sys.argv) != 2:
        print("Usage: python -m appsec.github_check <sarif-file>", file=sys.stderr)
        return 2
    try:
        result = create_check_run(Path(sys.argv[1]))
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"Could not create AI AppSec check run: {exc}", file=sys.stderr)
        return 1
    print(f"Created AI AppSec check run {result.get('html_url', '')}".strip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
