"""Translate SARIF results into safe GitHub Actions workflow annotations."""

import json
import os
import sys
from pathlib import Path, PurePosixPath
from typing import Any


def _escape_data(value: str) -> str:
    """Escape workflow-command message data."""
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_property(value: str) -> str:
    """Escape workflow-command annotation properties."""
    return (
        value.replace("%", "%25")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
        .replace(":", "%3A")
        .replace(",", "%2C")
    )


def emit_annotations(document: dict[str, Any], path_prefix: str = "") -> int:
    """Emit one workflow annotation per SARIF result and return the result count."""
    prefix = path_prefix.strip("/")
    prefix_path = PurePosixPath(prefix)
    if prefix and (
        prefix_path.is_absolute()
        or ".." in prefix_path.parts
        or "\\" in prefix
        or "\n" in prefix
        or "\r" in prefix
    ):
        raise ValueError("Annotation path prefix must be a safe relative path.")

    runs = document.get("runs")
    if not isinstance(runs, list):
        raise TypeError("SARIF document must contain a runs list.")

    count = 0
    for run in runs:
        if not isinstance(run, dict) or not isinstance(run.get("results", []), list):
            raise TypeError("Each SARIF run must contain a results list.")
        for result in run.get("results", []):
            if not isinstance(result, dict):
                continue
            level = result.get("level", "warning")
            command = (
                "error" if level == "error" else "warning" if level == "warning" else "notice"
            )
            message_obj = result.get("message", {})
            message = (
                message_obj.get("text", "Security finding")
                if isinstance(message_obj, dict)
                else "Security finding"
            )
            rule_id = str(result.get("ruleId", "APPSEC"))
            locations = result.get("locations", [])
            properties = ""
            if locations and isinstance(locations[0], dict):
                physical = locations[0].get("physicalLocation", {})
                if isinstance(physical, dict):
                    artifact = physical.get("artifactLocation", {})
                    region = physical.get("region", {})
                    if isinstance(artifact, dict) and isinstance(artifact.get("uri"), str):
                        uri = artifact["uri"]
                        source_path = PurePosixPath(uri)
                        if (
                            uri
                            and not source_path.is_absolute()
                            and ".." not in source_path.parts
                            and "\\" not in uri
                            and "\n" not in uri
                            and "\r" not in uri
                        ):
                            annotation_path = f"{prefix}/{uri}" if prefix else uri
                            properties = f" file={_escape_property(annotation_path)}"
                    if isinstance(region, dict) and isinstance(region.get("startLine"), int):
                        properties += f",line={region['startLine']}"
            print(f"::{command}{properties}::{_escape_data(f'[{rule_id}] {message}')}")
            count += 1
    return count


def main() -> int:
    """Load a SARIF file and emit workflow annotations."""
    if len(sys.argv) != 2:
        print("Usage: python -m appsec.ci_report <sarif-file>", file=sys.stderr)
        return 2
    try:
        document = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
        if not isinstance(document, dict) or document.get("version") != "2.1.0":
            raise ValueError("Expected a SARIF 2.1.0 document.")
        prefix = os.getenv("APPSEC_ANNOTATION_PATH_PREFIX", "")
        count = emit_annotations(document, prefix)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        print(f"Could not emit SARIF annotations: {exc}", file=sys.stderr)
        return 2
    print(f"Emitted {count} AppSec workflow annotation(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
