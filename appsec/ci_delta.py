"""Compare SARIF reports and identify findings newly introduced by a change."""

from __future__ import annotations

import collections
import json
import os
import sys
from pathlib import Path
from typing import Any


def _validate_document(document: Any, label: str) -> dict[str, Any]:
    """Validate the minimum SARIF structure needed for a fail-closed comparison."""
    if not isinstance(document, dict) or document.get("version") != "2.1.0":
        raise ValueError(f"{label} is not a valid SARIF 2.1.0 document.")
    runs = document.get("runs")
    if not isinstance(runs, list):
        raise ValueError(f"{label} must contain a runs list.")
    for run in runs:
        if not isinstance(run, dict) or not isinstance(run.get("results", []), list):
            raise ValueError(f"{label} contains an invalid SARIF run.")
        for result in run.get("results", []):
            if not isinstance(result, dict):
                raise ValueError(f"{label} contains an invalid SARIF result.")
            fingerprint = (result.get("partialFingerprints") or {}).get("stableFindingId")
            if not isinstance(fingerprint, str) or not fingerprint:
                raise ValueError(f"{label} contains a finding without a stable fingerprint.")
    return document


def compare_sarif_documents(
    base_document: dict[str, Any], head_document: dict[str, Any]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Return a head SARIF document containing only findings absent from the base."""
    base = _validate_document(base_document, "Base report")
    head = _validate_document(head_document, "Pull request report")

    baseline_counts: collections.Counter[str] = collections.Counter()
    for run in base["runs"]:
        for result in run.get("results", []):
            fingerprint = result["partialFingerprints"]["stableFindingId"]
            baseline_counts[fingerprint] += 1

    remaining = baseline_counts.copy()
    new_results: list[dict[str, Any]] = []
    new_counts: collections.Counter[str] = collections.Counter()
    for run in head["runs"]:
        for result in run.get("results", []):
            fingerprint = result["partialFingerprints"]["stableFindingId"]
            if remaining[fingerprint] > 0:
                remaining[fingerprint] -= 1
            else:
                new_results.append(result)
                new_counts[fingerprint] += 1

    delta = dict(head)
    delta["runs"] = []
    for run in head["runs"]:
        copied_run = dict(run)
        copied_results: list[dict[str, Any]] = []
        for result in run.get("results", []):
            fingerprint = result["partialFingerprints"]["stableFindingId"]
            if new_counts[fingerprint] > 0:
                copied_results.append(result)
                new_counts[fingerprint] -= 1
        copied_run["results"] = copied_results
        delta["runs"].append(copied_run)
    return delta, new_results


def _read_report(path: Path) -> dict[str, Any]:
    """Read a SARIF JSON file."""
    return _validate_document(json.loads(path.read_text(encoding="utf-8")), path.name)


def main() -> int:
    """Write a SARIF delta and fail on newly introduced high/critical findings."""
    if len(sys.argv) != 4:
        print(
            "Usage: python -m appsec.ci_delta BASE.sarif HEAD.sarif OUTPUT.sarif",
            file=sys.stderr,
        )
        return 2

    base_path, head_path, output_path = map(Path, sys.argv[1:])
    try:
        if os.environ.get("BASE_SCAN_OUTCOME") != "success":
            raise RuntimeError("Base revision scan did not complete successfully.")
        if os.environ.get("HEAD_SCAN_OUTCOME") != "success":
            raise RuntimeError("Pull request revision scan did not complete successfully.")
        delta, new_findings = compare_sarif_documents(
            _read_report(base_path), _read_report(head_path)
        )
        output_path.write_text(json.dumps(delta, indent=2) + "\n", encoding="utf-8")
        blocking = [finding for finding in new_findings if finding.get("level") == "error"]
        print(
            f"New findings: {len(new_findings)}; "
            f"new high/critical findings: {len(blocking)}"
        )
        return 1 if blocking else 0
    except Exception as exc:
        # Preserve a valid failure report so the trusted workflow can publish a failed check.
        failure_report = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{"results": []}],
        }
        try:
            output_path.write_text(
                json.dumps(failure_report, indent=2) + "\n", encoding="utf-8"
            )
        except OSError:
            pass
        print(f"Finding comparison failed closed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
