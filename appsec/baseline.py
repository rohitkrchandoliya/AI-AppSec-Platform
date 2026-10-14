"""Versioned, deterministic finding baselines for suppressing known findings."""

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from appsec.models import Finding

_SCHEMA_VERSION = 1
_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")


def finding_fingerprint(finding: Finding) -> str:
    """Identify a finding across line shifts without including line numbers."""
    identity = {
        "rule_id": finding.rule_id,
        "path": finding.path.as_posix(),
        "title": finding.title,
        "evidence": finding.evidence or finding.message,
    }
    canonical = json.dumps(identity, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def write_baseline(path: Path, findings: list[Finding]) -> None:
    """Write a deterministic baseline without raw evidence or source snippets."""
    records = [
        {
            "fingerprint": finding_fingerprint(finding),
            "rule_id": finding.rule_id,
            "path": finding.path.as_posix(),
            "title": finding.title,
            "severity": finding.severity.value,
        }
        for finding in findings
    ]
    records.sort(key=lambda item: (item["path"], item["rule_id"], item["fingerprint"]))
    payload = {"schema_version": _SCHEMA_VERSION, "findings": records}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def load_baseline(path: Path) -> set[str]:
    """Load and validate baseline fingerprints; reject unknown schema or malformed records."""
    try:
        payload: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read finding baseline: {exc}") from exc

    if not isinstance(payload, dict) or payload.get("schema_version") != _SCHEMA_VERSION:
        raise ValueError(f"Unsupported finding baseline schema; expected version {_SCHEMA_VERSION}.")
    records = payload.get("findings")
    if not isinstance(records, list):
        raise ValueError("Finding baseline must contain a 'findings' list.")

    fingerprints: set[str] = set()
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise ValueError(f"Baseline finding at index {index} must be an object.")
        fingerprint = record.get("fingerprint")
        if not isinstance(fingerprint, str) or not _FINGERPRINT_RE.fullmatch(fingerprint):
            raise ValueError(f"Baseline finding at index {index} has an invalid fingerprint.")
        fingerprints.add(fingerprint)
    return fingerprints


def apply_baseline(
    findings: list[Finding], fingerprints: set[str]
) -> tuple[list[Finding], int]:
    """Return findings not present in the baseline and the number suppressed."""
    active: list[Finding] = []
    suppressed = 0
    for finding in findings:
        if finding_fingerprint(finding) in fingerprints:
            suppressed += 1
        else:
            active.append(finding)
    return active, suppressed
