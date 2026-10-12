"""SARIF 2.1.0 serialization for normalized scanner findings."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from appsec.models import Finding, ScanResult, Severity

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_SEVERITY_LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _line_hash(finding: Finding) -> str:
    """Hash available line evidence without placing source text in the report."""
    line_content = finding.evidence if finding.evidence is not None else finding.title
    return hashlib.sha256(line_content.encode("utf-8")).hexdigest()


def _fingerprint_identity(finding: Finding) -> tuple[str, ...]:
    """Return location-shift-independent identity fields for one finding."""
    return (
        finding.rule_id,
        finding.path.as_posix(),
        finding.title,
        finding.message,
        _line_hash(finding),
    )


def _fingerprint(finding: Finding, occurrence: int = 0) -> str:
    """Build a deterministic fingerprint that survives unrelated line insertions."""
    identity = json.dumps(
        [*_fingerprint_identity(finding), occurrence],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _rule_descriptor(finding: Finding) -> dict[str, Any]:
    properties: dict[str, str] = {}
    if finding.cwe:
        properties["cwe"] = finding.cwe
    if finding.owasp:
        properties["owasp"] = finding.owasp
    return {
        "id": finding.rule_id,
        "name": finding.title,
        "shortDescription": {"text": finding.title},
        "defaultConfiguration": {"level": _SEVERITY_LEVELS[finding.severity]},
        "properties": properties,
    }


def finding_to_sarif_result(finding: Finding, occurrence: int = 0) -> dict[str, Any]:
    """Convert one finding to SARIF without exporting source evidence."""
    location: dict[str, Any] = {
        "physicalLocation": {
            "artifactLocation": {"uri": Path(finding.path).as_posix()},
            "region": {
                "startLine": finding.line,
                "startColumn": finding.column or 1,
            },
        }
    }
    properties: dict[str, str | float] = {"confidence": finding.confidence}
    if finding.cwe:
        properties["cwe"] = finding.cwe
    if finding.owasp:
        properties["owasp"] = finding.owasp

    return {
        "ruleId": finding.rule_id,
        "level": _SEVERITY_LEVELS[finding.severity],
        "message": {"text": f"{finding.title}: {finding.message}"},
        "locations": [location],
        "partialFingerprints": {
            "primaryLocationLineHash": _line_hash(finding),
            "stableFindingId": _fingerprint(finding, occurrence),
        },
        "properties": properties,
    }


def to_sarif(result: ScanResult) -> dict[str, Any]:
    """Convert a scan result into a deterministic SARIF 2.1.0 document."""
    findings = sorted(
        result.findings,
        key=lambda item: (
            item.path.as_posix(),
            item.line,
            item.column or 0,
            item.rule_id,
        ),
    )
    rules_by_id: dict[str, dict[str, Any]] = {}
    fingerprint_occurrences: dict[tuple[str, ...], int] = {}
    sarif_results: list[dict[str, Any]] = []

    for finding in findings:
        rules_by_id.setdefault(finding.rule_id, _rule_descriptor(finding))
        identity = _fingerprint_identity(finding)
        occurrence = fingerprint_occurrences.get(identity, 0)
        fingerprint_occurrences[identity] = occurrence + 1
        sarif_results.append(finding_to_sarif_result(finding, occurrence))

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "AI AppSec Platform",
                "informationUri": "https://github.com/rohitkrchandoliya/ai-appsec-platform",
                "rules": [rules_by_id[key] for key in sorted(rules_by_id)],
            }
        },
        "results": sarif_results,
        "properties": {
            "filesScanned": result.files_scanned,
            "rulesRun": result.rules_run,
        },
    }
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [run],
    }


def sarif_json(result: ScanResult) -> str:
    """Serialize scan results to stable, pretty-printed SARIF JSON."""
    return json.dumps(to_sarif(result), indent=2, sort_keys=True)
