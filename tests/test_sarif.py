import json
from pathlib import Path

from appsec.models import Finding, ScanResult, Severity
from appsec.sarif import sarif_json, to_sarif
from appsec.scanners.secrets import SecretScanner


def _finding(
    *,
    rule_id: str = "PYSEC-001",
    severity: Severity = Severity.HIGH,
    path: str = "src/app.py",
    line: int = 12,
    column: int = 4,
    evidence: str = "eval(user_input)",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title="Dynamic code execution",
        severity=severity,
        message="Avoid evaluating untrusted input.",
        path=Path(path),
        line=line,
        column=column,
        cwe="CWE-95",
        owasp="A03:2021-Injection",
        evidence=evidence,
        confidence=0.98,
    )


def test_sarif_has_version_rules_locations_and_fingerprint() -> None:
    document = to_sarif(ScanResult(findings=[_finding()], files_scanned=3, rules_run=11))

    assert document["version"] == "2.1.0"
    run = document["runs"][0]
    assert run["tool"]["driver"]["name"] == "AI AppSec Platform"
    assert run["tool"]["driver"]["rules"][0]["id"] == "PYSEC-001"
    result = run["results"][0]
    assert result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/app.py"
    assert result["locations"][0]["physicalLocation"]["region"] == {
        "startLine": 12,
        "startColumn": 4,
    }
    fingerprints = result["partialFingerprints"]
    assert len(fingerprints["primaryLocationLineHash"]) == 64
    assert len(fingerprints["stableFindingId"]) == 64
    assert run["properties"] == {"filesScanned": 3, "rulesRun": 11}


def test_sarif_maps_severity_and_does_not_export_source_evidence() -> None:
    findings = [
        _finding(rule_id="SEC-001", severity=Severity.CRITICAL, evidence="PRIVATE_KEY_SECRET"),
        _finding(rule_id="JSSEC-005", severity=Severity.MEDIUM, evidence="secret_value"),
        _finding(rule_id="CUSTOM-INFO", severity=Severity.INFO, evidence="sensitive snippet"),
    ]
    serialized = sarif_json(ScanResult(findings=findings))
    document = json.loads(serialized)
    results = {item["ruleId"]: item for item in document["runs"][0]["results"]}

    assert results["SEC-001"]["level"] == "error"
    assert results["JSSEC-005"]["level"] == "warning"
    assert results["CUSTOM-INFO"]["level"] == "note"
    assert "PRIVATE_KEY_SECRET" not in serialized
    assert "sensitive snippet" not in serialized


def test_sarif_redacts_actual_secret_scanner_evidence(tmp_path: Path) -> None:
    token = "ghp_" + "A" * 36
    (tmp_path / "settings.py").write_text(f'TOKEN = "{token}"\n', encoding="utf-8")

    findings = SecretScanner().scan(tmp_path)
    serialized = sarif_json(ScanResult(findings=findings))

    assert any(finding.rule_id == "SEC-003" for finding in findings)
    assert token not in serialized


def test_fingerprint_is_stable_when_unrelated_lines_shift() -> None:
    original = to_sarif(ScanResult(findings=[_finding(line=12)]))
    shifted = to_sarif(ScanResult(findings=[_finding(line=99)]))
    original_result = original["runs"][0]["results"][0]
    shifted_result = shifted["runs"][0]["results"][0]

    assert (
        original_result["partialFingerprints"]["primaryLocationLineHash"]
        == shifted_result["partialFingerprints"]["primaryLocationLineHash"]
    )
    assert (
        original_result["partialFingerprints"]["stableFindingId"]
        == shifted_result["partialFingerprints"]["stableFindingId"]
    )
    assert (
        original_result["locations"][0]["physicalLocation"]["region"]["startLine"]
        != shifted_result["locations"][0]["physicalLocation"]["region"]["startLine"]
    )


def test_fingerprint_changes_when_evidence_changes() -> None:
    original = to_sarif(ScanResult(findings=[_finding(evidence="eval(user_input)")]))
    changed = to_sarif(ScanResult(findings=[_finding(evidence="eval(trusted_value)")]))
    original_fingerprint = original["runs"][0]["results"][0]["partialFingerprints"]
    changed_fingerprint = changed["runs"][0]["results"][0]["partialFingerprints"]

    assert (
        original_fingerprint["primaryLocationLineHash"]
        != changed_fingerprint["primaryLocationLineHash"]
    )
    assert original_fingerprint["stableFindingId"] != changed_fingerprint["stableFindingId"]


def test_identical_findings_receive_distinct_stable_ids() -> None:
    findings = [_finding(line=12), _finding(line=24)]
    results = to_sarif(ScanResult(findings=findings))["runs"][0]["results"]
    fingerprints = [item["partialFingerprints"] for item in results]

    assert fingerprints[0]["primaryLocationLineHash"] == fingerprints[1]["primaryLocationLineHash"]
    assert fingerprints[0]["stableFindingId"] != fingerprints[1]["stableFindingId"]


def test_sarif_output_is_deterministic_and_deduplicates_rule_descriptors() -> None:
    first = _finding(rule_id="PYSEC-001", path="z.py", line=9)
    second = _finding(rule_id="PYSEC-001", path="a.py", line=2)
    result = ScanResult(findings=[first, second])

    document = to_sarif(result)
    assert len(document["runs"][0]["tool"]["driver"]["rules"]) == 1
    assert [
        item["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for item in document["runs"][0]["results"]
    ] == ["a.py", "z.py"]
    assert sarif_json(result) == sarif_json(ScanResult(findings=[second, first]))
