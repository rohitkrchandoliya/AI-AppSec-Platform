import json
from pathlib import Path

import pytest

from appsec.baseline import apply_baseline, finding_fingerprint, load_baseline, write_baseline
from appsec.models import Finding, Severity


def make_finding(*, line: int = 1, path: str = "src/app.py", evidence: str = "eval(user)") -> Finding:
    return Finding(
        rule_id="PYSEC-001",
        title="Dynamic code execution",
        severity=Severity.HIGH,
        message="Avoid evaluating untrusted input.",
        path=Path(path),
        line=line,
        evidence=evidence,
    )


def test_fingerprint_is_stable_when_line_number_changes() -> None:
    assert finding_fingerprint(make_finding(line=1)) == finding_fingerprint(make_finding(line=99))


def test_fingerprint_changes_when_path_or_evidence_changes() -> None:
    original = finding_fingerprint(make_finding())
    assert original != finding_fingerprint(make_finding(path="src/other.py"))
    assert original != finding_fingerprint(make_finding(evidence="eval(other_input)"))


def test_baseline_round_trip_is_deterministic_and_excludes_evidence(tmp_path: Path) -> None:
    path = tmp_path / "security-baseline.json"
    finding = make_finding(evidence="SENSITIVE_SOURCE_SNIPPET")
    write_baseline(path, [finding])

    first = path.read_text(encoding="utf-8")
    write_baseline(path, [finding])
    assert path.read_text(encoding="utf-8") == first
    assert "SENSITIVE_SOURCE_SNIPPET" not in first
    payload = json.loads(first)
    assert payload["schema_version"] == 1
    assert load_baseline(path) == {finding_fingerprint(finding)}


def test_baseline_rejects_unknown_schema_and_invalid_fingerprint(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text('{"schema_version": 2, "findings": []}', encoding="utf-8")
    with pytest.raises(ValueError, match="Unsupported"):
        load_baseline(path)

    path.write_text(
        '{"schema_version": 1, "findings": [{"fingerprint": "not-a-hash"}]}',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="invalid fingerprint"):
        load_baseline(path)


def test_apply_baseline_suppresses_only_known_findings() -> None:
    known = make_finding()
    new = make_finding(path="src/new.py")
    active, suppressed = apply_baseline(
        [known, new],
        {finding_fingerprint(known)},
    )
    assert active == [new]
    assert suppressed == 1
