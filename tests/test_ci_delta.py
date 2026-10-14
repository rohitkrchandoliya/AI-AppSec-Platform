import pytest

from appsec.ci_delta import compare_sarif_documents


def result(fingerprint: str, level: str = "error") -> dict[str, object]:
    return {
        "ruleId": "PYSEC-001",
        "level": level,
        "message": {"text": "Synthetic test finding"},
        "partialFingerprints": {"stableFindingId": fingerprint},
    }


def document(*results: dict[str, object]) -> dict[str, object]:
    return {"version": "2.1.0", "runs": [{"results": list(results)}]}


def test_existing_findings_are_not_reported_as_new() -> None:
    existing = result("existing")
    added = result("new", "warning")
    delta, new_findings = compare_sarif_documents(
        document(existing), document(existing, added)
    )
    assert new_findings == [added]
    assert delta["runs"][0]["results"] == [added]


def test_new_high_finding_is_preserved_for_gate() -> None:
    added = result("new-high", "error")
    delta, new_findings = compare_sarif_documents(document(), document(added))
    assert new_findings == [added]
    assert delta["runs"][0]["results"] == [added]
    assert any(item.get("level") == "error" for item in new_findings)


def test_duplicate_findings_are_counted_as_a_multiset() -> None:
    existing = result("same")
    delta, new_findings = compare_sarif_documents(
        document(existing), document(existing, existing)
    )
    assert len(new_findings) == 1
    assert delta["runs"][0]["results"] == [existing]


def test_missing_stable_fingerprint_fails_closed() -> None:
    invalid = {"version": "2.1.0", "runs": [{"results": [{"level": "error"}]}]}
    with pytest.raises(ValueError, match="stable fingerprint"):
        compare_sarif_documents(document(), invalid)


def test_invalid_sarif_version_fails_closed() -> None:
    with pytest.raises(ValueError, match="SARIF 2.1.0"):
        compare_sarif_documents(
            {"version": "1.0", "runs": []},
            document(),
        )
