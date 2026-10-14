import pytest

from appsec.ci_report import emit_annotations


def test_emit_annotations_maps_levels_and_escapes_workflow_commands(capsys) -> None:
    document = {
        "runs": [
            {
                "results": [
                    {
                        "ruleId": "PYSEC-001",
                        "level": "error",
                        "message": {"text": "bad % value\nsecond line"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/a,b.py"},
                                    "region": {"startLine": 7},
                                }
                            }
                        ],
                    },
                    {"ruleId": "NOTE-1", "level": "note", "message": {"text": "Info"}},
                ]
            }
        ]
    }

    count = emit_annotations(document)

    output = capsys.readouterr().out
    assert count == 2
    assert "::error file=src/a%2Cb.py,line=7::[PYSEC-001] bad %25 value%0Asecond line" in output
    assert "::notice::[NOTE-1] Info" in output


def test_emit_annotations_rejects_invalid_runs() -> None:
    with pytest.raises(TypeError, match="runs list"):
        emit_annotations({"version": "2.1.0"})



def test_emit_annotations_prefixes_paths_and_skips_traversal(capsys) -> None:
    document = {
        "runs": [
            {
                "results": [
                    {
                        "ruleId": "SAFE-1",
                        "level": "warning",
                        "message": {"text": "safe finding"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/app.py"},
                                    "region": {"startLine": 3},
                                }
                            }
                        ],
                    },
                    {
                        "ruleId": "BAD-PATH",
                        "level": "error",
                        "message": {"text": "invalid path"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "../outside.py"},
                                    "region": {"startLine": 4},
                                }
                            }
                        ],
                    },
                ]
            }
        ]
    }

    assert emit_annotations(document, "target") == 2
    output = capsys.readouterr().out
    assert "file=target/src/app.py,line=3" in output
    assert "file=../outside.py" not in output


def test_emit_annotations_rejects_unsafe_prefix() -> None:
    with pytest.raises(ValueError, match="safe relative path"):
        emit_annotations({"runs": []}, "../outside")
