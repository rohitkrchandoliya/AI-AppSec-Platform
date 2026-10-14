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
    with pytest.raises(ValueError, match="runs list"):
        emit_annotations({"version": "2.1.0"})
