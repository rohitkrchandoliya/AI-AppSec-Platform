"""Tests for the opt-in explanation workflow."""

import json
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from appsec import cli
from appsec.models import Finding, Severity

runner = CliRunner()


def _finding(path: Path, line: int = 2) -> Finding:
    return Finding(
        rule_id="PYSEC-001",
        title="Dynamic code execution",
        severity=Severity.HIGH,
        message="eval() may execute attacker-controlled code.",
        path=path,
        line=line,
        cwe="CWE-95",
        evidence="eval(user_input)",
    )


def test_json_explain_adds_ai_reasoning_without_live_network(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    (tmp_path / "sample.py").write_text("eval(user_input)\n", encoding="utf-8")
    monkeypatch.setattr(
        cli,
        "_explain_findings",
        lambda root, findings: [
            {
                "finding_rule_id": "PYSEC-001",
                "explanation": "Dynamic evaluation is risky.",
                "exploitability": "Depends on input control.",
                "remediation": "Use a data parser instead.",
                "references": ["CWE-95"],
                "confidence": 0.8,
                "limitations": ["Static analysis cannot prove exploitability."],
            }
        ],
    )

    result = runner.invoke(cli.app, ["scan", str(tmp_path), "--json", "--explain"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["findings"][0]["rule_id"] == "PYSEC-001"
    assert payload["ai_reasoning"][0]["finding_rule_id"] == "PYSEC-001"


def test_explain_rejects_sarif_combination_before_provider_call(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    def fail_if_called(root: Path, findings: list[Finding]) -> list[dict[str, object]]:
        raise AssertionError("AI provider should not be called for an incompatible output mode.")

    monkeypatch.setattr(cli, "_explain_findings", fail_if_called)
    result = runner.invoke(cli.app, ["scan", str(tmp_path), "--sarif", "--explain"])

    assert result.exit_code != 0
    assert "not --sarif or --sbom" in result.output


def test_source_context_redacts_token_and_limits_window(tmp_path: Path) -> None:
    token = "ghp_" + "A" * 36
    root = tmp_path / "repo"
    root.mkdir()
    source = root / "sample.py"
    source.write_text(
        f"line one\nAPI_KEY = \"{token}\"\neval(user_input)\nline four\nline five\n",
        encoding="utf-8",
    )

    context = cli._source_context(root, _finding(Path("sample.py"), line=3))

    assert len(context) == 5
    assert token not in "\n".join(context)
    assert any("REDACTED" in line for line in context)


def test_source_context_does_not_read_outside_scan_root(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (tmp_path / "outside.py").write_text("eval(user_input)\n", encoding="utf-8")

    assert cli._source_context(root, _finding(Path("../outside.py"))) == []
