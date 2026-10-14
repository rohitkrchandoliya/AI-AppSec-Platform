import json
from pathlib import Path

from typer.testing import CliRunner

from appsec.cli import app

runner = CliRunner()


def test_version_command() -> None:
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert "ai-appsec-platform" in result.stdout


def test_scan_json_output(tmp_path: Path) -> None:
    (tmp_path / "sample.js").write_text("element.innerHTML = userInput;\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path), "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["files_scanned"] == 1
    assert payload["rules_run"] == 13
    assert payload["findings"][0]["rule_id"] == "JSSEC-004"
    assert payload["findings"][0]["path"] == "sample.js"
    assert payload["dependencies"] == []


def test_scan_sarif_output(tmp_path: Path) -> None:
    (tmp_path / "sample.py").write_text("eval(user_input)\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path), "--sarif"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["results"][0]["ruleId"] == "PYSEC-001"
    location = payload["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "sample.py"


def test_scan_rejects_multiple_machine_output_modes(tmp_path: Path) -> None:
    incompatible_modes = (
        ["--json", "--sarif"],
        ["--json", "--sbom"],
        ["--sarif", "--sbom"],
    )
    for flags in incompatible_modes:
        result = runner.invoke(app, ["scan", str(tmp_path), *flags])
        assert result.exit_code != 0, f"Expected incompatible output flags to fail: {flags}"


def test_scan_sbom_output(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text(
        'version = 1\n\n[[package]]\nname = "requests"\nversion = "2.32.0"\n',
        encoding="utf-8",
    )
    result = runner.invoke(app, ["scan", str(tmp_path), "--sbom"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["bomFormat"] == "CycloneDX"
    assert payload["specVersion"] == "1.5"
    assert payload["components"][0]["purl"] == "pkg:pypi/requests@2.32.0"


def test_json_report_redacts_inline_secret_from_sast_evidence(tmp_path: Path) -> None:
    token = "ghp_" + "A" * 36
    (tmp_path / "vulnerable.py").write_text(
        f'value = eval(user_input); API_KEY = "{token}"\n',
        encoding="utf-8",
    )

    result = runner.invoke(app, ["scan", str(tmp_path), "--json"])

    assert result.exit_code == 0
    assert token not in result.stdout
    payload = json.loads(result.stdout)
    finding = next(item for item in payload["findings"] if item["rule_id"] == "PYSEC-001")
    assert "REDACTED" in finding["evidence"]



def test_fail_on_high_exits_nonzero_for_high_finding(tmp_path: Path) -> None:
    (tmp_path / "unsafe.py").write_text("eval(user_input)\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(tmp_path), "--json", "--fail-on", "high"])

    assert result.exit_code == 1
    payload = json.loads(result.stdout.split("Security gate failed:")[0])
    assert any(item["severity"] == "high" for item in payload["findings"])


def test_fail_on_high_allows_lower_severity_findings(tmp_path: Path) -> None:
    (tmp_path / "unsafe.js").write_text("element.innerHTML = input;\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(tmp_path), "--fail-on", "critical"])

    assert result.exit_code == 0
    assert "Security gate failed" not in result.stdout


def test_fail_on_gate_preserves_sarif_output(tmp_path: Path) -> None:
    (tmp_path / "unsafe.py").write_text("eval(user_input)\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(tmp_path), "--sarif", "--fail-on", "high"])

    assert result.exit_code == 1
    payload = json.loads(result.stdout.split("Security gate failed:")[0])
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["results"][0]["ruleId"] == "PYSEC-001"


def test_fail_on_rejects_invalid_severity(tmp_path: Path) -> None:
    result = runner.invoke(app, ["scan", str(tmp_path), "--fail-on", "blocker"])

    assert result.exit_code != 0



def test_write_and_apply_finding_baseline(tmp_path: Path) -> None:
    source = tmp_path / "unsafe.py"
    source.write_text("eval(user_input)\n", encoding="utf-8")
    baseline = tmp_path / "baseline.json"

    created = runner.invoke(app, ["scan", str(tmp_path), "--write-baseline", str(baseline)])
    assert created.exit_code == 0
    assert baseline.is_file()

    scanned = runner.invoke(
        app, ["scan", str(tmp_path), "--baseline", str(baseline), "--json"]
    )
    assert scanned.exit_code == 0
    payload = json.loads(scanned.stdout)
    assert payload["findings"] == []
    assert payload["suppressed_findings"] == 1


def test_baseline_options_are_mutually_exclusive(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline.json"
    baseline.write_text('{"schema_version": 1, "findings": []}', encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "scan",
            str(tmp_path),
            "--baseline",
            str(baseline),
            "--write-baseline",
            str(tmp_path / "new.json"),
        ],
    )
    assert result.exit_code != 0



def test_patch_proposals_require_json_or_human_output(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["scan", str(tmp_path), "--sarif", "--propose-patches"]
    )
    assert result.exit_code != 0


def test_patch_proposals_with_no_findings_do_not_require_ai_key(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    result = runner.invoke(app, ["scan", str(tmp_path), "--json", "--propose-patches"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["ai_patch_proposals"] == []
