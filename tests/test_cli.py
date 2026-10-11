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
    payload = __import__("json").loads(result.stdout)
    assert payload["files_scanned"] == 1
    assert payload["rules_run"] == 13
    assert payload["findings"][0]["rule_id"] == "JSSEC-004"
    assert payload["findings"][0]["path"] == "sample.js"
    assert payload["dependencies"] == []



def test_scan_sarif_output(tmp_path: Path) -> None:
    (tmp_path / "sample.py").write_text("eval(user_input)\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path), "--sarif"])

    assert result.exit_code == 0
    payload = __import__("json").loads(result.stdout)
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["results"][0]["ruleId"] == "PYSEC-001"


def test_scan_rejects_json_and_sarif_together(tmp_path: Path) -> None:
    result = runner.invoke(app, ["scan", str(tmp_path), "--json", "--sarif"])

    assert result.exit_code != 0



def test_scan_sbom_output(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text(
        'version = 1\n\n[[package]]\nname = "requests"\nversion = "2.32.0"\n',
        encoding="utf-8",
    )
    result = runner.invoke(app, ["scan", str(tmp_path), "--sbom"])

    assert result.exit_code == 0
    payload = __import__("json").loads(result.stdout)
    assert payload["bomFormat"] == "CycloneDX"
    assert payload["components"][0]["purl"] == "pkg:pypi/requests@2.32.0"
