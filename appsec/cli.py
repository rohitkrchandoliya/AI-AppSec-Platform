"""Command-line entry point."""

import json
from pathlib import Path

import typer
from rich.console import Console

from appsec import __version__
from appsec.findings import normalize_findings
from appsec.models import DependencyRisk, ScanResult
from appsec.risk import dependency_risk_score
from appsec.sarif import sarif_json
from appsec.sbom import sbom_json
from appsec.scanners import JavaScriptSecurityScanner, PythonSecurityScanner, SecretScanner
from appsec.scanners.advisories import audit_dependencies
from appsec.scanners.dependencies import discover_dependencies

app = typer.Typer(help="AI-assisted application security scanner.")
console = Console()


@app.command()
def version() -> None:
    """Show the platform version."""
    console.print(f"ai-appsec-platform {__version__}")


@app.command()
def scan(
    path: Path = typer.Argument(  # noqa: B008
        Path("."), exists=True, file_okay=False, readable=True
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Emit machine-readable JSON instead of human-readable output."
    ),
    sarif_output: bool = typer.Option(
        False, "--sarif", help="Emit SARIF 2.1.0 JSON for code-scanning integrations."
    ),
    audit_dependencies_flag: bool = typer.Option(
        False,
        "--audit-dependencies",
        help="Query OSV for known issues in exact-pinned Python dependencies.",
    ),
    sbom_output: bool = typer.Option(
        False, "--sbom", help="Emit a CycloneDX 1.5 SBOM for exact-pinned Python dependencies."
    ),
) -> None:
    """Run deterministic security scanners against PATH."""
    scanners = (
        PythonSecurityScanner(),
        JavaScriptSecurityScanner(),
        SecretScanner(),
    )
    raw_findings = [finding for scanner in scanners for finding in scanner.scan(path)]
    findings = normalize_findings(raw_findings, path)

    extensions = SecretScanner._EXTENSIONS | JavaScriptSecurityScanner._EXTENSIONS
    extensions.add(".py")
    files_scanned = sum(
        1
        for candidate in path.rglob("*")
        if candidate.is_file()
        and candidate.suffix.lower() in extensions
        and not any(
            part in {".git", ".venv", "venv", "__pycache__", "node_modules"}
            for part in candidate.parts
        )
    )
    dependencies = discover_dependencies(path)
    if audit_dependencies_flag:
        try:
            dependency_findings = audit_dependencies(dependencies, path)
        except RuntimeError as exc:
            raise typer.BadParameter(str(exc)) from exc
        findings = normalize_findings([*findings, *dependency_findings], path)

    dependency_risks: list[DependencyRisk] = []
    for dependency in dependencies:
        score, severity, rationale = dependency_risk_score(dependency, findings)
        dependency_risks.append(
            DependencyRisk(
                name=dependency.name,
                score=score,
                severity=severity,
                rationale=rationale,
            )
        )

    result = ScanResult(
        findings=findings,
        dependencies=dependencies,
        dependency_risks=dependency_risks,
        files_scanned=files_scanned,
        rules_run=sum(scanner.rule_count for scanner in scanners),
    )

    output_modes = sum((json_output, sarif_output, sbom_output))
    if output_modes > 1:
        raise typer.BadParameter("Use only one of --json, --sarif, or --sbom.")
    if sbom_output:
        typer.echo(sbom_json(dependencies, path))
        return
    if sarif_output:
        typer.echo(sarif_json(result))
        return
    if json_output:
        typer.echo(json.dumps(result.model_dump(mode="json"), indent=2))
        return

    console.print(f"Scanned [bold]{path.resolve()}[/bold]")
    console.print(
        f"Files: {result.files_scanned} | Findings: {len(result.findings)} | Rules: {result.rules_run}"
    )
    for finding in result.findings:
        console.print(
            f"[{finding.severity.value}] {finding.rule_id} "
            f"{finding.path}:{finding.line} — {finding.title}"
        )
