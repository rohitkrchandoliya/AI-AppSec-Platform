"""Command-line entry point."""

import json
from pathlib import Path

import typer
from rich.console import Console

from appsec import __version__
from appsec.ai_provider import OpenAICompatibleReasoningProvider
from appsec.baseline import apply_baseline, load_baseline
from appsec.baseline import write_baseline as save_baseline
from appsec.findings import normalize_findings
from appsec.models import DependencyRisk, Finding, ScanResult, Severity
from appsec.reasoning import GuardedReasoningProvider, build_reasoning_request
from appsec.redaction import redact_sensitive_text
from appsec.risk import dependency_risk_score
from appsec.sarif import sarif_json
from appsec.sbom import sbom_json
from appsec.scanners import JavaScriptSecurityScanner, PythonSecurityScanner, SecretScanner
from appsec.scanners.advisories import audit_dependencies
from appsec.scanners.base import iter_source_files
from appsec.scanners.dependencies import discover_dependencies

app = typer.Typer(help="AI-assisted application security scanner.")
console = Console()
gate_console = Console(stderr=True)


@app.command()
def version() -> None:
    """Show the platform version."""
    console.print(f"ai-appsec-platform {__version__}")


def _source_context(root: Path, finding: Finding) -> list[str]:
    """Return a small, redacted source window only when the path remains inside ROOT."""
    resolved_root = root.resolve()
    candidate = (resolved_root / finding.path).resolve()
    if not candidate.is_relative_to(resolved_root):
        return []

    try:
        lines = candidate.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return []

    first = max(1, finding.line - 2)
    last = min(len(lines), finding.line + 2)
    return [
        f"{line_number}: {redact_sensitive_text(lines[line_number - 1])}"
        for line_number in range(first, last + 1)
    ]


def _enforce_severity_gate(findings: list[Finding], threshold: Severity | None) -> None:
    """Exit unsuccessfully when any finding meets or exceeds the configured severity."""
    if threshold is None:
        return
    rank = {
        Severity.INFO: 0,
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }
    blocking = [finding for finding in findings if rank[finding.severity] >= rank[threshold]]
    if blocking:
        gate_console.print(
            f"[bold red]Security gate failed:[/bold red] {len(blocking)} finding(s) "
            f"at or above {threshold.value} severity."
        )
        raise typer.Exit(code=1)


def _explain_findings(root: Path, findings: list[Finding]) -> list[dict[str, object]]:
    """Request and validate opt-in AI explanations for each deterministic finding."""
    if not findings:
        return []

    provider = GuardedReasoningProvider(OpenAICompatibleReasoningProvider())
    explanations: list[dict[str, object]] = []
    for finding in findings:
        references = [value for value in (finding.cwe, finding.owasp) if value]
        request = build_reasoning_request(
            finding,
            source_context=_source_context(root, finding),
            references=references,
        )
        response = provider.explain(request)
        explanations.append(response.model_dump(mode="json"))
    return explanations


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
    baseline: Path | None = typer.Option(  # noqa: B008
        None, "--baseline", exists=True, file_okay=True, dir_okay=False, readable=True,
        help="Suppress findings already recorded in this baseline JSON file.",
    ),
    write_baseline: Path | None = typer.Option(  # noqa: B008
        None, "--write-baseline", file_okay=True, dir_okay=False,
        help="Write a baseline JSON file from the current findings.",
    ),
    fail_on: Severity | None = typer.Option(  # noqa: B008
        None,
        "--fail-on",
        case_sensitive=False,
        help="Exit with status 1 when any finding meets or exceeds this severity.",
    ),
    explain: bool = typer.Option(
        False,
        "--explain",
        help=(
            "Add evidence-grounded AI explanations. Sends redacted finding/source context "
            "to the configured OpenAI-compatible endpoint."
        ),
    ),
) -> None:
    """Run deterministic security scanners against PATH."""
    output_modes = sum((json_output, sarif_output, sbom_output))
    if output_modes > 1:
        raise typer.BadParameter("Use only one of --json, --sarif, or --sbom.")
    if explain and (sarif_output or sbom_output):
        raise typer.BadParameter("--explain can be combined with --json, but not --sarif or --sbom.")
    if baseline is not None and write_baseline is not None:
        raise typer.BadParameter("Use either --baseline or --write-baseline, not both.")
    if sbom_output and (baseline is not None or write_baseline is not None):
        raise typer.BadParameter("Baseline options apply to findings and cannot be combined with --sbom.")

    scanners = (
        PythonSecurityScanner(),
        JavaScriptSecurityScanner(),
        SecretScanner(),
    )
    raw_findings = [finding for scanner in scanners for finding in scanner.scan(path)]
    findings = normalize_findings(raw_findings, path)

    extensions = SecretScanner._EXTENSIONS | JavaScriptSecurityScanner._EXTENSIONS
    extensions.add(".py")
    files_scanned = sum(1 for _ in iter_source_files(path, extensions))
    dependencies = discover_dependencies(path)
    if audit_dependencies_flag:
        try:
            dependency_findings = audit_dependencies(dependencies, path)
        except RuntimeError as exc:
            raise typer.BadParameter(str(exc)) from exc
        findings = normalize_findings([*findings, *dependency_findings], path)

    suppressed_count = 0
    if write_baseline is not None:
        try:
            save_baseline(write_baseline, findings)
        except OSError as exc:
            raise typer.BadParameter(f"Could not write finding baseline: {exc}") from exc
    if baseline is not None:
        try:
            findings, suppressed_count = apply_baseline(findings, load_baseline(baseline))
        except (TypeError, ValueError) as exc:
            raise typer.BadParameter(str(exc)) from exc

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

    explanations: list[dict[str, object]] = []
    if explain:
        try:
            explanations = _explain_findings(path, findings)
        except (RuntimeError, ValueError) as exc:
            raise typer.BadParameter(f"AI explanation failed: {exc}") from exc

    if sbom_output:
        typer.echo(sbom_json(dependencies, path))
        return
    if sarif_output:
        typer.echo(sarif_json(result))
        _enforce_severity_gate(findings, fail_on)
        return
    if json_output:
        payload = result.model_dump(mode="json")
        if baseline is not None:
            payload["suppressed_findings"] = suppressed_count
        if explain:
            payload["ai_reasoning"] = explanations
        typer.echo(json.dumps(payload, indent=2))
        _enforce_severity_gate(findings, fail_on)
        return

    console.print(f"Scanned [bold]{path.resolve()}[/bold]")
    console.print(
        f"Files: {result.files_scanned} | Findings: {len(result.findings)} | Rules: {result.rules_run}"
    )
    if baseline is not None:
        console.print(f"Suppressed known findings: {suppressed_count}")
    explanation_by_rule = {
        item["finding_rule_id"]: item for item in explanations if "finding_rule_id" in item
    }
    for finding in result.findings:
        console.print(
            f"[{finding.severity.value}] {finding.rule_id} "
            f"{finding.path}:{finding.line} — {finding.title}"
        )
        explanation = explanation_by_rule.get(finding.rule_id)
        if explanation:
            console.print(f"  Explanation: {explanation['explanation']}")
            console.print(f"  Exploitability: {explanation['exploitability']}")
            console.print(f"  Remediation: {explanation['remediation']}")
            console.print(f"  Confidence: {explanation['confidence']}")

    _enforce_severity_gate(findings, fail_on)
