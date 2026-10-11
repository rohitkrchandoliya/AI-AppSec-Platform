"""AST-based Python security rules for the AppSec MVP."""

import ast
from pathlib import Path

from appsec.models import Finding, Severity
from appsec.scanners.base import Scanner


class PythonSecurityScanner(Scanner):
    """Detect a small set of high-confidence Python security anti-patterns."""

    name = "python-sast"
    rule_count = 2

    def scan(self, root: Path) -> list[Finding]:
        findings: list[Finding] = []
        for path in sorted(root.rglob("*.py")):
            if any(part in {".git", ".venv", "venv", "__pycache__", "node_modules"} for part in path.parts):
                continue
            findings.extend(self._scan_file(path))
        return findings

    def _scan_file(self, path: Path) -> list[Finding]:
        try:
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(path))
        except (OSError, UnicodeDecodeError, SyntaxError):
            return []

        findings: list[Finding] = []
        lines = source.splitlines()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                findings.extend(self._check_call(node, path, lines))
        return findings

    def _check_call(self, node: ast.Call, path: Path, lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        name = self._call_name(node.func)

        if name in {"eval", "exec"}:
            findings.append(
                self._finding(
                    rule_id="PYSEC-001",
                    title=f"Dynamic code execution via {name}()",
                    message="Dynamic evaluation can execute attacker-controlled Python code. Avoid it or enforce a strict non-code data format.",
                    path=path,
                    node=node,
                    lines=lines,
                    severity=Severity.HIGH,
                    cwe="CWE-95",
                    owasp="A03:2021-Injection",
                )
            )

        if name == "subprocess.run" and any(
            isinstance(keyword.value, ast.Constant)
            and keyword.arg == "shell"
            and keyword.value.value is True
            for keyword in node.keywords
        ):
            findings.append(
                self._finding(
                    rule_id="PYSEC-002",
                    title="subprocess.run() uses shell=True",
                    message="shell=True increases command-injection risk when command content reaches the call from untrusted input. Prefer argument arrays and shell=False.",
                    path=path,
                    node=node,
                    lines=lines,
                    severity=Severity.HIGH,
                    cwe="CWE-78",
                    owasp="A03:2021-Injection",
                )
            )

        return findings

    @staticmethod
    def _call_name(func: ast.expr) -> str:
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            return f"{func.value.id}.{func.attr}"
        return ""

    @staticmethod
    def _finding(
        *,
        rule_id: str,
        title: str,
        message: str,
        path: Path,
        node: ast.Call,
        lines: list[str],
        severity: Severity,
        cwe: str,
        owasp: str,
    ) -> Finding:
        line = node.lineno
        evidence = lines[line - 1].strip() if 0 < line <= len(lines) else None
        return Finding(
            rule_id=rule_id,
            title=title,
            severity=severity,
            message=message,
            path=path,
            line=line,
            column=node.col_offset + 1,
            cwe=cwe,
            owasp=owasp,
            evidence=evidence,
            confidence=0.98,
        )
