"""Regex-based JavaScript and TypeScript security rules for the AppSec MVP."""

import re
from pathlib import Path
from typing import ClassVar

from appsec.models import Finding, Severity
from appsec.scanners.base import Scanner


class JavaScriptSecurityScanner(Scanner):
    """Detect high-confidence JavaScript/TypeScript security anti-patterns."""

    name = "javascript-sast"
    _EXTENSIONS: ClassVar[set[str]] = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}

    _RULES: ClassVar[tuple[tuple[str, re.Pattern[str], str, str, Severity, str, str], ...]] = (
        (
            "JSSEC-001",
            re.compile(r"\beval\s*\("),
            "Dynamic code execution via eval()",
            "Dynamic evaluation can execute attacker-controlled JavaScript. Prefer data parsing or explicit dispatch.",
            Severity.HIGH,
            "CWE-95",
            "A03:2021-Injection",
        ),
        (
            "JSSEC-002",
            re.compile(r"\bnew\s+Function\s*\("),
            "Dynamic code execution via Function()",
            "The Function constructor evaluates a string as code and can become a code-injection sink.",
            Severity.HIGH,
            "CWE-95",
            "A03:2021-Injection",
        ),
        (
            "JSSEC-003",
            re.compile(r"\b(?:exec|execSync)\s*\("),
            "Shell command execution via child_process",
            "Shell command execution is dangerous when command content can contain untrusted input. Prefer execFile/execFileSync with argument arrays.",
            Severity.HIGH,
            "CWE-78",
            "A03:2021-Injection",
        ),
        (
            "JSSEC-004",
            re.compile(r"\.innerHTML\s*="),
            "Unsafe innerHTML assignment",
            "Assigning untrusted HTML to innerHTML can enable cross-site scripting. Prefer textContent or a trusted HTML sanitizer.",
            Severity.HIGH,
            "CWE-79",
            "A03:2021-Injection",
        ),
        (
            "JSSEC-005",
            re.compile(r"dangerouslySetInnerHTML\s*="),
            "React dangerouslySetInnerHTML usage",
            "dangerouslySetInnerHTML bypasses React's normal escaping and requires trusted, sanitized HTML.",
            Severity.MEDIUM,
            "CWE-79",
            "A03:2021-Injection",
        ),
    )
    rule_count = len(_RULES)

    def scan(self, root: Path) -> list[Finding]:
        findings: list[Finding] = []
        for path in sorted(root.rglob("*")):
            if (
                not path.is_file()
                or path.suffix.lower() not in self._EXTENSIONS
                or any(
                    part in {".git", ".venv", "venv", "__pycache__", "node_modules"}
                    for part in path.parts
                )
            ):
                continue
            findings.extend(self._scan_file(path))
        return findings

    def _scan_file(self, path: Path) -> list[Finding]:
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError):
            return []

        findings: list[Finding] = []
        for line_number, line in enumerate(lines, start=1):
            for rule_id, pattern, title, message, severity, cwe, owasp in self._RULES:
                match = pattern.search(line)
                if match:
                    findings.append(
                        Finding(
                            rule_id=rule_id,
                            title=title,
                            severity=severity,
                            message=message,
                            path=path,
                            line=line_number,
                            column=match.start() + 1,
                            cwe=cwe,
                            owasp=owasp,
                            evidence=line.strip()[:500],
                            confidence=0.96,
                        )
                    )
        return findings
