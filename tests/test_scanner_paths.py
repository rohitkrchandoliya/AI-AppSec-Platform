"""Regression tests for safe source-tree traversal."""

from pathlib import Path

import pytest

from appsec.scanners.javascript import JavaScriptSecurityScanner
from appsec.scanners.python import PythonSecurityScanner
from appsec.scanners.secrets import SecretScanner


def test_project_inside_venv_named_parent_is_still_scanned(tmp_path: Path) -> None:
    root = tmp_path / "venv" / "project"
    root.mkdir(parents=True)
    (root / "sample.py").write_text("value = eval(user_input)\n", encoding="utf-8")
    (root / "sample.js").write_text("eval(input);\n", encoding="utf-8")
    (root / "config.py").write_text('password = "production-secret-123"\n', encoding="utf-8")

    assert any(f.rule_id == "PYSEC-001" for f in PythonSecurityScanner().scan(root))
    assert any(f.rule_id == "JSSEC-001" for f in JavaScriptSecurityScanner().scan(root))
    assert any(f.rule_id == "SEC-005" for f in SecretScanner().scan(root))


def test_scanners_do_not_follow_source_file_symlinks_outside_root(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "external.py").write_text("value = eval(user_input)\n", encoding="utf-8")
    (outside / "external.js").write_text("eval(input);\n", encoding="utf-8")
    (outside / "external-secret.py").write_text(
        'password = "production-secret-123"\n', encoding="utf-8"
    )
    links = [
        (outside / "external.py", root / "external.py"),
        (outside / "external.js", root / "external.js"),
        (outside / "external-secret.py", root / "external-secret.py"),
    ]
    try:
        for source, target in links:
            target.symlink_to(source)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable in this environment: {exc}")

    assert PythonSecurityScanner().scan(root) == []
    assert JavaScriptSecurityScanner().scan(root) == []
    assert SecretScanner().scan(root) == []
