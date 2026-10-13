from pathlib import Path

from appsec.scanners.dependencies import (
    discover_dependencies,
    parse_pipfile_lock,
    parse_pyproject,
    parse_requirements,
    parse_toml_lockfile,
)


def test_parses_pep621_dependencies(tmp_path: Path) -> None:
    path = tmp_path / "pyproject.toml"
    path.write_text(
        """[project]
dependencies = [
    "requests>=2.31,<3",
    "pydantic>=2.9,<3",
    "httpx[socks]>=0.27; python_version >= '3.10'",
]

[project.optional-dependencies]
dev = ["pytest>=8,<9"]
""",
        encoding="utf-8",
    )
    dependencies = parse_pyproject(path)
    assert [(item.name, item.specifier) for item in dependencies] == [
        ("requests", ">=2.31,<3"),
        ("pydantic", ">=2.9,<3"),
        ("httpx", ">=0.27"),
        ("pytest", ">=8,<9"),
    ]


def test_parses_requirements_and_ignores_options(tmp_path: Path) -> None:
    path = tmp_path / "requirements.txt"
    path.write_text(
        """# comment
requests==2.32.0
-r base.txt
--index-url https://example.invalid/simple
urllib3>=2.0
""",
        encoding="utf-8",
    )
    dependencies = parse_requirements(path)
    assert [(item.name, item.specifier) for item in dependencies] == [
        ("requests", "==2.32.0"),
        ("urllib3", ">=2.0"),
    ]


def test_parses_requirement_extras_and_strips_environment_markers(tmp_path: Path) -> None:
    path = tmp_path / "requirements.txt"
    path.write_text(
        'requests[security, socks]>=2.31,<3; python_version >= "3.10"\n'
        'urllib3==2.2.0; python_version < "3.13"\n',
        encoding="utf-8",
    )

    dependencies = parse_requirements(path)

    assert [(item.name, item.specifier) for item in dependencies] == [
        ("requests", ">=2.31,<3"),
        ("urllib3", "==2.2.0"),
    ]


def test_follows_local_requirement_includes_and_handles_cycles(tmp_path: Path) -> None:
    root = tmp_path / "project"
    nested = root / "nested"
    nested.mkdir(parents=True)
    requirements = root / "requirements.txt"
    base = nested / "base.txt"

    requirements.write_text(
        "-r nested/base.txt\nrequests==2.32.0\n",
        encoding="utf-8",
    )
    base.write_text(
        "-r ../requirements.txt\nurllib3==2.2.0\n",
        encoding="utf-8",
    )

    dependencies = parse_requirements(requirements, root=root)

    assert [(item.name, item.specifier) for item in dependencies] == [
        ("urllib3", "==2.2.0"),
        ("requests", "==2.32.0"),
    ]


def test_discovers_supported_manifests(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\ndependencies = ["requests>=2.0"]\n',
        encoding="utf-8",
    )
    (tmp_path / "requirements.txt").write_text("urllib3==2.2.0\n", encoding="utf-8")
    dependencies = discover_dependencies(tmp_path)
    assert {item.name for item in dependencies} == {"requests", "urllib3"}


def test_parses_uv_and_poetry_lockfiles(tmp_path: Path) -> None:
    uv_lock = tmp_path / "uv.lock"
    uv_lock.write_text(
        'version = 1\n\n[[package]]\nname = "requests"\nversion = "2.32.0"\n',
        encoding="utf-8",
    )
    poetry_lock = tmp_path / "poetry.lock"
    poetry_lock.write_text(
        '[[package]]\nname = "urllib3"\nversion = "2.2.0"\n',
        encoding="utf-8",
    )

    uv = parse_toml_lockfile(uv_lock)
    poetry = parse_toml_lockfile(poetry_lock)
    assert [(item.name, item.specifier) for item in uv] == [("requests", "==2.32.0")]
    assert [(item.name, item.specifier) for item in poetry] == [("urllib3", "==2.2.0")]


def test_parses_pipfile_lock_versions(tmp_path: Path) -> None:
    path = tmp_path / "Pipfile.lock"
    path.write_text(
        '{"default":{"requests":{"version":"==2.32.0"}},'
        '"develop":{"pytest":{"version":"==8.3.0"}},'
        '"meta":{"hash":{"sha256":"example"}}}',
        encoding="utf-8",
    )

    dependencies = parse_pipfile_lock(path)
    assert {(item.name, item.specifier) for item in dependencies} == {
        ("requests", "==2.32.0"),
        ("pytest", "==8.3.0"),
    }


def test_audits_exact_pins_and_deduplicates_versions(tmp_path: Path) -> None:
    from appsec.models import Dependency, Severity
    from appsec.scanners.advisories import audit_dependencies

    requirements = tmp_path / "requirements.txt"
    dependencies = [
        Dependency(name="requests", specifier="==2.32.0", source=str(requirements)),
        Dependency(name="requests", specifier="==2.32.0", source=str(requirements)),
        Dependency(name="flask", specifier=">=3.0", source=str(requirements)),
    ]
    calls: list[tuple[str, str]] = []

    def fake_query(name: str, version: str) -> list[dict[str, object]]:
        calls.append((name, version))
        return [
            {
                "id": "PYSEC-TEST-1",
                "summary": "Test advisory",
                "affected": [{"ecosystem_specific": {"severity": "HIGH"}}],
            }
        ]

    findings = audit_dependencies(dependencies, tmp_path, query=fake_query)

    assert calls == [("requests", "2.32.0")]
    assert len(findings) == 1
    assert findings[0].rule_id == "DEP-PYSEC-TEST-1"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].path == Path("requirements.txt")


def test_audits_exact_pin_with_environment_marker(tmp_path: Path) -> None:
    from appsec.scanners.advisories import audit_dependencies

    requirements = tmp_path / "requirements.txt"
    requirements.write_text(
        'requests[security]==2.32.0; python_version >= "3.10"\n',
        encoding="utf-8",
    )
    dependencies = parse_requirements(requirements)
    calls: list[tuple[str, str]] = []

    def fake_query(name: str, version: str) -> list[dict[str, object]]:
        calls.append((name, version))
        return []

    audit_dependencies(dependencies, tmp_path, query=fake_query)

    assert calls == [("requests", "2.32.0")]



def test_requirement_includes_reject_absolute_and_out_of_root_paths(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("must-not-be-read==9.9.9\n", encoding="utf-8")
    requirements = root / "requirements.txt"
    requirements.write_text(
        f"-r ../outside.txt\n-c {outside}\nrequests==2.32.0\n",
        encoding="utf-8",
    )

    dependencies = parse_requirements(requirements, root=root)

    assert [(item.name, item.specifier) for item in dependencies] == [
        ("requests", "==2.32.0"),
    ]


def test_requirement_include_equals_forms_are_followed(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    requirements = root / "requirements.txt"
    constraints = root / "constraints.txt"
    nested = root / "nested.txt"
    requirements.write_text(
        "--requirement=nested.txt\n--constraint=constraints.txt\n",
        encoding="utf-8",
    )
    nested.write_text("requests==2.32.0\n", encoding="utf-8")
    constraints.write_text("urllib3==2.2.0\n", encoding="utf-8")

    dependencies = parse_requirements(requirements, root=root)

    assert [(item.name, item.specifier) for item in dependencies] == [
        ("requests", "==2.32.0"),
        ("urllib3", "==2.2.0"),
    ]


def test_missing_and_invalid_utf8_requirement_files_fail_closed(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    requirements = root / "requirements.txt"
    requirements.write_text(
        "-r missing.txt\nrequests==2.32.0\n",
        encoding="utf-8",
    )

    assert [(item.name, item.specifier) for item in parse_requirements(requirements, root=root)] == [
        ("requests", "==2.32.0"),
    ]

    invalid = root / "invalid.txt"
    invalid.write_bytes(b"requests==2.32.0\n\xff\xfe")
    assert parse_requirements(invalid, root=root) == []
