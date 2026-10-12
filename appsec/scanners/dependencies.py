"""Python dependency inventory parsing."""

import json
import re
import tomllib
from pathlib import Path

from appsec.models import Dependency

_REQUIREMENT = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[A-Za-z0-9_.-]+(?:\s*,\s*[A-Za-z0-9_.-]+)*\])?\s*(.*)$"
)


def parse_requirements(path: Path, root: Path | None = None) -> list[Dependency]:
    """Parse requirements files and safe, repository-local include directives."""
    scan_root = (root or path.parent).resolve()
    return _parse_requirements_file(path.resolve(), scan_root, set())


def _parse_requirements_file(
    path: Path,
    root: Path,
    visited: set[Path],
) -> list[Dependency]:
    resolved_path = path.resolve()
    try:
        resolved_path.relative_to(root)
    except ValueError:
        return []
    if resolved_path in visited:
        return []
    visited.add(resolved_path)

    dependencies: list[Dependency] = []
    try:
        lines = resolved_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return dependencies

    for line in lines:
        line = line.split("#", 1)[0].strip()
        if not line:
            continue

        include_target = _include_target(line)
        if include_target is not None:
            target = Path(include_target)
            if target.is_absolute():
                continue
            include_path = (resolved_path.parent / target).resolve()
            try:
                include_path.relative_to(root)
            except ValueError:
                continue
            dependencies.extend(_parse_requirements_file(include_path, root, visited))
            continue

        if line.startswith(("--", "git+", "http:", "https:")):
            continue
        match = _REQUIREMENT.match(line)
        if match:
            specifier = match.group(2).split(";", 1)[0].strip()
            dependencies.append(
                Dependency(name=match.group(1), specifier=specifier, source=str(resolved_path))
            )
    return dependencies


def _include_target(line: str) -> str | None:
    """Return a local include target for common pip requirements directives."""
    for prefix in ("--requirement=", "--constraint=", "-r=", "-c="):
        if line.startswith(prefix):
            target = line[len(prefix) :].strip()
            return target.strip("\"'") or None

    for prefix in ("--requirement ", "--constraint ", "-r ", "-c "):
        if line.startswith(prefix):
            target = line[len(prefix) :].strip()
            return target.strip("\"'") or None
    return None


def parse_pyproject(path: Path) -> list[Dependency]:
    """Parse PEP 621 project dependencies and optional dependency groups."""
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return []

    project = data.get("project", {})
    if not isinstance(project, dict):
        return []

    values: list[str] = []
    dependencies = project.get("dependencies", [])
    if isinstance(dependencies, list):
        values.extend(item for item in dependencies if isinstance(item, str))

    optional = project.get("optional-dependencies", {})
    if isinstance(optional, dict):
        for group in optional.values():
            if isinstance(group, list):
                values.extend(item for item in group if isinstance(item, str))

    parsed: list[Dependency] = []
    for value in values:
        dependency = _parse_requirement(value, path)
        if dependency is not None:
            parsed.append(dependency)
    return parsed


def _parse_requirement(value: str, path: Path) -> Dependency | None:
    normalized = value.strip().split(";", 1)[0].strip()
    match = _REQUIREMENT.match(normalized)
    if not match:
        return None
    return Dependency(
        name=match.group(1),
        specifier=match.group(2).strip(),
        source=str(path),
    )


def parse_toml_lockfile(path: Path) -> list[Dependency]:
    """Parse exact package versions from uv.lock or poetry.lock."""
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return []

    packages = data.get("package", [])
    if not isinstance(packages, list):
        return []

    dependencies: list[Dependency] = []
    for package in packages:
        if not isinstance(package, dict):
            continue
        name = package.get("name")
        version = package.get("version")
        if isinstance(name, str) and isinstance(version, str) and name and version:
            dependencies.append(
                Dependency(name=name, specifier=f"=={version}", source=str(path))
            )
    return dependencies


def parse_pipfile_lock(path: Path) -> list[Dependency]:
    """Parse exact package versions from Pipfile.lock."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return []
    if not isinstance(data, dict):
        return []

    dependencies: list[Dependency] = []
    for section in ("default", "develop"):
        packages = data.get(section, {})
        if not isinstance(packages, dict):
            continue
        for name, details in packages.items():
            if not isinstance(name, str) or not isinstance(details, dict):
                continue
            version = details.get("version")
            if isinstance(version, str) and version.startswith("=="):
                dependencies.append(
                    Dependency(name=name, specifier=version, source=str(path))
                )
    return dependencies


def discover_dependencies(root: Path) -> list[Dependency]:
    """Discover supported Python manifests and lockfiles below ROOT."""
    dependencies: list[Dependency] = []
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        dependencies.extend(parse_pyproject(pyproject))

    for filename in ("uv.lock", "poetry.lock"):
        path = root / filename
        if path.is_file():
            dependencies.extend(parse_toml_lockfile(path))

    pipfile_lock = root / "Pipfile.lock"
    if pipfile_lock.is_file():
        dependencies.extend(parse_pipfile_lock(pipfile_lock))

    for filename in ("requirements.txt", "requirements-dev.txt", "requirements-test.txt"):
        path = root / filename
        if path.is_file():
            dependencies.extend(parse_requirements(path, root=root))

    return dependencies
