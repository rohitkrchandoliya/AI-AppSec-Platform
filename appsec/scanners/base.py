"""Scanner interfaces and safe source-tree traversal."""

from abc import ABC, abstractmethod
from collections.abc import Iterator, Set as AbstractSet
from pathlib import Path

from appsec.models import Finding

_EXCLUDED_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules"}

def iter_source_files(root: Path, extensions: AbstractSet[str]) -> Iterator[Path]:
    """Yield supported files inside ROOT, excluding generated/vendor trees and external symlinks."""
    root_path = root.resolve()
    allowed_extensions = {extension.lower() for extension in extensions}
    for path in sorted(root_path.rglob("*")):
        try:
            if not path.is_file() or path.suffix.lower() not in allowed_extensions:
                continue
            resolved = path.resolve()
            relative = resolved.relative_to(root_path)
            lexical_relative = path.relative_to(root_path)
        except (OSError, RuntimeError, ValueError):
            continue
        if any(part in _EXCLUDED_DIRS for part in relative.parts):
            continue
        if any(part in _EXCLUDED_DIRS for part in lexical_relative.parts):
            continue
        yield path

class Scanner(ABC):
    """Base interface implemented by security scanners."""

    name: str = "base"
    rule_count: int = 0

    @abstractmethod
    def scan(self, root: Path) -> list[Finding]:
        """Scan a source tree and return security findings."""
        raise NotImplementedError
