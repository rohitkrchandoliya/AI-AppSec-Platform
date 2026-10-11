"""Scanner interfaces."""

from abc import ABC, abstractmethod
from pathlib import Path

from appsec.models import Finding


class Scanner(ABC):
    """Base interface implemented by security scanners."""

    name: str = "base"
    rule_count: int = 0

    @abstractmethod
    def scan(self, root: Path) -> list[Finding]:
        """Scan a source tree and return security findings."""
        raise NotImplementedError
