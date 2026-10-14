"""Redact likely credentials from source evidence before reporting findings."""

import math
import re

_SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bghp_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
)
_ASSIGNMENT = re.compile(
    r"""(?ix)\b(?P<name>api[_-]?key|secret|password|passwd|token|access[_-]?token)\s*[:=]\s*(?P<quote>["'])(?P<value>[^"']{8,})(?P=quote)"""
)
_QUOTED = re.compile(r"""(?P<quote>["'])(?P<value>[^"'\s]{20,})(?P=quote)""")


def _is_high_entropy(value: str) -> bool:
    normalized = value.strip()
    if not 20 <= len(normalized) <= 200:
        return False
    if normalized.startswith(("http://", "https://")) or "://" in normalized:
        return False
    if normalized.count("/") >= 2 or normalized.count("\\") >= 2:
        return False
    if normalized.isalnum() and normalized.isalpha():
        return False
    counts = {character: normalized.count(character) for character in set(normalized)}
    entropy = -sum(
        (count / len(normalized)) * math.log2(count / len(normalized))
        for count in counts.values()
    )
    return entropy >= 4.0


def redact_sensitive_text(text: str) -> str:
    """Mask common credential patterns and high-entropy quoted values in source evidence."""
    text = _ASSIGNMENT.sub(lambda match: f"{match.group('name')}=***REDACTED***", text)
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("***REDACTED***", text)

    def redact_quoted(match: re.Match[str]) -> str:
        if _is_high_entropy(match.group("value")):
            return f"{match.group('quote')}***REDACTED***{match.group('quote')}"
        return match.group(0)

    return _QUOTED.sub(redact_quoted, text)
