"""Provider-neutral, evidence-grounded AI security reasoning contracts."""

# ruff: noqa: I001

import re
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field

from appsec.models import Finding
from appsec.redaction import redact_sensitive_text


_SECURITY_IDENTIFIER = re.compile(r"\b(?:CVE-\d{4}-\d{4,}|CWE-\d+)\b", re.IGNORECASE)


class ReasoningRequest(BaseModel):
    """Bounded evidence supplied to a reasoning provider."""

    model_config = ConfigDict(extra="forbid")

    finding: Finding
    source_context: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)


class ReasoningResponse(BaseModel):
    """Structured reasoning that can be safely attached to a finding."""

    model_config = ConfigDict(extra="forbid")

    finding_rule_id: str = Field(min_length=1)
    explanation: str = Field(min_length=1)
    exploitability: str = Field(min_length=1)
    remediation: str = Field(min_length=1)
    references: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    limitations: list[str] = Field(default_factory=list)


class ReasoningProvider(Protocol):
    """Provider interface implemented by an AI reasoning backend."""

    def explain(self, request: ReasoningRequest) -> ReasoningResponse:
        """Explain one finding using only the supplied request evidence."""
        ...


def build_reasoning_request(
    finding: Finding,
    *,
    source_context: list[str] | None = None,
    references: list[str] | None = None,
) -> ReasoningRequest:
    """Create a bounded reasoning request without adding repository data implicitly."""
    return ReasoningRequest(
        finding=finding,
        source_context=list(source_context or []),
        references=list(references or []),
    )


def validate_reasoning_response(
    request: ReasoningRequest,
    response: ReasoningResponse,
) -> ReasoningResponse:
    """Reject responses that cross the evidence boundary or change finding identity."""
    if response.finding_rule_id != request.finding.rule_id:
        raise ValueError("Reasoning response targets a different finding.")

    allowed_references = set(request.references)
    unknown_references = set(response.references) - allowed_references
    if unknown_references:
        raise ValueError("Reasoning response contains references not supplied as evidence.")

    allowed_identifiers = {request.finding.rule_id}
    if request.finding.cwe:
        allowed_identifiers.add(request.finding.cwe.upper())
    if request.finding.owasp:
        allowed_identifiers.add(request.finding.owasp.upper())

    generated_text = " ".join(
        [
            response.explanation,
            response.exploitability,
            response.remediation,
            *response.limitations,
        ]
    )
    for identifier in _SECURITY_IDENTIFIER.findall(generated_text):
        if identifier.upper() not in allowed_identifiers:
            raise ValueError(
                f"Reasoning response contains unsupported security identifier: {identifier}"
            )

    return response


class GuardedReasoningProvider:
    """Adapter that enforces the evidence boundary around an AI provider."""

    def __init__(self, provider: ReasoningProvider) -> None:
        self._provider = provider

    def explain(self, request: ReasoningRequest) -> ReasoningResponse:
        """Call the provider and validate its structured response."""
        response = self._provider.explain(request)
        return validate_reasoning_response(request, response)



class PatchProposalRequest(BaseModel):
    """Bounded finding context used to request a proposed patch."""

    model_config = ConfigDict(extra="forbid")

    finding: Finding
    source_context: list[str] = Field(default_factory=list)


class PatchProposal(BaseModel):
    """A proposed unified diff; it is never applied automatically."""

    model_config = ConfigDict(extra="forbid")

    finding_rule_id: str = Field(min_length=1)
    unified_diff: str = Field(min_length=1, max_length=20000)
    rationale: str = Field(min_length=1, max_length=3000)
    limitations: list[str] = Field(default_factory=list, max_length=20)


class PatchProposalProvider(Protocol):
    """Provider interface for a generated patch proposal."""

    def propose_patch(self, request: PatchProposalRequest) -> PatchProposal:
        """Propose a patch for the supplied finding without modifying any files."""
        ...


def build_patch_request(
    finding: Finding, *, source_context: list[str] | None = None
) -> PatchProposalRequest:
    """Build a patch request using only explicitly supplied, bounded context."""
    return PatchProposalRequest(
        finding=finding,
        source_context=list(source_context or []),
    )


def validate_patch_proposal(
    request: PatchProposalRequest, proposal: PatchProposal
) -> PatchProposal:
    """Reject mismatched, multi-file, malformed, or path-escaping patch proposals."""
    from pathlib import PurePosixPath

    if proposal.finding_rule_id != request.finding.rule_id:
        raise ValueError("Patch proposal targets a different finding.")
    path = request.finding.path.as_posix()
    normalized = PurePosixPath(path)
    if normalized.is_absolute() or ".." in normalized.parts or not path or "\n" in path or "\r" in path:
        raise ValueError("Finding path is not safe for a patch proposal.")

    lines = proposal.unified_diff.splitlines()
    if len(lines) < 5:
        raise ValueError("Patch proposal is not a valid unified diff.")
    if lines[0] != f"--- a/{path}" or lines[1] != f"+++ b/{path}":
        raise ValueError("Patch proposal must target only the finding's relative file path.")
    if sum(line.startswith("--- ") for line in lines) != 1 or sum(
        line.startswith("+++ ") for line in lines
    ) != 1:
        raise ValueError("Patch proposal must modify exactly one file.")
    if not any(line.startswith("@@ ") for line in lines):
        raise ValueError("Patch proposal must contain a unified diff hunk.")
    if any(line.startswith(("GIT binary patch", "Binary files ")) for line in lines):
        raise ValueError("Binary patch proposals are not supported.")
    if any("\x00" in line for line in lines):
        raise ValueError("Patch proposal contains a null byte.")
    return proposal


class GuardedPatchProposalProvider:
    """Validate untrusted AI-generated patches before returning them to the caller."""

    def __init__(self, provider: PatchProposalProvider) -> None:
        self._provider = provider

    def propose_patch(self, request: PatchProposalRequest) -> PatchProposal:
        proposal = self._provider.propose_patch(request)
        return validate_patch_proposal(request, proposal)
