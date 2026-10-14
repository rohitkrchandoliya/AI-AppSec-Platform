from pathlib import Path

import pytest

from appsec.models import Finding, Severity
from appsec.reasoning import (
    GuardedPatchProposalProvider,
    PatchProposal,
    PatchProposalRequest,
    build_patch_request,
)


def finding(path: str = "src/app.py") -> Finding:
    return Finding(
        rule_id="PYSEC-001",
        title="Dynamic execution",
        severity=Severity.HIGH,
        message="Unsafe dynamic execution.",
        path=Path(path),
        line=3,
        evidence="eval(user_input)",
    )


def proposal(diff: str | None = None, rule_id: str = "PYSEC-001") -> PatchProposal:
    return PatchProposal(
        finding_rule_id=rule_id,
        unified_diff=diff or (
            "--- a/src/app.py\n"
            "+++ b/src/app.py\n"
            "@@ -1,1 +1,1 @@\n"
            "-eval(user_input)\n"
            "+ast.literal_eval(user_input)\n"
        ),
        rationale="Replace dynamic execution with a safer parsing strategy.",
        limitations=["Review whether the input grammar permits literal_eval."],
    )


class FakePatchProvider:
    def __init__(self, result: PatchProposal) -> None:
        self.result = result

    def propose_patch(self, request: PatchProposalRequest) -> PatchProposal:
        return self.result


def test_guard_accepts_single_file_patch_for_finding() -> None:
    result = GuardedPatchProposalProvider(FakePatchProvider(proposal())).propose_patch(
        build_patch_request(finding(), source_context=["3: eval(user_input)"])
    )
    assert result.finding_rule_id == "PYSEC-001"
    assert result.unified_diff.startswith("--- a/src/app.py\n")
    assert "ast.literal_eval" in result.unified_diff


def test_guard_rejects_patch_for_different_finding() -> None:
    with pytest.raises(ValueError, match="different finding"):
        GuardedPatchProposalProvider(FakePatchProvider(proposal(rule_id="OTHER-1"))).propose_patch(
            build_patch_request(finding())
        )


def test_guard_rejects_path_traversal_and_header_injection() -> None:
    with pytest.raises(ValueError, match="safe"):
        GuardedPatchProposalProvider(FakePatchProvider(proposal())).propose_patch(
            build_patch_request(finding("../secret.py"))
        )
    unsafe_path = "src/app.py\n--- a/other.py"
    with pytest.raises(ValueError, match="safe"):
        GuardedPatchProposalProvider(FakePatchProvider(proposal())).propose_patch(
            build_patch_request(finding(unsafe_path))
        )


def test_guard_rejects_multi_file_patch() -> None:
    diff = (
        "--- a/src/app.py\n+++ b/src/app.py\n@@ -1 +1 @@\n-old\n+new\n"
        "--- a/other.py\n+++ b/other.py\n@@ -1 +1 @@\n-old\n+new\n"
    )
    with pytest.raises(ValueError, match="exactly one file"):
        GuardedPatchProposalProvider(FakePatchProvider(proposal(diff))).propose_patch(
            build_patch_request(finding())
        )


def test_guard_rejects_missing_hunk() -> None:
    diff = "--- a/src/app.py\n+++ b/src/app.py\nold text\nnew text\n"
    with pytest.raises(ValueError, match="hunk"):
        GuardedPatchProposalProvider(FakePatchProvider(proposal(diff))).propose_patch(
            build_patch_request(finding())
        )



def test_guard_rejects_patch_that_looks_like_it_contains_a_secret() -> None:
    diff = (
        "--- a/src/app.py\n+++ b/src/app.py\n@@ -1 +1 @@\n"
        "-API_KEY = \"old-value\"\n+API_KEY = \"ghp_"
        + "A" * 36
        + "\"\n"
    )
    with pytest.raises(ValueError, match="contain a secret"):
        GuardedPatchProposalProvider(FakePatchProvider(proposal(diff))).propose_patch(
            build_patch_request(finding())
        )
