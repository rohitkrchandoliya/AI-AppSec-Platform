"""Tests for the opt-in OpenAI-compatible reasoning provider."""

import json
from pathlib import Path
from typing import Any, Self

import pytest

from appsec import ai_provider
from appsec.models import Finding, Severity
from appsec.reasoning import ReasoningRequest


class FakeResponse:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = json.dumps(payload).encode("utf-8")

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self) -> bytes:
        return self._payload


def _request() -> ReasoningRequest:
    return ReasoningRequest(
        finding=Finding(
            rule_id="PYSEC-001",
            title="Dynamic code execution",
            severity=Severity.HIGH,
            message="eval() can execute attacker-controlled Python code.",
            path=Path("app.py"),
            line=3,
            cwe="CWE-95",
            evidence="eval(user_input)",
        ),
        source_context=["3: eval(user_input)"],
        references=["CWE-95"],
    )


def _provider_content() -> dict[str, Any]:
    return {
        "finding_rule_id": "PYSEC-001",
        "explanation": "The call evaluates an expression dynamically.",
        "exploitability": "Risk depends on whether untrusted input reaches this call.",
        "remediation": "Use a non-executable data format instead of eval().",
        "references": ["CWE-95"],
        "confidence": 0.86,
        "limitations": ["The scanner does not prove attacker control of the input."],
    }


def test_provider_parses_structured_response(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {"choices": [{"message": {"content": json.dumps(_provider_content())}}]}
    captured: dict[str, Any] = {}

    def fake_urlopen(request: Any, timeout: float) -> FakeResponse:
        captured["url"] = request.full_url
        captured["authorization"] = request.get_header("Authorization")
        captured["timeout"] = timeout
        captured["payload"] = json.loads(request.data.decode("utf-8"))
        return FakeResponse(payload)

    monkeypatch.setattr(ai_provider, "urlopen", fake_urlopen)
    provider = ai_provider.OpenAICompatibleReasoningProvider(
        api_key="test-key",
        model="test-model",
        base_url="https://provider.example/v1",
        timeout=4,
    )

    result = provider.explain(_request())

    assert result.finding_rule_id == "PYSEC-001"
    assert result.references == ["CWE-95"]
    assert captured["url"] == "https://provider.example/v1/chat/completions"
    assert captured["authorization"] == "Bearer test-key"
    assert captured["timeout"] == 4
    assert captured["payload"]["model"] == "test-model"
    assert captured["payload"]["temperature"] == 0


def test_provider_requires_explicit_api_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    with pytest.raises(RuntimeError, match="OPENAI_API_KEY"):
        ai_provider.OpenAICompatibleReasoningProvider()


def test_provider_rejects_invalid_structured_content(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = {"choices": [{"message": {"content": "not json"}}]}
    monkeypatch.setattr(ai_provider, "urlopen", lambda request, timeout: FakeResponse(payload))
    provider = ai_provider.OpenAICompatibleReasoningProvider(api_key="test-key")

    with pytest.raises(RuntimeError, match="valid structured explanation"):
        provider.explain(_request())
