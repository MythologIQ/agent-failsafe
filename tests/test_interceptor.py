"""Tests for FailSafeInterceptor — ToolCallInterceptor protocol implementation."""

from dataclasses import dataclass, field
from typing import Any

import pytest

from agent_failsafe.interceptor import FailSafeInterceptor
from agent_failsafe.types import (
    DecisionRequest,
    DecisionResponse,
    RiskGrade,
    VerdictDecision,
)


# --- Mock toolkit types (avoid requiring agent-os-kernel in tests) ---


@dataclass
class MockToolCallRequest:
    tool_name: str = "test_tool"
    arguments: dict[str, Any] = field(default_factory=dict)
    call_id: str = "call_1"
    agent_id: str = "did:myth:scrivener:abc"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class MockToolCallResult:
    allowed: bool = True
    reason: str | None = None
    modified_arguments: dict[str, Any] | None = None
    audit_entry: dict[str, Any] | None = None


class MockFailSafeClient:
    """Configurable mock client for testing."""

    def __init__(self, response: DecisionResponse | None = None):
        self._response = response or DecisionResponse(allowed=True)
        self.last_request: DecisionRequest | None = None

    def evaluate(self, request: DecisionRequest) -> DecisionResponse:
        self.last_request = request
        return self._response

    def classify_risk(self, file_path: str, content: str = "") -> RiskGrade:
        return RiskGrade.L1

    def get_shadow_genome(self, agent_did: str = ""):
        return []


@pytest.fixture(autouse=True)
def _patch_imports(monkeypatch):
    """Patch the lazy imports so tests don't need agent-os-kernel."""
    import agent_failsafe.interceptor as mod
    monkeypatch.setattr(mod, "_ToolCallRequest", MockToolCallRequest)
    monkeypatch.setattr(mod, "_ToolCallResult", MockToolCallResult)


class TestFailSafeInterceptor:
    def test_allow(self):
        client = MockFailSafeClient(DecisionResponse(allowed=True))
        interceptor = FailSafeInterceptor(client=client)

        result = interceptor.intercept(MockToolCallRequest(tool_name="read_file"))
        assert result.allowed is True
        assert interceptor.stats["decisions"] == 1
        assert interceptor.stats["blocks"] == 0

    def test_block(self):
        client = MockFailSafeClient(DecisionResponse(
            allowed=False,
            risk_grade=RiskGrade.L3,
            verdict=VerdictDecision.BLOCK,
            reason="Contains password",
        ))
        interceptor = FailSafeInterceptor(client=client)

        result = interceptor.intercept(MockToolCallRequest(tool_name="write_file"))
        assert result.allowed is False
        assert "password" in result.reason.lower()
        assert interceptor.stats["blocks"] == 1

    def test_l3_escalation_blocks(self):
        client = MockFailSafeClient(DecisionResponse(
            allowed=True,
            risk_grade=RiskGrade.L3,
            verdict=VerdictDecision.ESCALATE,
            reason="Human review required",
        ))
        interceptor = FailSafeInterceptor(client=client, block_on_l3=True)

        result = interceptor.intercept(MockToolCallRequest(tool_name="write_file"))
        assert result.allowed is False
        assert "L3" in result.reason

    def test_l3_escalation_allows_when_configured(self):
        client = MockFailSafeClient(DecisionResponse(
            allowed=True,
            risk_grade=RiskGrade.L3,
            verdict=VerdictDecision.ESCALATE,
        ))
        interceptor = FailSafeInterceptor(client=client, block_on_l3=False)

        result = interceptor.intercept(MockToolCallRequest(tool_name="write_file"))
        assert result.allowed is True

    def test_fail_open_on_error(self):
        class FailingClient:
            def evaluate(self, req):
                raise ConnectionError("FailSafe unreachable")
            def classify_risk(self, *a):
                return RiskGrade.L1
            def get_shadow_genome(self, *a):
                return []

        interceptor = FailSafeInterceptor(client=FailingClient())
        result = interceptor.intercept(MockToolCallRequest())
        assert result.allowed is True
        assert "fail-open" in result.reason.lower()

    def test_tool_name_mapping(self):
        client = MockFailSafeClient()
        interceptor = FailSafeInterceptor(client=client)

        interceptor.intercept(MockToolCallRequest(tool_name="write_file"))
        assert client.last_request.action == "file.write"

        interceptor.intercept(MockToolCallRequest(tool_name="delete_file"))
        assert client.last_request.action == "file.delete"

        interceptor.intercept(MockToolCallRequest(tool_name="read_status"))
        assert client.last_request.action == "checkpoint.create"

    def test_audit_entry_populated(self):
        client = MockFailSafeClient(DecisionResponse(
            allowed=True,
            risk_grade=RiskGrade.L2,
            verdict=VerdictDecision.WARN,
            nonce="test-nonce",
        ))
        interceptor = FailSafeInterceptor(client=client)

        result = interceptor.intercept(MockToolCallRequest())
        assert result.audit_entry["failsafe_risk_grade"] == "L2"
        assert result.audit_entry["failsafe_verdict"] == "WARN"
        assert result.audit_entry["failsafe_nonce"] == "test-nonce"

    def test_agent_did_from_request(self):
        client = MockFailSafeClient()
        interceptor = FailSafeInterceptor(client=client, default_agent_did="did:myth:scrivener:default")

        interceptor.intercept(MockToolCallRequest(agent_id="did:myth:scrivener:custom"))
        assert client.last_request.agent_did == "did:myth:scrivener:custom"

    def test_default_agent_did(self):
        client = MockFailSafeClient()
        interceptor = FailSafeInterceptor(client=client, default_agent_did="did:myth:scrivener:fallback")

        interceptor.intercept(MockToolCallRequest(agent_id=""))
        assert client.last_request.agent_did == "did:myth:scrivener:fallback"


class TestOnDecisionCallback:
    def test_on_decision_called_on_allow(self):
        """Callback receives (request, response, latency_ms) when tool call is allowed."""
        captured = []
        client = MockFailSafeClient(DecisionResponse(allowed=True))
        interceptor = FailSafeInterceptor(client=client, on_decision=lambda req, resp, lat: captured.append((req, resp, lat)))

        interceptor.intercept(MockToolCallRequest(tool_name="read_file"))
        assert len(captured) == 1
        assert isinstance(captured[0][0], DecisionRequest)
        assert captured[0][1].allowed is True
        assert captured[0][2] >= 0  # latency_ms is non-negative

    def test_on_decision_called_on_block(self):
        """Callback receives (request, response, latency_ms) when tool call is blocked."""
        captured = []
        client = MockFailSafeClient(DecisionResponse(
            allowed=False, risk_grade=RiskGrade.L3, verdict=VerdictDecision.BLOCK,
        ))
        interceptor = FailSafeInterceptor(client=client, on_decision=lambda req, resp, lat: captured.append((req, resp, lat)))

        interceptor.intercept(MockToolCallRequest(tool_name="write_file"))
        assert len(captured) == 1
        assert captured[0][1].allowed is False
        assert captured[0][2] >= 0  # latency_ms is non-negative

    def test_on_decision_not_called_on_fail_open(self):
        """Callback is NOT invoked when client.evaluate raises (fail-open path)."""
        captured = []

        class FailingClient:
            def evaluate(self, req):
                raise ConnectionError("unreachable")
            def classify_risk(self, *a):
                return RiskGrade.L1
            def get_shadow_genome(self, *a):
                return []

        interceptor = FailSafeInterceptor(client=FailingClient(), on_decision=lambda req, resp: captured.append((req, resp)))
        interceptor.intercept(MockToolCallRequest())
        assert len(captured) == 0

    def test_on_decision_none_by_default(self):
        """No error when on_decision is None (default)."""
        client = MockFailSafeClient(DecisionResponse(allowed=True))
        interceptor = FailSafeInterceptor(client=client)

        assert interceptor.on_decision is None
        result = interceptor.intercept(MockToolCallRequest())
        assert result.allowed is True


class TestFailOpenFailClosed:
    def test_fail_closed_raises_on_client_error(self):
        """fail_open=False re-raises the exception."""
        class FailingClient:
            def evaluate(self, req):
                raise ConnectionError("FailSafe unreachable")
            def classify_risk(self, *a):
                return RiskGrade.L1
            def get_shadow_genome(self, *a):
                return []

        interceptor = FailSafeInterceptor(client=FailingClient(), fail_open=False)
        with pytest.raises(ConnectionError, match="unreachable"):
            interceptor.intercept(MockToolCallRequest())

    def test_fail_open_result_no_exception_leak(self):
        """Fail-open result contains generic message, no str(exc) in reason."""
        class FailingClient:
            def evaluate(self, req):
                raise ConnectionError("SENSITIVE_INTERNAL_ERROR_DETAILS")
            def classify_risk(self, *a):
                return RiskGrade.L1
            def get_shadow_genome(self, *a):
                return []

        interceptor = FailSafeInterceptor(client=FailingClient(), fail_open=True)
        result = interceptor.intercept(MockToolCallRequest())
        assert result.allowed is True
        assert "SENSITIVE_INTERNAL_ERROR_DETAILS" not in result.reason
        assert "fail-open" in result.reason.lower()

    def test_fail_open_default_is_true(self):
        """Default fail_open is True for backward compatibility."""
        client = MockFailSafeClient()
        interceptor = FailSafeInterceptor(client=client)
        assert interceptor.fail_open is True
