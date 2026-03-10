"""Tests for FailSafeKernel integration and AdapterRegistry."""

import os
from types import SimpleNamespace
from unittest.mock import MagicMock

from agent_os.integrations.base import BaseIntegration
from agent_os.integrations.registry import AdapterRegistry

from agent_failsafe.audit_sink import decision_to_audit_entry
from agent_failsafe.integration import FailSafeKernel, create_failsafe_kernel
from agent_failsafe.pipeline import GovernancePipeline, PipelineStage
from agent_failsafe.types import (
    DecisionRequest,
    DecisionResponse,
    RiskGrade,
    VerdictDecision,
)


def _mock_client(allowed: bool = True, verdict: str = "PASS",
                 risk_grade: str = "L1") -> MagicMock:
    response = MagicMock()
    response.allowed = allowed
    response.risk_grade.value = risk_grade
    response.reason = ""
    response.nonce = "test-nonce"
    response.verdict.value = verdict
    response.verdict = MagicMock()
    response.verdict.value = verdict
    response.timestamp = "2026-03-10T05:00:00Z"
    client = MagicMock()
    client.evaluate.return_value = response
    return client


def test_failsafe_kernel_registered():
    """AdapterRegistry.get('failsafe') returns FailSafeKernel."""
    registry = AdapterRegistry()
    assert registry.get("failsafe") is FailSafeKernel


def test_failsafe_kernel_is_base_integration():
    """FailSafeKernel is a subclass of BaseIntegration."""
    assert issubclass(FailSafeKernel, BaseIntegration)


def test_create_failsafe_kernel_returns_instance():
    """Factory returns a FailSafeKernel instance."""
    client = _mock_client()
    kernel = create_failsafe_kernel(client)
    assert isinstance(kernel, FailSafeKernel)


def test_wrap_returns_governed_agent():
    """kernel.wrap(agent) returns a governed proxy."""
    client = _mock_client()
    kernel = FailSafeKernel(client)
    agent = MagicMock()
    agent.agent_id = "test-agent"
    governed = kernel.wrap(agent)
    assert governed is not agent
    assert governed.agent_id == "test-agent"


def test_evaluate_delegates_to_client():
    """kernel.evaluate() calls client.evaluate with correct action."""
    client = _mock_client(allowed=True)
    kernel = FailSafeKernel(client)
    result = kernel.evaluate("did:myth:scrivener:abc", "file.write")
    assert result is True
    client.evaluate.assert_called_once()


# --- Phase 2: Kernel Orchestration Wiring ---


def test_kernel_no_backends_no_callback():
    """interceptor.on_decision is None when no backends configured."""
    client = _mock_client()
    kernel = FailSafeKernel(client)
    assert kernel.interceptor.on_decision is None


def test_kernel_sli_records_on_decision():
    """SLI records decisions when _on_decision dispatches."""
    sli = MagicMock()
    client = _mock_client(allowed=True)
    kernel = FailSafeKernel(client, sli=sli)

    assert kernel.interceptor.on_decision is not None
    request = DecisionRequest(action="file.write", agent_did="did:myth:scrivener:abc")
    response = DecisionResponse(allowed=True, verdict=VerdictDecision.PASS)
    kernel._on_decision(request, response)
    sli.record_decision.assert_called_once_with(response)


def test_kernel_audit_sink_writes_on_decision():
    """Audit sink receives mapped entry when _on_decision dispatches."""
    audit_sink = MagicMock()
    client = _mock_client(allowed=True)
    kernel = FailSafeKernel(client, audit_sink=audit_sink)

    request = DecisionRequest(action="file.write", agent_did="did:myth:scrivener:abc")
    response = DecisionResponse(allowed=True, verdict=VerdictDecision.PASS)
    kernel._on_decision(request, response)
    audit_sink.write.assert_called_once()
    entry = audit_sink.write.call_args[0][0]
    assert entry.event_type == "governance_eval"


def test_kernel_approval_submits_on_escalate():
    """Approval backend receives submit when verdict is ESCALATE."""
    approval = MagicMock()
    client = _mock_client(allowed=True)
    kernel = FailSafeKernel(client, approval_backend=approval)

    request = DecisionRequest(action="file.write", agent_did="did:myth:scrivener:abc")
    response = DecisionResponse(
        allowed=True, verdict=VerdictDecision.ESCALATE, risk_grade=RiskGrade.L3,
    )
    kernel._on_decision(request, response)
    approval.submit.assert_called_once_with(request)


def test_decision_to_audit_entry_mapping():
    """Pure function produces correct field values."""
    request = DecisionRequest(
        action="file.write",
        agent_did="did:myth:scrivener:abc",
        artifact_path="/src/main.py",
    )
    response = DecisionResponse(
        allowed=True,
        nonce="abc123",
        risk_grade=RiskGrade.L1,
        verdict=VerdictDecision.PASS,
        reason="OK",
        timestamp="2026-03-10T05:00:00Z",
    )
    entry = decision_to_audit_entry(request, response)

    assert entry.entry_id == "abc123"
    assert entry.event_type == "governance_eval"
    assert entry.agent_did == "did:myth:scrivener:abc"
    assert entry.action == "file.write"
    assert entry.resource == os.path.normpath("/src/main.py")
    assert entry.outcome == "allowed"
    assert entry.policy_decision == "PASS"
    assert entry.data == {"verdict": "PASS", "reason": "OK"}


# --- Phase 3: Pipeline Integration ---


def test_pipeline_evaluate_with_pipeline():
    """Kernel delegates to pipeline when configured."""
    client = MagicMock()
    response = DecisionResponse(allowed=True, verdict=VerdictDecision.PASS)
    client.evaluate.return_value = response
    pipeline = GovernancePipeline(client=client)
    kernel = FailSafeKernel(client, pipeline=pipeline)

    req = DecisionRequest(action="file.write", agent_did="did:myth:scrivener:abc")
    result = kernel.pipeline_evaluate(req)
    assert result.allowed is True
    assert result.stage == PipelineStage.AUDITED


def test_pipeline_evaluate_fallback():
    """Without pipeline, kernel wraps basic eval in PipelineResult."""
    client = MagicMock()
    response = DecisionResponse(allowed=False, verdict=VerdictDecision.BLOCK)
    client.evaluate.return_value = response
    kernel = FailSafeKernel(client)

    req = DecisionRequest(action="file.write", agent_did="did:myth:scrivener:abc")
    result = kernel.pipeline_evaluate(req)
    assert result.allowed is False
    assert result.stage == PipelineStage.GOVERNANCE
    assert result.governance is response


# --- Phase 4: Webhook Notifier Wiring ---


def test_webhook_notifier_called_on_decision():
    """Webhook notifier receives translated event on governance decision."""
    notifier = MagicMock()
    client = _mock_client(allowed=True)
    kernel = FailSafeKernel(client, webhook_notifier=notifier)

    request = DecisionRequest(action="file.write", agent_did="did:myth:scrivener:abc")
    response = DecisionResponse(allowed=True, verdict=VerdictDecision.PASS)
    kernel._on_decision(request, response)

    notifier.notify.assert_called_once()
    event = notifier.notify.call_args[0][0]
    assert event.event_type == "governance_decision"
    assert event.agent_id == "did:myth:scrivener:abc"


def test_webhook_notifier_failure_does_not_halt():
    """Notifier exception is swallowed — kernel continues."""
    notifier = MagicMock()
    notifier.notify.side_effect = RuntimeError("webhook down")
    client = _mock_client(allowed=True)
    kernel = FailSafeKernel(client, webhook_notifier=notifier)

    request = DecisionRequest(action="file.write", agent_did="did:myth:scrivener:abc")
    response = DecisionResponse(allowed=True, verdict=VerdictDecision.PASS)
    # Should not raise
    kernel._on_decision(request, response)
    notifier.notify.assert_called_once()


def test_has_backends_includes_webhook():
    """_has_backends returns True when only webhook_notifier is configured."""
    notifier = MagicMock()
    client = _mock_client(allowed=True)
    kernel = FailSafeKernel(client, webhook_notifier=notifier)
    assert kernel._has_backends is True
    assert kernel.interceptor.on_decision is not None
