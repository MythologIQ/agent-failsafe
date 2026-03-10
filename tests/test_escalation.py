"""Tests for FailSafeApprovalBackend — L3 escalation routing."""

from dataclasses import dataclass, field
from typing import Any

import pytest

from agent_failsafe.escalation import FailSafeApprovalBackend
from agent_failsafe.types import DecisionRequest, DecisionResponse, RiskGrade


class MockClient:
    def __init__(self):
        self.requests: list[DecisionRequest] = []

    def evaluate(self, request: DecisionRequest) -> DecisionResponse:
        self.requests.append(request)
        return DecisionResponse(allowed=True, risk_grade=RiskGrade.L3)

    def classify_risk(self, *a):
        return RiskGrade.L1

    def get_shadow_genome(self, *a):
        return []


@dataclass
class MockEscalationRequest:
    request_id: str = "esc_001"
    agent_id: str = "did:myth:scrivener:abc"
    action: str = "file.write"
    reason: str = "Contains credentials"
    context_snapshot: dict[str, Any] = field(default_factory=dict)


class TestFailSafeApprovalBackend:
    def test_submit(self):
        client = MockClient()
        backend = FailSafeApprovalBackend(client=client)
        backend.submit(MockEscalationRequest())

        assert len(client.requests) == 1
        assert client.requests[0].action == "l3.approve"
        assert backend.get_decision("esc_001") is not None

    def test_approve(self):
        client = MockClient()
        backend = FailSafeApprovalBackend(client=client)
        backend.submit(MockEscalationRequest())

        result = backend.approve("esc_001", approver="admin@corp.com")
        assert result is True
        # Approval notification sent to FailSafe
        assert len(client.requests) == 2

    def test_deny(self):
        client = MockClient()
        backend = FailSafeApprovalBackend(client=client)
        backend.submit(MockEscalationRequest())

        result = backend.deny("esc_001")
        assert result is True
        assert len(client.requests) == 2

    def test_approve_unknown(self):
        backend = FailSafeApprovalBackend(client=MockClient())
        assert backend.approve("nonexistent") is False

    def test_deny_unknown(self):
        backend = FailSafeApprovalBackend(client=MockClient())
        assert backend.deny("nonexistent") is False

    def test_double_approve(self):
        client = MockClient()
        backend = FailSafeApprovalBackend(client=client)
        backend.submit(MockEscalationRequest())

        backend.approve("esc_001")
        result = backend.approve("esc_001")  # Already resolved
        assert result is False

    def test_list_pending(self):
        client = MockClient()
        backend = FailSafeApprovalBackend(client=client)

        backend.submit(MockEscalationRequest(request_id="a"))
        backend.submit(MockEscalationRequest(request_id="b"))
        backend.approve("a")

        pending = backend.list_pending()
        assert len(pending) == 1

    def test_max_requests_eviction(self):
        """Oldest entries evicted when max_requests exceeded."""
        client = MockClient()
        backend = FailSafeApprovalBackend(client=client, max_requests=3)

        for i in range(5):
            backend.submit(MockEscalationRequest(request_id=f"req_{i}"))

        assert len(backend._requests) == 3
        # Oldest (req_0, req_1) should be evicted
        assert "req_0" not in backend._requests
        assert "req_1" not in backend._requests
        # Newest should remain
        assert "req_4" in backend._requests
