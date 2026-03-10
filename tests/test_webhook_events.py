"""Tests for webhook event translation — decisions to WebhookEvent objects."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from agent_failsafe.types import (
    DecisionRequest,
    DecisionResponse,
    RiskGrade,
    VerdictDecision,
)
from agent_failsafe.webhook_events import (
    _map_event_type,
    _map_severity,
    decision_to_webhook_event,
    decisions_to_webhook_events,
)


# ── helpers ──────────────────────────────────────────────────────────────


def _req(
    action: str = "file.write",
    agent_did: str = "did:myth:scrivener:abc",
) -> DecisionRequest:
    return DecisionRequest(action=action, agent_did=agent_did)


def _resp(
    allowed: bool = True,
    risk_grade: RiskGrade = RiskGrade.L1,
    verdict: VerdictDecision = VerdictDecision.PASS,
    reason: str = "",
) -> DecisionResponse:
    return DecisionResponse(
        allowed=allowed, risk_grade=risk_grade, verdict=verdict, reason=reason,
    )


# ── TestMapEventType ─────────────────────────────────────────────────────


class TestMapEventType:
    def test_block_maps_to_tool_call_blocked(self) -> None:
        assert _map_event_type(_resp(verdict=VerdictDecision.BLOCK)) == "tool_call_blocked"

    def test_quarantine_maps_to_agent_quarantined(self) -> None:
        assert _map_event_type(_resp(verdict=VerdictDecision.QUARANTINE)) == "agent_quarantined"

    def test_denied_maps_to_policy_violation(self) -> None:
        resp = _resp(allowed=False, verdict=VerdictDecision.WARN)
        assert _map_event_type(resp) == "policy_violation"

    def test_escalate_maps_to_escalation_required(self) -> None:
        assert _map_event_type(_resp(verdict=VerdictDecision.ESCALATE)) == "escalation_required"

    def test_warn_maps_to_governance_warning(self) -> None:
        assert _map_event_type(_resp(verdict=VerdictDecision.WARN)) == "governance_warning"

    def test_pass_maps_to_governance_decision(self) -> None:
        assert _map_event_type(_resp(verdict=VerdictDecision.PASS)) == "governance_decision"


# ── TestMapSeverity ──────────────────────────────────────────────────────


class TestMapSeverity:
    def test_block_is_critical(self) -> None:
        assert _map_severity(_resp(verdict=VerdictDecision.BLOCK, risk_grade=RiskGrade.L1)) == "critical"

    def test_quarantine_is_critical(self) -> None:
        assert _map_severity(_resp(verdict=VerdictDecision.QUARANTINE)) == "critical"

    def test_l3_is_critical(self) -> None:
        assert _map_severity(_resp(risk_grade=RiskGrade.L3)) == "critical"

    def test_l2_pass_is_warning(self) -> None:
        assert _map_severity(_resp(risk_grade=RiskGrade.L2)) == "warning"

    def test_denied_l1_is_warning(self) -> None:
        assert _map_severity(_resp(allowed=False, risk_grade=RiskGrade.L1, verdict=VerdictDecision.WARN)) == "warning"

    def test_l1_pass_is_info(self) -> None:
        assert _map_severity(_resp(risk_grade=RiskGrade.L1)) == "info"


# ── TestDecisionToWebhookEvent ───────────────────────────────────────────


class TestDecisionToWebhookEvent:
    def test_returns_simplenamespace_without_agent_os(self, monkeypatch) -> None:
        import agent_failsafe.webhook_events as mod

        monkeypatch.setattr(mod, "_WebhookEvent", None)
        monkeypatch.setattr(mod, "_agent_os_checked", True)
        event = decision_to_webhook_event(_req(), _resp())
        assert isinstance(event, SimpleNamespace)
        assert event.event_type == "governance_decision"
        assert event.agent_id == "did:myth:scrivener:abc"
        assert event.action == "file.write"
        assert event.severity == "info"

    def test_returns_webhook_event_when_available(self, monkeypatch) -> None:
        from dataclasses import dataclass, field
        from typing import Any

        @dataclass
        class FakeWebhookEvent:
            event_type: str = ""
            agent_id: str = ""
            action: str = ""
            details: dict[str, Any] = field(default_factory=dict)
            severity: str = "info"
            timestamp: str = ""

        import agent_failsafe.webhook_events as mod

        monkeypatch.setattr(mod, "_WebhookEvent", FakeWebhookEvent)
        monkeypatch.setattr(mod, "_agent_os_checked", True)
        event = decision_to_webhook_event(_req(), _resp())
        assert isinstance(event, FakeWebhookEvent)
        assert event.event_type == "governance_decision"

    def test_details_includes_all_fields(self) -> None:
        event = decision_to_webhook_event(
            _req(action="file.delete", agent_did="did:myth:sentinel:xyz"),
            _resp(risk_grade=RiskGrade.L2, verdict=VerdictDecision.WARN, reason="risky"),
        )
        d = event.details
        assert d["risk_grade"] == "L2"
        assert d["verdict"] == "WARN"
        assert d["reason"] == "risky"
        assert d["agent_did"] == "did:myth:sentinel:xyz"
        assert "artifact_path" in d
        assert "nonce" in d

    def test_block_verdict_produces_critical_event(self) -> None:
        event = decision_to_webhook_event(
            _req(), _resp(allowed=False, verdict=VerdictDecision.BLOCK),
        )
        assert event.event_type == "tool_call_blocked"
        assert event.severity == "critical"

    def test_l1_pass_produces_info_event(self) -> None:
        event = decision_to_webhook_event(_req(), _resp())
        assert event.event_type == "governance_decision"
        assert event.severity == "info"


# ── TestBatchTranslation ────────────────────────────────────────────────


class TestBatchTranslation:
    def test_translates_multiple_pairs(self) -> None:
        pairs = [
            (_req(), _resp()),
            (_req(action="file.delete"), _resp(verdict=VerdictDecision.BLOCK)),
        ]
        events = decisions_to_webhook_events(pairs)
        assert len(events) == 2
        assert events[0].event_type == "governance_decision"
        assert events[1].event_type == "tool_call_blocked"

    def test_empty_list(self) -> None:
        assert decisions_to_webhook_events([]) == []
