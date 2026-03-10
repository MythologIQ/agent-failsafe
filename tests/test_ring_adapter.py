"""Tests for the FailSafe ring adapter."""

from __future__ import annotations

import pytest

from agent_failsafe.ring_adapter import FailSafeRingAdapter
from agent_failsafe.types import DecisionResponse, RiskGrade, VerdictDecision


@pytest.fixture
def adapter() -> FailSafeRingAdapter:
    return FailSafeRingAdapter()


def _response(
    verdict: VerdictDecision = VerdictDecision.PASS,
    risk_grade: RiskGrade = RiskGrade.L1,
) -> DecisionResponse:
    return DecisionResponse(
        allowed=verdict not in (VerdictDecision.BLOCK, VerdictDecision.QUARANTINE),
        verdict=verdict,
        risk_grade=risk_grade,
    )


class TestDecisionToRing:
    def test_l1_maps_to_ring2(self, adapter):
        resp = _response(VerdictDecision.PASS, RiskGrade.L1)
        assert adapter.decision_to_ring(resp) == 2

    def test_l2_warn_maps_to_ring2(self, adapter):
        resp = _response(VerdictDecision.WARN, RiskGrade.L2)
        assert adapter.decision_to_ring(resp) == 2

    def test_l3_maps_to_ring3(self, adapter):
        resp = _response(VerdictDecision.ESCALATE, RiskGrade.L3)
        assert adapter.decision_to_ring(resp) == 3

    def test_block_maps_to_ring3(self, adapter):
        resp = _response(VerdictDecision.BLOCK, RiskGrade.L2)
        assert adapter.decision_to_ring(resp) == 3

    def test_quarantine_maps_to_ring3(self, adapter):
        resp = _response(VerdictDecision.QUARANTINE, RiskGrade.L1)
        assert adapter.decision_to_ring(resp) == 3

    def test_verdict_overrides_risk(self, adapter):
        """L1 risk + BLOCK verdict → ring 3 (verdict wins)."""
        resp = _response(VerdictDecision.BLOCK, RiskGrade.L1)
        assert adapter.decision_to_ring(resp) == 3


class TestDecisionToKillReason:
    def test_quarantine_triggers_kill(self, adapter):
        resp = _response(VerdictDecision.QUARANTINE)
        assert adapter.decision_to_kill_reason(resp) == "behavioral_drift"

    def test_block_no_kill(self, adapter):
        resp = _response(VerdictDecision.BLOCK)
        assert adapter.decision_to_kill_reason(resp) is None

    def test_pass_no_kill(self, adapter):
        resp = _response(VerdictDecision.PASS)
        assert adapter.decision_to_kill_reason(resp) is None

    def test_escalate_no_kill(self, adapter):
        resp = _response(VerdictDecision.ESCALATE)
        assert adapter.decision_to_kill_reason(resp) is None

    def test_warn_no_kill(self, adapter):
        resp = _response(VerdictDecision.WARN)
        assert adapter.decision_to_kill_reason(resp) is None


class TestTrustScoreToRing:
    def test_above_threshold(self, adapter):
        assert adapter.trust_score_to_ring(0.8) == 2

    def test_below_threshold(self, adapter):
        assert adapter.trust_score_to_ring(0.3) == 3

    def test_at_threshold(self, adapter):
        """Exactly 0.60 → sandbox (not standard)."""
        assert adapter.trust_score_to_ring(0.60) == 3

    def test_max_score(self, adapter):
        assert adapter.trust_score_to_ring(1.0) == 2

    def test_zero_score(self, adapter):
        assert adapter.trust_score_to_ring(0.0) == 3


class TestTypedRingMethods:
    """Tests for hypervisor-typed methods (ExecutionRing, KillReason, KillSwitch)."""

    def test_decision_to_execution_ring_returns_enum(self, adapter, monkeypatch):
        """With hypervisor available, returns ExecutionRing enum."""
        from enum import IntEnum

        class FakeRing(IntEnum):
            RING_2_STANDARD = 2
            RING_3_SANDBOX = 3

        import agent_failsafe.ring_adapter as mod
        monkeypatch.setattr(mod, "_ExecutionRing", FakeRing)
        monkeypatch.setattr(mod, "_hypervisor_checked", True)
        resp = _response(VerdictDecision.PASS, RiskGrade.L1)
        result = adapter.decision_to_execution_ring(resp)
        assert result == FakeRing.RING_2_STANDARD
        assert isinstance(result, FakeRing)

    def test_decision_to_execution_ring_no_hypervisor(self, adapter, monkeypatch):
        """Without hypervisor, raises ImportError."""
        import agent_failsafe.ring_adapter as mod
        monkeypatch.setattr(mod, "_ExecutionRing", None)
        monkeypatch.setattr(mod, "_hypervisor_checked", True)
        resp = _response(VerdictDecision.PASS, RiskGrade.L1)
        with pytest.raises(ImportError, match="agent-hypervisor"):
            adapter.decision_to_execution_ring(resp)

    def test_decision_to_kill_reason_enum_quarantine(self, adapter, monkeypatch):
        """QUARANTINE returns KillReason.BEHAVIORAL_DRIFT."""
        from enum import Enum

        class FakeKillReason(str, Enum):
            BEHAVIORAL_DRIFT = "behavioral_drift"

        import agent_failsafe.ring_adapter as mod
        monkeypatch.setattr(mod, "_KillReason", FakeKillReason)
        monkeypatch.setattr(mod, "_hypervisor_checked", True)
        resp = _response(VerdictDecision.QUARANTINE)
        result = adapter.decision_to_kill_reason_enum(resp)
        assert result == FakeKillReason.BEHAVIORAL_DRIFT

    def test_decision_to_kill_reason_enum_pass_returns_none(self, adapter, monkeypatch):
        """PASS verdict returns None (no kill)."""
        resp = _response(VerdictDecision.PASS)
        result = adapter.decision_to_kill_reason_enum(resp)
        assert result is None

    def test_decision_to_kill_reason_enum_no_hypervisor(self, adapter, monkeypatch):
        """Without hypervisor, QUARANTINE raises ImportError."""
        import agent_failsafe.ring_adapter as mod
        monkeypatch.setattr(mod, "_KillReason", None)
        monkeypatch.setattr(mod, "_hypervisor_checked", True)
        resp = _response(VerdictDecision.QUARANTINE)
        with pytest.raises(ImportError, match="agent-hypervisor"):
            adapter.decision_to_kill_reason_enum(resp)

    def test_request_kill_quarantine(self, adapter, monkeypatch):
        """QUARANTINE triggers KillSwitch.kill() with correct args."""
        from enum import Enum
        from unittest.mock import MagicMock

        class FakeKillReason(str, Enum):
            BEHAVIORAL_DRIFT = "behavioral_drift"

        mock_result = MagicMock()
        mock_switch_cls = MagicMock()
        mock_switch_cls.return_value.kill.return_value = mock_result

        import agent_failsafe.ring_adapter as mod
        monkeypatch.setattr(mod, "_KillReason", FakeKillReason)
        monkeypatch.setattr(mod, "_KillSwitch", mock_switch_cls)
        monkeypatch.setattr(mod, "_hypervisor_checked", True)

        resp = _response(VerdictDecision.QUARANTINE)
        result = adapter.request_kill(resp, "did:myth:scrivener:abc", "session-1")
        assert result is mock_result
        mock_switch_cls.return_value.kill.assert_called_once_with(
            agent_did="did:myth:scrivener:abc",
            session_id="session-1",
            reason=FakeKillReason.BEHAVIORAL_DRIFT,
            details="FailSafe QUARANTINE",
        )

    def test_request_kill_pass_returns_none(self, adapter):
        """PASS verdict skips kill entirely (no hypervisor needed)."""
        resp = _response(VerdictDecision.PASS)
        result = adapter.request_kill(resp, "did:myth:scrivener:abc", "session-1")
        assert result is None

    def test_request_kill_no_hypervisor(self, adapter, monkeypatch):
        """Without hypervisor, QUARANTINE raises ImportError."""
        import agent_failsafe.ring_adapter as mod
        monkeypatch.setattr(mod, "_KillReason", None)
        monkeypatch.setattr(mod, "_hypervisor_checked", True)
        resp = _response(VerdictDecision.QUARANTINE)
        with pytest.raises(ImportError, match="agent-hypervisor"):
            adapter.request_kill(resp, "did:myth:scrivener:abc", "session-1")


class TestNeverAssignsPrivilegedRings:
    def test_no_mapping_produces_ring_0_or_1(self, adapter):
        """Verify no combination of verdict + risk grade produces ring 0 or 1."""
        for verdict in VerdictDecision:
            for risk_grade in RiskGrade:
                resp = _response(verdict, risk_grade)
                ring = adapter.decision_to_ring(resp)
                assert ring >= 2, (
                    f"Ring {ring} assigned for {verdict.value}/{risk_grade.value}"
                )
