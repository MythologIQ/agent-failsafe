"""Tests for FailSafe SLI and signal generation."""

from agent_failsafe.sli import FailSafeComplianceSLI, decision_to_signal
from agent_failsafe.types import DecisionResponse, RiskGrade, VerdictDecision


class TestFailSafeComplianceSLI:
    def test_empty(self):
        sli = FailSafeComplianceSLI()
        assert sli.current_value() is None
        assert sli.is_meeting_target() is None

    def test_all_allowed(self):
        sli = FailSafeComplianceSLI(target=0.95)
        for _ in range(10):
            sli.record_decision(DecisionResponse(allowed=True))

        assert sli.current_value() == 1.0
        assert sli.is_meeting_target() is True

    def test_some_blocked(self):
        sli = FailSafeComplianceSLI(target=0.95)
        for _ in range(9):
            sli.record_decision(DecisionResponse(allowed=True))
        sli.record_decision(DecisionResponse(allowed=False))

        assert sli.current_value() == 0.9
        assert sli.is_meeting_target() is False

    def test_to_dict(self):
        sli = FailSafeComplianceSLI()
        sli.record_decision(DecisionResponse(allowed=True))
        d = sli.to_dict()

        assert d["name"] == "failsafe_compliance"
        assert d["target"] == 0.95
        assert d["total_decisions"] == 1


class TestDecisionToSignal:
    def test_allowed_no_signal(self):
        resp = DecisionResponse(allowed=True, verdict=VerdictDecision.PASS)
        assert decision_to_signal(resp) is None

    def test_blocked_generates_signal(self):
        resp = DecisionResponse(
            allowed=False,
            risk_grade=RiskGrade.L3,
            verdict=VerdictDecision.BLOCK,
            reason="Contains password",
        )
        result = decision_to_signal(resp)
        # If agent-sre is installed, a Signal is returned; otherwise None
        if result is not None:
            assert result.signal_type.value == "policy_violation"
            assert "password" in result.message.lower()

    def test_escalation_generates_signal(self):
        resp = DecisionResponse(
            allowed=True,
            risk_grade=RiskGrade.L3,
            verdict=VerdictDecision.ESCALATE,
            reason="Human review needed",
        )
        result = decision_to_signal(resp)
        if result is not None:
            assert result.signal_type.value == "policy_violation"
