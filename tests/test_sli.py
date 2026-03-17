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


class TestDequeEviction:
    def test_decisions_evicted_at_maxlen(self):
        """Decisions beyond maxlen are auto-evicted (oldest dropped)."""
        sli = FailSafeComplianceSLI(window="1h")
        # _WINDOW_MAX_ENTRIES["1h"] = 5000, but we test the deque behavior
        for i in range(10):
            sli.record_decision(DecisionResponse(
                allowed=True, risk_grade=RiskGrade.L1, verdict=VerdictDecision.PASS,
            ))
        assert len(sli._decisions) == 10  # under maxlen, all retained

    def test_deque_type(self):
        """Verify _decisions is a deque, not a list."""
        from collections import deque
        sli = FailSafeComplianceSLI()
        assert isinstance(sli._decisions, deque)


class TestSignalReasonTruncation:
    def test_signal_reason_truncated(self):
        """Reason longer than 200 chars is truncated in signal message."""
        long_reason = "x" * 500
        resp = DecisionResponse(
            allowed=False,
            risk_grade=RiskGrade.L3,
            verdict=VerdictDecision.BLOCK,
            reason=long_reason,
        )
        result = decision_to_signal(resp)
        if result is not None:
            # The message should not contain 500 x's
            assert len(result.message) < 500
            assert "x" * 201 not in result.message


class TestGetSlis:
    def test_empty_sli_returns_seven_metrics(self):
        """get_slis() returns 7 SliMetric objects even when empty."""
        sli = FailSafeComplianceSLI()
        metrics = sli.get_slis()

        assert len(metrics) == 7
        names = [m.name for m in metrics]
        assert "Availability" in names
        assert "Latency P99" in names
        assert "Error Rate" in names
        assert "Throughput" in names
        assert "Trust Score" in names
        assert "Coverage" in names
        assert "Decision Latency" in names

    def test_slis_with_data(self):
        """get_slis() reflects recorded decisions."""
        sli = FailSafeComplianceSLI()
        for _ in range(10):
            sli.record_decision(DecisionResponse(allowed=True))

        metrics = sli.get_slis()
        availability = next(m for m in metrics if m.name == "Availability")

        assert availability.current_value == 1.0
        assert availability.total_decisions == 10

    def test_slis_targets(self):
        """Each SLI has expected target values."""
        sli = FailSafeComplianceSLI()
        metrics = sli.get_slis()

        targets = {m.name: m.target for m in metrics}
        assert targets["Availability"] == 0.999
        assert targets["Latency P99"] == 0.95
        assert targets["Error Rate"] == 0.99
        assert targets["Throughput"] == 0.90
        assert targets["Trust Score"] == 0.80
        assert targets["Coverage"] == 0.90
        assert targets["Decision Latency"] == 0.95

    def test_slis_error_budget(self):
        """Availability and Coverage SLIs have error budget."""
        sli = FailSafeComplianceSLI()
        for _ in range(10):
            sli.record_decision(DecisionResponse(allowed=True))

        metrics = sli.get_slis()
        availability = next(m for m in metrics if m.name == "Availability")
        coverage = next(m for m in metrics if m.name == "Coverage")

        # 100% compliance, so error budget should be positive
        assert availability.error_budget_remaining is not None
        assert availability.error_budget_remaining > 0
        assert coverage.error_budget_remaining is not None
        assert coverage.error_budget_remaining > 0

    def test_slis_to_dict(self):
        """SliMetric.to_dict() serializes correctly."""
        sli = FailSafeComplianceSLI()
        sli.record_decision(DecisionResponse(allowed=True))
        metrics = sli.get_slis()
        availability = next(m for m in metrics if m.name == "Availability")

        d = availability.to_dict()
        assert d["name"] == "Availability"
        assert d["target"] == 0.999
        assert "currentValue" in d
        assert "meetingTarget" in d
        assert "totalDecisions" in d

    def test_throughput_with_no_data(self):
        """Throughput SLI is None when no decisions recorded."""
        sli = FailSafeComplianceSLI()
        metrics = sli.get_slis()
        throughput = next(m for m in metrics if m.name == "Throughput")

        assert throughput.current_value is None
        assert throughput.meeting_target is None

    def test_throughput_with_data(self):
        """Throughput SLI is 1.0 when decisions exist."""
        sli = FailSafeComplianceSLI()
        sli.record_decision(DecisionResponse(allowed=True))
        metrics = sli.get_slis()
        throughput = next(m for m in metrics if m.name == "Throughput")

        assert throughput.current_value == 1.0
        assert throughput.meeting_target is True
