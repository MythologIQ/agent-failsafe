"""Tests for GovernancePipeline — full lifecycle orchestration."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from agent_failsafe.pipeline import (
    GovernancePipeline,
    PipelineResult,
    PipelineStage,
    create_pipeline,
)
from agent_failsafe.types import (
    DecisionRequest,
    DecisionResponse,
    RiskGrade,
    VerdictDecision,
)


# ── helpers ──────────────────────────────────────────────────────────────


def _req(action: str = "file.write", agent_did: str = "did:myth:scrivener:abc") -> DecisionRequest:
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


def _mock_client(response: DecisionResponse) -> MagicMock:
    client = MagicMock()
    client.evaluate.return_value = response
    return client


# ── TestPipelineResult ───────────────────────────────────────────────────


class TestPipelineResult:
    def test_frozen(self) -> None:
        result = PipelineResult(stage=PipelineStage.AUDITED, allowed=True)
        with pytest.raises(AttributeError):
            result.allowed = False  # type: ignore[misc]

    def test_defaults(self) -> None:
        result = PipelineResult(stage=PipelineStage.GOVERNANCE, allowed=False)
        assert result.governance is None
        assert result.circuit_breaker_open is False
        assert result.execution_ring == 3
        assert result.kill_reason is None
        assert result.halted_reason == ""

    def test_stage_values(self) -> None:
        assert len(PipelineStage) == 4
        assert PipelineStage.GOVERNANCE.value == "governance"
        assert PipelineStage.SRE_HEALTH.value == "sre_health"
        assert PipelineStage.RING_ASSIGNED.value == "ring_assigned"
        assert PipelineStage.AUDITED.value == "audited"


# ── TestGovernancePipeline ───────────────────────────────────────────────


class TestGovernancePipeline:
    def test_denied_at_governance(self) -> None:
        resp = _resp(allowed=False, verdict=VerdictDecision.BLOCK, reason="blocked")
        pipeline = GovernancePipeline(client=_mock_client(resp))
        result = pipeline.evaluate(_req())

        assert result.allowed is False
        assert result.stage == PipelineStage.GOVERNANCE
        assert result.governance is resp
        assert result.halted_reason == "blocked"

    def test_l3_escalate_blocks(self) -> None:
        resp = _resp(allowed=True, risk_grade=RiskGrade.L3, verdict=VerdictDecision.ESCALATE)
        pipeline = GovernancePipeline(client=_mock_client(resp))
        result = pipeline.evaluate(_req())

        assert result.allowed is False
        assert result.stage == PipelineStage.GOVERNANCE
        assert "L3" in result.halted_reason

    def test_circuit_breaker_open(self) -> None:
        resp = _resp(allowed=True)
        pipeline = GovernancePipeline(
            client=_mock_client(resp),
            circuit_breaker_fn=lambda _: False,
        )
        result = pipeline.evaluate(_req())

        assert result.allowed is False
        assert result.stage == PipelineStage.SRE_HEALTH
        assert result.circuit_breaker_open is True
        assert result.governance is resp

    def test_circuit_breaker_not_configured(self) -> None:
        resp = _resp(allowed=True)
        pipeline = GovernancePipeline(client=_mock_client(resp))
        result = pipeline.evaluate(_req())

        assert result.allowed is True
        assert result.stage == PipelineStage.AUDITED

    def test_full_pipeline_allowed(self) -> None:
        resp = _resp(allowed=True, risk_grade=RiskGrade.L1, verdict=VerdictDecision.PASS)
        sli = MagicMock()
        audit_sink = MagicMock()
        pipeline = GovernancePipeline(
            client=_mock_client(resp),
            sli=sli,
            audit_sink=audit_sink,
            circuit_breaker_fn=lambda _: True,
        )
        result = pipeline.evaluate(_req())

        assert result.allowed is True
        assert result.stage == PipelineStage.AUDITED
        assert result.execution_ring == 2
        assert result.kill_reason is None
        sli.record_decision.assert_called_once_with(resp)
        audit_sink.write.assert_called_once()

    def test_ring_assignment_l3(self) -> None:
        resp = _resp(allowed=True, risk_grade=RiskGrade.L3, verdict=VerdictDecision.WARN)
        pipeline = GovernancePipeline(client=_mock_client(resp))
        result = pipeline.evaluate(_req())

        assert result.execution_ring == 2  # WARN overrides L3 risk

    def test_ring_assignment_l1(self) -> None:
        resp = _resp(allowed=True, risk_grade=RiskGrade.L1, verdict=VerdictDecision.PASS)
        pipeline = GovernancePipeline(client=_mock_client(resp))
        result = pipeline.evaluate(_req())

        assert result.execution_ring == 2

    def test_kill_reason_quarantine(self) -> None:
        resp = _resp(allowed=False, verdict=VerdictDecision.QUARANTINE)
        pipeline = GovernancePipeline(client=_mock_client(resp))
        result = pipeline.evaluate(_req())

        # QUARANTINE is denied at governance stage, but kill_reason is still extracted
        assert result.stage == PipelineStage.GOVERNANCE

    def test_sli_recorded(self) -> None:
        resp = _resp(allowed=True)
        sli = MagicMock()
        pipeline = GovernancePipeline(client=_mock_client(resp), sli=sli)
        pipeline.evaluate(_req())

        sli.record_decision.assert_called_once_with(resp)

    def test_audit_written(self) -> None:
        resp = _resp(allowed=True)
        audit_sink = MagicMock()
        pipeline = GovernancePipeline(client=_mock_client(resp), audit_sink=audit_sink)
        pipeline.evaluate(_req())

        audit_sink.write.assert_called_once()

    def test_no_backends(self) -> None:
        resp = _resp(allowed=True)
        pipeline = GovernancePipeline(client=_mock_client(resp))
        result = pipeline.evaluate(_req())

        assert result.allowed is True
        assert result.stage == PipelineStage.AUDITED

    def test_quarantine_triggers_kill_switch(self) -> None:
        """QUARANTINE with kill_switch_fn calls the fn with correct args."""
        resp = _resp(allowed=True, verdict=VerdictDecision.QUARANTINE)
        # QUARANTINE + allowed=True is unusual, but tests kill path without governance halt
        kill_fn = MagicMock(return_value=None)
        pipeline = GovernancePipeline(
            client=_mock_client(resp), kill_switch_fn=kill_fn,
        )
        result = pipeline.evaluate(_req(agent_did="did:myth:scrivener:abc"))

        kill_fn.assert_called_once_with("did:myth:scrivener:abc", "", "behavioral_drift")
        assert result.kill_reason == "behavioral_drift"
        assert result.kill_executed is True

    def test_kill_switch_failure_does_not_halt_pipeline(self) -> None:
        """kill_switch_fn raises, pipeline still returns result."""
        resp = _resp(allowed=True, verdict=VerdictDecision.QUARANTINE)
        kill_fn = MagicMock(side_effect=RuntimeError("switch down"))
        pipeline = GovernancePipeline(
            client=_mock_client(resp), kill_switch_fn=kill_fn,
        )
        result = pipeline.evaluate(_req())

        assert result.allowed is True
        assert result.stage == PipelineStage.AUDITED
        assert result.kill_reason == "behavioral_drift"
        assert result.kill_executed is False

    def test_no_kill_switch_fn_skips_kill(self) -> None:
        """Without kill_switch_fn, QUARANTINE produces kill_reason but no fn call."""
        resp = _resp(allowed=True, verdict=VerdictDecision.QUARANTINE)
        pipeline = GovernancePipeline(client=_mock_client(resp))
        result = pipeline.evaluate(_req())

        assert result.kill_reason == "behavioral_drift"
        assert result.kill_executed is False

    def test_client_exception_fails_open(self) -> None:
        client = MagicMock()
        client.evaluate.side_effect = RuntimeError("connection lost")
        pipeline = GovernancePipeline(client=client)
        result = pipeline.evaluate(_req())

        assert result.allowed is True
        assert result.stage == PipelineStage.GOVERNANCE
        assert "fail-open" in result.halted_reason


# ── TestCreatePipeline ───────────────────────────────────────────────────


class TestCreatePipeline:
    def test_factory_returns_pipeline(self) -> None:
        client = MagicMock()
        pipeline = create_pipeline(client)
        assert isinstance(pipeline, GovernancePipeline)

    def test_factory_forwards_kwargs(self) -> None:
        client = MagicMock()
        sli = MagicMock()
        pipeline = create_pipeline(client, sli=sli)
        assert pipeline.sli is sli


class TestFailOpenFailClosed:
    def test_fail_closed_raises(self) -> None:
        """fail_open=False re-raises client exceptions."""
        client = MagicMock()
        client.evaluate.side_effect = RuntimeError("connection lost")
        pipeline = GovernancePipeline(client=client, fail_open=False)
        with pytest.raises(RuntimeError, match="connection lost"):
            pipeline.evaluate(_req())

    def test_fail_open_default_is_true(self) -> None:
        """Default fail_open is True for backward compatibility."""
        client = MagicMock()
        pipeline = GovernancePipeline(client=client)
        assert pipeline.fail_open is True

    def test_fail_open_returns_allowed(self) -> None:
        """fail_open=True returns allowed result on client error."""
        client = MagicMock()
        client.evaluate.side_effect = RuntimeError("down")
        pipeline = GovernancePipeline(client=client, fail_open=True)
        result = pipeline.evaluate(_req())
        assert result.allowed is True
        assert "fail-open" in result.halted_reason
