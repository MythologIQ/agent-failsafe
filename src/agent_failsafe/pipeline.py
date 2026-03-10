"""Full lifecycle governance pipeline.

Sequences the governance evaluation, SRE health check, ring assignment,
SLI recording, and audit logging into a single composable pipeline.
Returns an immutable ``PipelineResult`` capturing the full decision trail.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable

from .audit_sink import FailSafeAuditSink, decision_to_audit_entry
from .ring_adapter import FailSafeRingAdapter
from .sli import FailSafeComplianceSLI
from .types import (
    DecisionRequest,
    DecisionResponse,
    FailSafeClient,
    VerdictDecision,
)

logger = logging.getLogger(__name__)


class PipelineStage(Enum):
    """Marks how far the pipeline progressed before returning."""

    GOVERNANCE = "governance"
    SRE_HEALTH = "sre_health"
    RING_ASSIGNED = "ring_assigned"
    AUDITED = "audited"


@dataclass(frozen=True)
class PipelineResult:
    """Immutable record of a complete governance pipeline evaluation."""

    stage: PipelineStage
    allowed: bool
    governance: DecisionResponse | None = None
    circuit_breaker_open: bool = False
    execution_ring: int = 3
    kill_reason: str | None = None
    kill_executed: bool = False
    halted_reason: str = ""


def _governance_halt(
    response: DecisionResponse,
    reason: str = "",
) -> PipelineResult:
    """Build a PipelineResult for a governance-stage halt."""
    return PipelineResult(
        stage=PipelineStage.GOVERNANCE,
        allowed=False,
        governance=response,
        halted_reason=reason or response.reason,
    )


class GovernancePipeline:
    """Composes existing adapters into a sequential governance pipeline.

    Stages: governance eval -> circuit breaker -> ring assignment -> SLI -> audit.
    All backends are optional. The pipeline works with zero configuration
    beyond the required ``FailSafeClient``.

    Args:
        client: FailSafeClient implementation for governance evaluation.
        ring_adapter: Maps risk grades to execution rings. Defaults to standard adapter.
        audit_sink: Writes Merkle-chained audit entries. Optional.
        sli: Records compliance metrics. Optional.
        circuit_breaker_fn: ``Callable[[agent_did], is_available]``. Optional.
        kill_switch_fn: ``Callable[[agent_did, session_id, kill_reason], Any]``. Optional.
    """

    def __init__(
        self,
        client: FailSafeClient,
        ring_adapter: FailSafeRingAdapter | None = None,
        audit_sink: FailSafeAuditSink | None = None,
        sli: FailSafeComplianceSLI | None = None,
        circuit_breaker_fn: Callable[[str], bool] | None = None,
        kill_switch_fn: Callable[[str, str, str], Any] | None = None,
    ) -> None:
        self.client = client
        self.ring_adapter = ring_adapter or FailSafeRingAdapter()
        self.audit_sink = audit_sink
        self.sli = sli
        self.circuit_breaker_fn = circuit_breaker_fn
        self.kill_switch_fn = kill_switch_fn

    def evaluate(self, request: DecisionRequest) -> PipelineResult:
        """Run the full governance pipeline and return an immutable result."""
        response = self._governance_stage(request)
        if response is None:
            return self._fail_open_result(request)

        halt = self._check_governance_halt(response)
        if halt is not None:
            return halt

        sre_halt = self._sre_health_stage(request.agent_did, response)
        if sre_halt is not None:
            return sre_halt

        ring, kill_reason, kill_executed = self._ring_stage(response, request.agent_did)
        self._record_and_audit(request, response)

        return PipelineResult(
            stage=PipelineStage.AUDITED,
            allowed=True,
            governance=response,
            execution_ring=ring,
            kill_reason=kill_reason,
            kill_executed=kill_executed,
        )

    def _governance_stage(self, request: DecisionRequest) -> DecisionResponse | None:
        """Evaluate governance policy. Returns None on client failure (fail-open)."""
        try:
            return self.client.evaluate(request)
        except Exception as exc:
            logger.error("Pipeline governance eval failed: %s", exc)
            return None

    def _check_governance_halt(self, response: DecisionResponse) -> PipelineResult | None:
        """Check if governance denies or escalates. Returns halt result or None."""
        if not response.allowed:
            return _governance_halt(response)
        if response.verdict == VerdictDecision.ESCALATE:
            return _governance_halt(response, "L3 human approval required")
        return None

    def _sre_health_stage(
        self, agent_did: str, response: DecisionResponse,
    ) -> PipelineResult | None:
        """Check circuit breaker. Returns halt result or None to continue."""
        if self.circuit_breaker_fn is None:
            return None
        if self.circuit_breaker_fn(agent_did):
            return None
        return PipelineResult(
            stage=PipelineStage.SRE_HEALTH,
            allowed=False,
            governance=response,
            circuit_breaker_open=True,
            halted_reason="circuit breaker open for agent",
        )

    def _ring_stage(
        self, response: DecisionResponse, agent_did: str,
    ) -> tuple[int, str | None, bool]:
        """Assign execution ring, extract kill reason, and fire kill switch."""
        ring = self.ring_adapter.decision_to_ring(response)
        kill_reason = self.ring_adapter.decision_to_kill_reason(response)
        kill_executed = self._try_kill(agent_did, kill_reason)
        return ring, kill_reason, kill_executed

    def _try_kill(self, agent_did: str, kill_reason: str | None) -> bool:
        """Attempt to fire the kill switch. Returns True if kill executed."""
        if kill_reason is None or self.kill_switch_fn is None:
            return False
        try:
            self.kill_switch_fn(agent_did, "", kill_reason)
            return True
        except Exception as exc:
            logger.warning("Kill switch failed: %s", exc)
            return False

    def _record_and_audit(
        self, request: DecisionRequest, response: DecisionResponse,
    ) -> None:
        """Record SLI metrics and write audit entry."""
        if self.sli is not None:
            self.sli.record_decision(response)
        if self.audit_sink is not None:
            entry = decision_to_audit_entry(request, response)
            self.audit_sink.write(entry)

    def _fail_open_result(self, request: DecisionRequest) -> PipelineResult:
        """Build a fail-open result when the governance client is unavailable."""
        return PipelineResult(
            stage=PipelineStage.GOVERNANCE,
            allowed=True,
            halted_reason=f"FailSafe unavailable; fail-open for {request.action}",
        )


def create_pipeline(client: FailSafeClient, **kwargs: Any) -> GovernancePipeline:
    """Convenience factory for creating a GovernancePipeline."""
    return GovernancePipeline(client, **kwargs)
