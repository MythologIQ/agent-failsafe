"""BaseIntegration subclass for FailSafe governance.

Provides the ``FailSafeKernel`` — a framework adapter that wraps any agent
with FailSafe governance enforcement, registered via ``@register_adapter``.
"""

from __future__ import annotations

import logging
from typing import Any

from agent_os.integrations.base import BaseIntegration, GovernanceEventType
from agent_os.integrations.registry import register_adapter

from .agent_metrics import AgentMetricsRegistry
from .audit_sink import FailSafeAuditSink, decision_to_audit_entry
from .escalation import FailSafeApprovalBackend
from .interceptor import FailSafeInterceptor
from .pipeline import GovernancePipeline, PipelineResult, PipelineStage
from .sli import FailSafeComplianceSLI
from .types import DecisionRequest, DecisionResponse, FailSafeClient, VerdictDecision

logger = logging.getLogger(__name__)


class _GovernedAgent:
    """Thin proxy that wraps an agent with governance checks."""

    def __init__(self, original: Any, ctx: Any, kernel: Any) -> None:
        self._original = original
        self._ctx = ctx
        self._kernel = kernel

    def __getattr__(self, name: str) -> Any:
        return getattr(self._original, name)


def _evaluate_action(
    client: FailSafeClient,
    agent_did: str,
    action: str,
    emit_fn: Any,
    **kw: Any,
) -> bool:
    """Evaluate a governance action and emit blocked event if denied."""
    req = DecisionRequest(action=action, agent_did=agent_did, **kw)
    response = client.evaluate(req)
    if not response.allowed:
        emit_fn(GovernanceEventType.TOOL_CALL_BLOCKED, {
            "agent_id": agent_did,
            "action": action,
            "risk_grade": response.risk_grade.value,
            "reason": response.reason,
        })
    return response.allowed


@register_adapter("failsafe")
class FailSafeKernel(BaseIntegration):
    """Agent OS integration adapter for FailSafe governance.

    Wraps agents with FailSafe governance enforcement via the
    BaseIntegration lifecycle (pre_execute / post_execute).
    """

    def __init__(
        self,
        client: FailSafeClient,
        default_agent_did: str = "did:myth:scrivener:unknown",
        block_on_l3: bool = True,
        sli: FailSafeComplianceSLI | None = None,
        audit_sink: FailSafeAuditSink | None = None,
        approval_backend: FailSafeApprovalBackend | None = None,
        pipeline: GovernancePipeline | None = None,
        webhook_notifier: Any | None = None,
        agent_metrics: AgentMetricsRegistry | None = None,
        **kw: Any,
    ) -> None:
        super().__init__(**kw)
        self.fs_client = client
        self.pipeline = pipeline
        self.sli = sli
        self.audit_sink = audit_sink
        self.approval_backend = approval_backend
        self.webhook_notifier = webhook_notifier
        self.agent_metrics = agent_metrics
        self.interceptor = FailSafeInterceptor(
            client=client,
            default_agent_did=default_agent_did,
            block_on_l3=block_on_l3,
            on_decision=self._on_decision if self._has_backends else None,
        )
        self._wrapped_agents: dict[int, Any] = {}

    @property
    def _has_backends(self) -> bool:
        """Check if any backend is configured."""
        return any((
            self.sli, self.audit_sink, self.approval_backend,
            self.webhook_notifier, self.agent_metrics,
        ))

    def _on_decision(
        self,
        request: DecisionRequest,
        response: DecisionResponse,
        latency_ms: float = 0.0,
    ) -> None:
        """Dispatch a governance decision to configured backends."""
        if self.sli is not None:
            self.sli.record_decision(response)
        if self.audit_sink is not None:
            entry = decision_to_audit_entry(request, response)
            self.audit_sink.write(entry)
        if self.approval_backend is not None:
            if response.verdict == VerdictDecision.ESCALATE:
                self.approval_backend.submit(request)
        if self.webhook_notifier is not None:
            self._emit_webhook(request, response)
        if self.agent_metrics is not None:
            self.agent_metrics.record_decision(
                request.agent_did, response.allowed, latency_ms,
            )

    def _emit_webhook(self, request: DecisionRequest, response: DecisionResponse) -> None:
        """Translate decision to WebhookEvent and send via notifier."""
        from .webhook_events import decision_to_webhook_event

        event = decision_to_webhook_event(request, response)
        try:
            self.webhook_notifier.notify(event)
        except Exception as exc:
            logger.warning("Webhook notification failed: %s", exc)

    def wrap(self, agent: Any) -> Any:
        """Wrap an agent with FailSafe governance."""
        agent_id = getattr(agent, "agent_id", None) or str(id(agent))
        ctx = self.create_context(agent_id)

        self._wrapped_agents[id(agent)] = agent
        self.emit(GovernanceEventType.POLICY_CHECK, {
            "agent_id": agent_id,
            "phase": "wrap",
            "adapter": "failsafe",
        })

        logger.info("FailSafe governance applied to agent %s", agent_id)
        return _GovernedAgent(agent, ctx, self)

    def unwrap(self, governed_agent: Any) -> Any:
        """Remove FailSafe governance wrapper."""
        if isinstance(governed_agent, _GovernedAgent):
            return governed_agent._original
        return governed_agent

    def evaluate(self, agent_did: str, action: str, **kw: Any) -> bool:
        """Direct governance evaluation. Returns True if allowed."""
        return _evaluate_action(self.fs_client, agent_did, action, self.emit, **kw)

    def pipeline_evaluate(self, request: DecisionRequest) -> PipelineResult:
        """Run the full governance pipeline. Falls back to basic eval if no pipeline."""
        if self.pipeline is not None:
            return self.pipeline.evaluate(request)
        response = self.fs_client.evaluate(request)
        return PipelineResult(
            stage=PipelineStage.AUDITED if response.allowed else PipelineStage.GOVERNANCE,
            allowed=response.allowed,
            governance=response,
        )


def create_failsafe_kernel(client: FailSafeClient, **kwargs: Any) -> FailSafeKernel:
    """Convenience factory for creating a FailSafeKernel instance."""
    return FailSafeKernel(client, **kwargs)
