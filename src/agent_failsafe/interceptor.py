"""ToolCallInterceptor implementation for FailSafe governance.

Plugs into the Agent OS CompositeInterceptor chain to enforce
FailSafe governance decisions on every tool call.
"""

from __future__ import annotations

import logging
from typing import Any

from .types import DecisionRequest, DecisionResponse, FailSafeClient, RiskGrade, VerdictDecision

logger = logging.getLogger(__name__)

# Lazy imports — toolkit packages are optional dependencies
_ToolCallRequest = None
_ToolCallResult = None


def _ensure_imports() -> None:
    global _ToolCallRequest, _ToolCallResult
    if _ToolCallRequest is None:
        from agent_os.integrations.base import ToolCallRequest, ToolCallResult
        _ToolCallRequest = ToolCallRequest
        _ToolCallResult = ToolCallResult


class FailSafeInterceptor:
    """ToolCallInterceptor that delegates decisions to a FailSafe governance engine.

    Implements the ``agent_os.integrations.base.ToolCallInterceptor`` protocol.
    Add it to a ``CompositeInterceptor`` chain alongside other interceptors.

    Args:
        client: A FailSafeClient implementation (MCP, local, or HTTP).
        default_agent_did: Fallback DID when the request has no agent_id.
        block_on_l3: If True, block tool calls that require L3 human approval
            rather than allowing them to proceed while queued.
    """

    def __init__(
        self,
        client: FailSafeClient,
        default_agent_did: str = "did:myth:scrivener:unknown",
        block_on_l3: bool = True,
    ) -> None:
        self.client = client
        self.default_agent_did = default_agent_did
        self.block_on_l3 = block_on_l3
        self._decision_count = 0
        self._block_count = 0

    def intercept(self, request: Any) -> Any:
        """Intercept a tool call and enforce FailSafe governance.

        Conforms to ``ToolCallInterceptor.intercept(ToolCallRequest) -> ToolCallResult``.
        """
        _ensure_imports()

        agent_did = getattr(request, "agent_id", "") or self.default_agent_did
        tool_name = getattr(request, "tool_name", "unknown")
        arguments = getattr(request, "arguments", {})

        # Map tool call to a FailSafe governance action
        action = self._map_tool_to_action(tool_name)

        decision_req = DecisionRequest(
            action=action,
            agent_did=agent_did,
            artifact_path=arguments.get("path", arguments.get("file_path", "")),
            payload={"tool_name": tool_name, "arguments": arguments},
        )

        try:
            response = self.client.evaluate(decision_req)
        except Exception as exc:
            logger.error("FailSafe evaluation failed: %s", exc)
            # Fail-open: allow the call but log the failure
            self._decision_count += 1
            return _ToolCallResult(
                allowed=True,
                reason=f"FailSafe unavailable ({exc}); fail-open policy applied",
                audit_entry={"failsafe_error": str(exc), "fail_open": True},
            )

        self._decision_count += 1

        if not response.allowed:
            self._block_count += 1
            return _ToolCallResult(
                allowed=False,
                reason=response.reason or f"Blocked by FailSafe (risk={response.risk_grade.value})",
                audit_entry=self._audit_entry(response, tool_name),
            )

        # L3 escalation: block if configured
        if response.risk_grade == RiskGrade.L3 and self.block_on_l3:
            if response.verdict == VerdictDecision.ESCALATE:
                self._block_count += 1
                return _ToolCallResult(
                    allowed=False,
                    reason="L3 human approval required — action queued for review",
                    audit_entry=self._audit_entry(response, tool_name),
                )

        return _ToolCallResult(
            allowed=True,
            audit_entry=self._audit_entry(response, tool_name),
        )

    def _map_tool_to_action(self, tool_name: str) -> str:
        """Map a toolkit tool name to a FailSafe GovernanceAction string."""
        write_tools = {"write_file", "file_write", "create_file", "save_file", "edit_file"}
        delete_tools = {"delete_file", "file_delete", "remove_file"}

        lower = tool_name.lower()
        if lower in write_tools or "write" in lower:
            return "file.write"
        if lower in delete_tools or "delete" in lower:
            return "file.delete"
        # Default: treat as a checkpoint action for auditing
        return "checkpoint.create"

    def _audit_entry(self, response: DecisionResponse, tool_name: str) -> dict:
        """Build an audit entry dict from a FailSafe decision."""
        return {
            "failsafe_allowed": response.allowed,
            "failsafe_risk_grade": response.risk_grade.value,
            "failsafe_verdict": response.verdict.value,
            "failsafe_reason": response.reason,
            "failsafe_nonce": response.nonce,
            "tool_name": tool_name,
        }

    @property
    def stats(self) -> dict:
        """Return interceptor statistics."""
        return {
            "decisions": self._decision_count,
            "blocks": self._block_count,
            "block_rate": (
                self._block_count / self._decision_count
                if self._decision_count > 0
                else 0.0
            ),
        }
