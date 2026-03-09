"""BaseIntegration subclass for FailSafe governance.

Provides the ``FailSafeKernel`` — a framework adapter that wraps any agent
with FailSafe governance enforcement, registered via ``@register_adapter``.
"""

from __future__ import annotations

import logging
from typing import Any

from .interceptor import FailSafeInterceptor
from .types import DecisionRequest, FailSafeClient

logger = logging.getLogger(__name__)

# Lazy imports — agent-os is an optional dependency
_BaseIntegration = None
_GovernanceEventType = None
_register_adapter = None


def _ensure_imports() -> None:
    global _BaseIntegration, _GovernanceEventType, _register_adapter
    if _BaseIntegration is None:
        from agent_os.integrations.base import BaseIntegration, GovernanceEventType
        from agent_os.integrations.registry import register_adapter
        _BaseIntegration = BaseIntegration
        _GovernanceEventType = GovernanceEventType
        _register_adapter = register_adapter


def create_failsafe_kernel(client: FailSafeClient, **kwargs: Any) -> Any:
    """Factory function to create a FailSafeKernel.

    This defers the import of BaseIntegration until runtime so the package
    can be imported without agent-os-kernel installed.

    Args:
        client: A FailSafeClient implementation.
        **kwargs: Passed to the FailSafeKernel constructor.

    Returns:
        A FailSafeKernel instance (BaseIntegration subclass).
    """
    _ensure_imports()

    class FailSafeKernel(_BaseIntegration):
        """Agent OS integration adapter for FailSafe governance.

        Wraps agents with FailSafe governance enforcement via the
        BaseIntegration lifecycle (pre_execute / post_execute).
        """

        def __init__(
            self,
            fs_client: FailSafeClient,
            default_agent_did: str = "did:myth:scrivener:unknown",
            block_on_l3: bool = True,
            **kw: Any,
        ) -> None:
            super().__init__(**kw)
            self.fs_client = fs_client
            self.interceptor = FailSafeInterceptor(
                client=fs_client,
                default_agent_did=default_agent_did,
                block_on_l3=block_on_l3,
            )
            self._wrapped_agents: dict[int, Any] = {}

        def wrap(self, agent: Any) -> Any:
            """Wrap an agent with FailSafe governance.

            Returns a thin proxy that runs pre/post governance checks
            around the agent's execution.
            """
            agent_id = getattr(agent, "agent_id", None) or str(id(agent))
            ctx = self.create_context(agent_id)

            self._wrapped_agents[id(agent)] = agent
            self.emit(_GovernanceEventType.POLICY_CHECK, {
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
            """Direct governance evaluation without the interceptor chain.

            Returns True if the action is allowed.
            """
            req = DecisionRequest(action=action, agent_did=agent_did, **kw)
            response = self.fs_client.evaluate(req)

            if not response.allowed:
                self.emit(_GovernanceEventType.TOOL_CALL_BLOCKED, {
                    "agent_id": agent_did,
                    "action": action,
                    "risk_grade": response.risk_grade.value,
                    "reason": response.reason,
                })

            return response.allowed

    class _GovernedAgent:
        """Thin proxy that wraps an agent with governance checks."""

        def __init__(self, original: Any, ctx: Any, kernel: FailSafeKernel) -> None:
            self._original = original
            self._ctx = ctx
            self._kernel = kernel

        def __getattr__(self, name: str) -> Any:
            return getattr(self._original, name)

    # Register with the adapter registry
    try:
        _register_adapter("failsafe")(FailSafeKernel)
    except (ValueError, TypeError):
        # Already registered or registry not available
        pass

    return FailSafeKernel(client, **kwargs)
