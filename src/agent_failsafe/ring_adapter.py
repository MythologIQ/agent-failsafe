"""Ring adapter for mapping FailSafe decisions to hypervisor ExecutionRing values.

Pure data translation with optional typed returns when agent-hypervisor is
installed. Int-based methods always work with zero dependencies.
"""

from __future__ import annotations

import logging
from typing import Any

from .types import DecisionResponse, RiskGrade, VerdictDecision

logger = logging.getLogger(__name__)

# Lazy imports — agent-hypervisor is an optional dependency
_ExecutionRing: Any = None
_KillReason: Any = None
_KillSwitch: Any = None
_hypervisor_checked = False


def _ensure_imports() -> None:
    """Attempt to import hypervisor types. Safe to call repeatedly."""
    global _ExecutionRing, _KillReason, _KillSwitch, _hypervisor_checked
    if _hypervisor_checked:
        return
    _hypervisor_checked = True
    try:
        from hypervisor.models import ExecutionRing
        from hypervisor.security.kill_switch import KillReason, KillSwitch
        _ExecutionRing = ExecutionRing
        _KillReason = KillReason
        _KillSwitch = KillSwitch
    except ImportError:
        pass


class FailSafeRingAdapter:
    """Maps FailSafe risk grades and verdicts to hypervisor ExecutionRing int values.

    Ring values match hypervisor.models.ExecutionRing enum:
      0 = RING_0_ROOT (never assigned by adapter)
      1 = RING_1_PRIVILEGED (never assigned — requires SRE consensus)
      2 = RING_2_STANDARD
      3 = RING_3_SANDBOX
    """

    RISK_TO_RING: dict[RiskGrade, int] = {
        RiskGrade.L1: 2,
        RiskGrade.L2: 2,
        RiskGrade.L3: 3,
    }

    VERDICT_RING_OVERRIDES: dict[VerdictDecision, int] = {
        VerdictDecision.PASS: 2,
        VerdictDecision.WARN: 2,
        VerdictDecision.ESCALATE: 3,
        VerdictDecision.BLOCK: 3,
        VerdictDecision.QUARANTINE: 3,
    }

    VERDICT_TO_KILL_REASON: dict[VerdictDecision, str | None] = {
        VerdictDecision.QUARANTINE: "behavioral_drift",
        VerdictDecision.BLOCK: None,
        VerdictDecision.ESCALATE: None,
        VerdictDecision.WARN: None,
        VerdictDecision.PASS: None,
    }

    # --- Int-based methods (zero dependencies) ---

    def decision_to_ring(self, response: DecisionResponse) -> int:
        """Map a FailSafe decision to an ExecutionRing int value.

        Verdict overrides risk grade when both are present.
        Never returns 0 (ROOT) or 1 (PRIVILEGED).
        """
        return self.VERDICT_RING_OVERRIDES.get(
            response.verdict,
            self.RISK_TO_RING.get(response.risk_grade, 3),
        )

    def decision_to_kill_reason(self, response: DecisionResponse) -> str | None:
        """Extract a kill reason from a FailSafe decision, if applicable.

        Only QUARANTINE triggers a kill reason ("behavioral_drift").
        BLOCK stops the action but does not kill the agent.
        """
        return self.VERDICT_TO_KILL_REASON.get(response.verdict)

    def trust_score_to_ring(self, trust_score: float) -> int:
        """Map a normalized trust score (0.0-1.0) to an ExecutionRing int value.

        Scores above 0.60 -> RING_2_STANDARD (2).
        Scores at or below 0.60 -> RING_3_SANDBOX (3).
        """
        if trust_score > 0.60:
            return 2
        return 3

    # --- Typed methods (require agent-hypervisor) ---

    def decision_to_execution_ring(self, response: DecisionResponse) -> Any:
        """Return ExecutionRing enum value for a FailSafe decision.

        Raises:
            ImportError: If agent-hypervisor is not installed.
        """
        _ensure_imports()
        if _ExecutionRing is None:
            raise ImportError("agent-hypervisor required for ExecutionRing")
        return _ExecutionRing(self.decision_to_ring(response))

    def decision_to_kill_reason_enum(self, response: DecisionResponse) -> Any | None:
        """Return KillReason enum value if verdict warrants a kill, else None.

        Raises:
            ImportError: If agent-hypervisor is not installed and verdict is QUARANTINE.
        """
        raw = self.decision_to_kill_reason(response)
        if raw is None:
            return None
        _ensure_imports()
        if _KillReason is None:
            raise ImportError("agent-hypervisor required for KillReason")
        return _KillReason(raw)

    def request_kill(
        self,
        response: DecisionResponse,
        agent_did: str,
        session_id: str,
        details: str = "",
    ) -> Any | None:
        """Request KillSwitch.kill() if verdict warrants it.

        Returns KillResult if kill executed, None if no kill needed.

        Raises:
            ImportError: If agent-hypervisor is not installed and kill is needed.
        """
        reason_enum = self.decision_to_kill_reason_enum(response)
        if reason_enum is None:
            return None
        _ensure_imports()
        if _KillSwitch is None:
            raise ImportError("agent-hypervisor required for KillSwitch")
        switch = _KillSwitch()
        return switch.kill(
            agent_did=agent_did,
            session_id=session_id,
            reason=reason_enum,
            details=details or f"FailSafe {response.verdict.value}",
        )
