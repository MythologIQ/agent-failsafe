"""Ring adapter for mapping FailSafe decisions to hypervisor ExecutionRing values.

Pure data translation. No state, no side effects. No imports from
agent-hypervisor — uses int values directly to avoid mandatory dependency.
"""

from __future__ import annotations

from .types import DecisionResponse, RiskGrade, VerdictDecision


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
        """Map a normalized trust score (0.0–1.0) to an ExecutionRing int value.

        Scores above 0.60 → RING_2_STANDARD (2).
        Scores at or below 0.60 → RING_3_SANDBOX (3).
        """
        if trust_score > 0.60:
            return 2
        return 3
