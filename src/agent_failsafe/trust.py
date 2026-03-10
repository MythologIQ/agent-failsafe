"""Trust scoring, stage determination, and influence weight calculations.

Pure functions for computing trust evolution within the FailSafe governance
model.  All functions are stateless and side-effect-free -- they accept a
``TrustConfig`` (frozen dataclass) that carries the tuning knobs.

Trust stages map to FailSafe's CBT/KBT/IBT progression:
  - CBT (Capability-Based Trust): score < cbt_max  (default 0.5)
  - KBT (Knowledge-Based Trust): cbt_max <= score < kbt_max  (default 0.8)
  - IBT (Identity-Based Trust): score >= kbt_max
"""

from __future__ import annotations

from dataclasses import dataclass

from .types import TrustStage


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TrustConfig:
    """Immutable configuration for trust scoring calculations.

    All thresholds and deltas can be overridden per-deployment while keeping
    deterministic, reproducible scoring behaviour.

    Attributes:
        default_trust: Starting trust score for a new agent.
        success_delta: Score increment for a successful (allowed) outcome.
        failure_delta: Score decrement for a denied non-L3 outcome.
        violation_penalty: Score decrement for a denied L3 outcome.
        probation_floor: Minimum score during probationary period.
        probation_verifications: Required verifications to exit probation.
        probation_days: Required active days to exit probation.
        cbt_max: Upper bound (exclusive) for CBT stage.
        kbt_max: Upper bound (exclusive) for KBT stage.
    """

    default_trust: float = 0.35
    success_delta: float = 0.05
    failure_delta: float = -0.10
    violation_penalty: float = -0.25
    probation_floor: float = 0.35
    probation_verifications: int = 5
    probation_days: int = 30
    cbt_max: float = 0.5
    kbt_max: float = 0.8


DEFAULT_TRUST_CONFIG: TrustConfig = TrustConfig()
"""Module-level default configuration instance."""


# ---------------------------------------------------------------------------
# Pure scoring functions
# ---------------------------------------------------------------------------


def determine_stage(
    score: float,
    config: TrustConfig = DEFAULT_TRUST_CONFIG,
) -> TrustStage:
    """Determine the trust stage for a given score.

    Args:
        score: Current trust score (0.0 -- 1.0).
        config: Trust configuration with stage boundaries.

    Returns:
        The ``TrustStage`` corresponding to *score*.
    """
    if score < config.cbt_max:
        return TrustStage.CBT
    if score < config.kbt_max:
        return TrustStage.KBT
    return TrustStage.IBT


def apply_outcome(
    current_score: float,
    allowed: bool,
    risk_grade: str,
    config: TrustConfig = DEFAULT_TRUST_CONFIG,
    consecutive_successes: int = 0,
) -> float:
    """Apply a governance outcome to produce an updated trust score.

    Args:
        current_score: Trust score before this outcome (0.0 -- 1.0).
        allowed: Whether the action was allowed.
        risk_grade: The risk grade string (``"L1"``, ``"L2"``, or ``"L3"``).
        config: Trust configuration with delta values.
        consecutive_successes: Number of consecutive successes before this
            outcome.  Applies diminishing returns (0.8^n decay) to the
            success delta, making rapid trust escalation harder.

    Returns:
        Updated trust score, clamped to [0.0, 1.0].
    """
    if allowed:
        decay = 0.8 ** consecutive_successes
        delta = config.success_delta * decay
    elif risk_grade == "L3":
        delta = config.violation_penalty
    else:
        delta = config.failure_delta

    return max(0.0, min(1.0, current_score + delta))


def is_probationary(
    days_active: int,
    verifications_completed: int,
    config: TrustConfig = DEFAULT_TRUST_CONFIG,
) -> bool:
    """Check whether an agent is still in its probationary period.

    An agent exits probation only when *both* the minimum active days
    and the minimum verification count have been met.

    Args:
        days_active: Number of days the agent has been active.
        verifications_completed: Number of completed verifications.
        config: Trust configuration with probation thresholds.

    Returns:
        ``True`` if the agent is still probationary.
    """
    return (
        days_active < config.probation_days
        or verifications_completed < config.probation_verifications
    )


def calculate_influence_weight(
    score: float,
    is_probationary_flag: bool,
    config: TrustConfig = DEFAULT_TRUST_CONFIG,
) -> float:
    """Calculate how much influence an agent's actions carry.

    Probationary agents receive a fixed low weight.  Non-probationary
    agents receive a linearly-scaled weight from 0.5 (score=0.0) to
    2.0 (score=1.0).

    Args:
        score: Current trust score (0.0 -- 1.0).
        is_probationary_flag: Whether the agent is probationary.
        config: Trust configuration (reserved for future use).

    Returns:
        Influence weight (>= 0.1).
    """
    if is_probationary_flag:
        return 0.1
    return 0.5 + 1.5 * score


def score_to_mesh_trust(score: float) -> int:
    """Convert a FailSafe trust score (0.0 -- 1.0) to Agent Mesh scale (0 -- 1000).

    Args:
        score: FailSafe trust score.

    Returns:
        Integer mesh trust score, clamped to [0, 1000].
    """
    return int(round(max(0.0, min(1.0, score)) * 1000))
