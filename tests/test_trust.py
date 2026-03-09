"""Tests for agent_failsafe.trust module."""

from __future__ import annotations

import pytest

from agent_failsafe.trust import (
    apply_outcome,
    calculate_influence_weight,
    determine_stage,
    is_probationary,
    score_to_mesh_trust,
)
from agent_failsafe.types import TrustStage


# ---------------------------------------------------------------------------
# TestDetermineStage
# ---------------------------------------------------------------------------


class TestDetermineStage:
    """Tests for determine_stage()."""

    def test_cbt_at_low_score(self) -> None:
        assert determine_stage(0.3) == TrustStage.CBT

    def test_kbt_at_mid_score(self) -> None:
        assert determine_stage(0.6) == TrustStage.KBT

    def test_ibt_at_high_score(self) -> None:
        assert determine_stage(0.9) == TrustStage.IBT

    def test_boundary_at_cbt_max_is_kbt(self) -> None:
        """Exactly at cbt_max (0.5) should be KBT, not CBT (< is strict)."""
        assert determine_stage(0.5) == TrustStage.KBT

    def test_boundary_at_kbt_max_is_ibt(self) -> None:
        """Exactly at kbt_max (0.8) should be IBT, not KBT (< is strict)."""
        assert determine_stage(0.8) == TrustStage.IBT


# ---------------------------------------------------------------------------
# TestApplyOutcome
# ---------------------------------------------------------------------------


class TestApplyOutcome:
    """Tests for apply_outcome()."""

    def test_success_adds_delta(self) -> None:
        result = apply_outcome(0.5, allowed=True, risk_grade="L1")
        assert result == pytest.approx(0.55)

    def test_failure_subtracts_delta(self) -> None:
        result = apply_outcome(0.5, allowed=False, risk_grade="L1")
        assert result == pytest.approx(0.40)

    def test_l3_violation_subtracts_penalty(self) -> None:
        result = apply_outcome(0.5, allowed=False, risk_grade="L3")
        assert result == pytest.approx(0.25)

    def test_clamp_at_zero(self) -> None:
        result = apply_outcome(0.05, allowed=False, risk_grade="L1")
        assert result == pytest.approx(0.0)

    def test_clamp_at_one(self) -> None:
        result = apply_outcome(0.98, allowed=True, risk_grade="L1")
        assert result == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# TestIsProbationary
# ---------------------------------------------------------------------------


class TestIsProbationary:
    """Tests for is_probationary()."""

    def test_new_agent_is_probationary(self) -> None:
        assert is_probationary(days_active=0, verifications_completed=0) is True

    def test_mature_agent_not_probationary(self) -> None:
        assert is_probationary(days_active=60, verifications_completed=10) is False

    def test_only_days_low_is_probationary(self) -> None:
        assert is_probationary(days_active=10, verifications_completed=10) is True

    def test_only_verifications_low_is_probationary(self) -> None:
        assert is_probationary(days_active=60, verifications_completed=2) is True


# ---------------------------------------------------------------------------
# TestCalculateInfluenceWeight
# ---------------------------------------------------------------------------


class TestCalculateInfluenceWeight:
    """Tests for calculate_influence_weight()."""

    def test_probationary_returns_fixed(self) -> None:
        assert calculate_influence_weight(0.9, is_probationary_flag=True) == pytest.approx(0.1)

    def test_score_zero_returns_base(self) -> None:
        assert calculate_influence_weight(0.0, is_probationary_flag=False) == pytest.approx(0.5)

    def test_score_one_returns_max(self) -> None:
        assert calculate_influence_weight(1.0, is_probationary_flag=False) == pytest.approx(2.0)

    def test_mid_score(self) -> None:
        assert calculate_influence_weight(0.5, is_probationary_flag=False) == pytest.approx(1.25)


# ---------------------------------------------------------------------------
# TestScoreToMeshTrust
# ---------------------------------------------------------------------------


class TestScoreToMeshTrust:
    """Tests for score_to_mesh_trust()."""

    def test_zero(self) -> None:
        assert score_to_mesh_trust(0.0) == 0

    def test_half(self) -> None:
        assert score_to_mesh_trust(0.5) == 500

    def test_one(self) -> None:
        assert score_to_mesh_trust(1.0) == 1000

    def test_fractional(self) -> None:
        assert score_to_mesh_trust(0.35) == 350
