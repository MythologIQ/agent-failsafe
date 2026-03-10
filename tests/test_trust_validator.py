"""Tests for FailSafeTrustValidator — CBT/KBT/IBT trust-gated validation."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from agent_failsafe.trust import DEFAULT_TRUST_CONFIG, TrustConfig
from agent_failsafe.trust_validator import (
    FailSafeTrustValidator,
    _corrective_actions,
    _extract_agent_did,
    _extract_trust_score,
    _stage_allows_risk,
)
from agent_failsafe.types import (
    DecisionRequest,
    DecisionResponse,
    RiskGrade,
    TrustStage,
    VerdictDecision,
)


# ── helpers ──────────────────────────────────────────────────────────────


def _mock_client(
    allowed: bool = True,
    risk_grade: RiskGrade = RiskGrade.L1,
    verdict: VerdictDecision = VerdictDecision.PASS,
) -> MagicMock:
    client = MagicMock()
    client.evaluate.return_value = DecisionResponse(
        allowed=allowed, risk_grade=risk_grade, verdict=verdict,
    )
    return client


def _make_request(action_type: str = "file.write", agent_id: str = "") -> MagicMock:
    req = MagicMock()
    req.action_type = action_type
    req.agent_id = agent_id
    return req


# ── TestStageAllowsRisk ─────────────────────────────────────────────────


class TestStageAllowsRisk:
    def test_cbt_allows_l1(self) -> None:
        assert _stage_allows_risk(TrustStage.CBT, RiskGrade.L1) is True

    def test_cbt_blocks_l2(self) -> None:
        assert _stage_allows_risk(TrustStage.CBT, RiskGrade.L2) is False

    def test_cbt_blocks_l3(self) -> None:
        assert _stage_allows_risk(TrustStage.CBT, RiskGrade.L3) is False

    def test_kbt_allows_l1(self) -> None:
        assert _stage_allows_risk(TrustStage.KBT, RiskGrade.L1) is True

    def test_kbt_allows_l2(self) -> None:
        assert _stage_allows_risk(TrustStage.KBT, RiskGrade.L2) is True

    def test_kbt_blocks_l3(self) -> None:
        assert _stage_allows_risk(TrustStage.KBT, RiskGrade.L3) is False

    def test_ibt_allows_l1(self) -> None:
        assert _stage_allows_risk(TrustStage.IBT, RiskGrade.L1) is True

    def test_ibt_allows_l2(self) -> None:
        assert _stage_allows_risk(TrustStage.IBT, RiskGrade.L2) is True

    def test_ibt_allows_l3(self) -> None:
        assert _stage_allows_risk(TrustStage.IBT, RiskGrade.L3) is True


# ── TestExtractHelpers ───────────────────────────────────────────────────


class TestExtractHelpers:
    def test_agent_did_from_context(self) -> None:
        req = MagicMock()
        ctx = {"agent_did": "did:myth:scrivener:abc"}
        assert _extract_agent_did(req, ctx) == "did:myth:scrivener:abc"

    def test_agent_did_from_request(self) -> None:
        req = MagicMock()
        req.agent_id = "did:myth:sentinel:xyz"
        assert _extract_agent_did(req, None) == "did:myth:sentinel:xyz"

    def test_agent_did_default(self) -> None:
        req = MagicMock()
        req.agent_id = ""
        assert _extract_agent_did(req, None) == "did:myth:scrivener:unknown"

    def test_trust_score_from_context(self) -> None:
        assert _extract_trust_score({"trust_score": 0.75}) == 0.75

    def test_trust_score_default(self) -> None:
        assert _extract_trust_score(None) == DEFAULT_TRUST_CONFIG.default_trust


# ── TestCorrectiveActions ────────────────────────────────────────────────


class TestCorrectiveActions:
    def test_cbt_with_l3(self) -> None:
        actions = _corrective_actions(TrustStage.CBT, RiskGrade.L3)
        assert len(actions) == 2
        assert "KBT" in actions[0]
        assert "L3" in actions[1]

    def test_ibt_with_l1(self) -> None:
        assert _corrective_actions(TrustStage.IBT, RiskGrade.L1) == []


# ── TestFailSafeTrustValidator ───────────────────────────────────────────


class TestFailSafeTrustValidator:
    def test_metadata_without_control_plane(self, monkeypatch) -> None:
        import agent_failsafe.trust_validator as mod

        monkeypatch.setattr(mod, "_PluginMetadata", None)
        monkeypatch.setattr(mod, "_control_plane_checked", True)
        validator = FailSafeTrustValidator(client=_mock_client())
        meta = validator.metadata
        assert meta["name"] == "failsafe-trust-validator"
        assert meta["plugin_type"] == "validator"

    def test_metadata_with_control_plane(self, monkeypatch) -> None:
        from dataclasses import dataclass, field
        from enum import Enum

        class FakeCapability(Enum):
            REQUEST_VALIDATION = "request_validation"
            RISK_ASSESSMENT = "risk_assessment"

        @dataclass
        class FakePluginMetadata:
            name: str = ""
            version: str = ""
            description: str = ""
            plugin_type: str = ""
            capabilities: list = field(default_factory=list)

        import agent_failsafe.trust_validator as mod

        monkeypatch.setattr(mod, "_PluginMetadata", FakePluginMetadata)
        monkeypatch.setattr(mod, "_PluginCapability", FakeCapability)
        monkeypatch.setattr(mod, "_control_plane_checked", True)

        validator = FailSafeTrustValidator(client=_mock_client())
        meta = validator.metadata
        assert isinstance(meta, FakePluginMetadata)
        assert meta.name == "failsafe-trust-validator"
        assert len(meta.capabilities) == 2

    def test_cbt_allows_l1_action(self) -> None:
        """CBT agent (score=0.3) with L1 risk → valid."""
        client = _mock_client(allowed=True, risk_grade=RiskGrade.L1)
        validator = FailSafeTrustValidator(client=client)
        result = validator.validate_request(
            _make_request(), context={"trust_score": 0.3},
        )
        assert result.is_valid is True

    def test_cbt_blocks_l2_action(self) -> None:
        """CBT agent (score=0.3) with L2 risk → invalid + corrective actions."""
        client = _mock_client(allowed=True, risk_grade=RiskGrade.L2)
        validator = FailSafeTrustValidator(client=client)
        result = validator.validate_request(
            _make_request(), context={"trust_score": 0.3},
        )
        assert result.is_valid is False
        assert "CBT" in result.reason or "insufficient" in result.reason
        assert len(result.corrective_actions) >= 1

    def test_kbt_allows_l2_action(self) -> None:
        """KBT agent (score=0.6) with L2 risk → valid."""
        client = _mock_client(allowed=True, risk_grade=RiskGrade.L2)
        validator = FailSafeTrustValidator(client=client)
        result = validator.validate_request(
            _make_request(), context={"trust_score": 0.6},
        )
        assert result.is_valid is True

    def test_kbt_blocks_l3_action(self) -> None:
        """KBT agent (score=0.6) with L3 risk → invalid."""
        client = _mock_client(allowed=True, risk_grade=RiskGrade.L3)
        validator = FailSafeTrustValidator(client=client)
        result = validator.validate_request(
            _make_request(), context={"trust_score": 0.6},
        )
        assert result.is_valid is False

    def test_ibt_allows_l3_action(self) -> None:
        """IBT agent (score=0.9) with L3 risk → valid."""
        client = _mock_client(allowed=True, risk_grade=RiskGrade.L3)
        validator = FailSafeTrustValidator(client=client)
        result = validator.validate_request(
            _make_request(), context={"trust_score": 0.9},
        )
        assert result.is_valid is True

    def test_governance_denial_overrides_trust(self) -> None:
        """FailSafe denies → always invalid regardless of trust stage."""
        client = _mock_client(allowed=False, risk_grade=RiskGrade.L1)
        validator = FailSafeTrustValidator(client=client)
        result = validator.validate_request(
            _make_request(), context={"trust_score": 0.9},  # IBT
        )
        assert result.is_valid is False

    def test_validation_log_records_decisions(self) -> None:
        client = _mock_client(allowed=True, risk_grade=RiskGrade.L1)
        validator = FailSafeTrustValidator(client=client)
        validator.validate_request(_make_request(), context={"trust_score": 0.3})
        validator.validate_request(_make_request(), context={"trust_score": 0.6})

        log = validator.get_validation_log()
        assert len(log) == 2
        # newest first
        assert log[0]["trust_stage"] == "KBT"
        assert log[1]["trust_stage"] == "CBT"

    def test_validation_log_capacity(self) -> None:
        client = _mock_client(allowed=True, risk_grade=RiskGrade.L1)
        validator = FailSafeTrustValidator(client=client, log_capacity=3)
        for _ in range(5):
            validator.validate_request(_make_request(), context={"trust_score": 0.3})

        log = validator.get_validation_log(limit=10)
        assert len(log) == 3  # capped at capacity

    def test_default_trust_score_used(self) -> None:
        """No context → defaults to TrustConfig.default_trust (0.35 → CBT)."""
        client = _mock_client(allowed=True, risk_grade=RiskGrade.L1)
        validator = FailSafeTrustValidator(client=client)
        result = validator.validate_request(_make_request())
        assert result.is_valid is True
        assert result.details["trust_stage"] == "CBT"
