"""Tests for agent_failsafe.types — core data structures."""

from agent_failsafe.types import (
    DecisionRequest,
    DecisionResponse,
    FailureMode,
    GovernanceAction,
    HeuristicResult,
    PersonaType,
    RiskGrade,
    ShadowGenomeEntry,
    TrustStage,
    VerdictDecision,
)


class TestRiskGrade:
    def test_values(self):
        assert RiskGrade.L1.value == "L1"
        assert RiskGrade.L2.value == "L2"
        assert RiskGrade.L3.value == "L3"

    def test_from_string(self):
        assert RiskGrade("L1") == RiskGrade.L1


class TestVerdictDecision:
    def test_all_variants(self):
        verdicts = [v.value for v in VerdictDecision]
        assert "PASS" in verdicts
        assert "BLOCK" in verdicts
        assert "ESCALATE" in verdicts
        assert "QUARANTINE" in verdicts
        assert "WARN" in verdicts


class TestGovernanceAction:
    def test_file_actions(self):
        assert GovernanceAction.FILE_WRITE.value == "file.write"
        assert GovernanceAction.FILE_DELETE.value == "file.delete"

    def test_l3_actions(self):
        assert GovernanceAction.L3_APPROVE.value == "l3.approve"
        assert GovernanceAction.L3_REJECT.value == "l3.reject"


class TestDecisionRequest:
    def test_defaults(self):
        req = DecisionRequest(action="file.write", agent_did="did:myth:scrivener:abc123")
        assert req.action == "file.write"
        assert req.agent_did == "did:myth:scrivener:abc123"
        assert req.nonce  # auto-generated
        assert req.payload == {}

    def test_with_payload(self):
        req = DecisionRequest(
            action="file.write",
            agent_did="did:myth:scrivener:abc123",
            artifact_path="/src/main.py",
            payload={"lines": 42},
        )
        assert req.payload["lines"] == 42

    def test_empty_action_raises(self):
        import pytest
        with pytest.raises(ValueError, match="action must not be empty"):
            DecisionRequest(action="", agent_did="did:myth:scrivener:abc")

    def test_empty_agent_did_raises(self):
        import pytest
        with pytest.raises(ValueError, match="agent_did must not be empty"):
            DecisionRequest(action="file.write", agent_did="")

    def test_path_traversal_normalized(self):
        req = DecisionRequest(
            action="file.write",
            agent_did="did:myth:scrivener:abc",
            artifact_path="src/../secrets/key.pem",
        )
        assert ".." not in req.artifact_path

    def test_valid_action_passes(self):
        req = DecisionRequest(action="file.write", agent_did="did:myth:scrivener:abc")
        assert req.action == "file.write"

    def test_unknown_action_warns(self, caplog):
        import logging
        with caplog.at_level(logging.DEBUG):
            DecisionRequest(action="custom.action", agent_did="did:myth:scrivener:abc")
        assert "Unknown governance action" in caplog.text


class TestDecisionResponse:
    def test_allowed(self):
        resp = DecisionResponse(allowed=True)
        assert resp.allowed is True
        assert resp.risk_grade == RiskGrade.L1
        assert resp.verdict == VerdictDecision.PASS

    def test_blocked(self):
        resp = DecisionResponse(
            allowed=False,
            risk_grade=RiskGrade.L3,
            verdict=VerdictDecision.BLOCK,
            reason="Contains secret",
        )
        assert resp.allowed is False
        assert resp.risk_grade == RiskGrade.L3
        assert "secret" in resp.reason.lower()


class TestShadowGenomeEntry:
    def test_defaults(self):
        entry = ShadowGenomeEntry(
            agent_did="did:myth:scrivener:abc",
            failure_mode=FailureMode.HALLUCINATION,
        )
        assert entry.failure_mode == FailureMode.HALLUCINATION
        assert entry.remediation_status == "UNRESOLVED"
        assert entry.entry_id  # auto-generated

    def test_all_failure_modes(self):
        modes = [m.value for m in FailureMode]
        assert "HALLUCINATION" in modes
        assert "SECRET_EXPOSURE" in modes
        assert "PII_LEAK" in modes


class TestTrustStage:
    def test_stages(self):
        assert TrustStage.CBT.value == "CBT"
        assert TrustStage.KBT.value == "KBT"
        assert TrustStage.IBT.value == "IBT"


class TestPersonaType:
    def test_personas(self):
        assert PersonaType.SCRIVENER.value == "scrivener"
        assert PersonaType.SENTINEL.value == "sentinel"
        assert PersonaType.JUDGE.value == "judge"
        assert PersonaType.OVERSEER.value == "overseer"


class TestHeuristicResult:
    def test_creation(self):
        result = HeuristicResult(pattern_id="secret_detect", matched=True, severity="critical")
        assert result.matched is True
        assert result.severity == "critical"
