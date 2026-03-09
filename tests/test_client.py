"""Tests for LocalFailSafeClient — local governance evaluation."""

import tempfile
from pathlib import Path

import pytest

from agent_failsafe.client import LocalFailSafeClient
from agent_failsafe.types import DecisionRequest, RiskGrade, VerdictDecision


@pytest.fixture
def tmp_failsafe(tmp_path):
    """Create a minimal FailSafe config directory."""
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    policies_dir = config_dir / "policies"
    policies_dir.mkdir()

    # Write a risk grading policy
    (policies_dir / "risk_grading.yaml").write_text(
        "l3_triggers:\n  - password\n  - api_key\n  - secret\n"
    )

    ledger_path = tmp_path / "ledger" / "ledger.db"
    ledger_path.parent.mkdir()
    return config_dir, ledger_path


class TestLocalFailSafeClient:
    def test_evaluate_l1(self, tmp_failsafe):
        config_dir, ledger_path = tmp_failsafe
        client = LocalFailSafeClient(config_dir=config_dir, ledger_path=ledger_path)

        req = DecisionRequest(action="checkpoint.create", agent_did="did:myth:scrivener:abc")
        resp = client.evaluate(req)

        assert resp.allowed is True
        assert resp.risk_grade == RiskGrade.L1
        assert resp.verdict == VerdictDecision.PASS

    def test_evaluate_l2_file_write(self, tmp_failsafe):
        config_dir, ledger_path = tmp_failsafe
        client = LocalFailSafeClient(config_dir=config_dir, ledger_path=ledger_path)

        req = DecisionRequest(
            action="file.write",
            agent_did="did:myth:scrivener:abc",
            artifact_path="/src/utils.py",
        )
        resp = client.evaluate(req)

        assert resp.allowed is True
        assert resp.risk_grade == RiskGrade.L2
        assert resp.verdict == VerdictDecision.WARN

    def test_evaluate_l3_secret(self, tmp_failsafe):
        config_dir, ledger_path = tmp_failsafe
        client = LocalFailSafeClient(config_dir=config_dir, ledger_path=ledger_path)

        req = DecisionRequest(
            action="file.write",
            agent_did="did:myth:scrivener:abc",
            artifact_path="/src/config.py",
            payload={"content": "api_key = 'sk-xxx'"},
        )
        resp = client.evaluate(req)

        assert resp.allowed is True  # escalated, not blocked
        assert resp.risk_grade == RiskGrade.L3
        assert resp.verdict == VerdictDecision.ESCALATE

    def test_classify_risk_l3(self, tmp_failsafe):
        config_dir, ledger_path = tmp_failsafe
        client = LocalFailSafeClient(config_dir=config_dir, ledger_path=ledger_path)

        assert client.classify_risk("/auth/password_reset.py") == RiskGrade.L3
        assert client.classify_risk("/utils/helper.py") == RiskGrade.L2
        assert client.classify_risk("/docs/readme.md") == RiskGrade.L1

    def test_no_config_dir(self, tmp_path):
        """Client works even without config directory."""
        client = LocalFailSafeClient(
            config_dir=tmp_path / "nonexistent",
            ledger_path=tmp_path / "ledger.db",
        )
        req = DecisionRequest(action="file.write", agent_did="did:myth:scrivener:abc")
        resp = client.evaluate(req)
        assert resp.allowed is True

    def test_ledger_persistence(self, tmp_failsafe):
        config_dir, ledger_path = tmp_failsafe
        client = LocalFailSafeClient(config_dir=config_dir, ledger_path=ledger_path)

        # Make two evaluations
        client.evaluate(DecisionRequest(action="file.write", agent_did="did:myth:scrivener:abc"))
        client.evaluate(DecisionRequest(action="file.delete", agent_did="did:myth:scrivener:abc"))

        # Verify ledger has entries
        import sqlite3
        conn = sqlite3.connect(str(ledger_path))
        count = conn.execute("SELECT COUNT(*) FROM evaluations").fetchone()[0]
        conn.close()
        assert count == 2

    def test_shadow_genome_empty(self, tmp_failsafe):
        config_dir, ledger_path = tmp_failsafe
        client = LocalFailSafeClient(config_dir=config_dir, ledger_path=ledger_path)
        entries = client.get_shadow_genome()
        assert entries == []
