"""Tests for MCP-based FailSafe client."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agent_failsafe.mcp_client import MCPFailSafeClient, MCPToolError, _read_line, _verdict_to_response
from agent_failsafe.types import (
    DecisionRequest,
    RiskGrade,
    VerdictDecision,
)


# ---------------------------------------------------------------------------
# _verdict_to_response (pure function tests)
# ---------------------------------------------------------------------------


class TestVerdictToResponse:
    def test_pass_verdict(self):
        verdict = {"decision": "PASS", "riskGrade": "L1", "id": "abc123", "summary": "All clear"}
        resp = _verdict_to_response(verdict)
        assert resp.allowed is True
        assert resp.verdict == VerdictDecision.PASS
        assert resp.risk_grade == RiskGrade.L1
        assert resp.nonce == "abc123"
        assert resp.reason == "All clear"

    def test_block_verdict(self):
        verdict = {"decision": "BLOCK", "riskGrade": "L2", "id": "blk1", "summary": "Blocked"}
        resp = _verdict_to_response(verdict)
        assert resp.allowed is False
        assert resp.verdict == VerdictDecision.BLOCK
        assert resp.risk_grade == RiskGrade.L2

    def test_quarantine_verdict(self):
        verdict = {"decision": "QUARANTINE", "riskGrade": "L3", "id": "q1"}
        resp = _verdict_to_response(verdict)
        assert resp.allowed is False
        assert resp.verdict == VerdictDecision.QUARANTINE

    def test_escalate_verdict(self):
        verdict = {"decision": "ESCALATE", "riskGrade": "L3", "id": "esc1", "summary": "Needs review"}
        resp = _verdict_to_response(verdict)
        assert resp.allowed is True
        assert resp.verdict == VerdictDecision.ESCALATE
        assert resp.risk_grade == RiskGrade.L3

    def test_warn_verdict(self):
        verdict = {"decision": "WARN", "riskGrade": "L2", "id": "w1"}
        resp = _verdict_to_response(verdict)
        assert resp.allowed is True
        assert resp.verdict == VerdictDecision.WARN

    def test_matched_patterns(self):
        verdict = {
            "decision": "WARN",
            "riskGrade": "L2",
            "id": "mp1",
            "matchedPatterns": ["secret_in_code", "hardcoded_key"],
        }
        resp = _verdict_to_response(verdict)
        assert resp.conditions == ["secret_in_code", "hardcoded_key"]

    def test_ledger_entry_id_present(self):
        verdict = {"decision": "PASS", "riskGrade": "L1", "id": "x", "ledgerEntryId": 42}
        resp = _verdict_to_response(verdict)
        assert resp.ledger_entry_id == "42"

    def test_ledger_entry_id_absent(self):
        verdict = {"decision": "PASS", "riskGrade": "L1", "id": "x"}
        resp = _verdict_to_response(verdict)
        assert resp.ledger_entry_id is None

    def test_defaults_on_empty_dict(self):
        resp = _verdict_to_response({})
        assert resp.allowed is True
        assert resp.verdict == VerdictDecision.PASS
        assert resp.risk_grade == RiskGrade.L1
        assert resp.nonce == ""
        assert resp.conditions == []
        assert resp.reason == ""
        assert resp.ledger_entry_id is None


# ---------------------------------------------------------------------------
# MCPFailSafeClient (with mock subprocess)
# ---------------------------------------------------------------------------


def _make_mock_process(*responses: dict) -> MagicMock:
    """Create a mock Popen that returns JSON-RPC responses line by line."""
    proc = MagicMock(spec=subprocess.Popen)
    proc.poll.return_value = None
    proc.stdin = MagicMock()
    lines = [json.dumps(r).encode() + b"\n" for r in responses]
    proc.stdout = MagicMock()
    proc.stdout.readline = MagicMock(side_effect=lines)
    return proc


class TestMCPFailSafeClient:
    def test_evaluate_calls_audit_then_log(self):
        """Verify evaluate calls _audit_file, then _log_decision for L2+."""
        init_resp = {"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2024-11-05"}}
        audit_resp = {
            "jsonrpc": "2.0", "id": 2,
            "result": {"content": [{"type": "text", "text": json.dumps({
                "decision": "WARN", "riskGrade": "L2", "id": "n1",
                "summary": "Suspicious", "matchedPatterns": ["secret"],
            })}]},
        }
        log_resp = {"jsonrpc": "2.0", "id": 3, "result": {}}
        mock_proc = _make_mock_process(init_resp, audit_resp, log_resp)

        with patch("subprocess.Popen", return_value=mock_proc):
            client = MCPFailSafeClient(["node", "mcp.js"], intent_id="intent-1")
            req = DecisionRequest(
                action="file.write", agent_did="did:myth:scrivener:abc",
                artifact_path="/src/utils.py",
            )
            resp = client.evaluate(req)

        assert resp.allowed is True
        assert resp.verdict == VerdictDecision.WARN
        assert resp.risk_grade == RiskGrade.L2
        # Verify 3 writes: init + audit + log
        assert mock_proc.stdin.write.call_count == 3

    def test_evaluate_returns_response_even_if_log_fails(self):
        """_log_decision error does not corrupt evaluate return."""
        init_resp = {"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2024-11-05"}}
        audit_resp = {
            "jsonrpc": "2.0", "id": 2,
            "result": {"content": [{"type": "text", "text": json.dumps({
                "decision": "ESCALATE", "riskGrade": "L3", "id": "e1",
                "summary": "Needs approval",
            })}]},
        }
        log_error = {"jsonrpc": "2.0", "id": 3, "error": {"code": -1, "message": "db locked"}}
        mock_proc = _make_mock_process(init_resp, audit_resp, log_error)

        with patch("subprocess.Popen", return_value=mock_proc):
            client = MCPFailSafeClient(["node", "mcp.js"], intent_id="intent-1")
            req = DecisionRequest(
                action="file.write", agent_did="did:myth:sentinel:xyz",
                artifact_path="/src/auth.py",
            )
            resp = client.evaluate(req)

        assert resp.allowed is True
        assert resp.verdict == VerdictDecision.ESCALATE
        assert resp.risk_grade == RiskGrade.L3

    def test_evaluate_l1_skips_log(self):
        """L1 decisions do not trigger ledger logging."""
        init_resp = {"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2024-11-05"}}
        audit_resp = {
            "jsonrpc": "2.0", "id": 2,
            "result": {"content": [{"type": "text", "text": json.dumps({
                "decision": "PASS", "riskGrade": "L1", "id": "p1",
            })}]},
        }
        mock_proc = _make_mock_process(init_resp, audit_resp)

        with patch("subprocess.Popen", return_value=mock_proc):
            client = MCPFailSafeClient(["node", "mcp.js"], intent_id="intent-1")
            req = DecisionRequest(
                action="checkpoint.create", agent_did="did:myth:scrivener:abc",
                artifact_path="/src/readme.md",
            )
            resp = client.evaluate(req)

        assert resp.allowed is True
        # Only 2 writes: init + audit (no log)
        assert mock_proc.stdin.write.call_count == 2

    def test_classify_risk_from_audit(self):
        """classify_risk extracts riskGrade from sentinel audit result."""
        init_resp = {"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2024-11-05"}}
        audit_resp = {
            "jsonrpc": "2.0", "id": 2,
            "result": {"content": [{"type": "text", "text": json.dumps({
                "decision": "WARN", "riskGrade": "L2", "id": "c1",
            })}]},
        }
        mock_proc = _make_mock_process(init_resp, audit_resp)

        with patch("subprocess.Popen", return_value=mock_proc):
            client = MCPFailSafeClient(["node", "mcp.js"], intent_id="intent-1")
            grade = client.classify_risk("/src/utils.py")

        assert grade == RiskGrade.L2

    def test_fetch_intent_id_from_status(self):
        """No intent_id → calls qorelogic_status, caches result."""
        init_resp = {"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2024-11-05"}}
        status_resp = {
            "jsonrpc": "2.0", "id": 2,
            "result": {"content": [{"type": "text", "text": json.dumps({
                "active_intent": "intent-fetched-123",
            })}]},
        }
        audit_resp = {
            "jsonrpc": "2.0", "id": 3,
            "result": {"content": [{"type": "text", "text": json.dumps({
                "decision": "PASS", "riskGrade": "L1", "id": "f1",
            })}]},
        }
        mock_proc = _make_mock_process(init_resp, status_resp, audit_resp)

        with patch("subprocess.Popen", return_value=mock_proc):
            client = MCPFailSafeClient(["node", "mcp.js"])  # no intent_id
            req = DecisionRequest(
                action="checkpoint.create", agent_did="did:myth:scrivener:abc",
                artifact_path="/src/main.py",
            )
            resp = client.evaluate(req)

        assert resp.allowed is True
        assert client._intent_id == "intent-fetched-123"

    def test_connection_error_raises(self):
        """Subprocess fails to start → clear error."""
        with patch("subprocess.Popen", side_effect=OSError("not found")):
            client = MCPFailSafeClient(["nonexistent-binary"])
            with pytest.raises(MCPToolError, match="Failed to start MCP server"):
                client._ensure_connected()

    def test_close_terminates_process(self):
        """Verify close() sends EOF and waits."""
        init_resp = {"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2024-11-05"}}
        mock_proc = _make_mock_process(init_resp)

        with patch("subprocess.Popen", return_value=mock_proc):
            client = MCPFailSafeClient(["node", "mcp.js"])
            client._ensure_connected()
            client.close()

        mock_proc.stdin.close.assert_called_once()
        mock_proc.wait.assert_called()
        assert client._process is None

    def test_shadow_genome_reads_sqlite(self, tmp_path):
        """get_shadow_genome reads from SQLite, not MCP."""
        # Create a minimal ledger DB with no DIVERGENCE_DECLARED rows
        import sqlite3
        db_path = tmp_path / "ledger.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("""
            CREATE TABLE ledger (
                id INTEGER PRIMARY KEY,
                eventType TEXT,
                agentDid TEXT,
                payload TEXT,
                timestamp TEXT
            )
        """)
        conn.commit()
        conn.close()

        client = MCPFailSafeClient(
            ["node", "mcp.js"],
            ledger_path=str(db_path),
        )
        entries = client.get_shadow_genome()
        assert entries == []

    def test_mcp_tool_error_format(self):
        """MCPToolError includes tool name in message."""
        err = MCPToolError("sentinel_audit_file", "timeout")
        assert "sentinel_audit_file" in str(err)
        assert "timeout" in str(err)

    def test_read_line_timeout_raises(self):
        """_read_line raises MCPToolError when server doesn't respond."""
        mock_proc = MagicMock(spec=subprocess.Popen)
        mock_proc.stdout = MagicMock()
        mock_proc.stdout.readline = MagicMock(return_value=b"")
        mock_proc.kill = MagicMock()

        with pytest.raises(MCPToolError, match="EOF or killed by timeout"):
            _read_line(mock_proc, timeout=1.0)

    def test_read_line_success(self):
        """_read_line returns data when server responds."""
        mock_proc = MagicMock(spec=subprocess.Popen)
        mock_proc.stdout = MagicMock()
        mock_proc.stdout.readline = MagicMock(return_value=b'{"ok": true}\n')
        mock_proc.kill = MagicMock()

        result = _read_line(mock_proc, timeout=5.0)
        assert result == b'{"ok": true}\n'
