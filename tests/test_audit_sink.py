"""Tests for FailSafeAuditSink — Merkle-chained audit trail."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

import pytest

from agent_failsafe.audit_sink import FailSafeAuditSink


@dataclass
class MockAuditEntry:
    """Mock of agentmesh AuditEntry for testing without the dependency."""

    entry_id: str = "audit_test001"
    timestamp: datetime = field(default_factory=datetime.utcnow)
    event_type: str = "tool_call"
    agent_did: str = "did:myth:scrivener:abc"
    action: str = "file.write"
    resource: Optional[str] = "/src/main.py"
    target_did: Optional[str] = None
    data: dict = field(default_factory=dict)
    outcome: str = "success"
    policy_decision: Optional[str] = None
    matched_rule: Optional[str] = None
    trace_id: Optional[str] = None
    session_id: Optional[str] = None


class TestFailSafeAuditSink:
    def test_write_single(self, tmp_path):
        sink = FailSafeAuditSink(ledger_path=tmp_path / "audit.db")
        sink.write(MockAuditEntry())
        assert sink._entry_count == 1

    def test_write_batch(self, tmp_path):
        sink = FailSafeAuditSink(ledger_path=tmp_path / "audit.db")
        entries = [MockAuditEntry(entry_id=f"batch_{i}") for i in range(5)]
        sink.write_batch(entries)
        assert sink._entry_count == 5

    def test_integrity_valid(self, tmp_path):
        sink = FailSafeAuditSink(ledger_path=tmp_path / "audit.db")
        for i in range(3):
            sink.write(MockAuditEntry(entry_id=f"chain_{i}"))

        valid, error = sink.verify_integrity()
        assert valid is True
        assert error is None

    def test_integrity_catches_tampering(self, tmp_path):
        db_path = tmp_path / "audit.db"
        sink = FailSafeAuditSink(ledger_path=db_path)
        for i in range(3):
            sink.write(MockAuditEntry(entry_id=f"tamper_{i}"))

        # Tamper with the ledger
        import sqlite3
        conn = sqlite3.connect(str(db_path))
        conn.execute("UPDATE audit_entries SET event_type = 'TAMPERED' WHERE id = 2")
        conn.commit()
        conn.close()

        valid, error = sink.verify_integrity()
        assert valid is False
        assert "mismatch" in error.lower()

    def test_chain_continuity(self, tmp_path):
        sink = FailSafeAuditSink(ledger_path=tmp_path / "audit.db")
        sink.write(MockAuditEntry(entry_id="first"))
        hash_after_first = sink._prev_hash

        sink.write(MockAuditEntry(entry_id="second"))
        assert sink._prev_hash != hash_after_first  # Chain advanced

    def test_empty_ledger_integrity(self, tmp_path):
        sink = FailSafeAuditSink(ledger_path=tmp_path / "audit.db")
        valid, error = sink.verify_integrity()
        assert valid is True

    def test_close_is_noop(self, tmp_path):
        sink = FailSafeAuditSink(ledger_path=tmp_path / "audit.db")
        sink.close()  # Should not raise

    def test_creates_parent_dirs(self, tmp_path):
        deep_path = tmp_path / "a" / "b" / "c" / "audit.db"
        sink = FailSafeAuditSink(ledger_path=deep_path)
        sink.write(MockAuditEntry())
        assert deep_path.exists()

    def test_default_hmac_key_warns(self, tmp_path, caplog):
        """Default dev HMAC key logs a warning at construction."""
        import logging
        with caplog.at_level(logging.WARNING):
            FailSafeAuditSink(ledger_path=tmp_path / "warn.db")
        assert any("default dev HMAC key" in r.message for r in caplog.records)

    def test_custom_hmac_key_no_warning(self, tmp_path, caplog):
        """Custom HMAC key does not trigger the warning."""
        import logging
        with caplog.at_level(logging.WARNING):
            FailSafeAuditSink(ledger_path=tmp_path / "no_warn.db", hmac_key=b"prod-key")
        assert not any("default dev HMAC key" in r.message for r in caplog.records)
