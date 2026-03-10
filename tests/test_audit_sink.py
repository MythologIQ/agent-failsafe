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
        sink = FailSafeAuditSink(ledger_path=tmp_path / "audit.db", hmac_key=b"test-key")
        sink.write(MockAuditEntry())
        assert sink._entry_count == 1

    def test_write_batch(self, tmp_path):
        sink = FailSafeAuditSink(ledger_path=tmp_path / "audit.db", hmac_key=b"test-key")
        entries = [MockAuditEntry(entry_id=f"batch_{i}") for i in range(5)]
        sink.write_batch(entries)
        assert sink._entry_count == 5

    def test_integrity_valid(self, tmp_path):
        sink = FailSafeAuditSink(ledger_path=tmp_path / "audit.db", hmac_key=b"test-key")
        for i in range(3):
            sink.write(MockAuditEntry(entry_id=f"chain_{i}"))

        valid, error = sink.verify_integrity()
        assert valid is True
        assert error is None

    def test_integrity_catches_tampering(self, tmp_path):
        db_path = tmp_path / "audit.db"
        sink = FailSafeAuditSink(ledger_path=db_path, hmac_key=b"test-key")
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
        sink = FailSafeAuditSink(ledger_path=tmp_path / "audit.db", hmac_key=b"test-key")
        sink.write(MockAuditEntry(entry_id="first"))
        hash_after_first = sink._prev_hash

        sink.write(MockAuditEntry(entry_id="second"))
        assert sink._prev_hash != hash_after_first  # Chain advanced

    def test_empty_ledger_integrity(self, tmp_path):
        sink = FailSafeAuditSink(ledger_path=tmp_path / "audit.db", hmac_key=b"test-key")
        valid, error = sink.verify_integrity()
        assert valid is True

    def test_close_is_noop(self, tmp_path):
        sink = FailSafeAuditSink(ledger_path=tmp_path / "audit.db", hmac_key=b"test-key")
        sink.close()  # Should not raise

    def test_creates_parent_dirs(self, tmp_path):
        deep_path = tmp_path / "a" / "b" / "c" / "audit.db"
        sink = FailSafeAuditSink(ledger_path=deep_path, hmac_key=b"test-key")
        sink.write(MockAuditEntry())
        assert deep_path.exists()

    def test_default_hmac_key_warns(self, tmp_path, caplog):
        """Explicit dev HMAC key logs a warning at construction."""
        import logging
        with caplog.at_level(logging.WARNING):
            FailSafeAuditSink(ledger_path=tmp_path / "warn.db", hmac_key=b"failsafe-dev-key")
        assert any("default dev HMAC key" in r.message for r in caplog.records)

    def test_custom_hmac_key_no_warning(self, tmp_path, caplog):
        """Custom HMAC key does not trigger the warning."""
        import logging
        with caplog.at_level(logging.WARNING):
            FailSafeAuditSink(ledger_path=tmp_path / "no_warn.db", hmac_key=b"prod-key")
        assert not any("default dev HMAC key" in r.message for r in caplog.records)

    def test_persistent_connection_reused(self, tmp_path):
        """Single connection is reused across multiple writes."""
        sink = FailSafeAuditSink(ledger_path=tmp_path / "persist.db", hmac_key=b"test-key")
        conn_id = id(sink._conn)
        sink.write(MockAuditEntry(entry_id="first"))
        sink.write(MockAuditEntry(entry_id="second"))
        assert id(sink._conn) == conn_id  # Same connection object

    def test_close_releases_connection(self, tmp_path):
        """close() sets _conn to None."""
        sink = FailSafeAuditSink(ledger_path=tmp_path / "close.db", hmac_key=b"test-key")
        assert sink._conn is not None
        sink.close()
        assert sink._conn is None

    def test_wal_mode_enabled(self, tmp_path):
        """WAL journal mode is set on the persistent connection."""
        import sqlite3
        sink = FailSafeAuditSink(ledger_path=tmp_path / "wal.db", hmac_key=b"test-key")
        mode = sink._conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode == "wal"


class TestVerifyAuditIntegrity:
    def test_standalone_function(self, tmp_path):
        """Module-level verify_audit_integrity works independently."""
        from agent_failsafe.audit_sink import verify_audit_integrity
        db = tmp_path / "standalone.db"
        sink = FailSafeAuditSink(ledger_path=db, hmac_key=b"failsafe-dev-key")
        sink.write(MockAuditEntry(entry_id="s1"))
        sink.write(MockAuditEntry(entry_id="s2"))
        valid, error = verify_audit_integrity(db, b"failsafe-dev-key")
        assert valid is True
        assert error is None

    def test_standalone_detects_tampering(self, tmp_path):
        """Module-level function detects hash chain tampering."""
        import sqlite3
        from agent_failsafe.audit_sink import verify_audit_integrity
        db = tmp_path / "tamper.db"
        sink = FailSafeAuditSink(ledger_path=db, hmac_key=b"failsafe-dev-key")
        sink.write(MockAuditEntry(entry_id="t1"))
        sink.write(MockAuditEntry(entry_id="t2"))
        conn = sqlite3.connect(str(db))
        conn.execute("UPDATE audit_entries SET event_type = 'TAMPERED' WHERE id = 1")
        conn.commit()
        conn.close()
        valid, error = verify_audit_integrity(db, b"failsafe-dev-key")
        assert valid is False
        assert "mismatch" in error.lower()


class TestHmacKeyRequired:
    def test_hmac_key_none_raises(self, tmp_path):
        """Omitting hmac_key raises ValueError."""
        with pytest.raises(ValueError, match="hmac_key is required"):
            FailSafeAuditSink(ledger_path=tmp_path / "no_key.db")

    def test_explicit_dev_key_warns(self, tmp_path, caplog):
        """Explicit dev key works but warns."""
        import logging
        with caplog.at_level(logging.WARNING):
            sink = FailSafeAuditSink(
                ledger_path=tmp_path / "dev.db",
                hmac_key=b"failsafe-dev-key",
            )
        assert any("dev HMAC key" in r.message for r in caplog.records)
        sink.close()

    def test_repr_excludes_key(self, tmp_path):
        """__repr__ does not leak HMAC key."""
        sink = FailSafeAuditSink(
            ledger_path=tmp_path / "repr.db",
            hmac_key=b"super-secret-key",
        )
        r = repr(sink)
        assert "super-secret-key" not in r
        assert "FailSafeAuditSink" in r
        sink.close()
