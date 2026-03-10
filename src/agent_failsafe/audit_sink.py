"""AuditSink that writes to the FailSafe Merkle-chained SQLite ledger."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import sqlite3
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from .types import DecisionRequest, DecisionResponse

logger = logging.getLogger(__name__)


def decision_to_audit_entry(
    request: DecisionRequest,
    response: DecisionResponse,
) -> SimpleNamespace:
    """Map a governance decision to an AuditEntry-compatible object."""
    return SimpleNamespace(
        entry_id=response.nonce or "",
        timestamp=response.timestamp,
        event_type="governance_eval",
        agent_did=request.agent_did,
        action=request.action,
        resource=request.artifact_path or None,
        target_did=None,
        data={"verdict": response.verdict.value, "reason": response.reason},
        outcome="allowed" if response.allowed else "blocked",
        policy_decision=response.verdict.value,
        matched_rule=None,
        trace_id=None,
        session_id=None,
    )


def _extract_record(entry: Any) -> dict[str, Any]:
    """Extract a record dict from an AuditEntry-like object."""
    return {
        "entry_id": getattr(entry, "entry_id", ""),
        "timestamp": str(getattr(entry, "timestamp", "")),
        "event_type": getattr(entry, "event_type", ""),
        "agent_did": getattr(entry, "agent_did", ""),
        "action": getattr(entry, "action", ""),
        "resource": getattr(entry, "resource", None),
        "target_did": getattr(entry, "target_did", None),
        "data": json.dumps(getattr(entry, "data", {})),
        "outcome": getattr(entry, "outcome", "success"),
        "policy_decision": getattr(entry, "policy_decision", None),
        "matched_rule": getattr(entry, "matched_rule", None),
        "trace_id": getattr(entry, "trace_id", None),
        "session_id": getattr(entry, "session_id", None),
    }


def _sign_record(
    record: dict[str, Any],
    prev_hash: str,
    hmac_key: bytes,
) -> tuple[str, str]:
    """Compute entry hash and HMAC signature. Returns (hash, signature)."""
    content = FailSafeAuditSink._content_for_hash(record)
    entry_hash = hashlib.sha256(f"{prev_hash}:{content}".encode()).hexdigest()
    signature = hmac.new(hmac_key, entry_hash.encode(), hashlib.sha256).hexdigest()
    return entry_hash, signature


class FailSafeAuditSink:
    """Audit sink that writes Agent Mesh audit entries to the FailSafe ledger.

    Implements the ``agentmesh.governance.audit_backends.AuditSink`` protocol.
    Each entry is HMAC-signed and Merkle-chained for tamper evidence.

    Args:
        ledger_path: Path to the FailSafe SQLite ledger database.
        hmac_key: Secret key for HMAC-SHA256 signatures.
            Defaults to a derived key (suitable for dev/test only).
    """

    def __init__(
        self,
        ledger_path: str | Path = ".failsafe/ledger/ledger.db",
        hmac_key: bytes = b"failsafe-dev-key",
    ) -> None:
        self.ledger_path = Path(ledger_path)
        self.hmac_key = hmac_key
        if hmac_key == b"failsafe-dev-key":
            logger.warning("FailSafeAuditSink: using default dev HMAC key — set hmac_key for production")
        self._lock = threading.Lock()
        self._prev_hash = "0" * 64
        self._entry_count = 0
        self._ensure_table()

    def write(self, entry: Any) -> None:
        """Write a single audit entry to the FailSafe ledger.

        Conforms to ``AuditSink.write(entry: AuditEntry) -> None``.
        """
        with self._lock:
            self._write_entry(entry)

    def write_batch(self, entries: list[Any]) -> None:
        """Write a batch of audit entries to the FailSafe ledger.

        Conforms to ``AuditSink.write_batch(entries: list[AuditEntry]) -> None``.
        """
        with self._lock:
            for entry in entries:
                self._write_entry(entry)

    def verify_integrity(self) -> tuple[bool, str | None]:
        """Verify the hash chain integrity of the ledger.

        Conforms to ``AuditSink.verify_integrity() -> tuple[bool, str | None]``.
        """
        if not self.ledger_path.exists():
            return True, None

        try:
            conn = sqlite3.connect(str(self.ledger_path))
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM audit_entries ORDER BY id ASC"
            )

            prev_hash = "0" * 64
            for row in cursor.fetchall():
                content = self._content_for_hash(dict(row))
                expected_hash = hashlib.sha256(
                    f"{prev_hash}:{content}".encode()
                ).hexdigest()

                if row["entry_hash"] != expected_hash:
                    conn.close()
                    return False, (
                        f"Hash mismatch at entry {row['id']}: "
                        f"expected {expected_hash[:16]}..., "
                        f"got {row['entry_hash'][:16]}..."
                    )

                expected_sig = hmac.new(
                    self.hmac_key, expected_hash.encode(), hashlib.sha256
                ).hexdigest()
                if row["signature"] != expected_sig:
                    conn.close()
                    return False, f"Signature mismatch at entry {row['id']}"

                prev_hash = expected_hash

            conn.close()
            return True, None

        except Exception as exc:
            return False, f"Integrity verification failed: {exc}"

    def close(self) -> None:
        """Release resources (no-op for SQLite file access)."""
        pass

    def _ensure_table(self) -> None:
        """Create the audit_entries table if it doesn't exist."""
        if not self.ledger_path.parent.exists():
            self.ledger_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            conn = sqlite3.connect(str(self.ledger_path))
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entry_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    agent_did TEXT NOT NULL,
                    action TEXT NOT NULL,
                    resource TEXT,
                    target_did TEXT,
                    data TEXT NOT NULL DEFAULT '{}',
                    outcome TEXT NOT NULL DEFAULT 'success',
                    policy_decision TEXT,
                    matched_rule TEXT,
                    trace_id TEXT,
                    session_id TEXT,
                    entry_hash TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    signature TEXT NOT NULL
                )
            """)
            conn.commit()

            cursor = conn.execute(
                "SELECT entry_hash FROM audit_entries ORDER BY id DESC LIMIT 1"
            )
            row = cursor.fetchone()
            if row:
                self._prev_hash = row[0]

            conn.close()
        except Exception as exc:
            logger.warning("Failed to initialize audit table: %s", exc)

    def _write_entry(self, entry: Any) -> None:
        """Write a single entry (must hold _lock)."""
        record = _extract_record(entry)
        entry_hash, signature = _sign_record(record, self._prev_hash, self.hmac_key)

        record["entry_hash"] = entry_hash
        record["prev_hash"] = self._prev_hash
        record["signature"] = signature

        try:
            conn = sqlite3.connect(str(self.ledger_path))
            conn.execute(
                """INSERT INTO audit_entries
                   (entry_id, timestamp, event_type, agent_did, action,
                    resource, target_did, data, outcome, policy_decision,
                    matched_rule, trace_id, session_id,
                    entry_hash, prev_hash, signature)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    record["entry_id"], record["timestamp"], record["event_type"],
                    record["agent_did"], record["action"], record["resource"],
                    record["target_did"], record["data"], record["outcome"],
                    record["policy_decision"], record["matched_rule"],
                    record["trace_id"], record["session_id"],
                    entry_hash, self._prev_hash, signature,
                ),
            )
            conn.commit()
            conn.close()
            self._prev_hash = entry_hash
            self._entry_count += 1
        except Exception as exc:
            logger.error("Failed to write audit entry: %s", exc)

    @staticmethod
    def _content_for_hash(record: dict) -> str:
        """Build deterministic content string for hashing."""
        fields = [
            "entry_id", "timestamp", "event_type", "agent_did",
            "action", "resource", "outcome", "data",
        ]
        parts = [str(record.get(f, "")) for f in fields]
        return "|".join(parts)
