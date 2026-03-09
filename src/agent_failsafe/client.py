"""FailSafe client implementations.

Provides concrete FailSafeClient implementations that communicate with
the FailSafe governance engine via different transports.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from pathlib import Path
from typing import Any

import yaml

from .types import (
    DecisionRequest,
    DecisionResponse,
    FailureMode,
    RiskGrade,
    ShadowGenomeEntry,
    VerdictDecision,
)

logger = logging.getLogger(__name__)

# Default L3 trigger keywords (from FailSafe risk_grading.yaml)
_DEFAULT_L3_TRIGGERS = frozenset({
    "auth", "login", "crypto", "payment", "private_key",
    "password", "api_key", "secret", "credential", "token",
})


class LocalFailSafeClient:
    """FailSafe client that reads policies and ledger directly.

    No Node.js or MCP dependency — reads FailSafe YAML policies and
    SQLite ledger from the filesystem. Suitable for testing, CI, and
    lightweight deployments.

    Args:
        config_dir: Path to FailSafe config directory (default: .failsafe/config).
        ledger_path: Path to SQLite ledger (default: .failsafe/ledger/ledger.db).
        l3_triggers: Set of keywords that trigger L3 risk grade.
    """

    def __init__(
        self,
        config_dir: str | Path = ".failsafe/config",
        ledger_path: str | Path = ".failsafe/ledger/ledger.db",
        l3_triggers: frozenset[str] | None = None,
    ) -> None:
        self.config_dir = Path(config_dir)
        self.ledger_path = Path(ledger_path)
        self.l3_triggers = l3_triggers or _DEFAULT_L3_TRIGGERS
        self._policies: dict[str, Any] = {}
        self._load_policies()

    def _load_policies(self) -> None:
        """Load risk grading policies from YAML config."""
        policy_dir = self.config_dir / "policies"
        if not policy_dir.exists():
            logger.debug("No policy directory at %s", policy_dir)
            return

        for policy_file in policy_dir.glob("*.yaml"):
            try:
                with open(policy_file) as f:
                    data = yaml.safe_load(f) or {}
                self._policies[policy_file.stem] = data
                logger.debug("Loaded policy: %s", policy_file.stem)
            except Exception as exc:
                logger.warning("Failed to load policy %s: %s", policy_file, exc)

        # Extract L3 triggers from risk_grading policy if present
        risk_policy = self._policies.get("risk_grading", {})
        triggers = risk_policy.get("l3_triggers", [])
        if triggers:
            self.l3_triggers = frozenset(triggers)

    def evaluate(self, request: DecisionRequest) -> DecisionResponse:
        """Evaluate a governance decision using local heuristics.

        Risk grading logic:
        - L3: artifact path or payload contains L3 trigger keywords
        - L2: action modifies files (file.write, file.delete)
        - L1: everything else (read-only, status checks)
        """
        risk_grade = self._classify_request(request)
        verdict = self._compute_verdict(request, risk_grade)

        allowed = verdict not in (VerdictDecision.BLOCK, VerdictDecision.QUARANTINE)
        reason = ""
        if not allowed:
            reason = f"Blocked: {verdict.value} at risk grade {risk_grade.value}"
        elif verdict == VerdictDecision.ESCALATE:
            reason = "L3 human approval required"

        response = DecisionResponse(
            allowed=allowed,
            nonce=request.nonce,
            risk_grade=risk_grade,
            verdict=verdict,
            reason=reason,
        )

        self._log_to_ledger(request, response)
        return response

    def classify_risk(self, file_path: str, content: str = "") -> RiskGrade:
        """Classify risk grade for a file path and optional content."""
        combined = f"{file_path} {content}".lower()
        if any(trigger in combined for trigger in self.l3_triggers):
            return RiskGrade.L3
        if any(ext in file_path.lower() for ext in (".py", ".js", ".ts", ".rs")):
            return RiskGrade.L2
        return RiskGrade.L1

    def get_shadow_genome(self, agent_did: str = "") -> list[ShadowGenomeEntry]:
        """Retrieve Shadow Genome entries from the ledger.

        Queries the FailSafe SQLite ledger for DIVERGENCE_DECLARED events
        and maps them to ShadowGenomeEntry instances.
        """
        if not self.ledger_path.exists():
            return []

        entries: list[ShadowGenomeEntry] = []
        try:
            conn = sqlite3.connect(str(self.ledger_path))
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            query = "SELECT * FROM ledger WHERE eventType = 'DIVERGENCE_DECLARED'"
            params: list[str] = []
            if agent_did:
                query += " AND agentDid = ?"
                params.append(agent_did)
            query += " ORDER BY timestamp DESC LIMIT 100"

            cursor.execute(query, params)
            for row in cursor.fetchall():
                payload = json.loads(row["payload"]) if row["payload"] else {}
                entries.append(ShadowGenomeEntry(
                    entry_id=str(row["id"]),
                    agent_did=row["agentDid"],
                    failure_mode=FailureMode(payload.get("failureMode", "OTHER")),
                    input_vector=payload.get("inputVector", ""),
                    causal_vector=payload.get("causalVector", ""),
                    negative_constraint=payload.get("negativeConstraint", ""),
                    remediation_status=payload.get("remediationStatus", "UNRESOLVED"),
                    created_at=row["timestamp"],
                ))
            conn.close()
        except Exception as exc:
            logger.warning("Failed to read Shadow Genome from ledger: %s", exc)

        return entries

    def _classify_request(self, request: DecisionRequest) -> RiskGrade:
        """Determine risk grade from request content."""
        searchable = f"{request.action} {request.artifact_path} {json.dumps(request.payload)}".lower()
        if any(trigger in searchable for trigger in self.l3_triggers):
            return RiskGrade.L3
        if request.action in ("file.write", "file.delete"):
            return RiskGrade.L2
        return RiskGrade.L1

    def _compute_verdict(self, request: DecisionRequest, risk_grade: RiskGrade) -> VerdictDecision:
        """Compute a verdict based on risk grade and action."""
        if risk_grade == RiskGrade.L3:
            return VerdictDecision.ESCALATE
        if risk_grade == RiskGrade.L2:
            return VerdictDecision.WARN
        return VerdictDecision.PASS

    def _log_to_ledger(self, request: DecisionRequest, response: DecisionResponse) -> None:
        """Append an evaluation record to the SQLite ledger."""
        if not self.ledger_path.parent.exists():
            return

        try:
            conn = sqlite3.connect(str(self.ledger_path))
            conn.execute("""
                CREATE TABLE IF NOT EXISTS evaluations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    action TEXT NOT NULL,
                    agent_did TEXT NOT NULL,
                    risk_grade TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    allowed INTEGER NOT NULL,
                    nonce TEXT,
                    reason TEXT
                )
            """)
            conn.execute(
                """INSERT INTO evaluations
                   (timestamp, action, agent_did, risk_grade, verdict, allowed, nonce, reason)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    response.timestamp,
                    request.action,
                    request.agent_did,
                    response.risk_grade.value,
                    response.verdict.value,
                    int(response.allowed),
                    response.nonce,
                    response.reason,
                ),
            )
            conn.commit()
            conn.close()
        except Exception as exc:
            logger.debug("Ledger write failed (non-critical): %s", exc)
