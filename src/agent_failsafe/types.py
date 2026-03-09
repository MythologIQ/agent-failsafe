"""Shared types for the agent-failsafe adapter.

Defines the FailSafe-side contracts that the adapter translates
to/from the Microsoft Agent Governance Toolkit extension points.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional, Protocol, runtime_checkable


# ---------------------------------------------------------------------------
# Risk grading (mirrors FailSafe L1/L2/L3)
# ---------------------------------------------------------------------------


class RiskGrade(Enum):
    """FailSafe risk classification levels."""

    L1 = "L1"  # Auto-approved
    L2 = "L2"  # Sentinel review
    L3 = "L3"  # Human required


# ---------------------------------------------------------------------------
# Verdict decisions (mirrors FailSafe VerdictDecision)
# ---------------------------------------------------------------------------


class VerdictDecision(Enum):
    """Sentinel verdict outcomes."""

    PASS = "PASS"
    WARN = "WARN"
    BLOCK = "BLOCK"
    ESCALATE = "ESCALATE"
    QUARANTINE = "QUARANTINE"


# ---------------------------------------------------------------------------
# Governance actions (mirrors FailSafe GovernanceAction)
# ---------------------------------------------------------------------------


class GovernanceAction(Enum):
    """Actions subject to governance evaluation."""

    FILE_WRITE = "file.write"
    FILE_DELETE = "file.delete"
    INTENT_CREATE = "intent.create"
    INTENT_SEAL = "intent.seal"
    CHECKPOINT_CREATE = "checkpoint.create"
    AGENT_REGISTER = "agent.register"
    L3_APPROVE = "l3.approve"
    L3_REJECT = "l3.reject"


# ---------------------------------------------------------------------------
# Failure modes (Shadow Genome)
# ---------------------------------------------------------------------------


class FailureMode(Enum):
    """Shadow Genome failure classifications."""

    HALLUCINATION = "HALLUCINATION"
    INJECTION_VULNERABILITY = "INJECTION_VULNERABILITY"
    LOGIC_ERROR = "LOGIC_ERROR"
    SPEC_VIOLATION = "SPEC_VIOLATION"
    HIGH_COMPLEXITY = "HIGH_COMPLEXITY"
    SECRET_EXPOSURE = "SECRET_EXPOSURE"
    PII_LEAK = "PII_LEAK"
    DEPENDENCY_CONFLICT = "DEPENDENCY_CONFLICT"
    TRUST_VIOLATION = "TRUST_VIOLATION"
    OTHER = "OTHER"


# ---------------------------------------------------------------------------
# Trust stages (mirrors FailSafe CBT/KBT/IBT)
# ---------------------------------------------------------------------------


class TrustStage(Enum):
    """FailSafe trust evolution stages."""

    CBT = "CBT"  # Capability-Based Trust
    KBT = "KBT"  # Knowledge-Based Trust
    IBT = "IBT"  # Identity-Based Trust


# ---------------------------------------------------------------------------
# Persona types
# ---------------------------------------------------------------------------


class PersonaType(Enum):
    """FailSafe agent persona types."""

    SCRIVENER = "scrivener"
    SENTINEL = "sentinel"
    JUDGE = "judge"
    OVERSEER = "overseer"


# ---------------------------------------------------------------------------
# Core data classes
# ---------------------------------------------------------------------------


@dataclass
class DecisionRequest:
    """Request for a governance evaluation (Python mirror of FailSafe DecisionRequest)."""

    action: str
    agent_did: str
    intent_id: str = ""
    artifact_path: str = ""
    artifact_hash: str = ""
    payload: dict[str, Any] = field(default_factory=dict)
    nonce: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    workflow: str = ""


@dataclass
class DecisionResponse:
    """Result of a governance evaluation (Python mirror of FailSafe DecisionResponse)."""

    allowed: bool
    nonce: str = ""
    risk_grade: RiskGrade = RiskGrade.L1
    verdict: VerdictDecision = VerdictDecision.PASS
    conditions: list[str] = field(default_factory=list)
    reason: str = ""
    timestamp: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    ledger_entry_id: Optional[str] = None


@dataclass
class ShadowGenomeEntry:
    """A single failure-mode record from the Shadow Genome."""

    entry_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    agent_did: str = ""
    failure_mode: FailureMode = FailureMode.OTHER
    input_vector: str = ""
    causal_vector: str = ""
    negative_constraint: str = ""
    remediation_status: str = "UNRESOLVED"
    created_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))


@dataclass
class HeuristicResult:
    """Result of a single heuristic pattern check."""

    pattern_id: str
    matched: bool
    severity: str = "low"  # critical, high, medium, low
    snippet: str = ""


# ---------------------------------------------------------------------------
# FailSafe client protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class FailSafeClient(Protocol):
    """Protocol for communicating with a FailSafe governance engine.

    Implementations may use MCP (stdio), direct SQLite access, HTTP, etc.
    """

    def evaluate(self, request: DecisionRequest) -> DecisionResponse:
        """Evaluate a governance decision."""
        ...

    def classify_risk(self, file_path: str, content: str = "") -> RiskGrade:
        """Classify the risk grade of an artifact."""
        ...

    def get_shadow_genome(self, agent_did: str = "") -> list[ShadowGenomeEntry]:
        """Retrieve Shadow Genome entries, optionally filtered by agent."""
        ...
