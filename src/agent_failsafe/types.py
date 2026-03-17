"""Shared types for the agent-failsafe adapter.

Defines the FailSafe-side contracts that the adapter translates
to/from the Microsoft Agent Governance Toolkit extension points.
"""

from __future__ import annotations

import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional, Protocol, runtime_checkable

_types_logger = logging.getLogger(__name__)


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


_GOVERNANCE_ACTIONS = frozenset(a.value for a in GovernanceAction)


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

    def __post_init__(self) -> None:
        if not self.action:
            raise ValueError("action must not be empty")
        if not self.agent_did:
            raise ValueError("agent_did must not be empty")
        if self.agent_did and not self.agent_did.startswith("did:"):
            _types_logger.warning("agent_did does not start with 'did:' prefix: %s", self.agent_did)
        if self.action not in _GOVERNANCE_ACTIONS:
            _types_logger.debug("Unknown governance action: %s", self.action)
        if self.artifact_path:
            self.artifact_path = os.path.normpath(self.artifact_path)


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
# SRE v2 types (circuit breaker, fleet health, multi-SLI)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CircuitBreakerConfig:
    """Configuration for circuit breaker thresholds."""

    half_open_threshold: int = 3  # Failures before half-open
    open_threshold: int = 5  # Failures before open
    recovery_threshold: int = 1  # Successes in half-open to close


@dataclass
class TrustDimension:
    """Single dimension of trust scoring."""

    name: str
    score: float  # 0.0-1.0
    weight: float  # 0.0-1.0, weights should sum to 1.0


@dataclass
class TrustScoreV2:
    """Agent trust score with optional dimensional breakdown."""

    agent_id: str
    stage: str  # CBT, KBT, IBT
    mesh_score: float
    total_score: Optional[float] = None
    tier: Optional[str] = None  # untrusted, limited, trusted, privileged
    dimensions: Optional[list[TrustDimension]] = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-compatible dict with camelCase keys."""
        d: dict[str, Any] = {
            "agentId": self.agent_id,
            "stage": self.stage,
            "meshScore": self.mesh_score,
        }
        if self.total_score is not None:
            d["totalScore"] = self.total_score
        if self.tier is not None:
            d["tier"] = self.tier
        if self.dimensions:
            d["dimensions"] = [
                {"name": dim.name, "score": dim.score, "weight": dim.weight}
                for dim in self.dimensions
            ]
        return d


@dataclass
class AuditEvent:
    """Governance audit event for Activity Feed."""

    id: str
    timestamp: str  # ISO 8601
    type: str  # file.write, config.modify, dependency.add, etc.
    agent_id: str
    action: str  # ALLOW, DENY, AUDIT
    reason: Optional[str] = None
    resource: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-compatible dict with camelCase keys."""
        d: dict[str, Any] = {
            "id": self.id,
            "timestamp": self.timestamp,
            "type": self.type,
            "agentId": self.agent_id,
            "action": self.action,
        }
        if self.reason is not None:
            d["reason"] = self.reason
        if self.resource is not None:
            d["resource"] = self.resource
        return d


@dataclass
class FleetAgent:
    """Per-agent health status for Fleet Health section."""

    agent_id: str
    status: str  # active, idle, error
    circuit_state: str  # closed, open, half-open
    task_count: int
    success_rate: float  # 0.0-1.0
    avg_latency_ms: float
    last_active_at: str  # ISO 8601
    trust_stage: str  # CBT, KBT, IBT - derived from success_rate

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-compatible dict with camelCase keys."""
        return {
            "agentId": self.agent_id,
            "status": self.status,
            "circuitState": self.circuit_state,
            "taskCount": self.task_count,
            "successRate": self.success_rate,
            "avgLatencyMs": self.avg_latency_ms,
            "lastActiveAt": self.last_active_at,
        }


@dataclass
class SliMetric:
    """Individual SLI for multi-SLI dashboard."""

    name: str
    target: float  # 0.0-1.0
    current_value: Optional[float]  # 0.0-1.0, None if no data
    meeting_target: Optional[bool]
    total_decisions: int
    error_budget_remaining: Optional[float] = None  # 0.0-1.0

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-compatible dict with camelCase keys."""
        d: dict[str, Any] = {
            "name": self.name,
            "target": self.target,
            "currentValue": self.current_value,
            "meetingTarget": self.meeting_target,
            "totalDecisions": self.total_decisions,
        }
        if self.error_budget_remaining is not None:
            d["errorBudgetRemaining"] = self.error_budget_remaining
        return d


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
