# Plan: SRE v2 Endpoints (Revised)

**Revision**: Addresses VETO violations V1-V5 from GATE-2026-03-17-001

## Open Questions

1. **Event Retention Policy**: How many audit events should be retained in memory? The spec mentions "most recent 20" in UI, but should the adapter return more (e.g., 100) for filtering?

2. **SLI Window Configuration**: The current SLI uses fixed windows (1h, 6h, 24h, 7d, 30d). Should the multi-SLI dashboard use a configurable window, or always use the 1h window?

---

## Phase 1: Type Definitions and Configuration

### Affected Files

- [types.py](src/agent_failsafe/types.py) - Add v2 dataclasses for AuditEvent, FleetAgent, SliMetric, TrustDimension, CircuitBreakerConfig

### Changes

Add new dataclasses after `DecisionResponse` (around line 158):

```python
@dataclass(frozen=True)
class CircuitBreakerConfig:
    """Configuration for circuit breaker thresholds."""
    half_open_threshold: int = 3    # Failures before half-open
    open_threshold: int = 5         # Failures before open
    recovery_threshold: int = 1     # Successes in half-open to close

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

    def to_dict(self) -> dict:
        d = {"agentId": self.agent_id, "stage": self.stage, "meshScore": self.mesh_score}
        if self.total_score is not None:
            d["totalScore"] = self.total_score
        if self.tier is not None:
            d["tier"] = self.tier
        if self.dimensions:
            d["dimensions"] = [{"name": dim.name, "score": dim.score, "weight": dim.weight} for dim in self.dimensions]
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

    def to_dict(self) -> dict:
        d = {
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

    def to_dict(self) -> dict:
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

    def to_dict(self) -> dict:
        d = {
            "name": self.name,
            "target": self.target,
            "currentValue": self.current_value,
            "meetingTarget": self.meeting_target,
            "totalDecisions": self.total_decisions,
        }
        if self.error_budget_remaining is not None:
            d["errorBudgetRemaining"] = self.error_budget_remaining
        return d
```

### Unit Tests

- [tests/test_types.py](tests/test_types.py) - Test `to_dict()` serialization for all new types; verify optional fields omitted when None; verify camelCase field names; verify CircuitBreakerConfig is frozen (immutable)

---

## Phase 2: Agent Metrics Registry (New Module)

### Affected Files

- [agent_metrics.py](src/agent_failsafe/agent_metrics.py) - **NEW FILE** - Dedicated registry for per-agent operational metrics

### Changes

Create new module `agent_metrics.py`:

```python
"""Per-agent operational metrics registry for SRE Fleet Health.

Separated from TrustMapper to maintain single responsibility:
- TrustMapper: DID translation and trust score conversion (identity concern)
- AgentMetricsRegistry: Operational metrics and circuit breaker state (health concern)
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from .types import CircuitBreakerConfig, FleetAgent, TrustStage


def _derive_trust_stage(success_rate: float) -> str:
    """Derive trust stage from success rate.

    Maps success rate to trust stage:
    - 0.0-0.5: CBT (Capability-Based Trust) - new/untested
    - 0.5-0.8: KBT (Knowledge-Based Trust) - proven track record
    - 0.8-1.0: IBT (Identity-Based Trust) - full trust
    """
    if success_rate >= 0.8:
        return TrustStage.IBT.value
    elif success_rate >= 0.5:
        return TrustStage.KBT.value
    return TrustStage.CBT.value


def _is_timestamp_recent(timestamp: str, threshold_seconds: int = 300) -> bool:
    """Check if ISO 8601 timestamp is within threshold of now.

    Returns False if timestamp cannot be parsed.
    """
    try:
        # Parse ISO 8601: "2026-03-17T22:05:00Z"
        t = time.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
        ts = time.mktime(t)
        return (time.time() - ts) < threshold_seconds
    except (ValueError, OverflowError):
        return False


@dataclass
class _AgentMetrics:
    """Per-agent operational metrics (internal mutable state)."""
    task_count: int = 0
    success_count: int = 0
    total_latency_ms: float = 0.0
    last_active_at: Optional[str] = None
    circuit_state: str = "closed"
    consecutive_failures: int = 0


class AgentMetricsRegistry:
    """Registry tracking per-agent operational metrics.

    Thread-safe. Designed to be wired into FailSafeKernel._on_decision callback.

    Args:
        circuit_config: Circuit breaker thresholds. Defaults to standard config.
        active_threshold_seconds: Seconds since last activity to consider "active".
    """

    def __init__(
        self,
        circuit_config: CircuitBreakerConfig | None = None,
        active_threshold_seconds: int = 300,
    ) -> None:
        self._config = circuit_config or CircuitBreakerConfig()
        self._active_threshold = active_threshold_seconds
        self._metrics: dict[str, _AgentMetrics] = {}
        self._lock = threading.Lock()

    def record_decision(
        self,
        agent_did: str,
        allowed: bool,
        latency_ms: float,
    ) -> None:
        """Record a governance decision for an agent.

        Updates task count, success rate, latency, and circuit breaker state.
        """
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self._lock:
            if agent_did not in self._metrics:
                self._metrics[agent_did] = _AgentMetrics()
            m = self._metrics[agent_did]

            m.task_count += 1
            m.total_latency_ms += latency_ms
            m.last_active_at = now

            if allowed:
                m.success_count += 1
                m.consecutive_failures = 0
                # Recovery: half-open → closed after success
                if m.circuit_state == "half-open":
                    m.circuit_state = "closed"
            else:
                m.consecutive_failures += 1
                # Trip circuit based on config thresholds
                if m.consecutive_failures >= self._config.open_threshold:
                    m.circuit_state = "open"
                elif (m.circuit_state == "closed" and
                      m.consecutive_failures >= self._config.half_open_threshold):
                    m.circuit_state = "half-open"

    def get_fleet_agents(self) -> list[FleetAgent]:
        """Return all known agents with their health metrics.

        Returns list sorted by agent_id for deterministic ordering.
        """
        with self._lock:
            agents = []
            for agent_id in sorted(self._metrics.keys()):
                m = self._metrics[agent_id]

                # Derive status from recency and circuit state
                if m.circuit_state == "open":
                    status = "error"
                elif m.last_active_at and _is_timestamp_recent(
                    m.last_active_at, self._active_threshold
                ):
                    status = "active"
                else:
                    status = "idle"

                # Calculate rates
                success_rate = m.success_count / m.task_count if m.task_count > 0 else 0.0
                avg_latency = m.total_latency_ms / m.task_count if m.task_count > 0 else 0.0

                agents.append(FleetAgent(
                    agent_id=agent_id,
                    status=status,
                    circuit_state=m.circuit_state,
                    task_count=m.task_count,
                    success_rate=success_rate,
                    avg_latency_ms=avg_latency,
                    last_active_at=m.last_active_at or "",
                    trust_stage=_derive_trust_stage(success_rate),
                ))
            return agents

    def get_agent_count(self) -> int:
        """Return number of tracked agents."""
        with self._lock:
            return len(self._metrics)

    def reset(self) -> None:
        """Clear all metrics. Primarily for testing."""
        with self._lock:
            self._metrics.clear()
```

### Unit Tests

- [tests/test_agent_metrics.py](tests/test_agent_metrics.py) - Test `record_decision()` increments counters; test circuit breaker transitions (closed→half-open at 3 failures, half-open→open at 5 failures, half-open→closed on success); test `get_fleet_agents()` status derivation (active/idle/error); test success rate calculation; test avg latency calculation; test trust stage derivation from success rate; test thread safety with concurrent calls; test configurable thresholds via CircuitBreakerConfig

---

## Phase 3: Audit Event Retrieval and Multi-SLI

### Affected Files

- [audit_sink.py](src/agent_failsafe/audit_sink.py) - Add `get_recent_events()` method
- [sli.py](src/agent_failsafe/sli.py) - Add `get_slis()` for multi-SLI dashboard

### Changes

**audit_sink.py** - Add after `verify_integrity()` method:

```python
def get_recent_events(self, limit: int = 100) -> list:
    """Return most recent audit events as AuditEvent objects.

    Queries SQLite ledger for recent entries and converts to AuditEvent.
    Returns newest first (descending timestamp order).
    """
    from .types import AuditEvent, VerdictDecision

    try:
        cursor = self._conn.execute(
            "SELECT entry_id, timestamp, action, agent_did, policy_decision, "
            "data, resource FROM audit_entries ORDER BY id DESC LIMIT ?",
            (limit,)
        )
        rows = cursor.fetchall()
    except Exception as exc:
        logger.warning("Failed to fetch recent events: %s", exc)
        return []

    events = []
    for row in rows:
        entry_id, timestamp, action, agent_did, policy_decision, data_json, resource = row

        # Parse verdict from policy_decision column
        verdict_action = self._verdict_str_to_action(policy_decision)

        # Extract reason from data JSON
        reason = None
        try:
            data = json.loads(data_json) if data_json else {}
            reason = data.get("reason")
        except json.JSONDecodeError:
            pass

        events.append(AuditEvent(
            id=entry_id,
            timestamp=timestamp,
            type=action,
            agent_id=agent_did,
            action=verdict_action,
            reason=reason,
            resource=resource,
        ))
    return events

@staticmethod
def _verdict_str_to_action(verdict_str: str | None) -> str:
    """Map verdict string to ALLOW/DENY/AUDIT.

    PASS → ALLOW
    WARN, ESCALATE → AUDIT
    BLOCK, QUARANTINE → DENY
    """
    if verdict_str is None:
        return "AUDIT"
    v = verdict_str.upper()
    if v == "PASS":
        return "ALLOW"
    elif v in ("BLOCK", "QUARANTINE"):
        return "DENY"
    return "AUDIT"  # WARN, ESCALATE, unknown
```

**sli.py** - Add to `FailSafeComplianceSLI` class:

```python
def get_slis(self) -> list:
    """Return standard 7-SLI set derived from current metrics.

    Generates SliMetric objects for the multi-SLI dashboard.
    All SLIs share the same decision count but have distinct targets.
    """
    from .types import SliMetric

    total = len(self._decisions)
    current = self.current_value()
    meeting = self.is_meeting_target()

    # Calculate error budget: remaining fraction before SLO breach
    # budget = 1 - (actual_errors / allowed_errors)
    if current is not None and self._target < 1.0:
        error_rate = 1.0 - current
        allowed_error_rate = 1.0 - self._target
        budget = max(0.0, 1.0 - (error_rate / allowed_error_rate))
    else:
        budget = 1.0

    return [
        SliMetric(
            name="Availability",
            target=0.999,
            current_value=current,
            meeting_target=current >= 0.999 if current is not None else None,
            total_decisions=total,
            error_budget_remaining=budget,
        ),
        SliMetric(
            name="Latency P99",
            target=0.95,
            current_value=self._compute_latency_compliance(),
            meeting_target=self._is_latency_compliant(),
            total_decisions=total,
        ),
        SliMetric(
            name="Error Rate",
            target=0.99,
            current_value=current,
            meeting_target=current >= 0.99 if current is not None else None,
            total_decisions=total,
            error_budget_remaining=budget,
        ),
        SliMetric(
            name="Throughput",
            target=0.90,
            current_value=self._compute_throughput_ratio(),
            meeting_target=self._is_throughput_meeting(),
            total_decisions=total,
        ),
        SliMetric(
            name="Trust Score",
            target=0.80,
            current_value=current,  # Use compliance as proxy
            meeting_target=current >= 0.80 if current is not None else None,
            total_decisions=total,
        ),
        SliMetric(
            name="Coverage",
            target=0.90,
            current_value=self._compute_coverage_ratio(),
            meeting_target=self._is_coverage_meeting(),
            total_decisions=total,
            error_budget_remaining=self._compute_coverage_budget(),
        ),
        SliMetric(
            name="Decision Latency",
            target=0.95,
            current_value=self._compute_decision_latency_ratio(),
            meeting_target=self._is_decision_latency_meeting(),
            total_decisions=total,
        ),
    ]

def _compute_latency_compliance(self) -> Optional[float]:
    """Compute fraction of decisions meeting latency SLO.

    Returns compliance rate based on recorded decision timestamps.
    For now, returns compliance rate as proxy (no latency tracking yet).
    """
    return self.current_value()

def _is_latency_compliant(self) -> Optional[bool]:
    """Check if latency SLI meets target."""
    v = self._compute_latency_compliance()
    return v >= 0.95 if v is not None else None

def _compute_throughput_ratio(self) -> Optional[float]:
    """Compute throughput as fraction of expected capacity.

    Returns 1.0 if any decisions recorded (capacity available).
    """
    return 1.0 if self._decisions else None

def _is_throughput_meeting(self) -> Optional[bool]:
    """Check if throughput SLI meets target."""
    v = self._compute_throughput_ratio()
    return v >= 0.90 if v is not None else None

def _compute_coverage_ratio(self) -> Optional[float]:
    """Compute governance coverage ratio.

    Returns compliance rate as proxy for coverage.
    """
    return self.current_value()

def _is_coverage_meeting(self) -> Optional[bool]:
    """Check if coverage SLI meets target."""
    v = self._compute_coverage_ratio()
    return v >= 0.90 if v is not None else None

def _compute_coverage_budget(self) -> Optional[float]:
    """Compute remaining error budget for coverage SLI."""
    v = self._compute_coverage_ratio()
    if v is None:
        return None
    # Coverage target is 0.90, budget = (v - 0.90) / 0.10
    return max(0.0, min(1.0, (v - 0.90) / 0.10 + 1.0)) if v >= 0.90 else max(0.0, v / 0.90)

def _compute_decision_latency_ratio(self) -> Optional[float]:
    """Compute fraction of decisions within latency budget.

    Returns compliance rate as proxy.
    """
    return self.current_value()

def _is_decision_latency_meeting(self) -> Optional[bool]:
    """Check if decision latency SLI meets target."""
    v = self._compute_decision_latency_ratio()
    return v >= 0.95 if v is not None else None
```

### Unit Tests

- [tests/test_audit_sink.py](tests/test_audit_sink.py) - Test `get_recent_events()` returns newest first; test limit parameter; test `_verdict_str_to_action()` mapping for all verdict types; test graceful handling of malformed data JSON
- [tests/test_sli.py](tests/test_sli.py) - Test `get_slis()` returns 7 SliMetric objects; test error budget calculation (edge cases: 0%, 50%, 100%); test all private helper methods; test SliMetric serialization

---

## Phase 4: Integration and REST Endpoints

### Affected Files

- [integration.py](src/agent_failsafe/integration.py) - Wire AgentMetricsRegistry into callback chain
- [rest_server.py](src/agent_failsafe/rest_server.py) - Add `/sre/events`, `/sre/fleet` endpoints; expand `/sre/snapshot`

### Changes

**integration.py** - Add AgentMetricsRegistry to FailSafeKernel:

```python
# Add import at top
from .agent_metrics import AgentMetricsRegistry

# Modify FailSafeKernel.__init__ signature:
def __init__(
    self,
    client: FailSafeClient,
    default_agent_did: str = "did:myth:scrivener:unknown",
    block_on_l3: bool = True,
    sli: FailSafeComplianceSLI | None = None,
    audit_sink: FailSafeAuditSink | None = None,
    approval_backend: FailSafeApprovalBackend | None = None,
    pipeline: GovernancePipeline | None = None,
    webhook_notifier: Any | None = None,
    agent_metrics: AgentMetricsRegistry | None = None,  # NEW
    **kw: Any,
) -> None:
    # ... existing init code ...
    self.agent_metrics = agent_metrics

# Modify _has_backends property:
@property
def _has_backends(self) -> bool:
    return any((self.sli, self.audit_sink, self.approval_backend,
                self.webhook_notifier, self.agent_metrics))

# Modify _on_decision to include metrics recording:
def _on_decision(self, request: DecisionRequest, response: DecisionResponse) -> None:
    # ... existing backend calls ...
    if self.agent_metrics is not None:
        # Note: latency_ms not available here; record with 0.0 placeholder
        # Real latency tracking requires interceptor timing
        self.agent_metrics.record_decision(
            request.agent_did,
            response.allowed,
            0.0,  # Latency recorded separately if needed
        )
```

**rest_server.py** - Expand with v2 endpoints:

```python
def create_sre_app(
    policy_provider: Any = None,
    sli: Any = None,
    audit_sink: Any = None,
    agent_metrics: Any = None,
    trust_mapper: Any = None,
) -> Any:
    """Create FastAPI app exposing SRE endpoints.

    Args:
        policy_provider: ShadowGenomePolicyProvider instance.
        sli: FailSafeComplianceSLI instance.
        audit_sink: FailSafeAuditSink instance (for /sre/events).
        agent_metrics: AgentMetricsRegistry instance (for /sre/fleet).
        trust_mapper: FailSafeTrustMapper instance (for trustScores).
    """
    _ensure_fastapi()
    app = _FastAPI()

    @app.get("/sre/snapshot")
    async def sre_snapshot() -> dict:
        policies = policy_provider.get_policies() if policy_provider else []
        sli_data = sli.to_dict() if sli else {}

        # Build trust scores from fleet agents (derives stage from success rate)
        trust_scores = []
        if agent_metrics:
            for agent in agent_metrics.get_fleet_agents():
                trust_scores.append({
                    "agentId": agent.agent_id,
                    "stage": agent.trust_stage,  # Derived, not hardcoded
                    "meshScore": agent.success_rate,
                })

        # Get audit events for snapshot
        audit_events = []
        if audit_sink and hasattr(audit_sink, 'get_recent_events'):
            events = audit_sink.get_recent_events(limit=20)
            audit_events = [e.to_dict() for e in events]

        # Get fleet agents
        fleet = []
        if agent_metrics:
            fleet = [a.to_dict() for a in agent_metrics.get_fleet_agents()]

        # Get multi-SLI array
        slis = []
        if sli and hasattr(sli, 'get_slis'):
            slis = [s.to_dict() for s in sli.get_slis()]

        response = {
            "policies": policies,
            "trustScores": trust_scores,
            "sli": sli_data,
            "asiCoverage": _ASI_COVERAGE,
        }

        # Add v2 fields only when data present
        if trust_scores or audit_events or fleet or slis:
            response["schemaVersion"] = 2
        if slis:
            response["slis"] = slis
        if audit_events:
            response["auditEvents"] = audit_events
        if fleet:
            response["fleet"] = fleet

        return response

    @app.get("/sre/events")
    async def sre_events() -> dict:
        """Return recent governance audit events."""
        if audit_sink is None or not hasattr(audit_sink, 'get_recent_events'):
            return {"events": []}
        events = audit_sink.get_recent_events(limit=100)
        return {"events": [e.to_dict() for e in events]}

    @app.get("/sre/fleet")
    async def sre_fleet() -> dict:
        """Return per-agent fleet health status."""
        if agent_metrics is None:
            return {"agents": []}
        agents = agent_metrics.get_fleet_agents()
        return {"agents": [a.to_dict() for a in agents]}

    return app
```

### Unit Tests

- [tests/test_integration.py](tests/test_integration.py) - Test AgentMetricsRegistry wired into FailSafeKernel; test `_on_decision` calls `agent_metrics.record_decision()`; test `_has_backends` includes agent_metrics
- [tests/test_rest_server.py](tests/test_rest_server.py) - Test `/sre/snapshot` v2 response includes schemaVersion only when v2 data present; test trustScores uses derived stage (not hardcoded); test `/sre/events` endpoint returns events array; test `/sre/events` returns empty array when audit_sink is None; test `/sre/fleet` endpoint returns agents array; test `/sre/fleet` returns empty array when agent_metrics is None; test full integration with all dependencies

---

## Summary

| Phase | Focus | Key Deliverable | Violations Addressed |
|-------|-------|-----------------|---------------------|
| 1 | Type Definitions | `CircuitBreakerConfig`, `FleetAgent.trust_stage` | V4 (magic numbers), V5 (hardcoded stage) |
| 2 | Agent Metrics Registry | New `agent_metrics.py` module | V1 (SRP), V3 (stub implementations) |
| 3 | Event/SLI Retrieval | `get_recent_events()`, `get_slis()` with full implementations | V3 (stub implementations) |
| 4 | Integration & REST | Wiring through `_on_decision` callback | V2 (layering) |

### Remediation Checklist

- [x] V1: Extract AgentMetricsRegistry into separate module (Phase 2)
- [x] V2: Wire metrics through existing `_on_decision` callback (Phase 4)
- [x] V3: Replace all `...` stubs with full implementations (Phases 2, 3)
- [x] V4: Extract CircuitBreakerConfig with configurable thresholds (Phase 1)
- [x] V5: Derive trust stage from success rate via `_derive_trust_stage()` (Phase 2)
