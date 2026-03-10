# agent-failsafe: Adapter Architecture & Usage Guide

**Version**: 0.3.0 | **Python**: >= 3.11 | **License**: MIT
**Status**: Alpha (all adapters implemented, 277 tests passing)

---

## Problem

The [Microsoft Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit) provides deterministic policy enforcement, zero-trust identity, and execution sandboxing for autonomous AI agents. It exposes extension points for interceptors, integrations, policy providers, SLIs, audit sinks, and escalation backends.

[FailSafe](https://github.com/MythologIQ/FailSafe) is a separate governance engine (MythologIQ IP) with its own Shadow Genome, Merkle-chained ledger, risk grading, and persona-based DID system (`did:myth`).

**agent-failsafe** bridges the two. It adapts FailSafe into the toolkit's extension points without modifying either system. FailSafe adapts to the toolkit, not the reverse.

---

## Architecture

```
Agent (any framework)
  |
  v
FailSafeInterceptor ──── ToolCallInterceptor protocol (agent-os)
  |
  v
FailSafeClient ──────── LocalFailSafeClient (filesystem)
  |                      MCPFailSafeClient   (JSON-RPC stdio)
  v
GovernancePipeline ───── Orchestrates all stages below:
  |
  ├─ Governance Eval ─── FailSafeClient.evaluate()
  ├─ SRE Health ──────── Circuit breaker check (injectable)
  ├─ Ring Assignment ─── FailSafeRingAdapter → ExecutionRing
  ├─ SLI Recording ───── FailSafeComplianceSLI
  └─ Audit Logging ───── FailSafeAuditSink → Merkle-chained SQLite
```

### Extension Point Mapping

| Adapter Module       | Toolkit Extension Point    | Protocol                                |
|----------------------|----------------------------|-----------------------------------------|
| `interceptor.py`       | ToolCallInterceptor        | `intercept(request) -> result`          |
| `integration.py`       | BaseIntegration            | `wrap()`, `evaluate()`, `unwrap()`      |
| `pipeline.py`          | Full lifecycle orchestration | `evaluate(request) -> PipelineResult` |
| `ring_adapter.py`      | ExecutionRing + KillSwitch | `decision_to_ring()`, `request_kill()`  |
| `trust_validator.py`   | ValidatorInterface         | `validate_request()`, `metadata`        |
| `policy_provider.py`   | PolicyProviderInterface    | `get_policies()`, `refresh()`           |
| `sli.py`               | SLI (agent-sre)            | `record_decision()`, `current_value()`  |
| `audit_sink.py`        | AuditSink                  | `write()`, `verify_integrity()`         |
| `escalation.py`        | ApprovalBackend            | `submit()`, `approve()`, `deny()`       |
| `trust_mapper.py`      | DID translation            | `myth_to_mesh()`, `mesh_to_myth()`      |
| `webhook_events.py`    | WebhookEvent translation   | `decision_to_webhook_event()`           |

### Dependency Strategy

Only `pyyaml` is required. All toolkit packages are optional:

```toml
# pyproject.toml
dependencies = ["pyyaml>=6.0"]

[project.optional-dependencies]
agent-os  = ["agent-os-kernel>=1.1.0"]
agent-sre = ["agent-sre>=1.1.0"]
agent-mesh = ["agentmesh-platform>=1.1.0"]
agent-hypervisor = ["agent-hypervisor>=1.1.0"]
full = ["agent-os-kernel>=1.1.0", "agent-sre>=1.1.0", "agentmesh-platform>=1.1.0", "agent-hypervisor>=1.1.0"]
```

Every adapter module uses lazy imports. If a toolkit package is missing, the adapter degrades gracefully or raises a clear `ImportError` at call time (not import time).

---

## Installation

```bash
# Core only (types, clients, patterns, trust scoring)
pip install agent-failsafe

# With specific toolkit packages
pip install agent-failsafe[agent-os]          # Interceptor + Integration + Webhook events
pip install agent-failsafe[agent-sre]         # SLI + Signal generation
pip install agent-failsafe[agent-mesh]        # Audit sink
pip install agent-failsafe[agent-hypervisor]  # ExecutionRing + KillSwitch

# Everything
pip install agent-failsafe[full]
```

---

## Core Types

### DecisionRequest

Every governance evaluation starts with a `DecisionRequest`:

```python
from agent_failsafe import DecisionRequest

request = DecisionRequest(
    action="file.write",                    # GovernanceAction string
    agent_did="did:myth:scrivener:a1b2c3",  # FailSafe DID
    artifact_path="/src/main.py",           # File being acted on
    payload={"content": "..."},             # Optional context
)
```

**Actions** (`GovernanceAction` enum values):
`file.write`, `file.delete`, `intent.create`, `intent.seal`, `checkpoint.create`, `agent.register`, `l3.approve`, `l3.reject`

### DecisionResponse

Every evaluation returns a `DecisionResponse`:

```python
from agent_failsafe import DecisionResponse, RiskGrade, VerdictDecision

response = DecisionResponse(
    allowed=True,
    risk_grade=RiskGrade.L1,         # L1 (auto) | L2 (sentinel) | L3 (human)
    verdict=VerdictDecision.PASS,    # PASS | WARN | BLOCK | ESCALATE | QUARANTINE
    reason="Low risk, auto-approved",
    nonce="abc123",
    timestamp="2026-03-10T05:00:00Z",
)
```

### Risk Grades

| Grade | Meaning | Routing |
|-------|---------|---------|
| L1    | Low risk | Auto-approved |
| L2    | Moderate risk | Sentinel review |
| L3    | High risk | Human approval required |

### Verdict Decisions

| Verdict    | Effect | Pipeline Behavior |
|------------|--------|-------------------|
| PASS       | Allowed | Proceeds through all stages |
| WARN       | Allowed with conditions | Proceeds, conditions recorded |
| BLOCK      | Denied | Halts at governance stage |
| ESCALATE   | Denied pending human approval | Halts at governance stage |
| QUARANTINE | Denied, agent flagged | Triggers `behavioral_drift` kill reason |

---

## Clients

### LocalFailSafeClient

Reads FailSafe YAML policies and SQLite ledger directly. No Node.js or MCP server required.

```python
from agent_failsafe import LocalFailSafeClient, DecisionRequest

client = LocalFailSafeClient(
    config_dir=".failsafe/config",           # Policy YAML location
    ledger_path=".failsafe/ledger/ledger.db", # SQLite ledger
)

request = DecisionRequest(
    action="file.write",
    agent_did="did:myth:scrivener:a1b2c3",
    artifact_path="/src/auth.py",
)

response = client.evaluate(request)
# response.risk_grade == RiskGrade.L3 (path contains "auth")
# response.allowed == False
```

**Risk grading logic**:
- L3 if artifact path or payload contains L3 triggers (auth, login, crypto, payment, private_key, password, api_key, secret, credential, token)
- L2 if action modifies files (`file.write`, `file.delete`)
- L1 otherwise

### MCPFailSafeClient

Communicates with FailSafe VS Code extension via JSON-RPC over stdio.

```python
from agent_failsafe import MCPFailSafeClient

client = MCPFailSafeClient(
    server_command=["node", "dist/mcp-server.js"],  # MCP server startup
    intent_id="session-001",
    timeout=30.0,
)

response = client.evaluate(request)
client.close()  # Clean up subprocess
```

**MCP tools called**: `sentinel_audit_file`, `ledger_log_decision`, `qorelogic_status`

### FailSafeClient Protocol

Both clients implement the `FailSafeClient` protocol. Custom clients must implement:

```python
from agent_failsafe import FailSafeClient

class MyClient:
    def evaluate(self, request: DecisionRequest) -> DecisionResponse: ...
    def classify_risk(self, file_path: str, content: str = "") -> RiskGrade: ...
    def get_shadow_genome(self, agent_did: str = "") -> list[ShadowGenomeEntry]: ...
```

---

## Adapters

### 1. FailSafeInterceptor

Plugs into the Agent OS `CompositeInterceptor` chain. Evaluates every tool call against FailSafe governance.

```python
from agent_failsafe import FailSafeInterceptor, LocalFailSafeClient

client = LocalFailSafeClient()
interceptor = FailSafeInterceptor(
    client=client,
    default_agent_did="did:myth:scrivener:a1b2c3",
    block_on_l3=True,  # Block L3 actions (default: True)
)

# Register with Agent OS CompositeInterceptor
from agent_os.integrations.base import CompositeInterceptor
composite = CompositeInterceptor()
composite.add(interceptor)
```

**Decision callback**: Wire post-decision side effects (SLI, audit) via `on_decision`:

```python
def my_callback(request, response):
    print(f"Decision: {response.verdict.value} for {request.action}")

interceptor = FailSafeInterceptor(client=client, on_decision=my_callback)
```

### 2. FailSafeKernel (BaseIntegration)

Full agent lifecycle integration registered as `@register_adapter("failsafe")`.

```python
from agent_failsafe import FailSafeKernel, LocalFailSafeClient

client = LocalFailSafeClient()
kernel = FailSafeKernel(client)

# Wrap an agent with governance
governed_agent = kernel.wrap(my_agent)

# Direct evaluation
allowed = kernel.evaluate("did:myth:scrivener:abc", "file.write")
```

**With all backends**:

```python
from agent_failsafe import (
    FailSafeKernel,
    FailSafeComplianceSLI,
    FailSafeAuditSink,
    FailSafeApprovalBackend,
    GovernancePipeline,
    LocalFailSafeClient,
)

client = LocalFailSafeClient()
sli = FailSafeComplianceSLI(target=0.95, window="24h")
audit = FailSafeAuditSink(ledger_path=".failsafe/ledger/ledger.db")
approval = FailSafeApprovalBackend(client=client)
pipeline = GovernancePipeline(
    client=client,
    sli=sli,
    audit_sink=audit,
)

kernel = FailSafeKernel(
    client=client,
    sli=sli,
    audit_sink=audit,
    approval_backend=approval,
    pipeline=pipeline,
    webhook_notifier=my_notifier,  # Optional: duck-typed .notify(event)
)
```

**Adapter registry lookup**:

```python
from agent_os.integrations.registry import AdapterRegistry

registry = AdapterRegistry()
FailSafeKernelClass = registry.get("failsafe")  # Returns FailSafeKernel
```

### 3. GovernancePipeline

Composes all adapters into a sequential 5-stage pipeline. Returns an immutable `PipelineResult`.

```python
from agent_failsafe import (
    GovernancePipeline,
    LocalFailSafeClient,
    FailSafeRingAdapter,
    FailSafeComplianceSLI,
    FailSafeAuditSink,
    DecisionRequest,
)

client = LocalFailSafeClient()

pipeline = GovernancePipeline(
    client=client,
    ring_adapter=FailSafeRingAdapter(),           # Optional (has defaults)
    sli=FailSafeComplianceSLI(target=0.95),       # Optional
    audit_sink=FailSafeAuditSink(),               # Optional
    circuit_breaker_fn=lambda did: True,           # Optional: returns True if healthy
)

request = DecisionRequest(action="file.write", agent_did="did:myth:scrivener:abc")
result = pipeline.evaluate(request)

result.allowed          # bool — final allow/deny decision
result.stage            # PipelineStage — how far the pipeline progressed
result.governance       # DecisionResponse | None — raw governance response
result.execution_ring   # int — assigned privilege ring (2=standard, 3=sandbox)
result.kill_reason      # str | None — kill reason if QUARANTINE
result.circuit_breaker_open  # bool — True if SRE halted execution
result.halted_reason    # str — human-readable halt explanation
```

**Pipeline stages**:

| Stage | What Happens | Halt Condition |
|-------|-------------|----------------|
| GOVERNANCE | Policy evaluation | `allowed=False` or `verdict=ESCALATE` |
| SRE_HEALTH | Circuit breaker check | `circuit_breaker_fn(agent_did)` returns `False` |
| RING_ASSIGNED | Map risk grade to execution ring | Never halts |
| AUDITED | Record SLI + write audit entry | Never halts (terminal stage) |

**Fail-open**: If the governance client throws an exception, the pipeline returns `allowed=True` with `halted_reason` explaining the degradation.

**Circuit breaker injection**: Pass any `Callable[[str], bool]` to avoid hard-coupling to agent-sre:

```python
from agent_sre.circuit_breaker import CircuitBreakerRegistry

registry = CircuitBreakerRegistry()
pipeline = GovernancePipeline(
    client=client,
    circuit_breaker_fn=lambda did: registry.is_available(did),
)
```

**Via FailSafeKernel**:

```python
kernel = FailSafeKernel(client=client, pipeline=pipeline)
result = kernel.pipeline_evaluate(request)

# Without a pipeline, falls back to basic eval wrapped in PipelineResult
kernel_basic = FailSafeKernel(client=client)
result = kernel_basic.pipeline_evaluate(request)  # Works, but no SRE/ring/audit stages
```

### 4. FailSafeRingAdapter

Maps governance decisions to hypervisor execution rings. Int-based methods work with zero dependencies; typed methods require `agent-hypervisor`.

```python
from agent_failsafe import FailSafeRingAdapter

adapter = FailSafeRingAdapter()

# Int-based (always works)
ring = adapter.decision_to_ring(response)       # int (2 or 3)
kill = adapter.decision_to_kill_reason(response) # str | None

# Typed (requires agent-hypervisor)
ring_enum = adapter.decision_to_execution_ring(response)    # ExecutionRing enum
kill_enum = adapter.decision_to_kill_reason_enum(response)  # KillReason | None

# KillSwitch integration
result = adapter.request_kill(
    response=response,
    agent_did="did:myth:scrivener:abc",
    session_id="session-001",
)
# Returns KillResult if QUARANTINE, None otherwise
```

**Mapping rules**:

| Verdict     | Ring | Kill Reason |
|-------------|------|-------------|
| PASS        | 2 (Standard) | None |
| WARN        | 2 (Standard) | None |
| ESCALATE    | 3 (Sandbox)  | None |
| BLOCK       | 3 (Sandbox)  | None |
| QUARANTINE  | 3 (Sandbox)  | `"behavioral_drift"` |

Trust-based ring assignment: `adapter.trust_score_to_ring(0.7)` returns 2 (Standard) if score > 0.60, else 3 (Sandbox).

### 5. FailSafeTrustMapper

Bidirectional DID translation between FailSafe (`did:myth`) and Agent Mesh (`did:mesh`).

```python
from agent_failsafe import FailSafeTrustMapper, TrustStage, PersonaType

mapper = FailSafeTrustMapper(default_trust_score=500)

# DID translation
mesh_did = mapper.myth_to_mesh("did:myth:scrivener:a1b2c3d4")
myth_did = mapper.mesh_to_myth(mesh_did)  # Reverse lookup (cached)

# Trust score conversion
mesh_score = mapper.trust_to_mesh_score(
    trust_score=0.75,
    trust_stage=TrustStage.KBT,
    persona=PersonaType.SENTINEL,
)
# mesh_score: 625 (KBT range 400-700, scaled + sentinel modifier +100)

trust, stage = mapper.mesh_score_to_trust(625)
# trust: ~0.75, stage: TrustStage.KBT
```

**Trust stages** (CBT/KBT/IBT progression):

| Stage | Score Range (Mesh) | Meaning |
|-------|--------------------|---------|
| CBT   | 100-400 | Capability-Based Trust (new agent, proving competence) |
| KBT   | 400-700 | Knowledge-Based Trust (established track record) |
| IBT   | 700-1000 | Identity-Based Trust (deeply trusted, minimal oversight) |

### 6. FailSafeComplianceSLI

Measures governance compliance rate for SRE alerting.

```python
from agent_failsafe import FailSafeComplianceSLI, decision_to_signal

sli = FailSafeComplianceSLI(target=0.95, window="24h")
sli.record_decision(response)

compliance = sli.current_value()   # float (0.0-1.0) or None if no data
on_target = sli.is_meeting_target()  # bool or None
```

**SRE Signal generation** (requires agent-sre):

```python
signal = decision_to_signal(response, source="failsafe")
# Returns Signal for BLOCK/ESCALATE decisions, None otherwise
```

**SRE-native SLI** (subclasses agent-sre `SLI`):

```python
from agent_failsafe import create_sre_sli

sli = create_sre_sli(target=0.95, window="24h")
# Returns agent-sre SLI subclass if available, else standalone
```

### 7. FailSafeAuditSink

Writes tamper-evident audit entries to FailSafe's Merkle-chained SQLite ledger.

```python
from agent_failsafe import FailSafeAuditSink, decision_to_audit_entry

sink = FailSafeAuditSink(
    ledger_path=".failsafe/ledger/ledger.db",
    hmac_key=b"your-production-key",  # Default is dev-only key
)

entry = decision_to_audit_entry(request, response)
sink.write(entry)

# Verify ledger integrity
valid, broken_at = sink.verify_integrity()
```

**Audit entry fields**: `entry_id`, `event_type`, `agent_did`, `action`, `resource`, `outcome` ("allowed"/"denied"), `policy_decision`, `data`, `timestamp`.

**Security**: Entries are HMAC-SHA256 signed and hash-chained. A warning is logged if the default dev key is used.

### 8. FailSafeApprovalBackend

Routes L3 escalation requests to FailSafe's human approval workflow.

```python
from agent_failsafe import FailSafeApprovalBackend

approval = FailSafeApprovalBackend(
    client=client,
    overseer_did="did:myth:overseer:local",
    max_requests=1000,  # FIFO eviction
)

approval.submit(escalation_request)
pending = approval.list_pending()
approval.approve("request-id", approver="admin@example.com")
```

### 9. ShadowGenomePolicyProvider

Derives deny policies from Shadow Genome failure records.

```python
from agent_failsafe import ShadowGenomePolicyProvider

provider = ShadowGenomePolicyProvider(client=client, agent_did="did:myth:scrivener:abc")
provider.refresh()  # Load from Shadow Genome

policies = provider.get_policies(action_type="file.write")
# Returns deny policies for failure modes affecting file writes
```

### 10. FailSafeTrustValidator

Validates requests using CBT/KBT/IBT trust stage gating. Duck-types the control plane `ValidatorInterface` protocol — works without `agent-os-kernel` installed.

```python
from agent_failsafe import FailSafeTrustValidator, LocalFailSafeClient

client = LocalFailSafeClient()
validator = FailSafeTrustValidator(client=client)

# Validate a request with trust context
result = validator.validate_request(
    request=tool_request,
    context={"agent_did": "did:myth:scrivener:abc", "trust_score": 0.6},
)
result.is_valid         # bool
result.reason           # str (empty if valid)
result.details          # {"trust_score": 0.6, "trust_stage": "KBT", ...}
result.corrective_actions  # list[str] (suggestions if denied)

# Register with control plane (when agent-os-kernel installed)
from agent_control_plane.control_plane import AgentControlPlane
control_plane = AgentControlPlane()
control_plane.register_validator(validator, action_types=["file.write", "file.delete"])
```

**Trust stage gating**:

| Stage | Allowed Risk Grades | Score Range |
|-------|---------------------|-------------|
| CBT   | L1 only            | < 0.50 |
| KBT   | L1 + L2            | 0.50 - 0.80 |
| IBT   | L1 + L2 + L3       | >= 0.80 |

**Validation log**: `validator.get_validation_log(limit=100)` returns recent entries (deque-backed, default capacity 500).

### 11. Webhook Event Translation

Pure functions that translate governance decisions into `WebhookEvent` objects for the toolkit's `WebhookNotifier`. Returns `SimpleNamespace` fallback when `agent-os-kernel` is not installed.

```python
from agent_failsafe import decision_to_webhook_event, decisions_to_webhook_events

# Single decision
event = decision_to_webhook_event(request, response)
event.event_type  # "governance_decision", "tool_call_blocked", etc.
event.agent_id    # "did:myth:scrivener:abc"
event.action      # "file.write"
event.severity    # "info", "warning", or "critical"
event.details     # {"risk_grade": "L1", "verdict": "PASS", ...}

# Batch translation
events = decisions_to_webhook_events([(req1, resp1), (req2, resp2)])
```

**Event type mapping**:

| Verdict | Condition | Event Type |
|---------|-----------|------------|
| BLOCK | — | `tool_call_blocked` |
| QUARANTINE | — | `agent_quarantined` |
| any | `allowed=False` | `policy_violation` |
| ESCALATE | — | `escalation_required` |
| WARN | `allowed=True` | `governance_warning` |
| PASS | — | `governance_decision` |

**Severity mapping**: BLOCK/QUARANTINE/L3 = `critical`, L2 or denied = `warning`, otherwise `info`.

**Kernel wiring**: `FailSafeKernel` accepts `webhook_notifier` and dispatches events automatically:

```python
kernel = FailSafeKernel(
    client=client,
    webhook_notifier=my_notifier,  # duck-typed: must have .notify(event)
)
# Every governance decision calls notifier.notify(event)
# Notifier exceptions are swallowed (logged as warnings)
```

---

## Heuristic Pattern Matching

10 CWE-referenced security patterns for content scanning.

```python
from agent_failsafe import match_content, classify_risk

matches = match_content("SELECT * FROM users WHERE id = " + user_input)
# [PatternMatch(pattern=INJ001, severity=CRITICAL, cwe="CWE-89", ...)]

grade = classify_risk("/src/auth.py", content="password = 'hunter2'")
# RiskGrade.L3 (path trigger "auth" + content trigger "password")
```

**Built-in patterns**:

| ID     | Category  | Severity | CWE      | Detects |
|--------|-----------|----------|----------|---------|
| INJ001 | Injection | Critical | CWE-89   | SQL injection |
| INJ002 | Injection | Critical | CWE-78   | Command injection |
| SEC001 | Secrets   | High     | CWE-798  | Hardcoded API keys |
| SEC002 | Secrets   | High     | CWE-798  | Hardcoded passwords |
| PII001 | PII       | High     | CWE-359  | SSN patterns |
| PII002 | PII       | High     | CWE-359  | Credit card numbers |
| CMP001 | Complexity| Medium   | CWE-1121 | Deep nesting |
| CRY001 | Crypto    | Medium   | CWE-328  | Weak hash algorithms |
| AUTH001 | Auth     | Medium   | CWE-522  | Basic auth headers |
| DEP001 | Dependency| Low      | CWE-1104 | Pinned dependency versions |

---

## Trust Scoring

Stateless, side-effect-free trust calculations following CBT/KBT/IBT progression.

```python
from agent_failsafe import (
    TrustConfig, DEFAULT_TRUST_CONFIG,
    determine_stage, apply_outcome, is_probationary, calculate_influence_weight,
)

# Determine trust stage
stage = determine_stage(0.6)  # TrustStage.KBT

# Apply governance outcome
new_score = apply_outcome(0.6, allowed=True, risk_grade="L2")
# 0.65 (success: +0.05)

new_score = apply_outcome(0.6, allowed=False, risk_grade="L3")
# 0.35 (L3 violation: -0.25)

# Check probation
on_probation = is_probationary(days_active=10, verifications_completed=3)
# True (needs >=30 days AND >=5 verifications)

# Calculate influence weight
weight = calculate_influence_weight(0.7, is_probationary_flag=False)
# 1.55 (formula: 0.5 + 1.5 * score)
```

---

## Shadow Genome

Records agent failure modes as negative constraints.

```python
from agent_failsafe import (
    InMemoryShadowGenomeStore,
    ShadowGenomeEntry,
    FailureMode,
    classify_failure_mode,
    generate_negative_constraint,
    get_constraints_for_agent,
)

store = InMemoryShadowGenomeStore(max_entries=10_000)

# Record a failure
entry = ShadowGenomeEntry(
    agent_did="did:myth:scrivener:abc",
    failure_mode=FailureMode.SECRET_EXPOSURE,
    input_vector="commit containing API key",
    causal_vector="No pre-commit secret scan",
    negative_constraint=generate_negative_constraint(
        FailureMode.SECRET_EXPOSURE, "/src/config.py", "API key in source"
    ),
)
store.record(entry)

# Query failures
entries = store.query(agent_did="did:myth:scrivener:abc", failure_mode=FailureMode.SECRET_EXPOSURE)

# Get constraints for agent
constraints = get_constraints_for_agent(store, "did:myth:scrivener:abc")
# ["AVOID: Hard-coded secrets. REQUIRE: Environment variables..."]
```

**Failure modes** (10 types):
`HALLUCINATION`, `INJECTION_VULNERABILITY`, `LOGIC_ERROR`, `SPEC_VIOLATION`, `HIGH_COMPLEXITY`, `SECRET_EXPOSURE`, `PII_LEAK`, `DEPENDENCY_CONFLICT`, `TRUST_VIOLATION`, `OTHER`

---

## Quick Start: Minimal Setup

```python
from agent_failsafe import LocalFailSafeClient, GovernancePipeline, DecisionRequest

# 1. Create client
client = LocalFailSafeClient()

# 2. Create pipeline (all backends optional)
pipeline = GovernancePipeline(client=client)

# 3. Evaluate
request = DecisionRequest(action="file.write", agent_did="did:myth:scrivener:abc")
result = pipeline.evaluate(request)

if result.allowed:
    print(f"Allowed. Ring: {result.execution_ring}")
else:
    print(f"Denied at {result.stage.value}: {result.halted_reason}")
```

## Quick Start: Full Stack

```python
from agent_failsafe import (
    LocalFailSafeClient,
    GovernancePipeline,
    FailSafeKernel,
    FailSafeRingAdapter,
    FailSafeComplianceSLI,
    FailSafeAuditSink,
    FailSafeApprovalBackend,
    FailSafeTrustMapper,
    FailSafeTrustValidator,
    DecisionRequest,
)

# Backends
client = LocalFailSafeClient()
sli = FailSafeComplianceSLI(target=0.95)
audit = FailSafeAuditSink(hmac_key=b"production-key-from-env")
approval = FailSafeApprovalBackend(client=client)
mapper = FailSafeTrustMapper()
validator = FailSafeTrustValidator(client=client)

# Pipeline
pipeline = GovernancePipeline(
    client=client,
    ring_adapter=FailSafeRingAdapter(),
    sli=sli,
    audit_sink=audit,
)

# Kernel (registers as "failsafe" adapter)
kernel = FailSafeKernel(
    client=client,
    sli=sli,
    audit_sink=audit,
    approval_backend=approval,
    pipeline=pipeline,
)

# Evaluate through pipeline
request = DecisionRequest(action="file.write", agent_did="did:myth:scrivener:abc")
result = kernel.pipeline_evaluate(request)
```

---

## Claim Map

| Claim | Status | Source |
|---|---|---|
| 18 source files, 3354 lines | implemented | `src/agent_failsafe/*.py` |
| 277 tests passing | implemented | `tests/test_*.py` |
| 51 public exports | implemented | `__init__.py:63-132` |
| pyyaml only required dep | implemented | `pyproject.toml:25-27` |
| Toolkit deps are optional | implemented | `pyproject.toml:29-39` |
| Lazy imports in all adapters | implemented | Each module's `_ensure_imports()` |
| Fail-open on client error | implemented | `pipeline.py`, `interceptor.py` |
| HMAC-SHA256 signed audit | implemented | `audit_sink.py` |
| Merkle chain verification | implemented | `audit_sink.py:verify_integrity` |
| 10 CWE-referenced patterns | implemented | `patterns.py:DEFAULT_PATTERNS` |
| CBT/KBT/IBT trust stages | implemented | `trust.py`, `trust_mapper.py`, `trust_validator.py` |
| Circuit breaker via callable | implemented | `pipeline.py` |
| QUARANTINE triggers kill reason | implemented | `ring_adapter.py:VERDICT_TO_KILL_REASON` |
| Hypervisor typed ring/kill | implemented | `ring_adapter.py:decision_to_execution_ring`, `request_kill` |
| ValidatorInterface (control plane) | implemented | `trust_validator.py:FailSafeTrustValidator` |
| WebhookEvent translation | implemented | `webhook_events.py:decision_to_webhook_event` |
| Webhook fault isolation | implemented | `integration.py:_emit_webhook` |
| PyPI publication | planned | `pyproject.toml:47` |
