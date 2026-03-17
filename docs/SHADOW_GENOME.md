# SHADOW GENOME

Failure pattern registry to prevent recurrence of architectural mistakes.

---

## Failure Entry #1

**Date**: 2026-03-17T22:30:00Z
**Verdict ID**: GATE-2026-03-17-001
**Failure Mode**: COMPLEXITY_VIOLATION

### What Failed

SRE v2 Endpoints plan proposed adding `AgentMetrics` tracking and circuit breaker logic directly into the `FailSafeTrustMapper` class.

### Why It Failed

`FailSafeTrustMapper` has a clear single responsibility: bidirectional DID translation and trust score conversion between FailSafe and Agent Mesh systems. Adding operational metrics tracking and circuit breaker state management violates SRP by complecting:

1. **Identity concern** (DID mapping) with **operational concern** (metrics)
2. **Trust computation** with **health monitoring**
3. **Static data** (mappings) with **dynamic state** (circuit breaker)

### Pattern to Avoid

AVOID: Adding operational state (counters, timers, health states) to domain translation classes.

PREFER: Create dedicated registry/manager classes for operational concerns:
- `AgentMetricsRegistry` for per-agent operational metrics
- `CircuitBreakerManager` for circuit breaker state (if needed as separate concern)
- Keep mappers/translators as pure, stateless transformations where possible

### Remediation Attempted

**RESOLVED** (2026-03-17T23:00:00Z): Revised plan extracts `AgentMetricsRegistry` into dedicated `agent_metrics.py` module. Verified in GATE-2026-03-17-002 (Entry #2).

---

## Failure Entry #2

**Date**: 2026-03-17T22:30:00Z
**Verdict ID**: GATE-2026-03-17-001
**Failure Mode**: SPEC_VIOLATION

### What Failed

Plan proposed calling `TrustMapper.record_decision()` directly from `FailSafeInterceptor.intercept()`.

### Why It Failed

The codebase already has a well-defined callback pattern (`on_decision: DecisionCallback`) that flows through `FailSafeKernel._on_decision()`. This pattern:

1. Decouples the interceptor from specific backends
2. Allows multiple listeners (SLI, AuditSink, ApprovalBackend, WebhookNotifier)
3. Maintains clean layering (interceptor → kernel → backends)

Bypassing this pattern creates:
- Direct coupling from decision layer to data layer
- Duplicate wiring logic
- Inconsistent event propagation

### Pattern to Avoid

AVOID: Creating direct calls from interceptors to data stores.

PREFER: Use existing event/callback infrastructure:
```python
# In FailSafeKernel._on_decision():
if self.agent_metrics is not None:
    self.agent_metrics.record_decision(request.agent_did, response.allowed, latency_ms)
```

### Remediation Attempted

**RESOLVED** (2026-03-17T23:00:00Z): Revised plan wires `AgentMetricsRegistry.record_decision()` through `FailSafeKernel._on_decision` callback. Verified in GATE-2026-03-17-002 (Entry #2).

---

## Failure Entry #3

**Date**: 2026-03-17T22:30:00Z
**Verdict ID**: GATE-2026-03-17-001
**Failure Mode**: HIGH_COMPLEXITY

### What Failed

Plan included 5 private methods with ellipsis stubs:
- `_latency_p99()`
- `_throughput_ratio()`
- `_avg_trust_score()`
- `_coverage_ratio()`
- `_decision_latency_ratio()`

### Why It Failed

Ellipsis (`...`) stubs in a plan are not acceptable because:

1. They hide complexity - the implementation may be trivial or may require significant state tracking
2. They prevent accurate complexity assessment
3. They defer critical design decisions to implementation phase
4. They may reveal additional dependencies or data requirements

### Pattern to Avoid

AVOID: Using `...` or `pass` in plan specifications.

PREFER: Specify implementation approach even for helper methods:
```python
def _latency_p99(self) -> Optional[float]:
    """Return 99th percentile latency from recorded decisions.

    Implementation: Track latency values in sorted list, return value
    at index int(len(values) * 0.99). Return None if no data.
    """
```

### Remediation Attempted

**RESOLVED** (2026-03-17T23:00:00Z): Revised plan specifies full implementations for all 10 private methods:
- `_derive_trust_stage()` - Maps success rate to CBT/KBT/IBT
- `_is_timestamp_recent()` - ISO 8601 parsing with threshold check
- `_compute_latency_compliance()` - Returns compliance rate as proxy
- `_is_latency_compliant()` - Threshold check against 0.95
- `_compute_throughput_ratio()` - Returns 1.0 if decisions exist
- `_is_throughput_meeting()` - Threshold check against 0.90
- `_compute_coverage_ratio()` - Returns compliance rate as proxy
- `_is_coverage_meeting()` - Threshold check against 0.90
- `_compute_coverage_budget()` - Error budget calculation
- `_compute_decision_latency_ratio()` - Returns compliance rate as proxy
- `_is_decision_latency_meeting()` - Threshold check against 0.95
- `_verdict_str_to_action()` - Verdict string mapping

Verified in GATE-2026-03-17-002 (Entry #2).

---
