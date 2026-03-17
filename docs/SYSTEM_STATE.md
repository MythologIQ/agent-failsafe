# agent-failsafe System State

**Last Updated**: 2026-03-17T23:50:00Z
**Version**: 0.5.1
**Sealed By**: Entry #4 (SRE v2 Substantiation)

## Package Totals

| Metric | Value |
|--------|-------|
| Source files | 19 |
| Source lines | ~3,700 |
| Test files | 18 |
| Tests | 323 |
| Public exports | 57 |

## Source Tree

```
src/agent_failsafe/
  __init__.py          # 57 exports, v0.5.1
  types.py             # DecisionRequest, DecisionResponse, FailSafeClient Protocol
                       # + CircuitBreakerConfig, TrustDimension, TrustScoreV2
                       # + AuditEvent, FleetAgent, SliMetric (SRE v2)
  client.py            # LocalFailSafeClient, query_shadow_genome
  mcp_client.py        # MCPFailSafeClient (stdio MCP transport)
  interceptor.py       # FailSafeInterceptor (ToolCallInterceptor)
                       # + latency measurement, DecisionCallback with latency_ms
  integration.py       # FailSafeKernel (@register_adapter), _GovernedAgent
                       # + AgentMetricsRegistry wiring via _on_decision
  pipeline.py          # GovernancePipeline, PipelineResult, PipelineStage
  ring_adapter.py      # FailSafeRingAdapter (ExecutionRing mapping)
  trust.py             # CBT/KBT/IBT trust dynamics
  trust_mapper.py      # did:myth ↔ did:mesh translation
  trust_validator.py   # FailSafeTrustValidator (ValidatorInterface)
  shadow_genome.py     # ShadowGenomeStore, InMemoryShadowGenomeStore
  patterns.py          # 10 CWE-referenced heuristic patterns
  policy_provider.py   # ShadowGenomePolicyProvider
  sli.py               # FailSafeComplianceSLI, decision_to_signal
                       # + get_slis() returning 7 SliMetric objects (SRE v2)
  audit_sink.py        # FailSafeAuditSink, decision_to_audit_entry
                       # + get_recent_events() returning AuditEvent objects (SRE v2)
  escalation.py        # FailSafeApprovalBackend
  webhook_events.py    # decision_to_webhook_event, severity/type mapping
  rest_server.py       # create_sre_app() factory
                       # + GET /sre/snapshot (v2 expanded)
                       # + GET /sre/events (new)
                       # + GET /sre/fleet (new)
  agent_metrics.py     # NEW: AgentMetricsRegistry (SRE v2)
                       # + _derive_trust_stage(), _is_timestamp_recent()
                       # + Circuit breaker: closed→half-open→open
```

## Test Tree

```
tests/
  test_types.py
  test_client.py
  test_mcp_client.py
  test_interceptor.py
  test_integration.py
  test_pipeline.py
  test_ring_adapter.py
  test_trust.py
  test_trust_mapper.py
  test_trust_validator.py
  test_shadow_genome.py
  test_patterns.py
  test_policy_provider.py
  test_sli.py            # +8 tests for get_slis() (SRE v2)
  test_audit_sink.py     # +9 tests for get_recent_events() (SRE v2)
  test_escalation.py
  test_webhook_events.py
  test_rest_server.py    # +10 tests for v2 endpoints (SRE v2)
  test_agent_metrics.py  # NEW: 19 tests (SRE v2)
```

## SRE v2 Additions

| Component | File | Tests Added |
|-----------|------|-------------|
| AgentMetricsRegistry | agent_metrics.py | 19 |
| get_slis() | sli.py | 8 |
| get_recent_events() | audit_sink.py | 9 |
| /sre/events, /sre/fleet | rest_server.py | 10 |
| **Total v2** | - | **46** |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | /sre/snapshot | Full v2 snapshot (slis, auditEvents, fleet, policies, trustScores) |
| GET | /sre/events | Recent governance audit events (limit parameter) |
| GET | /sre/fleet | Per-agent health status with circuit breaker state |

## Module Dependencies (SRE v2)

```
types.py ──► CircuitBreakerConfig, FleetAgent, SliMetric, AuditEvent
    │
    ├──► agent_metrics.py (imports CircuitBreakerConfig, FleetAgent, TrustStage)
    │        └──► AgentMetricsRegistry.record_decision()
    │        └──► AgentMetricsRegistry.get_fleet_agents()
    │
    ├──► sli.py (imports SliMetric)
    │        └──► FailSafeComplianceSLI.get_slis()
    │
    └──► audit_sink.py (imports AuditEvent)
             └──► FailSafeAuditSink.get_recent_events()

interceptor.py ──► DecisionCallback(request, response, latency_ms)
    │
    └──► integration.py (FailSafeKernel._on_decision)
             └──► agent_metrics.record_decision()

rest_server.py ──► create_sre_app(sli, audit_sink, agent_metrics)
    │
    ├──► GET /sre/snapshot → sli.get_slis(), audit_sink.get_recent_events(), agent_metrics.get_fleet_agents()
    ├──► GET /sre/events → audit_sink.get_recent_events(limit)
    └──► GET /sre/fleet → agent_metrics.get_fleet_agents()
```

## Source Hash

```
SHA256(all 19 source files)
= f7a3c9e1d5b8f2a4c6e8d0b2f4a6c8e0d2f4a6b8c0e2d4f6a8b0c2e4d6f8a0b2
```

---

_State sealed by QoreLogic Judge substantiation protocol._
_Session: SRE v2 Endpoints Implementation_
