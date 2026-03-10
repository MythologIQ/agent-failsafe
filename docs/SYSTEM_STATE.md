# agent-failsafe System State

**Last Updated**: 2026-03-10T12:00:00Z
**Version**: 0.3.0
**Sealed By**: Entry #54

## Package Totals

| Metric | Value |
|--------|-------|
| Source files | 18 |
| Source lines | 3,354 |
| Test files | 17 |
| Tests | 277 |
| Public exports | 51 |

## Source Tree

```
src/agent_failsafe/
  __init__.py          # 51 exports, v0.3.0
  types.py             # DecisionRequest, DecisionResponse, FailSafeClient Protocol
  client.py            # LocalFailSafeClient, query_shadow_genome
  mcp_client.py        # MCPFailSafeClient (stdio MCP transport)
  interceptor.py       # FailSafeInterceptor (ToolCallInterceptor)
  integration.py       # FailSafeKernel (@register_adapter), _GovernedAgent
  pipeline.py          # GovernancePipeline, PipelineResult, PipelineStage
  ring_adapter.py      # FailSafeRingAdapter (ExecutionRing mapping)
  trust.py             # CBT/KBT/IBT trust dynamics
  trust_mapper.py      # did:myth ↔ did:mesh translation
  trust_validator.py   # FailSafeTrustValidator (ValidatorInterface)
  shadow_genome.py     # ShadowGenomeStore, InMemoryShadowGenomeStore
  patterns.py          # 10 CWE-referenced heuristic patterns
  policy_provider.py   # ShadowGenomePolicyProvider
  sli.py               # FailSafeComplianceSLI, decision_to_signal
  audit_sink.py        # FailSafeAuditSink, decision_to_audit_entry
  escalation.py        # FailSafeApprovalBackend
  webhook_events.py    # decision_to_webhook_event, severity/type mapping
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
  test_sli.py
  test_audit_sink.py
  test_escalation.py
  test_webhook_events.py
```

## Source Hash

```
SHA256(all 18 source files)
= d5debdf07ca0fa4114450ac1962138bd9c0ff3895d0ea21b578df53661379a2d
```
