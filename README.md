# agent-failsafe

FailSafe governance adapter for the [Microsoft Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit).

Bridges FailSafe's governance engine (Shadow Genome, risk grading, trust dynamics) into the toolkit's extension points.

## Installation

```bash
pip install agent-failsafe
```

With toolkit integration:
```bash
pip install agent-failsafe[full]
```

## Extension Points

| FailSafe Concept | Toolkit Extension Point |
|---|---|
| `FailSafeInterceptor` | `ToolCallInterceptor` |
| `create_failsafe_kernel()` | `BaseIntegration` + `@register_adapter` |
| `ShadowGenomePolicyProvider` | `PolicyProviderInterface` |
| `FailSafeComplianceSLI` | `SLI` |
| `FailSafeAuditSink` | `AuditSink` |
| `FailSafeApprovalBackend` | `ApprovalBackend` |
| `FailSafeTrustMapper` | DID translation (`did:myth` ↔ `did:mesh`) |

## Quick Start

```python
from agent_failsafe import LocalFailSafeClient, FailSafeInterceptor

client = LocalFailSafeClient()
interceptor = FailSafeInterceptor(client=client)

# Add to a CompositeInterceptor chain
from agent_os.integrations.base import CompositeInterceptor
chain = CompositeInterceptor()
chain.add(interceptor)
```

## License

MIT
