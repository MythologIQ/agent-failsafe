# agent-failsafe

[![PyPI](https://img.shields.io/pypi/v/agent-failsafe)](https://pypi.org/project/agent-failsafe/)
[![Downloads](https://img.shields.io/pypi/dm/agent-failsafe)](https://pypi.org/project/agent-failsafe/)
[![Python](https://img.shields.io/pypi/pyversions/agent-failsafe)](https://pypi.org/project/agent-failsafe/)
[![License](https://img.shields.io/github/license/MythologIQ/agent-failsafe)](https://github.com/MythologIQ/agent-failsafe/blob/main/LICENSE)
[![VS Code](https://img.shields.io/visual-studio-marketplace/v/MythologIQ.mythologiq-failsafe)](https://marketplace.visualstudio.com/items?itemName=MythologIQ.mythologiq-failsafe)

FailSafe governance adapter for the [Microsoft Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit).

agent-failsafe is a Python adapter that connects the FailSafe runtime governance engine to the Microsoft Agent Governance Toolkit.

• Adds runtime behavioral governance to the toolkit
• Detects failure patterns such as tool recursion and reasoning collapse
• Integrates through interceptors, validators, and policy providers
• Install with `pip install agent-failsafe`

Core runtime: [https://github.com/MythologIQ/Failsafe](https://github.com/MythologIQ/Failsafe)

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

## Extension Points

| Adapter | Toolkit Extension Point | Module |
|---|---|---|
| `FailSafeInterceptor` | `ToolCallInterceptor` | `interceptor.py` |
| `FailSafeKernel` | `BaseIntegration` + `@register_adapter` | `integration.py` |
| `GovernancePipeline` | Full lifecycle orchestration | `pipeline.py` |
| `FailSafeRingAdapter` | `ExecutionRing` + `KillSwitch` | `ring_adapter.py` |
| `FailSafeTrustValidator` | `ValidatorInterface` (control plane) | `trust_validator.py` |
| `ShadowGenomePolicyProvider` | `PolicyProviderInterface` | `policy_provider.py` |
| `FailSafeComplianceSLI` | `SLI` (agent-sre) | `sli.py` |
| `FailSafeAuditSink` | `AuditSink` | `audit_sink.py` |
| `FailSafeApprovalBackend` | `ApprovalBackend` | `escalation.py` |
| `FailSafeTrustMapper` | DID translation (`did:myth` <> `did:mesh`) | `trust_mapper.py` |
| `decision_to_webhook_event` | `WebhookEvent` translation | `webhook_events.py` |

## Architecture Diagram

```text
AI Agent
↓
Agent Governance Toolkit
↓
agent-failsafe adapter
↓
FailSafe runtime engine
↓
Tool execution
```

## Basic Usage Example

Basic interceptor example

```python
from agent_failsafe import FailSafeInterceptor

interceptor = FailSafeInterceptor()
result = interceptor.intercept(request)
```

```python
from agent_failsafe import FailSafeInterceptor

interceptor = FailSafeInterceptor()
result = interceptor.intercept(request)
```

See [docs/ADAPTER_ARCHITECTURE.md](docs/ADAPTER_ARCHITECTURE.md) for full API reference.

## Ecosystem

FailSafe runtime engine
[https://github.com/MythologIQ/Failsafe](https://github.com/MythologIQ/Failsafe)

Developer extension
[https://marketplace.visualstudio.com/items?itemName=MythologIQ.mythologiq-failsafe](https://marketplace.visualstudio.com/items?itemName=MythologIQ.mythologiq-failsafe)
[https://open-vsx.org/extension/MythologIQ/mythologiq-failsafe](https://open-vsx.org/extension/MythologIQ/mythologiq-failsafe)

## Recommended GitHub Topics

- ai-agents
- agent-governance
- agentic-ai
- ai-runtime
- ai-reliability
- llm-agents
- ai-infrastructure
- open-source

## License

MIT
