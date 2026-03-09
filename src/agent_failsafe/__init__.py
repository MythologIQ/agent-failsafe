"""agent-failsafe — FailSafe governance adapter for Microsoft Agent Governance Toolkit.

This package bridges the FailSafe governance engine into the toolkit's
extension points: ToolCallInterceptor, BaseIntegration, PolicyProvider,
AuditSink, SLI, and ApprovalBackend.

FailSafe is a separate product (MythologIQ IP). This adapter connects
it to the toolkit — it does not contain FailSafe itself.
"""

from .types import (
    DecisionRequest,
    DecisionResponse,
    FailSafeClient,
    FailureMode,
    GovernanceAction,
    HeuristicResult,
    PersonaType,
    RiskGrade,
    ShadowGenomeEntry,
    TrustStage,
    VerdictDecision,
)
from .client import LocalFailSafeClient, query_shadow_genome
from .mcp_client import MCPFailSafeClient, MCPToolError
from .ring_adapter import FailSafeRingAdapter
from .interceptor import FailSafeInterceptor
from .trust_mapper import FailSafeTrustMapper
from .policy_provider import ShadowGenomePolicyProvider
from .sli import FailSafeComplianceSLI, create_sre_sli, decision_to_signal
from .audit_sink import FailSafeAuditSink
from .escalation import FailSafeApprovalBackend

__version__ = "0.2.0"

__all__ = [
    # Types
    "DecisionRequest",
    "DecisionResponse",
    "FailSafeClient",
    "FailureMode",
    "GovernanceAction",
    "HeuristicResult",
    "PersonaType",
    "RiskGrade",
    "ShadowGenomeEntry",
    "TrustStage",
    "VerdictDecision",
    # Client
    "LocalFailSafeClient",
    "query_shadow_genome",
    # MCP Client (→ FailSafe VS Code extension)
    "MCPFailSafeClient",
    "MCPToolError",
    # Ring adapter (→ hypervisor ExecutionRing)
    "FailSafeRingAdapter",
    # Interceptor (ToolCallInterceptor)
    "FailSafeInterceptor",
    # Trust mapping (did:myth ↔ did:mesh)
    "FailSafeTrustMapper",
    # Policy provider (Shadow Genome → policies)
    "ShadowGenomePolicyProvider",
    # SLI (governance compliance)
    "FailSafeComplianceSLI",
    "create_sre_sli",
    "decision_to_signal",
    # Audit sink (→ FailSafe ledger)
    "FailSafeAuditSink",
    # Escalation (→ FailSafe L3)
    "FailSafeApprovalBackend",
]
