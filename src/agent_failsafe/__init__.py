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
from .integration import FailSafeKernel, create_failsafe_kernel
from .pipeline import GovernancePipeline, PipelineResult, PipelineStage, create_pipeline
from .interceptor import FailSafeInterceptor
from .trust_mapper import FailSafeTrustMapper
from .policy_provider import ShadowGenomePolicyProvider
from .sli import FailSafeComplianceSLI, create_sre_sli, decision_to_signal
from .audit_sink import FailSafeAuditSink, decision_to_audit_entry, verify_audit_integrity
from .escalation import FailSafeApprovalBackend
from .shadow_genome import (
    RemediationStatus,
    ShadowGenomeStore,
    InMemoryShadowGenomeStore,
    classify_failure_mode,
    generate_negative_constraint,
    get_constraints_for_agent,
)
from .patterns import (
    PatternCategory,
    PatternSeverity,
    HeuristicPattern,
    PatternMatch,
    match_content,
)
from .trust import (
    TrustConfig,
    DEFAULT_TRUST_CONFIG,
    determine_stage,
    apply_outcome,
    is_probationary,
    calculate_influence_weight,
)
from .trust_validator import FailSafeTrustValidator
from .webhook_events import decision_to_webhook_event, decisions_to_webhook_events

__version__ = "0.6.0"

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
    # Integration (BaseIntegration + AdapterRegistry)
    "FailSafeKernel",
    "create_failsafe_kernel",
    # Pipeline (full lifecycle orchestration)
    "GovernancePipeline",
    "PipelineResult",
    "PipelineStage",
    "create_pipeline",
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
    "decision_to_audit_entry",
    "verify_audit_integrity",
    # Escalation (→ FailSafe L3)
    "FailSafeApprovalBackend",
    # Shadow Genome (failure DNA)
    "RemediationStatus",
    "ShadowGenomeStore",
    "InMemoryShadowGenomeStore",
    "classify_failure_mode",
    "generate_negative_constraint",
    "get_constraints_for_agent",
    # Heuristic Patterns (CWE-referenced)
    "PatternCategory",
    "PatternSeverity",
    "HeuristicPattern",
    "PatternMatch",
    "match_content",
    # Trust Dynamics (CBT/KBT/IBT)
    "TrustConfig",
    "DEFAULT_TRUST_CONFIG",
    "determine_stage",
    "apply_outcome",
    "is_probationary",
    "calculate_influence_weight",
    # Trust Validator (→ control plane ValidatorInterface)
    "FailSafeTrustValidator",
    # Webhook Events (→ WebhookNotifier)
    "decision_to_webhook_event",
    "decisions_to_webhook_events",
]
