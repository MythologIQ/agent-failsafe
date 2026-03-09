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
from .client import LocalFailSafeClient
from .interceptor import FailSafeInterceptor
from .trust_mapper import FailSafeTrustMapper
from .policy_provider import ShadowGenomePolicyProvider
from .sli import FailSafeComplianceSLI, create_sre_sli, decision_to_signal
from .audit_sink import FailSafeAuditSink
from .escalation import FailSafeApprovalBackend

__version__ = "0.1.0"

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
