"""ValidatorInterface implementation using FailSafe trust dynamics.

Plugs into the Agent OS control plane as a custom validator via
``control_plane.register_validator()``.  Uses CBT/KBT/IBT trust stages
to gate actions by risk grade:

- **CBT** (Capability-Based Trust): L1 only
- **KBT** (Knowledge-Based Trust): L1 + L2
- **IBT** (Identity-Based Trust): all risk grades

Works without ``agent-os-kernel`` installed (degrades to a plain object
returning ``SimpleNamespace`` results).  When agent_control_plane IS
installed, the ``metadata`` property returns a real ``PluginMetadata``.
"""

from __future__ import annotations

import itertools
import logging
from collections import deque
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any

from .trust import DEFAULT_TRUST_CONFIG, TrustConfig, determine_stage
from .types import (
    DecisionRequest,
    DecisionResponse,
    FailSafeClient,
    RiskGrade,
    TrustStage,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Lazy imports — agent_control_plane is an optional dependency
# ---------------------------------------------------------------------------

_ValidatorInterface: Any = None
_ValidationResult: Any = None
_PluginMetadata: Any = None
_PluginCapability: Any = None
_control_plane_checked = False


def _ensure_imports() -> None:
    """Import control plane types once, swallow ImportError."""
    global _ValidatorInterface, _ValidationResult, _PluginMetadata, _PluginCapability, _control_plane_checked
    if _control_plane_checked:
        return
    _control_plane_checked = True
    try:
        from agent_control_plane.interfaces.plugin_interface import (
            PluginCapability,
            PluginMetadata,
            ValidationResult,
            ValidatorInterface,
        )

        _ValidatorInterface = ValidatorInterface
        _ValidationResult = ValidationResult
        _PluginMetadata = PluginMetadata
        _PluginCapability = PluginCapability
    except ImportError:
        pass


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def _stage_allows_risk(stage: TrustStage, risk_grade: RiskGrade) -> bool:
    """CBT: L1 only.  KBT: L1 + L2.  IBT: all."""
    if stage == TrustStage.IBT:
        return True
    if stage == TrustStage.KBT:
        return risk_grade in (RiskGrade.L1, RiskGrade.L2)
    return risk_grade == RiskGrade.L1  # CBT


def _extract_agent_did(request: Any, context: dict[str, Any] | None) -> str:
    """Pull agent DID from context or request attributes."""
    if context and "agent_did" in context:
        return context["agent_did"]
    return getattr(request, "agent_id", "") or "did:myth:scrivener:unknown"


def _extract_trust_score(context: dict[str, Any] | None) -> float:
    """Pull trust score from context, defaulting to TrustConfig.default_trust."""
    if context and "trust_score" in context:
        return float(context["trust_score"])
    return DEFAULT_TRUST_CONFIG.default_trust


def _denial_reason(response: DecisionResponse, stage: TrustStage) -> str:
    """Build a human-readable denial reason."""
    if not response.allowed:
        return response.reason or f"Blocked by FailSafe ({response.risk_grade.value})"
    return f"Trust stage {stage.value} insufficient for {response.risk_grade.value} action"


def _corrective_actions(stage: TrustStage, risk_grade: RiskGrade) -> list[str]:
    """Suggest corrective actions for a denied request."""
    actions: list[str] = []
    if stage == TrustStage.CBT:
        actions.append("Complete verification checks to advance to KBT stage")
    if risk_grade == RiskGrade.L3:
        actions.append("Request L3 human approval for this action")
    return actions


def _log_entry(
    agent_did: str, action: str, is_valid: bool, stage: TrustStage,
) -> dict[str, Any]:
    """Build a validation log entry."""
    return {
        "agent_did": agent_did,
        "action": action,
        "is_valid": is_valid,
        "trust_stage": stage.value,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# FailSafeTrustValidator
# ---------------------------------------------------------------------------


class FailSafeTrustValidator:
    """Validates requests using FailSafe governance + CBT/KBT/IBT trust gating.

    Implements the ``ValidatorInterface`` protocol methods so it can be
    registered with ``control_plane.register_validator()`` when the
    control plane is available.

    Args:
        client: FailSafeClient for governance evaluation.
        trust_config: Trust scoring configuration.
        log_capacity: Maximum validation log entries (FIFO eviction).
    """

    def __init__(
        self,
        client: FailSafeClient,
        trust_config: TrustConfig = DEFAULT_TRUST_CONFIG,
        log_capacity: int = 500,
    ) -> None:
        self._client = client
        self._config = trust_config
        self._log: deque[dict[str, Any]] = deque(maxlen=log_capacity)

    @property
    def metadata(self) -> Any:
        """Return PluginMetadata if control plane available, else dict."""
        _ensure_imports()
        if _PluginMetadata is None:
            return {"name": "failsafe-trust-validator", "version": "0.3.0",
                    "plugin_type": "validator"}
        return _PluginMetadata(
            name="failsafe-trust-validator",
            version="0.3.0",
            description="FailSafe CBT/KBT/IBT trust-based request validator",
            plugin_type="validator",
            capabilities=[
                _PluginCapability.REQUEST_VALIDATION,
                _PluginCapability.RISK_ASSESSMENT,
            ],
        )

    def validate_request(
        self, request: Any, context: dict[str, Any] | None = None,
    ) -> Any:
        """Validate using FailSafe governance + trust stage gating."""
        agent_did = _extract_agent_did(request, context)
        trust_score = _extract_trust_score(context)
        stage = determine_stage(trust_score, self._config)

        action = getattr(request, "action_type", None) or getattr(request, "tool_name", "unknown")
        decision_req = DecisionRequest(action=action, agent_did=agent_did)
        response = self._client.evaluate(decision_req)

        result = self._build_result(response, stage, trust_score)
        self._log.append(_log_entry(agent_did, action, result.is_valid, stage))
        return result

    def _build_result(
        self, response: DecisionResponse, stage: TrustStage, trust_score: float,
    ) -> Any:
        """Build a ValidationResult (or SimpleNamespace fallback)."""
        _ensure_imports()
        is_valid = response.allowed and _stage_allows_risk(stage, response.risk_grade)
        reason = "" if is_valid else _denial_reason(response, stage)
        details = {
            "trust_score": trust_score,
            "trust_stage": stage.value,
            "risk_grade": response.risk_grade.value,
            "verdict": response.verdict.value,
        }
        corrective = [] if is_valid else _corrective_actions(stage, response.risk_grade)

        if _ValidationResult is not None:
            return _ValidationResult(
                is_valid=is_valid, reason=reason,
                details=details, corrective_actions=corrective,
            )
        return SimpleNamespace(
            is_valid=is_valid, reason=reason,
            details=details, corrective_actions=corrective,
        )

    def get_validation_log(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return recent validation log entries, newest first."""
        return list(itertools.islice(reversed(self._log), limit))
