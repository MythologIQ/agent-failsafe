"""Pure functions translating governance decisions to WebhookEvent objects.

This module produces ``WebhookEvent`` instances (from ``agent_os.integrations
.webhooks``) for callers to dispatch via an existing ``WebhookNotifier``.
It does NOT create, manage, or invoke a notifier — it is a data translator.

When ``agent-os-kernel`` is not installed, returns ``SimpleNamespace``
objects with identical fields.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Iterable

from .types import (
    DecisionRequest,
    DecisionResponse,
    RiskGrade,
    VerdictDecision,
)

# ---------------------------------------------------------------------------
# Lazy imports — agent-os-kernel is an optional dependency
# ---------------------------------------------------------------------------

_WebhookEvent: Any = None
_agent_os_checked = False


def _ensure_imports() -> None:
    """Import WebhookEvent once, swallow ImportError."""
    global _WebhookEvent, _agent_os_checked
    if _agent_os_checked:
        return
    _agent_os_checked = True
    try:
        from agent_os.integrations.webhooks import WebhookEvent

        _WebhookEvent = WebhookEvent
    except ImportError:
        pass


# ---------------------------------------------------------------------------
# Mapping helpers
# ---------------------------------------------------------------------------


def _map_event_type(response: DecisionResponse) -> str:
    """Map verdict to webhook event type string."""
    if response.verdict == VerdictDecision.BLOCK:
        return "tool_call_blocked"
    if response.verdict == VerdictDecision.QUARANTINE:
        return "agent_quarantined"
    if not response.allowed:
        return "policy_violation"
    if response.verdict == VerdictDecision.ESCALATE:
        return "escalation_required"
    if response.verdict == VerdictDecision.WARN:
        return "governance_warning"
    return "governance_decision"


def _map_severity(response: DecisionResponse) -> str:
    """Map risk grade + verdict to webhook severity."""
    if response.verdict in (VerdictDecision.BLOCK, VerdictDecision.QUARANTINE):
        return "critical"
    if response.risk_grade == RiskGrade.L3:
        return "critical"
    if response.risk_grade == RiskGrade.L2 or not response.allowed:
        return "warning"
    return "info"


def _build_details(
    request: DecisionRequest, response: DecisionResponse,
) -> dict[str, Any]:
    """Build the details dict for a WebhookEvent."""
    return {
        "risk_grade": response.risk_grade.value,
        "verdict": response.verdict.value,
        "reason": response.reason,
        "nonce": response.nonce,
        "agent_did": request.agent_did,
        "artifact_path": request.artifact_path,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def decision_to_webhook_event(
    request: DecisionRequest,
    response: DecisionResponse,
) -> Any:
    """Translate a FailSafe governance decision into a WebhookEvent.

    Returns a ``WebhookEvent`` if ``agent-os-kernel`` is installed,
    otherwise a ``SimpleNamespace`` with the same fields.

    Args:
        request: The governance decision request.
        response: The governance decision response.

    Returns:
        WebhookEvent or SimpleNamespace with event_type, agent_id,
        action, details, severity, and timestamp fields.
    """
    _ensure_imports()
    event_type = _map_event_type(response)
    severity = _map_severity(response)
    details = _build_details(request, response)

    if _WebhookEvent is not None:
        return _WebhookEvent(
            event_type=event_type,
            agent_id=request.agent_did,
            action=request.action,
            details=details,
            severity=severity,
        )
    return SimpleNamespace(
        event_type=event_type,
        agent_id=request.agent_did,
        action=request.action,
        details=details,
        severity=severity,
        timestamp="",
    )


def decisions_to_webhook_events(
    pairs: Iterable[tuple[DecisionRequest, DecisionResponse]],
) -> list[Any]:
    """Translate multiple decision pairs into WebhookEvents.

    Args:
        pairs: Iterable of (request, response) tuples.

    Returns:
        List of WebhookEvent or SimpleNamespace objects.
    """
    _ensure_imports()
    return [decision_to_webhook_event(req, resp) for req, resp in pairs]
