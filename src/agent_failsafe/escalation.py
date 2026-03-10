"""ApprovalBackend implementation that routes to FailSafe L3 workflow.

Bridges the Agent OS escalation system to FailSafe's human-in-the-loop
L3 approval queue, translating between the two systems' request formats.
"""

from __future__ import annotations

import logging
import threading
import uuid
from datetime import datetime, timezone
from typing import Any

from .types import DecisionRequest, FailSafeClient

logger = logging.getLogger(__name__)

# Lazy imports — agent-os is an optional dependency
_ApprovalBackend = None
_EscalationRequest = None
_EscalationDecision = None


def _ensure_imports() -> None:
    global _ApprovalBackend, _EscalationRequest, _EscalationDecision
    if _ApprovalBackend is None:
        from agent_os.integrations.escalation import (
            ApprovalBackend,
            EscalationDecision,
            EscalationRequest,
        )
        _ApprovalBackend = ApprovalBackend
        _EscalationRequest = EscalationRequest
        _EscalationDecision = EscalationDecision


def _build_l3_request(request: Any) -> tuple[str, DecisionRequest]:
    """Build an L3 governance request from an escalation request.

    Returns (request_id, decision_request).
    """
    request_id = getattr(request, "request_id", str(uuid.uuid4()))
    return request_id, DecisionRequest(
        action="l3.approve",
        agent_did=getattr(request, "agent_id", "unknown"),
        payload={
            "escalation_id": request_id,
            "original_action": getattr(request, "action", "unknown"),
            "reason": getattr(request, "reason", ""),
            "context": getattr(request, "context_snapshot", {}),
        },
    )


class FailSafeApprovalBackend:
    """Escalation backend that delegates to FailSafe L3 approval workflow.

    When a tool call requires human approval, this backend submits it
    to the FailSafe governance engine as an L3 approval request and
    polls for the decision.

    Can be used directly or as an ``ApprovalBackend`` implementation
    when agent-os is installed.

    Args:
        client: A FailSafeClient for governance communication.
        overseer_did: DID of the human overseer. Defaults to local overseer.
    """

    def __init__(
        self,
        client: FailSafeClient,
        overseer_did: str = "did:myth:overseer:local",
        max_requests: int = 1000,
    ) -> None:
        self.client = client
        self.overseer_did = overseer_did
        self._requests: dict[str, dict[str, Any]] = {}
        self._max_requests = max_requests
        self._lock = threading.Lock()

    def submit(self, request: Any) -> None:
        """Submit an escalation request for human review.

        Translates the Agent OS EscalationRequest to a FailSafe L3
        governance evaluation and stores the result.
        """
        request_id, decision_req = _build_l3_request(request)

        try:
            response = self.client.evaluate(decision_req)
            with self._lock:
                self._requests[request_id] = {
                    "request": request,
                    "failsafe_response": response,
                    "status": "pending",
                    "submitted_at": datetime.now(timezone.utc),
                }
            if len(self._requests) > self._max_requests:
                oldest_key = next(iter(self._requests))
                del self._requests[oldest_key]
            logger.info("L3 escalation submitted: %s (risk=%s)", request_id, response.risk_grade.value)
        except Exception as exc:
            logger.error("Failed to submit L3 escalation: %s", exc)
            with self._lock:
                self._requests[request_id] = {
                    "request": request,
                    "failsafe_response": None,
                    "status": "error",
                    "error": str(exc),
                    "submitted_at": datetime.now(timezone.utc),
                }

    def get_decision(self, request_id: str) -> Any | None:
        """Retrieve the current state of an escalation request."""
        with self._lock:
            entry = self._requests.get(request_id)
        if entry is None:
            return None
        return entry.get("request")

    def approve(self, request_id: str, approver: str = "") -> bool:
        """Approve an escalation request."""
        with self._lock:
            entry = self._requests.get(request_id)
            if entry is None or entry["status"] != "pending":
                return False
            entry["status"] = "approved"
            entry["resolved_by"] = approver or self.overseer_did
            entry["resolved_at"] = datetime.now(timezone.utc)

        # Notify FailSafe of approval
        try:
            self.client.evaluate(DecisionRequest(
                action="l3.approve",
                agent_did=approver or self.overseer_did,
                payload={"escalation_id": request_id, "decision": "APPROVED"},
            ))
        except Exception as exc:
            logger.warning("Failed to notify FailSafe of approval: %s", exc)

        return True

    def deny(self, request_id: str, approver: str = "") -> bool:
        """Deny an escalation request."""
        with self._lock:
            entry = self._requests.get(request_id)
            if entry is None or entry["status"] != "pending":
                return False
            entry["status"] = "denied"
            entry["resolved_by"] = approver or self.overseer_did
            entry["resolved_at"] = datetime.now(timezone.utc)

        # Notify FailSafe of rejection
        try:
            self.client.evaluate(DecisionRequest(
                action="l3.reject",
                agent_did=approver or self.overseer_did,
                payload={"escalation_id": request_id, "decision": "REJECTED"},
            ))
        except Exception as exc:
            logger.warning("Failed to notify FailSafe of denial: %s", exc)

        return True

    def list_pending(self) -> list[Any]:
        """List all pending escalation requests."""
        with self._lock:
            return [
                entry["request"]
                for entry in self._requests.values()
                if entry["status"] == "pending"
            ]
