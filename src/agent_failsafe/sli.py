"""SLI (Service Level Indicator) for FailSafe governance compliance.

Provides a custom SLI that measures how well agents comply with
FailSafe governance policies, and a signal emitter for the SRE
incident detection pipeline.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from .types import DecisionResponse, VerdictDecision

logger = logging.getLogger(__name__)

# Lazy imports — agent-sre is an optional dependency
_SLI = None
_SLIValue = None
_TimeWindow = None
_Signal = None
_SignalType = None


def _ensure_sli_imports() -> None:
    global _SLI, _SLIValue, _TimeWindow
    if _SLI is None:
        from agent_sre.slo.indicators import SLI, SLIValue, TimeWindow
        _SLI = SLI
        _SLIValue = SLIValue
        _TimeWindow = TimeWindow


def _ensure_signal_imports() -> None:
    global _Signal, _SignalType
    if _Signal is None:
        from agent_sre.incidents.detector import Signal, SignalType
        _Signal = Signal
        _SignalType = SignalType


class FailSafeComplianceSLI:
    """Measures FailSafe governance compliance as an SLI.

    Tracks the fraction of governance decisions that pass without
    blocks or escalations. This is a standalone tracker that can
    also be registered as an ``agent_sre.slo.indicators.SLI`` subclass.

    Args:
        target: Target compliance rate (0.0–1.0). Default 0.95.
        window: Time window for aggregation. Default "24h".
    """

    def __init__(self, target: float = 0.95, window: str = "24h") -> None:
        self.name = "failsafe_compliance"
        self.target = target
        self.window = window
        self._decisions: list[dict[str, Any]] = []

    def record_decision(self, response: DecisionResponse) -> None:
        """Record a governance decision for SLI tracking."""
        self._decisions.append({
            "timestamp": time.time(),
            "allowed": response.allowed,
            "risk_grade": response.risk_grade.value,
            "verdict": response.verdict.value,
        })

    def current_value(self) -> float | None:
        """Compute current compliance rate within the window."""
        window_seconds = {"1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800, "30d": 2592000}
        cutoff = time.time() - window_seconds.get(self.window, 86400)
        recent = [d for d in self._decisions if d["timestamp"] >= cutoff]
        if not recent:
            return None
        good = sum(1 for d in recent if d["allowed"])
        return good / len(recent)

    def is_meeting_target(self) -> bool | None:
        """Check if compliance meets the target SLO."""
        value = self.current_value()
        if value is None:
            return None
        return value >= self.target

    def to_dict(self) -> dict[str, Any]:
        """Serialize SLI state."""
        return {
            "name": self.name,
            "target": self.target,
            "window": self.window,
            "current_value": self.current_value(),
            "meeting_target": self.is_meeting_target(),
            "total_decisions": len(self._decisions),
        }


def create_sre_sli(target: float = 0.95, window: str = "24h") -> Any:
    """Create a FailSafe SLI that extends agent_sre.slo.indicators.SLI.

    Returns an SLI subclass instance if agent-sre is installed,
    otherwise returns a standalone FailSafeComplianceSLI.
    """
    try:
        _ensure_sli_imports()
    except ImportError:
        logger.debug("agent-sre not installed; using standalone SLI tracker")
        return FailSafeComplianceSLI(target=target, window=window)

    class _FailSafeSLI(_SLI):
        """SLI subclass for agent-sre integration."""

        def __init__(self) -> None:
            super().__init__("failsafe_compliance", target, _TimeWindow(window))
            self._total = 0
            self._compliant = 0

        def collect(self) -> Any:
            """Collect current compliance measurement."""
            rate = self._compliant / self._total if self._total > 0 else 1.0
            return self.record(rate)

        def record_decision(self, response: DecisionResponse) -> None:
            """Record a governance decision."""
            self._total += 1
            if response.allowed:
                self._compliant += 1

    return _FailSafeSLI()


def decision_to_signal(response: DecisionResponse, source: str = "failsafe") -> Any | None:
    """Convert a FailSafe decision to an SRE Signal if it indicates an incident.

    Only generates signals for blocked or escalated decisions.

    Args:
        response: The governance decision response.
        source: Signal source identifier.

    Returns:
        A Signal instance if agent-sre is installed and the decision
        warrants alerting, otherwise None.
    """
    if response.allowed and response.verdict != VerdictDecision.ESCALATE:
        return None

    try:
        _ensure_signal_imports()
    except ImportError:
        return None

    signal_type = _SignalType.POLICY_VIOLATION

    return _Signal(
        signal_type=signal_type,
        source=source,
        value=0.0 if not response.allowed else 1.0,
        threshold=0.0,
        message=(
            f"FailSafe {response.verdict.value}: {response.reason} "
            f"(risk={response.risk_grade.value})"
        ),
        metadata={
            "risk_grade": response.risk_grade.value,
            "verdict": response.verdict.value,
            "nonce": response.nonce,
        },
    )
