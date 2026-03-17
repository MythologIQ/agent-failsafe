"""Per-agent operational metrics registry for SRE Fleet Health.

Separated from TrustMapper to maintain single responsibility:
- TrustMapper: DID translation and trust score conversion (identity concern)
- AgentMetricsRegistry: Operational metrics and circuit breaker state (health concern)
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Optional

from .types import CircuitBreakerConfig, FleetAgent, TrustStage


def _derive_trust_stage(success_rate: float) -> str:
    """Derive trust stage from success rate.

    Maps success rate to trust stage:
    - 0.0-0.5: CBT (Capability-Based Trust) - new/untested
    - 0.5-0.8: KBT (Knowledge-Based Trust) - proven track record
    - 0.8-1.0: IBT (Identity-Based Trust) - full trust
    """
    if success_rate >= 0.8:
        return TrustStage.IBT.value
    elif success_rate >= 0.5:
        return TrustStage.KBT.value
    return TrustStage.CBT.value


def _is_timestamp_recent(timestamp: str, threshold_seconds: int = 300) -> bool:
    """Check if ISO 8601 timestamp is within threshold of now.

    Returns False if timestamp cannot be parsed.
    """
    try:
        t = time.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
        ts = time.mktime(t)
        return (time.time() - ts) < threshold_seconds
    except (ValueError, OverflowError):
        return False


@dataclass
class _AgentMetrics:
    """Per-agent operational metrics (internal mutable state)."""

    task_count: int = 0
    success_count: int = 0
    total_latency_ms: float = 0.0
    last_active_at: Optional[str] = None
    circuit_state: str = "closed"
    consecutive_failures: int = 0


class AgentMetricsRegistry:
    """Registry tracking per-agent operational metrics.

    Thread-safe. Designed to be wired into FailSafeKernel._on_decision callback.

    Args:
        circuit_config: Circuit breaker thresholds. Defaults to standard config.
        active_threshold_seconds: Seconds since last activity to consider "active".
    """

    def __init__(
        self,
        circuit_config: CircuitBreakerConfig | None = None,
        active_threshold_seconds: int = 300,
    ) -> None:
        self._config = circuit_config or CircuitBreakerConfig()
        self._active_threshold = active_threshold_seconds
        self._metrics: dict[str, _AgentMetrics] = {}
        self._lock = threading.Lock()

    def record_decision(
        self,
        agent_did: str,
        allowed: bool,
        latency_ms: float,
    ) -> None:
        """Record a governance decision for an agent.

        Updates task count, success rate, latency, and circuit breaker state.
        """
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self._lock:
            if agent_did not in self._metrics:
                self._metrics[agent_did] = _AgentMetrics()
            m = self._metrics[agent_did]

            m.task_count += 1
            m.total_latency_ms += latency_ms
            m.last_active_at = now

            if allowed:
                m.success_count += 1
                m.consecutive_failures = 0
                if m.circuit_state == "half-open":
                    m.circuit_state = "closed"
            else:
                m.consecutive_failures += 1
                if m.consecutive_failures >= self._config.open_threshold:
                    m.circuit_state = "open"
                elif (
                    m.circuit_state == "closed"
                    and m.consecutive_failures >= self._config.half_open_threshold
                ):
                    m.circuit_state = "half-open"

    def get_fleet_agents(self) -> list[FleetAgent]:
        """Return all known agents with their health metrics.

        Returns list sorted by agent_id for deterministic ordering.
        """
        with self._lock:
            agents = []
            for agent_id in sorted(self._metrics.keys()):
                m = self._metrics[agent_id]
                status = self._derive_status(m)
                success_rate = m.success_count / m.task_count if m.task_count > 0 else 0.0
                avg_latency = m.total_latency_ms / m.task_count if m.task_count > 0 else 0.0

                agents.append(
                    FleetAgent(
                        agent_id=agent_id,
                        status=status,
                        circuit_state=m.circuit_state,
                        task_count=m.task_count,
                        success_rate=success_rate,
                        avg_latency_ms=avg_latency,
                        last_active_at=m.last_active_at or "",
                        trust_stage=_derive_trust_stage(success_rate),
                    )
                )
            return agents

    def _derive_status(self, m: _AgentMetrics) -> str:
        """Derive agent status from circuit state and recency."""
        if m.circuit_state == "open":
            return "error"
        if m.last_active_at and _is_timestamp_recent(m.last_active_at, self._active_threshold):
            return "active"
        return "idle"

    def get_agent_count(self) -> int:
        """Return number of tracked agents."""
        with self._lock:
            return len(self._metrics)

    def reset(self) -> None:
        """Clear all metrics. Primarily for testing."""
        with self._lock:
            self._metrics.clear()
