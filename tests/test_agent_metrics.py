"""Tests for AgentMetricsRegistry — per-agent operational metrics."""

import time

from agent_failsafe.agent_metrics import (
    AgentMetricsRegistry,
    _derive_trust_stage,
    _is_timestamp_recent,
)
from agent_failsafe.types import CircuitBreakerConfig, TrustStage


class TestDeriveTrustStage:
    def test_high_success_ibt(self):
        assert _derive_trust_stage(0.9) == TrustStage.IBT.value
        assert _derive_trust_stage(0.8) == TrustStage.IBT.value
        assert _derive_trust_stage(1.0) == TrustStage.IBT.value

    def test_medium_success_kbt(self):
        assert _derive_trust_stage(0.7) == TrustStage.KBT.value
        assert _derive_trust_stage(0.5) == TrustStage.KBT.value
        assert _derive_trust_stage(0.79) == TrustStage.KBT.value

    def test_low_success_cbt(self):
        assert _derive_trust_stage(0.4) == TrustStage.CBT.value
        assert _derive_trust_stage(0.0) == TrustStage.CBT.value
        assert _derive_trust_stage(0.49) == TrustStage.CBT.value


class TestIsTimestampRecent:
    def test_recent_timestamp(self):
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        assert _is_timestamp_recent(now, threshold_seconds=60) is True

    def test_old_timestamp(self):
        old = "2020-01-01T00:00:00Z"
        assert _is_timestamp_recent(old, threshold_seconds=300) is False

    def test_invalid_timestamp(self):
        assert _is_timestamp_recent("not-a-timestamp", threshold_seconds=300) is False
        assert _is_timestamp_recent("", threshold_seconds=300) is False


class TestAgentMetricsRegistry:
    def test_empty_registry(self):
        registry = AgentMetricsRegistry()
        assert registry.get_agent_count() == 0
        assert registry.get_fleet_agents() == []

    def test_record_single_decision(self):
        registry = AgentMetricsRegistry()
        registry.record_decision("did:myth:test:001", allowed=True, latency_ms=10.0)

        assert registry.get_agent_count() == 1
        agents = registry.get_fleet_agents()
        assert len(agents) == 1
        assert agents[0].agent_id == "did:myth:test:001"
        assert agents[0].task_count == 1
        assert agents[0].success_rate == 1.0
        assert agents[0].avg_latency_ms == 10.0

    def test_multiple_decisions_same_agent(self):
        registry = AgentMetricsRegistry()
        registry.record_decision("did:myth:test:001", allowed=True, latency_ms=10.0)
        registry.record_decision("did:myth:test:001", allowed=True, latency_ms=20.0)
        registry.record_decision("did:myth:test:001", allowed=False, latency_ms=30.0)

        agents = registry.get_fleet_agents()
        assert len(agents) == 1
        assert agents[0].task_count == 3
        assert agents[0].success_rate == 2 / 3
        assert agents[0].avg_latency_ms == 20.0  # (10+20+30)/3

    def test_multiple_agents(self):
        registry = AgentMetricsRegistry()
        registry.record_decision("did:myth:test:001", allowed=True, latency_ms=10.0)
        registry.record_decision("did:myth:test:002", allowed=True, latency_ms=20.0)

        assert registry.get_agent_count() == 2
        agents = registry.get_fleet_agents()
        assert len(agents) == 2
        # Sorted by agent_id
        assert agents[0].agent_id == "did:myth:test:001"
        assert agents[1].agent_id == "did:myth:test:002"

    def test_circuit_breaker_closed(self):
        registry = AgentMetricsRegistry()
        registry.record_decision("did:myth:test:001", allowed=True, latency_ms=10.0)

        agents = registry.get_fleet_agents()
        assert agents[0].circuit_state == "closed"

    def test_circuit_breaker_half_open(self):
        config = CircuitBreakerConfig(half_open_threshold=2, open_threshold=5)
        registry = AgentMetricsRegistry(circuit_config=config)
        # Two failures trigger half-open
        registry.record_decision("did:myth:test:001", allowed=False, latency_ms=10.0)
        registry.record_decision("did:myth:test:001", allowed=False, latency_ms=10.0)

        agents = registry.get_fleet_agents()
        assert agents[0].circuit_state == "half-open"

    def test_circuit_breaker_open(self):
        config = CircuitBreakerConfig(half_open_threshold=2, open_threshold=3)
        registry = AgentMetricsRegistry(circuit_config=config)
        # Three failures trigger open
        for _ in range(3):
            registry.record_decision("did:myth:test:001", allowed=False, latency_ms=10.0)

        agents = registry.get_fleet_agents()
        assert agents[0].circuit_state == "open"

    def test_circuit_breaker_recovery(self):
        config = CircuitBreakerConfig(half_open_threshold=2, open_threshold=5)
        registry = AgentMetricsRegistry(circuit_config=config)
        # Two failures -> half-open
        registry.record_decision("did:myth:test:001", allowed=False, latency_ms=10.0)
        registry.record_decision("did:myth:test:001", allowed=False, latency_ms=10.0)
        # One success -> closed
        registry.record_decision("did:myth:test:001", allowed=True, latency_ms=10.0)

        agents = registry.get_fleet_agents()
        assert agents[0].circuit_state == "closed"

    def test_trust_stage_derived(self):
        registry = AgentMetricsRegistry()
        # All successes -> 100% -> IBT
        for _ in range(10):
            registry.record_decision("did:myth:test:001", allowed=True, latency_ms=10.0)

        agents = registry.get_fleet_agents()
        assert agents[0].trust_stage == TrustStage.IBT.value

    def test_status_active_recent(self):
        registry = AgentMetricsRegistry(active_threshold_seconds=300)
        registry.record_decision("did:myth:test:001", allowed=True, latency_ms=10.0)

        agents = registry.get_fleet_agents()
        assert agents[0].status == "active"

    def test_status_error_circuit_open(self):
        config = CircuitBreakerConfig(half_open_threshold=2, open_threshold=3)
        registry = AgentMetricsRegistry(circuit_config=config)
        for _ in range(3):
            registry.record_decision("did:myth:test:001", allowed=False, latency_ms=10.0)

        agents = registry.get_fleet_agents()
        assert agents[0].status == "error"

    def test_reset_clears_all(self):
        registry = AgentMetricsRegistry()
        registry.record_decision("did:myth:test:001", allowed=True, latency_ms=10.0)
        registry.reset()

        assert registry.get_agent_count() == 0
        assert registry.get_fleet_agents() == []

    def test_fleet_agent_to_dict(self):
        registry = AgentMetricsRegistry()
        registry.record_decision("did:myth:test:001", allowed=True, latency_ms=10.0)

        agents = registry.get_fleet_agents()
        d = agents[0].to_dict()

        assert d["agentId"] == "did:myth:test:001"
        assert d["status"] == "active"
        assert d["circuitState"] == "closed"
        assert d["taskCount"] == 1
        assert d["successRate"] == 1.0
        assert d["avgLatencyMs"] == 10.0
        assert "lastActiveAt" in d
