"""Tests for agent_failsafe.shadow_genome module."""

from __future__ import annotations

import pytest

from agent_failsafe.shadow_genome import (
    InMemoryShadowGenomeStore,
    RemediationStatus,
    classify_failure_mode,
    generate_negative_constraint,
    get_constraints_for_agent,
)
from agent_failsafe.types import FailureMode, ShadowGenomeEntry


# ── helpers ──────────────────────────────────────────────────────────────

def _entry(
    agent_did: str = "did:myth:test:abc",
    failure_mode: FailureMode = FailureMode.OTHER,
    status: str = "UNRESOLVED",
    constraint: str = "test constraint",
) -> ShadowGenomeEntry:
    return ShadowGenomeEntry(
        agent_did=agent_did,
        failure_mode=failure_mode,
        remediation_status=status,
        negative_constraint=constraint,
    )


# ── TestRemediationStatus ────────────────────────────────────────────────


class TestRemediationStatus:
    """Verify enum members and string behaviour."""

    def test_has_five_members(self) -> None:
        assert len(RemediationStatus) == 5

    def test_string_values(self) -> None:
        expected = {"UNRESOLVED", "IN_PROGRESS", "RESOLVED", "WONT_FIX", "SUPERSEDED"}
        assert {m.value for m in RemediationStatus} == expected


# ── TestClassifyFailureMode ──────────────────────────────────────────────


class TestClassifyFailureMode:
    """Keyword-based failure classification."""

    def test_injection(self) -> None:
        result = classify_failure_mode(["sql_injection"], "L2", "found injection")
        assert result is FailureMode.INJECTION_VULNERABILITY

    def test_secret(self) -> None:
        result = classify_failure_mode(["hardcoded_secret"], "L3", "exposed credential")
        assert result is FailureMode.SECRET_EXPOSURE

    def test_pii(self) -> None:
        result = classify_failure_mode([], "L2", "contains ssn data")
        assert result is FailureMode.PII_LEAK

    def test_complexity(self) -> None:
        result = classify_failure_mode(["high_complexity"], "L1", "deep nesting")
        assert result is FailureMode.HIGH_COMPLEXITY

    def test_unknown_fallback(self) -> None:
        result = classify_failure_mode([], "L1", "something unusual happened")
        assert result is FailureMode.OTHER


# ── TestGenerateNegativeConstraint ───────────────────────────────────────


class TestGenerateNegativeConstraint:
    """AVOID/REQUIRE template generation."""

    def test_injection_constraint(self) -> None:
        c = generate_negative_constraint(FailureMode.INJECTION_VULNERABILITY, "app.py", "")
        assert "AVOID:" in c and "REQUIRE:" in c
        assert "app.py" in c

    def test_secret_constraint(self) -> None:
        c = generate_negative_constraint(FailureMode.SECRET_EXPOSURE, "config.py", "")
        assert "AVOID:" in c and "REQUIRE:" in c
        assert "config.py" in c

    def test_complexity_constraint(self) -> None:
        c = generate_negative_constraint(FailureMode.HIGH_COMPLEXITY, "core.py", "")
        assert "AVOID:" in c and "REQUIRE:" in c

    def test_fallback_constraint(self) -> None:
        c = generate_negative_constraint(FailureMode.OTHER, "unknown.py", "")
        assert "AVOID:" in c and "REQUIRE:" in c


# ── TestInMemoryShadowGenomeStore ────────────────────────────────────────


class TestInMemoryShadowGenomeStore:
    """Thread-safe in-memory store with FIFO eviction."""

    def test_record_and_query(self) -> None:
        store = InMemoryShadowGenomeStore()
        store.record(_entry())
        assert len(store.query()) == 1

    def test_filter_by_agent_did(self) -> None:
        store = InMemoryShadowGenomeStore()
        store.record(_entry(agent_did="did:mesh:aaa"))
        store.record(_entry(agent_did="did:mesh:bbb"))
        results = store.query(agent_did="did:mesh:aaa")
        assert len(results) == 1
        assert results[0].agent_did == "did:mesh:aaa"

    def test_filter_by_failure_mode(self) -> None:
        store = InMemoryShadowGenomeStore()
        store.record(_entry(failure_mode=FailureMode.PII_LEAK))
        store.record(_entry(failure_mode=FailureMode.LOGIC_ERROR))
        results = store.query(failure_mode=FailureMode.PII_LEAK)
        assert len(results) == 1

    def test_filter_by_status(self) -> None:
        store = InMemoryShadowGenomeStore()
        store.record(_entry(status="RESOLVED"))
        store.record(_entry(status="UNRESOLVED"))
        results = store.query(status="RESOLVED")
        assert len(results) == 1

    def test_compound_filter(self) -> None:
        store = InMemoryShadowGenomeStore()
        store.record(_entry(agent_did="a", failure_mode=FailureMode.PII_LEAK, status="RESOLVED"))
        store.record(_entry(agent_did="a", failure_mode=FailureMode.PII_LEAK, status="UNRESOLVED"))
        store.record(_entry(agent_did="b", failure_mode=FailureMode.PII_LEAK, status="RESOLVED"))
        results = store.query(agent_did="a", failure_mode=FailureMode.PII_LEAK, status="RESOLVED")
        assert len(results) == 1

    def test_fifo_eviction(self) -> None:
        store = InMemoryShadowGenomeStore(max_entries=3)
        for i in range(5):
            store.record(_entry(constraint=f"c{i}"))
        results = store.query()
        assert len(results) == 3
        # Newest first after reverse, oldest evicted
        assert results[0].negative_constraint == "c4"
        assert results[2].negative_constraint == "c2"

    def test_limit_parameter(self) -> None:
        store = InMemoryShadowGenomeStore()
        for _ in range(10):
            store.record(_entry())
        assert len(store.query(limit=3)) == 3

    def test_empty_store(self) -> None:
        store = InMemoryShadowGenomeStore()
        assert len(store.query()) == 0


# ── TestGetConstraintsForAgent ───────────────────────────────────────────


class TestGetConstraintsForAgent:
    """Constraint retrieval by agent DID."""

    def test_returns_constraints(self) -> None:
        store = InMemoryShadowGenomeStore()
        store.record(_entry(agent_did="did:mesh:x", constraint="no injection"))
        store.record(_entry(agent_did="did:mesh:x", constraint="no secrets"))
        result = get_constraints_for_agent(store, "did:mesh:x")
        assert result == ["no secrets", "no injection"]

    def test_respects_limit(self) -> None:
        store = InMemoryShadowGenomeStore()
        for i in range(5):
            store.record(_entry(agent_did="did:mesh:y", constraint=f"c{i}"))
        result = get_constraints_for_agent(store, "did:mesh:y", limit=2)
        assert len(result) == 2

    def test_empty_store_returns_empty(self) -> None:
        store = InMemoryShadowGenomeStore()
        assert get_constraints_for_agent(store, "did:mesh:z") == []
