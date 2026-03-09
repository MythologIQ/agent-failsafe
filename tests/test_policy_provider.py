"""Tests for ShadowGenomePolicyProvider — Shadow Genome as dynamic policy source."""

import pytest

from agent_failsafe.policy_provider import ShadowGenomePolicyProvider
from agent_failsafe.types import (
    DecisionRequest,
    DecisionResponse,
    FailureMode,
    RiskGrade,
    ShadowGenomeEntry,
)


class MockClient:
    """Mock FailSafeClient that returns configured Shadow Genome entries."""

    def __init__(self, entries: list[ShadowGenomeEntry] | None = None):
        self._entries = entries or []

    def evaluate(self, request):
        return DecisionResponse(allowed=True)

    def classify_risk(self, file_path, content=""):
        return RiskGrade.L1

    def get_shadow_genome(self, agent_did=""):
        if agent_did:
            return [e for e in self._entries if e.agent_did == agent_did]
        return self._entries


class TestShadowGenomePolicyProvider:
    def test_empty_genome(self):
        provider = ShadowGenomePolicyProvider(client=MockClient())
        policies = provider.get_policies()
        assert policies == []

    def test_unresolved_entries_become_policies(self):
        entries = [
            ShadowGenomeEntry(
                agent_did="did:myth:scrivener:abc",
                failure_mode=FailureMode.SECRET_EXPOSURE,
                negative_constraint="api_key",
                remediation_status="UNRESOLVED",
            ),
            ShadowGenomeEntry(
                agent_did="did:myth:scrivener:abc",
                failure_mode=FailureMode.HALLUCINATION,
                negative_constraint="fabricated_url",
                remediation_status="RESOLVED",  # Should be excluded
            ),
        ]
        provider = ShadowGenomePolicyProvider(client=MockClient(entries))
        policies = provider.get_policies()

        assert len(policies) == 1
        assert policies[0]["name"] == "Shadow Genome: SECRET_EXPOSURE"
        assert "api_key" in policies[0]["rules"][0]["blocked_patterns"]

    def test_policy_structure(self):
        entries = [
            ShadowGenomeEntry(
                entry_id="test123",
                agent_did="did:myth:scrivener:abc",
                failure_mode=FailureMode.PII_LEAK,
                input_vector="user_email",
                negative_constraint="email_pattern",
                causal_vector="unfiltered input",
            ),
        ]
        provider = ShadowGenomePolicyProvider(client=MockClient(entries))
        policy = provider.get_policies()[0]

        assert policy["policy_id"] == "shadow_genome_test123"
        assert policy["priority"] == 100
        assert policy["enabled"] is True
        assert policy["metadata"]["source"] == "shadow_genome"
        assert policy["metadata"]["failure_mode"] == "PII_LEAK"
        assert "email_pattern" in policy["rules"][0]["blocked_patterns"]
        assert "user_email" in policy["rules"][0]["blocked_patterns"]

    def test_failure_mode_action_mapping(self):
        entries = [
            ShadowGenomeEntry(failure_mode=FailureMode.SECRET_EXPOSURE),
            ShadowGenomeEntry(failure_mode=FailureMode.TRUST_VIOLATION),
        ]
        provider = ShadowGenomePolicyProvider(client=MockClient(entries))
        policies = provider.get_policies()

        secret_actions = policies[0]["rules"][0]["actions"]
        assert "file.write" in secret_actions
        assert "checkpoint.create" in secret_actions

        trust_actions = policies[1]["rules"][0]["actions"]
        assert "agent.register" in trust_actions
        assert "l3.approve" in trust_actions

    def test_agent_filter(self):
        entries = [
            ShadowGenomeEntry(agent_did="did:myth:scrivener:abc", failure_mode=FailureMode.LOGIC_ERROR),
            ShadowGenomeEntry(agent_did="did:myth:scrivener:xyz", failure_mode=FailureMode.LOGIC_ERROR),
        ]
        provider = ShadowGenomePolicyProvider(client=MockClient(entries))
        policies = provider.get_policies(agent_id="did:myth:scrivener:abc")
        assert len(policies) == 1

    def test_add_manual_policy(self):
        provider = ShadowGenomePolicyProvider(client=MockClient())
        provider.refresh()  # load empty
        provider.add_policy({"policy_id": "manual_1", "name": "Manual"})
        assert len(provider.get_policies()) == 1

    def test_delete_policy(self):
        entries = [
            ShadowGenomeEntry(entry_id="del_me", failure_mode=FailureMode.OTHER),
        ]
        provider = ShadowGenomePolicyProvider(client=MockClient(entries))
        provider.refresh()
        assert len(provider.get_policies()) == 1
        provider.delete_policy("shadow_genome_del_me")
        assert len(provider.get_policies()) == 0

    def test_refresh_reloads(self):
        client = MockClient()
        provider = ShadowGenomePolicyProvider(client=client)
        assert provider.get_policies() == []

        # Add an entry and refresh
        client._entries.append(
            ShadowGenomeEntry(failure_mode=FailureMode.INJECTION_VULNERABILITY)
        )
        provider.refresh()
        assert len(provider.get_policies()) == 1
