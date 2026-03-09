"""PolicyProviderInterface implementation — Shadow Genome as dynamic policy source.

Translates FailSafe Shadow Genome AVOID/REQUIRE constraints into policy
definitions consumable by the Agent OS control plane.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from .types import FailSafeClient, FailureMode, ShadowGenomeEntry

logger = logging.getLogger(__name__)


class ShadowGenomePolicyProvider:
    """Provides dynamic policies derived from FailSafe Shadow Genome entries.

    Each unresolved Shadow Genome entry generates a DENY rule that blocks
    the failure pattern from recurring. Resolved entries are ignored.

    This class can be used standalone or registered as a
    ``PolicyProviderInterface`` plugin in the Agent OS control plane.

    Args:
        client: A FailSafeClient for retrieving Shadow Genome entries.
        agent_did: Optional filter — only load entries for this agent.
    """

    def __init__(
        self,
        client: FailSafeClient,
        agent_did: str = "",
    ) -> None:
        self.client = client
        self.agent_did = agent_did
        self._policies: list[dict[str, Any]] = []
        self._loaded = False

    def refresh(self) -> None:
        """Reload policies from the Shadow Genome."""
        entries = self.client.get_shadow_genome(self.agent_did)
        self._policies = [
            self._entry_to_policy(entry)
            for entry in entries
            if entry.remediation_status == "UNRESOLVED"
        ]
        self._loaded = True
        logger.info(
            "ShadowGenomePolicyProvider: loaded %d policies from %d entries",
            len(self._policies),
            len(entries),
        )

    def get_policies(
        self,
        agent_id: Optional[str] = None,
        action_type: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Get applicable policies derived from Shadow Genome.

        Args:
            agent_id: Optional agent filter.
            action_type: Optional action type filter.

        Returns:
            List of policy definition dicts.
        """
        if not self._loaded:
            self.refresh()

        policies = self._policies
        if agent_id:
            policies = [p for p in policies if p.get("agent_did", "") in ("", agent_id)]
        if action_type:
            policies = [
                p for p in policies
                if action_type in p.get("rules", [{}])[0].get("actions", [action_type])
            ]
        return policies

    def add_policy(self, policy: dict[str, Any]) -> bool:
        """Add a manual policy (not backed by Shadow Genome)."""
        self._policies.append(policy)
        return True

    def delete_policy(self, policy_id: str) -> bool:
        """Remove a policy by ID."""
        before = len(self._policies)
        self._policies = [p for p in self._policies if p.get("policy_id") != policy_id]
        return len(self._policies) < before

    def _entry_to_policy(self, entry: ShadowGenomeEntry) -> dict[str, Any]:
        """Convert a Shadow Genome entry into a policy definition.

        The negative_constraint from the genome becomes a blocked pattern,
        and the failure_mode determines which actions are restricted.
        """
        blocked_patterns = []
        if entry.negative_constraint:
            blocked_patterns.append(entry.negative_constraint)
        if entry.input_vector:
            blocked_patterns.append(entry.input_vector)

        restricted_actions = self._failure_mode_to_actions(entry.failure_mode)

        return {
            "policy_id": f"shadow_genome_{entry.entry_id}",
            "name": f"Shadow Genome: {entry.failure_mode.value}",
            "description": (
                f"Auto-generated DENY rule from Shadow Genome entry {entry.entry_id}. "
                f"Failure mode: {entry.failure_mode.value}. "
                f"Causal vector: {entry.causal_vector or 'unknown'}."
            ),
            "rules": [
                {
                    "action": "DENY",
                    "actions": restricted_actions,
                    "blocked_patterns": blocked_patterns,
                    "reason": f"Blocked by Shadow Genome ({entry.failure_mode.value})",
                }
            ],
            "priority": 100,  # High priority — safety constraints
            "enabled": True,
            "agent_did": entry.agent_did,
            "metadata": {
                "source": "shadow_genome",
                "failure_mode": entry.failure_mode.value,
                "entry_id": entry.entry_id,
                "created_at": entry.created_at,
            },
        }

    @staticmethod
    def _failure_mode_to_actions(mode: FailureMode) -> list[str]:
        """Map a failure mode to the actions it should restrict."""
        mapping: dict[FailureMode, list[str]] = {
            FailureMode.SECRET_EXPOSURE: ["file.write", "checkpoint.create"],
            FailureMode.PII_LEAK: ["file.write", "file.delete"],
            FailureMode.INJECTION_VULNERABILITY: ["file.write"],
            FailureMode.HALLUCINATION: ["file.write", "intent.seal"],
            FailureMode.SPEC_VIOLATION: ["intent.seal"],
            FailureMode.TRUST_VIOLATION: ["agent.register", "l3.approve"],
        }
        return mapping.get(mode, ["file.write"])
