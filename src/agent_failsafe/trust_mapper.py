"""DID translation and trust score mapping between FailSafe and Agent Mesh.

Bridges ``did:myth:{persona}:{hash}`` (FailSafe) to ``did:mesh:{hash}``
(Agent Mesh) and translates FailSafe trust stages (CBT/KBT/IBT) to
Agent Mesh RewardSignal scores (0–1000).
"""

from __future__ import annotations

import hashlib
import logging
import re

from .types import PersonaType, TrustStage

logger = logging.getLogger(__name__)

# Trust stage → mesh trust score range (0–1000)
_STAGE_SCORE_RANGES: dict[TrustStage, tuple[int, int]] = {
    TrustStage.CBT: (100, 400),   # Capability-Based: low-mid
    TrustStage.KBT: (400, 700),   # Knowledge-Based: mid-high
    TrustStage.IBT: (700, 1000),  # Identity-Based: high
}

# Persona → base trust modifier
_PERSONA_MODIFIERS: dict[PersonaType, int] = {
    PersonaType.SCRIVENER: 0,
    PersonaType.SENTINEL: 100,
    PersonaType.JUDGE: 150,
    PersonaType.OVERSEER: 200,
}

# DID pattern matchers
_MYTH_DID_PATTERN = re.compile(r"^did:myth:(\w+):([a-f0-9]+|local)$")
_MESH_DID_PATTERN = re.compile(r"^did:mesh:([a-f0-9]+)$")


class FailSafeTrustMapper:
    """Bidirectional DID and trust score mapper.

    Maintains a mapping table between FailSafe DIDs and Agent Mesh DIDs,
    and translates trust scores between the two systems.

    Args:
        default_trust_score: Default mesh trust score for unknown agents.
    """

    def __init__(self, default_trust_score: int = 500) -> None:
        self.default_trust_score = default_trust_score
        self._did_map: dict[str, str] = {}  # myth_did -> mesh_did
        self._reverse_map: dict[str, str] = {}  # mesh_did -> myth_did

    def myth_to_mesh(self, myth_did: str) -> str:
        """Convert a FailSafe DID to an Agent Mesh DID.

        Format: ``did:myth:{persona}:{hash}`` → ``did:mesh:{derived_hash}``

        The mesh hash is derived by hashing the full myth DID to produce
        a deterministic, unique mesh identifier.
        """
        if myth_did in self._did_map:
            return self._did_map[myth_did]

        match = _MYTH_DID_PATTERN.match(myth_did)
        if not match:
            raise ValueError(f"Invalid FailSafe DID format: {myth_did}")

        mesh_hash = hashlib.sha256(myth_did.encode()).hexdigest()[:32]
        mesh_did = f"did:mesh:{mesh_hash}"

        self._did_map[myth_did] = mesh_did
        self._reverse_map[mesh_did] = myth_did
        return mesh_did

    def mesh_to_myth(self, mesh_did: str) -> str | None:
        """Look up the FailSafe DID for a known Agent Mesh DID.

        Returns None if the mesh DID has no known FailSafe mapping.
        """
        return self._reverse_map.get(mesh_did)

    def register_mapping(self, myth_did: str, mesh_did: str) -> None:
        """Manually register a DID mapping."""
        self._did_map[myth_did] = mesh_did
        self._reverse_map[mesh_did] = myth_did

    def trust_to_mesh_score(
        self,
        trust_score: float,
        trust_stage: TrustStage,
        persona: PersonaType = PersonaType.SCRIVENER,
    ) -> int:
        """Convert a FailSafe trust score to an Agent Mesh score (0–1000).

        The conversion uses the trust stage to determine the base range,
        then scales the FailSafe score (0.0–1.0) within that range,
        and applies a persona modifier.

        Args:
            trust_score: FailSafe trust score (0.0–1.0).
            trust_stage: Current trust evolution stage.
            persona: Agent persona type.

        Returns:
            Agent Mesh trust score (0–1000).
        """
        low, high = _STAGE_SCORE_RANGES.get(trust_stage, (100, 400))
        base = int(low + (high - low) * max(0.0, min(1.0, trust_score)))
        modifier = _PERSONA_MODIFIERS.get(persona, 0)
        return min(1000, base + modifier)

    def mesh_score_to_trust(self, mesh_score: int) -> tuple[float, TrustStage]:
        """Convert an Agent Mesh score (0–1000) back to FailSafe trust.

        Returns (trust_score, trust_stage) tuple.
        """
        if mesh_score >= 700:
            stage = TrustStage.IBT
            low, high = 700, 1000
        elif mesh_score >= 400:
            stage = TrustStage.KBT
            low, high = 400, 700
        else:
            stage = TrustStage.CBT
            low, high = 100, 400

        trust_score = (mesh_score - low) / (high - low) if high > low else 0.0
        return max(0.0, min(1.0, trust_score)), stage

    @staticmethod
    def extract_persona(myth_did: str) -> PersonaType | None:
        """Extract the persona type from a FailSafe DID."""
        match = _MYTH_DID_PATTERN.match(myth_did)
        if not match:
            return None
        try:
            return PersonaType(match.group(1))
        except ValueError:
            return None

    @staticmethod
    def is_myth_did(did: str) -> bool:
        """Check if a DID is in FailSafe format."""
        return bool(_MYTH_DID_PATTERN.match(did))

    @staticmethod
    def is_mesh_did(did: str) -> bool:
        """Check if a DID is in Agent Mesh format."""
        return bool(_MESH_DID_PATTERN.match(did))
