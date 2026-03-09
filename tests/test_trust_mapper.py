"""Tests for FailSafeTrustMapper — DID and trust score translation."""

import pytest

from agent_failsafe.trust_mapper import FailSafeTrustMapper
from agent_failsafe.types import PersonaType, TrustStage


class TestDIDConversion:
    def test_myth_to_mesh(self):
        mapper = FailSafeTrustMapper()
        mesh_did = mapper.myth_to_mesh("did:myth:scrivener:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4")
        assert mesh_did.startswith("did:mesh:")
        assert len(mesh_did) == len("did:mesh:") + 32

    def test_deterministic(self):
        mapper = FailSafeTrustMapper()
        did = "did:myth:sentinel:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
        assert mapper.myth_to_mesh(did) == mapper.myth_to_mesh(did)

    def test_round_trip(self):
        mapper = FailSafeTrustMapper()
        myth_did = "did:myth:judge:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
        mesh_did = mapper.myth_to_mesh(myth_did)
        assert mapper.mesh_to_myth(mesh_did) == myth_did

    def test_invalid_myth_did(self):
        mapper = FailSafeTrustMapper()
        with pytest.raises(ValueError, match="Invalid FailSafe DID"):
            mapper.myth_to_mesh("did:invalid:foo")

    def test_manual_mapping(self):
        mapper = FailSafeTrustMapper()
        mapper.register_mapping("did:myth:scrivener:abc123abc123abc123abc123abc123ab", "did:mesh:custom123")
        assert mapper.myth_to_mesh("did:myth:scrivener:abc123abc123abc123abc123abc123ab") == "did:mesh:custom123"

    def test_local_overseer(self):
        mapper = FailSafeTrustMapper()
        mesh_did = mapper.myth_to_mesh("did:myth:overseer:local")
        assert mesh_did.startswith("did:mesh:")


class TestTrustScoreConversion:
    def test_cbt_low(self):
        mapper = FailSafeTrustMapper()
        score = mapper.trust_to_mesh_score(0.0, TrustStage.CBT)
        assert 100 <= score <= 400

    def test_kbt_mid(self):
        mapper = FailSafeTrustMapper()
        score = mapper.trust_to_mesh_score(0.5, TrustStage.KBT)
        assert 400 <= score <= 700

    def test_ibt_high(self):
        mapper = FailSafeTrustMapper()
        score = mapper.trust_to_mesh_score(1.0, TrustStage.IBT)
        assert 700 <= score <= 1000

    def test_persona_modifier(self):
        mapper = FailSafeTrustMapper()
        base = mapper.trust_to_mesh_score(0.5, TrustStage.CBT, PersonaType.SCRIVENER)
        sentinel = mapper.trust_to_mesh_score(0.5, TrustStage.CBT, PersonaType.SENTINEL)
        assert sentinel > base

    def test_clamped_to_1000(self):
        mapper = FailSafeTrustMapper()
        score = mapper.trust_to_mesh_score(1.0, TrustStage.IBT, PersonaType.OVERSEER)
        assert score <= 1000

    def test_reverse_conversion(self):
        mapper = FailSafeTrustMapper()
        trust, stage = mapper.mesh_score_to_trust(800)
        assert stage == TrustStage.IBT
        assert 0.0 <= trust <= 1.0

        trust, stage = mapper.mesh_score_to_trust(500)
        assert stage == TrustStage.KBT

        trust, stage = mapper.mesh_score_to_trust(200)
        assert stage == TrustStage.CBT


class TestPersonaExtraction:
    def test_extract_scrivener(self):
        assert FailSafeTrustMapper.extract_persona(
            "did:myth:scrivener:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
        ) == PersonaType.SCRIVENER

    def test_extract_sentinel(self):
        assert FailSafeTrustMapper.extract_persona(
            "did:myth:sentinel:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
        ) == PersonaType.SENTINEL

    def test_invalid_did(self):
        assert FailSafeTrustMapper.extract_persona("not-a-did") is None

    def test_unknown_persona(self):
        assert FailSafeTrustMapper.extract_persona(
            "did:myth:unknown:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
        ) is None


class TestDIDValidation:
    def test_is_myth_did(self):
        assert FailSafeTrustMapper.is_myth_did("did:myth:scrivener:abc123abc123abc123abc123abc123ab")
        assert not FailSafeTrustMapper.is_myth_did("did:mesh:abc123")

    def test_is_mesh_did(self):
        assert FailSafeTrustMapper.is_mesh_did("did:mesh:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4")
        assert not FailSafeTrustMapper.is_mesh_did("did:myth:scrivener:abc")
