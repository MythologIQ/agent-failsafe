"""Tests for rest_server — SRE panel REST bridge."""

from __future__ import annotations

import importlib
import sys
from unittest.mock import MagicMock

import pytest


def _import_module():
    """Import rest_server with a clean FastAPI mock."""
    if "agent_failsafe.rest_server" in sys.modules:
        del sys.modules["agent_failsafe.rest_server"]
    return importlib.import_module("agent_failsafe.rest_server")


# ── create_sre_app ────────────────────────────────────────────────────────────

def test_create_sre_app_returns_application():
    """create_sre_app() returns an object when FastAPI is available."""
    mod = _import_module()
    app = mod.create_sre_app()
    assert app is not None


def test_create_sre_app_raises_import_error_when_fastapi_missing(monkeypatch):
    """create_sre_app() raises ImportError when FastAPI is not installed."""
    if "agent_failsafe.rest_server" in sys.modules:
        del sys.modules["agent_failsafe.rest_server"]

    import builtins
    original_import = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if name == "fastapi":
            raise ImportError("No module named 'fastapi'")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", mock_import)

    if "agent_failsafe.rest_server" in sys.modules:
        del sys.modules["agent_failsafe.rest_server"]

    mod = importlib.import_module("agent_failsafe.rest_server")
    mod._FastAPI = None  # reset cached import

    with pytest.raises(ImportError):
        mod._ensure_fastapi()


# ── /sre/snapshot endpoint ────────────────────────────────────────────────────

@pytest.fixture
def client():
    """Return a TestClient for a default SRE app."""
    from fastapi.testclient import TestClient
    mod = _import_module()
    app = mod.create_sre_app()
    return TestClient(app)


def test_snapshot_default_response(client):
    """/sre/snapshot returns expected shape with no deps."""
    resp = client.get("/sre/snapshot")
    assert resp.status_code == 200
    data = resp.json()
    assert data["policies"] == []
    assert data["trustScores"] == []
    assert data["sli"] == {}
    assert "ASI-01" in data["asiCoverage"]


def test_snapshot_policies_from_provider():
    """/sre/snapshot policies reflect policy_provider.get_policies()."""
    from fastapi.testclient import TestClient
    mod = _import_module()
    provider = MagicMock()
    provider.get_policies.return_value = [{"name": "p1", "type": "allow", "enforced": True}]
    app = mod.create_sre_app(policy_provider=provider)
    resp = TestClient(app).get("/sre/snapshot")
    assert resp.json()["policies"] == [{"name": "p1", "type": "allow", "enforced": True}]


def test_snapshot_sli_from_sli_instance():
    """/sre/snapshot sli reflects sli.to_dict()."""
    from fastapi.testclient import TestClient
    mod = _import_module()
    sli = MagicMock()
    sli.to_dict.return_value = {"name": "compliance", "target": 0.95}
    app = mod.create_sre_app(sli=sli)
    resp = TestClient(app).get("/sre/snapshot")
    assert resp.json()["sli"] == {"name": "compliance", "target": 0.95}


def test_snapshot_asi_coverage_structure(client):
    """asiCoverage contains all 6 draft controls with correct shape."""
    data = client.get("/sre/snapshot").json()
    asi = data["asiCoverage"]
    for key in ("ASI-01", "ASI-02", "ASI-03", "ASI-04", "ASI-05", "ASI-06"):
        assert key in asi, f"Missing {key}"
        assert isinstance(asi[key]["covered"], bool)
        assert isinstance(asi[key]["label"], str)
        assert isinstance(asi[key]["feature"], str)


def test_snapshot_asi03_covered(client):
    """ASI-03 Audit Trail is marked covered."""
    asi = client.get("/sre/snapshot").json()["asiCoverage"]
    assert asi["ASI-03"]["covered"] is True


def test_snapshot_asi06_present(client):
    """ASI-06 Delegation Chain Visibility key is present."""
    asi = client.get("/sre/snapshot").json()["asiCoverage"]
    assert "ASI-06" in asi
