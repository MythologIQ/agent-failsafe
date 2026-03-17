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


# ── v2 SRE endpoints ──────────────────────────────────────────────────────────


def test_snapshot_v2_fields(client):
    """/sre/snapshot includes v2 fields: slis, auditEvents, fleet."""
    data = client.get("/sre/snapshot").json()
    assert "slis" in data
    assert "auditEvents" in data
    assert "fleet" in data


def test_snapshot_v2_slis_from_sli():
    """/sre/snapshot slis array reflects sli.get_slis()."""
    from fastapi.testclient import TestClient
    mod = _import_module()
    sli = MagicMock()
    sli.to_dict.return_value = {"name": "compliance"}
    mock_metric = MagicMock()
    mock_metric.to_dict.return_value = {"name": "Availability", "target": 0.999}
    sli.get_slis.return_value = [mock_metric]
    app = mod.create_sre_app(sli=sli)
    data = TestClient(app).get("/sre/snapshot").json()
    assert data["slis"] == [{"name": "Availability", "target": 0.999}]


def test_snapshot_v2_audit_events():
    """/sre/snapshot auditEvents reflects audit_sink.get_recent_events()."""
    from fastapi.testclient import TestClient
    mod = _import_module()
    sink = MagicMock()
    mock_event = MagicMock()
    mock_event.to_dict.return_value = {"id": "ev1", "type": "file.write", "action": "ALLOW"}
    sink.get_recent_events.return_value = [mock_event]
    app = mod.create_sre_app(audit_sink=sink)
    data = TestClient(app).get("/sre/snapshot").json()
    assert data["auditEvents"] == [{"id": "ev1", "type": "file.write", "action": "ALLOW"}]


def test_snapshot_v2_fleet():
    """/sre/snapshot fleet reflects agent_metrics.get_fleet_agents()."""
    from fastapi.testclient import TestClient
    mod = _import_module()
    metrics = MagicMock()
    mock_agent = MagicMock()
    mock_agent.to_dict.return_value = {"agentId": "did:myth:test", "status": "active"}
    metrics.get_fleet_agents.return_value = [mock_agent]
    app = mod.create_sre_app(agent_metrics=metrics)
    data = TestClient(app).get("/sre/snapshot").json()
    assert data["fleet"] == [{"agentId": "did:myth:test", "status": "active"}]


# ── /sre/events endpoint ──────────────────────────────────────────────────────


def test_events_endpoint_empty(client):
    """/sre/events returns empty array when no audit_sink."""
    resp = client.get("/sre/events")
    assert resp.status_code == 200
    assert resp.json() == {"events": []}


def test_events_endpoint_with_sink():
    """/sre/events returns events from audit_sink.get_recent_events()."""
    from fastapi.testclient import TestClient
    mod = _import_module()
    sink = MagicMock()
    mock_event = MagicMock()
    mock_event.to_dict.return_value = {"id": "ev1", "action": "ALLOW"}
    sink.get_recent_events.return_value = [mock_event]
    app = mod.create_sre_app(audit_sink=sink)
    data = TestClient(app).get("/sre/events").json()
    assert data["events"] == [{"id": "ev1", "action": "ALLOW"}]


def test_events_endpoint_respects_limit():
    """/sre/events?limit=N passes limit to get_recent_events()."""
    from fastapi.testclient import TestClient
    mod = _import_module()
    sink = MagicMock()
    sink.get_recent_events.return_value = []
    app = mod.create_sre_app(audit_sink=sink)
    TestClient(app).get("/sre/events?limit=25")
    sink.get_recent_events.assert_called_with(limit=25)


# ── /sre/fleet endpoint ───────────────────────────────────────────────────────


def test_fleet_endpoint_empty(client):
    """/sre/fleet returns empty array when no agent_metrics."""
    resp = client.get("/sre/fleet")
    assert resp.status_code == 200
    assert resp.json() == {"agents": []}


def test_fleet_endpoint_with_metrics():
    """/sre/fleet returns agents from agent_metrics.get_fleet_agents()."""
    from fastapi.testclient import TestClient
    mod = _import_module()
    metrics = MagicMock()
    mock_agent = MagicMock()
    mock_agent.to_dict.return_value = {"agentId": "did:myth:test", "status": "active"}
    metrics.get_fleet_agents.return_value = [mock_agent]
    app = mod.create_sre_app(agent_metrics=metrics)
    data = TestClient(app).get("/sre/fleet").json()
    assert data["agents"] == [{"agentId": "did:myth:test", "status": "active"}]
