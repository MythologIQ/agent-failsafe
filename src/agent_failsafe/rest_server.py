"""REST bridge — exposes FailSafe adapter data for the SRE panel.

Install extras: pip install "agent-failsafe[server]"
Run:           python -m agent_failsafe.rest_server
"""

from __future__ import annotations

from typing import Any

# Lazy FastAPI import — requires server extra
_FastAPI: Any = None


def _ensure_fastapi() -> None:
    global _FastAPI
    if _FastAPI is None:
        from fastapi import FastAPI  # noqa: PLC0415
        _FastAPI = FastAPI


# OWASP ASI draft coverage — what agent-failsafe covers
_ASI_COVERAGE = {
    "ASI-01": {"label": "Intent Verification",        "covered": True,  "feature": "FailSafeInterceptor"},
    "ASI-02": {"label": "Permission Scoping",          "covered": True,  "feature": "GovernancePipeline"},
    "ASI-03": {"label": "Audit Trail",                 "covered": True,  "feature": "FailSafeAuditSink"},
    "ASI-04": {"label": "Trust Chain",                 "covered": True,  "feature": "FailSafeTrustMapper"},
    "ASI-05": {"label": "Behavioral Constraints",      "covered": True,  "feature": "ShadowGenomePolicyProvider"},
    "ASI-06": {"label": "Delegation Chain Visibility", "covered": True,  "feature": "FailSafeTrustMapper (partial)"},
}


def create_sre_app(
    policy_provider: Any = None,
    sli: Any = None,
    audit_sink: Any = None,
    agent_metrics: Any = None,
) -> Any:
    """Create FastAPI app exposing SRE v2 endpoints.

    Args:
        policy_provider: ShadowGenomePolicyProvider instance (or None).
        sli: FailSafeComplianceSLI instance (or None).
        audit_sink: FailSafeAuditSink instance (or None).
        agent_metrics: AgentMetricsRegistry instance (or None).

    Returns:
        FastAPI application with /sre/snapshot, /sre/events, /sre/fleet.
    """
    _ensure_fastapi()
    app = _FastAPI()

    @app.get("/sre/snapshot")
    async def sre_snapshot() -> dict:
        """Return v2 SRE snapshot with SLIs, events, and fleet data."""
        policies = policy_provider.get_policies() if policy_provider else []

        # SLIs array (v2)
        slis = []
        if sli is not None and hasattr(sli, "get_slis"):
            slis = [s.to_dict() for s in sli.get_slis()]

        # Audit events (v2)
        audit_events = []
        if audit_sink is not None and hasattr(audit_sink, "get_recent_events"):
            audit_events = [e.to_dict() for e in audit_sink.get_recent_events(limit=50)]

        # Fleet agents (v2)
        fleet = []
        if agent_metrics is not None and hasattr(agent_metrics, "get_fleet_agents"):
            fleet = [a.to_dict() for a in agent_metrics.get_fleet_agents()]

        # Legacy sli dict for backward compatibility
        sli_data = sli.to_dict() if sli else {}

        return {
            "policies": policies,
            "trustScores": [],
            "sli": sli_data,
            "slis": slis,
            "auditEvents": audit_events,
            "fleet": fleet,
            "asiCoverage": _ASI_COVERAGE,
        }

    @app.get("/sre/events")
    async def sre_events(limit: int = 100) -> dict:
        """Return recent governance audit events."""
        if audit_sink is None or not hasattr(audit_sink, "get_recent_events"):
            return {"events": []}
        events = audit_sink.get_recent_events(limit=limit)
        return {"events": [e.to_dict() for e in events]}

    @app.get("/sre/fleet")
    async def sre_fleet() -> dict:
        """Return per-agent health status for Fleet Health section."""
        if agent_metrics is None or not hasattr(agent_metrics, "get_fleet_agents"):
            return {"agents": []}
        agents = agent_metrics.get_fleet_agents()
        return {"agents": [a.to_dict() for a in agents]}

    return app


if __name__ == "__main__":
    import uvicorn
    app = create_sre_app()
    uvicorn.run(app, host="127.0.0.1", port=9377)
