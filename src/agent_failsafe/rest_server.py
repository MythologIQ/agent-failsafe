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
) -> Any:
    """Create FastAPI app exposing GET /sre/snapshot.

    Args:
        policy_provider: ShadowGenomePolicyProvider instance (or None).
        sli: FailSafeComplianceSLI instance (or None).

    Returns:
        FastAPI application.
    """
    _ensure_fastapi()
    app = _FastAPI()

    @app.get("/sre/snapshot")
    async def sre_snapshot() -> dict:
        policies = policy_provider.get_policies() if policy_provider else []
        sli_data = sli.to_dict() if sli else {}
        return {
            "policies": policies,
            "trustScores": [],
            "sli": sli_data,
            "asiCoverage": _ASI_COVERAGE,
        }

    return app


if __name__ == "__main__":
    import uvicorn
    app = create_sre_app()
    uvicorn.run(app, host="127.0.0.1", port=9377)
