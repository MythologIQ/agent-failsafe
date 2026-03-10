"""End-to-end integration example using FailSafeKernel with all backends.

Demonstrates three governance scenarios with SLI, audit sink, and ring mapping
wired through the kernel's single callback dispatch.

Usage:
    python examples/toolkit_integration.py
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from agent_failsafe import (
    DecisionRequest,
    FailSafeAuditSink,
    FailSafeComplianceSLI,
    FailSafeKernel,
    LocalFailSafeClient,
)
from agent_failsafe.ring_adapter import FailSafeRingAdapter


def run_scenario(
    kernel: FailSafeKernel,
    adapter: FailSafeRingAdapter,
    label: str,
    request: DecisionRequest,
) -> None:
    """Evaluate a single governance request and print results."""
    response = kernel.fs_client.evaluate(request)
    ring = adapter.decision_to_ring(response)
    kill_reason = adapter.decision_to_kill_reason(response)

    # Manually fire the kernel callback so backends see this decision
    if kernel.interceptor.on_decision is not None:
        kernel.interceptor.on_decision(request, response)

    print(f"\n--- {label} ---")
    print(f"  Action:     {request.action}")
    print(f"  Artifact:   {request.artifact_path}")
    print(f"  Verdict:    {response.verdict.value}")
    print(f"  Risk Grade: {response.risk_grade.value}")
    print(f"  Allowed:    {response.allowed}")
    print(f"  Ring:       {ring}")
    if kill_reason:
        print(f"  Kill:       {kill_reason}")


def main() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        config_dir = Path(tmpdir) / "config"
        config_dir.mkdir()
        (config_dir / "policies").mkdir()
        ledger_dir = Path(tmpdir) / "ledger"
        ledger_dir.mkdir()
        audit_path = Path(tmpdir) / "audit" / "audit.db"

        client = LocalFailSafeClient(
            config_dir=str(config_dir),
            ledger_path=str(ledger_dir / "ledger.db"),
        )
        sli = FailSafeComplianceSLI(target=0.95)
        audit_sink = FailSafeAuditSink(ledger_path=audit_path)
        adapter = FailSafeRingAdapter()

        # Single kernel entry point — SLI and audit happen automatically
        kernel = FailSafeKernel(
            client=client,
            sli=sli,
            audit_sink=audit_sink,
        )

        # Scenario 1: L1 auto-approve
        run_scenario(kernel, adapter, "L1: Auto-Approve", DecisionRequest(
            action="checkpoint.create",
            agent_did="did:myth:scrivener:a1b2c3",
            artifact_path="/src/readme.md",
        ))

        # Scenario 2: L2 sentinel warn
        run_scenario(kernel, adapter, "L2: Sentinel Warn", DecisionRequest(
            action="file.write",
            agent_did="did:myth:scrivener:a1b2c3",
            artifact_path="/src/utils.py",
        ))

        # Scenario 3: L3 human escalate
        run_scenario(kernel, adapter, "L3: Human Escalate", DecisionRequest(
            action="file.write",
            agent_did="did:myth:scrivener:a1b2c3",
            artifact_path="/src/auth.py",
            payload={"content": "api_key = 'sk-abc123'"},
        ))

        # SLI Summary
        sli_data = sli.to_dict()
        print(f"\n=== SLI Summary ===")
        print(f"  Total:      {sli_data['total_decisions']}")
        print(f"  Compliance: {sli_data['current_value']:.0%}" if sli_data["current_value"] else "  Compliance: N/A")

        # Audit chain integrity
        valid, error = audit_sink.verify_integrity()
        print(f"\n=== Audit Chain ===")
        print(f"  Valid: {valid}")
        if error:
            print(f"  Error: {error}")


if __name__ == "__main__":
    main()
