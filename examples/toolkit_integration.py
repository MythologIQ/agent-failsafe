"""End-to-end integration example using LocalFailSafeClient.

Demonstrates three governance scenarios with ring mapping and SLI tracking.
No MCP dependency — uses local policy files and in-memory evaluation.

Usage:
    python examples/toolkit_integration.py
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from agent_failsafe import (
    DecisionRequest,
    FailSafeComplianceSLI,
    LocalFailSafeClient,
)
from agent_failsafe.ring_adapter import FailSafeRingAdapter


def run_scenario(
    client: LocalFailSafeClient,
    adapter: FailSafeRingAdapter,
    sli: FailSafeComplianceSLI,
    label: str,
    request: DecisionRequest,
) -> None:
    """Evaluate a single governance request and print results."""
    response = client.evaluate(request)
    ring = adapter.decision_to_ring(response)
    kill_reason = adapter.decision_to_kill_reason(response)
    sli.record_decision(response)

    print(f"\n--- {label} ---")
    print(f"  Action:     {request.action}")
    print(f"  Artifact:   {request.artifact_path}")
    print(f"  Verdict:    {response.verdict.value}")
    print(f"  Risk Grade: {response.risk_grade.value}")
    print(f"  Allowed:    {response.allowed}")
    print(f"  Ring:       {ring}")
    if kill_reason:
        print(f"  Kill:       {kill_reason}")
    total = len(sli._decisions)
    good = sum(1 for d in sli._decisions if d["allowed"])
    print(f"  SLI Good:   {good} / {total}")


def main() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        config_dir = Path(tmpdir) / "config"
        config_dir.mkdir()
        (config_dir / "policies").mkdir()
        ledger_dir = Path(tmpdir) / "ledger"
        ledger_dir.mkdir()

        client = LocalFailSafeClient(
            config_dir=str(config_dir),
            ledger_path=str(ledger_dir / "ledger.db"),
        )
        adapter = FailSafeRingAdapter()
        sli = FailSafeComplianceSLI()

        # Scenario 1: L1 auto-approve
        run_scenario(client, adapter, sli, "L1: Auto-Approve", DecisionRequest(
            action="checkpoint.create",
            agent_did="did:myth:scrivener:a1b2c3",
            artifact_path="/src/readme.md",
        ))

        # Scenario 2: L2 sentinel warn
        run_scenario(client, adapter, sli, "L2: Sentinel Warn", DecisionRequest(
            action="file.write",
            agent_did="did:myth:scrivener:a1b2c3",
            artifact_path="/src/utils.py",
        ))

        # Scenario 3: L3 human escalate
        run_scenario(client, adapter, sli, "L3: Human Escalate", DecisionRequest(
            action="file.write",
            agent_did="did:myth:scrivener:a1b2c3",
            artifact_path="/src/auth.py",
            payload={"content": "api_key = 'sk-abc123'"},
        ))

        # Summary
        total = len(sli._decisions)
        good = sum(1 for d in sli._decisions if d["allowed"])
        compliance = good / total if total else 0
        print(f"\n=== SLI Summary ===")
        print(f"  Total:      {total}")
        print(f"  Good:       {good}")
        print(f"  Compliance: {compliance:.0%}")


if __name__ == "__main__":
    main()
