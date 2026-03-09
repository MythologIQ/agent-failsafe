"""MCP-based FailSafe client.

Communicates with the FailSafe VS Code extension (or standalone MCP server)
via JSON-RPC over stdio. Implements the FailSafeClient protocol.
"""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path
from typing import Any

from .client import query_shadow_genome
from .types import (
    DecisionRequest,
    DecisionResponse,
    RiskGrade,
    ShadowGenomeEntry,
    VerdictDecision,
)

logger = logging.getLogger(__name__)


class MCPToolError(Exception):
    """Raised when an MCP tool call returns an error."""

    def __init__(self, tool_name: str, message: str) -> None:
        self.tool_name = tool_name
        super().__init__(f"MCP tool '{tool_name}' failed: {message}")


def _verdict_to_response(verdict_dict: dict[str, Any]) -> DecisionResponse:
    """Pure mapping from SentinelVerdict JSON to DecisionResponse.

    No side effects. No network calls. Testable in isolation.
    """
    verdict = VerdictDecision(verdict_dict.get("decision", "PASS"))
    return DecisionResponse(
        allowed=verdict not in (VerdictDecision.BLOCK, VerdictDecision.QUARANTINE),
        nonce=verdict_dict.get("id", ""),
        risk_grade=RiskGrade(verdict_dict.get("riskGrade", "L1")),
        verdict=verdict,
        conditions=verdict_dict.get("matchedPatterns", []),
        reason=verdict_dict.get("summary", ""),
        ledger_entry_id=(
            str(verdict_dict["ledgerEntryId"])
            if verdict_dict.get("ledgerEntryId")
            else None
        ),
    )


class MCPFailSafeClient:
    """FailSafe client that communicates via MCP (JSON-RPC over stdio).

    Spawns the FailSafe MCP server as a subprocess and sends tool calls
    using the Model Context Protocol.
    """

    def __init__(
        self,
        server_command: list[str],
        intent_id: str = "",
        ledger_path: str | Path = ".failsafe/ledger/ledger.db",
        cwd: str = ".",
    ) -> None:
        self._server_command = server_command
        self._intent_id = intent_id
        self._ledger_path = Path(ledger_path)
        self._cwd = cwd
        self._process: subprocess.Popen[bytes] | None = None
        self._request_id = 0

    # ----- MCP Transport -----

    def _call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Send a JSON-RPC tools/call request and return parsed result."""
        self._ensure_connected()
        assert self._process is not None
        assert self._process.stdin is not None
        assert self._process.stdout is not None

        self._request_id += 1
        request = {
            "jsonrpc": "2.0",
            "id": self._request_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }

        self._process.stdin.write(json.dumps(request).encode() + b"\n")
        self._process.stdin.flush()

        line = self._process.stdout.readline()
        if not line:
            raise MCPToolError(name, "No response from MCP server (EOF)")

        response = json.loads(line)
        if "error" in response:
            err = response["error"]
            raise MCPToolError(name, err.get("message", str(err)))

        result = response.get("result", {})
        content = result.get("content", [])
        if content and content[0].get("type") == "text":
            return json.loads(content[0]["text"])
        return result

    # ----- Sentinel Audit (read) -----

    def _audit_file(self, file_path: str, intent_id: str) -> dict[str, Any]:
        """Call sentinel_audit_file MCP tool. Returns raw SentinelVerdict dict."""
        return self._call_tool(
            "sentinel_audit_file",
            {"path": file_path, "intent_id": intent_id},
        )

    # ----- Ledger Logging (write, fire-and-forget) -----

    def _log_decision(
        self, decision: str, rationale: str, risk_grade: str, intent_id: str,
    ) -> None:
        """Call ledger_log_decision MCP tool. Fire-and-forget with error logging."""
        try:
            self._call_tool(
                "ledger_log_decision",
                {
                    "decision": decision,
                    "rationale": rationale,
                    "risk_grade": risk_grade,
                    "intent_id": intent_id,
                },
            )
        except Exception as exc:
            logger.warning("Ledger log failed (non-critical): %s", exc)

    # ----- FailSafeClient Protocol -----

    def evaluate(self, request: DecisionRequest) -> DecisionResponse:
        """Evaluate a governance decision via the FailSafe MCP server."""
        intent_id = self._intent_id or self._fetch_intent_id()

        # Step 1: audit (the read)
        verdict_dict = self._audit_file(request.artifact_path, intent_id)

        # Step 2: map (pure data translation)
        response = _verdict_to_response(verdict_dict)

        # Step 3: log (fire-and-forget write, failure does not affect response)
        if response.risk_grade in (RiskGrade.L2, RiskGrade.L3):
            self._log_decision(
                decision=response.verdict.value,
                rationale=response.reason,
                risk_grade=response.risk_grade.value,
                intent_id=intent_id,
            )

        return response

    def classify_risk(self, file_path: str, content: str = "") -> RiskGrade:
        """Classify risk by calling sentinel_audit_file and extracting riskGrade."""
        intent_id = self._intent_id or self._fetch_intent_id()
        try:
            verdict_dict = self._audit_file(file_path, intent_id)
            return RiskGrade(verdict_dict.get("riskGrade", "L1"))
        except MCPToolError:
            return RiskGrade.L1

    def get_shadow_genome(self, agent_did: str = "") -> list[ShadowGenomeEntry]:
        """Read Shadow Genome from SQLite ledger (no MCP tool for this)."""
        return query_shadow_genome(self._ledger_path, agent_did)

    # ----- Connection Lifecycle -----

    def _ensure_connected(self) -> None:
        """Spawn subprocess if not running. Send MCP initialize handshake."""
        if self._process is not None and self._process.poll() is None:
            return

        try:
            self._process = subprocess.Popen(
                self._server_command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=self._cwd,
            )
        except OSError as exc:
            raise MCPToolError("initialize", f"Failed to start MCP server: {exc}") from exc

        assert self._process.stdin is not None
        assert self._process.stdout is not None

        # Send MCP initialize handshake
        self._request_id += 1
        init_request = {
            "jsonrpc": "2.0",
            "id": self._request_id,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "agent-failsafe", "version": "0.1.0"},
            },
        }
        self._process.stdin.write(json.dumps(init_request).encode() + b"\n")
        self._process.stdin.flush()

        line = self._process.stdout.readline()
        if not line:
            raise MCPToolError("initialize", "MCP server did not respond to initialize")

        response = json.loads(line)
        if "error" in response:
            raise MCPToolError("initialize", response["error"].get("message", "init failed"))

    def _fetch_intent_id(self) -> str:
        """Call qorelogic_status, extract active_intent. Cache result."""
        status = self._call_tool("qorelogic_status", {})
        intent_id = status.get("active_intent", "")
        if intent_id:
            self._intent_id = intent_id
        return intent_id

    def close(self) -> None:
        """Send stdin EOF, wait for process exit, clean up."""
        if self._process is None:
            return

        try:
            if self._process.stdin:
                self._process.stdin.close()
            self._process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.wait()
        finally:
            self._process = None
