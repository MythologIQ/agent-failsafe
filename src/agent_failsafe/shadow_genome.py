"""Shadow Genome store, classifier, and constraint generator.

Records agent failure modes as negative constraints that prevent repeated
mistakes across sessions.  Thread-safe in-memory store with FIFO eviction.
"""

from __future__ import annotations

import threading
from collections import deque
from enum import Enum
from typing import Protocol, Sequence

from .types import FailureMode, ShadowGenomeEntry


# ---------------------------------------------------------------------------
# Remediation lifecycle
# ---------------------------------------------------------------------------


class RemediationStatus(str, Enum):
    """Lifecycle status for a Shadow Genome entry."""

    UNRESOLVED = "UNRESOLVED"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"
    WONT_FIX = "WONT_FIX"
    SUPERSEDED = "SUPERSEDED"


# ---------------------------------------------------------------------------
# Store protocol
# ---------------------------------------------------------------------------


class ShadowGenomeStore(Protocol):
    """Abstract store for Shadow Genome entries."""

    def record(self, entry: ShadowGenomeEntry) -> None:
        """Persist a new failure-mode entry."""
        ...

    def query(
        self,
        agent_did: str | None = None,
        failure_mode: FailureMode | None = None,
        status: str | None = None,
        limit: int = 50,
    ) -> Sequence[ShadowGenomeEntry]:
        """Return entries matching all supplied filters, newest first."""
        ...


# ---------------------------------------------------------------------------
# In-memory implementation
# ---------------------------------------------------------------------------


class InMemoryShadowGenomeStore:
    """Thread-safe in-memory Shadow Genome store with FIFO eviction.

    Args:
        max_entries: Maximum entries before oldest are evicted.
    """

    def __init__(self, max_entries: int = 10_000) -> None:
        self._entries: deque[ShadowGenomeEntry] = deque(maxlen=max_entries)
        self._lock = threading.Lock()

    def record(self, entry: ShadowGenomeEntry) -> None:
        """Append an entry, evicting the oldest if at capacity."""
        with self._lock:
            self._entries.append(entry)

    def query(
        self,
        agent_did: str | None = None,
        failure_mode: FailureMode | None = None,
        status: str | None = None,
        limit: int = 50,
    ) -> Sequence[ShadowGenomeEntry]:
        """Filter entries by compound AND of all supplied params, newest first."""
        with self._lock:
            results = list(self._entries)

        if agent_did is not None:
            results = [e for e in results if e.agent_did == agent_did]
        if failure_mode is not None:
            results = [e for e in results if e.failure_mode == failure_mode]
        if status is not None:
            results = [e for e in results if e.remediation_status == status]

        results.reverse()
        return results[:limit]


# ---------------------------------------------------------------------------
# Failure-mode classifier
# ---------------------------------------------------------------------------

_KEYWORD_MAP: list[tuple[tuple[str, ...], FailureMode]] = [
    (("injection", "command"), FailureMode.INJECTION_VULNERABILITY),
    (("secret", "credential", "api_key"), FailureMode.SECRET_EXPOSURE),
    (("pii", "ssn", "credit_card"), FailureMode.PII_LEAK),
    (("complexity", "nesting"), FailureMode.HIGH_COMPLEXITY),
    (("trust", "violation"), FailureMode.TRUST_VIOLATION),
    (("dependency",), FailureMode.DEPENDENCY_CONFLICT),
    (("spec", "drift"), FailureMode.SPEC_VIOLATION),
    (("hallucination",), FailureMode.HALLUCINATION),
    (("logic",), FailureMode.LOGIC_ERROR),
]


def classify_failure_mode(
    matched_patterns: Sequence[str],
    risk_grade: str,
    reason: str,
) -> FailureMode:
    """Classify a failure mode from sentinel output via keyword dispatch.

    Scans the combined text of *matched_patterns* and *reason* for known
    keywords and returns the first matching ``FailureMode``.  Falls back
    to ``FailureMode.OTHER`` when no keyword matches.

    Args:
        matched_patterns: Pattern identifiers from heuristic checks.
        risk_grade: Risk grade string (currently unused, reserved).
        reason: Free-text explanation from the sentinel.

    Returns:
        The best-matching ``FailureMode`` enum member.
    """
    combined = " ".join(matched_patterns).lower() + " " + reason.lower()
    for keywords, mode in _KEYWORD_MAP:
        for kw in keywords:
            if kw in combined:
                return mode
    return FailureMode.OTHER


# ---------------------------------------------------------------------------
# Negative-constraint generator
# ---------------------------------------------------------------------------

_CONSTRAINT_TEMPLATES: dict[FailureMode, str] = {
    FailureMode.INJECTION_VULNERABILITY: (
        "AVOID: Unsanitised user input reaching shell/eval in {fp}. "
        "REQUIRE: Input validation and parameterised commands."
    ),
    FailureMode.SECRET_EXPOSURE: (
        "AVOID: Hard-coded secrets or credentials in {fp}. "
        "REQUIRE: Environment variables or a secrets manager."
    ),
    FailureMode.PII_LEAK: (
        "AVOID: Logging or transmitting PII from {fp}. "
        "REQUIRE: Redaction before any external output."
    ),
    FailureMode.HIGH_COMPLEXITY: (
        "AVOID: Deeply nested or high-cyclomatic-complexity code in {fp}. "
        "REQUIRE: Extract helper functions, max 3 nesting levels."
    ),
    FailureMode.TRUST_VIOLATION: (
        "AVOID: Bypassing trust checks in {fp}. "
        "REQUIRE: Full trust-score validation before delegation."
    ),
    FailureMode.DEPENDENCY_CONFLICT: (
        "AVOID: Conflicting or undeclared dependencies in {fp}. "
        "REQUIRE: Pin versions and verify compatibility."
    ),
    FailureMode.SPEC_VIOLATION: (
        "AVOID: Deviating from the agreed specification in {fp}. "
        "REQUIRE: Contract tests covering the spec surface."
    ),
    FailureMode.HALLUCINATION: (
        "AVOID: Generating unverified claims or fabricated data in {fp}. "
        "REQUIRE: Source verification and citation."
    ),
    FailureMode.LOGIC_ERROR: (
        "AVOID: Incorrect boolean/branching logic in {fp}. "
        "REQUIRE: Unit tests for all branches."
    ),
    FailureMode.OTHER: (
        "AVOID: Repeating the unclassified failure observed in {fp}. "
        "REQUIRE: Manual review and targeted tests."
    ),
}


def generate_negative_constraint(
    failure_mode: FailureMode,
    file_path: str,
    description: str,
) -> str:
    """Build an AVOID/REQUIRE constraint string for a failure mode.

    Args:
        failure_mode: The classified failure mode.
        file_path: Path of the artifact that exhibited the failure.
        description: Human-readable description (reserved for future use).

    Returns:
        A constraint string containing AVOID and REQUIRE directives.
    """
    template = _CONSTRAINT_TEMPLATES.get(
        failure_mode, _CONSTRAINT_TEMPLATES[FailureMode.OTHER]
    )
    return template.format(fp=file_path)


# ---------------------------------------------------------------------------
# Agent constraint retrieval
# ---------------------------------------------------------------------------


def get_constraints_for_agent(
    store: ShadowGenomeStore,
    agent_did: str,
    limit: int = 10,
) -> list[str]:
    """Retrieve negative constraints applicable to a specific agent.

    Args:
        store: A ``ShadowGenomeStore`` implementation.
        agent_did: The DID of the agent to query.
        limit: Maximum number of constraints to return.

    Returns:
        List of constraint strings, newest first.
    """
    entries = store.query(agent_did=agent_did, limit=limit)
    return [e.negative_constraint for e in entries]
