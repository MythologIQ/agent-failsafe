"""Heuristic pattern matching and risk classification."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Sequence

from .types import RiskGrade


class PatternCategory(str, Enum):
    """Categories of heuristic security patterns."""
    INJECTION = "injection"
    AUTH = "auth"
    CRYPTO = "crypto"
    SECRETS = "secrets"
    PII = "pii"
    RESOURCE = "resource"
    LOGIC = "logic"
    COMPLEXITY = "complexity"
    EXISTENCE = "existence"
    DEPENDENCY = "dependency"


class PatternSeverity(str, Enum):
    """Severity levels for pattern matches."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True)
class HeuristicPattern:
    """A single CWE-referenced heuristic pattern definition."""
    id: str
    name: str
    category: PatternCategory
    severity: PatternSeverity
    cwe: str
    pattern: str
    description: str
    remediation: str


@dataclass(frozen=True)
class PatternMatch:
    """Result of a pattern match against a line of content."""
    pattern: HeuristicPattern
    line_number: int
    matched_text: str

DEFAULT_PATTERNS: tuple[HeuristicPattern, ...] = (
    HeuristicPattern(
        id="INJ001", name="SQL Injection Risk",
        category=PatternCategory.INJECTION, severity=PatternSeverity.CRITICAL,
        cwe="CWE-89",
        pattern=r"execute\s*\(.*%[sd]|cursor\.\w+\(.*%[sd]|f['\"].*(?:SELECT|INSERT|UPDATE|DELETE)",
        description="String formatting in SQL query may allow injection.",
        remediation="Use parameterized queries with placeholders.",
    ),
    HeuristicPattern(
        id="INJ002", name="Command Injection Risk",
        category=PatternCategory.INJECTION, severity=PatternSeverity.CRITICAL,
        cwe="CWE-78",
        pattern=r"os\.system\(|subprocess\.call\(.*shell\s*=\s*True",
        description="Shell command execution with potential user input.",
        remediation="Use subprocess with shell=False and explicit argument lists.",
    ),
    HeuristicPattern(
        id="SEC001", name="Hardcoded API Key",
        category=PatternCategory.SECRETS, severity=PatternSeverity.HIGH,
        cwe="CWE-798",
        pattern=r"(?i)api[_-]?key\s*=\s*['\"][A-Za-z0-9]{16,}",
        description="API key appears to be hardcoded in source.",
        remediation="Use environment variables or a secrets manager.",
    ),
    HeuristicPattern(
        id="SEC002", name="Hardcoded Password",
        category=PatternCategory.SECRETS, severity=PatternSeverity.HIGH,
        cwe="CWE-798",
        pattern=r"(?i)password\s*=\s*['\"][^'\"]+['\"]",
        description="Password appears to be hardcoded in source.",
        remediation="Use environment variables or a secrets manager.",
    ),
    HeuristicPattern(
        id="PII001", name="SSN Pattern",
        category=PatternCategory.PII, severity=PatternSeverity.HIGH,
        cwe="CWE-359",
        pattern=r"\b\d{3}-\d{2}-\d{4}\b",
        description="Content may contain a Social Security Number.",
        remediation="Remove or mask PII before storage or transmission.",
    ),
    HeuristicPattern(
        id="PII002", name="Credit Card Pattern",
        category=PatternCategory.PII, severity=PatternSeverity.HIGH,
        cwe="CWE-359",
        pattern=r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",
        description="Content may contain a credit card number.",
        remediation="Remove or mask PII before storage or transmission.",
    ),
    HeuristicPattern(
        id="CMP001", name="Deep Nesting",
        category=PatternCategory.COMPLEXITY, severity=PatternSeverity.MEDIUM,
        cwe="CWE-1121",
        pattern=r"^\s{16,}\S",
        description="Deeply nested code reduces readability and maintainability.",
        remediation="Refactor to reduce nesting depth.",
    ),
    HeuristicPattern(
        id="CRY001", name="Weak Hash Algorithm",
        category=PatternCategory.CRYPTO, severity=PatternSeverity.MEDIUM,
        cwe="CWE-328",
        pattern=r"(?i)\b(?:md5|sha1)\s*\(",
        description="Weak hash algorithm is not collision-resistant.",
        remediation="Use SHA-256 or stronger hash algorithms.",
    ),
    HeuristicPattern(
        id="AUTH001", name="Basic Auth Header",
        category=PatternCategory.AUTH, severity=PatternSeverity.MEDIUM,
        cwe="CWE-522",
        pattern=r"(?i)Authorization.*Basic",
        description="Basic authentication transmits credentials in base64.",
        remediation="Use token-based or certificate-based authentication.",
    ),
    HeuristicPattern(
        id="DEP001", name="Pinned Dependency Version",
        category=PatternCategory.DEPENDENCY, severity=PatternSeverity.LOW,
        cwe="CWE-1104",
        pattern=r"==\d+\.\d+",
        description="Pinned dependency may miss security patches.",
        remediation="Use compatible-release specifiers (~=) or version ranges.",
    ),
)

_L3_CONTENT_TRIGGERS: frozenset[str] = frozenset({
    "create table", "drop table", "alter table", "authenticate",
    "bcrypt", "aes", "rsa", "private_key",
})

_L3_PATH_TRIGGERS: frozenset[str] = frozenset({
    "auth", "login", "crypto", "payment", "private_key",
    "password", "api_key", "secret", "credential", "token",
})

_SEVERITY_ORDER: dict[PatternSeverity, int] = {
    PatternSeverity.CRITICAL: 0,
    PatternSeverity.HIGH: 1,
    PatternSeverity.MEDIUM: 2,
    PatternSeverity.LOW: 3,
}


def match_content(
    content: str,
    patterns: Sequence[HeuristicPattern] | None = None,
) -> list[PatternMatch]:
    """Scan content lines against heuristic patterns, sorted by severity."""
    active = patterns if patterns is not None else DEFAULT_PATTERNS
    compiled = [(p, re.compile(p.pattern)) for p in active]
    matches: list[PatternMatch] = []

    for line_number, line in enumerate(content.splitlines(), start=1):
        for pat, regex in compiled:
            m = regex.search(line)
            if m:
                matches.append(PatternMatch(
                    pattern=pat,
                    line_number=line_number,
                    matched_text=m.group(),
                ))

    matches.sort(key=lambda pm: _SEVERITY_ORDER.get(pm.pattern.severity, 9))
    return matches


def classify_risk(
    file_path: str,
    content: str = "",
    extra_l3_triggers: frozenset[str] | None = None,
) -> RiskGrade:
    """Classify risk grade from path, content, and pattern signals."""
    path_triggers = _L3_PATH_TRIGGERS | extra_l3_triggers if extra_l3_triggers else _L3_PATH_TRIGGERS
    path_lower = file_path.lower()

    if any(trigger in path_lower for trigger in path_triggers):
        return RiskGrade.L3

    content_lower = content.lower()
    if any(trigger in content_lower for trigger in _L3_CONTENT_TRIGGERS):
        return RiskGrade.L3

    if extra_l3_triggers and any(trigger in content_lower for trigger in extra_l3_triggers):
        return RiskGrade.L3

    if content:
        matches = match_content(content)
        severities = {m.pattern.severity for m in matches}
        if PatternSeverity.CRITICAL in severities:
            return RiskGrade.L3
        if PatternSeverity.HIGH in severities:
            return RiskGrade.L2

    if any(path_lower.endswith(ext) for ext in (".py", ".js", ".ts", ".rs")):
        return RiskGrade.L2

    return RiskGrade.L1
