"""Tests for heuristic pattern matching and risk classification."""

from __future__ import annotations

import re

import pytest

from agent_failsafe.patterns import (
    DEFAULT_PATTERNS,
    HeuristicPattern,
    PatternCategory,
    PatternMatch,
    PatternSeverity,
    classify_risk,
    match_content,
)
from agent_failsafe.types import RiskGrade


# ---------------------------------------------------------------------------
# TestPatternCategory
# ---------------------------------------------------------------------------


class TestPatternCategory:
    """Tests for the PatternCategory enum."""

    def test_has_all_ten_members(self) -> None:
        expected = {
            "injection", "auth", "crypto", "secrets", "pii",
            "resource", "logic", "complexity", "existence", "dependency",
        }
        assert {m.value for m in PatternCategory} == expected


# ---------------------------------------------------------------------------
# TestHeuristicPattern
# ---------------------------------------------------------------------------


class TestHeuristicPattern:
    """Tests for the HeuristicPattern frozen dataclass."""

    def test_frozen_immutability(self) -> None:
        p = DEFAULT_PATTERNS[0]
        with pytest.raises(AttributeError):
            p.id = "CHANGED"  # type: ignore[misc]

    def test_all_fields_present(self) -> None:
        p = DEFAULT_PATTERNS[0]
        assert p.id
        assert p.name
        assert isinstance(p.category, PatternCategory)
        assert isinstance(p.severity, PatternSeverity)
        assert p.cwe
        assert p.pattern
        assert p.description
        assert p.remediation


# ---------------------------------------------------------------------------
# TestDefaultPatterns
# ---------------------------------------------------------------------------


class TestDefaultPatterns:
    """Tests for the DEFAULT_PATTERNS constant."""

    def test_all_patterns_compile(self) -> None:
        for p in DEFAULT_PATTERNS:
            compiled = re.compile(p.pattern)
            assert compiled is not None, f"Pattern {p.id} failed to compile"

    def test_all_have_cwe_refs(self) -> None:
        for p in DEFAULT_PATTERNS:
            assert p.cwe.startswith("CWE-"), f"Pattern {p.id} has invalid CWE: {p.cwe}"


# ---------------------------------------------------------------------------
# TestMatchContent
# ---------------------------------------------------------------------------


class TestMatchContent:
    """Tests for the match_content function."""

    def test_sql_injection_match(self) -> None:
        code = 'cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)'
        matches = match_content(code)
        assert len(matches) >= 1
        ids = {m.pattern.id for m in matches}
        assert "INJ001" in ids

    def test_command_injection_match(self) -> None:
        code = "os.system(cmd)"
        matches = match_content(code)
        assert len(matches) >= 1
        ids = {m.pattern.id for m in matches}
        assert "INJ002" in ids

    def test_hardcoded_secret_match(self) -> None:
        code = 'api_key = "skliveabc123def456ghi"'
        matches = match_content(code)
        assert len(matches) >= 1
        ids = {m.pattern.id for m in matches}
        assert "SEC001" in ids

    def test_pii_ssn_match(self) -> None:
        code = 'ssn = "123-45-6789"'
        matches = match_content(code)
        assert len(matches) >= 1
        ids = {m.pattern.id for m in matches}
        assert "PII001" in ids

    def test_pii_credit_card_match(self) -> None:
        code = 'card = "4111-1111-1111-1111"'
        matches = match_content(code)
        assert len(matches) >= 1
        ids = {m.pattern.id for m in matches}
        assert "PII002" in ids

    def test_no_match_on_clean_code(self) -> None:
        code = "x = 1 + 2"
        matches = match_content(code)
        assert matches == []

    def test_multiple_matches_sorted_by_severity(self) -> None:
        code = (
            'os.system(cmd)\n'
            'api_key = "skliveabc123def456ghi"\n'
            'md5(data)\n'
        )
        matches = match_content(code)
        assert len(matches) >= 3
        severities = [m.pattern.severity for m in matches]
        # Critical should come before high, high before medium
        assert severities.index(PatternSeverity.CRITICAL) < severities.index(PatternSeverity.HIGH)
        assert severities.index(PatternSeverity.HIGH) < severities.index(PatternSeverity.MEDIUM)


# ---------------------------------------------------------------------------
# TestClassifyRisk
# ---------------------------------------------------------------------------


class TestClassifyRisk:
    """Tests for the classify_risk function."""

    def test_l3_from_path_trigger(self) -> None:
        assert classify_risk("/src/auth.py") == RiskGrade.L3

    def test_l3_from_content_trigger(self) -> None:
        assert classify_risk("/readme.txt", content="CREATE TABLE users") == RiskGrade.L3

    def test_l3_from_extra_triggers(self) -> None:
        grade = classify_risk(
            "/src/utils.txt",
            content="handle billing logic",
            extra_l3_triggers=frozenset({"billing"}),
        )
        assert grade == RiskGrade.L3

    def test_l2_from_code_extension(self) -> None:
        assert classify_risk("/src/utils.py") == RiskGrade.L2

    def test_l1_from_clean_text(self) -> None:
        assert classify_risk("/readme.txt") == RiskGrade.L1
