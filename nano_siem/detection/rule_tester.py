"""
detection/rule_tester.py — Per-Rule Unit Test Runner

Runs a Sigma rule against explicit test fixtures (positive + negative examples)
to verify it fires when it should and stays silent when it shouldn't.

Fixture format (YAML, lives alongside the rule or in tests/fixtures/):

    title: SSH Brute Force Test Fixtures
    rule: rules/sample/ssh_brute_force.yml
    tests:
      - description: "Should fire: classic failed password"
        should_match: true
        log: '<34>1 2026-06-02T03:00:01Z web-01 sshd - - - Failed password for root from 1.2.3.4'

      - description: "Should NOT fire: successful login"
        should_match: false
        log: '<34>1 2026-06-02T10:00:00Z web-01 sshd - - - Accepted password for deploy from 10.0.0.1'

      - description: "Should fire: invalid user"
        should_match: true
        log: '<34>1 2026-06-02T03:00:01Z web-01 sshd - - - Invalid user hacker from 5.5.5.5'

Run with:
    nano-siem test-rule rules/sample/ssh_brute_force.yml
    nano-siem test-rule rules/  (runs all fixtures in the dir)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from nano_siem.ingestion.normalizer import normalize
from nano_siem.ingestion.parser import parse
from nano_siem.sigma.ast import ASTBuildError, build_ast
from nano_siem.sigma.evaluator import evaluate_rule
from nano_siem.sigma.loader import SigmaLoadError, load_rule


@dataclass
class TestCase:
    description: str
    should_match: bool
    log: str


@dataclass
class TestResult:
    test_case: TestCase
    actually_matched: bool
    elapsed_ms: float
    error: str | None = None

    @property
    def passed(self) -> bool:
        if self.error:
            return False
        return self.actually_matched == self.test_case.should_match

    def status_icon(self) -> str:
        if self.error:
            return "💥"
        return "✓" if self.passed else "✗"

    def __str__(self) -> str:
        icon = self.status_icon()
        expected = "MATCH" if self.test_case.should_match else "NO MATCH"
        got = "MATCH" if self.actually_matched else "NO MATCH"
        result = f"{icon} {self.test_case.description}"
        if not self.passed:
            result += f"\n     Expected: {expected}, Got: {got}"
        if self.error:
            result += f"\n     Error: {self.error}"
        result += f"  ({self.elapsed_ms:.2f}ms)"
        return result


@dataclass
class RuleTestReport:
    rule_path: str
    rule_title: str
    fixture_path: str
    results: list[TestResult] = field(default_factory=list)
    load_error: str | None = None

    @property
    def passed(self) -> bool:
        if self.load_error:
            return False
        return all(r.passed for r in self.results)

    @property
    def pass_count(self) -> int:
        return sum(1 for r in self.results if r.passed)

    @property
    def total(self) -> int:
        return len(self.results)

    def summary(self) -> str:
        if self.load_error:
            return f"✗ LOAD ERROR — {self.rule_title}: {self.load_error}"
        status = "✓ PASS" if self.passed else "✗ FAIL"
        return f"{status} — {self.rule_title} ({self.pass_count}/{self.total} tests passed)"


# ── Fixture discovery ─────────────────────────────────────────────────────────

def _find_fixture(rule_path: Path) -> Path | None:
    """
    Look for a test fixture file for the given rule.
    Search order:
      1. <rule_dir>/<rule_stem>.fixture.yml
      2. tests/fixtures/<rule_stem>.fixture.yml  (relative to project root)
      3. tests/fixtures/<rule_stem>.yml
    """
    stem = rule_path.stem
    candidates = [
        rule_path.parent / f"{stem}.fixture.yml",
        rule_path.parent.parent.parent / "tests" / "fixtures" / f"{stem}.fixture.yml",
        rule_path.parent.parent.parent / "tests" / "fixtures" / f"{stem}.yml",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def _load_fixture(path: Path) -> tuple[str, list[TestCase]]:
    """Load a fixture file, return (rule_path, [TestCase])."""
    with open(path) as f:
        data = yaml.safe_load(f)
    rule_path = data.get("rule", "")
    tests = []
    for raw in data.get("tests", []):
        tests.append(TestCase(
            description=raw.get("description", "unnamed test"),
            should_match=bool(raw.get("should_match", True)),
            log=str(raw.get("log", "")),
        ))
    return rule_path, tests


# ── Runner ────────────────────────────────────────────────────────────────────

def run_rule_tests(
    rule_path: str | Path,
    fixture_path: str | Path | None = None,
) -> RuleTestReport:
    """
    Run all test fixtures for a single rule.

    Args:
        rule_path:    Path to the .yml Sigma rule file.
        fixture_path: Optional explicit path to the fixture file.
                      If None, auto-discovered from rule path.
    """
    rule_path = Path(rule_path)
    report = RuleTestReport(
        rule_path=str(rule_path),
        rule_title=rule_path.stem,
        fixture_path="",
    )

    # Load rule
    try:
        rule = load_rule(rule_path)
        report.rule_title = rule.title
        ast = build_ast(rule.detection, rule_title=rule.title)
    except (SigmaLoadError, ASTBuildError) as e:
        report.load_error = str(e)
        return report

    # Find fixture
    if fixture_path is None:
        fixture_path = _find_fixture(rule_path)
    if fixture_path is None:
        report.load_error = (
            f"No fixture file found for {rule_path.name}. "
            f"Create tests/fixtures/{rule_path.stem}.fixture.yml"
        )
        return report

    report.fixture_path = str(fixture_path)

    # Load test cases
    try:
        _, test_cases = _load_fixture(Path(fixture_path))
    except Exception as e:
        report.load_error = f"Failed to load fixture: {e}"
        return report

    if not test_cases:
        report.load_error = "Fixture file has no test cases"
        return report

    # Run each test case
    for tc in test_cases:
        t0 = time.perf_counter()
        try:
            event = normalize(parse(tc.log))
            match = evaluate_rule(ast, rule, event)
            actually_matched = match is not None
            error = None
        except Exception as e:
            actually_matched = False
            error = str(e)
        elapsed = (time.perf_counter() - t0) * 1000

        report.results.append(TestResult(
            test_case=tc,
            actually_matched=actually_matched,
            elapsed_ms=elapsed,
            error=error,
        ))

    return report


def run_all_rule_tests(rules_dir: str | Path) -> list[RuleTestReport]:
    """
    Run tests for all rules in a directory that have fixture files.
    """
    rules_dir = Path(rules_dir)
    reports = []
    for rule_path in sorted(rules_dir.glob("**/*.yml")):
        fixture = _find_fixture(rule_path)
        if fixture:
            reports.append(run_rule_tests(rule_path, fixture))
    return reports
