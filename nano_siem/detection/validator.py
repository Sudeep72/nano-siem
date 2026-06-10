"""
detection/validator.py — Sigma Rule Validator

Validates a Sigma rule file beyond basic schema checking.
Catches real authoring mistakes before rules reach production:

Checks performed:
  1. Schema      — required fields, valid level/status values
  2. Syntax      — condition parses without error
  3. AST         — all condition references point to defined groups
  4. Logic       — detection block has at least one matcher
  5. Completeness — description, author, tags, falsepositives present
  6. MITRE       — tags follow attack.tXXXX format and are known techniques
  7. Test fixture — rule has an associated test fixture file (optional, warned)

Each check produces a ValidationResult with severity: ERROR | WARNING | INFO
ERRORs block the rule from loading. WARNINGs are advisory.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from nano_siem.sigma.loader import SigmaRule, load_rule, SigmaLoadError
from nano_siem.sigma.ast import build_ast, ASTBuildError
from nano_siem.detection.mitre import lookup as mitre_lookup


class Severity(str, Enum):
    ERROR   = "ERROR"
    WARNING = "WARNING"
    INFO    = "INFO"


@dataclass
class ValidationResult:
    severity: Severity
    check: str          # which check produced this result
    message: str

    def __str__(self) -> str:
        return f"[{self.severity.value:<7}] {self.check:<20} {self.message}"


@dataclass
class RuleValidationReport:
    path: str
    rule_title: str
    results: list[ValidationResult] = field(default_factory=list)

    @property
    def errors(self) -> list[ValidationResult]:
        return [r for r in self.results if r.severity == Severity.ERROR]

    @property
    def warnings(self) -> list[ValidationResult]:
        return [r for r in self.results if r.severity == Severity.WARNING]

    @property
    def passed(self) -> bool:
        return len(self.errors) == 0

    def summary(self) -> str:
        status = "✓ PASS" if self.passed else "✗ FAIL"
        return (
            f"{status} — {self.rule_title} "
            f"({len(self.errors)} errors, {len(self.warnings)} warnings)"
        )


# ── Individual checks ─────────────────────────────────────────────────────────

def _check_completeness(rule: SigmaRule) -> list[ValidationResult]:
    results = []
    if not rule.description or len(rule.description) < 20:
        results.append(ValidationResult(
            Severity.WARNING, "completeness",
            "description is missing or too short (< 20 chars) — add a meaningful description",
        ))
    if not rule.author:
        results.append(ValidationResult(
            Severity.WARNING, "completeness",
            "author field is missing",
        ))
    if not rule.tags:
        results.append(ValidationResult(
            Severity.WARNING, "completeness",
            "no tags — add at least one attack.tXXXX MITRE ATT&CK tag",
        ))
    if not rule.falsepositives:
        results.append(ValidationResult(
            Severity.WARNING, "completeness",
            "falsepositives field is missing — document known benign triggers",
        ))
    if not rule.id:
        results.append(ValidationResult(
            Severity.WARNING, "completeness",
            "id field is missing — add a UUID v4 for stable rule identification",
        ))
    return results


def _check_mitre_tags(rule: SigmaRule) -> list[ValidationResult]:
    results = []
    attack_tags = [t for t in rule.tags if t.lower().startswith("attack.")]
    if not attack_tags:
        results.append(ValidationResult(
            Severity.WARNING, "mitre",
            "no attack.tXXXX tags — map this rule to at least one MITRE ATT&CK technique",
        ))
        return results

    for tag in attack_tags:
        # Skip tactic tags like "attack.credential_access"
        if not any(c.isdigit() for c in tag):
            continue
        tech = mitre_lookup(tag)
        if tech is None:
            results.append(ValidationResult(
                Severity.WARNING, "mitre",
                f"unknown technique tag '{tag}' — verify against https://attack.mitre.org",
            ))
        else:
            results.append(ValidationResult(
                Severity.INFO, "mitre",
                f"mapped to {tech.display_name} [{tech.tactic}]",
            ))
    return results


def _check_ast(rule: SigmaRule) -> list[ValidationResult]:
    results = []
    try:
        ast = build_ast(rule.detection, rule_title=rule.title)
        # Check all groups have at least one matcher
        for name, group in ast.groups.items():
            if not group.matchers:
                results.append(ValidationResult(
                    Severity.ERROR, "ast",
                    f"detection group '{name}' has no matchers",
                ))
        # Condition references
        condition = rule.detection.get("condition", "")
        for word in condition.replace("(", " ").replace(")", " ").split():
            if word.lower() in ("and", "or", "not", "1", "of", "all", "them"):
                continue
            if "*" in word:
                continue  # glob selector
            if word not in ast.groups:
                results.append(ValidationResult(
                    Severity.ERROR, "ast",
                    f"condition references undefined group '{word}'",
                ))
    except ASTBuildError as e:
        results.append(ValidationResult(
            Severity.ERROR, "ast",
            f"condition parse error: {e}",
        ))
    return results


def _check_detection_logic(rule: SigmaRule) -> list[ValidationResult]:
    results = []
    detection = rule.detection
    groups = {k: v for k, v in detection.items() if k != "condition"}
    if not groups:
        results.append(ValidationResult(
            Severity.ERROR, "logic",
            "detection block has no search groups (only 'condition' key found)",
        ))
        return results

    # Warn about empty keyword lists
    for name, value in groups.items():
        if isinstance(value, list) and len(value) == 0:
            results.append(ValidationResult(
                Severity.ERROR, "logic",
                f"group '{name}' is an empty list — add at least one keyword",
            ))
        if isinstance(value, dict) and len(value) == 0:
            results.append(ValidationResult(
                Severity.ERROR, "logic",
                f"group '{name}' is an empty dict — add field matchers",
            ))

    return results


def _check_test_fixture(rule: SigmaRule) -> list[ValidationResult]:
    """Warn if no test fixture exists for this rule."""
    results = []
    rule_path = Path(rule.source_file)
    rule_stem = rule_path.stem  # filename without .yml
    fixtures_dir = rule_path.parent.parent.parent / "tests" / "fixtures"
    expected = fixtures_dir / f"{rule_stem}.log"
    if not expected.exists():
        results.append(ValidationResult(
            Severity.WARNING, "test_fixture",
            f"no test fixture found at tests/fixtures/{rule_stem}.log — "
            "add a sample log line to verify this rule fires correctly",
        ))
    return results


# ── Public API ────────────────────────────────────────────────────────────────

def validate_rule(path: str | Path) -> RuleValidationReport:
    """
    Validate a single Sigma rule file.
    Returns a RuleValidationReport with all findings.
    """
    path = Path(path)
    report = RuleValidationReport(path=str(path), rule_title=str(path.name))

    # Step 1: load (schema + YAML validation)
    try:
        rule = load_rule(path)
        report.rule_title = rule.title
    except SigmaLoadError as e:
        report.results.append(ValidationResult(
            Severity.ERROR, "schema", str(e)
        ))
        return report

    # Step 2: run all checks
    report.results.extend(_check_completeness(rule))
    report.results.extend(_check_mitre_tags(rule))
    report.results.extend(_check_ast(rule))
    report.results.extend(_check_detection_logic(rule))
    report.results.extend(_check_test_fixture(rule))

    return report


def validate_rules_dir(directory: str | Path) -> list[RuleValidationReport]:
    """Validate all .yml rule files in a directory (recursive)."""
    directory = Path(directory)
    reports = []
    for path in sorted(directory.glob("**/*.yml")):
        reports.append(validate_rule(path))
    return reports
