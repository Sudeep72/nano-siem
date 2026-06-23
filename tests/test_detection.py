"""
test_detection.py — Tests for v2.0 detection engineering components

Covers:
  - MITRE ATT&CK registry (lookup, techniques_for_tags, coverage_summary)
  - Rule validator (schema, AST, MITRE, completeness, logic checks)
  - Rule tester (fixture loading, positive/negative cases, reporting)
  - Coverage reporter (report building, to_dict, to_markdown, to_json)
"""

import pytest
import tempfile
import os
from pathlib import Path

from nano_siem.detection.mitre import (
    lookup, techniques_for_tags, coverage_summary, REGISTRY, Technique,
)
from nano_siem.detection.validator import (
    validate_rule, validate_rules_dir, Severity, RuleValidationReport,
)
from nano_siem.detection.rule_tester import (
    run_rule_tests, run_all_rule_tests, RuleTestReport,
)
from nano_siem.detection.coverage import build_coverage_report, CoverageReport


# ── Helpers ────────────────────────────────────────────────────────────────────

VALID_RULE = """
title: Test SSH Brute Force
id: test-uuid-0001
status: stable
level: high
description: Detects repeated failed SSH authentication attempts from a single source.
author: TestAuthor
tags:
  - attack.credential_access
  - attack.t1110.001
logsource:
  product: linux
  service: sshd
detection:
  keywords:
    - 'Failed password'
    - 'Invalid user'
  condition: keywords
falsepositives:
  - Legitimate users mistyping passwords
"""

MINIMAL_RULE = """
title: Minimal Rule
status: stable
level: medium
logsource:
  product: linux
detection:
  keywords:
    - 'test'
  condition: keywords
"""

BAD_CONDITION_RULE = """
title: Bad Condition
id: test-uuid-0002
status: stable
level: medium
description: A rule with a condition that references an undefined group.
author: Test
tags:
  - attack.t1110
logsource:
  product: linux
detection:
  keywords:
    - 'test'
  condition: keywords and nonexistent_group
falsepositives:
  - None
"""

EMPTY_GROUP_RULE = """
title: Empty Group
id: test-uuid-0003
status: stable
level: medium
description: A rule with an empty detection group.
author: Test
tags:
  - attack.t1110
logsource:
  product: linux
detection:
  keywords: []
  condition: keywords
falsepositives:
  - None
"""


def write_rule(tmp_path: Path, name: str, content: str) -> Path:
    path = tmp_path / name
    path.write_text(content)
    return path


def write_fixture(tmp_path: Path, name: str, rule_path: str, tests: list) -> Path:
    import yaml
    content = {"title": f"{name} fixtures", "rule": rule_path, "tests": tests}
    path = tmp_path / name
    path.write_text(yaml.dump(content))
    return path


# ── MITRE Registry Tests ──────────────────────────────────────────────────────

class TestMITRERegistry:
    def test_lookup_known_technique(self):
        t = lookup("T1110")
        assert t is not None
        assert t.name == "Brute Force"
        assert t.tactic == "Credential Access"

    def test_lookup_subtechnique(self):
        t = lookup("T1110.001")
        assert t is not None
        assert t.name == "Password Guessing"
        assert t.is_subtechnique is True

    def test_lookup_case_insensitive(self):
        assert lookup("t1110") is not None
        assert lookup("T1110") is not None
        assert lookup("t1110.001") is not None

    def test_lookup_with_attack_prefix(self):
        t = lookup("attack.t1110.001")
        assert t is not None
        assert t.name == "Password Guessing"

    def test_lookup_unknown_returns_none(self):
        assert lookup("T9999") is None
        assert lookup("") is None
        assert lookup("notareal.technique") is None

    def test_technique_has_url(self):
        t = lookup("T1110")
        assert t is not None
        assert "attack.mitre.org" in t.url

    def test_technique_full_id_parent(self):
        t = lookup("T1110")
        assert t.full_id == "T1110"

    def test_technique_full_id_sub(self):
        t = lookup("T1110.001")
        assert t.full_id == "T1110.001"

    def test_display_name_format(self):
        t = lookup("T1110")
        assert "T1110" in t.display_name
        assert "Brute Force" in t.display_name

    def test_techniques_for_tags_extracts_known(self):
        tags = ["attack.credential_access", "attack.t1110", "attack.t1110.001"]
        techs = techniques_for_tags(tags)
        ids = [t.full_id for t in techs]
        assert "T1110" in ids
        assert "T1110.001" in ids

    def test_techniques_for_tags_skips_unknown(self):
        tags = ["attack.t9999", "attack.t1110"]
        techs = techniques_for_tags(tags)
        assert len(techs) == 1
        assert techs[0].full_id == "T1110"

    def test_techniques_for_tags_no_duplicates(self):
        tags = ["attack.t1110", "attack.t1110"]
        techs = techniques_for_tags(tags)
        assert len(techs) == 1

    def test_registry_not_empty(self):
        assert len(REGISTRY) > 10

    def test_coverage_summary(self):
        from nano_siem.sigma.loader import load_rules_dir
        rules = load_rules_dir("rules/")
        summary = coverage_summary(rules)
        assert isinstance(summary, dict)
        # Should have at least one tactic covered by our rules
        assert len(summary) > 0


# ── Validator Tests ───────────────────────────────────────────────────────────

class TestValidator:
    def test_valid_rule_passes(self, tmp_path):
        path = write_rule(tmp_path, "rule.yml", VALID_RULE)
        report = validate_rule(path)
        assert report.passed
        assert len(report.errors) == 0

    def test_minimal_rule_has_warnings(self, tmp_path):
        path = write_rule(tmp_path, "rule.yml", MINIMAL_RULE)
        report = validate_rule(path)
        # Minimal rule passes (no errors) but has warnings
        assert report.passed
        assert len(report.warnings) > 0

    def test_missing_description_warning(self, tmp_path):
        path = write_rule(tmp_path, "rule.yml", MINIMAL_RULE)
        report = validate_rule(path)
        warning_messages = [r.message for r in report.warnings]
        assert any("description" in m for m in warning_messages)

    def test_missing_author_warning(self, tmp_path):
        path = write_rule(tmp_path, "rule.yml", MINIMAL_RULE)
        report = validate_rule(path)
        warning_messages = [r.message for r in report.warnings]
        assert any("author" in m for m in warning_messages)

    def test_missing_tags_warning(self, tmp_path):
        path = write_rule(tmp_path, "rule.yml", MINIMAL_RULE)
        report = validate_rule(path)
        warning_messages = [r.message for r in report.warnings]
        assert any("tag" in m for m in warning_messages)

    def test_bad_condition_reference_error(self, tmp_path):
        path = write_rule(tmp_path, "rule.yml", BAD_CONDITION_RULE)
        report = validate_rule(path)
        assert not report.passed
        error_messages = [r.message for r in report.errors]
        assert any("nonexistent_group" in m for m in error_messages)

    def test_empty_group_error(self, tmp_path):
        path = write_rule(tmp_path, "rule.yml", EMPTY_GROUP_RULE)
        report = validate_rule(path)
        assert not report.passed
        error_messages = [r.message for r in report.errors]
        assert any("empty" in m.lower() for m in error_messages)

    def test_missing_file_error(self):
        report = validate_rule("/nonexistent/path/rule.yml")
        assert not report.passed
        assert len(report.errors) > 0

    def test_known_mitre_tag_produces_info(self, tmp_path):
        path = write_rule(tmp_path, "rule.yml", VALID_RULE)
        report = validate_rule(path)
        info_messages = [r.message for r in report.results
                         if r.severity == Severity.INFO]
        assert any("T1110.001" in m for m in info_messages)

    def test_unknown_mitre_tag_produces_warning(self, tmp_path):
        rule = VALID_RULE.replace("attack.t1110.001", "attack.t9999")
        path = write_rule(tmp_path, "rule.yml", rule)
        report = validate_rule(path)
        warning_messages = [r.message for r in report.warnings]
        assert any("t9999" in m.lower() for m in warning_messages)

    def test_validate_rules_dir(self, tmp_path):
        write_rule(tmp_path, "rule1.yml", VALID_RULE)
        write_rule(tmp_path, "rule2.yml", MINIMAL_RULE)
        reports = validate_rules_dir(tmp_path)
        assert len(reports) == 2

    def test_validate_real_rules_dir(self):
        reports = validate_rules_dir("rules/")
        assert len(reports) > 0
        # All shipped rules should pass validation (no errors)
        for report in reports:
            assert report.passed, f"Rule failed: {report.rule_title} — {report.errors}"

    def test_report_summary_pass(self, tmp_path):
        path = write_rule(tmp_path, "rule.yml", VALID_RULE)
        report = validate_rule(path)
        assert "PASS" in report.summary()

    def test_report_summary_fail(self, tmp_path):
        path = write_rule(tmp_path, "rule.yml", BAD_CONDITION_RULE)
        report = validate_rule(path)
        assert "FAIL" in report.summary()


# ── Rule Tester Tests ─────────────────────────────────────────────────────────

class TestRuleTester:
    def _write_rule(self, tmp_path: Path) -> Path:
        return write_rule(tmp_path, "ssh_brute.yml", VALID_RULE)

    def _write_fixture(self, tmp_path: Path, rule_path: str) -> Path:
        import yaml
        content = {
            "title": "SSH Brute Test Fixtures",
            "rule": rule_path,
            "tests": [
                {
                    "description": "Should fire: failed password",
                    "should_match": True,
                    "log": "<34>1 2026-06-02T03:00:01Z web-01 sshd - - - Failed password for root from 1.2.3.4",
                },
                {
                    "description": "Should NOT fire: accepted",
                    "should_match": False,
                    "log": "<34>1 2026-06-02T10:00:00Z web-01 sshd - - - Accepted publickey for deploy",
                },
                {
                    "description": "Should fire: invalid user",
                    "should_match": True,
                    "log": "<34>1 2026-06-02T03:00:01Z web-01 sshd - - - Invalid user hacker from 5.5.5.5",
                },
            ],
        }
        path = tmp_path / "ssh_brute.fixture.yml"
        path.write_text(yaml.dump(content))
        return path

    def test_all_tests_pass(self, tmp_path):
        rule_path = self._write_rule(tmp_path)
        fixture_path = self._write_fixture(tmp_path, str(rule_path))
        report = run_rule_tests(rule_path, fixture_path)
        assert report.passed, f"Failed tests: {[r for r in report.results if not r.passed]}"

    def test_pass_count(self, tmp_path):
        rule_path = self._write_rule(tmp_path)
        fixture_path = self._write_fixture(tmp_path, str(rule_path))
        report = run_rule_tests(rule_path, fixture_path)
        assert report.pass_count == 3
        assert report.total == 3

    def test_failing_test_detected(self, tmp_path):
        import yaml
        rule_path = self._write_rule(tmp_path)
        # Wrong expectation: should_match=False but log will match
        content = {
            "title": "Failing Test",
            "rule": str(rule_path),
            "tests": [{
                "description": "Intentionally wrong",
                "should_match": False,
                "log": "<34>1 2026-06-02T03:00:01Z web-01 sshd - - - Failed password for root",
            }],
        }
        fixture_path = tmp_path / "fixture.yml"
        fixture_path.write_text(yaml.dump(content))
        report = run_rule_tests(rule_path, fixture_path)
        assert not report.passed
        assert report.pass_count == 0

    def test_no_fixture_load_error(self, tmp_path):
        rule_path = self._write_rule(tmp_path)
        report = run_rule_tests(rule_path)
        assert report.load_error is not None

    def test_bad_rule_load_error(self, tmp_path):
        bad_rule = tmp_path / "bad.yml"
        bad_rule.write_text("not: valid: yaml: [")
        report = run_rule_tests(bad_rule)
        assert report.load_error is not None

    def test_elapsed_time_recorded(self, tmp_path):
        rule_path = self._write_rule(tmp_path)
        fixture_path = self._write_fixture(tmp_path, str(rule_path))
        report = run_rule_tests(rule_path, fixture_path)
        for result in report.results:
            assert result.elapsed_ms >= 0.0

    def test_summary_pass(self, tmp_path):
        rule_path = self._write_rule(tmp_path)
        fixture_path = self._write_fixture(tmp_path, str(rule_path))
        report = run_rule_tests(rule_path, fixture_path)
        assert "PASS" in report.summary()

    def test_real_fixtures_pass(self):
        """Run actual shipped fixtures against actual shipped rules."""
        reports = run_all_rule_tests("rules/")
        for report in reports:
            if report.load_error:
                continue
            assert report.passed, (
                f"Rule '{report.rule_title}' failed tests:\n"
                + "\n".join(str(r) for r in report.results if not r.passed)
            )

    def test_run_all_finds_fixtures(self):
        reports = run_all_rule_tests("rules/")
        assert len(reports) > 0

    def test_result_status_icon_pass(self, tmp_path):
        rule_path = self._write_rule(tmp_path)
        fixture_path = self._write_fixture(tmp_path, str(rule_path))
        report = run_rule_tests(rule_path, fixture_path)
        for result in report.results:
            assert result.status_icon() in ("✓", "✗", "💥")


# ── Coverage Report Tests ─────────────────────────────────────────────────────

class TestCoverageReport:
    def test_build_from_real_rules(self):
        from nano_siem.sigma.loader import load_rules_dir
        from nano_siem.correlation.chains import BUILTIN_CHAINS
        rules = load_rules_dir("rules/")
        report = build_coverage_report(rules, BUILTIN_CHAINS)
        assert isinstance(report, CoverageReport)
        assert report.total_rules == len(rules)
        assert report.total_chains == len(BUILTIN_CHAINS)

    def test_techniques_covered_positive(self):
        from nano_siem.sigma.loader import load_rules_dir
        from nano_siem.correlation.chains import BUILTIN_CHAINS
        rules = load_rules_dir("rules/")
        report = build_coverage_report(rules, BUILTIN_CHAINS)
        assert report.total_techniques_covered > 0

    def test_coverage_percent_in_range(self):
        from nano_siem.sigma.loader import load_rules_dir
        from nano_siem.correlation.chains import BUILTIN_CHAINS
        rules = load_rules_dir("rules/")
        report = build_coverage_report(rules, BUILTIN_CHAINS)
        assert 0.0 <= report.coverage_percent <= 100.0

    def test_to_dict_structure(self):
        from nano_siem.sigma.loader import load_rules_dir
        rules = load_rules_dir("rules/")
        report = build_coverage_report(rules)
        d = report.to_dict()
        assert "total_rules" in d
        assert "techniques_covered" in d
        assert "coverage_percent" in d
        assert "tactics" in d
        assert isinstance(d["tactics"], dict)

    def test_to_json_valid(self):
        import json
        from nano_siem.sigma.loader import load_rules_dir
        rules = load_rules_dir("rules/")
        report = build_coverage_report(rules)
        parsed = json.loads(report.to_json())
        assert parsed["total_rules"] == len(rules)

    def test_to_markdown_contains_tactics(self):
        from nano_siem.sigma.loader import load_rules_dir
        rules = load_rules_dir("rules/")
        report = build_coverage_report(rules)
        md = report.to_markdown()
        assert "# NanoSIEM ATT&CK Coverage Report" in md
        assert "| Technique |" in md

    def test_empty_rules_zero_coverage(self):
        # No rules AND no chains = zero coverage
        report = build_coverage_report([], chains=[])
        assert report.total_techniques_covered == 0
        assert report.coverage_percent == 0.0

    def test_chain_coverage_included(self):
        from nano_siem.correlation.chains import BUILTIN_CHAINS
        report = build_coverage_report([], BUILTIN_CHAINS)
        # Chains have MITRE techniques — should have some coverage
        assert report.total_techniques_covered > 0

    def test_tactics_dict_keys_are_strings(self):
        from nano_siem.sigma.loader import load_rules_dir
        rules = load_rules_dir("rules/")
        report = build_coverage_report(rules)
        for key in report.tactics.keys():
            assert isinstance(key, str)

    def test_entries_sorted_by_technique_id(self):
        from nano_siem.sigma.loader import load_rules_dir
        rules = load_rules_dir("rules/")
        report = build_coverage_report(rules)
        for tactic, entries in report.tactics.items():
            ids = [e.technique.full_id for e in entries]
            assert ids == sorted(ids), f"Tactic {tactic} entries not sorted"
