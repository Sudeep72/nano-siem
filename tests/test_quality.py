"""
test_quality.py — Tests for detection/quality.py (Rule Quality Metrics)
"""

import pytest
from pathlib import Path

from nano_siem.sigma.loader import load_rule, load_rules_dir
from nano_siem.detection.quality import (
    assess_rule_quality, assess_all_rules, _compute_specificity,
    _estimate_fp_risk, _find_overlaps, _ast_depth, _ast_node_count,
)
from nano_siem.sigma.ast import build_ast


SPECIFIC_RULE = """
title: Specific Rule
id: q-0001
status: stable
level: high
description: A rule with specific, long field-based matchers.
author: Test
tags:
  - attack.t1110.001
logsource:
  product: linux
detection:
  selection:
    message|contains:
      - 'Failed password for invalid user'
  filter:
    message|contains: 'systemd-logind'
  condition: selection and not filter
falsepositives:
  - Documented edge case
"""

VAGUE_RULE = """
title: Vague Rule
id: q-0002
status: stable
level: medium
description: A rule with very short, generic keywords.
author: Test
tags:
  - attack.t1046
logsource:
  product: linux
detection:
  selection:
    - 'a'
    - 'ok'
  condition: selection
"""

OVERLAP_A = """
title: Overlap A
id: q-0003
status: stable
level: medium
description: First overlapping rule.
author: Test
tags:
  - attack.t1110
logsource:
  product: linux
detection:
  selection:
    - 'Failed password'
    - 'authentication failure'
  condition: selection
"""

OVERLAP_B = """
title: Overlap B
id: q-0004
status: stable
level: medium
description: Second overlapping rule sharing keywords with Overlap A.
author: Test
tags:
  - attack.t1110.001
logsource:
  product: linux
detection:
  selection:
    - 'Failed password'
    - 'authentication failure'
  condition: selection
"""


def write_rule(tmp_path: Path, name: str, content: str) -> Path:
    path = tmp_path / name
    path.write_text(content)
    return path


class TestASTHelpers:
    def test_ast_node_count_simple(self, tmp_path):
        path = write_rule(tmp_path, "r.yml", SPECIFIC_RULE)
        rule = load_rule(path)
        ast = build_ast(rule.detection, rule_title=rule.title)
        count = _ast_node_count(ast.condition)
        assert count >= 1

    def test_ast_depth_simple(self, tmp_path):
        path = write_rule(tmp_path, "r.yml", SPECIFIC_RULE)
        rule = load_rule(path)
        ast = build_ast(rule.detection, rule_title=rule.title)
        depth = _ast_depth(ast.condition)
        assert depth >= 1  # has an AND/NOT


class TestSpecificity:
    def test_specific_rule_scores_higher(self, tmp_path):
        specific = load_rule(write_rule(tmp_path, "a.yml", SPECIFIC_RULE))
        vague = load_rule(write_rule(tmp_path, "b.yml", VAGUE_RULE))
        spec_score = _compute_specificity(specific)
        vague_score = _compute_specificity(vague)
        assert spec_score > vague_score

    def test_specificity_in_range(self, tmp_path):
        rule = load_rule(write_rule(tmp_path, "a.yml", SPECIFIC_RULE))
        score = _compute_specificity(rule)
        assert 0.0 <= score <= 100.0

    def test_not_filter_increases_specificity(self, tmp_path):
        # SPECIFIC_RULE has a 'not filter' clause
        rule = load_rule(write_rule(tmp_path, "a.yml", SPECIFIC_RULE))
        score = _compute_specificity(rule)
        assert score > 50  # baseline is 50, not-filter adds bonus


class TestFPRisk:
    def test_vague_rule_higher_risk(self, tmp_path):
        vague = load_rule(write_rule(tmp_path, "b.yml", VAGUE_RULE))
        specific = load_rule(write_rule(tmp_path, "a.yml", SPECIFIC_RULE))
        vague_spec = _compute_specificity(vague)
        spec_spec = _compute_specificity(specific)
        vague_risk, _ = _estimate_fp_risk(vague, vague_spec)
        spec_risk, _ = _estimate_fp_risk(specific, spec_spec)
        risk_order = {"low": 0, "medium": 1, "high": 2}
        assert risk_order[vague_risk] >= risk_order[spec_risk]

    def test_fp_risk_returns_valid_level(self, tmp_path):
        rule = load_rule(write_rule(tmp_path, "a.yml", SPECIFIC_RULE))
        spec = _compute_specificity(rule)
        risk, reasons = _estimate_fp_risk(rule, spec)
        assert risk in ("low", "medium", "high")
        assert isinstance(reasons, list)

    def test_no_falsepositives_documented_flagged(self, tmp_path):
        rule = load_rule(write_rule(tmp_path, "b.yml", VAGUE_RULE))
        spec = _compute_specificity(rule)
        risk, reasons = _estimate_fp_risk(rule, spec)
        assert any("false positives" in r.lower() for r in reasons)


class TestOverlapDetection:
    def test_overlapping_rules_detected(self, tmp_path):
        a = load_rule(write_rule(tmp_path, "a.yml", OVERLAP_A))
        b = load_rule(write_rule(tmp_path, "b.yml", OVERLAP_B))
        overlaps = _find_overlaps([a, b])
        assert b.title in overlaps[a.title]
        assert a.title in overlaps[b.title]

    def test_non_overlapping_rules_not_flagged(self, tmp_path):
        a = load_rule(write_rule(tmp_path, "a.yml", OVERLAP_A))
        c = load_rule(write_rule(tmp_path, "c.yml", VAGUE_RULE))
        overlaps = _find_overlaps([a, c])
        assert c.title not in overlaps[a.title]

    def test_overlap_map_symmetric(self, tmp_path):
        a = load_rule(write_rule(tmp_path, "a.yml", OVERLAP_A))
        b = load_rule(write_rule(tmp_path, "b.yml", OVERLAP_B))
        overlaps = _find_overlaps([a, b])
        assert (b.title in overlaps[a.title]) == (a.title in overlaps[b.title])


class TestAssessRuleQuality:
    def test_returns_report(self, tmp_path):
        rule = load_rule(write_rule(tmp_path, "a.yml", SPECIFIC_RULE))
        report = assess_rule_quality(rule)
        assert report.rule_title == "Specific Rule"
        assert 0 <= report.maintenance_score <= 100

    def test_to_dict_serializable(self, tmp_path):
        import json
        rule = load_rule(write_rule(tmp_path, "a.yml", SPECIFIC_RULE))
        report = assess_rule_quality(rule)
        d = report.to_dict()
        json.dumps(d)  # should not raise
        assert "maintenance_score" in d

    def test_complexity_score_nonnegative(self, tmp_path):
        rule = load_rule(write_rule(tmp_path, "a.yml", SPECIFIC_RULE))
        report = assess_rule_quality(rule)
        assert report.complexity_score >= 0

    def test_overlaps_passed_through(self, tmp_path):
        a = load_rule(write_rule(tmp_path, "a.yml", OVERLAP_A))
        b = load_rule(write_rule(tmp_path, "b.yml", OVERLAP_B))
        report_a = assess_rule_quality(a, all_rules=[a, b])
        assert b.title in report_a.overlaps_with


class TestAssessAllRules:
    def test_assess_real_rules_dir(self):
        rules = load_rules_dir("rules/")
        reports = assess_all_rules(rules)
        assert len(reports) == len(rules)

    def test_all_reports_have_valid_scores(self):
        rules = load_rules_dir("rules/")
        reports = assess_all_rules(rules)
        for r in reports:
            assert 0 <= r.maintenance_score <= 100
            assert 0 <= r.specificity_score <= 100
            assert r.fp_risk in ("low", "medium", "high")

    def test_overlap_computed_once_for_all(self, tmp_path):
        a = load_rule(write_rule(tmp_path, "a.yml", OVERLAP_A))
        b = load_rule(write_rule(tmp_path, "b.yml", OVERLAP_B))
        reports = assess_all_rules([a, b])
        report_a = next(r for r in reports if r.rule_title == "Overlap A")
        assert "Overlap B" in report_a.overlaps_with
