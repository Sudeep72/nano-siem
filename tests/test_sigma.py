"""
test_sigma.py — Unit tests for the Sigma rule engine

Tests cover:
  - Rule loading and validation (loader.py)
  - AST construction from detection blocks (ast.py)
  - Rule evaluation against NormalizedEvents (evaluator.py)
  - Full engine: load rules dir + evaluate
"""

import os

import pytest

from nano_siem.schema import NormalizedEvent
from nano_siem.sigma.ast import ASTBuildError, build_ast
from nano_siem.sigma.evaluator import SigmaEngine, evaluate_rule
from nano_siem.sigma.loader import SigmaLoadError, SigmaRule, load_rule, load_rules_dir

# ── Helpers ───────────────────────────────────────────────────────────────────

def make_event(
    message: str = "",
    host: str = "testhost",
    program: str = "sshd",
    log_source: str = "syslog_rfc5424",
    source_ip: str | None = None,
    tags: list[str] | None = None,
    **fields,
) -> NormalizedEvent:
    e = NormalizedEvent()
    e.message = message
    e.raw = message
    e.host = host
    e.program = program
    e.log_source = log_source
    e.source_ip = source_ip
    e.tags = tags or []
    e.fields = fields
    return e


def write_rule(tmpdir: str, name: str, content: str) -> str:
    path = os.path.join(tmpdir, name)
    with open(path, "w") as f:
        f.write(content)
    return path


VALID_RULE_YAML = """
title: Test SSH Brute Force
id: test-001
status: stable
level: high
description: Test rule
author: test
tags:
  - attack.t1110
logsource:
  product: linux
  service: sshd
detection:
  keywords:
    - 'Failed password'
    - 'Invalid user'
  condition: keywords
"""

FIELD_MATCH_RULE = """
title: Test Field Match
id: test-002
status: stable
level: medium
logsource:
  product: linux
detection:
  auth_fail:
    message|contains:
      - 'Failed password'
      - 'authentication failure'
  from_external:
    source_ip|startswith:
      - '192.168.'
      - '10.'
  condition: auth_fail and from_external
"""

COMPOUND_RULE = """
title: Test Compound
id: test-003
status: stable
level: high
logsource:
  product: linux
detection:
  root_exec:
    message|contains:
      - 'uid=0'
  shell:
    message|contains:
      - '/bin/bash'
      - '/bin/sh'
  condition: root_exec and shell
"""

NOT_RULE = """
title: Test NOT
id: test-004
status: stable
level: low
logsource:
  product: linux
detection:
  keywords:
    - 'sudo'
  legit:
    message|contains:
      - 'systemd'
  condition: keywords and not legit
"""

ONE_OF_RULE = """
title: Test 1 of
id: test-005
status: stable
level: medium
logsource:
  product: linux
detection:
  group_a:
    message|contains: 'Failed'
  group_b:
    message|contains: 'error'
  condition: 1 of group_*
"""

ALL_OF_RULE = """
title: Test all of them
id: test-006
status: stable
level: high
logsource:
  product: linux
detection:
  group_a:
    message|contains: 'uid=0'
  group_b:
    message|contains: '/bin/bash'
  condition: all of them
"""


# ── Loader tests ───────────────────────────────────────────────────────────────

class TestLoader:
    def test_load_valid_rule(self, tmp_path):
        path = tmp_path / "test.yml"
        path.write_text(VALID_RULE_YAML)
        rule = load_rule(path)
        assert rule.title == "Test SSH Brute Force"
        assert rule.level == "high"
        assert rule.status == "stable"
        assert rule.id == "test-001"
        assert "attack.t1110" in rule.tags

    def test_missing_title_raises(self, tmp_path):
        path = tmp_path / "bad.yml"
        path.write_text("detection:\n  condition: test\nlogsource:\n  product: linux\n")
        with pytest.raises(SigmaLoadError, match="title"):
            load_rule(path)

    def test_missing_condition_raises(self, tmp_path):
        path = tmp_path / "bad.yml"
        path.write_text("title: T\nlogsource:\n  product: linux\ndetection:\n  kw:\n    - x\n")
        with pytest.raises(SigmaLoadError, match="condition"):
            load_rule(path)

    def test_missing_logsource_raises(self, tmp_path):
        path = tmp_path / "bad.yml"
        path.write_text("title: T\ndetection:\n  condition: kw\n  kw:\n    - x\n")
        with pytest.raises(SigmaLoadError, match="logsource"):
            load_rule(path)

    def test_invalid_level_defaults_to_medium(self, tmp_path):
        path = tmp_path / "test.yml"
        path.write_text(VALID_RULE_YAML.replace("level: high", "level: superduper"))
        rule = load_rule(path)
        assert rule.level == "medium"

    def test_file_not_found_raises(self):
        with pytest.raises(SigmaLoadError, match="not found"):
            load_rule("/nonexistent/path/rule.yml")

    def test_load_rules_dir(self, tmp_path):
        (tmp_path / "rule1.yml").write_text(VALID_RULE_YAML)
        (tmp_path / "rule2.yml").write_text(FIELD_MATCH_RULE)
        rules = load_rules_dir(tmp_path)
        assert len(rules) == 2

    def test_load_rules_dir_skips_bad_files(self, tmp_path):
        (tmp_path / "good.yml").write_text(VALID_RULE_YAML)
        (tmp_path / "bad.yml").write_text("not: valid: yaml: at: all: [}")
        rules = load_rules_dir(tmp_path)
        # bad file skipped, good file loaded
        assert len(rules) == 1

    def test_load_rules_dir_nonexistent(self, tmp_path):
        rules = load_rules_dir(tmp_path / "nonexistent")
        assert rules == []

    def test_level_priority(self, tmp_path):
        path = tmp_path / "test.yml"
        path.write_text(VALID_RULE_YAML)
        rule = load_rule(path)
        assert rule.level_priority == 3  # high = 3


# ── AST builder tests ─────────────────────────────────────────────────────────

class TestAST:
    def test_keyword_group_built(self):
        detection = {
            "keywords": ["Failed password", "Invalid user"],
            "condition": "keywords",
        }
        ast = build_ast(detection)
        assert "keywords" in ast.groups
        from nano_siem.sigma.ast import KeywordMatch
        assert any(isinstance(m, KeywordMatch) for m in ast.groups["keywords"].matchers)

    def test_field_match_group_built(self):
        detection = {
            "auth_fail": {"message|contains": ["Failed password"]},
            "condition": "auth_fail",
        }
        ast = build_ast(detection)
        assert "auth_fail" in ast.groups
        from nano_siem.sigma.ast import FieldMatch
        matchers = ast.groups["auth_fail"].matchers
        assert any(isinstance(m, FieldMatch) and m.modifier == "contains" for m in matchers)

    def test_and_condition(self):
        detection = {
            "a": {"message|contains": "foo"},
            "b": {"message|contains": "bar"},
            "condition": "a and b",
        }
        ast = build_ast(detection)
        from nano_siem.sigma.ast import AndNode
        assert isinstance(ast.condition, AndNode)

    def test_or_condition(self):
        detection = {
            "a": {"message|contains": "foo"},
            "b": {"message|contains": "bar"},
            "condition": "a or b",
        }
        ast = build_ast(detection)
        from nano_siem.sigma.ast import OrNode
        assert isinstance(ast.condition, OrNode)

    def test_not_condition(self):
        detection = {
            "a": {"message|contains": "foo"},
            "b": {"message|contains": "bar"},
            "condition": "a and not b",
        }
        ast = build_ast(detection)
        from nano_siem.sigma.ast import AndNode, NotNode
        assert isinstance(ast.condition, AndNode)
        assert isinstance(ast.condition.right, NotNode)

    def test_agg_one_of(self):
        detection = {
            "group_a": {"message|contains": "a"},
            "group_b": {"message|contains": "b"},
            "condition": "1 of group_*",
        }
        ast = build_ast(detection)
        from nano_siem.sigma.ast import AggNode
        assert isinstance(ast.condition, AggNode)
        assert ast.condition.quantifier == "one"
        assert ast.condition.selector == "group_*"

    def test_agg_all_of_them(self):
        detection = {
            "group_a": {"message|contains": "a"},
            "group_b": {"message|contains": "b"},
            "condition": "all of them",
        }
        ast = build_ast(detection)
        from nano_siem.sigma.ast import AggNode
        assert isinstance(ast.condition, AggNode)
        assert ast.condition.quantifier == "all"
        assert ast.condition.selector == "them"

    def test_empty_condition_raises(self):
        with pytest.raises(ASTBuildError):
            build_ast({"condition": "", "kw": ["x"]})

    def test_parenthesized_condition(self):
        detection = {
            "a": {"message|contains": "foo"},
            "b": {"message|contains": "bar"},
            "c": {"message|contains": "baz"},
            "condition": "(a or b) and c",
        }
        ast = build_ast(detection)
        from nano_siem.sigma.ast import AndNode, OrNode
        assert isinstance(ast.condition, AndNode)
        assert isinstance(ast.condition.left, OrNode)


# ── Evaluator tests ───────────────────────────────────────────────────────────

class TestEvaluator:
    def _make_rule_and_ast(self, yaml_str: str, tmp_path) -> tuple[SigmaRule, object]:
        path = tmp_path / "rule.yml"
        path.write_text(yaml_str)
        rule = load_rule(path)
        ast = build_ast(rule.detection, rule.title)
        return rule, ast

    def test_keyword_match_fires(self, tmp_path):
        rule, ast = self._make_rule_and_ast(VALID_RULE_YAML, tmp_path)
        event = make_event(message="Failed password for root from 1.2.3.4")
        result = evaluate_rule(ast, rule, event)
        assert result is not None
        assert result.rule.title == "Test SSH Brute Force"

    def test_keyword_no_match(self, tmp_path):
        rule, ast = self._make_rule_and_ast(VALID_RULE_YAML, tmp_path)
        event = make_event(message="Accepted publickey for deploy")
        result = evaluate_rule(ast, rule, event)
        assert result is None

    def test_keyword_second_value_matches(self, tmp_path):
        rule, ast = self._make_rule_and_ast(VALID_RULE_YAML, tmp_path)
        event = make_event(message="Invalid user hacker from 10.0.0.1")
        result = evaluate_rule(ast, rule, event)
        assert result is not None

    def test_field_match_and_condition(self, tmp_path):
        rule, ast = self._make_rule_and_ast(FIELD_MATCH_RULE, tmp_path)
        # Both conditions met
        event = make_event(
            message="Failed password for root from 192.168.1.100",
            source_ip="192.168.1.100",
        )
        result = evaluate_rule(ast, rule, event)
        assert result is not None

    def test_field_match_and_condition_partial_fails(self, tmp_path):
        rule, ast = self._make_rule_and_ast(FIELD_MATCH_RULE, tmp_path)
        # Message matches but source_ip doesn't match 192.168.* or 10.*
        event = make_event(
            message="Failed password for root",
            source_ip="203.0.113.5",   # external, not in 192.168.* or 10.*
        )
        result = evaluate_rule(ast, rule, event)
        assert result is None

    def test_compound_and_rule(self, tmp_path):
        rule, ast = self._make_rule_and_ast(COMPOUND_RULE, tmp_path)
        event = make_event(message="session opened for user root (uid=0) via /bin/bash")
        result = evaluate_rule(ast, rule, event)
        assert result is not None

    def test_compound_and_rule_partial_fail(self, tmp_path):
        rule, ast = self._make_rule_and_ast(COMPOUND_RULE, tmp_path)
        event = make_event(message="session opened for user root (uid=0)")
        # uid=0 present but no shell indicator
        result = evaluate_rule(ast, rule, event)
        assert result is None

    def test_not_condition_excludes(self, tmp_path):
        rule, ast = self._make_rule_and_ast(NOT_RULE, tmp_path)
        # sudo + no 'systemd' → should fire
        event = make_event(message="admin ran sudo /usr/bin/apt")
        result = evaluate_rule(ast, rule, event)
        assert result is not None

    def test_not_condition_suppresses_match(self, tmp_path):
        rule, ast = self._make_rule_and_ast(NOT_RULE, tmp_path)
        # sudo + 'systemd' → NOT condition suppresses
        event = make_event(message="systemd ran sudo service restart")
        result = evaluate_rule(ast, rule, event)
        assert result is None

    def test_1_of_glob_fires_on_one(self, tmp_path):
        rule, ast = self._make_rule_and_ast(ONE_OF_RULE, tmp_path)
        # Only group_a matches
        event = make_event(message="Failed login attempt")
        result = evaluate_rule(ast, rule, event)
        assert result is not None

    def test_1_of_glob_fires_on_both(self, tmp_path):
        rule, ast = self._make_rule_and_ast(ONE_OF_RULE, tmp_path)
        event = make_event(message="Failed with error code 5")
        result = evaluate_rule(ast, rule, event)
        assert result is not None

    def test_1_of_glob_no_match(self, tmp_path):
        rule, ast = self._make_rule_and_ast(ONE_OF_RULE, tmp_path)
        event = make_event(message="Everything is fine, system running normally")
        result = evaluate_rule(ast, rule, event)
        assert result is None

    def test_all_of_them_requires_all(self, tmp_path):
        rule, ast = self._make_rule_and_ast(ALL_OF_RULE, tmp_path)
        # Both present
        event = make_event(message="root executed uid=0 /bin/bash shell")
        result = evaluate_rule(ast, rule, event)
        assert result is not None

    def test_all_of_them_fails_if_one_missing(self, tmp_path):
        rule, ast = self._make_rule_and_ast(ALL_OF_RULE, tmp_path)
        event = make_event(message="uid=0 something happened")
        # uid=0 present, /bin/bash missing
        result = evaluate_rule(ast, rule, event)
        assert result is None

    def test_sigma_match_enriches_event(self, tmp_path):
        rule, ast = self._make_rule_and_ast(VALID_RULE_YAML, tmp_path)
        event = make_event(message="Failed password for root")
        evaluate_rule(ast, rule, event)
        # evaluate_rule alone doesn't enrich — engine does
        # test enrichment via engine instead

    def test_case_insensitive_keyword(self, tmp_path):
        rule, ast = self._make_rule_and_ast(VALID_RULE_YAML, tmp_path)
        event = make_event(message="FAILED PASSWORD for ROOT from 1.2.3.4")
        result = evaluate_rule(ast, rule, event)
        assert result is not None


# ── Engine integration tests ──────────────────────────────────────────────────

class TestSigmaEngine:
    def test_engine_loads_rules(self, tmp_path):
        (tmp_path / "r1.yml").write_text(VALID_RULE_YAML)
        (tmp_path / "r2.yml").write_text(FIELD_MATCH_RULE)
        engine = SigmaEngine(str(tmp_path))
        n = engine.load()
        assert n == 2
        assert engine.rule_count == 2

    def test_engine_evaluate_fires(self, tmp_path):
        (tmp_path / "r1.yml").write_text(VALID_RULE_YAML)
        engine = SigmaEngine(str(tmp_path))
        engine.load()
        event = make_event(message="Failed password for root from 1.2.3.4")
        matches = engine.evaluate(event)
        assert len(matches) == 1
        assert matches[0].rule.title == "Test SSH Brute Force"

    def test_engine_evaluate_no_match(self, tmp_path):
        (tmp_path / "r1.yml").write_text(VALID_RULE_YAML)
        engine = SigmaEngine(str(tmp_path))
        engine.load()
        event = make_event(message="System startup completed successfully")
        matches = engine.evaluate(event)
        assert matches == []

    def test_engine_enriches_event_tags(self, tmp_path):
        (tmp_path / "r1.yml").write_text(VALID_RULE_YAML)
        engine = SigmaEngine(str(tmp_path))
        engine.load()
        event = make_event(message="Failed password for root")
        engine.evaluate(event)
        assert any("sigma:" in t for t in event.tags)
        assert any("level:high" in t for t in event.tags)

    def test_engine_enriches_sigma_matches(self, tmp_path):
        (tmp_path / "r1.yml").write_text(VALID_RULE_YAML)
        engine = SigmaEngine(str(tmp_path))
        engine.load()
        event = make_event(message="Failed password for root")
        engine.evaluate(event)
        assert "Test SSH Brute Force" in event.sigma_matches

    def test_engine_multiple_rules_can_fire(self, tmp_path):
        (tmp_path / "r1.yml").write_text(VALID_RULE_YAML)
        (tmp_path / "r2.yml").write_text(NOT_RULE.replace("Test NOT", "Another Rule"))
        engine = SigmaEngine(str(tmp_path))
        engine.load()
        # "Failed password" matches r1; "sudo" not present, r2 won't fire
        event = make_event(message="Failed password for root")
        matches = engine.evaluate(event)
        assert len(matches) >= 1

    def test_engine_rule_summary(self, tmp_path):
        (tmp_path / "r1.yml").write_text(VALID_RULE_YAML)
        engine = SigmaEngine(str(tmp_path))
        engine.load()
        summary = engine.rule_summary()
        assert len(summary) == 1
        assert summary[0]["title"] == "Test SSH Brute Force"
        assert summary[0]["level"] == "high"

    def test_engine_bad_dir_loads_zero(self, tmp_path):
        engine = SigmaEngine(str(tmp_path / "nonexistent"))
        n = engine.load()
        assert n == 0

    def test_engine_loads_sample_rules(self):
        """Integration: load the actual rules shipped with nano-siem."""
        engine = SigmaEngine("rules/")
        n = engine.load()
        assert n >= 5, f"Expected at least 5 sample rules, got {n}"

    def test_sample_rules_ssh_brute_force(self):
        engine = SigmaEngine("rules/")
        engine.load()
        event = make_event(
            message="Failed password for root from 192.168.1.100 port 22 ssh2",
            program="sshd",
        )
        matches = engine.evaluate(event)
        titles = [m.rule.title for m in matches]
        assert any("SSH" in t and "Brute" in t for t in titles), f"Got: {titles}"

    def test_sample_rules_port_scan(self):
        engine = SigmaEngine("rules/")
        engine.load()
        event = make_event(
            message="Port Scan Detected from 192.168.100.5",
            log_source="cef",
        )
        matches = engine.evaluate(event)
        titles = [m.rule.title for m in matches]
        assert any("Port Scan" in t for t in titles), f"Got: {titles}"

    def test_sample_rules_web_admin(self):
        engine = SigmaEngine("rules/")
        engine.load()
        event = make_event(
            message='GET /admin/panel HTTP/1.1 403',
            program="nginx",
        )
        matches = engine.evaluate(event)
        titles = [m.rule.title for m in matches]
        assert any("Admin" in t or "admin" in t.lower() for t in titles), f"Got: {titles}"
