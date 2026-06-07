"""
sigma/evaluator.py — Rule Evaluator

Walks a RuleAST against a NormalizedEvent and returns whether the rule fires.
Also manages the full rule set: loading, hot-reloading, and batch evaluation.

Evaluation semantics:
  Within a SearchGroup:
    - KeywordMatch:  event matches if ANY keyword found in event.message (OR)
    - FieldMatch:    event matches if ANY value matches the field (OR within values)
    - Multiple matchers in a group: ALL must match (AND between matchers)
  Condition tree:
    - AndNode:  both children must match
    - OrNode:   either child must match
    - NotNode:  child must NOT match
    - GroupRef: the named SearchGroup must match
    - AggNode:  1 of / all of the selected groups
"""

from __future__ import annotations

import asyncio
import fnmatch
import logging
import re
import time
from dataclasses import dataclass
from pathlib import Path

from nano_siem.schema import NormalizedEvent
from nano_siem.sigma.ast import (
    AggNode,
    AndNode,
    ASTBuildError,
    CondNode,
    FieldMatch,
    GroupRef,
    KeywordMatch,
    NotNode,
    OrNode,
    RuleAST,
    SearchGroup,
    build_ast,
)
from nano_siem.sigma.loader import SigmaRule, load_rules_dir, reload_rules_if_changed

logger = logging.getLogger(__name__)


@dataclass
class RuleMatch:
    """Result of a single rule firing on an event."""
    rule: SigmaRule
    matched_groups: list[str]          # which group names fired
    event_id: str


# ── Field value lookup ────────────────────────────────────────────────────────

def _get_field_value(event: NormalizedEvent, field_path: str) -> str | None:
    """
    Get a field value from the event as a string for comparison.
    Handles top-level attributes and nested fields dict.
    """
    val = event.get_field(field_path)
    if val is None:
        return None
    if isinstance(val, list):
        # For list fields, join as space-separated for substring matching
        return " ".join(str(v) for v in val)
    return str(val)


# ── Single matcher evaluation ─────────────────────────────────────────────────

def _eval_keyword_match(km: KeywordMatch, event: NormalizedEvent) -> bool:
    """KeywordMatch fires if ANY keyword is found anywhere in event.message."""
    msg = event.message or ""
    msg_lower = msg.lower()
    for kw in km.keywords:
        if kw.lower() in msg_lower:
            return True
    # Also check raw log line as fallback
    raw_lower = (event.raw or "").lower()
    for kw in km.keywords:
        if kw.lower() in raw_lower:
            return True
    return False


def _eval_field_match(fm: FieldMatch, event: NormalizedEvent) -> bool:
    """
    FieldMatch fires if ANY value in fm.values matches the field, per modifier.
    Empty field = no match (except for 'not' inversions handled at caller).
    """
    field_val = _get_field_value(event, fm.field_path)
    if field_val is None:
        return False

    field_val_lower = field_val.lower()

    for match_val in fm.values:
        match_lower = match_val.lower()

        if fm.modifier == "contains":
            if match_lower in field_val_lower:
                return True
        elif fm.modifier == "startswith":
            if field_val_lower.startswith(match_lower):
                return True
        elif fm.modifier == "endswith":
            if field_val_lower.endswith(match_lower):
                return True
        elif fm.modifier == "re":
            try:
                if re.search(match_val, field_val, re.IGNORECASE):
                    return True
            except re.error:
                logger.warning("Invalid regex in rule: %r", match_val)
        elif fm.modifier == "exact":
            if field_val_lower == match_lower:
                return True
        else:
            # Unknown modifier — fall back to contains
            if match_lower in field_val_lower:
                return True

    return False


# ── SearchGroup evaluation ────────────────────────────────────────────────────

def _eval_group(group: SearchGroup, event: NormalizedEvent) -> bool:
    """
    A SearchGroup matches if ALL its matchers match (AND between matchers).
    Within each matcher, matches are OR (any value or keyword).
    """
    for matcher in group.matchers:
        if isinstance(matcher, KeywordMatch):
            if not _eval_keyword_match(matcher, event):
                return False
        elif isinstance(matcher, FieldMatch):
            if not _eval_field_match(matcher, event):
                return False
    return True


# ── Condition tree evaluation ─────────────────────────────────────────────────

def _eval_condition(
    node: CondNode,
    groups: dict[str, SearchGroup],
    event: NormalizedEvent,
    fired_groups: set[str],
) -> bool:
    """
    Recursively evaluate a condition AST node.
    fired_groups is populated as a side effect (tracks which groups matched).
    """
    if isinstance(node, AndNode):
        return (
            _eval_condition(node.left, groups, event, fired_groups)
            and _eval_condition(node.right, groups, event, fired_groups)
        )

    if isinstance(node, OrNode):
        left = _eval_condition(node.left, groups, event, fired_groups)
        right = _eval_condition(node.right, groups, event, fired_groups)
        return left or right

    if isinstance(node, NotNode):
        return not _eval_condition(node.operand, groups, event, fired_groups)

    if isinstance(node, GroupRef):
        group = groups.get(node.name)
        if group is None:
            return False
        result = _eval_group(group, event)
        if result:
            fired_groups.add(node.name)
        return result

    if isinstance(node, AggNode):
        # Resolve which groups match the selector pattern
        if node.selector.lower() == "them":
            candidate_names = list(groups.keys())
        else:
            candidate_names = [
                name for name in groups
                if fnmatch.fnmatch(name, node.selector)
            ]

        if not candidate_names:
            return False

        matches = [
            name for name in candidate_names
            if _eval_group(groups[name], event)
        ]

        if node.quantifier == "one":
            result = len(matches) >= 1
        else:  # "all"
            result = len(matches) == len(candidate_names)

        if result:
            fired_groups.update(matches)
        return result

    return False


# ── Single rule evaluation ────────────────────────────────────────────────────

def evaluate_rule(
    ast: RuleAST,
    rule: SigmaRule,
    event: NormalizedEvent,
) -> RuleMatch | None:
    """
    Evaluate one rule against one event.
    Returns RuleMatch if the rule fires, None otherwise.
    """
    fired_groups: set[str] = set()
    try:
        matched = _eval_condition(ast.condition, ast.groups, event, fired_groups)
    except Exception as e:
        logger.warning("Error evaluating rule '%s': %s", rule.title, e)
        return None

    if matched:
        return RuleMatch(
            rule=rule,
            matched_groups=sorted(fired_groups),
            event_id=event.event_id,
        )
    return None


# ── Rule engine — manages the full rule set ───────────────────────────────────

class SigmaEngine:
    """
    Manages loading, compiling, and evaluating a set of Sigma rules.

    Usage:
        engine = SigmaEngine("rules/")
        engine.load()
        matches = engine.evaluate(event)
    """

    def __init__(self, rules_dir: str, reload_interval: int = 60) -> None:
        self._rules_dir = rules_dir
        self._reload_interval = reload_interval
        self._rules: list[SigmaRule] = []
        self._asts: dict[str, RuleAST] = {}     # rule.id → AST
        self._last_mtimes: dict[str, float] = {}
        self._last_reload: float = 0.0
        self._lock = asyncio.Lock()

    def load(self) -> int:
        """
        Load all rules from rules_dir. Compiles each to an AST.
        Returns number of successfully compiled rules.
        """
        raw_rules = load_rules_dir(self._rules_dir)
        compiled = self._compile_rules(raw_rules)
        self._rules = [r for r, _ in compiled]
        self._asts = {r.id or r.title: ast for r, ast in compiled}
        self._last_reload = time.time()
        logger.info("Sigma engine: %d rules loaded and compiled", len(self._rules))
        return len(self._rules)

    def _compile_rules(
        self, rules: list[SigmaRule]
    ) -> list[tuple[SigmaRule, RuleAST]]:
        """Compile raw SigmaRules to ASTs, skipping any that fail."""
        compiled = []
        for rule in rules:
            try:
                ast = build_ast(rule.detection, rule_title=rule.title)
                compiled.append((rule, ast))
                logger.debug("Compiled rule: %s", rule.title)
            except ASTBuildError as e:
                logger.warning("Failed to compile rule '%s': %s", rule.title, e)
        return compiled

    def evaluate(self, event: NormalizedEvent) -> list[RuleMatch]:
        """
        Evaluate all loaded rules against one event.
        Returns list of RuleMatch for every rule that fires.
        Enriches the event in-place: adds sigma_matches tags.
        """
        matches: list[RuleMatch] = []

        for rule in self._rules:
            key = rule.id or rule.title
            ast = self._asts.get(key)
            if ast is None:
                continue
            match = evaluate_rule(ast, rule, event)
            if match:
                matches.append(match)
                # Enrich event
                event.sigma_matches.append(rule.title)
                event.add_tag(f"sigma:{rule.title.lower().replace(' ', '_')[:40]}")
                event.add_tag(f"level:{rule.level}")

        return matches

    async def maybe_reload(self) -> bool:
        """
        Hot-reload rules if files have changed since last load.
        Returns True if rules were reloaded.
        Called periodically from the main pipeline loop.
        """
        if time.time() - self._last_reload < self._reload_interval:
            return False

        async with self._lock:
            new_rules, self._last_mtimes = reload_rules_if_changed(
                self._rules_dir, self._last_mtimes
            )
            if new_rules is not None:
                compiled = self._compile_rules(new_rules)
                self._rules = [r for r, _ in compiled]
                self._asts = {r.id or r.title: ast for r, ast in compiled}
                self._last_reload = time.time()
                logger.info(
                    "Rules hot-reloaded: %d rules active", len(self._rules)
                )
                return True
        return False

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def rule_summary(self) -> list[dict[str, str]]:
        """Return a summary of all loaded rules for display."""
        return [
            {
                "title": r.title,
                "level": r.level,
                "status": r.status,
                "tags": ", ".join(r.tags[:3]),
                "file": Path(r.source_file).name,
            }
            for r in sorted(self._rules, key=lambda r: -r.level_priority)
        ]
