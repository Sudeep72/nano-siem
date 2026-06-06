"""
sigma/ast.py — Sigma Detection Block → Evaluable AST

Converts a Sigma detection block (parsed from YAML) into a tree of
MatchNode objects that the evaluator can walk against a NormalizedEvent.

Sigma detection anatomy:
  detection:
    <named_group_1>:           # a "search identifier"
      field|modifier: value    # field match
    <named_group_2>:
      - keyword                # keyword list (searches 'message' field)
    condition: <expression>    # combines groups with and/or/not/1of/allof

Supported modifiers:
  contains       — substring match (case-insensitive)
  startswith     — prefix match
  endswith       — suffix match
  re             — regex match
  (none)         — exact match or list-of-exact

Supported condition operators:
  and, or, not
  1 of <pattern>     — at least 1 named group matching the glob pattern fires
  all of <pattern>   — all named groups matching the glob pattern must fire
  1 of them          — 1 of all groups
  all of them        — all groups

Grammar (informal):
  expr     := term (('and'|'or') term)*
  term     := 'not' term | atom
  atom     := '(' expr ')' | '1' 'of' selector | 'all' 'of' selector | identifier
  selector := 'them' | pattern (glob)
"""

from __future__ import annotations
import fnmatch
import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ── Match nodes ────────────────────────────────────────────────────────────────

@dataclass
class FieldMatch:
    """
    Matches a single field against one or more values with an optional modifier.
    e.g. message|contains: ['Failed password', 'Invalid user']
    """
    field_path: str                    # e.g. "message", "fields.username"
    values: list[str]                  # values to match against
    modifier: str = "contains"         # contains | startswith | endswith | re | exact

    def __repr__(self) -> str:
        return f"FieldMatch({self.field_path}|{self.modifier}: {self.values})"


@dataclass
class KeywordMatch:
    """
    Matches keywords against the 'message' field (Sigma keyword lists).
    A list of strings — event matches if ANY keyword is found in message.
    """
    keywords: list[str]

    def __repr__(self) -> str:
        return f"KeywordMatch({self.keywords})"


@dataclass
class SearchGroup:
    """
    A named detection group — either field matches or keyword list.
    name corresponds to the YAML key under detection (excluding 'condition' and 'filter*').
    """
    name: str
    matchers: list[FieldMatch | KeywordMatch]
    # ALL matchers in a group must fire (AND within a group)
    # UNLESS it's a keyword list (OR within keywords)

    def __repr__(self) -> str:
        return f"SearchGroup({self.name!r}, {self.matchers})"


# ── Condition AST nodes ────────────────────────────────────────────────────────

@dataclass
class AndNode:
    left: "CondNode"
    right: "CondNode"

@dataclass
class OrNode:
    left: "CondNode"
    right: "CondNode"

@dataclass
class NotNode:
    operand: "CondNode"

@dataclass
class GroupRef:
    """References a named SearchGroup by name."""
    name: str

@dataclass
class AggNode:
    """1 of / all of <selector>"""
    quantifier: str    # "one" | "all"
    selector: str      # group name glob pattern, or "them"

CondNode = AndNode | OrNode | NotNode | GroupRef | AggNode


# ── Top-level rule AST ────────────────────────────────────────────────────────

@dataclass
class RuleAST:
    """
    Complete parsed detection block for one Sigma rule.
    groups: name → SearchGroup
    condition: root of the condition expression tree
    """
    groups: dict[str, SearchGroup]
    condition: CondNode
    raw_condition: str


# ── Builder: detection dict → RuleAST ─────────────────────────────────────────

class ASTBuildError(Exception):
    pass


def build_ast(detection: dict[str, Any], rule_title: str = "") -> RuleAST:
    """
    Convert a raw Sigma detection dict into a RuleAST.

    Args:
        detection:   The detection block parsed from YAML.
        rule_title:  Used in error messages only.

    Returns:
        RuleAST ready for the evaluator.

    Raises:
        ASTBuildError: If the detection block is malformed.
    """
    raw_condition = str(detection.get("condition", "")).strip()
    if not raw_condition:
        raise ASTBuildError(f"Rule '{rule_title}' has empty condition")

    # Build SearchGroups from all keys except 'condition'
    groups: dict[str, SearchGroup] = {}
    for key, value in detection.items():
        if key == "condition":
            continue
        group = _build_group(key, value, rule_title)
        if group is not None:
            groups[key] = group

    # Parse condition expression into AST
    try:
        condition = _parse_condition(raw_condition, groups)
    except Exception as e:
        raise ASTBuildError(
            f"Rule '{rule_title}' condition parse error: {e} (condition={raw_condition!r})"
        )

    return RuleAST(groups=groups, condition=condition, raw_condition=raw_condition)


def _build_group(name: str, value: Any, rule_title: str) -> SearchGroup | None:
    """Convert a single detection group value into a SearchGroup."""
    matchers: list[FieldMatch | KeywordMatch] = []

    # ── Keyword list: bare list of strings ────────────────────────────────────
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        matchers.append(KeywordMatch(keywords=[str(v) for v in value]))
        return SearchGroup(name=name, matchers=matchers)

    # ── Single keyword string ──────────────────────────────────────────────────
    if isinstance(value, str):
        matchers.append(KeywordMatch(keywords=[value]))
        return SearchGroup(name=name, matchers=matchers)

    # ── Field match dict ───────────────────────────────────────────────────────
    if isinstance(value, dict):
        for field_expr, match_value in value.items():
            fm = _build_field_match(field_expr, match_value, rule_title)
            if fm:
                matchers.append(fm)
        return SearchGroup(name=name, matchers=matchers) if matchers else None

    logger.warning("Rule '%s' group '%s' has unsupported value type %s",
                   rule_title, name, type(value).__name__)
    return None


def _build_field_match(field_expr: str, value: Any, rule_title: str) -> FieldMatch | None:
    """
    Parse a 'field|modifier: value' entry into a FieldMatch.

    field_expr examples:
      message              → exact / keyword match on message
      message|contains     → substring
      fields.username|re   → regex on fields dict username
    """
    parts = field_expr.split("|", 1)
    field_path = parts[0].strip()
    modifier = parts[1].strip().lower() if len(parts) > 1 else "exact"

    # Normalize values to a list of strings
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, list):
        values = [str(v) for v in value]
    elif isinstance(value, (int, float, bool)):
        values = [str(value)]
    else:
        logger.warning("Rule '%s' field '%s' unsupported value type %s",
                       rule_title, field_expr, type(value).__name__)
        return None

    return FieldMatch(field_path=field_path, values=values, modifier=modifier)


# ── Condition parser ───────────────────────────────────────────────────────────
# Recursive descent parser for Sigma condition expressions.
# Grammar is simple enough that a hand-rolled RD parser is cleaner than a lib.

class _Tokenizer:
    """Tokenizes a Sigma condition string into a list of tokens."""

    def __init__(self, text: str) -> None:
        self.tokens = self._tokenize(text)
        self.pos = 0

    def _tokenize(self, text: str) -> list[str]:
        # Split on whitespace but keep parentheses as separate tokens
        import re
        tokens = []
        for part in re.split(r'(\s+|\(|\))', text):
            part = part.strip()
            if part:
                tokens.append(part)
        return tokens

    def peek(self) -> str | None:
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return None

    def consume(self) -> str:
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def expect(self, value: str) -> None:
        tok = self.consume()
        if tok.lower() != value.lower():
            raise ASTBuildError(f"Expected '{value}', got '{tok}'")

    def at_end(self) -> bool:
        return self.pos >= len(self.tokens)


def _parse_condition(condition: str, groups: dict[str, SearchGroup]) -> CondNode:
    tok = _Tokenizer(condition)
    node = _parse_or(tok, groups)
    if not tok.at_end():
        raise ASTBuildError(f"Unexpected token '{tok.peek()}' in condition '{condition}'")
    return node


def _parse_or(tok: _Tokenizer, groups: dict[str, SearchGroup]) -> CondNode:
    left = _parse_and(tok, groups)
    while tok.peek() and tok.peek().lower() == "or":
        tok.consume()
        right = _parse_and(tok, groups)
        left = OrNode(left, right)
    return left


def _parse_and(tok: _Tokenizer, groups: dict[str, SearchGroup]) -> CondNode:
    left = _parse_not(tok, groups)
    while tok.peek() and tok.peek().lower() == "and":
        tok.consume()
        right = _parse_not(tok, groups)
        left = AndNode(left, right)
    return left


def _parse_not(tok: _Tokenizer, groups: dict[str, SearchGroup]) -> CondNode:
    if tok.peek() and tok.peek().lower() == "not":
        tok.consume()
        operand = _parse_not(tok, groups)
        return NotNode(operand)
    return _parse_atom(tok, groups)


def _parse_atom(tok: _Tokenizer, groups: dict[str, SearchGroup]) -> CondNode:
    t = tok.peek()
    if t is None:
        raise ASTBuildError("Unexpected end of condition")

    # Parenthesized expression
    if t == "(":
        tok.consume()
        node = _parse_or(tok, groups)
        tok.expect(")")
        return node

    # Aggregation: "1 of <selector>" or "all of <selector>"
    t_lower = t.lower()
    if t_lower in ("1", "all"):
        quantifier = "one" if t_lower == "1" else "all"
        tok.consume()
        tok.expect("of")
        selector_tok = tok.consume()
        return AggNode(quantifier=quantifier, selector=selector_tok)

    # Named group reference
    tok.consume()
    # Validate that the group exists (warn but don't crash)
    if t not in groups:
        logger.warning("Condition references undefined group '%s'", t)
    return GroupRef(name=t)
