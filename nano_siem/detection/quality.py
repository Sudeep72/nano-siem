"""
detection/quality.py — Rule Quality Metrics

Computes quality scores for Sigma rules to help detection engineers
prioritize rule maintenance and identify problem rules.

Metrics computed:
  - Complexity score:    AST depth, number of conditions, field modifiers used
  - Specificity score:   how narrow vs. broad the matchers are (keyword length,
                          field-match vs. plain keyword, presence of 'not' filters)
  - Overlap detection:   rules that match overlapping log patterns
                          (potential redundancy or alert fatigue)
  - FP risk estimate:    heuristic estimate based on specificity + falsepositives
                          documentation + test fixture coverage
  - Maintenance score:   composite 0-100 score combining all of the above

These are heuristics, not ground truth — they're meant to flag rules
for human review, not to replace validation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from nano_siem.sigma.ast import AggNode, AndNode, CondNode, GroupRef, NotNode, OrNode, build_ast
from nano_siem.sigma.loader import SigmaRule


@dataclass
class RuleQualityReport:
    rule_title: str
    source_file: str
    complexity_score: int          # 0+ — higher = more complex condition logic
    specificity_score: float       # 0-100 — higher = more specific/narrow
    fp_risk: str                   # "low" | "medium" | "high"
    fp_risk_reasons: list[str] = field(default_factory=list)
    maintenance_score: int = 0     # 0-100 composite — higher = healthier rule
    overlaps_with: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rule_title": self.rule_title,
            "source_file": self.source_file,
            "complexity_score": self.complexity_score,
            "specificity_score": round(self.specificity_score, 1),
            "fp_risk": self.fp_risk,
            "fp_risk_reasons": self.fp_risk_reasons,
            "maintenance_score": self.maintenance_score,
            "overlaps_with": self.overlaps_with,
        }


# ── AST complexity ────────────────────────────────────────────────────────────

def _ast_depth(node: CondNode) -> int:
    """Recursively compute the depth of a condition AST."""
    if isinstance(node, (AndNode, OrNode)):
        return 1 + max(_ast_depth(node.left), _ast_depth(node.right))
    if isinstance(node, NotNode):
        return 1 + _ast_depth(node.operand)
    if isinstance(node, AggNode):
        return 1
    if isinstance(node, GroupRef):
        return 0
    return 0


def _ast_node_count(node: CondNode) -> int:
    """Count total nodes in the condition AST (complexity proxy)."""
    if isinstance(node, (AndNode, OrNode)):
        return 1 + _ast_node_count(node.left) + _ast_node_count(node.right)
    if isinstance(node, NotNode):
        return 1 + _ast_node_count(node.operand)
    if isinstance(node, (AggNode, GroupRef)):
        return 1
    return 0


def _count_field_modifiers(rule: SigmaRule) -> int:
    """Count how many field|modifier patterns are used (re, contains, etc.)."""
    count = 0
    for key, value in rule.detection.items():
        if key == "condition":
            continue
        if isinstance(value, dict):
            for field_key in value.keys():
                if "|" in field_key:
                    count += 1
    return count


# ── Specificity ───────────────────────────────────────────────────────────────

def _compute_specificity(rule: SigmaRule) -> float:
    """
    Estimate how specific (narrow) a rule's matchers are, 0-100.
    Higher = more specific = less likely to false-positive on unrelated logs.

    Heuristics:
      - Longer keyword strings = more specific (less likely to match by chance)
      - Field-exact matches > field|contains > plain keyword
      - Presence of 'not' filters increases specificity
      - Very short keywords (<5 chars) heavily penalized
    """
    score = 50.0  # baseline
    total_keywords = 0
    short_keywords = 0
    field_matches = 0
    keyword_matches = 0

    for key, value in rule.detection.items():
        if key == "condition":
            continue
        if isinstance(value, list):
            for kw in value:
                total_keywords += 1
                keyword_matches += 1
                if isinstance(kw, str) and len(kw) < 5:
                    short_keywords += 1
        elif isinstance(value, dict):
            for field_key, field_val in value.items():
                vals = field_val if isinstance(field_val, list) else [field_val]
                for v in vals:
                    total_keywords += 1
                    field_matches += 1
                    if isinstance(v, str) and len(v) < 5:
                        short_keywords += 1

    if total_keywords == 0:
        return score

    # Field-based matches are more specific than plain keywords
    field_ratio = field_matches / total_keywords
    score += field_ratio * 20

    # Penalize short/generic keywords
    if total_keywords > 0:
        short_ratio = short_keywords / total_keywords
        score -= short_ratio * 30

    # Bonus for 'not' filters (excludes known-benign patterns)
    condition = rule.detection.get("condition", "")
    if " not " in f" {condition} ":
        score += 10

    return max(0.0, min(100.0, score))


# ── FP risk heuristic ──────────────────────────────────────────────────────────

def _estimate_fp_risk(rule: SigmaRule, specificity: float) -> tuple[str, list[str]]:
    """Estimate false-positive risk: low/medium/high, with reasons."""
    reasons = []
    risk_points = 0

    if specificity < 40:
        risk_points += 2
        reasons.append("Low specificity score — matchers may be too broad")

    if not rule.falsepositives:
        risk_points += 1
        reasons.append("No documented false positives — may be under-tested")

    # Single short keyword with OR condition = high FP risk
    condition = rule.detection.get("condition", "").lower()
    if " or " in condition and specificity < 50:
        risk_points += 1
        reasons.append("Broad OR condition combined with low specificity")

    if rule.level in ("low", "informational"):
        risk_points -= 1  # low-severity rules tolerate more FPs

    if risk_points >= 3:
        return "high", reasons
    elif risk_points >= 1:
        return "medium", reasons
    return "low", reasons or ["Well-specified rule with documented edge cases"]


# ── Overlap detection ────────────────────────────────────────────────────────

def _extract_keywords(rule: SigmaRule) -> set[str]:
    """Extract all literal keyword/value strings from a rule's detection block."""
    keywords = set()
    for key, value in rule.detection.items():
        if key == "condition":
            continue
        if isinstance(value, list):
            for v in value:
                if isinstance(v, str):
                    keywords.add(v.lower())
        elif isinstance(value, dict):
            for field_val in value.values():
                vals = field_val if isinstance(field_val, list) else [field_val]
                for v in vals:
                    if isinstance(v, str):
                        keywords.add(v.lower())
    return keywords


def _find_overlaps(rules: list[SigmaRule]) -> dict[str, list[str]]:
    """
    Find rules whose keyword sets significantly overlap.
    Returns rule_title -> [overlapping rule titles].
    Uses Jaccard similarity > 0.3 as the overlap threshold.
    """
    keyword_sets = {r.title: _extract_keywords(r) for r in rules}
    overlaps: dict[str, list[str]] = {r.title: [] for r in rules}

    titles = list(keyword_sets.keys())
    for i, title_a in enumerate(titles):
        set_a = keyword_sets[title_a]
        if not set_a:
            continue
        for title_b in titles[i + 1:]:
            set_b = keyword_sets[title_b]
            if not set_b:
                continue
            intersection = set_a & set_b
            union = set_a | set_b
            if not union:
                continue
            jaccard = len(intersection) / len(union)
            if jaccard > 0.3:
                overlaps[title_a].append(title_b)
                overlaps[title_b].append(title_a)

    return overlaps


# ── Public API ────────────────────────────────────────────────────────────────

def assess_rule_quality(
    rule: SigmaRule,
    all_rules: list[SigmaRule] | None = None,
    overlap_map: dict[str, list[str]] | None = None,
) -> RuleQualityReport:
    """
    Compute a quality report for a single rule.

    Args:
        rule:        The rule to assess.
        all_rules:   Full rule set, used for overlap detection if overlap_map not given.
        overlap_map: Precomputed overlap map (rule_title -> [overlapping titles]).
                     Use this when assessing many rules to avoid O(n^2) recomputation.
    """
    try:
        ast = build_ast(rule.detection, rule_title=rule.title)
        complexity = _ast_node_count(ast.condition)
        complexity += _count_field_modifiers(rule)
    except Exception:
        complexity = 0

    specificity = _compute_specificity(rule)
    fp_risk, fp_reasons = _estimate_fp_risk(rule, specificity)

    if overlap_map is not None:
        overlaps = overlap_map.get(rule.title, [])
    elif all_rules:
        overlaps = _find_overlaps(all_rules).get(rule.title, [])
    else:
        overlaps = []

    # Composite maintenance score (0-100)
    # Weighted: specificity 40%, fp_risk 30%, complexity penalty 15%, overlap penalty 15%
    fp_risk_score = {"low": 100, "medium": 60, "high": 20}[fp_risk]
    complexity_penalty = max(0, 100 - complexity * 5)
    overlap_penalty = max(0, 100 - len(overlaps) * 25)

    maintenance_score = round(
        specificity * 0.40
        + fp_risk_score * 0.30
        + complexity_penalty * 0.15
        + overlap_penalty * 0.15
    )

    return RuleQualityReport(
        rule_title=rule.title,
        source_file=Path(rule.source_file).name,
        complexity_score=complexity,
        specificity_score=specificity,
        fp_risk=fp_risk,
        fp_risk_reasons=fp_reasons,
        maintenance_score=max(0, min(100, maintenance_score)),
        overlaps_with=overlaps,
    )


def assess_all_rules(rules: list[SigmaRule]) -> list[RuleQualityReport]:
    """
    Compute quality reports for all rules, with overlap detection
    computed once and shared across all reports.
    """
    overlap_map = _find_overlaps(rules)
    return [assess_rule_quality(r, overlap_map=overlap_map) for r in rules]
