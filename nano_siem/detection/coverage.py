"""
detection/coverage.py — ATT&CK Coverage Reporter

Generates a coverage report showing which MITRE ATT&CK tactics and techniques
are covered by the loaded Sigma rules and correlation chains.

Output formats:
  - Console table (rich)
  - JSON (for CI integration / badge generation)
  - Markdown (for README / documentation)

Coverage is calculated per-tactic and shows:
  - How many techniques in that tactic are covered
  - Which specific techniques are covered
  - Which rules cover each technique
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from nano_siem.correlation.chains import BUILTIN_CHAINS, ChainRule
from nano_siem.detection.mitre import (
    REGISTRY,
    Technique,
    techniques_for_tags,
)
from nano_siem.sigma.loader import SigmaRule

# ── All tactics in ATT&CK Enterprise (ordered) ───────────────────────────────
TACTIC_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


@dataclass
class TechniqueEntry:
    technique: Technique
    covered_by_rules: list[str] = field(default_factory=list)      # rule titles
    covered_by_chains: list[str] = field(default_factory=list)     # chain titles


@dataclass
class CoverageReport:
    total_rules: int
    total_chains: int
    tactics: dict[str, list[TechniqueEntry]]   # tactic → covered techniques
    uncovered_techniques: list[Technique]       # known techniques with no coverage

    @property
    def total_techniques_covered(self) -> int:
        return sum(len(entries) for entries in self.tactics.values())

    @property
    def coverage_percent(self) -> float:
        total_known = len(REGISTRY)
        if total_known == 0:
            return 0.0
        return (self.total_techniques_covered / total_known) * 100

    def to_dict(self) -> dict:
        return {
            "total_rules": self.total_rules,
            "total_chains": self.total_chains,
            "techniques_covered": self.total_techniques_covered,
            "techniques_known": len(REGISTRY),
            "coverage_percent": round(self.coverage_percent, 1),
            "tactics": {
                tactic: [
                    {
                        "technique_id": e.technique.full_id,
                        "technique_name": e.technique.name,
                        "covered_by_rules": e.covered_by_rules,
                        "covered_by_chains": e.covered_by_chains,
                    }
                    for e in entries
                ]
                for tactic, entries in self.tactics.items()
            },
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_markdown(self) -> str:
        lines = [
            "# NanoSIEM ATT&CK Coverage Report",
            "",
            f"**Rules loaded:** {self.total_rules}  ",
            f"**Chains loaded:** {self.total_chains}  ",
            f"**Techniques covered:** {self.total_techniques_covered} / {len(REGISTRY)}  ",
            f"**Coverage:** {self.coverage_percent:.1f}%",
            "",
            "---",
            "",
        ]
        for tactic in TACTIC_ORDER:
            entries = self.tactics.get(tactic, [])
            if not entries:
                continue
            lines.append(f"## {tactic}")
            lines.append("")
            lines.append("| Technique | ID | Covered By |")
            lines.append("|---|---|---|")
            for entry in entries:
                covered = []
                covered.extend(f"Rule: {r}" for r in entry.covered_by_rules)
                covered.extend(f"Chain: {c}" for c in entry.covered_by_chains)
                covered_str = ", ".join(covered) if covered else "—"
                lines.append(
                    f"| {entry.technique.name} | "
                    f"[{entry.technique.full_id}]({entry.technique.url}) | "
                    f"{covered_str} |"
                )
            lines.append("")
        return "\n".join(lines)


# ── Builder ───────────────────────────────────────────────────────────────────

def build_coverage_report(
    rules: list[SigmaRule],
    chains: list[ChainRule] | None = None,
) -> CoverageReport:
    """
    Build a CoverageReport from loaded rules and chains.

    Args:
        rules:  List of SigmaRule objects from the Sigma engine.
        chains: List of ChainRule objects (defaults to BUILTIN_CHAINS).
    """
    if chains is None:
        chains = BUILTIN_CHAINS

    # technique_id → TechniqueEntry
    covered: dict[str, TechniqueEntry] = {}

    # Process Sigma rules
    for rule in rules:
        for tech in techniques_for_tags(rule.tags):
            key = tech.full_id
            if key not in covered:
                covered[key] = TechniqueEntry(technique=tech)
            covered[key].covered_by_rules.append(rule.title)

    # Process correlation chains
    for chain in chains:
        for tech_id in chain.mitre_techniques:
            from nano_siem.detection.mitre import lookup
            tech = lookup(tech_id)
            if tech:
                key = tech.full_id
                if key not in covered:
                    covered[key] = TechniqueEntry(technique=tech)
                covered[key].covered_by_chains.append(chain.title)

    # Group by tactic
    tactics: dict[str, list[TechniqueEntry]] = {}
    for entry in covered.values():
        tactic = entry.technique.tactic
        if tactic not in tactics:
            tactics[tactic] = []
        tactics[tactic].append(entry)

    # Sort each tactic's entries by technique ID
    for tactic in tactics:
        tactics[tactic].sort(key=lambda e: e.technique.full_id)

    # Find uncovered techniques
    uncovered = [
        tech for tid, tech in REGISTRY.items()
        if tid not in covered
    ]

    return CoverageReport(
        total_rules=len(rules),
        total_chains=len(chains),
        tactics=tactics,
        uncovered_techniques=uncovered,
    )
