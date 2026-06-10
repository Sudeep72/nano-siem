"""
detection/mitre.py — MITRE ATT&CK Registry

Maps technique IDs (T1110, T1110.001) to human-readable names, tactics,
descriptions, and URLs. Used by the rule validator, coverage reporter,
and CLI to enrich output without requiring a network call.

Coverage source: MITRE ATT&CK Enterprise v14 (subset of most common techniques).
Full matrix: https://attack.mitre.org/
"""

from __future__ import annotations
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Technique:
    id: str                        # e.g. "T1110"
    sub_id: str | None             # e.g. "T1110.001", None for parent
    name: str
    tactic: str                    # primary tactic
    all_tactics: list[str]         # some techniques span multiple tactics
    description: str
    url: str
    is_subtechnique: bool = False

    @property
    def full_id(self) -> str:
        return self.sub_id if self.sub_id else self.id

    @property
    def display_name(self) -> str:
        return f"{self.full_id}: {self.name}"


# ── Registry ──────────────────────────────────────────────────────────────────
# Curated subset covering the most common techniques seen in detection rules.
# Format: (id, sub_id, name, tactic, all_tactics, description)

_RAW: list[tuple] = [
    # Credential Access
    ("T1110", None, "Brute Force", "Credential Access",
     ["Credential Access"],
     "Adversaries may use brute force techniques to gain access to accounts."),
    ("T1110", "T1110.001", "Password Guessing", "Credential Access",
     ["Credential Access"],
     "Adversaries guess passwords without prior knowledge of the correct one."),
    ("T1110", "T1110.002", "Password Cracking", "Credential Access",
     ["Credential Access"],
     "Adversaries may use tools to crack previously obtained credentials offline."),
    ("T1110", "T1110.003", "Password Spraying", "Credential Access",
     ["Credential Access"],
     "Adversaries use a single or small list of commonly used passwords against accounts."),
    ("T1110", "T1110.004", "Credential Stuffing", "Credential Access",
     ["Credential Access"],
     "Adversaries use credentials obtained from breach dumps of other sites."),
    ("T1078", None, "Valid Accounts", "Defense Evasion",
     ["Defense Evasion", "Initial Access", "Persistence", "Privilege Escalation"],
     "Adversaries may obtain and abuse credentials of existing accounts."),

    # Privilege Escalation
    ("T1548", None, "Abuse Elevation Control Mechanism", "Privilege Escalation",
     ["Privilege Escalation", "Defense Evasion"],
     "Adversaries may circumvent mechanisms designed to control elevate privileges."),
    ("T1548", "T1548.003", "Sudo and Sudo Caching", "Privilege Escalation",
     ["Privilege Escalation", "Defense Evasion"],
     "Adversaries may perform sudo caching and/or use the sudoers file to elevate privileges."),
    ("T1548", "T1548.001", "Setuid and Setgid", "Privilege Escalation",
     ["Privilege Escalation", "Defense Evasion"],
     "Adversaries may perform shell escapes or exploit vulnerabilities in setuid/setgid binaries."),

    # Execution
    ("T1059", None, "Command and Scripting Interpreter", "Execution",
     ["Execution"],
     "Adversaries may abuse command and script interpreters to execute commands."),
    ("T1059", "T1059.004", "Unix Shell", "Execution",
     ["Execution"],
     "Adversaries may abuse Unix shell commands and scripts for execution."),

    # Discovery
    ("T1046", None, "Network Service Discovery", "Discovery",
     ["Discovery"],
     "Adversaries may attempt to get a listing of services running on remote hosts."),
    ("T1083", None, "File and Directory Discovery", "Discovery",
     ["Discovery"],
     "Adversaries may enumerate files and directories to find sensitive data."),
    ("T1087", None, "Account Discovery", "Discovery",
     ["Discovery"],
     "Adversaries may attempt to get a listing of valid accounts."),

    # Lateral Movement
    ("T1021", None, "Remote Services", "Lateral Movement",
     ["Lateral Movement"],
     "Adversaries may use valid accounts to log into a service specifically designed for remote access."),
    ("T1021", "T1021.004", "SSH", "Lateral Movement",
     ["Lateral Movement"],
     "Adversaries may use valid accounts to log into remote machines using Secure Shell (SSH)."),

    # Initial Access
    ("T1190", None, "Exploit Public-Facing Application", "Initial Access",
     ["Initial Access"],
     "Adversaries may attempt to take advantage of a weakness in an Internet-facing host or system."),
    ("T1133", None, "External Remote Services", "Initial Access",
     ["Initial Access", "Persistence"],
     "Adversaries may leverage external-facing remote services to initially access a network."),

    # Command and Control
    ("T1071", None, "Application Layer Protocol", "Command and Control",
     ["Command and Control"],
     "Adversaries may communicate using application layer protocols to avoid detection."),
    ("T1059", "T1059.001", "PowerShell", "Execution",
     ["Execution"],
     "Adversaries may abuse PowerShell commands and scripts for execution."),

    # Persistence
    ("T1053", None, "Scheduled Task/Job", "Persistence",
     ["Persistence", "Privilege Escalation", "Execution"],
     "Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution."),
    ("T1053", "T1053.003", "Cron", "Persistence",
     ["Persistence", "Privilege Escalation", "Execution"],
     "Adversaries may abuse the cron utility to perform task scheduling for initial or recurring execution."),

    # Defense Evasion
    ("T1036", None, "Masquerading", "Defense Evasion",
     ["Defense Evasion"],
     "Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate."),

    # Impact
    ("T1486", None, "Data Encrypted for Impact", "Impact",
     ["Impact"],
     "Adversaries may encrypt data on target systems or on large numbers of systems in a network."),
    ("T1489", None, "Service Stop", "Impact",
     ["Impact"],
     "Adversaries may stop or disable services on a system to render those services unavailable."),
]

_BASE_URL = "https://attack.mitre.org/techniques/"


def _build_registry() -> dict[str, Technique]:
    registry: dict[str, Technique] = {}
    for row in _RAW:
        tid, sub_id, name, tactic, all_tactics, desc = row
        key = (sub_id or tid).upper()
        url = _BASE_URL + (sub_id or tid).replace(".", "/") + "/"
        registry[key] = Technique(
            id=tid,
            sub_id=sub_id,
            name=name,
            tactic=tactic,
            all_tactics=list(all_tactics),
            description=desc,
            url=url,
            is_subtechnique=sub_id is not None,
        )
    return registry


REGISTRY: dict[str, Technique] = _build_registry()


def lookup(technique_id: str) -> Technique | None:
    """
    Look up a technique by ID. Case-insensitive.
    Accepts: "T1110", "t1110", "T1110.001", "attack.t1110.001"
    """
    # Strip "attack." prefix if present
    clean = technique_id.strip().upper()
    if clean.startswith("ATTACK."):
        clean = clean[7:]
    return REGISTRY.get(clean)


def techniques_for_tags(tags: list[str]) -> list[Technique]:
    """Extract all known MITRE techniques from a Sigma rule's tags list."""
    results = []
    seen = set()
    for tag in tags:
        t = lookup(tag)
        if t and t.full_id not in seen:
            results.append(t)
            seen.add(t.full_id)
    return results


def coverage_summary(rules: list) -> dict[str, list[str]]:
    """
    Given a list of SigmaRule objects, return a tactic → [technique names] map
    showing which ATT&CK tactics/techniques are covered.
    """
    coverage: dict[str, list[str]] = {}
    for rule in rules:
        for tech in techniques_for_tags(rule.tags):
            tactic = tech.tactic
            entry = tech.display_name
            if tactic not in coverage:
                coverage[tactic] = []
            if entry not in coverage[tactic]:
                coverage[tactic].append(entry)
    return coverage
