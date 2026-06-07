"""
chains.py — Attack Chain Rule Definitions

A ChainRule defines a multi-step attack pattern: a sequence of event tags
or sigma match titles that must appear from the same source within a time window.

Design:
  - Each step is a set of possible tags/sigma titles (OR within a step)
  - Steps must appear IN ORDER (not necessarily consecutive)
  - All steps must fire within window_seconds from the FIRST matching event
  - Grouping key: usually source_ip, but falls back to host

Built-in chains cover the most common attacker playbooks:
  1. Recon → Exploit        (scan then brute force)
  2. Brute Force → Success  (repeated failures then login)
  3. Login → Escalation     (SSH login then sudo/root exec)
  4. Scan → Web Probe       (port scan then admin panel access)
  5. Multi-stage Intrusion  (scan → brute → login → escalate)
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ChainStep:
    """
    One step in an attack chain.
    Fires if ANY of the matchers appear on an event from the tracked source.

    matchers: list of strings to check against:
      - event.sigma_matches  (rule title substrings)
      - event.tags           (tag substrings)
      - event.program        (exact)
    """
    name: str                      # human label for this step
    matchers: list[str]            # OR — any one of these fires the step


@dataclass
class ChainRule:
    """
    A complete multi-step attack chain definition.

    Attributes:
        id:              Unique identifier
        title:           Human-readable name
        description:     What this chain detects
        steps:           Ordered list of steps — must all fire in sequence
        window_seconds:  Max seconds between first and last step
        severity:        Alert severity if chain completes
        mitre_tactic:    Primary MITRE ATT&CK tactic
    """
    id: str
    title: str
    description: str
    steps: list[ChainStep]
    window_seconds: int = 300       # 5 minutes default
    severity: str = "high"
    mitre_tactic: str = ""
    mitre_techniques: list[str] = field(default_factory=list)


# ── Built-in chain rules ───────────────────────────────────────────────────────

BUILTIN_CHAINS: list[ChainRule] = [

    ChainRule(
        id="chain-001",
        title="Brute Force Followed by Successful Login",
        description=(
            "Detects repeated failed SSH authentication attempts from a source "
            "that subsequently achieves a successful login — the classic "
            "brute-force-to-access pattern."
        ),
        steps=[
            ChainStep(
                name="brute_force",
                matchers=["SSH Brute Force", "Failed password", "auth:failure"],
            ),
            ChainStep(
                name="successful_login",
                matchers=["SSH Successful Login", "Accepted password", "auth:success"],
            ),
        ],
        window_seconds=600,         # 10 minutes
        severity="critical",
        mitre_tactic="Credential Access → Initial Access",
        mitre_techniques=["T1110.001", "T1078"],
    ),

    ChainRule(
        id="chain-002",
        title="Port Scan Followed by Brute Force",
        description=(
            "Detects a reconnaissance port scan from a source that subsequently "
            "attempts brute-force authentication — recon-to-attack progression."
        ),
        steps=[
            ChainStep(
                name="port_scan",
                matchers=["Port Scan", "port scan", "portscan"],
            ),
            ChainStep(
                name="brute_force",
                matchers=["SSH Brute Force", "Failed password", "auth:failure"],
            ),
        ],
        window_seconds=300,
        severity="high",
        mitre_tactic="Discovery → Credential Access",
        mitre_techniques=["T1046", "T1110"],
    ),

    ChainRule(
        id="chain-003",
        title="Successful Login Followed by Privilege Escalation",
        description=(
            "Detects a successful login from a source followed by privilege "
            "escalation (sudo/root exec) — lateral movement to escalation chain."
        ),
        steps=[
            ChainStep(
                name="login",
                matchers=["SSH Successful Login", "Accepted password", "auth:success"],
            ),
            ChainStep(
                name="escalation",
                matchers=[
                    "Privilege Escalation",
                    "Suspicious Root Process",
                    "sudo",
                    "uid=0",
                ],
            ),
        ],
        window_seconds=900,         # 15 minutes
        severity="critical",
        mitre_tactic="Initial Access → Privilege Escalation",
        mitre_techniques=["T1078", "T1548.003"],
    ),

    ChainRule(
        id="chain-004",
        title="Port Scan → Web Admin Probe",
        description=(
            "Detects a port scan followed by HTTP requests to admin panel paths "
            "from the same source — automated attack tooling pattern."
        ),
        steps=[
            ChainStep(
                name="scan",
                matchers=["Port Scan", "portscan"],
            ),
            ChainStep(
                name="web_probe",
                matchers=["Web Admin Panel", "/admin", "wp-admin", "phpmyadmin"],
            ),
        ],
        window_seconds=180,
        severity="high",
        mitre_tactic="Discovery → Initial Access",
        mitre_techniques=["T1046", "T1190"],
    ),

    ChainRule(
        id="chain-005",
        title="Full Intrusion Kill Chain",
        description=(
            "Detects a complete multi-stage intrusion: scan → brute force → "
            "successful login → privilege escalation. High-confidence indicator "
            "of active compromise."
        ),
        steps=[
            ChainStep(
                name="recon",
                matchers=["Port Scan", "portscan"],
            ),
            ChainStep(
                name="brute_force",
                matchers=["SSH Brute Force", "Failed password", "auth:failure"],
            ),
            ChainStep(
                name="initial_access",
                matchers=["SSH Successful Login", "Accepted password", "auth:success"],
            ),
            ChainStep(
                name="escalation",
                matchers=["Privilege Escalation", "Suspicious Root Process", "uid=0"],
            ),
        ],
        window_seconds=1800,        # 30 minutes
        severity="critical",
        mitre_tactic="Full Kill Chain",
        mitre_techniques=["T1046", "T1110", "T1078", "T1548"],
    ),

    ChainRule(
        id="chain-006",
        title="Repeated Auth Failures from Single Source",
        description=(
            "Detects 3+ auth failure events from the same source within the window "
            "— threshold-based brute force detection complementing Sigma rule matching."
        ),
        steps=[
            ChainStep(name="fail_1", matchers=["auth:failure", "Failed password"]),
            ChainStep(name="fail_2", matchers=["auth:failure", "Failed password"]),
            ChainStep(name="fail_3", matchers=["auth:failure", "Failed password"]),
        ],
        window_seconds=120,
        severity="medium",
        mitre_tactic="Credential Access",
        mitre_techniques=["T1110"],
    ),
]

# Index by id for fast lookup
CHAIN_INDEX: dict[str, ChainRule] = {c.id: c for c in BUILTIN_CHAINS}
