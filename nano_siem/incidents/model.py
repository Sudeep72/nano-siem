"""
incidents/model.py — Incident Lifecycle Model

Turns one or more correlated alerts into a first-class Incident object
with state, ownership, disposition, and analyst notes.

State machine:
  new → triaging → contained → closed
              ↓
           dismissed  (false positive / not actionable)

Disposition (set on close/dismiss):
  true_positive | false_positive | benign_true_positive | undetermined

The feedback loop lives here: when an analyst marks an incident as
false_positive, the source alert fingerprints are recorded so the
ML baseline retrainer can exclude or down-weight those events.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class IncidentState(str, Enum):
    NEW        = "new"
    TRIAGING   = "triaging"
    CONTAINED  = "contained"
    DISMISSED  = "dismissed"
    CLOSED     = "closed"


class Disposition(str, Enum):
    TRUE_POSITIVE        = "true_positive"
    FALSE_POSITIVE       = "false_positive"
    BENIGN_TRUE_POSITIVE = "benign_true_positive"
    UNDETERMINED         = "undetermined"


VALID_TRANSITIONS = {
    IncidentState.NEW:       {IncidentState.TRIAGING, IncidentState.DISMISSED},
    IncidentState.TRIAGING:  {IncidentState.CONTAINED, IncidentState.DISMISSED},
    IncidentState.CONTAINED: {IncidentState.CLOSED, IncidentState.TRIAGING},
    IncidentState.DISMISSED: set(),
    IncidentState.CLOSED:    set(),
}


@dataclass
class IncidentNote:
    author: str
    content: str
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {"author": self.author, "content": self.content, "timestamp": self.timestamp}


@dataclass
class Incident:
    incident_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    title: str = ""
    state: IncidentState = IncidentState.NEW
    severity: str = "medium"
    owner: str | None = None
    disposition: Disposition | None = None
    alert_ids: list[str] = field(default_factory=list)
    source_ips: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    mitre_tactic: str = ""
    notes: list[IncidentNote] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    closed_at: float | None = None
    # FP feedback — alert fingerprints to feed back into ML retrainer
    fp_fingerprints: list[str] = field(default_factory=list)

    def transition(self, new_state: IncidentState) -> None:
        allowed = VALID_TRANSITIONS.get(self.state, set())
        if new_state not in allowed:
            raise ValueError(
                f"Invalid transition: {self.state.value} → {new_state.value}. "
                f"Allowed: {[s.value for s in allowed]}"
            )
        self.state = new_state
        self.updated_at = time.time()
        if new_state in (IncidentState.CLOSED, IncidentState.DISMISSED):
            self.closed_at = time.time()

    def add_note(self, author: str, content: str) -> IncidentNote:
        note = IncidentNote(author=author, content=content)
        self.notes.append(note)
        self.updated_at = time.time()
        return note

    def set_disposition(self, disposition: Disposition, fingerprints: list[str] | None = None) -> None:
        self.disposition = disposition
        self.updated_at = time.time()
        if disposition == Disposition.FALSE_POSITIVE and fingerprints:
            self.fp_fingerprints = fingerprints

    @property
    def is_false_positive(self) -> bool:
        return self.disposition == Disposition.FALSE_POSITIVE

    @property
    def age_seconds(self) -> float:
        end = self.closed_at or time.time()
        return end - self.created_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "state": self.state.value,
            "severity": self.severity,
            "owner": self.owner,
            "disposition": self.disposition.value if self.disposition else None,
            "alert_ids": self.alert_ids,
            "source_ips": self.source_ips,
            "mitre_techniques": self.mitre_techniques,
            "mitre_tactic": self.mitre_tactic,
            "notes": [n.to_dict() for n in self.notes],
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "closed_at": self.closed_at,
            "fp_fingerprints": self.fp_fingerprints,
            "is_false_positive": self.is_false_positive,
            "age_seconds": round(self.age_seconds, 1),
        }


def incident_from_alert(alert: dict) -> Incident:
    """Create a new Incident from a single alert dict."""
    source = alert.get("source_key", "")
    return Incident(
        title=alert.get("title", "Untitled Incident"),
        severity=alert.get("severity", "medium"),
        alert_ids=[alert.get("alert_id", "")],
        source_ips=[source] if source else [],
        mitre_techniques=alert.get("mitre_techniques", []),
        mitre_tactic=alert.get("mitre_tactic", ""),
    )


def incident_from_alerts(alerts: list[dict], title: str | None = None) -> Incident:
    """Merge multiple related alerts into one incident."""
    if not alerts:
        raise ValueError("Cannot create incident from empty alert list")

    severities = [a.get("severity", "medium") for a in alerts]
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
    top_sev = max(severities, key=lambda s: sev_rank.get(s, 0))

    all_techniques = list({t for a in alerts for t in a.get("mitre_techniques", [])})
    all_ips = list({a.get("source_key", "") for a in alerts if a.get("source_key")})
    tactics = list({a.get("mitre_tactic", "") for a in alerts if a.get("mitre_tactic")})

    return Incident(
        title=title or alerts[0].get("title", "Untitled Incident"),
        severity=top_sev,
        alert_ids=[a.get("alert_id", "") for a in alerts],
        source_ips=all_ips,
        mitre_techniques=all_techniques,
        mitre_tactic=" → ".join(tactics) if tactics else "",
    )
