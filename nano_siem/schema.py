"""
schema.py — Common Normalized Event Schema

Every log that enters nano-siem, regardless of source format (syslog, CEF, JSON),
gets converted into this structure. All downstream components (Sigma evaluator,
correlator, ML scorer, alerter) operate exclusively on NormalizedEvent dicts.

Schema design philosophy:
- Flat where possible (faster field lookups in Sigma evaluator)
- 'fields' dict captures format-specific key-values without polluting top-level
- 'tags' list accumulates labels as the event moves through the pipeline
  e.g. ["sigma:ssh_brute_force", "correlated:port_scan_chain", "ml:anomalous"]
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class NormalizedEvent:
    """
    The canonical event object that flows through the pipeline.

    Populated by ingestion/normalizer.py, then enriched by each stage.
    """

    # ── Identity ──────────────────────────────────────────────────────────────
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    # ── Timing ────────────────────────────────────────────────────────────────
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    ingested_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # ── Source ────────────────────────────────────────────────────────────────
    host: str = "unknown"           # originating hostname or IP
    source_ip: str | None = None    # parsed source IP if present
    dest_ip: str | None = None
    source_port: int | None = None
    dest_port: int | None = None

    # ── Log metadata ──────────────────────────────────────────────────────────
    log_source: str = "unknown"     # syslog | json | cef
    facility: str | None = None     # syslog facility (e.g. "auth", "daemon")
    severity: str | None = None     # syslog severity (e.g. "err", "warning")
    program: str | None = None      # process/program that generated the log
    pid: int | None = None

    # ── Content ───────────────────────────────────────────────────────────────
    message: str = ""               # human-readable log message
    raw: str = ""                   # original unmodified log line

    # ── Parsed key-values ─────────────────────────────────────────────────────
    fields: dict[str, Any] = field(default_factory=dict)

    # ── Pipeline enrichment ───────────────────────────────────────────────────
    tags: list[str] = field(default_factory=list)
    anomaly_score: float | None = None  # set by ML scorer (0.0–1.0)
    sigma_matches: list[str] = field(default_factory=list)  # rule titles that fired
    alert_id: str | None = None         # set when an alert is generated

    def to_dict(self) -> dict[str, Any]:
        """Serialize to plain dict for storage and STIX output."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "ingested_at": self.ingested_at.isoformat(),
            "host": self.host,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "source_port": self.source_port,
            "dest_port": self.dest_port,
            "log_source": self.log_source,
            "facility": self.facility,
            "severity": self.severity,
            "program": self.program,
            "pid": self.pid,
            "message": self.message,
            "raw": self.raw,
            "fields": self.fields,
            "tags": self.tags,
            "anomaly_score": self.anomaly_score,
            "sigma_matches": self.sigma_matches,
            "alert_id": self.alert_id,
        }

    def get_field(self, key: str) -> Any:
        """
        Unified field lookup used by the Sigma evaluator.

        Checks top-level attributes first, then falls back to fields dict.
        This lets Sigma rules reference both 'message' and 'fields.src_ip'
        with the same lookup interface.
        """
        # Top-level attribute lookup
        if hasattr(self, key):
            return getattr(self, key)
        # Nested fields dict lookup (dot-notation: "fields.username")
        if key.startswith("fields."):
            nested_key = key[7:]
            return self.fields.get(nested_key)
        # Direct fields dict lookup
        return self.fields.get(key)

    def add_tag(self, tag: str) -> None:
        if tag not in self.tags:
            self.tags.append(tag)

    def __repr__(self) -> str:
        return (
            f"NormalizedEvent(id={self.event_id[:8]}, "
            f"host={self.host}, program={self.program}, "
            f"msg={self.message[:60]!r})"
        )


# ── Syslog facility/severity maps ─────────────────────────────────────────────
# RFC 5424 — used by parser.py to decode numeric facility/severity codes

SYSLOG_FACILITIES = {
    0: "kern", 1: "user", 2: "mail", 3: "daemon",
    4: "auth", 5: "syslog", 6: "lpr", 7: "news",
    8: "uucp", 9: "cron", 10: "authpriv", 11: "ftp",
    16: "local0", 17: "local1", 18: "local2", 19: "local3",
    20: "local4", 21: "local5", 22: "local6", 23: "local7",
}

SYSLOG_SEVERITIES = {
    0: "emerg", 1: "alert", 2: "crit", 3: "err",
    4: "warning", 5: "notice", 6: "info", 7: "debug",
}
