"""
parser.py — Multi-format Log Parser

Detects the format of a raw log line and parses it into intermediate dicts.
Supports:
  - Syslog RFC 5424  (structured syslog with MSGID and SD elements)
  - Syslog RFC 3164  (traditional BSD syslog)
  - CEF              (ArcSight Common Event Format, used by many security tools)
  - JSON             (plain JSON log lines, e.g. from filebeat, fluentd)
  - Plaintext        (fallback — stores entire line as message)

The output of parse() feeds directly into normalizer.py which produces
a NormalizedEvent.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any

from nano_siem.schema import SYSLOG_FACILITIES, SYSLOG_SEVERITIES

logger = logging.getLogger(__name__)

# ── Format detection patterns ──────────────────────────────────────────────────

# RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
_RFC5424 = re.compile(
    r"^<(\d{1,3})>(\d)\s+"
    r"(\d{4}-\d{2}-\d{2}T[\d:\.]+(?:Z|[+-]\d{2}:\d{2})|-)\s+"
    r"(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+"
    r"(\[.*?\]|-)\s*(.*)"
)

# RFC 3164: <PRI>Mon DD HH:MM:SS hostname program[pid]: message
_RFC3164 = re.compile(
    r"^<(\d{1,3})>"
    r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(\S+)\s+"
    r"(\S+?)(?:\[(\d+)\])?:\s*(.*)"
)

# CEF prefix
_CEF_PREFIX = re.compile(r"^(?:<\d+>)?(?:\w{3}\s+\d+\s+[\d:]+\s+\S+\s+)?CEF:(\d+)\|")

# JSON
_JSON_PREFIX = re.compile(r"^\s*[\[{]")


# ── CEF extension parser ───────────────────────────────────────────────────────

def _parse_cef_extensions(ext_str: str) -> dict[str, str]:
    result: dict[str, str] = {}
    pattern = re.compile(r"(\w+)=((?:(?!(?:\s\w+=)).)*)", re.DOTALL)
    for match in pattern.finditer(ext_str):
        result[match.group(1).strip()] = match.group(2).strip()
    return result


# ── RFC 3164 timestamp parser ──────────────────────────────────────────────────

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

def _parse_3164_timestamp(ts_str: str) -> datetime:
    parts = ts_str.split()
    month = _MONTHS.get(parts[0], 1)
    day = int(parts[1])
    time_parts = parts[2].split(":")
    now = datetime.now(timezone.utc)
    try:
        return datetime(
            now.year, month, day,
            int(time_parts[0]), int(time_parts[1]), int(time_parts[2]),
            tzinfo=timezone.utc,
        )
    except ValueError:
        return now


# ── PRI decoder ───────────────────────────────────────────────────────────────

def _decode_pri(pri_str: str) -> tuple[str | None, str | None]:
    try:
        pri = int(pri_str)
        facility_code = pri >> 3
        severity_code = pri & 0x07
        return (
            SYSLOG_FACILITIES.get(facility_code),
            SYSLOG_SEVERITIES.get(severity_code),
        )
    except (ValueError, TypeError):
        return None, None


# ── Public API ─────────────────────────────────────────────────────────────────

class ParsedLog:
    """Intermediate representation between raw bytes and NormalizedEvent."""

    __slots__ = (
        "format", "timestamp", "host", "program", "pid",
        "facility", "severity", "message", "raw", "fields",
    )

    def __init__(self) -> None:
        self.format: str = "unknown"
        self.timestamp: datetime = datetime.now(timezone.utc)
        self.host: str = "unknown"
        self.program: str | None = None
        self.pid: int | None = None
        self.facility: str | None = None
        self.severity: str | None = None
        self.message: str = ""
        self.raw: str = ""
        self.fields: dict[str, Any] = {}


def parse(raw: str | bytes) -> ParsedLog:
    """
    Detect format and parse a raw log line into a ParsedLog.
    """
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8", errors="replace")
        except Exception:
            raw = str(raw)

    raw = raw.strip()
    result = ParsedLog()
    result.raw = raw

    # ── Try RFC 5424 ──────────────────────────────────────────────────────────
    m = _RFC5424.match(raw)
    if m:
        result.format = "syslog_rfc5424"
        result.facility, result.severity = _decode_pri(m.group(1))
        ts_str = m.group(3)
        if ts_str != "-":
            try:
                result.timestamp = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except ValueError:
                pass
        result.host = m.group(4) if m.group(4) != "-" else "unknown"
        result.program = m.group(5) if m.group(5) != "-" else None
        proc_id = m.group(6)
        if proc_id and proc_id != "-":
            try:
                result.pid = int(proc_id)
            except ValueError:
                pass
        result.message = m.group(9).strip()
        sd_str = m.group(8)
        if sd_str and sd_str != "-":
            sd_pattern = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')
            for sd_match in sd_pattern.finditer(sd_str):
                result.fields[sd_match.group(1)] = sd_match.group(2)
        return result

    # ── Try CEF ───────────────────────────────────────────────────────────────
    m = _CEF_PREFIX.match(raw)
    if m:
        result.format = "cef"
        cef_start = raw.index("CEF:")
        cef_body = raw[cef_start:]
        parts = cef_body.split("|", 8)
        if len(parts) >= 8:
            result.fields["cef_version"] = parts[0].replace("CEF:", "")
            result.fields["device_vendor"] = parts[1]
            result.fields["device_product"] = parts[2]
            result.fields["device_version"] = parts[3]
            result.fields["signature_id"] = parts[4]
            result.fields["name"] = parts[5]
            result.fields["cef_severity"] = parts[6]
            result.program = parts[2]
            result.message = parts[5]
            if len(parts) >= 8:
                result.fields.update(_parse_cef_extensions(parts[7]))
                if "src" in result.fields:
                    result.fields["source_ip"] = result.fields["src"]
                if "dst" in result.fields:
                    result.fields["dest_ip"] = result.fields["dst"]
                if "spt" in result.fields:
                    try:
                        result.fields["source_port"] = int(result.fields["spt"])
                    except ValueError:
                        pass
                if "dpt" in result.fields:
                    try:
                        result.fields["dest_port"] = int(result.fields["dpt"])
                    except ValueError:
                        pass
                if "dhost" in result.fields:
                    result.host = result.fields["dhost"]
                elif "shost" in result.fields:
                    result.host = result.fields["shost"]
        return result

    # ── Try JSON ──────────────────────────────────────────────────────────────
    if _JSON_PREFIX.match(raw):
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                result.format = "json"
                result.fields = data
                for ts_key in ("timestamp", "@timestamp", "time", "ts", "date"):
                    if ts_key in data:
                        try:
                            ts_val = data[ts_key]
                            if isinstance(ts_val, (int, float)):
                                result.timestamp = datetime.fromtimestamp(ts_val, tz=timezone.utc)
                            else:
                                result.timestamp = datetime.fromisoformat(
                                    str(ts_val).replace("Z", "+00:00")
                                )
                        except (ValueError, OSError):
                            pass
                        break
                for host_key in ("host", "hostname", "source_host", "logsource"):
                    if host_key in data:
                        result.host = str(data[host_key])
                        break
                for msg_key in ("message", "msg", "log", "event", "text"):
                    if msg_key in data:
                        result.message = str(data[msg_key])
                        break
                for prog_key in ("program", "process", "app", "application", "service"):
                    if prog_key in data:
                        result.program = str(data[prog_key])
                        break
                if "pid" in data:
                    try:
                        result.pid = int(data["pid"])
                    except (ValueError, TypeError):
                        pass
                if "level" in data or "severity" in data:
                    result.severity = str(data.get("level") or data.get("severity"))
                return result
        except (json.JSONDecodeError, ValueError):
            pass

    # ── Try RFC 3164 ──────────────────────────────────────────────────────────
    m = _RFC3164.match(raw)
    if m:
        result.format = "syslog_rfc3164"
        result.facility, result.severity = _decode_pri(m.group(1))
        result.timestamp = _parse_3164_timestamp(m.group(2))
        result.host = m.group(3)
        result.program = m.group(4)
        if m.group(5):
            try:
                result.pid = int(m.group(5))
            except ValueError:
                pass
        result.message = m.group(6).strip()
        return result

    # ── Fallback: plaintext ───────────────────────────────────────────────────
    result.format = "plaintext"
    result.message = raw
    return result
