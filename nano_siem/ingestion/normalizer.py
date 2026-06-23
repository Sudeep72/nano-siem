"""
normalizer.py — ParsedLog → NormalizedEvent

Takes the output of parser.py and maps it into the canonical NormalizedEvent
schema. Also extracts common security-relevant fields from log messages using
lightweight regex patterns (no heavy NLP — this is nano-siem).

Security field extraction covers:
  - IP addresses (source/dest)
  - Port numbers
  - Usernames
  - File paths
  - Process names
  - HTTP methods and status codes
  - Authentication outcomes (success/failure keywords)
"""

from __future__ import annotations

import logging
import re
from typing import Any

from nano_siem.ingestion.parser import ParsedLog
from nano_siem.schema import NormalizedEvent

logger = logging.getLogger(__name__)

# ── Security-relevant field extractors ────────────────────────────────────────
# Applied to the message field to pull out structured data from unstructured text

_RE_IPV4 = re.compile(
    r"\b((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?))\b"
)
_RE_PORT = re.compile(r"(?:port|dport|sport|dst_port|src_port)\s*[=:]?\s*(\d{1,5})", re.IGNORECASE)
_RE_USER = re.compile(
    r"(?:user|username|for user|invalid user|for)\s+([A-Za-z0-9_\.\-\@]+)", re.IGNORECASE
)
_RE_PID_IN_MSG = re.compile(r"\bpid[=:\s]+(\d+)\b", re.IGNORECASE)
_RE_FILEPATH = re.compile(r"(?:/[\w\.\-]+){2,}")
_RE_HTTP_METHOD = re.compile(r"\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)\b")
_RE_HTTP_STATUS = re.compile(r"HTTP/\d\.\d.\s+(\d{3})|status[=:\s]+(\d{3})", re.IGNORECASE)
_RE_AUTH_FAILURE = re.compile(
    r"\b(failed|failure|invalid|refused|denied|rejected|unauthorized|incorrect)\b",
    re.IGNORECASE,
)
_RE_AUTH_SUCCESS = re.compile(
    r"\b(accepted|success|succeeded|logged in|authenticated|granted)\b",
    re.IGNORECASE,
)

# Known authentication/security programs — used to tag events
_AUTH_PROGRAMS = frozenset({
    "sshd", "sudo", "su", "login", "pam", "auth", "passwd",
    "slapd", "krb5kdc", "gdm", "lightdm", "polkit",
})
_NETWORK_PROGRAMS = frozenset({
    "firewalld", "iptables", "nftables", "ufw", "fail2ban",
    "snort", "suricata", "zeek", "bro", "tcpdump",
})


def normalize(parsed: ParsedLog) -> NormalizedEvent:
    """
    Convert a ParsedLog into a NormalizedEvent.

    Field mapping priority (highest to lowest):
      1. Explicit top-level fields from parser (host, program, pid, etc.)
      2. Format-specific fields dict (CEF src/dst, JSON fields)
      3. Regex extraction from message text
    """
    event = NormalizedEvent()

    # ── Copy core fields ──────────────────────────────────────────────────────
    event.timestamp = parsed.timestamp
    event.host = parsed.host
    event.program = parsed.program
    event.pid = parsed.pid
    event.facility = parsed.facility
    event.severity = parsed.severity
    event.message = parsed.message
    event.raw = parsed.raw
    event.log_source = parsed.format
    event.fields = dict(parsed.fields)  # shallow copy

    # ── Extract IPs from fields dict (CEF / JSON) ─────────────────────────────
    event.source_ip = _coerce_str(
        parsed.fields.get("source_ip")
        or parsed.fields.get("src")
        or parsed.fields.get("src_ip")
        or parsed.fields.get("sourceAddress")
    )
    event.dest_ip = _coerce_str(
        parsed.fields.get("dest_ip")
        or parsed.fields.get("dst")
        or parsed.fields.get("dst_ip")
        or parsed.fields.get("destinationAddress")
    )
    event.source_port = _coerce_int(
        parsed.fields.get("source_port")
        or parsed.fields.get("spt")
        or parsed.fields.get("sourcePort")
    )
    event.dest_port = _coerce_int(
        parsed.fields.get("dest_port")
        or parsed.fields.get("dpt")
        or parsed.fields.get("destinationPort")
    )

    # ── Regex extraction from message (fills gaps left by structured formats) ─
    _extract_from_message(event)

    # ── Tag events by program category ───────────────────────────────────────
    if event.program:
        prog_lower = event.program.lower()
        if prog_lower in _AUTH_PROGRAMS:
            event.add_tag("category:auth")
        if prog_lower in _NETWORK_PROGRAMS:
            event.add_tag("category:network")

    # ── Tag auth outcomes ─────────────────────────────────────────────────────
    if event.message:
        if _RE_AUTH_FAILURE.search(event.message):
            event.add_tag("auth:failure")
        if _RE_AUTH_SUCCESS.search(event.message):
            event.add_tag("auth:success")

    return event


def _extract_from_message(event: NormalizedEvent) -> None:
    """Apply regex extractors to message text, filling empty fields."""
    msg = event.message
    if not msg:
        return

    # IP extraction — first two IPs found become src/dst if not already set
    ips = _RE_IPV4.findall(msg)
    if ips:
        if not event.source_ip and len(ips) >= 1:
            event.source_ip = ips[0]
            event.fields.setdefault("extracted_src_ip", ips[0])
        if not event.dest_ip and len(ips) >= 2:
            event.dest_ip = ips[1]
            event.fields.setdefault("extracted_dst_ip", ips[1])

    # Port extraction
    port_match = _RE_PORT.search(msg)
    if port_match and not event.dest_port:
        try:
            event.dest_port = int(port_match.group(1))
        except ValueError:
            pass

    # Username extraction
    user_match = _RE_USER.search(msg)
    if user_match:
        username = user_match.group(1).strip()
        # Filter out common false positives
        if username and len(username) < 64 and username not in {"from", "by", "for"}:
            event.fields.setdefault("username", username)

    # PID from message (if not already set by parser)
    if not event.pid:
        pid_match = _RE_PID_IN_MSG.search(msg)
        if pid_match:
            try:
                event.pid = int(pid_match.group(1))
            except ValueError:
                pass

    # File paths
    fp_matches = _RE_FILEPATH.findall(msg)
    if fp_matches:
        event.fields.setdefault("file_paths", fp_matches[:5])  # cap at 5

    # HTTP method
    http_match = _RE_HTTP_METHOD.search(msg)
    if http_match:
        event.fields.setdefault("http_method", http_match.group(1))

    # HTTP status code
    status_match = _RE_HTTP_STATUS.search(msg)
    if status_match:
        code = status_match.group(1) or status_match.group(2)
        if code:
            try:
                event.fields.setdefault("http_status", int(code))
            except ValueError:
                pass


def _coerce_str(val: Any) -> str | None:
    if val is None:
        return None
    s = str(val).strip()
    return s if s else None


def _coerce_int(val: Any) -> int | None:
    if val is None:
        return None
    try:
        return int(val)
    except (ValueError, TypeError):
        return None
