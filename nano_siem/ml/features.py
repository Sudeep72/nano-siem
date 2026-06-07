"""
ml/features.py — Event Feature Extractor

Converts a NormalizedEvent into a fixed-length numeric feature vector
for the Isolation Forest scorer.

Design constraints:
  - Zero heavy dependencies (no pandas, no torch)
  - Fast: must not be the bottleneck at 39k events/sec
  - Deterministic: same event always → same vector
  - Interpretable: every feature has a name, used for XAI output

Feature categories (31 total — matches ZeroSight in your resume):

  [0-4]   Temporal features
    0: hour_of_day          0-23 (normalized 0-1)
    1: minute_of_hour       0-59 (normalized 0-1)
    2: is_weekend           0 or 1
    3: is_off_hours         1 if hour < 6 or hour >= 22 else 0
    4: is_business_hours    1 if 8 <= hour < 18 and not weekend

  [5-9]   Source/network features
    5:  has_source_ip       0 or 1
    6:  source_ip_octet1    first octet / 255 (0-1)
    7:  source_ip_is_rfc1918 1 if private IP
    8:  dest_port_norm      dest_port / 65535 (0-1), 0 if None
    9:  source_port_norm    source_port / 65535 (0-1), 0 if None

  [10-14]  Port/protocol features
    10: is_common_port      1 if dest_port in {22,80,443,3306,5432,6379,...}
    11: is_high_port        1 if dest_port > 1024
    12: is_privileged_port  1 if dest_port <= 1024
    13: dest_port_bucket    0-9 (port range bucket)
    14: has_dest_port       0 or 1

  [15-19]  Log source / program features
    15: log_source_enc      encoded format (syslog5424=0.2, 3164=0.4, cef=0.6, json=0.8, plain=1.0)
    16: is_auth_program     1 if program in known auth programs
    17: is_network_program  1 if program in known network programs
    18: program_hash_norm   stable hash of program name / 1e6 (mod)
    19: has_pid             0 or 1

  [20-24]  Message content features
    20: message_length_norm  len(message) / 512 capped at 1.0
    21: has_ip_in_message   1 if IP pattern in message
    22: has_failure_keyword  1 if failure keyword in message
    23: has_success_keyword  1 if success keyword in message
    24: has_path_in_message  1 if filesystem path in message

  [25-29]  Severity/facility features
    25: severity_enc        emerg=1.0 down to debug=0.14 (0 if unknown)
    26: facility_enc        auth/authpriv=1.0, kern=0.9, etc.
    27: has_severity        0 or 1
    28: is_error_severity   1 if severity in (emerg, alert, crit, err)
    29: is_info_severity    1 if severity in (notice, info, debug)

  [30]    Tag/enrichment features
    30: tag_count_norm      len(tags) / 10 capped at 1.0
"""

from __future__ import annotations

import re
from datetime import timezone

from nano_siem.schema import NormalizedEvent

# ── Constants ─────────────────────────────────────────────────────────────────

FEATURE_NAMES = [
    "hour_of_day", "minute_of_hour", "is_weekend", "is_off_hours", "is_business_hours",
    "has_source_ip", "source_ip_octet1", "source_ip_is_rfc1918", "dest_port_norm", "source_port_norm",
    "is_common_port", "is_high_port", "is_privileged_port", "dest_port_bucket", "has_dest_port",
    "log_source_enc", "is_auth_program", "is_network_program", "program_hash_norm", "has_pid",
    "message_length_norm", "has_ip_in_message", "has_failure_keyword", "has_success_keyword", "has_path_in_message",
    "severity_enc", "facility_enc", "has_severity", "is_error_severity", "is_info_severity",
    "tag_count_norm",
]

FEATURE_DIM = len(FEATURE_NAMES)  # 31

_COMMON_PORTS = frozenset({
    20, 21, 22, 23, 25, 53, 80, 110, 143, 443,
    465, 587, 993, 995, 1433, 1521, 3306, 3389,
    5432, 5900, 6379, 8080, 8443, 27017,
})

_AUTH_PROGRAMS = frozenset({
    "sshd", "sudo", "su", "login", "pam", "auth", "passwd",
    "slapd", "krb5kdc", "gdm", "lightdm", "polkit",
})

_NETWORK_PROGRAMS = frozenset({
    "firewalld", "iptables", "nftables", "ufw", "fail2ban",
    "snort", "suricata", "zeek", "bro", "tcpdump", "nginx", "apache",
})

_LOG_SOURCE_ENC = {
    "syslog_rfc5424": 0.2,
    "syslog_rfc3164": 0.4,
    "cef": 0.6,
    "json": 0.8,
    "plaintext": 1.0,
    "file": 0.3,
    "unknown": 0.5,
}

_SEVERITY_ENC = {
    "emerg": 1.0, "alert": 0.86, "crit": 0.72, "err": 0.58,
    "warning": 0.44, "notice": 0.30, "info": 0.16, "debug": 0.08,
}

_FACILITY_ENC = {
    "auth": 1.0, "authpriv": 1.0, "kern": 0.9, "daemon": 0.7,
    "syslog": 0.6, "user": 0.5, "mail": 0.4, "cron": 0.4,
    "ftp": 0.3, "news": 0.2, "lpr": 0.2, "uucp": 0.2,
    "local0": 0.1, "local1": 0.1, "local2": 0.1, "local3": 0.1,
    "local4": 0.1, "local5": 0.1, "local6": 0.1, "local7": 0.1,
}

_RFC1918 = [
    (10, 0, 0, 0, 8),       # 10.0.0.0/8
    (172, 16, 0, 0, 12),    # 172.16.0.0/12
    (192, 168, 0, 0, 16),   # 192.168.0.0/16
]

_RE_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_FAIL = re.compile(
    r"\b(fail\w*|error\w*|denied|reject\w*|invalid|unauthori[sz]\w*|refused|incorrect)",
    re.IGNORECASE,
)
_RE_SUCCESS = re.compile(
    r"\b(accept\w*|success\w*|granted|authenticated|logged.in|connected)",
    re.IGNORECASE,
)
_RE_PATH = re.compile(r"(?:/[\w.\-]+){2,}")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_rfc1918(ip_str: str) -> bool:
    try:
        parts = [int(x) for x in ip_str.split(".")]
        if len(parts) != 4:
            return False
        # 10.x.x.x
        if parts[0] == 10:
            return True
        # 172.16-31.x.x
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        # 192.168.x.x
        if parts[0] == 192 and parts[1] == 168:
            return True
    except (ValueError, IndexError):
        pass
    return False


def _port_bucket(port: int) -> float:
    """Map port number to 0-9 bucket, normalized to 0-1."""
    if port <= 0:
        return 0.0
    if port <= 80:
        return 0.1
    if port <= 443:
        return 0.2
    if port <= 1024:
        return 0.3
    if port <= 3306:
        return 0.4
    if port <= 5432:
        return 0.5
    if port <= 8080:
        return 0.6
    if port <= 8443:
        return 0.7
    if port <= 32768:
        return 0.8
    return 0.9   # ephemeral


def _stable_hash(s: str) -> float:
    """Deterministic hash of a string → float in [0, 1]."""
    h = 0
    for ch in s:
        h = (h * 31 + ord(ch)) & 0xFFFFFF
    return h / 0xFFFFFF


# ── Public API ────────────────────────────────────────────────────────────────

def extract(event: NormalizedEvent) -> list[float]:
    """
    Extract a 31-dimensional feature vector from a NormalizedEvent.

    Returns:
        List of 31 floats, all in [0.0, 1.0].
        Always returns exactly FEATURE_DIM values — never raises.
    """
    vec: list[float] = [0.0] * FEATURE_DIM

    # ── Temporal [0-4] ────────────────────────────────────────────────────────
    try:
        ts = event.timestamp
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        hour = ts.hour
        minute = ts.minute
        weekday = ts.weekday()  # 0=Mon, 6=Sun

        vec[0] = hour / 23.0
        vec[1] = minute / 59.0
        vec[2] = 1.0 if weekday >= 5 else 0.0
        vec[3] = 1.0 if (hour < 6 or hour >= 22) else 0.0
        vec[4] = 1.0 if (8 <= hour < 18 and weekday < 5) else 0.0
    except Exception:
        pass

    # ── Source/network [5-9] ──────────────────────────────────────────────────
    src_ip = event.source_ip
    if src_ip:
        vec[5] = 1.0
        try:
            octet1 = int(src_ip.split(".")[0])
            vec[6] = octet1 / 255.0
        except (ValueError, IndexError):
            pass
        vec[7] = 1.0 if _is_rfc1918(src_ip) else 0.0

    if event.dest_port:
        vec[8] = min(event.dest_port / 65535.0, 1.0)
    if event.source_port:
        vec[9] = min(event.source_port / 65535.0, 1.0)

    # ── Port/protocol [10-14] ─────────────────────────────────────────────────
    dport = event.dest_port or 0
    if dport:
        vec[10] = 1.0 if dport in _COMMON_PORTS else 0.0
        vec[11] = 1.0 if dport > 1024 else 0.0
        vec[12] = 1.0 if dport <= 1024 else 0.0
        vec[13] = _port_bucket(dport)
        vec[14] = 1.0

    # ── Log source / program [15-19] ──────────────────────────────────────────
    vec[15] = _LOG_SOURCE_ENC.get(event.log_source, 0.5)

    prog = (event.program or "").lower()
    if prog:
        vec[16] = 1.0 if prog in _AUTH_PROGRAMS else 0.0
        vec[17] = 1.0 if prog in _NETWORK_PROGRAMS else 0.0
        vec[18] = _stable_hash(prog)

    vec[19] = 1.0 if event.pid is not None else 0.0

    # ── Message content [20-24] ───────────────────────────────────────────────
    msg = event.message or ""
    vec[20] = min(len(msg) / 512.0, 1.0)
    vec[21] = 1.0 if _RE_IP.search(msg) else 0.0
    vec[22] = 1.0 if _RE_FAIL.search(msg) else 0.0
    vec[23] = 1.0 if _RE_SUCCESS.search(msg) else 0.0
    vec[24] = 1.0 if _RE_PATH.search(msg) else 0.0

    # ── Severity / facility [25-29] ───────────────────────────────────────────
    sev = (event.severity or "").lower()
    fac = (event.facility or "").lower()

    if sev:
        vec[25] = _SEVERITY_ENC.get(sev, 0.0)
        vec[27] = 1.0
        vec[28] = 1.0 if sev in ("emerg", "alert", "crit", "err") else 0.0
        vec[29] = 1.0 if sev in ("notice", "info", "debug") else 0.0

    if fac:
        vec[26] = _FACILITY_ENC.get(fac, 0.1)

    # ── Tags [30] ─────────────────────────────────────────────────────────────
    vec[30] = min(len(event.tags) / 10.0, 1.0)

    return vec


def top_features(
    vector: list[float],
    baseline_vector: list[float] | None = None,
    n: int = 5,
) -> list[tuple[str, float]]:
    """
    Return the top-n features by absolute deviation from baseline.
    Used for XAI: "why did this event score as anomalous?"

    If no baseline provided, returns top-n by raw value.

    Returns:
        List of (feature_name, value) sorted by deviation descending.
    """
    if baseline_vector:
        deviations = [
            (FEATURE_NAMES[i], abs(vector[i] - baseline_vector[i]))
            for i in range(FEATURE_DIM)
        ]
    else:
        deviations = [
            (FEATURE_NAMES[i], vector[i])
            for i in range(FEATURE_DIM)
        ]
    return sorted(deviations, key=lambda x: x[1], reverse=True)[:n]
