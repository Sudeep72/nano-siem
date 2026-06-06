"""
test_parser.py — Unit tests for ingestion/parser.py

Tests every supported format: RFC 5424, RFC 3164, CEF, JSON, plaintext.
Each test validates that the correct format is detected and key fields parsed.
"""

import pytest
from datetime import timezone
from nano_siem.ingestion.parser import parse, ParsedLog


# ── RFC 5424 ──────────────────────────────────────────────────────────────────

class TestRFC5424:
    def test_basic_parse(self):
        line = "<34>1 2026-06-02T10:00:01.123Z web-01 sshd 1234 - - Failed password for root"
        r = parse(line)
        assert r.format == "syslog_rfc5424"
        assert r.host == "web-01"
        assert r.program == "sshd"
        assert r.pid == 1234
        assert "Failed password" in r.message

    def test_facility_severity_decoded(self):
        # PRI 34 = facility 4 (auth), severity 2 (crit)
        r = parse("<34>1 2026-06-02T10:00:00Z host app - - - msg")
        assert r.facility == "auth"
        assert r.severity == "crit"

    def test_nil_hostname(self):
        r = parse("<13>1 2026-06-02T10:00:00Z - - - - - test message")
        assert r.format == "syslog_rfc5424"
        assert r.host == "unknown"
        assert "test message" in r.message

    def test_nil_procid(self):
        r = parse("<13>1 2026-06-02T10:00:00Z host app - - - msg")
        assert r.pid is None

    def test_structured_data_parsed(self):
        line = '<13>1 2026-06-02T10:00:00Z host app 1 ID1 [exampleSDID@32473 iut="3" eventSource="Application"] msg'
        r = parse(line)
        assert r.format == "syslog_rfc5424"
        assert r.fields.get("iut") == "3"

    def test_timestamp_parsed(self):
        r = parse("<13>1 2026-06-02T10:30:00Z host app - - - msg")
        assert r.timestamp.year == 2026
        assert r.timestamp.month == 6
        assert r.timestamp.tzinfo == timezone.utc


# ── RFC 3164 ──────────────────────────────────────────────────────────────────

class TestRFC3164:
    def test_basic_parse(self):
        line = "<86>Jun  2 10:00:05 db-server postgres[5678]: auth failed"
        r = parse(line)
        assert r.format == "syslog_rfc3164"
        assert r.host == "db-server"
        assert r.program == "postgres"
        assert r.pid == 5678
        assert r.message == "auth failed"

    def test_no_pid(self):
        line = "<13>Jun  2 10:00:05 host syslog: system started"
        r = parse(line)
        assert r.format == "syslog_rfc3164"
        assert r.pid is None

    def test_facility_severity(self):
        # PRI 86 = facility 10 (authpriv), severity 6 (info)
        r = parse("<86>Jun  2 10:00:05 host sshd[1]: Accepted")
        assert r.facility == "authpriv"
        assert r.severity == "info"

    def test_timestamp_uses_current_year(self):
        r = parse("<13>Jun  2 10:00:05 host syslog: msg")
        assert r.timestamp is not None
        assert r.timestamp.hour == 10
        assert r.timestamp.minute == 0
        assert r.timestamp.second == 5


# ── CEF ───────────────────────────────────────────────────────────────────────

class TestCEF:
    def test_basic_parse(self):
        line = "CEF:0|Cisco|ASA|9.8|106023|Deny tcp|7|src=10.0.0.1 spt=54321 dst=192.168.1.10 dpt=80"
        r = parse(line)
        assert r.format == "cef"
        assert r.fields["device_vendor"] == "Cisco"
        assert r.fields["device_product"] == "ASA"
        assert r.fields["signature_id"] == "106023"
        assert r.fields.get("source_ip") == "10.0.0.1"
        assert r.fields.get("dest_port") == 80

    def test_message_is_cef_name(self):
        line = "CEF:0|V|P|1.0|id|SQL Injection Attempt|9|src=1.2.3.4"
        r = parse(line)
        assert r.message == "SQL Injection Attempt"

    def test_program_is_device_product(self):
        line = "CEF:0|Palo Alto|NGFW|10.1|threat|Block|8|"
        r = parse(line)
        assert r.program == "NGFW"

    def test_host_from_dhost(self):
        line = "CEF:0|V|P|1|id|name|5|src=1.1.1.1 dhost=target-server dpt=443"
        r = parse(line)
        assert r.host == "target-server"

    def test_syslog_prefix_stripped(self):
        line = "<13>Jun  2 10:00:00 fw CEF:0|V|P|1|id|name|5|src=1.2.3.4"
        r = parse(line)
        assert r.format == "cef"


# ── JSON ──────────────────────────────────────────────────────────────────────

class TestJSON:
    def test_basic_json(self):
        line = '{"timestamp":"2026-06-02T10:00:00Z","host":"app-01","service":"nginx","level":"error","message":"upstream timeout"}'
        r = parse(line)
        assert r.format == "json"
        assert r.host == "app-01"
        assert r.message == "upstream timeout"
        assert r.severity == "error"

    def test_at_timestamp(self):
        line = '{"@timestamp":"2026-06-02T09:00:00Z","host":"h","message":"m"}'
        r = parse(line)
        assert r.timestamp.year == 2026

    def test_msg_alias(self):
        line = '{"msg":"hello world","hostname":"srv"}'
        r = parse(line)
        assert r.message == "hello world"
        assert r.host == "srv"

    def test_pid_extracted(self):
        line = '{"message":"m","pid":9999,"host":"h"}'
        r = parse(line)
        assert r.pid == 9999

    def test_extra_fields_preserved(self):
        line = '{"message":"m","host":"h","request_id":"abc","status":404}'
        r = parse(line)
        assert r.fields.get("request_id") == "abc"
        assert r.fields.get("status") == 404

    def test_malformed_json_fallback(self):
        line = '{"broken json'
        r = parse(line)
        assert r.format == "plaintext"

    def test_process_field(self):
        line = '{"message":"m","host":"h","process":"gunicorn"}'
        r = parse(line)
        assert r.program == "gunicorn"


# ── Plaintext fallback ────────────────────────────────────────────────────────

class TestPlaintext:
    def test_plain_line(self):
        line = "this is just a plain log line with no structure"
        r = parse(line)
        assert r.format == "plaintext"
        assert r.message == line

    def test_bytes_input(self):
        r = parse(b"<34>1 2026-06-02T10:00:00Z host app - - - msg from bytes")
        assert r.format == "syslog_rfc5424"
        assert "msg from bytes" in r.message

    def test_whitespace_only(self):
        r = parse("   \t  ")
        assert r.format == "plaintext"

    def test_raw_preserved(self):
        line = "<13>1 2026-06-02T10:00:00Z host app - - - raw test"
        r = parse(line)
        assert r.raw == line

    def test_returns_parsedlog_instance(self):
        r = parse("anything")
        assert isinstance(r, ParsedLog)
