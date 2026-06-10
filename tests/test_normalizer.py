"""
test_normalizer.py — Unit tests for ingestion/normalizer.py

Tests the full parse → normalize pipeline producing NormalizedEvent objects.
Validates field mapping, IP extraction, auth tagging, and schema completeness.
"""

from nano_siem.ingestion.normalizer import normalize
from nano_siem.ingestion.parser import parse
from nano_siem.schema import NormalizedEvent


def norm(line: str) -> NormalizedEvent:
    """Helper: parse + normalize a raw log line."""
    return normalize(parse(line))


# ── Schema completeness ───────────────────────────────────────────────────────

class TestSchemaCompleteness:
    """Every NormalizedEvent must have all required top-level fields."""

    REQUIRED_ATTRS = {
        "event_id", "timestamp", "host", "message", "raw",
        "log_source", "fields", "tags", "sigma_matches",
    }

    def _assert_complete(self, line: str):
        event = norm(line)
        for attr in self.REQUIRED_ATTRS:
            assert hasattr(event, attr), f"Missing attribute: {attr}"
        return event

    def test_rfc5424_complete(self):
        self._assert_complete("<34>1 2026-06-02T10:00:01Z web-01 sshd 1234 - - Failed password")

    def test_rfc3164_complete(self):
        self._assert_complete("<13>Jun  2 10:00:05 db postgres[99]: error connecting")

    def test_cef_complete(self):
        self._assert_complete("CEF:0|Cisco|ASA|9.8|id|Block|7|src=1.2.3.4")

    def test_json_complete(self):
        self._assert_complete('{"host":"h","message":"test","level":"info"}')

    def test_plaintext_complete(self):
        self._assert_complete("some plain log line")


# ── IP extraction ─────────────────────────────────────────────────────────────

class TestIPExtraction:
    def test_ip_from_syslog_message(self):
        line = "<34>1 2026-06-02T10:00:00Z web-01 sshd - - - Failed password for root from 192.168.1.100 port 22"
        event = norm(line)
        assert event.source_ip == "192.168.1.100"

    def test_ip_from_cef_fields(self):
        line = "CEF:0|Cisco|ASA|9|id|Block|5|src=10.0.0.1 dst=172.16.0.5 dpt=443"
        event = norm(line)
        assert event.source_ip == "10.0.0.1"
        assert event.dest_ip == "172.16.0.5"

    def test_port_from_cef(self):
        line = "CEF:0|V|P|1|id|name|5|src=1.2.3.4 spt=12345 dst=5.6.7.8 dpt=443"
        event = norm(line)
        assert event.source_port == 12345
        assert event.dest_port == 443

    def test_port_from_message(self):
        line = "<13>1 2026-06-02T10:00:00Z host sshd - - - Connection from 10.0.0.1 port 22"
        event = norm(line)
        assert event.dest_port == 22

    def test_no_ip_no_crash(self):
        event = norm("plain log with no IPs at all")
        assert event.source_ip is None
        assert event.dest_ip is None


# ── Auth tagging ──────────────────────────────────────────────────────────────

class TestAuthTagging:
    def test_failed_password_tagged(self):
        line = "<34>1 2026-06-02T10:00:00Z host sshd - - - Failed password for root from 1.2.3.4"
        event = norm(line)
        assert "auth:failure" in event.tags

    def test_accepted_password_tagged(self):
        line = "<34>1 2026-06-02T10:00:00Z host sshd - - - Accepted password for deploy from 10.0.0.5"
        event = norm(line)
        assert "auth:success" in event.tags

    def test_sshd_program_tagged(self):
        line = "<34>1 2026-06-02T10:00:00Z host sshd - - - some message"
        event = norm(line)
        assert "category:auth" in event.tags

    def test_sudo_program_tagged(self):
        line = "<86>1 2026-06-02T10:00:00Z host sudo - - - user ran command"
        event = norm(line)
        assert "category:auth" in event.tags

    def test_plain_message_no_false_auth_tag(self):
        event = norm("kernel: network interface eth0 up")
        assert "auth:failure" not in event.tags
        assert "auth:success" not in event.tags


# ── Username extraction ───────────────────────────────────────────────────────

class TestUsernameExtraction:
    def test_username_from_sshd(self):
        line = "<34>1 2026-06-02T10:00:00Z host sshd - - - Failed password for admin from 10.0.0.1"
        event = norm(line)
        assert event.fields.get("username") == "admin"

    def test_invalid_user_extracted(self):
        line = "<34>1 2026-06-02T10:00:00Z host sshd - - - Failed password for invalid user hacker from 1.2.3.4"
        event = norm(line)
        assert event.fields.get("username") is not None


# ── Field preservation ────────────────────────────────────────────────────────

class TestFieldPreservation:
    def test_json_extra_fields_in_fields_dict(self):
        line = '{"host":"h","message":"m","request_id":"abc-123","trace_id":"xyz"}'
        event = norm(line)
        assert event.fields.get("request_id") == "abc-123"
        assert event.fields.get("trace_id") == "xyz"

    def test_cef_extensions_in_fields(self):
        line = "CEF:0|Cisco|ASA|9|id|Block|7|src=1.2.3.4 spt=1234 act=blocked"
        event = norm(line)
        assert event.fields.get("act") == "blocked"

    def test_raw_preserved(self):
        line = "<13>1 2026-06-02T10:00:00Z host app - - - raw test line"
        event = norm(line)
        assert event.raw == line

    def test_log_source_set(self):
        rfc5424 = norm("<13>1 2026-06-02T10:00:00Z host app - - - msg")
        assert rfc5424.log_source == "syslog_rfc5424"

        cef = norm("CEF:0|V|P|1|id|name|5|")
        assert cef.log_source == "cef"

        plain = norm("just a plain line")
        assert plain.log_source == "plaintext"


# ── to_dict serialization ─────────────────────────────────────────────────────

class TestSerialization:
    def test_to_dict_is_json_serializable(self):
        import json
        event = norm("<34>1 2026-06-02T10:00:00Z host sshd 123 - - Failed password for root")
        d = event.to_dict()
        # Should not raise
        serialized = json.dumps(d)
        assert "event_id" in serialized

    def test_to_dict_has_timestamp_as_string(self):
        event = norm("<13>1 2026-06-02T10:00:00Z host app - - - msg")
        d = event.to_dict()
        assert isinstance(d["timestamp"], str)
        assert "2026" in d["timestamp"]

    def test_get_field_top_level(self):
        event = norm("<13>1 2026-06-02T10:00:00Z myhost app - - - msg")
        assert event.get_field("host") == "myhost"

    def test_get_field_nested(self):
        line = '{"host":"h","message":"m","custom_key":"custom_val"}'
        event = norm(line)
        assert event.get_field("fields.custom_key") == "custom_val"

    def test_add_tag_no_duplicates(self):
        event = norm("plain")
        event.add_tag("test:tag")
        event.add_tag("test:tag")
        assert event.tags.count("test:tag") == 1
