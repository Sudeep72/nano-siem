"""
test_alerting.py — Unit tests for alerting/manager.py and alerting/stix_output.py

Covers:
  - Alert construction from all three sources (sigma, correlation, ml)
  - Deduplication logic (window, hit_count, new vs suppressed)
  - Severity filtering (min_severity threshold)
  - STIX bundle structure validation (all required fields)
  - File output (bundle JSON, NDJSON log)
  - Round-trip: Alert → STIX bundle → JSON-parseable
"""

import asyncio
import json
from unittest.mock import MagicMock

from nano_siem.alerting.manager import (
    SEVERITY_RANK,
    Alert,
    AlertManager,
    _fingerprint,
    _ml_severity,
)
from nano_siem.alerting.stix_output import _stix_id, build_bundle, write_alert_log, write_bundle
from nano_siem.schema import NormalizedEvent

# ── Helpers ────────────────────────────────────────────────────────────────────

def make_event(
    message: str = "test",
    source_ip: str | None = "1.2.3.4",
    host: str = "testhost",
    program: str = "sshd",
) -> NormalizedEvent:
    e = NormalizedEvent()
    e.message = message
    e.raw = message
    e.source_ip = source_ip
    e.host = host
    e.program = program
    e.tags = []
    e.sigma_matches = []
    return e


def make_sigma_match(
    title: str = "SSH Brute Force",
    level: str = "high",
    rule_id: str = "rule-001",
    tags: list[str] | None = None,
    description: str = "Test rule",
):
    match = MagicMock()
    match.rule.title = title
    match.rule.level = level
    match.rule.id = rule_id
    match.rule.tags = tags or ["attack.t1110"]
    match.rule.description = description
    match.matched_groups = ["keywords"]
    return match


def make_corr_alert(
    chain_id: str = "chain-001",
    title: str = "Brute Force then Login",
    severity: str = "critical",
    source_key: str = "1.2.3.4",
    duration: float = 120.0,
):
    alert = MagicMock()
    alert.chain.id = chain_id
    alert.chain.title = title
    alert.chain.description = "Test chain"
    alert.chain.severity = severity
    alert.chain.mitre_tactic = "Credential Access"
    alert.chain.mitre_techniques = ["T1110", "T1078"]
    alert.chain.steps = [MagicMock(name="s1"), MagicMock(name="s2")]
    alert.source_key = source_key
    alert.duration_seconds = duration
    e = make_event()
    alert.step_events = [e, e]
    return alert


def make_scored(score: float = 0.85, threshold: float = 0.62):
    scored = MagicMock()
    scored.anomaly_score = score
    scored.is_anomalous = score >= threshold
    scored.top_features = [
        ("hour_of_day", 0.9),
        ("source_ip_is_rfc1918", 0.8),
        ("is_off_hours", 0.7),
        ("dest_port_norm", 0.6),
        ("message_length_norm", 0.5),
    ]
    scored.event_id = "test-event-id"
    return scored


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# ── Severity helpers ──────────────────────────────────────────────────────────

class TestSeverityHelpers:
    def test_ml_severity_high(self):
        assert _ml_severity(0.90) == "high"
        assert _ml_severity(0.85) == "high"

    def test_ml_severity_medium(self):
        assert _ml_severity(0.75) == "medium"
        assert _ml_severity(0.70) == "medium"

    def test_ml_severity_low(self):
        assert _ml_severity(0.69) == "low"
        assert _ml_severity(0.62) == "low"

    def test_severity_rank_ordering(self):
        assert SEVERITY_RANK["critical"] > SEVERITY_RANK["high"]
        assert SEVERITY_RANK["high"] > SEVERITY_RANK["medium"]
        assert SEVERITY_RANK["medium"] > SEVERITY_RANK["low"]
        assert SEVERITY_RANK["low"] > SEVERITY_RANK["informational"]

    def test_fingerprint_deterministic(self):
        fp1 = _fingerprint("sigma", "1.2.3.4", "SSH Brute Force")
        fp2 = _fingerprint("sigma", "1.2.3.4", "SSH Brute Force")
        assert fp1 == fp2

    def test_fingerprint_differs_by_type(self):
        fp1 = _fingerprint("sigma", "1.2.3.4", "Title")
        fp2 = _fingerprint("ml", "1.2.3.4", "Title")
        assert fp1 != fp2

    def test_fingerprint_differs_by_key(self):
        fp1 = _fingerprint("sigma", "1.2.3.4", "Title")
        fp2 = _fingerprint("sigma", "5.6.7.8", "Title")
        assert fp1 != fp2


# ── Alert construction ────────────────────────────────────────────────────────

class TestAlertConstruction:
    def test_alert_to_dict_complete(self):
        a = Alert(
            alert_type="sigma",
            title="Test",
            severity="high",
            source_key="1.2.3.4",
            event_id="ev-001",
        )
        d = a.to_dict()
        required_keys = {
            "alert_id", "alert_type", "title", "severity", "source_key",
            "event_id", "timestamp", "hit_count", "fingerprint",
        }
        for k in required_keys:
            assert k in d, f"Missing key: {k}"

    def test_alert_default_hit_count(self):
        a = Alert()
        assert a.hit_count == 1

    def test_alert_has_uuid(self):
        a = Alert()
        import uuid
        uuid.UUID(a.alert_id)   # should not raise


# ── AlertManager tests ────────────────────────────────────────────────────────

class TestAlertManager:
    def test_sigma_alert_generated(self, tmp_path):
        mgr = AlertManager(output_dir=str(tmp_path), stix_output=False)
        event = make_event("Failed password for root")
        sigma = [make_sigma_match()]
        alerts = run(mgr.process(event, sigma, [], None))
        assert len(alerts) == 1
        assert alerts[0].alert_type == "sigma"
        assert alerts[0].title == "SSH Brute Force"
        assert alerts[0].severity == "high"

    def test_correlation_alert_generated(self, tmp_path):
        mgr = AlertManager(output_dir=str(tmp_path), stix_output=False)
        event = make_event()
        corr = [make_corr_alert()]
        alerts = run(mgr.process(event, [], corr, None))
        assert len(alerts) == 1
        assert alerts[0].alert_type == "correlation"
        assert alerts[0].chain_id == "chain-001"
        assert alerts[0].severity == "critical"

    def test_ml_alert_generated(self, tmp_path):
        mgr = AlertManager(output_dir=str(tmp_path), stix_output=False)
        event = make_event()
        scored = make_scored(score=0.90)
        alerts = run(mgr.process(event, [], [], scored))
        assert len(alerts) == 1
        assert alerts[0].alert_type == "ml"
        assert alerts[0].anomaly_score == 0.90

    def test_non_anomalous_ml_no_alert(self, tmp_path):
        mgr = AlertManager(output_dir=str(tmp_path), stix_output=False)
        event = make_event()
        scored = make_scored(score=0.30)
        scored.is_anomalous = False
        alerts = run(mgr.process(event, [], [], scored))
        ml_alerts = [a for a in alerts if a.alert_type == "ml"]
        assert ml_alerts == []

    def test_multiple_sources_same_event(self, tmp_path):
        mgr = AlertManager(output_dir=str(tmp_path), stix_output=False)
        event = make_event()
        alerts = run(mgr.process(
            event,
            [make_sigma_match()],
            [make_corr_alert()],
            make_scored(0.90),
        ))
        assert len(alerts) == 3
        types = {a.alert_type for a in alerts}
        assert types == {"sigma", "correlation", "ml"}

    def test_deduplication_suppresses_repeat(self, tmp_path):
        mgr = AlertManager(output_dir=str(tmp_path), dedup_window_seconds=300, stix_output=False)
        event = make_event()
        sigma = [make_sigma_match()]
        alerts1 = run(mgr.process(event, sigma, [], None))
        alerts2 = run(mgr.process(event, sigma, [], None))
        assert len(alerts1) == 1
        assert len(alerts2) == 0
        assert mgr.stats["deduped"] == 1

    def test_deduplication_increments_hit_count(self, tmp_path):
        mgr = AlertManager(output_dir=str(tmp_path), dedup_window_seconds=300, stix_output=False)
        event = make_event()
        sigma = [make_sigma_match()]
        run(mgr.process(event, sigma, [], None))
        run(mgr.process(event, sigma, [], None))
        # hit_count on cached alert should be 2
        cached = list(mgr._cache.values())[0]
        assert cached.hit_count == 2

    def test_severity_filter_suppresses_low(self, tmp_path):
        mgr = AlertManager(output_dir=str(tmp_path), min_severity="high", stix_output=False)
        event = make_event()
        sigma = [make_sigma_match(level="low")]
        alerts = run(mgr.process(event, sigma, [], None))
        assert alerts == []
        assert mgr.stats["suppressed_by_severity"] == 1

    def test_severity_filter_passes_high(self, tmp_path):
        mgr = AlertManager(output_dir=str(tmp_path), min_severity="high", stix_output=False)
        event = make_event()
        sigma = [make_sigma_match(level="high")]
        alerts = run(mgr.process(event, sigma, [], None))
        assert len(alerts) == 1

    def test_stats_updated(self, tmp_path):
        mgr = AlertManager(output_dir=str(tmp_path), stix_output=False)
        event = make_event()
        run(mgr.process(event, [make_sigma_match()], [make_corr_alert()], make_scored(0.9)))
        s = mgr.get_stats()
        assert s["sigma_alerts"] == 1
        assert s["correlation_alerts"] == 1
        assert s["ml_alerts"] == 1
        assert s["total_alerts"] == 3

    def test_event_enriched_with_alert_id(self, tmp_path):
        mgr = AlertManager(output_dir=str(tmp_path), stix_output=False)
        event = make_event()
        alerts = run(mgr.process(event, [make_sigma_match()], [], None))
        assert event.alert_id == alerts[0].alert_id

    def test_sigma_mitre_techniques_extracted(self, tmp_path):
        mgr = AlertManager(output_dir=str(tmp_path), stix_output=False)
        event = make_event()
        sigma = [make_sigma_match(tags=["attack.t1110.001", "attack.credential_access"])]
        alerts = run(mgr.process(event, sigma, [], None))
        assert any("1110" in t or "T1110" in str(t) for t in alerts[0].mitre_techniques)

    def test_chain_steps_preserved(self, tmp_path):
        mgr = AlertManager(output_dir=str(tmp_path), stix_output=False)
        event = make_event()
        corr = [make_corr_alert()]
        alerts = run(mgr.process(event, [], corr, None))
        assert len(alerts[0].chain_steps) == 2

    def test_xai_features_preserved(self, tmp_path):
        mgr = AlertManager(output_dir=str(tmp_path), stix_output=False)
        event = make_event()
        scored = make_scored(0.9)
        alerts = run(mgr.process(event, [], [], scored))
        assert len(alerts[0].xai_features) == 5

    def test_no_source_ip_falls_back_to_host(self, tmp_path):
        mgr = AlertManager(output_dir=str(tmp_path), stix_output=False)
        event = make_event(source_ip=None, host="myhost")
        alerts = run(mgr.process(event, [make_sigma_match()], [], None))
        assert alerts[0].source_key == "myhost"


# ── STIX output tests ─────────────────────────────────────────────────────────

class TestSTIXOutput:
    def _make_alert(self, alert_type: str = "sigma") -> Alert:
        return Alert(
            alert_type=alert_type,
            title="Test Alert",
            description="Test description",
            severity="high",
            source_key="1.2.3.4",
            event_id="ev-001",
            event_message="Failed password for root from 1.2.3.4",
            sigma_rule_id="rule-001",
            sigma_tags=["attack.t1110"],
            mitre_techniques=["T1110"],
            chain_id="chain-001" if alert_type == "correlation" else "",
            chain_steps=[{"step": "s1", "message": "scan"}, {"step": "s2", "message": "brute"}] if alert_type == "correlation" else [],
            mitre_tactic="Credential Access",
            anomaly_score=0.85 if alert_type == "ml" else 0.0,
            xai_features=[("hour_of_day", 0.9), ("is_off_hours", 0.8)] if alert_type == "ml" else [],
            fingerprint="abc123",
        )

    def test_bundle_has_required_top_level_fields(self):
        alert = self._make_alert()
        bundle = build_bundle(alert)
        assert bundle["type"] == "bundle"
        assert bundle["spec_version"] == "2.1"
        assert "id" in bundle
        assert "objects" in bundle

    def test_bundle_contains_three_objects(self):
        alert = self._make_alert()
        bundle = build_bundle(alert)
        assert len(bundle["objects"]) == 3

    def test_bundle_has_indicator(self):
        alert = self._make_alert()
        bundle = build_bundle(alert)
        types = [o["type"] for o in bundle["objects"]]
        assert "indicator" in types

    def test_bundle_has_sighting(self):
        alert = self._make_alert()
        bundle = build_bundle(alert)
        types = [o["type"] for o in bundle["objects"]]
        assert "sighting" in types

    def test_bundle_has_observed_data(self):
        alert = self._make_alert()
        bundle = build_bundle(alert)
        types = [o["type"] for o in bundle["objects"]]
        assert "observed-data" in types

    def test_indicator_has_required_fields(self):
        alert = self._make_alert()
        bundle = build_bundle(alert)
        indicator = next(o for o in bundle["objects"] if o["type"] == "indicator")
        required = {"type", "spec_version", "id", "created", "modified",
                    "name", "pattern", "pattern_type", "valid_from"}
        for field in required:
            assert field in indicator, f"Indicator missing field: {field}"

    def test_sighting_references_indicator(self):
        alert = self._make_alert()
        bundle = build_bundle(alert)
        indicator = next(o for o in bundle["objects"] if o["type"] == "indicator")
        sighting = next(o for o in bundle["objects"] if o["type"] == "sighting")
        assert sighting["sighting_of_ref"] == indicator["id"]

    def test_bundle_is_json_serializable(self):
        for alert_type in ("sigma", "correlation", "ml"):
            alert = self._make_alert(alert_type)
            bundle = build_bundle(alert)
            serialized = json.dumps(bundle, default=str)
            parsed = json.loads(serialized)
            assert parsed["type"] == "bundle"

    def test_stix_ids_are_deterministic(self):
        alert = self._make_alert()
        b1 = build_bundle(alert)
        b2 = build_bundle(alert)
        assert b1["id"] == b2["id"]

    def test_mitre_references_in_indicator(self):
        alert = self._make_alert()
        bundle = build_bundle(alert)
        indicator = next(o for o in bundle["objects"] if o["type"] == "indicator")
        refs = indicator.get("external_references", [])
        assert any(r.get("source_name") == "mitre-attack" for r in refs)

    def test_observed_data_has_custom_properties(self):
        alert = self._make_alert()
        bundle = build_bundle(alert)
        obs = next(o for o in bundle["objects"] if o["type"] == "observed-data")
        custom = obs.get("custom_properties", {})
        assert "x_nano_siem_alert_id" in custom
        assert custom["x_nano_siem_alert_type"] == "sigma"
        assert custom["x_nano_siem_severity"] == "high"

    def test_ml_bundle_has_xai_features(self):
        alert = self._make_alert("ml")
        bundle = build_bundle(alert)
        obs = next(o for o in bundle["objects"] if o["type"] == "observed-data")
        xai = obs["custom_properties"].get("x_nano_siem_xai_features", [])
        assert len(xai) == 2
        assert xai[0]["feature"] == "hour_of_day"

    def test_write_bundle_creates_file(self, tmp_path):
        alert = self._make_alert()
        path = write_bundle(alert, tmp_path)
        assert path.exists()
        assert path.suffix == ".json"
        content = json.loads(path.read_text())
        assert content["type"] == "bundle"

    def test_write_bundle_in_date_subdir(self, tmp_path):
        alert = self._make_alert()
        path = write_bundle(alert, tmp_path)
        # Should be in <output>/<YYYY-MM-DD>/
        assert path.parent != tmp_path
        assert len(path.parent.name) == 10   # YYYY-MM-DD

    def test_write_alert_log_appends_ndjson(self, tmp_path):
        alert1 = self._make_alert("sigma")
        alert2 = self._make_alert("ml")
        write_alert_log(alert1, tmp_path)
        write_alert_log(alert2, tmp_path)
        # Find the ndjson file
        ndjson_files = list(tmp_path.glob("*.ndjson"))
        assert len(ndjson_files) == 1
        lines = ndjson_files[0].read_text().strip().split("\n")
        assert len(lines) == 2
        for line in lines:
            d = json.loads(line)
            assert "alert_id" in d
            assert "alert_type" in d

    def test_write_bundle_all_types(self, tmp_path):
        for alert_type in ("sigma", "correlation", "ml"):
            alert = self._make_alert(alert_type)
            path = write_bundle(alert, tmp_path)
            assert path.exists()
            content = json.loads(path.read_text())
            assert content["type"] == "bundle"

    def test_stix_id_format(self):
        sid = _stix_id("indicator", "test-value")
        parts = sid.split("--")
        assert len(parts) == 2
        assert parts[0] == "indicator"
        import uuid
        uuid.UUID(parts[1])   # validates UUID format
