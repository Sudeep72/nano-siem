"""
test_incidents.py — Tests for incidents/model.py and incidents/store.py

Covers:
  - Incident creation from alerts (single and multi)
  - State machine transitions (valid and invalid)
  - Owner assignment, notes, disposition
  - FP feedback loop — fingerprint accumulation and retrain triggering
  - IncidentStore CRUD and filtering
"""

import pytest
from unittest.mock import MagicMock

from nano_siem.incidents.model import (
    Incident, IncidentState, Disposition, IncidentNote,
    incident_from_alert, incident_from_alerts, VALID_TRANSITIONS,
)
from nano_siem.incidents.store import IncidentStore


SIGMA_ALERT = {
    "alert_id": "alert-001",
    "alert_type": "sigma",
    "title": "SSH Brute Force Attempt",
    "severity": "high",
    "source_key": "8.8.8.8",
    "mitre_tactic": "Credential Access",
    "mitre_techniques": ["T1110.001"],
}

CORR_ALERT = {
    "alert_id": "alert-002",
    "alert_type": "correlation",
    "title": "Brute Force Followed by Successful Login",
    "severity": "critical",
    "source_key": "8.8.8.8",
    "mitre_tactic": "Credential Access → Initial Access",
    "mitre_techniques": ["T1110", "T1078"],
}

ML_ALERT = {
    "alert_id": "alert-003",
    "alert_type": "ml",
    "title": "ML Anomaly Detected (score=0.99)",
    "severity": "medium",
    "source_key": "203.0.113.9",
    "mitre_tactic": "",
    "mitre_techniques": [],
}


class TestIncidentCreation:
    def test_from_single_alert(self):
        incident = incident_from_alert(SIGMA_ALERT)
        assert incident.title == "SSH Brute Force Attempt"
        assert incident.severity == "high"
        assert incident.alert_ids == ["alert-001"]
        assert incident.source_ips == ["8.8.8.8"]
        assert incident.state == IncidentState.NEW

    def test_from_multiple_alerts_picks_top_severity(self):
        incident = incident_from_alerts([SIGMA_ALERT, CORR_ALERT])
        assert incident.severity == "critical"

    def test_from_multiple_alerts_merges_alert_ids(self):
        incident = incident_from_alerts([SIGMA_ALERT, CORR_ALERT])
        assert set(incident.alert_ids) == {"alert-001", "alert-002"}

    def test_from_multiple_alerts_merges_techniques(self):
        incident = incident_from_alerts([SIGMA_ALERT, CORR_ALERT])
        assert "T1110.001" in incident.mitre_techniques
        assert "T1110" in incident.mitre_techniques
        assert "T1078" in incident.mitre_techniques

    def test_from_multiple_alerts_dedupes_source_ips(self):
        incident = incident_from_alerts([SIGMA_ALERT, CORR_ALERT])
        assert incident.source_ips == ["8.8.8.8"]

    def test_from_multiple_alerts_custom_title(self):
        incident = incident_from_alerts([SIGMA_ALERT, CORR_ALERT], title="Custom Title")
        assert incident.title == "Custom Title"

    def test_empty_alert_list_raises(self):
        with pytest.raises(ValueError):
            incident_from_alerts([])

    def test_incident_id_generated(self):
        a = incident_from_alert(SIGMA_ALERT)
        b = incident_from_alert(SIGMA_ALERT)
        assert a.incident_id != b.incident_id


class TestStateMachine:
    def test_new_to_triaging(self):
        incident = incident_from_alert(SIGMA_ALERT)
        incident.transition(IncidentState.TRIAGING)
        assert incident.state == IncidentState.TRIAGING

    def test_new_to_dismissed(self):
        incident = incident_from_alert(SIGMA_ALERT)
        incident.transition(IncidentState.DISMISSED)
        assert incident.state == IncidentState.DISMISSED
        assert incident.closed_at is not None

    def test_triaging_to_contained(self):
        incident = incident_from_alert(SIGMA_ALERT)
        incident.transition(IncidentState.TRIAGING)
        incident.transition(IncidentState.CONTAINED)
        assert incident.state == IncidentState.CONTAINED

    def test_contained_to_closed(self):
        incident = incident_from_alert(SIGMA_ALERT)
        incident.transition(IncidentState.TRIAGING)
        incident.transition(IncidentState.CONTAINED)
        incident.transition(IncidentState.CLOSED)
        assert incident.state == IncidentState.CLOSED
        assert incident.closed_at is not None

    def test_contained_back_to_triaging(self):
        incident = incident_from_alert(SIGMA_ALERT)
        incident.transition(IncidentState.TRIAGING)
        incident.transition(IncidentState.CONTAINED)
        incident.transition(IncidentState.TRIAGING)
        assert incident.state == IncidentState.TRIAGING

    def test_invalid_transition_new_to_closed(self):
        incident = incident_from_alert(SIGMA_ALERT)
        with pytest.raises(ValueError, match="Invalid transition"):
            incident.transition(IncidentState.CLOSED)

    def test_invalid_transition_from_closed(self):
        incident = incident_from_alert(SIGMA_ALERT)
        incident.transition(IncidentState.TRIAGING)
        incident.transition(IncidentState.CONTAINED)
        incident.transition(IncidentState.CLOSED)
        with pytest.raises(ValueError):
            incident.transition(IncidentState.TRIAGING)

    def test_invalid_transition_from_dismissed(self):
        incident = incident_from_alert(SIGMA_ALERT)
        incident.transition(IncidentState.DISMISSED)
        with pytest.raises(ValueError):
            incident.transition(IncidentState.TRIAGING)

    def test_all_states_have_transition_entries(self):
        for state in IncidentState:
            assert state in VALID_TRANSITIONS

    def test_updated_at_changes_on_transition(self):
        incident = incident_from_alert(SIGMA_ALERT)
        original = incident.updated_at
        import time; time.sleep(0.01)
        incident.transition(IncidentState.TRIAGING)
        assert incident.updated_at > original


class TestNotesAndOwnership:
    def test_add_note(self):
        incident = incident_from_alert(SIGMA_ALERT)
        note = incident.add_note("alice", "Investigating source IP")
        assert len(incident.notes) == 1
        assert incident.notes[0].author == "alice"
        assert incident.notes[0].content == "Investigating source IP"

    def test_note_to_dict(self):
        note = IncidentNote(author="bob", content="test")
        d = note.to_dict()
        assert d["author"] == "bob"
        assert "timestamp" in d

    def test_multiple_notes_preserved_in_order(self):
        incident = incident_from_alert(SIGMA_ALERT)
        incident.add_note("alice", "first")
        incident.add_note("bob", "second")
        assert incident.notes[0].content == "first"
        assert incident.notes[1].content == "second"


class TestDisposition:
    def test_set_true_positive(self):
        incident = incident_from_alert(SIGMA_ALERT)
        incident.set_disposition(Disposition.TRUE_POSITIVE)
        assert incident.disposition == Disposition.TRUE_POSITIVE
        assert incident.is_false_positive is False

    def test_set_false_positive_records_fingerprints(self):
        incident = incident_from_alert(SIGMA_ALERT)
        incident.set_disposition(Disposition.FALSE_POSITIVE, fingerprints=["fp1", "fp2"])
        assert incident.is_false_positive is True
        assert incident.fp_fingerprints == ["fp1", "fp2"]

    def test_non_fp_disposition_no_fingerprints(self):
        incident = incident_from_alert(SIGMA_ALERT)
        incident.set_disposition(Disposition.BENIGN_TRUE_POSITIVE, fingerprints=["fp1"])
        assert incident.fp_fingerprints == []


class TestSerialization:
    def test_to_dict_structure(self):
        incident = incident_from_alert(SIGMA_ALERT)
        d = incident.to_dict()
        assert d["state"] == "new"
        assert d["disposition"] is None
        assert "age_seconds" in d
        assert d["is_false_positive"] is False

    def test_to_dict_json_serializable(self):
        import json
        incident = incident_from_alerts([SIGMA_ALERT, CORR_ALERT])
        incident.add_note("alice", "test note")
        incident.set_disposition(Disposition.FALSE_POSITIVE, fingerprints=["fp1"])
        json.dumps(incident.to_dict())

    def test_age_seconds_positive(self):
        incident = incident_from_alert(SIGMA_ALERT)
        assert incident.age_seconds >= 0


# ── IncidentStore ─────────────────────────────────────────────────────────────

class TestIncidentStore:
    def test_create_from_alert(self):
        store = IncidentStore()
        incident = store.create_from_alert(SIGMA_ALERT)
        assert store.get(incident.incident_id) is not None

    def test_create_from_alerts(self):
        store = IncidentStore()
        incident = store.create_from_alerts([SIGMA_ALERT, CORR_ALERT])
        assert len(incident.alert_ids) == 2

    def test_get_nonexistent_returns_none(self):
        store = IncidentStore()
        assert store.get("nonexistent") is None

    def test_list_all(self):
        store = IncidentStore()
        store.create_from_alert(SIGMA_ALERT)
        store.create_from_alert(ML_ALERT)
        incidents = store.list_all()
        assert len(incidents) == 2

    def test_list_filtered_by_state(self):
        store = IncidentStore()
        i1 = store.create_from_alert(SIGMA_ALERT)
        i2 = store.create_from_alert(ML_ALERT)
        store.update_state(i1.incident_id, "triaging")
        new_incidents = store.list_all(state="new")
        triaging_incidents = store.list_all(state="triaging")
        assert len(new_incidents) == 1
        assert len(triaging_incidents) == 1
        assert new_incidents[0].incident_id == i2.incident_id

    def test_list_filtered_by_owner(self):
        store = IncidentStore()
        i1 = store.create_from_alert(SIGMA_ALERT)
        store.create_from_alert(ML_ALERT)
        store.assign_owner(i1.incident_id, "alice")
        owned = store.list_all(owner="alice")
        assert len(owned) == 1
        assert owned[0].incident_id == i1.incident_id

    def test_update_state(self):
        store = IncidentStore()
        incident = store.create_from_alert(SIGMA_ALERT)
        updated = store.update_state(incident.incident_id, "triaging")
        assert updated.state == IncidentState.TRIAGING

    def test_update_state_invalid_raises(self):
        store = IncidentStore()
        incident = store.create_from_alert(SIGMA_ALERT)
        with pytest.raises(ValueError):
            store.update_state(incident.incident_id, "closed")

    def test_update_state_nonexistent_raises(self):
        store = IncidentStore()
        with pytest.raises(KeyError):
            store.update_state("nonexistent", "triaging")

    def test_assign_owner(self):
        store = IncidentStore()
        incident = store.create_from_alert(SIGMA_ALERT)
        store.assign_owner(incident.incident_id, "bob")
        assert store.get(incident.incident_id).owner == "bob"

    def test_add_note(self):
        store = IncidentStore()
        incident = store.create_from_alert(SIGMA_ALERT)
        store.add_note(incident.incident_id, "alice", "checking logs")
        assert len(store.get(incident.incident_id).notes) == 1

    def test_get_stats_structure(self):
        store = IncidentStore()
        store.create_from_alert(SIGMA_ALERT)
        stats = store.get_stats()
        assert "total" in stats
        assert "by_state" in stats
        assert stats["total"] == 1
        assert stats["by_state"]["new"] == 1


# ── FP Feedback Loop ──────────────────────────────────────────────────────────

class TestFPFeedbackLoop:
    def test_fp_disposition_accumulates_fingerprints(self):
        store = IncidentStore(fp_retrain_threshold=10)
        incident = store.create_from_alert(SIGMA_ALERT)
        store.set_disposition(incident.incident_id, "false_positive", fingerprints=["fp1", "fp2"])
        stats = store.get_feedback_stats()
        assert stats["pending_fp_fingerprints"] == 2
        assert stats["false_positive_incidents"] == 1

    def test_retrain_not_triggered_below_threshold(self):
        scorer = MagicMock()
        store = IncidentStore(fp_retrain_threshold=10)
        store.set_ml_scorer(scorer)
        incident = store.create_from_alert(SIGMA_ALERT)
        store.set_disposition(incident.incident_id, "false_positive", fingerprints=["fp1"])
        scorer.retrain_excluding_fingerprints.assert_not_called()

    def test_retrain_triggered_at_threshold(self):
        scorer = MagicMock()
        scorer.retrain_excluding_fingerprints.return_value = True
        store = IncidentStore(fp_retrain_threshold=2)
        store.set_ml_scorer(scorer)

        i1 = store.create_from_alert(SIGMA_ALERT)
        i2 = store.create_from_alert(ML_ALERT)
        store.set_disposition(i1.incident_id, "false_positive", fingerprints=["fp1"])
        store.set_disposition(i2.incident_id, "false_positive", fingerprints=["fp2"])

        scorer.retrain_excluding_fingerprints.assert_called_once()
        called_fps = scorer.retrain_excluding_fingerprints.call_args[0][0]
        assert set(called_fps) == {"fp1", "fp2"}

    def test_retrain_clears_pending_fingerprints(self):
        scorer = MagicMock()
        scorer.retrain_excluding_fingerprints.return_value = True
        store = IncidentStore(fp_retrain_threshold=1)
        store.set_ml_scorer(scorer)

        incident = store.create_from_alert(SIGMA_ALERT)
        store.set_disposition(incident.incident_id, "false_positive", fingerprints=["fp1"])

        stats = store.get_feedback_stats()
        assert stats["pending_fp_fingerprints"] == 0
        assert stats["retrain_count"] == 1

    def test_retrain_without_scorer_logs_warning_no_crash(self):
        store = IncidentStore(fp_retrain_threshold=1)
        incident = store.create_from_alert(SIGMA_ALERT)
        # No scorer injected — should not raise
        store.set_disposition(incident.incident_id, "false_positive", fingerprints=["fp1"])
        assert store.get_feedback_stats()["retrain_count"] == 0

    def test_retrain_failure_handled_gracefully(self):
        scorer = MagicMock()
        scorer.retrain_excluding_fingerprints.side_effect = RuntimeError("boom")
        store = IncidentStore(fp_retrain_threshold=1)
        store.set_ml_scorer(scorer)

        incident = store.create_from_alert(SIGMA_ALERT)
        # Should not raise even though retrain throws
        store.set_disposition(incident.incident_id, "false_positive", fingerprints=["fp1"])
        assert store.get_feedback_stats()["retrain_count"] == 0

    def test_retrain_returns_false_does_not_increment_count(self):
        scorer = MagicMock()
        scorer.retrain_excluding_fingerprints.return_value = False
        store = IncidentStore(fp_retrain_threshold=1)
        store.set_ml_scorer(scorer)

        incident = store.create_from_alert(SIGMA_ALERT)
        store.set_disposition(incident.incident_id, "false_positive", fingerprints=["fp1"])
        assert store.get_feedback_stats()["retrain_count"] == 0

    def test_non_fp_disposition_does_not_trigger_retrain(self):
        scorer = MagicMock()
        store = IncidentStore(fp_retrain_threshold=1)
        store.set_ml_scorer(scorer)

        incident = store.create_from_alert(SIGMA_ALERT)
        store.set_disposition(incident.incident_id, "true_positive")
        scorer.retrain_excluding_fingerprints.assert_not_called()

    def test_multiple_retrain_cycles(self):
        scorer = MagicMock()
        scorer.retrain_excluding_fingerprints.return_value = True
        store = IncidentStore(fp_retrain_threshold=1)
        store.set_ml_scorer(scorer)

        for i in range(3):
            incident = store.create_from_alert({**SIGMA_ALERT, "alert_id": f"alert-{i}"})
            store.set_disposition(incident.incident_id, "false_positive", fingerprints=[f"fp{i}"])

        assert store.get_feedback_stats()["retrain_count"] == 3
