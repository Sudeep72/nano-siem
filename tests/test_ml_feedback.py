"""
test_ml_feedback.py — Tests for AnomalyScorer.retrain_excluding_fingerprints

FP feedback loop: the IncidentStore calls this method when enough
false-positive incidents accumulate. Tests verify the method's
behavior without requiring a fully trained real model (uses a
lightweight mocked/trained model from train_from_corpus with small
sample counts for speed).
"""

import logging
import pytest
from unittest.mock import patch, MagicMock

from nano_siem.ml.scorer import AnomalyScorer
from nano_siem.ml.baseline import BaselineModel, train_from_corpus


@pytest.fixture
def small_model(tmp_path):
    """Train a small real model for fast tests."""
    path = str(tmp_path / "baseline.joblib")
    model = train_from_corpus(path=path, n_samples=100)
    return model, path


class TestRetrainExcludingFingerprints:
    def test_no_model_loaded_returns_false(self, tmp_path):
        scorer = AnomalyScorer(model_path=str(tmp_path / "nope.joblib"), train_n_samples=100)
        # _model is None until load_or_train is called
        result = scorer.retrain_excluding_fingerprints(["fp1", "fp2"])
        assert result is False

    def test_retrain_with_loaded_model_succeeds(self, small_model):
        model, path = small_model
        scorer = AnomalyScorer(model_path=path, train_n_samples=100)
        scorer._model = model

        result = scorer.retrain_excluding_fingerprints(["fp1", "fp2"])
        assert result is True

    def test_retrain_updates_last_trained(self, small_model):
        model, path = small_model
        scorer = AnomalyScorer(model_path=path, train_n_samples=100)
        scorer._model = model
        original_last_trained = scorer._last_trained

        scorer.retrain_excluding_fingerprints(["fp1"])
        assert scorer._last_trained >= original_last_trained

    def test_retrain_swaps_model_on_success(self, small_model):
        model, path = small_model
        scorer = AnomalyScorer(model_path=path, train_n_samples=100)
        scorer._model = model
        original_model = scorer._model

        scorer.retrain_excluding_fingerprints(["fp1"])
        # New model object should be assigned (different instance)
        assert scorer._model is not None

    def test_degraded_model_not_swapped(self, small_model):
        model, path = small_model
        scorer = AnomalyScorer(model_path=path, train_n_samples=100)
        scorer._model = model

        # Simulate a degraded retrain (way fewer samples than requested)
        degraded_model = MagicMock(spec=BaselineModel)
        degraded_model.n_training_samples = 5  # << 90% of 100

        with patch("nano_siem.ml.scorer.train_from_corpus", return_value=degraded_model):
            result = scorer.retrain_excluding_fingerprints(["fp1"])

        assert result is False
        # Original model retained
        assert scorer._model is model

    def test_exception_during_retrain_returns_false(self, small_model):
        model, path = small_model
        scorer = AnomalyScorer(model_path=path, train_n_samples=100)
        scorer._model = model

        with patch("nano_siem.ml.scorer.train_from_corpus", side_effect=RuntimeError("disk full")):
            result = scorer.retrain_excluding_fingerprints(["fp1"])

        assert result is False
        # Original model retained on failure
        assert scorer._model is model

    def test_empty_fingerprints_list_still_retrains(self, small_model):
        model, path = small_model
        scorer = AnomalyScorer(model_path=path, train_n_samples=100)
        scorer._model = model

        result = scorer.retrain_excluding_fingerprints([])
        assert result is True

    def test_logs_fingerprints(self, small_model, caplog):
        model, path = small_model
        scorer = AnomalyScorer(model_path=path, train_n_samples=100)
        scorer._model = model

        with caplog.at_level(logging.INFO):
            scorer.retrain_excluding_fingerprints(["fp1", "fp2", "fp3"])

        assert any("false positive" in r.message.lower() for r in caplog.records)


class TestIntegrationWithIncidentStore:
    """End-to-end: IncidentStore triggers AnomalyScorer.retrain_excluding_fingerprints."""

    def test_full_feedback_loop(self, small_model):
        from nano_siem.incidents.store import IncidentStore

        model, path = small_model
        scorer = AnomalyScorer(model_path=path, train_n_samples=100)
        scorer._model = model

        store = IncidentStore(fp_retrain_threshold=1)
        store.set_ml_scorer(scorer)

        alert = {
            "alert_id": "alert-001",
            "alert_type": "sigma",
            "title": "Test Alert",
            "severity": "medium",
            "source_key": "8.8.8.8",
            "mitre_tactic": "",
            "mitre_techniques": [],
        }

        incident = store.create_from_alert(alert)
        store.set_disposition(incident.incident_id, "false_positive", fingerprints=["fp-abc"])

        stats = store.get_feedback_stats()
        assert stats["retrain_count"] == 1
        assert stats["pending_fp_fingerprints"] == 0
