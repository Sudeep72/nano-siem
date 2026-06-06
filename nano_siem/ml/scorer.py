"""
ml/scorer.py — Per-Event Anomaly Scorer

Wraps the BaselineModel to provide:
  1. Per-event anomaly score (0.0 = normal, 1.0 = maximally anomalous)
  2. XAI explanation: top features driving the anomaly score
  3. Async-safe model loading/reloading
  4. Graceful degradation: if no model exists, trains one on first call

The scorer is a lightweight stateful object — one instance per pipeline run.
It holds the loaded BaselineModel in memory and scores events synchronously
(IsolationForest inference is ~0.1ms per event, safe on the event loop).
"""

from __future__ import annotations
import asyncio
import logging
import os
import time
from dataclasses import dataclass

from nano_siem.schema import NormalizedEvent
from nano_siem.ml.features import extract, top_features, FEATURE_DIM
from nano_siem.ml.baseline import BaselineModel, load, train_from_corpus

logger = logging.getLogger(__name__)


@dataclass
class ScoredEvent:
    """Result of scoring one event."""
    event_id: str
    anomaly_score: float               # 0.0 (normal) → 1.0 (anomalous)
    is_anomalous: bool                 # score >= threshold
    top_features: list[tuple[str, float]]  # (feature_name, deviation) top 5
    scored_at: float                   # unix timestamp


class AnomalyScorer:
    """
    Anomaly scorer backed by a trained IsolationForest.

    Lifecycle:
      scorer = AnomalyScorer(model_path="data/baseline.joblib", threshold=0.62)
      await scorer.load_or_train()
      scored = scorer.score(event)
    """

    def __init__(
        self,
        model_path: str = "data/baseline.joblib",
        threshold: float = 0.62,
        train_n_samples: int = 2000,
        retrain_interval: int = 3600,   # retrain every hour if enabled
        auto_retrain: bool = False,
    ) -> None:
        self._model_path = model_path
        self._threshold = threshold
        self._train_n_samples = train_n_samples
        self._retrain_interval = retrain_interval
        self._auto_retrain = auto_retrain
        self._model: BaselineModel | None = None
        self._last_trained: float = 0.0
        self._lock = asyncio.Lock()

        # Running stats
        self.stats: dict[str, float | int] = {
            "events_scored": 0,
            "anomalies_detected": 0,
            "avg_score": 0.0,
            "max_score": 0.0,
        }

    async def load_or_train(self) -> None:
        """
        Load model from disk if it exists, otherwise train a new one.
        Called once at startup. Safe to call multiple times (idempotent).
        """
        async with self._lock:
            if self._model is not None:
                return
            loop = asyncio.get_running_loop()
            self._model = await loop.run_in_executor(
                None, self._load_or_train_sync
            )
            self._last_trained = time.time()

    def _load_or_train_sync(self) -> BaselineModel:
        if os.path.exists(self._model_path):
            try:
                return load(self._model_path)
            except Exception as e:
                logger.warning("Failed to load model from %s: %s — retraining", self._model_path, e)
        logger.info("No model found at %s — training on synthetic corpus", self._model_path)
        return train_from_corpus(
            path=self._model_path,
            n_samples=self._train_n_samples,
        )

    def score(self, event: NormalizedEvent) -> ScoredEvent:
        """
        Score one event synchronously.
        Must call load_or_train() before first use.

        Returns ScoredEvent and enriches event.anomaly_score in-place.
        """
        if self._model is None:
            # Fallback if called before load — return neutral score
            logger.warning("Scorer called before model loaded — returning neutral score")
            event.anomaly_score = 0.0
            return ScoredEvent(
                event_id=event.event_id,
                anomaly_score=0.0,
                is_anomalous=False,
                top_features=[],
                scored_at=time.time(),
            )

        # Extract feature vector
        vector = extract(event)

        # Score against baseline
        anomaly_score = self._model.predict_score(vector)

        # XAI: top features driving this score
        xai_features = top_features(
            vector,
            baseline_vector=self._model.baseline_vector,
            n=5,
        )

        is_anomalous = anomaly_score >= self._threshold

        # Enrich event in-place
        event.anomaly_score = anomaly_score
        if is_anomalous:
            event.add_tag("ml:anomalous")
            event.add_tag(f"ml:score:{anomaly_score:.2f}")

        # Update stats
        n = self.stats["events_scored"] + 1
        self.stats["events_scored"] = n
        self.stats["avg_score"] = (
            (self.stats["avg_score"] * (n - 1) + anomaly_score) / n
        )
        if anomaly_score > self.stats["max_score"]:
            self.stats["max_score"] = anomaly_score
        if is_anomalous:
            self.stats["anomalies_detected"] = self.stats["anomalies_detected"] + 1

        return ScoredEvent(
            event_id=event.event_id,
            anomaly_score=anomaly_score,
            is_anomalous=is_anomalous,
            top_features=xai_features,
            scored_at=time.time(),
        )

    async def maybe_retrain(self) -> bool:
        """
        Retrain model if auto_retrain is enabled and interval has elapsed.
        Returns True if retrained.
        """
        if not self._auto_retrain:
            return False
        if time.time() - self._last_trained < self._retrain_interval:
            return False
        async with self._lock:
            loop = asyncio.get_running_loop()
            self._model = await loop.run_in_executor(
                None,
                lambda: train_from_corpus(self._model_path, self._train_n_samples),
            )
            self._last_trained = time.time()
            logger.info("Model retrained and saved to %s", self._model_path)
        return True

    @property
    def is_loaded(self) -> bool:
        return self._model is not None

    @property
    def threshold(self) -> float:
        return self._threshold

    def get_stats(self) -> dict:
        return {
            **self.stats,
            "model_path": self._model_path,
            "threshold": self._threshold,
            "model_loaded": self._model is not None,
            "training_samples": (
                self._model.n_training_samples if self._model else 0
            ),
        }
