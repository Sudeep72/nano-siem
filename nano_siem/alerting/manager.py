"""
alerting/manager.py — Alert Manager

Collects signals from all three detection layers (Sigma, Correlation, ML),
deduplicates them, assigns unified severity, and produces Alert objects
ready for STIX serialization and console output.

Alert sources:
  - SigmaMatch      → rule title + level from Sigma evaluator
  - CorrelationAlert → chain title + severity from correlator
  - ML anomaly      → anomaly_score + XAI from scorer

Deduplication:
  An alert is deduplicated by a fingerprint = hash(source, alert_type, key).
  Duplicate within dedup_window_seconds → suppressed, existing alert's
  hit_count incremented instead.

Severity mapping (unified across sources):
  critical > high > medium > low > informational
  ML anomalies get severity by score bucket:
    score >= 0.85 → high, >= 0.70 → medium, else → low
"""

from __future__ import annotations
import hashlib
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from nano_siem.schema import NormalizedEvent
from nano_siem.sigma.evaluator import RuleMatch
from nano_siem.correlation.chainer import CorrelationAlert
from nano_siem.ml.scorer import ScoredEvent

logger = logging.getLogger(__name__)

SEVERITY_RANK = {
    "critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1,
}


def _ml_severity(score: float) -> str:
    if score >= 0.85:
        return "high"
    if score >= 0.70:
        return "medium"
    return "low"


@dataclass
class Alert:
    """
    Unified alert object produced by the AlertManager.
    Combines signals from Sigma, correlation, and ML layers.
    """
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    alert_type: str = "unknown"        # sigma | correlation | ml
    title: str = ""
    description: str = ""
    severity: str = "medium"
    source_key: str = ""               # IP or host that triggered
    event_id: str = ""                 # triggering event
    event_message: str = ""
    timestamp: float = field(default_factory=time.time)

    # Sigma-specific
    sigma_rule_id: str = ""
    sigma_tags: list[str] = field(default_factory=list)

    # Correlation-specific
    chain_id: str = ""
    chain_steps: list[dict] = field(default_factory=list)
    duration_seconds: float = 0.0
    mitre_tactic: str = ""
    mitre_techniques: list[str] = field(default_factory=list)

    # ML-specific
    anomaly_score: float = 0.0
    xai_features: list[tuple[str, float]] = field(default_factory=list)

    # Lifecycle
    hit_count: int = 1                 # incremented on dedup
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    fingerprint: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "alert_type": self.alert_type,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "source_key": self.source_key,
            "event_id": self.event_id,
            "event_message": self.event_message,
            "timestamp": self.timestamp,
            "sigma_rule_id": self.sigma_rule_id,
            "sigma_tags": self.sigma_tags,
            "chain_id": self.chain_id,
            "chain_steps": self.chain_steps,
            "duration_seconds": self.duration_seconds,
            "mitre_tactic": self.mitre_tactic,
            "mitre_techniques": self.mitre_techniques,
            "anomaly_score": self.anomaly_score,
            "xai_features": [{"feature": f, "deviation": v} for f, v in self.xai_features],
            "hit_count": self.hit_count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "fingerprint": self.fingerprint,
        }


def _fingerprint(alert_type: str, key: str, title: str) -> str:
    raw = f"{alert_type}:{key}:{title}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


class AlertManager:
    """
    Collects, deduplicates, and routes alerts from all detection layers.

    Usage:
        mgr = AlertManager(output_dir="alerts/", dedup_window_seconds=300)
        alerts = await mgr.process(event, sigma_matches, corr_alerts, scored)
    """

    def __init__(
        self,
        output_dir: str = "alerts/",
        dedup_window_seconds: int = 300,
        stix_output: bool = True,
        min_severity: str = "low",
    ) -> None:
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._dedup_window = dedup_window_seconds
        self._stix_output = stix_output
        self._min_rank = SEVERITY_RANK.get(min_severity, 1)

        # fingerprint → Alert (active dedup cache)
        self._cache: dict[str, Alert] = {}
        self._last_cache_clean: float = time.time()

        self.stats: dict[str, int] = {
            "total_alerts": 0,
            "sigma_alerts": 0,
            "correlation_alerts": 0,
            "ml_alerts": 0,
            "deduped": 0,
            "suppressed_by_severity": 0,
        }

    def _clean_cache(self) -> None:
        now = time.time()
        if now - self._last_cache_clean < 60:
            return
        cutoff = now - self._dedup_window
        expired = [fp for fp, a in self._cache.items() if a.last_seen < cutoff]
        for fp in expired:
            del self._cache[fp]
        self._last_cache_clean = now

    def _dedup_or_new(self, alert: Alert) -> Alert | None:
        """
        Check dedup cache. Returns:
          - None if this is a duplicate (cache entry updated in-place)
          - alert if this is new
        """
        fp = alert.fingerprint
        now = time.time()
        existing = self._cache.get(fp)
        if existing and (now - existing.last_seen) < self._dedup_window:
            existing.hit_count += 1
            existing.last_seen = now
            self.stats["deduped"] += 1
            return None
        self._cache[fp] = alert
        return alert

    def _from_sigma(self, event: NormalizedEvent, match: RuleMatch) -> Alert:
        src = event.source_ip or event.host
        return Alert(
            alert_type="sigma",
            title=match.rule.title,
            description=match.rule.description,
            severity=match.rule.level,
            source_key=src,
            event_id=event.event_id,
            event_message=event.message[:256],
            sigma_rule_id=match.rule.id,
            sigma_tags=match.rule.tags,
            mitre_techniques=[
                t.split("attack.")[-1].upper()
                for t in match.rule.tags
                if t.lower().startswith("attack.t")
            ],
            fingerprint=_fingerprint("sigma", src, match.rule.title),
        )

    def _from_correlation(self, corr: CorrelationAlert) -> Alert:
        return Alert(
            alert_type="correlation",
            title=corr.chain.title,
            description=corr.chain.description,
            severity=corr.chain.severity,
            source_key=corr.source_key,
            event_id=corr.step_events[-1].event_id if corr.step_events else "",
            event_message=corr.step_events[-1].message[:256] if corr.step_events else "",
            chain_id=corr.chain.id,
            chain_steps=[
                {
                    "step": corr.chain.steps[i].name,
                    "event_id": e.event_id,
                    "message": e.message[:120],
                }
                for i, e in enumerate(corr.step_events)
            ],
            duration_seconds=corr.duration_seconds,
            mitre_tactic=corr.chain.mitre_tactic,
            mitre_techniques=corr.chain.mitre_techniques,
            fingerprint=_fingerprint("correlation", corr.source_key, corr.chain.id),
        )

    def _from_ml(self, event: NormalizedEvent, scored: ScoredEvent) -> Alert:
        src = event.source_ip or event.host
        top = scored.top_features[:3]
        xai_desc = ", ".join(f"{f}={v:.2f}" for f, v in top)
        return Alert(
            alert_type="ml",
            title=f"ML Anomaly Detected (score={scored.anomaly_score:.3f})",
            description=f"Isolation Forest flagged anomalous event. Top drivers: {xai_desc}",
            severity=_ml_severity(scored.anomaly_score),
            source_key=src,
            event_id=event.event_id,
            event_message=event.message[:256],
            anomaly_score=scored.anomaly_score,
            xai_features=scored.top_features,
            fingerprint=_fingerprint("ml", src, f"ml:{int(scored.anomaly_score * 10)}"),
        )

    async def process(
        self,
        event: NormalizedEvent,
        sigma_matches: list[RuleMatch],
        corr_alerts: list[CorrelationAlert],
        scored: ScoredEvent | None,
    ) -> list[Alert]:
        """
        Process all detection signals for one event.
        Returns list of new (non-deduped) alerts.
        """
        self._clean_cache()
        new_alerts: list[Alert] = []

        # ── Sigma alerts ──────────────────────────────────────────────────────
        for match in sigma_matches:
            alert = self._from_sigma(event, match)
            if SEVERITY_RANK.get(alert.severity, 0) < self._min_rank:
                self.stats["suppressed_by_severity"] += 1
                continue
            result = self._dedup_or_new(alert)
            if result:
                self.stats["sigma_alerts"] += 1
                self.stats["total_alerts"] += 1
                new_alerts.append(result)

        # ── Correlation alerts ────────────────────────────────────────────────
        for corr in corr_alerts:
            alert = self._from_correlation(corr)
            if SEVERITY_RANK.get(alert.severity, 0) < self._min_rank:
                self.stats["suppressed_by_severity"] += 1
                continue
            result = self._dedup_or_new(alert)
            if result:
                self.stats["correlation_alerts"] += 1
                self.stats["total_alerts"] += 1
                new_alerts.append(result)

        # ── ML anomaly alert ──────────────────────────────────────────────────
        if scored and scored.is_anomalous:
            alert = self._from_ml(event, scored)
            if SEVERITY_RANK.get(alert.severity, 0) >= self._min_rank:
                result = self._dedup_or_new(alert)
                if result:
                    self.stats["ml_alerts"] += 1
                    self.stats["total_alerts"] += 1
                    new_alerts.append(result)

        # ── Enrich triggering event ───────────────────────────────────────────
        if new_alerts:
            event.alert_id = new_alerts[0].alert_id

        return new_alerts

    def get_stats(self) -> dict:
        return {**self.stats, "cache_size": len(self._cache)}
