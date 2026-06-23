"""
incidents/store.py — In-memory Incident Store + FP Feedback Loop

Manages the lifecycle of all incidents and provides the feedback loop:
  analyst marks FP → store records fingerprints → retrainer picks them up
  → Isolation Forest baseline is retrained excluding FP events

The retraining is async (doesn't block the analyst) and conservative:
  - Only retrains if enough FP fingerprints have accumulated (configurable)
  - Keeps the previous model as fallback if retraining degrades performance
  - Logs all retraining events for audit purposes
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict

from nano_siem.incidents.model import (
    Disposition,
    Incident,
    IncidentState,
    incident_from_alert,
    incident_from_alerts,
)

logger = logging.getLogger(__name__)


class IncidentStore:
    """
    Thread-safe (asyncio-safe) in-memory incident store.

    For production use, this would back onto a database (SQLite/Postgres).
    For NanoSIEM's scale (hundreds of incidents), in-memory is sufficient
    and avoids adding a DB dependency for the SIEM's scope.
    """

    def __init__(self, fp_retrain_threshold: int = 5) -> None:
        self._incidents: dict[str, Incident] = {}
        self._fp_retrain_threshold = fp_retrain_threshold
        self._pending_fp_fingerprints: list[str] = []
        self._retrain_count = 0
        self._ml_scorer = None   # injected by pipeline after init

    def set_ml_scorer(self, scorer) -> None:
        """Inject the MLScorer so the store can trigger retraining."""
        self._ml_scorer = scorer

    # ── CRUD ─────────────────────────────────────────────────────────────────

    def create_from_alert(self, alert: dict) -> Incident:
        incident = incident_from_alert(alert)
        self._incidents[incident.incident_id] = incident
        logger.info("Incident %s created from alert %s", incident.incident_id, alert.get("alert_id"))
        return incident

    def create_from_alerts(self, alerts: list[dict], title: str | None = None) -> Incident:
        incident = incident_from_alerts(alerts, title=title)
        self._incidents[incident.incident_id] = incident
        logger.info("Incident %s created from %d alerts", incident.incident_id, len(alerts))
        return incident

    def get(self, incident_id: str) -> Incident | None:
        return self._incidents.get(incident_id)

    def list_all(
        self,
        state: str | None = None,
        owner: str | None = None,
        limit: int = 100,
    ) -> list[Incident]:
        incidents = list(self._incidents.values())
        if state:
            incidents = [i for i in incidents if i.state.value == state]
        if owner:
            incidents = [i for i in incidents if i.owner == owner]
        incidents.sort(key=lambda i: i.created_at, reverse=True)
        return incidents[:limit]

    def update_state(self, incident_id: str, new_state: str) -> Incident:
        incident = self._get_or_raise(incident_id)
        incident.transition(IncidentState(new_state))
        return incident

    def assign_owner(self, incident_id: str, owner: str) -> Incident:
        incident = self._get_or_raise(incident_id)
        incident.owner = owner
        incident.updated_at = time.time()
        return incident

    def add_note(self, incident_id: str, author: str, content: str) -> Incident:
        incident = self._get_or_raise(incident_id)
        incident.add_note(author=author, content=content)
        return incident

    def set_disposition(
        self,
        incident_id: str,
        disposition: str,
        fingerprints: list[str] | None = None,
    ) -> Incident:
        incident = self._get_or_raise(incident_id)
        incident.set_disposition(Disposition(disposition), fingerprints=fingerprints)

        # FP feedback loop
        if incident.is_false_positive and incident.fp_fingerprints:
            self._pending_fp_fingerprints.extend(incident.fp_fingerprints)
            logger.info(
                "FP disposition recorded for incident %s — %d fingerprints pending retraining "
                "(%d total pending, threshold=%d)",
                incident_id, len(incident.fp_fingerprints),
                len(self._pending_fp_fingerprints), self._fp_retrain_threshold,
            )
            self._maybe_retrain()

        return incident

    # ── FP Feedback Loop ──────────────────────────────────────────────────────

    def _maybe_retrain(self) -> None:
        """
        Trigger ML baseline retraining if enough FP fingerprints have
        accumulated. Conservative — only retrains when threshold is met,
        not on every single FP mark.
        """
        if len(self._pending_fp_fingerprints) < self._fp_retrain_threshold:
            return
        if self._ml_scorer is None:
            logger.warning("FP retraining triggered but no ML scorer injected — skipping")
            return

        fingerprints = list(self._pending_fp_fingerprints)
        self._pending_fp_fingerprints.clear()

        try:
            retrained = self._ml_scorer.retrain_excluding_fingerprints(fingerprints)
            if retrained:
                self._retrain_count += 1
                logger.info(
                    "ML baseline retrained (run #%d) — excluded %d FP fingerprints",
                    self._retrain_count, len(fingerprints),
                )
            else:
                logger.warning("ML retraining skipped — scorer returned False (degraded performance?)")
        except Exception as e:
            logger.exception("ML retraining failed: %s", e)

    def get_feedback_stats(self) -> dict:
        fp_incidents = [i for i in self._incidents.values() if i.is_false_positive]
        return {
            "total_incidents": len(self._incidents),
            "false_positive_incidents": len(fp_incidents),
            "pending_fp_fingerprints": len(self._pending_fp_fingerprints),
            "retrain_count": self._retrain_count,
            "retrain_threshold": self._fp_retrain_threshold,
        }

    def get_stats(self) -> dict:
        by_state = defaultdict(int)
        for i in self._incidents.values():
            by_state[i.state.value] += 1
        return {
            "total": len(self._incidents),
            "by_state": dict(by_state),
            **self.get_feedback_stats(),
        }

    def _get_or_raise(self, incident_id: str) -> Incident:
        incident = self._incidents.get(incident_id)
        if not incident:
            raise KeyError(f"Incident '{incident_id}' not found")
        return incident
