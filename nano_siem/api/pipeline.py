"""
api/pipeline.py — Pipeline Manager for API Mode

Runs the full NanoSIEM detection pipeline as a background asyncio task
alongside the FastAPI server. Exposes stats, alerts, and events via
thread-safe data structures that the REST endpoints read from.

Architecture:
  PipelineManager.start() launches:
    - Sigma engine (loaded once, hot-reloaded every 60s)
    - Correlator
    - ML scorer
    - Alert manager
    - Network listeners (UDP syslog, TCP syslog, TCP JSON)
    - Pipeline consumer (parse → normalize → detect → alert)
    - WebSocket broadcaster (pushes events+alerts to dashboard)
"""

from __future__ import annotations

import asyncio
import collections
import logging
import time
from typing import Any

from nano_siem.alerting.manager import Alert, AlertManager
from nano_siem.alerting.stix_output import write_alert_log, write_bundle
from nano_siem.correlation.chainer import Correlator
from nano_siem.correlation.chains import BUILTIN_CHAINS
from nano_siem.ingestion.listener import (
    RawMessage,
    TCPJsonListener,
    TCPSyslogListener,
    UDPSyslogListener,
)
from nano_siem.ingestion.normalizer import normalize
from nano_siem.ingestion.parser import parse
from nano_siem.ml.scorer import AnomalyScorer
from nano_siem.sigma.evaluator import SigmaEngine
from nano_siem.storage.ringbuffer import EventRingBuffer

logger = logging.getLogger(__name__)

# Max alerts and events to keep in memory for the API
_MAX_MEMORY_ALERTS = 500
_MAX_MEMORY_EVENTS = 1000


class PipelineManager:
    """
    Manages the full NanoSIEM pipeline in API mode.
    Thread-safe reads via deques, asyncio writes from pipeline coroutine.
    """

    def __init__(self, config: dict[str, Any]) -> None:
        self._config = config
        self._running = False
        self._tasks: list[asyncio.Task] = []
        self._ws_manager = None

        # In-memory stores for API reads
        self._recent_alerts: collections.deque[dict] = collections.deque(maxlen=_MAX_MEMORY_ALERTS)
        self._recent_events: collections.deque[dict] = collections.deque(maxlen=_MAX_MEMORY_EVENTS)

        # Pipeline stats
        self._stats: dict[str, Any] = {
            "events_processed": 0,
            "sigma_hits": 0,
            "chain_alerts": 0,
            "ml_anomalies": 0,
            "alerts_written": 0,
            "deduped": 0,
            "errors": 0,
            "events_per_sec": 0.0,
            "uptime_seconds": 0.0,
            "tracked_sources": 0,
            "buffered_events": 0,
            "ml_avg_score": 0.0,
            "ml_max_score": 0.0,
        }
        self._start_time = time.time()
        self._last_eps_check = time.time()
        self._eps_event_count = 0

        # Components (initialized in start())
        self.sigma_engine: SigmaEngine | None = None
        self._hot_reload = None
        self._correlator: Correlator | None = None
        self._scorer: AnomalyScorer | None = None
        self._alert_manager: AlertManager | None = None
        self._storage: EventRingBuffer | None = None
        self._queue: asyncio.Queue[RawMessage] | None = None

    @property
    def running(self) -> bool:
        return self._running

    def register_ws_manager(self, ws_manager) -> None:
        self._ws_manager = ws_manager

    async def start(self) -> None:
        """Initialize all components and start background tasks."""
        cfg = self._config
        ingest_cfg = cfg.get("ingestion", {})
        storage_cfg = cfg.get("storage", {})
        sigma_cfg = cfg.get("sigma", {})
        corr_cfg = cfg.get("correlation", {})
        ml_cfg = cfg.get("ml", {})
        alert_cfg = cfg.get("alerting", {})

        # Queue
        self._queue = asyncio.Queue(maxsize=10_000)

        # Sigma
        self.sigma_engine = SigmaEngine(
            rules_dir=sigma_cfg.get("rules_dir", "rules/"),
            reload_interval=sigma_cfg.get("reload_interval", 60),
        )
        self.sigma_engine.load()
        logger.info("Sigma engine: %d rules loaded", self.sigma_engine.rule_count)

        # Hot reload manager — watches rules dir, validates before swap,
        # updates sigma_engine's rule set live
        from nano_siem.detection.hot_reload import HotReloadManager
        rules_dir = sigma_cfg.get("rules_dir", "rules/")
        self._hot_reload = HotReloadManager(
            rules_dir,
            check_interval=sigma_cfg.get("reload_interval", 60),
        )
        self._hot_reload.set_on_reload(self._on_rules_reloaded)

        # Correlator
        self._correlator = Correlator(
            chains=BUILTIN_CHAINS,
            max_window_seconds=corr_cfg.get("window_seconds", 1800),
            max_events_per_source=corr_cfg.get("max_events_per_host", 500),
            dedup_window_seconds=alert_cfg.get("dedup_window_seconds", 300),
        )

        # ML scorer
        self._scorer = AnomalyScorer(
            model_path=ml_cfg.get("model_path", "data/baseline.joblib"),
            threshold=ml_cfg.get("anomaly_threshold", 0.62),
        )
        if ml_cfg.get("train_on_startup", True):
            await self._scorer.load_or_train()
            logger.info("ML model ready")

        # Alert manager
        self._alert_manager = AlertManager(
            output_dir=alert_cfg.get("output_dir", "alerts/"),
            dedup_window_seconds=alert_cfg.get("dedup_window_seconds", 300),
            stix_output=alert_cfg.get("stix_output", True),
            min_severity=alert_cfg.get("min_severity", "low"),
        )

        # Storage
        self._storage = EventRingBuffer(
            db_path=storage_cfg.get("db_path", "data/events.db"),
            max_events=storage_cfg.get("max_events", 100_000),
        )

        # Listeners
        listeners = [
            UDPSyslogListener(
                ingest_cfg.get("syslog_host", "0.0.0.0"),
                ingest_cfg.get("syslog_port", 5140),
                self._queue,
            ),
            TCPSyslogListener(
                ingest_cfg.get("syslog_host", "0.0.0.0"),
                ingest_cfg.get("syslog_port", 5140),
                self._queue,
            ),
            TCPJsonListener(
                ingest_cfg.get("json_host", "0.0.0.0"),
                ingest_cfg.get("json_port", 5141),
                self._queue,
            ),
        ]

        self._running = True

        # Start background tasks
        loop = asyncio.get_running_loop()
        for listener in listeners:
            task = loop.create_task(listener.start())
            self._tasks.append(task)

        consumer = loop.create_task(self._consume())
        self._tasks.append(consumer)

        stats_updater = loop.create_task(self._update_stats_loop())
        self._tasks.append(stats_updater)

        if self._hot_reload:
            await self._hot_reload.start()

        logger.info("PipelineManager started — %d listeners, pipeline consumer running",
                    len(listeners))

    async def stop(self) -> None:
        """Cancel all background tasks and close storage."""
        self._running = False
        if self._hot_reload:
            await self._hot_reload.stop()
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        if self._storage:
            self._storage.close()
        logger.info("PipelineManager stopped")

    def _on_rules_reloaded(self, new_rules) -> None:
        """Callback fired by HotReloadManager when rules change and pass validation."""
        if self.sigma_engine:
            self.sigma_engine.set_rules(new_rules)
            logger.info("Sigma engine rule set updated live: %d rules", len(new_rules))

    async def _consume(self) -> None:
        """Main pipeline consumer — runs for the lifetime of the server."""
        while self._running:
            try:
                raw_msg: RawMessage = await asyncio.wait_for(
                    self._queue.get(), timeout=1.0
                )
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break

            try:
                # Parse + normalize
                parsed = parse(raw_msg.data)
                if parsed.host == "unknown" and raw_msg.source_addr:
                    parsed.host = raw_msg.source_addr[0]
                event = normalize(parsed)

                # Sigma
                sigma_matches = self.sigma_engine.evaluate(event) if self.sigma_engine else []
                if sigma_matches:
                    self._stats["sigma_hits"] += len(sigma_matches)

                # Correlation
                corr_alerts = await self._correlator.ingest(event) if self._correlator else []
                if corr_alerts:
                    self._stats["chain_alerts"] += len(corr_alerts)

                # ML
                scored = self._scorer.score(event) if self._scorer and self._scorer.is_loaded else None
                if scored and scored.is_anomalous:
                    self._stats["ml_anomalies"] += 1

                # Alert manager
                new_alerts: list[Alert] = []
                if self._alert_manager:
                    new_alerts = await self._alert_manager.process(
                        event, sigma_matches, corr_alerts, scored
                    )
                    for alert in new_alerts:
                        self._stats["alerts_written"] += 1
                        alert_dict = alert.to_dict()
                        self._recent_alerts.appendleft(alert_dict)
                        try:
                            write_bundle(alert, self._alert_manager._output_dir)
                            write_alert_log(alert, self._alert_manager._output_dir)
                        except Exception as e:
                            logger.warning("Failed to write alert: %s", e)

                # Store event
                if self._storage:
                    await self._storage.insert(event)

                # Add to in-memory event store
                event_dict = event.to_dict()
                self._recent_events.appendleft(event_dict)

                # Update stats
                self._stats["events_processed"] += 1
                self._eps_event_count += 1

                # Broadcast to WebSocket clients
                if self._ws_manager:
                    await self._ws_manager.broadcast({
                        "type": "event",
                        "data": _event_to_ws(event, sigma_matches, corr_alerts, scored, new_alerts),
                    })
                    for alert in new_alerts:
                        await self._ws_manager.broadcast({
                            "type": "alert",
                            "data": alert.to_dict(),
                        })

            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.exception("Pipeline error: %s", exc)
                self._stats["errors"] += 1
            finally:
                self._queue.task_done()

    async def _update_stats_loop(self) -> None:
        """Update events/sec and uptime every 2 seconds."""
        while self._running:
            await asyncio.sleep(2)
            now = time.time()
            elapsed = now - self._last_eps_check
            if elapsed > 0:
                self._stats["events_per_sec"] = round(self._eps_event_count / elapsed, 1)
                self._eps_event_count = 0
                self._last_eps_check = now
            self._stats["uptime_seconds"] = round(now - self._start_time, 1)
            if self._correlator:
                cs = self._correlator.get_stats()
                self._stats["tracked_sources"] = cs.get("tracked_sources", 0)
                self._stats["buffered_events"] = cs.get("buffered_events", 0)
            if self._scorer:
                ms = self._scorer.get_stats()
                self._stats["ml_avg_score"] = round(ms.get("avg_score", 0.0), 3)
                self._stats["ml_max_score"] = round(ms.get("max_score", 0.0), 3)
            if self._alert_manager:
                mgr_stats = self._alert_manager.get_stats()
                self._stats["deduped"] = mgr_stats.get("deduped", 0)

            # Broadcast stats update
            if self._ws_manager:
                await self._ws_manager.broadcast({
                    "type": "stats",
                    "data": self._stats.copy(),
                })

    def get_stats(self) -> dict:
        return self._stats.copy()

    def get_recent_alerts(
        self,
        limit: int = 50,
        offset: int = 0,
        severity: str | None = None,
        alert_type: str | None = None,
    ) -> list[dict]:
        alerts = list(self._recent_alerts)
        if severity:
            alerts = [a for a in alerts if a.get("severity") == severity]
        if alert_type:
            alerts = [a for a in alerts if a.get("alert_type") == alert_type]
        return alerts[offset:offset + limit]

    async def get_recent_events(
        self,
        limit: int = 100,
        offset: int = 0,
        host: str | None = None,
        has_alert: bool | None = None,
    ) -> list[dict]:
        if self._storage:
            return await self._storage.query(
                host=host, has_alert=has_alert, limit=limit, offset=offset
            )
        events = list(self._recent_events)
        if host:
            events = [e for e in events if e.get("host") == host]
        return events[offset:offset + limit]


def _event_to_ws(event, sigma_matches, corr_alerts, scored, new_alerts) -> dict:
    """Build the WebSocket event payload."""
    return {
        "event_id": event.event_id,
        "timestamp": event.timestamp.isoformat(),
        "host": event.host,
        "source_ip": event.source_ip,
        "dest_port": event.dest_port,
        "log_source": event.log_source,
        "program": event.program,
        "severity": event.severity,
        "message": event.message[:200],
        "tags": event.tags,
        "sigma_matches": [m.rule.title for m in sigma_matches],
        "sigma_levels": [m.rule.level for m in sigma_matches],
        "chain_alerts": [a.title for a in corr_alerts],
        "chain_severities": [a.severity for a in corr_alerts],
        "anomaly_score": event.anomaly_score,
        "is_anomalous": scored.is_anomalous if scored else False,
        "alert_count": len(new_alerts),
        "alert_ids": [a.alert_id for a in new_alerts],
    }
