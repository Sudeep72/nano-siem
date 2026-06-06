"""
main.py — Pipeline Orchestrator

Wires together all Phase 1 components:
  Listeners → Queue → Parser → Normalizer → Storage → Console Output

Later phases will insert:
  → Sigma Evaluator → Correlation Engine → ML Scorer → Alert Manager

The pipeline is entirely async. The queue decouples network I/O from
processing, allowing listeners to run at line-rate without blocking on
parsing or DB writes.
"""

from __future__ import annotations
import asyncio
import logging
import signal
import sys
from pathlib import Path
from typing import Any

import yaml

from nano_siem.ingestion.listener import (
    UDPSyslogListener,
    TCPSyslogListener,
    TCPJsonListener,
    FileTailListener,
    RawMessage,
)
from nano_siem.ingestion.parser import parse
from nano_siem.ingestion.normalizer import normalize
from nano_siem.storage.ringbuffer import EventRingBuffer
from nano_siem.schema import NormalizedEvent
from nano_siem.sigma.evaluator import SigmaEngine, RuleMatch
from nano_siem.correlation.chainer import Correlator, CorrelationAlert
from nano_siem.ml.scorer import AnomalyScorer
from nano_siem.alerting.manager import AlertManager, Alert
from nano_siem.alerting.stix_output import write_bundle, write_alert_log

logger = logging.getLogger(__name__)


def load_config(path: str = "config.yaml") -> dict[str, Any]:
    with open(path) as f:
        return yaml.safe_load(f)


def setup_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )


async def process_queue(
    queue: asyncio.Queue[RawMessage],
    storage: EventRingBuffer,
    sigma_engine: SigmaEngine | None = None,
    correlator: Correlator | None = None,
    scorer: AnomalyScorer | None = None,
    alert_manager: AlertManager | None = None,
    console_output: bool = True,
    stats: dict[str, int] | None = None,
) -> None:
    """
    Main pipeline consumer.

    Pulls RawMessages from the queue, parses + normalizes them,
    stores to SQLite, and optionally prints to console.

    This is the extension point for future phases:
      - After normalize(), call sigma_evaluator.evaluate(event)
      - After sigma, call correlator.ingest(event)
      - After correlation, call ml_scorer.score(event)
      - After scoring, call alert_manager.process(event)
    """
    if stats is None:
        stats = {}

    while True:
        try:
            raw_msg: RawMessage = await queue.get()
        except asyncio.CancelledError:
            break

        try:
            # ── Parse ──────────────────────────────────────────────────────
            parsed = parse(raw_msg.data)

            # Attach source addr from listener if parser couldn't get it
            if parsed.host == "unknown" and raw_msg.source_addr:
                parsed.host = raw_msg.source_addr[0]

            # ── Normalize ──────────────────────────────────────────────────
            event: NormalizedEvent = normalize(parsed)

            # Phase 2 — Sigma evaluation
            sigma_matches = []
            if sigma_engine:
                sigma_matches = sigma_engine.evaluate(event)
                if sigma_matches:
                    stats["sigma_hits"] = stats.get("sigma_hits", 0) + len(sigma_matches)

            # Phase 3 — Correlation
            corr_alerts = []
            if correlator:
                corr_alerts = await correlator.ingest(event)
                if corr_alerts:
                    stats["corr_alerts"] = stats.get("corr_alerts", 0) + len(corr_alerts)

            # Phase 4 — ML anomaly scoring
            scored = None
            if scorer and scorer.is_loaded:
                scored = scorer.score(event)
                if scored.is_anomalous:
                    stats["ml_anomalies"] = stats.get("ml_anomalies", 0) + 1

            # Phase 5 — Alert manager + STIX output
            new_alerts: list[Alert] = []
            if alert_manager:
                new_alerts = await alert_manager.process(
                    event, sigma_matches, corr_alerts, scored
                )
                for alert in new_alerts:
                    stats["alerts_written"] = stats.get("alerts_written", 0) + 1
                    try:
                        write_bundle(alert, alert_manager._output_dir)
                        write_alert_log(alert, alert_manager._output_dir)
                    except Exception as e:
                        logger.warning("Failed to write alert: %s", e)

            # ── Store ──────────────────────────────────────────────────────
            await storage.insert(event)

            # ── Console output ─────────────────────────────────────────────
            if console_output:
                _print_event(event, sigma_matches, corr_alerts, scored, new_alerts)

            # ── Stats ──────────────────────────────────────────────────────
            stats["processed"] = stats.get("processed", 0) + 1

        except Exception as exc:
            logger.exception("Pipeline error processing message: %s", exc)
            stats["errors"] = stats.get("errors", 0) + 1
        finally:
            queue.task_done()


def _print_event(
    event: NormalizedEvent,
    sigma_matches: list | None = None,
    corr_alerts: list | None = None,
    scored=None,
    new_alerts: list | None = None,
) -> None:
    """Pretty-print a normalized event to stdout."""
    tags_str = " ".join(
        f"[{t}]" for t in event.tags
        if not any(t.startswith(p) for p in ("sigma:", "level:", "correlated:", "chain_", "ml:"))
    )
    src = f"{event.source_ip}:{event.source_port}" if event.source_ip else event.host
    if sigma_matches:
        for m in sigma_matches:
            print(f"\033[91m  ⚡ SIGMA  [{m.rule.level.upper():8}] {m.rule.title}\033[0m")
    if corr_alerts:
        for a in corr_alerts:
            print(f"\033[95m  🔗 CHAIN  [{a.severity.upper():8}] {a.title} | src={a.source_key} | {a.duration_seconds:.0f}s\033[0m")
    if scored and scored.is_anomalous:
        top = ", ".join(f"{f}={v:.2f}" for f, v in scored.top_features[:3])
        print(f"\033[93m  🤖 ML     [ANOMALOUS] score={scored.anomaly_score:.3f} | drivers: {top}\033[0m")
    if new_alerts:
        for a in new_alerts:
            print(f"\033[96m  📄 STIX   [{a.severity.upper():8}] {a.alert_type.upper()} alert written → alerts/{a.alert_id[:8]}\033[0m")
    print(
        f"  {event.timestamp.strftime('%H:%M:%S')} "
        f"| {event.log_source:<14} "
        f"| {src:<22} "
        f"| {(event.program or 'unknown'):<16} "
        f"| {event.message[:70]:<70} "
        f"{tags_str}"
    )


async def run(config_path: str = "config.yaml", tail_file: str | None = None) -> None:
    """
    Start the nano-siem pipeline.

    Args:
        config_path: Path to config.yaml
        tail_file:   Optional log file to tail (bypasses network listeners)
    """
    cfg = load_config(config_path)
    setup_logging(cfg.get("logging", {}).get("level", "INFO"))

    ingest_cfg = cfg.get("ingestion", {})
    storage_cfg = cfg.get("storage", {})

    # Ingestion queue — bounded to apply backpressure when processing is slow
    queue: asyncio.Queue[RawMessage] = asyncio.Queue(maxsize=10_000)

    # Storage
    storage = EventRingBuffer(
        db_path=storage_cfg.get("db_path", "data/events.db"),
        max_events=storage_cfg.get("max_events", 100_000),
    )

    sigma_cfg = cfg.get("sigma", {})

    # Sigma engine
    sigma_engine = SigmaEngine(
        rules_dir=sigma_cfg.get("rules_dir", "rules/"),
        reload_interval=sigma_cfg.get("reload_interval", 60),
    )
    n_rules = sigma_engine.load()

    corr_cfg = cfg.get("correlation", {})
    correlator = Correlator(
        max_window_seconds=corr_cfg.get("window_seconds", 1800),
        max_events_per_source=corr_cfg.get("max_events_per_host", 500),
        dedup_window_seconds=cfg.get("alerting", {}).get("dedup_window_seconds", 300),
    )

    ml_cfg = cfg.get("ml", {})
    scorer = AnomalyScorer(
        model_path=ml_cfg.get("model_path", "data/baseline.joblib"),
        threshold=ml_cfg.get("anomaly_threshold", 0.62),
        train_n_samples=ml_cfg.get("train_n_samples", 2000),
    )
    if ml_cfg.get("train_on_startup", True):
        print("  Training ML baseline model...")
        await scorer.load_or_train()
        print(f"  ML model ready ({scorer.get_stats()['training_samples']} training samples)")

    alert_cfg = cfg.get("alerting", {})
    alert_manager = AlertManager(
        output_dir=alert_cfg.get("output_dir", "alerts/"),
        dedup_window_seconds=alert_cfg.get("dedup_window_seconds", 300),
        stix_output=alert_cfg.get("stix_output", True),
        min_severity=alert_cfg.get("min_severity", "low"),
    )

    console = alert_cfg.get("console_output", True)
    stats: dict[str, int] = {}

    # Build listener list
    listeners = []
    if tail_file:
        listeners.append(FileTailListener(tail_file, queue, seek_to_end=False))
    else:
        listeners.append(
            UDPSyslogListener(
                ingest_cfg.get("syslog_host", "0.0.0.0"),
                ingest_cfg.get("syslog_port", 5140),
                queue,
            )
        )
        if ingest_cfg.get("syslog_protocol", "udp") == "tcp":
            listeners.append(
                TCPSyslogListener(
                    ingest_cfg.get("syslog_host", "0.0.0.0"),
                    ingest_cfg.get("syslog_port", 5140),
                    queue,
                )
            )
        listeners.append(
            TCPJsonListener(
                ingest_cfg.get("json_host", "0.0.0.0"),
                ingest_cfg.get("json_port", 5141),
                queue,
            )
        )

    print("\n  nano-siem v0.1.0 — Phase 1: Ingestion Pipeline")
    print("  " + "─" * 60)
    print(f"  DB path   : {storage_cfg.get('db_path', 'data/events.db')}")
    if tail_file:
        print(f"  Mode      : File tail → {tail_file}")
    else:
        print(f"  UDP syslog: {ingest_cfg.get('syslog_host')}:{ingest_cfg.get('syslog_port')}")
        print(f"  TCP JSON  : {ingest_cfg.get('json_host')}:{ingest_cfg.get('json_port')}")
    print(f"  Sigma rules: {n_rules} loaded from {sigma_cfg.get('rules_dir', 'rules/')}")
    print("  " + "─" * 60)
    print(f"  {'TIME':<10} | {'FORMAT':<14} | {'SOURCE':<22} | {'PROGRAM':<16} | MESSAGE")
    print("  " + "─" * 60)

    # Graceful shutdown on SIGINT/SIGTERM
    shutdown_event = asyncio.Event()

    def _handle_signal() -> None:
        logger.info("Shutdown signal received")
        shutdown_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _handle_signal)
        except NotImplementedError:
            pass  # Windows

    # Start all tasks
    async with asyncio.TaskGroup() as tg:
        # Listeners
        listener_tasks = [tg.create_task(l.start()) for l in listeners]
        # Pipeline consumer
        consumer_task = tg.create_task(
            process_queue(
                queue, storage,
                sigma_engine=sigma_engine,
                correlator=correlator,
                scorer=scorer,
                alert_manager=alert_manager,
                console_output=console,
                stats=stats,
            )
        )
        # Shutdown watcher
        async def _watch_shutdown() -> None:
            await shutdown_event.wait()
            for t in listener_tasks:
                t.cancel()
            consumer_task.cancel()

        tg.create_task(_watch_shutdown())

    storage.close()
    mgr_stats = alert_manager.get_stats() if alert_manager else {}
    print(
        f"\n  Processed: {stats.get('processed', 0)} events"
        f" | Sigma: {stats.get('sigma_hits', 0)}"
        f" | Chains: {stats.get('corr_alerts', 0)}"
        f" | ML anomalies: {stats.get('ml_anomalies', 0)}"
        f" | Alerts written: {stats.get('alerts_written', 0)}"
        f" | Deduped: {mgr_stats.get('deduped', 0)}"
        f" | Errors: {stats.get('errors', 0)}"
    )
