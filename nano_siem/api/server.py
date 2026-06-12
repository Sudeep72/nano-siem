"""
api/server.py — NanoSIEM FastAPI Backend

Provides REST endpoints and a WebSocket live event stream
for the v3 React dashboard.

Endpoints:
  GET  /                    Health check
  GET  /api/health          Health + pipeline status
  GET  /api/stats           Pipeline stats (events/sec, hits, anomalies)
  GET  /api/alerts          Recent alerts (paginated)
  GET  /api/events          Recent events from ring buffer (paginated)
  GET  /api/rules           Loaded Sigma rules
  GET  /api/chains          Built-in correlation chains
  GET  /api/coverage        ATT&CK coverage JSON
  WS   /ws/events           Live event+alert stream (WebSocket broadcast)

The pipeline runs as a background task alongside the API server.
WebSocket clients receive every event+alert as it fires — no polling needed.
"""

from __future__ import annotations

import asyncio
import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import yaml
from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from nano_siem.api.models import (
    AlertModel,
    ChainModel,
    CoverageModel,
    EventModel,
    HealthModel,
    RuleModel,
    StatsModel,
)
from nano_siem.api.pipeline import PipelineManager

logger = logging.getLogger(__name__)

# ── Global pipeline manager ───────────────────────────────────────────────────
_pipeline: PipelineManager | None = None
_start_time: float = time.time()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Start the detection pipeline when the API server starts."""
    global _pipeline
    config = _load_config()
    _pipeline = PipelineManager(config)
    await _pipeline.start()
    logger.info("NanoSIEM pipeline started via API server")
    yield
    await _pipeline.stop()
    logger.info("NanoSIEM pipeline stopped")


def _load_config(path: str = "config.yaml") -> dict[str, Any]:
    try:
        with open(path) as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        return {}


# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="NanoSIEM API",
    description="NanoSIEM v3.0 — SOC Operations Edition REST API",
    version="3.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # dev mode — restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── WebSocket connection manager ──────────────────────────────────────────────
class ConnectionManager:
    def __init__(self) -> None:
        self._connections: list[WebSocket] = []

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._connections.append(ws)
        logger.debug("WebSocket client connected. Total: %d", len(self._connections))

    def disconnect(self, ws: WebSocket) -> None:
        if ws in self._connections:
            self._connections.remove(ws)
        logger.debug("WebSocket client disconnected. Total: %d", len(self._connections))

    async def broadcast(self, message: dict) -> None:
        dead = []
        for ws in self._connections:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

    @property
    def connection_count(self) -> int:
        return len(self._connections)


ws_manager = ConnectionManager()


# ── REST Endpoints ────────────────────────────────────────────────────────────

@app.get("/", response_model=HealthModel)
async def root():
    return await health()


@app.get("/api/health", response_model=HealthModel)
async def health():
    rules_loaded = 0
    if _pipeline:
        rules_loaded = _pipeline.sigma_engine.rule_count if _pipeline.sigma_engine else 0
    return HealthModel(
        status="ok",
        version="3.0.0",
        pipeline_running=_pipeline is not None and _pipeline.running,
        rules_loaded=rules_loaded,
        uptime_seconds=round(time.time() - _start_time, 1),
    )


@app.get("/api/stats", response_model=StatsModel)
async def stats():
    if not _pipeline:
        raise HTTPException(503, "Pipeline not running")
    s = _pipeline.get_stats()
    return StatsModel(**s)


@app.get("/api/alerts", response_model=list[AlertModel])
async def get_alerts(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    severity: str | None = Query(None),
    alert_type: str | None = Query(None),
):
    if not _pipeline:
        raise HTTPException(503, "Pipeline not running")
    alerts = _pipeline.get_recent_alerts(limit=limit, offset=offset,
                                          severity=severity, alert_type=alert_type)
    return alerts


@app.get("/api/events", response_model=list[EventModel])
async def get_events(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    host: str | None = Query(None),
    has_alert: bool | None = Query(None),
):
    if not _pipeline:
        raise HTTPException(503, "Pipeline not running")
    events = await _pipeline.get_recent_events(limit=limit, offset=offset,
                                                host=host, has_alert=has_alert)
    return events


@app.get("/api/rules", response_model=list[RuleModel])
async def get_rules():
    if not _pipeline or not _pipeline.sigma_engine:
        raise HTTPException(503, "Pipeline not running")
    rules = []
    for rule in _pipeline.sigma_engine._rules:
        mitre = [t for t in rule.tags if t.lower().startswith("attack.t")]
        rules.append(RuleModel(
            title=rule.title,
            level=rule.level,
            status=rule.status,
            id=rule.id,
            tags=rule.tags,
            description=rule.description,
            source_file=Path(rule.source_file).name,
            mitre_techniques=mitre,
        ))
    return sorted(rules, key=lambda r: -{"critical":5,"high":4,"medium":3,"low":2,"informational":1}.get(r.level,0))


@app.get("/api/chains", response_model=list[ChainModel])
async def get_chains():
    from nano_siem.correlation.chains import BUILTIN_CHAINS
    return [
        ChainModel(
            id=c.id,
            title=c.title,
            description=c.description,
            severity=c.severity,
            window_seconds=c.window_seconds,
            mitre_tactic=c.mitre_tactic,
            mitre_techniques=c.mitre_techniques,
            steps=[s.name for s in c.steps],
        )
        for c in BUILTIN_CHAINS
    ]


@app.get("/api/coverage", response_model=CoverageModel)
async def get_coverage():
    if not _pipeline or not _pipeline.sigma_engine:
        raise HTTPException(503, "Pipeline not running")
    from nano_siem.correlation.chains import BUILTIN_CHAINS
    from nano_siem.detection.coverage import build_coverage_report
    rules = _pipeline.sigma_engine._rules
    report = build_coverage_report(rules, BUILTIN_CHAINS)
    d = report.to_dict()
    return CoverageModel(**d)


# ── WebSocket endpoint ────────────────────────────────────────────────────────

@app.websocket("/ws/events")
async def websocket_events(ws: WebSocket):
    """
    Live event stream. Sends JSON messages as events flow through the pipeline.

    Message types:
      { "type": "event",  "data": EventModel }
      { "type": "alert",  "data": AlertModel }
      { "type": "stats",  "data": StatsModel }
      { "type": "ping",   "data": {} }
    """
    await ws_manager.connect(ws)
    if _pipeline:
        _pipeline.register_ws_manager(ws_manager)
    try:
        # Send a welcome ping with current stats
        if _pipeline:
            await ws.send_json({"type": "ping", "data": {"connected": True,
                "clients": ws_manager.connection_count}})
        while True:
            # Keep connection alive — pipeline pushes data via broadcast
            await asyncio.sleep(30)
            await ws.send_json({"type": "ping", "data": {}})
    except WebSocketDisconnect:
        ws_manager.disconnect(ws)
    except Exception:
        ws_manager.disconnect(ws)
