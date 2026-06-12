"""
api/models.py — Pydantic response models for the FastAPI backend.

Every API endpoint returns one of these models.
Pydantic handles serialization and OpenAPI schema generation automatically.
"""

from __future__ import annotations

from pydantic import BaseModel


class AlertModel(BaseModel):
    alert_id: str
    alert_type: str          # sigma | correlation | ml
    title: str
    severity: str            # low | medium | high | critical
    source_key: str
    event_message: str
    timestamp: float
    hit_count: int
    anomaly_score: float | None
    mitre_tactic: str
    mitre_techniques: list[str]
    chain_steps: list[dict]
    xai_features: list[dict]
    sigma_tags: list[str]
    fingerprint: str


class EventModel(BaseModel):
    event_id: str
    timestamp: str
    host: str
    source_ip: str | None
    dest_port: int | None
    log_source: str
    program: str | None
    severity: str | None
    facility: str | None
    message: str
    tags: list[str]
    sigma_matches: list[str]
    anomaly_score: float | None
    alert_id: str | None


class StatsModel(BaseModel):
    events_processed: int
    sigma_hits: int
    chain_alerts: int
    ml_anomalies: int
    alerts_written: int
    deduped: int
    errors: int
    events_per_sec: float
    uptime_seconds: float
    tracked_sources: int
    buffered_events: int
    ml_avg_score: float
    ml_max_score: float


class RuleModel(BaseModel):
    title: str
    level: str
    status: str
    id: str
    tags: list[str]
    description: str
    source_file: str
    mitre_techniques: list[str]


class CoverageModel(BaseModel):
    total_rules: int
    total_chains: int
    techniques_covered: int
    techniques_known: int
    coverage_percent: float
    tactics: dict[str, list[dict]]


class ChainModel(BaseModel):
    id: str
    title: str
    description: str
    severity: str
    window_seconds: int
    mitre_tactic: str
    mitre_techniques: list[str]
    steps: list[str]


class HealthModel(BaseModel):
    status: str
    version: str
    pipeline_running: bool
    rules_loaded: int
    uptime_seconds: float
