"""
alerting/stix_output.py — STIX 2.1 Alert Serializer

Converts Alert objects into valid STIX 2.1 bundles and writes them to disk.

STIX objects produced per alert:
  - Indicator    (what was detected — the pattern)
  - Sighting     (this specific occurrence)
  - ObservedData (the raw event that triggered the alert)
  - ThreatActor  (placeholder with source IP, for correlation alerts)
  - Bundle       (wraps all of the above)

STIX 2.1 spec references:
  https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html

Output format:
  alerts/<YYYY-MM-DD>/alert-<alert_id>.json
  Each file is a self-contained STIX Bundle.
"""

from __future__ import annotations
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path

from nano_siem.alerting.manager import Alert

logger = logging.getLogger(__name__)

# STIX 2.1 timestamp format
_STIX_TS = "%Y-%m-%dT%H:%M:%S.000Z"


def _now_stix() -> str:
    return datetime.now(timezone.utc).strftime(_STIX_TS)


def _ts_from_unix(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime(_STIX_TS)


def _stix_id(obj_type: str, local_id: str) -> str:
    """Produce a deterministic STIX ID from type and local identifier."""
    import hashlib
    h = hashlib.sha256(f"{obj_type}:{local_id}".encode()).hexdigest()
    # STIX UUIDs are formatted as type--uuid4-format
    uid = f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"
    return f"{obj_type}--{uid}"


def _severity_to_confidence(severity: str) -> int:
    """Map severity string to STIX confidence (0-100)."""
    return {
        "critical": 95,
        "high": 80,
        "medium": 60,
        "low": 40,
        "informational": 20,
    }.get(severity, 50)


def _build_indicator(alert: Alert) -> dict:
    """
    STIX Indicator — describes WHAT was detected.
    Uses a simplified STIX pattern based on alert type.
    """
    now = _now_stix()
    alert_ts = _ts_from_unix(alert.timestamp)

    # Build a STIX pattern appropriate to the alert type
    if alert.alert_type == "sigma":
        pattern = (
            f"[network-traffic:dst_ref.type = 'ipv4-addr' AND "
            f"process:name = '{alert.source_key}']"
            if not alert.source_key or not re.match(r'\d+\.\d+', alert.source_key)
            else f"[network-traffic:src_ref.value = '{alert.source_key}']"
        )
    elif alert.alert_type == "correlation":
        pattern = (
            f"[network-traffic:src_ref.value = '{alert.source_key}' AND "
            f"network-traffic:dst_port > 0]"
        )
    else:  # ml
        pattern = (
            f"[network-traffic:src_ref.value = '{alert.source_key}']"
            if re.match(r'\d+\.\d+', alert.source_key or "")
            else "[process:name != 'unknown']"
        )

    obj = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": _stix_id("indicator", alert.alert_id),
        "created": now,
        "modified": now,
        "name": alert.title,
        "description": alert.description or alert.title,
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": alert_ts,
        "confidence": _severity_to_confidence(alert.severity),
        "labels": [alert.alert_type, alert.severity],
        "external_references": [],
    }

    # Add MITRE ATT&CK references
    for tech in (alert.mitre_techniques or []):
        tid = tech.upper().replace(".", "")
        if tid.startswith("T"):
            obj["external_references"].append({
                "source_name": "mitre-attack",
                "external_id": tech.upper(),
                "url": f"https://attack.mitre.org/techniques/{tid}/",
            })

    if alert.sigma_tags:
        obj["labels"].extend(
            t for t in alert.sigma_tags if t not in obj["labels"]
        )

    return obj


def _build_sighting(alert: Alert, indicator_id: str) -> dict:
    """STIX Sighting — this specific occurrence of the indicator."""
    now = _now_stix()
    alert_ts = _ts_from_unix(alert.timestamp)
    return {
        "type": "sighting",
        "spec_version": "2.1",
        "id": _stix_id("sighting", f"{alert.alert_id}:sight"),
        "created": now,
        "modified": now,
        "sighting_of_ref": indicator_id,
        "first_seen": _ts_from_unix(alert.first_seen),
        "last_seen": _ts_from_unix(alert.last_seen),
        "count": alert.hit_count,
        "summary": False,
        "description": (
            f"Alert fired {alert.hit_count} time(s). "
            f"Source: {alert.source_key}. "
            f"Triggering message: {alert.event_message[:200]}"
        ),
    }


def _build_observed_data(alert: Alert) -> dict:
    """STIX ObservedData — the raw event that triggered the alert."""
    now = _now_stix()
    alert_ts = _ts_from_unix(alert.timestamp)

    # Build observed objects
    observed_objects: dict = {}
    obj_idx = 0

    # Network traffic if we have a source IP
    if alert.source_key and re.match(r"\d+\.\d+\.\d+\.\d+", alert.source_key):
        observed_objects[str(obj_idx)] = {
            "type": "ipv4-addr",
            "value": alert.source_key,
        }
        src_ref = str(obj_idx)
        obj_idx += 1
        observed_objects[str(obj_idx)] = {
            "type": "network-traffic",
            "src_ref": src_ref,
            "protocols": ["tcp"],
        }
        obj_idx += 1

    # Log entry as artifact
    observed_objects[str(obj_idx)] = {
        "type": "artifact",
        "mime_type": "text/plain",
        "payload_bin": _b64_safe(alert.event_message),
    }

    return {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": _stix_id("observed-data", alert.event_id or alert.alert_id),
        "created": now,
        "modified": now,
        "first_observed": alert_ts,
        "last_observed": alert_ts,
        "number_observed": alert.hit_count,
        "object_refs": [],     # v2.1 uses object_refs, not objects inline
        "custom_properties": {
            "x_nano_siem_alert_id": alert.alert_id,
            "x_nano_siem_alert_type": alert.alert_type,
            "x_nano_siem_event_id": alert.event_id,
            "x_nano_siem_event_message": alert.event_message[:500],
            "x_nano_siem_severity": alert.severity,
            "x_nano_siem_chain_id": alert.chain_id or None,
            "x_nano_siem_anomaly_score": alert.anomaly_score or None,
            "x_nano_siem_xai_features": [
                {"feature": f, "deviation": round(v, 4)}
                for f, v in (alert.xai_features or [])[:5]
            ],
            "x_nano_siem_mitre_tactic": alert.mitre_tactic or None,
            "x_nano_siem_chain_steps": alert.chain_steps or None,
        },
    }


def _b64_safe(text: str) -> str:
    """Base64-encode text safely."""
    import base64
    return base64.b64encode(text.encode("utf-8", errors="replace")).decode("ascii")


def build_bundle(alert: Alert) -> dict:
    """
    Build a complete STIX 2.1 Bundle for one alert.
    Contains: Indicator + Sighting + ObservedData.
    """
    indicator = _build_indicator(alert)
    sighting = _build_sighting(alert, indicator["id"])
    observed = _build_observed_data(alert)

    return {
        "type": "bundle",
        "id": _stix_id("bundle", alert.alert_id),
        "spec_version": "2.1",
        "objects": [indicator, sighting, observed],
    }


def write_bundle(alert: Alert, output_dir: str | Path) -> Path:
    """
    Serialize an Alert to a STIX 2.1 JSON file.

    File path: <output_dir>/<YYYY-MM-DD>/alert-<alert_id[:8]>.json

    Returns path to written file.
    """
    output_dir = Path(output_dir)
    date_str = datetime.fromtimestamp(alert.timestamp, tz=timezone.utc).strftime("%Y-%m-%d")
    day_dir = output_dir / date_str
    day_dir.mkdir(parents=True, exist_ok=True)

    bundle = build_bundle(alert)
    filename = f"alert-{alert.alert_id[:8]}-{alert.alert_type}.json"
    path = day_dir / filename

    with open(path, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2, default=str)

    logger.debug("STIX bundle written: %s", path)
    return path


def write_alert_log(alert: Alert, output_dir: str | Path) -> Path:
    """
    Write a flat JSON alert log entry (non-STIX) for easy parsing/ingestion.
    Appends to a single NDJSON file per day.

    File: <output_dir>/alerts-<YYYY-MM-DD>.ndjson
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    date_str = datetime.fromtimestamp(alert.timestamp, tz=timezone.utc).strftime("%Y-%m-%d")
    path = output_dir / f"alerts-{date_str}.ndjson"
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(alert.to_dict(), default=str) + "\n")
    return path
