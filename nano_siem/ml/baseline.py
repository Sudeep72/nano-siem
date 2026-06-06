"""
ml/baseline.py — Isolation Forest Baseline Trainer

Trains an Isolation Forest on a corpus of "clean" events to learn what
normal traffic looks like. The model is then used by scorer.py to flag
deviations from that baseline.

Training workflow:
  1. Ingest a stream of events considered "clean" (normal hours, known sources)
  2. Extract feature vectors for each
  3. Fit IsolationForest(contamination=0.05) — assumes ≤5% anomalies in training data
  4. Serialize model + feature mean (baseline_vector) to disk with joblib

The baseline_vector is the mean feature vector of the training corpus.
scorer.py uses it for XAI: top features by deviation from baseline.

Synthetic training data:
  generate_clean_corpus() produces realistic clean log events covering:
  - Normal SSH logins from RFC1918 addresses, business hours
  - Routine sudo usage by known service accounts
  - Web traffic to common ports (80, 443)
  - System cron jobs, daemon heartbeats
  - DNS lookups, NTP syncs
"""

from __future__ import annotations
import logging
import os
import random
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from nano_siem.schema import NormalizedEvent
from nano_siem.ml.features import extract, FEATURE_DIM, FEATURE_NAMES

logger = logging.getLogger(__name__)

# ── Baseline model container ──────────────────────────────────────────────────

class BaselineModel:
    """
    Serializable container for the trained IsolationForest and metadata.
    Saved/loaded with joblib.
    """
    def __init__(
        self,
        model: IsolationForest,
        baseline_vector: list[float],
        n_training_samples: int,
        trained_at: str,
        feature_names: list[str],
        score_min: float = -0.65,
        score_max: float = -0.40,
    ) -> None:
        self.model = model
        self.baseline_vector = baseline_vector
        self.n_training_samples = n_training_samples
        self.trained_at = trained_at
        self.feature_names = feature_names
        self.score_min = score_min   # raw score at 1st percentile (most anomalous in training)
        self.score_max = score_max   # raw score at 99th percentile (most normal in training)

    def predict_score(self, vector: list[float]) -> float:
        """
        Score one feature vector → [0.0, 1.0] where 1.0 = most anomalous.
        Uses percentile-calibrated normalization from training data.
        """
        arr = np.array(vector, dtype=np.float32).reshape(1, -1)
        raw = self.model.score_samples(arr)[0]
        # Lower raw score = more anomalous; remap to [0,1] inverted
        span = self.score_max - self.score_min
        if span == 0:
            return 0.5
        normalized = (self.score_max - raw) / span
        return float(np.clip(normalized, 0.0, 1.0))


# ── Synthetic clean corpus generator ─────────────────────────────────────────

def _make_clean_event(
    hour: int,
    source_ip: str,
    program: str,
    message: str,
    severity: str = "info",
    facility: str = "auth",
    dest_port: int | None = None,
    log_source: str = "syslog_rfc5424",
    pid: int | None = None,
) -> NormalizedEvent:
    """Construct a synthetic clean NormalizedEvent for training."""
    e = NormalizedEvent()
    weekday = random.randint(0, 4)     # Monday–Friday
    e.timestamp = datetime(
        2026, random.randint(1, 5), random.randint(1, 28),
        hour, random.randint(0, 59), random.randint(0, 59),
        tzinfo=timezone.utc,
    )
    e.host = f"server-{random.randint(1, 20):02d}"
    e.source_ip = source_ip
    e.program = program
    e.message = message
    e.raw = message
    e.severity = severity
    e.facility = facility
    e.dest_port = dest_port
    e.log_source = log_source
    e.pid = pid or random.randint(1000, 9999)
    e.tags = []
    return e


_INTERNAL_IPS = [
    f"10.0.{b}.{c}" for b in range(0, 5) for c in range(1, 20)
] + [
    f"192.168.1.{c}" for c in range(1, 50)
] + [
    f"172.16.{b}.{c}" for b in range(0, 3) for c in range(1, 10)
]

_SERVICE_ACCOUNTS = [
    "deploy", "ansible", "jenkins", "backup", "monitor",
    "svc-web", "svc-db", "nagios", "zabbix",
]

_BUSINESS_HOURS = list(range(8, 18))


def generate_clean_corpus(n_samples: int = 2000) -> list[NormalizedEvent]:
    """
    Generate n_samples synthetic clean log events representing normal traffic.
    Covers all common event types seen in a healthy Linux environment.
    """
    events: list[NormalizedEvent] = []
    rng = random.Random(42)    # fixed seed for reproducibility

    # ── SSH logins from internal IPs, business hours ──────────────────────────
    n_ssh = n_samples // 5
    for _ in range(n_ssh):
        ip = rng.choice(_INTERNAL_IPS)
        user = rng.choice(_SERVICE_ACCOUNTS)
        hour = rng.choice(_BUSINESS_HOURS)
        events.append(_make_clean_event(
            hour=hour, source_ip=ip, program="sshd",
            message=f"Accepted publickey for {user} from {ip} port {rng.randint(40000, 65000)} ssh2",
            severity="info", facility="authpriv", dest_port=22,
        ))

    # ── Sudo usage by known accounts ──────────────────────────────────────────
    n_sudo = n_samples // 8
    _SUDO_CMDS = ["/usr/bin/apt", "/usr/bin/systemctl", "/usr/sbin/service",
                  "/usr/bin/journalctl", "/usr/bin/tail", "/usr/bin/grep"]
    for _ in range(n_sudo):
        user = rng.choice(_SERVICE_ACCOUNTS)
        cmd = rng.choice(_SUDO_CMDS)
        hour = rng.choice(_BUSINESS_HOURS)
        events.append(_make_clean_event(
            hour=hour, source_ip=rng.choice(_INTERNAL_IPS),
            program="sudo",
            message=f"{user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}",
            severity="notice", facility="authpriv", dest_port=None,
        ))

    # ── Web traffic to common ports ───────────────────────────────────────────
    n_web = n_samples // 5
    _WEB_PATHS = ["/", "/index.html", "/api/health", "/api/v1/users",
                  "/static/main.js", "/favicon.ico", "/robots.txt"]
    _WEB_METHODS = ["GET", "POST", "PUT"]
    for _ in range(n_web):
        ip = rng.choice(_INTERNAL_IPS)
        path = rng.choice(_WEB_PATHS)
        method = rng.choice(_WEB_METHODS)
        port = rng.choice([80, 443, 8080])
        hour = rng.choice(_BUSINESS_HOURS)
        events.append(_make_clean_event(
            hour=hour, source_ip=ip, program="nginx",
            message=f'{ip} - - [{hour}:00:00 +0000] "{method} {path} HTTP/1.1" 200 1234',
            severity="info", facility="daemon", dest_port=port,
            log_source="json",
        ))

    # ── Cron jobs ─────────────────────────────────────────────────────────────
    n_cron = n_samples // 8
    _CRON_JOBS = [
        "run-parts /etc/cron.daily", "/usr/sbin/logrotate /etc/logrotate.conf",
        "/usr/bin/updatedb", "/usr/bin/find /tmp -mtime +7 -delete",
        "/usr/lib/update-notifier/apt-check",
    ]
    for _ in range(n_cron):
        hour = rng.choice(list(range(0, 24)))  # cron runs any hour
        events.append(_make_clean_event(
            hour=hour, source_ip="127.0.0.1", program="cron",
            message=f"({rng.choice(_SERVICE_ACCOUNTS)}) CMD ({rng.choice(_CRON_JOBS)})",
            severity="info", facility="cron", dest_port=None,
        ))

    # ── System daemon heartbeats ───────────────────────────────────────────────
    n_daemon = n_samples // 8
    _DAEMONS = ["systemd", "rsyslogd", "dbus-daemon", "networkd", "resolved"]
    _DAEMON_MSGS = [
        "Started Session {n} of user {u}",
        "Reached target {t}",
        "Unit {s}.service entered running state",
        "Reloading configuration",
        "Listening on /run/systemd/private/tmp-capsule.sock",
    ]
    for _ in range(n_daemon):
        hour = rng.randint(0, 23)
        daemon = rng.choice(_DAEMONS)
        msg_tmpl = rng.choice(_DAEMON_MSGS)
        msg = msg_tmpl.format(
            n=rng.randint(1, 999), u=rng.choice(_SERVICE_ACCOUNTS),
            t="Multi-User", s=daemon,
        )
        events.append(_make_clean_event(
            hour=hour, source_ip=None, program=daemon,
            message=msg, severity="info", facility="daemon", dest_port=None,
            log_source="syslog_rfc5424",
        ))

    # ── DNS / NTP / DHCP traffic ──────────────────────────────────────────────
    n_net = n_samples - len(events)
    _NET_MSGS = [
        "query[A] example.com from {ip}",
        "reply example.com is 93.184.216.34",
        "synchronized to 0.pool.ntp.org, stratum 2",
        "DHCP_ACK on 10.0.1.{n} to {mac}",
    ]
    _MACS = ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", "de:ad:be:ef:00:01"]
    for _ in range(n_net):
        hour = rng.randint(0, 23)
        ip = rng.choice(_INTERNAL_IPS)
        msg_tmpl = rng.choice(_NET_MSGS)
        msg = msg_tmpl.format(ip=ip, n=rng.randint(1, 254), mac=rng.choice(_MACS))
        prog = rng.choice(["named", "ntpd", "dhcpd"])
        port = {"named": 53, "ntpd": 123, "dhcpd": 67}.get(prog, 53)
        events.append(_make_clean_event(
            hour=hour, source_ip=ip, program=prog,
            message=msg, severity="info", facility="daemon", dest_port=port,
        ))

    rng.shuffle(events)
    return events[:n_samples]


# ── Training ──────────────────────────────────────────────────────────────────

def train(
    events: list[NormalizedEvent],
    contamination: float = 0.05,
    n_estimators: int = 100,
    random_state: int = 42,
) -> BaselineModel:
    """
    Train an IsolationForest on the provided events.

    Args:
        events:        List of "clean" NormalizedEvent objects.
        contamination: Expected fraction of anomalies in training data.
        n_estimators:  Number of isolation trees.
        random_state:  For reproducibility.

    Returns:
        Fitted BaselineModel ready for serialization.
    """
    if not events:
        raise ValueError("Cannot train on empty event list")

    logger.info("Extracting features from %d events...", len(events))
    vectors = [extract(e) for e in events]
    X = np.array(vectors, dtype=np.float32)

    baseline_vector = X.mean(axis=0).tolist()

    logger.info(
        "Training IsolationForest (n_estimators=%d, contamination=%.2f)...",
        n_estimators, contamination,
    )
    t0 = time.perf_counter()
    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=random_state,
        n_jobs=-1,
    )
    model.fit(X)
    elapsed = time.perf_counter() - t0
    logger.info("Training complete in %.2fs", elapsed)

    # Calibrate score range from training data (1st/99th percentile)
    raw_scores = model.score_samples(X)
    score_min = float(np.percentile(raw_scores, 1))
    score_max = float(np.percentile(raw_scores, 99))
    logger.info("Score range calibrated: min=%.4f max=%.4f", score_min, score_max)

    return BaselineModel(
        model=model,
        baseline_vector=baseline_vector,
        n_training_samples=len(events),
        trained_at=datetime.now(timezone.utc).isoformat(),
        feature_names=FEATURE_NAMES,
        score_min=score_min,
        score_max=score_max,
    )


def save(model: BaselineModel, path: str) -> None:
    """Serialize BaselineModel to disk."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, path)
    logger.info("Model saved to %s", path)


def load(path: str) -> BaselineModel:
    """Load BaselineModel from disk."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"Model file not found: {path}")
    model = joblib.load(path)
    logger.info(
        "Model loaded from %s (%d training samples, trained %s)",
        path, model.n_training_samples, model.trained_at,
    )
    return model


def train_from_corpus(
    path: str,
    n_samples: int = 2000,
    contamination: float = 0.05,
) -> BaselineModel:
    """
    Convenience: generate synthetic clean corpus, train, and save.
    Called on first startup when no model file exists.
    """
    logger.info("Generating %d clean training events...", n_samples)
    events = generate_clean_corpus(n_samples)
    model = train(events, contamination=contamination)
    save(model, path)
    return model
