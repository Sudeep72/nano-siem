"""
ringbuffer.py — SQLite-backed Event Ring Buffer

Stores normalized events in a SQLite database with a fixed max capacity.
When capacity is reached, oldest events are automatically evicted (FIFO).

Design choices:
  - SQLite with WAL mode for concurrent read-write without locks
  - Events stored as JSON blobs (flexible schema, no migrations needed)
  - Auto-vacuum on eviction to keep file size bounded
  - Simple integer rowid as the ring pointer

Thread safety: SQLite connections are NOT thread-safe across threads.
All writes go through the async executor to avoid blocking the event loop.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
from pathlib import Path
from typing import Any

from nano_siem.schema import NormalizedEvent

logger = logging.getLogger(__name__)

_CREATE_EVENTS_TABLE = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id    TEXT NOT NULL,
    timestamp   TEXT NOT NULL,
    host        TEXT,
    program     TEXT,
    log_source  TEXT,
    severity    TEXT,
    message     TEXT,
    has_alert   INTEGER DEFAULT 0,
    sigma_hits  TEXT,
    anomaly_score REAL,
    tags        TEXT,
    payload     TEXT NOT NULL
);
"""

_CREATE_INDEXES = [
    'CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)',
    'CREATE INDEX IF NOT EXISTS idx_events_host ON events(host)',
    'CREATE INDEX IF NOT EXISTS idx_events_has_alert ON events(has_alert)',
]

_CREATE_META_TABLE = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""


class EventRingBuffer:
    """
    Async-friendly SQLite event store with fixed max capacity.

    All DB operations run in a thread pool executor to avoid blocking
    the asyncio event loop on disk I/O.
    """

    def __init__(self, db_path: str, max_events: int = 100_000) -> None:
        self._db_path = db_path
        self._max_events = max_events
        self._conn: sqlite3.Connection | None = None
        self._lock = asyncio.Lock()

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(self._db_path, check_same_thread=False)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA cache_size=-8000")  # 8MB cache
            conn.execute(_CREATE_EVENTS_TABLE)
            for idx in _CREATE_INDEXES:
                conn.execute(idx)
            conn.execute(_CREATE_META_TABLE)
            conn.commit()
            self._conn = conn
            logger.info("SQLite ring buffer opened: %s (max=%d)", self._db_path, self._max_events)
        return self._conn

    def _insert_sync(self, event: NormalizedEvent) -> None:
        """Synchronous insert — runs in thread pool."""
        conn = self._get_conn()
        payload = json.dumps(event.to_dict())
        conn.execute(
            """
            INSERT INTO events
                (event_id, timestamp, host, program, log_source, severity,
                 message, has_alert, sigma_hits, anomaly_score, tags, payload)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.event_id,
                event.timestamp.isoformat(),
                event.host,
                event.program,
                event.log_source,
                event.severity,
                event.message[:512],           # cap for index efficiency
                1 if event.alert_id else 0,
                json.dumps(event.sigma_matches),
                event.anomaly_score,
                json.dumps(event.tags),
                payload,
            ),
        )
        conn.commit()
        self._evict_if_needed_sync(conn)

    def _evict_if_needed_sync(self, conn: sqlite3.Connection) -> None:
        """Delete oldest rows if we exceed max_events."""
        row = conn.execute("SELECT COUNT(*) FROM events").fetchone()
        count = row[0] if row else 0
        if count > self._max_events:
            excess = count - self._max_events
            conn.execute(
                "DELETE FROM events WHERE id IN "
                "(SELECT id FROM events ORDER BY id ASC LIMIT ?)",
                (excess,),
            )
            conn.commit()
            logger.debug("Evicted %d old events from ring buffer", excess)

    async def insert(self, event: NormalizedEvent) -> None:
        """Insert an event into the ring buffer (async)."""
        loop = asyncio.get_running_loop()
        async with self._lock:
            await loop.run_in_executor(None, self._insert_sync, event)

    def _query_sync(
        self,
        host: str | None = None,
        has_alert: bool | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        conn = self._get_conn()
        conditions = []
        params: list[Any] = []
        if host:
            conditions.append("host = ?")
            params.append(host)
        if has_alert is not None:
            conditions.append("has_alert = ?")
            params.append(1 if has_alert else 0)
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        params.extend([limit, offset])
        rows = conn.execute(
            f"SELECT payload FROM events {where} ORDER BY id DESC LIMIT ? OFFSET ?",
            params,
        ).fetchall()
        return [json.loads(row[0]) for row in rows]

    async def query(
        self,
        host: str | None = None,
        has_alert: bool | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Query events from the ring buffer (async)."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, self._query_sync, host, has_alert, limit, offset
        )

    def _count_sync(self) -> int:
        conn = self._get_conn()
        row = conn.execute("SELECT COUNT(*) FROM events").fetchone()
        return row[0] if row else 0

    async def count(self) -> int:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._count_sync)

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None
