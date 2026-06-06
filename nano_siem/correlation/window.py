"""
window.py — Sliding Time Window Event Buffer

Maintains a per-source deque of recent events.
Events older than max_window_seconds are evicted on every insert.

Key design decisions:
  - Grouped by source key (source_ip if available, else host)
  - Pure in-memory — no SQLite (correlation needs microsecond access)
  - Thread-safe for async via asyncio.Lock (one lock per source bucket)
  - Bounded per-source capacity (max_events_per_source) to prevent OOM
    from a single chatty host dominating memory
  - Global capacity: if total tracked sources > max_sources, evict the
    source with the oldest last-seen event (LRU eviction)

Memory estimate at defaults (500 events × 200 bytes × 1000 sources = ~100MB max)
"""

from __future__ import annotations
import asyncio
import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Iterator

from nano_siem.schema import NormalizedEvent

logger = logging.getLogger(__name__)


@dataclass
class WindowedEvent:
    """
    Lightweight wrapper around a NormalizedEvent for window storage.
    We store the full event reference plus a float timestamp for fast
    window boundary checks without re-parsing ISO strings.
    """
    event: NormalizedEvent
    ts: float          # unix timestamp (time.time() at ingestion)
    source_key: str    # the grouping key used


class SlidingWindowBuffer:
    """
    Per-source sliding time window of recent events.

    Usage:
        buf = SlidingWindowBuffer(max_window_seconds=300)
        await buf.add(event)
        recent = buf.get_window(source_key, window_seconds=120)
    """

    def __init__(
        self,
        max_window_seconds: int = 1800,   # keep events up to 30 min
        max_events_per_source: int = 500,
        max_sources: int = 10_000,
    ) -> None:
        self._max_window = max_window_seconds
        self._max_per_source = max_events_per_source
        self._max_sources = max_sources

        # source_key → deque of WindowedEvent (oldest first)
        self._buckets: dict[str, deque[WindowedEvent]] = defaultdict(
            lambda: deque(maxlen=max_events_per_source)
        )
        # source_key → last seen timestamp (for LRU eviction)
        self._last_seen: dict[str, float] = {}
        self._lock = asyncio.Lock()

    def _source_key(self, event: NormalizedEvent) -> str:
        """Derive the grouping key from an event."""
        # Prefer source IP (attacker-centric grouping)
        if event.source_ip:
            return event.source_ip
        # Fall back to host (for local events)
        return event.host or "unknown"

    def _evict_old_events(self, bucket: deque[WindowedEvent], now: float) -> None:
        """Remove events older than max_window_seconds from the left of the deque."""
        cutoff = now - self._max_window
        while bucket and bucket[0].ts < cutoff:
            bucket.popleft()

    def _evict_stale_sources(self, now: float) -> None:
        """
        If we're tracking too many sources, evict the ones
        with the oldest last-seen timestamp (LRU).
        """
        if len(self._buckets) <= self._max_sources:
            return
        # Sort by last_seen ascending, drop oldest 10% to avoid thrashing
        n_to_evict = max(1, len(self._buckets) // 10)
        sorted_keys = sorted(self._last_seen, key=lambda k: self._last_seen[k])
        for key in sorted_keys[:n_to_evict]:
            del self._buckets[key]
            del self._last_seen[key]
        logger.debug("LRU evicted %d stale sources", n_to_evict)

    async def add(self, event: NormalizedEvent) -> str:
        """
        Add an event to its source bucket.
        Returns the source key used.
        """
        key = self._source_key(event)
        now = time.time()

        async with self._lock:
            bucket = self._buckets[key]
            self._evict_old_events(bucket, now)
            bucket.append(WindowedEvent(event=event, ts=now, source_key=key))
            self._last_seen[key] = now
            self._evict_stale_sources(now)

        return key

    def get_window(
        self,
        source_key: str,
        window_seconds: int | None = None,
    ) -> list[WindowedEvent]:
        """
        Return all events for a source within the last window_seconds.
        Safe to call without the lock (returns a snapshot copy).
        """
        bucket = self._buckets.get(source_key)
        if not bucket:
            return []

        now = time.time()
        cutoff = now - (window_seconds or self._max_window)
        return [we for we in bucket if we.ts >= cutoff]

    def get_all_keys(self) -> list[str]:
        """Return all currently tracked source keys."""
        return list(self._buckets.keys())

    def source_count(self) -> int:
        return len(self._buckets)

    def event_count(self) -> int:
        return sum(len(b) for b in self._buckets.values())

    async def purge_old(self) -> int:
        """
        Evict all events older than max_window_seconds across all sources.
        Call periodically to keep memory bounded.
        Returns number of events removed.
        """
        now = time.time()
        removed = 0
        async with self._lock:
            empty_keys = []
            for key, bucket in self._buckets.items():
                before = len(bucket)
                self._evict_old_events(bucket, now)
                removed += before - len(bucket)
                if not bucket:
                    empty_keys.append(key)
            for key in empty_keys:
                del self._buckets[key]
                self._last_seen.pop(key, None)
        if removed:
            logger.debug("Window purge: removed %d old events", removed)
        return removed
