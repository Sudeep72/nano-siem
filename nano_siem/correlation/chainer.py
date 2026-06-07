"""
chainer.py — Attack Chain Detector

For each incoming event, checks whether any ChainRule has now completed
given the recent event history in the SlidingWindowBuffer.

Algorithm per event:
  1. Add event to window buffer (updates the source's deque)
  2. For each ChainRule:
       a. Fetch the source's window for chain.window_seconds
       b. Try to find a valid sequence: walk the window chronologically,
          greedily matching each step in order
       c. If all steps matched → emit a CorrelationAlert
       d. Track which chain+source combos have recently fired to deduplicate

Step matching:
  An event matches a ChainStep if ANY of the step's matchers appear in:
    - event.sigma_matches  (Sigma rule title substrings, case-insensitive)
    - event.tags           (tag substrings, case-insensitive)
    - event.message        (message substrings, case-insensitive)
    - event.program        (exact, case-insensitive)

Deduplication:
  A (chain_id, source_key) pair that fired within dedup_window_seconds
  will not fire again. This prevents the same chain from spamming alerts
  as new events keep arriving within the same attack window.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from nano_siem.correlation.chains import BUILTIN_CHAINS, ChainRule, ChainStep
from nano_siem.correlation.window import SlidingWindowBuffer, WindowedEvent
from nano_siem.schema import NormalizedEvent

logger = logging.getLogger(__name__)


@dataclass
class CorrelationAlert:
    """
    Emitted when an attack chain completes.

    Contains the full chain definition, the events that triggered each step,
    and metadata about the source and timing.
    """
    chain: ChainRule
    source_key: str                          # IP or host that triggered the chain
    step_events: list[NormalizedEvent]       # one event per step (the one that fired it)
    triggered_at: float = field(default_factory=time.time)
    duration_seconds: float = 0.0           # time between first and last step event

    @property
    def title(self) -> str:
        return self.chain.title

    @property
    def severity(self) -> str:
        return self.chain.severity

    def summary(self) -> str:
        steps = " → ".join(
            f"[{s.name}]" for s in self.chain.steps
        )
        return (
            f"CORRELATED [{self.chain.severity.upper()}] {self.chain.title} | "
            f"Source: {self.source_key} | "
            f"Steps: {steps} | "
            f"Duration: {self.duration_seconds:.0f}s"
        )

    def to_dict(self) -> dict:
        return {
            "chain_id": self.chain.id,
            "chain_title": self.chain.title,
            "severity": self.chain.severity,
            "source_key": self.source_key,
            "mitre_tactic": self.chain.mitre_tactic,
            "mitre_techniques": self.chain.mitre_techniques,
            "duration_seconds": self.duration_seconds,
            "triggered_at": self.triggered_at,
            "steps": [
                {
                    "step": self.chain.steps[i].name,
                    "event_id": e.event_id,
                    "event_message": e.message[:120],
                    "event_ts": e.timestamp.isoformat(),
                }
                for i, e in enumerate(self.step_events)
            ],
        }


# ── Step matcher ──────────────────────────────────────────────────────────────

def _event_matches_step(event: NormalizedEvent, step: ChainStep) -> bool:
    """
    Check if a single event satisfies a ChainStep.
    Returns True if ANY of the step's matchers match.
    """
    for matcher in step.matchers:
        m_lower = matcher.lower()

        # Check sigma_matches (rule titles)
        for sm in event.sigma_matches:
            if m_lower in sm.lower():
                return True

        # Check tags
        for tag in event.tags:
            if m_lower in tag.lower():
                return True

        # Check message
        if event.message and m_lower in event.message.lower():
            return True

        # Check program
        if event.program and m_lower == event.program.lower():
            return True

    return False


# ── Sequence finder ───────────────────────────────────────────────────────────

def _find_sequence(
    window: list[WindowedEvent],
    steps: list[ChainStep],
) -> list[NormalizedEvent] | None:
    """
    Attempt to find a valid ordered sequence of step matches in the window.

    Uses a greedy forward scan:
      - Iterate window chronologically
      - For each event, check if it matches the CURRENT step
      - If yes, advance to the next step
      - If all steps matched, return the matching events

    This is O(n * m) where n = window size, m = number of steps.
    For realistic window sizes (≤500 events, ≤5 steps) this is negligible.

    Returns list of matched events (one per step) or None if sequence not found.
    """
    if not steps:
        return []

    matched_events: list[NormalizedEvent] = []
    step_idx = 0

    for we in window:
        if step_idx >= len(steps):
            break
        if _event_matches_step(we.event, steps[step_idx]):
            matched_events.append(we.event)
            step_idx += 1

    if step_idx == len(steps):
        return matched_events
    return None


# ── Correlator ────────────────────────────────────────────────────────────────

AlertCallback = Callable[[CorrelationAlert], Awaitable[None]]


class Correlator:
    """
    Manages the sliding window buffer and evaluates chain rules
    against each incoming event.

    Usage:
        correlator = Correlator()
        correlator.on_alert(my_alert_handler)
        await correlator.ingest(event)   # call for every event
    """

    def __init__(
        self,
        chains: list[ChainRule] | None = None,
        max_window_seconds: int = 1800,
        max_events_per_source: int = 500,
        dedup_window_seconds: int = 300,
        purge_interval: int = 60,
    ) -> None:
        self._chains = chains if chains is not None else BUILTIN_CHAINS
        self._window = SlidingWindowBuffer(
            max_window_seconds=max_window_seconds,
            max_events_per_source=max_events_per_source,
        )
        self._dedup_window = dedup_window_seconds
        self._purge_interval = purge_interval

        # (chain_id, source_key) → last fired timestamp
        self._dedup_cache: dict[tuple[str, str], float] = {}

        self._alert_callbacks: list[AlertCallback] = []
        self._last_purge: float = time.time()

        # Stats
        self.stats: dict[str, int] = {
            "events_ingested": 0,
            "chains_evaluated": 0,
            "alerts_fired": 0,
            "alerts_deduped": 0,
        }

    def on_alert(self, callback: AlertCallback) -> None:
        """Register an async callback for correlation alerts."""
        self._alert_callbacks.append(callback)

    def _is_deduped(self, chain_id: str, source_key: str) -> bool:
        """Check if this (chain, source) pair fired recently."""
        key = (chain_id, source_key)
        last_fired = self._dedup_cache.get(key)
        if last_fired and (time.time() - last_fired) < self._dedup_window:
            return True
        return False

    def _mark_fired(self, chain_id: str, source_key: str) -> None:
        self._dedup_cache[(chain_id, source_key)] = time.time()
        # Clean up old dedup entries to prevent unbounded growth
        if len(self._dedup_cache) > 50_000:
            now = time.time()
            self._dedup_cache = {
                k: v for k, v in self._dedup_cache.items()
                if now - v < self._dedup_window
            }

    async def ingest(self, event: NormalizedEvent) -> list[CorrelationAlert]:
        """
        Process one event through the correlation engine.

        1. Add to sliding window
        2. Evaluate all chain rules against the updated window
        3. Fire callbacks for any new alerts
        4. Periodically purge stale events

        Returns list of CorrelationAlert objects fired (may be empty).
        """
        self.stats["events_ingested"] += 1

        # Add to window and get source key
        source_key = await self._window.add(event)

        # Periodic purge of old events
        now = time.time()
        if now - self._last_purge > self._purge_interval:
            await self._window.purge_old()
            self._last_purge = now

        # Evaluate all chain rules
        fired_alerts: list[CorrelationAlert] = []

        for chain in self._chains:
            self.stats["chains_evaluated"] += 1

            # Dedup check
            if self._is_deduped(chain.id, source_key):
                self.stats["alerts_deduped"] += 1
                continue

            # Get relevant window for this chain's time range
            window = self._window.get_window(source_key, chain.window_seconds)
            if len(window) < len(chain.steps):
                # Not enough events to complete this chain — skip
                continue

            # Try to find the step sequence
            matched_events = _find_sequence(window, chain.steps)
            if matched_events is None:
                continue

            # Chain completed!
            first_ts = window[0].ts if window else now
            last_ts = now
            duration = last_ts - first_ts

            alert = CorrelationAlert(
                chain=chain,
                source_key=source_key,
                step_events=matched_events,
                triggered_at=now,
                duration_seconds=duration,
            )

            self.stats["alerts_fired"] += 1
            self._mark_fired(chain.id, source_key)

            # Enrich the triggering event
            event.add_tag(f"correlated:{chain.id}")
            event.add_tag(f"chain_severity:{chain.severity}")

            fired_alerts.append(alert)

            # Fire callbacks
            for cb in self._alert_callbacks:
                try:
                    await cb(alert)
                except Exception as e:
                    logger.error("Alert callback error: %s", e)

        return fired_alerts

    def get_stats(self) -> dict[str, int | float]:
        return {
            **self.stats,
            "tracked_sources": self._window.source_count(),
            "buffered_events": self._window.event_count(),
            "dedup_cache_size": len(self._dedup_cache),
        }
