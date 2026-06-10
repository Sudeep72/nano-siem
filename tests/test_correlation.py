"""
test_correlation.py — Unit tests for the correlation engine

Covers:
  - SlidingWindowBuffer: add, eviction, get_window, LRU
  - _event_matches_step: all matcher types
  - _find_sequence: ordering, partial, missing steps
  - Correlator.ingest: alert firing, dedup, enrichment, multi-chain
  - Built-in chain rules: real attack sequence playbacks
"""

import asyncio
import time

from nano_siem.correlation.chainer import (
    CorrelationAlert,
    Correlator,
    _event_matches_step,
    _find_sequence,
)
from nano_siem.correlation.chains import BUILTIN_CHAINS, ChainRule, ChainStep
from nano_siem.correlation.window import SlidingWindowBuffer, WindowedEvent
from nano_siem.schema import NormalizedEvent

# ── Helpers ────────────────────────────────────────────────────────────────────

def make_event(
    message: str = "",
    source_ip: str | None = "1.2.3.4",
    host: str = "testhost",
    program: str = "sshd",
    sigma_matches: list[str] | None = None,
    tags: list[str] | None = None,
) -> NormalizedEvent:
    e = NormalizedEvent()
    e.message = message
    e.raw = message
    e.source_ip = source_ip
    e.host = host
    e.program = program
    e.sigma_matches = sigma_matches or []
    e.tags = tags or []
    return e


def run(coro):
    """Run a coroutine in a fresh event loop."""
    return asyncio.get_event_loop().run_until_complete(coro)


# ── SlidingWindowBuffer tests ─────────────────────────────────────────────────

class TestSlidingWindowBuffer:
    def test_add_and_retrieve(self):
        buf = SlidingWindowBuffer(max_window_seconds=300)
        e = make_event("test", source_ip="10.0.0.1")
        key = run(buf.add(e))
        assert key == "10.0.0.1"
        window = buf.get_window("10.0.0.1")
        assert len(window) == 1
        assert window[0].event is e

    def test_source_key_falls_back_to_host(self):
        buf = SlidingWindowBuffer()
        e = make_event("test", source_ip=None, host="myhost")
        key = run(buf.add(e))
        assert key == "myhost"

    def test_multiple_sources_isolated(self):
        buf = SlidingWindowBuffer()
        run(buf.add(make_event("a", source_ip="1.1.1.1")))
        run(buf.add(make_event("b", source_ip="2.2.2.2")))
        assert len(buf.get_window("1.1.1.1")) == 1
        assert len(buf.get_window("2.2.2.2")) == 1

    def test_window_seconds_filters_old_events(self):
        buf = SlidingWindowBuffer(max_window_seconds=600)
        e = make_event("old")
        run(buf.add(e))
        # Force the timestamp to be old by manipulating the bucket
        bucket = buf._buckets["1.2.3.4"]
        bucket[0] = WindowedEvent(event=e, ts=time.time() - 400, source_key="1.2.3.4")
        # get_window with 60s should exclude it
        window = buf.get_window("1.2.3.4", window_seconds=60)
        assert len(window) == 0
        # get_window with 500s should include it
        window = buf.get_window("1.2.3.4", window_seconds=500)
        assert len(window) == 1

    def test_max_events_per_source_caps_deque(self):
        buf = SlidingWindowBuffer(max_events_per_source=5)
        for i in range(10):
            run(buf.add(make_event(f"msg {i}")))
        # deque maxlen=5 keeps only last 5
        assert len(buf._buckets["1.2.3.4"]) == 5

    def test_source_count(self):
        buf = SlidingWindowBuffer()
        run(buf.add(make_event("a", source_ip="1.1.1.1")))
        run(buf.add(make_event("b", source_ip="2.2.2.2")))
        run(buf.add(make_event("c", source_ip="3.3.3.3")))
        assert buf.source_count() == 3

    def test_event_count(self):
        buf = SlidingWindowBuffer()
        run(buf.add(make_event("a", source_ip="1.1.1.1")))
        run(buf.add(make_event("b", source_ip="1.1.1.1")))
        run(buf.add(make_event("c", source_ip="2.2.2.2")))
        assert buf.event_count() == 3

    def test_purge_old_removes_expired(self):
        buf = SlidingWindowBuffer(max_window_seconds=60)
        e = make_event("old")
        run(buf.add(e))
        # Age the event
        bucket = buf._buckets["1.2.3.4"]
        bucket[0] = WindowedEvent(event=e, ts=time.time() - 120, source_key="1.2.3.4")
        removed = run(buf.purge_old())
        assert removed == 1

    def test_unknown_source_returns_empty(self):
        buf = SlidingWindowBuffer()
        assert buf.get_window("nonexistent.ip") == []


# ── Step matcher tests ────────────────────────────────────────────────────────

class TestStepMatcher:
    def test_matches_sigma_title_substring(self):
        e = make_event(sigma_matches=["SSH Brute Force Attempt"])
        step = ChainStep("test", ["SSH Brute Force"])
        assert _event_matches_step(e, step) is True

    def test_matches_tag_substring(self):
        e = make_event(tags=["auth:failure", "category:auth"])
        step = ChainStep("test", ["auth:failure"])
        assert _event_matches_step(e, step) is True

    def test_matches_message_substring(self):
        e = make_event(message="Failed password for root from 1.2.3.4")
        step = ChainStep("test", ["Failed password"])
        assert _event_matches_step(e, step) is True

    def test_matches_program_exact(self):
        e = make_event(program="sshd")
        step = ChainStep("test", ["sshd"])
        assert _event_matches_step(e, step) is True

    def test_case_insensitive(self):
        e = make_event(message="FAILED PASSWORD for root")
        step = ChainStep("test", ["failed password"])
        assert _event_matches_step(e, step) is True

    def test_no_match(self):
        e = make_event(message="Normal startup completed")
        step = ChainStep("test", ["Failed password", "Invalid user"])
        assert _event_matches_step(e, step) is False

    def test_any_matcher_fires(self):
        e = make_event(message="Invalid user hacker")
        step = ChainStep("test", ["Failed password", "Invalid user"])
        assert _event_matches_step(e, step) is True

    def test_empty_matchers_no_match(self):
        e = make_event(message="anything")
        step = ChainStep("test", [])
        assert _event_matches_step(e, step) is False


# ── Sequence finder tests ─────────────────────────────────────────────────────

class TestFindSequence:
    def _make_windowed(self, events: list[NormalizedEvent]) -> list[WindowedEvent]:
        now = time.time()
        return [
            WindowedEvent(event=e, ts=now + i * 10, source_key="1.2.3.4")
            for i, e in enumerate(events)
        ]

    def test_simple_2_step_sequence(self):
        steps = [
            ChainStep("step1", ["Failed password"]),
            ChainStep("step2", ["Accepted password"]),
        ]
        events = [
            make_event("Failed password for root"),
            make_event("Accepted password for root"),
        ]
        result = _find_sequence(self._make_windowed(events), steps)
        assert result is not None
        assert len(result) == 2

    def test_sequence_with_noise_in_between(self):
        steps = [
            ChainStep("step1", ["Failed password"]),
            ChainStep("step2", ["Accepted password"]),
        ]
        events = [
            make_event("Failed password for root"),
            make_event("System heartbeat"),          # noise
            make_event("DNS lookup completed"),       # noise
            make_event("Accepted password for root"),
        ]
        result = _find_sequence(self._make_windowed(events), steps)
        assert result is not None
        assert result[0].message == "Failed password for root"
        assert result[1].message == "Accepted password for root"

    def test_out_of_order_no_match(self):
        steps = [
            ChainStep("step1", ["Failed password"]),
            ChainStep("step2", ["Accepted password"]),
        ]
        # Reversed order
        events = [
            make_event("Accepted password for root"),
            make_event("Failed password for root"),
        ]
        result = _find_sequence(self._make_windowed(events), steps)
        assert result is None

    def test_missing_step_no_match(self):
        steps = [
            ChainStep("step1", ["scan"]),
            ChainStep("step2", ["brute"]),
            ChainStep("step3", ["login"]),
        ]
        events = [
            make_event("port scan detected"),
            make_event("system login"),   # skips brute force step
        ]
        result = _find_sequence(self._make_windowed(events), steps)
        assert result is None

    def test_3_step_sequence(self):
        steps = [
            ChainStep("s1", ["scan"]),
            ChainStep("s2", ["brute"]),
            ChainStep("s3", ["login"]),
        ]
        events = [
            make_event("port scan detected"),
            make_event("brute force attempt"),
            make_event("successful login"),
        ]
        result = _find_sequence(self._make_windowed(events), steps)
        assert result is not None
        assert len(result) == 3

    def test_empty_window_returns_none(self):
        steps = [ChainStep("s1", ["anything"])]
        result = _find_sequence([], steps)
        assert result is None

    def test_empty_steps_returns_empty_list(self):
        events = [make_event("anything")]
        result = _find_sequence(self._make_windowed(events), [])
        assert result == []

    def test_same_event_can_match_repeated_steps(self):
        # chain-006 pattern: 3x auth failure
        steps = [
            ChainStep("f1", ["auth:failure"]),
            ChainStep("f2", ["auth:failure"]),
            ChainStep("f3", ["auth:failure"]),
        ]
        events = [
            make_event("fail1", tags=["auth:failure"]),
            make_event("fail2", tags=["auth:failure"]),
            make_event("fail3", tags=["auth:failure"]),
        ]
        result = _find_sequence(self._make_windowed(events), steps)
        assert result is not None
        assert len(result) == 3


# ── Correlator tests ──────────────────────────────────────────────────────────

class TestCorrelator:
    def test_no_alert_on_single_event(self):
        corr = Correlator(chains=BUILTIN_CHAINS)
        e = make_event("Failed password", source_ip="5.5.5.5")
        alerts = run(corr.ingest(e))
        # A single event can't complete a multi-step chain
        multi_step = [a for a in alerts if len(a.chain.steps) > 1]
        assert multi_step == []

    def test_brute_then_success_fires_chain(self):
        chain = ChainRule(
            id="test-bf",
            title="Test Brute Force",
            description="test",
            steps=[
                ChainStep("fail", ["Failed password"]),
                ChainStep("success", ["Accepted password"]),
            ],
            window_seconds=300,
            severity="high",
        )
        corr = Correlator(chains=[chain])
        run(corr.ingest(make_event("Failed password for root", source_ip="6.6.6.6")))
        alerts = run(corr.ingest(make_event("Accepted password for root", source_ip="6.6.6.6")))
        assert len(alerts) == 1
        assert alerts[0].chain.id == "test-bf"
        assert alerts[0].source_key == "6.6.6.6"

    def test_different_sources_dont_cross_correlate(self):
        chain = ChainRule(
            id="test-cross",
            title="Test Cross Source",
            description="test",
            steps=[
                ChainStep("fail", ["Failed password"]),
                ChainStep("success", ["Accepted password"]),
            ],
            window_seconds=300,
            severity="medium",
        )
        corr = Correlator(chains=[chain])
        run(corr.ingest(make_event("Failed password", source_ip="7.7.7.7")))
        # Success comes from a DIFFERENT source
        alerts = run(corr.ingest(make_event("Accepted password", source_ip="8.8.8.8")))
        # 8.8.8.8 has no prior fails, shouldn't fire
        assert not any(a.chain.id == "test-cross" for a in alerts)

    def test_deduplication_suppresses_repeat_alert(self):
        chain = ChainRule(
            id="test-dedup",
            title="Test Dedup",
            description="test",
            steps=[
                ChainStep("s1", ["step1"]),
                ChainStep("s2", ["step2"]),
            ],
            window_seconds=300,
            severity="medium",
        )
        corr = Correlator(chains=[chain], dedup_window_seconds=300)
        run(corr.ingest(make_event("step1", source_ip="9.9.9.9")))
        alerts1 = run(corr.ingest(make_event("step2", source_ip="9.9.9.9")))
        assert len(alerts1) == 1
        # Immediately re-trigger — should be deduped
        run(corr.ingest(make_event("step1", source_ip="9.9.9.9")))
        alerts2 = run(corr.ingest(make_event("step2", source_ip="9.9.9.9")))
        assert len(alerts2) == 0
        assert corr.stats["alerts_deduped"] > 0

    def test_alert_enriches_event_tags(self):
        chain = ChainRule(
            id="test-enrich",
            title="Test Enrich",
            description="test",
            steps=[
                ChainStep("s1", ["step1"]),
                ChainStep("s2", ["step2"]),
            ],
            window_seconds=300,
            severity="high",
        )
        corr = Correlator(chains=[chain])
        run(corr.ingest(make_event("step1", source_ip="11.11.11.11")))
        trigger_event = make_event("step2", source_ip="11.11.11.11")
        run(corr.ingest(trigger_event))
        assert any("correlated:" in t for t in trigger_event.tags)
        assert any("chain_severity:high" in t for t in trigger_event.tags)

    def test_callback_is_called(self):
        chain = ChainRule(
            id="test-cb",
            title="Test Callback",
            description="test",
            steps=[
                ChainStep("s1", ["alpha"]),
                ChainStep("s2", ["beta"]),
            ],
            window_seconds=300,
            severity="medium",
        )
        received = []
        async def handler(alert: CorrelationAlert):
            received.append(alert)

        corr = Correlator(chains=[chain])
        corr.on_alert(handler)
        run(corr.ingest(make_event("alpha event", source_ip="12.12.12.12")))
        run(corr.ingest(make_event("beta event", source_ip="12.12.12.12")))
        assert len(received) == 1
        assert received[0].chain.id == "test-cb"

    def test_step_events_in_alert(self):
        chain = ChainRule(
            id="test-steps",
            title="Test Step Events",
            description="test",
            steps=[
                ChainStep("s1", ["scan"]),
                ChainStep("s2", ["exploit"]),
            ],
            window_seconds=300,
            severity="high",
        )
        corr = Correlator(chains=[chain])
        e1 = make_event("port scan detected", source_ip="13.13.13.13")
        e2 = make_event("exploit attempt", source_ip="13.13.13.13")
        run(corr.ingest(e1))
        alerts = run(corr.ingest(e2))
        assert len(alerts) == 1
        assert len(alerts[0].step_events) == 2
        assert alerts[0].step_events[0].message == "port scan detected"
        assert alerts[0].step_events[1].message == "exploit attempt"

    def test_stats_tracked(self):
        chain = ChainRule(
            id="test-stats",
            title="Test Stats",
            description="test",
            steps=[ChainStep("s1", ["x"]), ChainStep("s2", ["y"])],
            window_seconds=300,
            severity="low",
        )
        corr = Correlator(chains=[chain])
        run(corr.ingest(make_event("x event", source_ip="14.14.14.14")))
        run(corr.ingest(make_event("y event", source_ip="14.14.14.14")))
        s = corr.get_stats()
        assert s["events_ingested"] == 2
        assert s["alerts_fired"] == 1
        assert s["tracked_sources"] >= 1

    def test_alert_to_dict(self):
        chain = ChainRule(
            id="test-dict",
            title="Test Dict",
            description="test",
            steps=[ChainStep("s1", ["foo"]), ChainStep("s2", ["bar"])],
            window_seconds=300,
            severity="medium",
            mitre_tactic="Test",
            mitre_techniques=["T0001"],
        )
        corr = Correlator(chains=[chain])
        run(corr.ingest(make_event("foo event", source_ip="15.15.15.15")))
        alerts = run(corr.ingest(make_event("bar event", source_ip="15.15.15.15")))
        d = alerts[0].to_dict()
        assert d["chain_id"] == "test-dict"
        assert d["severity"] == "medium"
        assert d["source_key"] == "15.15.15.15"
        assert len(d["steps"]) == 2

    def test_no_alert_when_window_too_short(self):
        chain = ChainRule(
            id="test-window",
            title="Test Window",
            description="test",
            steps=[ChainStep("s1", ["scan"]), ChainStep("s2", ["brute"])],
            window_seconds=1,   # 1 second window — very tight
            severity="high",
        )
        corr = Correlator(chains=[chain], max_window_seconds=2)
        run(corr.ingest(make_event("scan detected", source_ip="16.16.16.16")))
        # Age the event artificially
        import time
        bucket = corr._window._buckets["16.16.16.16"]
        bucket[0] = WindowedEvent(
            event=bucket[0].event,
            ts=time.time() - 5,   # 5 seconds old, outside 1s window
            source_key="16.16.16.16",
        )
        alerts = run(corr.ingest(make_event("brute force", source_ip="16.16.16.16")))
        chain_alerts = [a for a in alerts if a.chain.id == "test-window"]
        assert chain_alerts == []


# ── Built-in chain integration tests ─────────────────────────────────────────

class TestBuiltinChains:
    """Play back realistic attack sequences against built-in chains."""

    def _run_sequence(self, events: list[NormalizedEvent]) -> list[CorrelationAlert]:
        """Run a sequence of events and collect all alerts."""
        corr = Correlator(chains=BUILTIN_CHAINS, dedup_window_seconds=0)
        all_alerts = []
        for e in events:
            alerts = run(corr.ingest(e))
            all_alerts.extend(alerts)
        return all_alerts

    def test_brute_force_to_login_chain(self):
        events = [
            make_event("Failed password for root",
                       tags=["auth:failure"], sigma_matches=["SSH Brute Force Attempt"],
                       source_ip="attacker"),
            make_event("Failed password for root",
                       tags=["auth:failure"], sigma_matches=["SSH Brute Force Attempt"],
                       source_ip="attacker"),
            make_event("Accepted password for deploy",
                       tags=["auth:success"], sigma_matches=["SSH Successful Login"],
                       source_ip="attacker"),
        ]
        alerts = self._run_sequence(events)
        titles = [a.title for a in alerts]
        assert any("Brute Force" in t and "Successful" in t for t in titles), \
            f"Expected brute→login chain, got: {titles}"

    def test_port_scan_to_brute_force_chain(self):
        events = [
            make_event("Port Scan Detected from 192.168.100.5",
                       sigma_matches=["Port Scan Detected"], source_ip="scanner"),
            make_event("Failed password for root from scanner",
                       tags=["auth:failure"], source_ip="scanner"),
        ]
        alerts = self._run_sequence(events)
        titles = [a.title for a in alerts]
        assert any("Port Scan" in t and "Brute" in t for t in titles), \
            f"Expected scan→brute chain, got: {titles}"

    def test_login_to_escalation_chain(self):
        events = [
            make_event("Accepted password for deploy",
                       tags=["auth:success"], sigma_matches=["SSH Successful Login"],
                       source_ip="insider"),
            make_event("sudo: deploy ran COMMAND=/bin/bash as uid=0",
                       sigma_matches=["Privilege Escalation via Sudo"],
                       source_ip="insider"),
        ]
        alerts = self._run_sequence(events)
        titles = [a.title for a in alerts]
        assert any("Login" in t and "Escalation" in t for t in titles), \
            f"Expected login→escalation chain, got: {titles}"

    def test_repeated_auth_failures_chain(self):
        events = [
            make_event("Failed password", tags=["auth:failure"], source_ip="brutebot"),
            make_event("Failed password", tags=["auth:failure"], source_ip="brutebot"),
            make_event("Failed password", tags=["auth:failure"], source_ip="brutebot"),
        ]
        alerts = self._run_sequence(events)
        titles = [a.title for a in alerts]
        assert any("Repeated Auth" in t for t in titles), \
            f"Expected repeated auth failures chain, got: {titles}"

    def test_clean_traffic_no_chain(self):
        events = [
            make_event("System startup completed", source_ip="cleanhost"),
            make_event("Cron job executed /usr/bin/updatedb", source_ip="cleanhost"),
            make_event("DNS resolved example.com", source_ip="cleanhost"),
        ]
        alerts = self._run_sequence(events)
        assert alerts == [], f"Expected no alerts, got: {[a.title for a in alerts]}"

    def test_builtin_chains_count(self):
        assert len(BUILTIN_CHAINS) >= 5

    def test_all_builtin_chains_have_steps(self):
        for chain in BUILTIN_CHAINS:
            assert len(chain.steps) >= 2, f"Chain {chain.id} has < 2 steps"
            assert chain.window_seconds > 0
            assert chain.severity in ("low", "medium", "high", "critical")
