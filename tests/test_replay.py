"""
test_replay.py — Tests for reasoning/replay.py (Attack Replay Engine)
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock

from nano_siem.reasoning.replay import (
    build_replay, build_replay_with_commentary, ReplaySession, ReplayStep,
)
from nano_siem.reasoning.engine import ReasoningEngine, AIResult
from nano_siem.reasoning.gemini import GeminiResponse


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


CORRELATION_ALERT = {
    "alert_id": "alert-002",
    "alert_type": "correlation",
    "title": "Brute Force Followed by Successful Login",
    "severity": "critical",
    "source_key": "203.0.113.5",
    "timestamp": 161.0,
    "duration_seconds": 60.0,
    "mitre_tactic": "Credential Access → Initial Access",
    "mitre_techniques": ["T1110", "T1078"],
    "chain_id": "chain-001",
    "chain_steps": [
        {"step": "brute_force", "message": "Failed password for root from 203.0.113.5"},
        {"step": "successful_login", "message": "Accepted password for deploy from 203.0.113.5"},
    ],
}

SIGMA_ALERT = {
    "alert_id": "alert-001",
    "alert_type": "sigma",
    "title": "SSH Brute Force Attempt",
    "severity": "high",
    "source_key": "203.0.113.5",
    "timestamp": 100.0,
    "duration_seconds": 0,
    "mitre_tactic": "Credential Access",
    "mitre_techniques": ["T1110.001"],
    "chain_id": "",
    "chain_steps": [],
}

ML_ALERT = {**SIGMA_ALERT, "alert_type": "ml", "chain_steps": []}


class TestBuildReplay:
    def test_correlation_alert_builds_session(self):
        session = build_replay(CORRELATION_ALERT)
        assert isinstance(session, ReplaySession)
        assert session.step_count == 2
        assert session.chain_title == "Brute Force Followed by Successful Login"

    def test_step_order_preserved(self):
        session = build_replay(CORRELATION_ALERT)
        assert session.steps[0].step_name == "brute_force"
        assert session.steps[1].step_name == "successful_login"

    def test_step_messages_preserved(self):
        session = build_replay(CORRELATION_ALERT)
        assert "Failed password" in session.steps[0].message
        assert "Accepted password" in session.steps[1].message

    def test_timestamps_distributed(self):
        session = build_replay(CORRELATION_ALERT)
        # 2 steps over 60s duration ending at ts=161
        assert session.steps[0].timestamp is not None
        assert session.steps[1].timestamp is not None
        assert session.steps[0].timestamp < session.steps[1].timestamp

    def test_metadata_preserved(self):
        session = build_replay(CORRELATION_ALERT)
        assert session.severity == "critical"
        assert session.source_key == "203.0.113.5"
        assert session.mitre_techniques == ["T1110", "T1078"]

    def test_sigma_alert_raises(self):
        with pytest.raises(ValueError, match="correlation"):
            build_replay(SIGMA_ALERT)

    def test_ml_alert_raises(self):
        with pytest.raises(ValueError, match="correlation"):
            build_replay(ML_ALERT)

    def test_correlation_without_steps_raises(self):
        alert = {**CORRELATION_ALERT, "chain_steps": []}
        with pytest.raises(ValueError, match="chain_steps"):
            build_replay(alert)

    def test_commentary_initially_none(self):
        session = build_replay(CORRELATION_ALERT)
        for step in session.steps:
            assert step.commentary is None

    def test_summary_initially_none(self):
        session = build_replay(CORRELATION_ALERT)
        assert session.summary is None

    def test_to_dict_structure(self):
        session = build_replay(CORRELATION_ALERT)
        d = session.to_dict()
        assert d["step_count"] == 2
        assert len(d["steps"]) == 2
        assert "summary" in d

    def test_to_dict_json_serializable(self):
        import json
        session = build_replay(CORRELATION_ALERT)
        json.dumps(session.to_dict())

    def test_step_to_dict(self):
        step = ReplayStep(index=0, step_name="brute_force", message="test", timestamp=100.0)
        d = step.to_dict()
        assert d["index"] == 0
        assert d["step_name"] == "brute_force"


class TestBuildReplayWithCommentary:
    def _make_engine(self):
        engine = ReasoningEngine(api_key="fake-test-key")
        mock_response = GeminiResponse(
            text="This step represents an attacker attempting credential brute force.",
            model="gemini-2.5-flash", prompt_tokens=50, output_tokens=20,
        )
        engine._client.generate = AsyncMock(return_value=mock_response)
        return engine

    def test_adds_commentary_per_step(self):
        engine = self._make_engine()
        session = run(build_replay_with_commentary(CORRELATION_ALERT, engine))
        for step in session.steps:
            assert step.commentary is not None
            assert len(step.commentary) > 0

    def test_adds_overall_summary(self):
        engine = self._make_engine()
        session = run(build_replay_with_commentary(CORRELATION_ALERT, engine))
        assert session.summary is not None

    def test_step_count_unchanged(self):
        engine = self._make_engine()
        session = run(build_replay_with_commentary(CORRELATION_ALERT, engine))
        assert session.step_count == 2

    def test_handles_failed_commentary_gracefully(self):
        engine = ReasoningEngine(api_key="fake-key")
        engine._client.generate = AsyncMock(side_effect=RuntimeError("API down"))
        session = run(build_replay_with_commentary(CORRELATION_ALERT, engine))
        # Commentary stays None on failure, but session still builds
        assert session.step_count == 2
        for step in session.steps:
            assert step.commentary is None
        assert session.summary is None
