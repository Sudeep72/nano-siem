"""
reasoning/replay.py — Attack Replay Engine

Replays a correlated attack chain step-by-step, optionally with
AI-generated analyst commentary at each step (via ReasoningEngine).

DESIGN NOTE: Replay operates on alerts that detection has ALREADY
generated and ordered. It does not re-run detection or alter the
sequence — it presents the existing chain_steps from a CORRELATION
alert as a guided walkthrough, useful for:
  - Training new analysts ("here's what a real kill chain looked like")
  - Post-incident review
  - Generating step-by-step narrative reports

Two modes:
  - build_replay(alert)                    -> ReplaySession (no AI)
  - build_replay_with_commentary(alert, engine) -> ReplaySession with
    Gemini-generated commentary per step (uses ReasoningEngine, which
    itself never performs detection — see reasoning/engine.py)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from nano_siem.reasoning.engine import AIResult, ReasoningEngine


@dataclass
class ReplayStep:
    index: int
    step_name: str          # e.g. "brute_force", "successful_login"
    message: str            # the log message for this step
    timestamp: float | None = None
    commentary: str | None = None   # optional AI-generated explanation

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "step_name": self.step_name,
            "message": self.message,
            "timestamp": self.timestamp,
            "commentary": self.commentary,
        }


@dataclass
class ReplaySession:
    alert_id: str
    chain_title: str
    chain_id: str
    severity: str
    source_key: str
    mitre_tactic: str
    mitre_techniques: list[str]
    duration_seconds: float
    steps: list[ReplayStep] = field(default_factory=list)
    summary: str | None = None     # optional overall AI narrative

    @property
    def step_count(self) -> int:
        return len(self.steps)

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "chain_title": self.chain_title,
            "chain_id": self.chain_id,
            "severity": self.severity,
            "source_key": self.source_key,
            "mitre_tactic": self.mitre_tactic,
            "mitre_techniques": self.mitre_techniques,
            "duration_seconds": self.duration_seconds,
            "step_count": self.step_count,
            "steps": [s.to_dict() for s in self.steps],
            "summary": self.summary,
        }


def build_replay(alert: dict) -> ReplaySession:
    """
    Build a replay session from a correlation alert dict.

    Raises ValueError if the alert is not a correlation alert or has no
    chain_steps (replay only applies to multi-step correlation alerts).
    """
    if alert.get("alert_type") != "correlation":
        raise ValueError(
            f"Replay is only available for correlation alerts, got '{alert.get('alert_type')}'"
        )

    chain_steps = alert.get("chain_steps", [])
    if not chain_steps:
        raise ValueError("This alert has no chain_steps to replay")

    duration = alert.get("duration_seconds", 0.0)
    base_ts = alert.get("timestamp", 0.0)
    n = len(chain_steps)

    steps = []
    for i, step in enumerate(chain_steps):
        # Distribute timestamps evenly across the duration if not provided
        step_ts = None
        if base_ts and duration and n > 1:
            step_ts = base_ts - duration + (duration * i / (n - 1))
        elif base_ts:
            step_ts = base_ts

        steps.append(ReplayStep(
            index=i,
            step_name=step.get("step", f"step_{i}"),
            message=step.get("message", ""),
            timestamp=step_ts,
        ))

    return ReplaySession(
        alert_id=alert.get("alert_id", ""),
        chain_title=alert.get("title", "Unknown Chain"),
        chain_id=alert.get("chain_id", ""),
        severity=alert.get("severity", "unknown"),
        source_key=alert.get("source_key", ""),
        mitre_tactic=alert.get("mitre_tactic", ""),
        mitre_techniques=alert.get("mitre_techniques", []),
        duration_seconds=duration,
        steps=steps,
    )


async def build_replay_with_commentary(
    alert: dict,
    engine: ReasoningEngine,
) -> ReplaySession:
    """
    Build a replay session and add AI-generated commentary for each step
    plus an overall summary, using the existing ReasoningEngine.

    This calls Gemini once per step + once for the overall summary.
    For free-tier rate limits (14 req/min), sessions with many steps
    will take longer — this is acceptable since replay is an on-demand
    analyst/training feature, not part of the live detection pipeline.
    """
    session = build_replay(alert)

    for step in session.steps:
        step_prompt = (
            f"In one or two sentences, explain what this log event represents "
            f"in the context of a {session.chain_title} attack "
            f"(MITRE: {session.mitre_tactic}):\n\n"
            f"Step: {step.step_name}\n"
            f"Log: {step.message}\n\n"
            f"Be concise — this is a single step in a guided replay, not a full report."
        )
        result: AIResult = await engine._run(f"replay_step_{step.index}", step_prompt)
        if result.success:
            step.commentary = result.content

    # Overall narrative summary
    narrative_result = await engine.generate_threat_narrative([alert])
    if narrative_result.success:
        session.summary = narrative_result.content

    return session
