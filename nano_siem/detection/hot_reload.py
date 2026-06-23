"""
detection/hot_reload.py — Rule Hot Reload Manager

Watches a rules directory for changes (new/modified/deleted .yml files)
and reloads the Sigma rule set without restarting the pipeline.

Built on top of nano_siem.sigma.loader.reload_rules_if_changed (mtime diffing —
no filesystem watch dependencies). Adds:
  - A standalone async watch loop with configurable interval
  - Reload event history (what changed, when, validation results)
  - Callback hooks so SigmaEngine.rules can be swapped live
  - Validation-before-swap: a broken rule file does NOT take down
    the running rule set — the previous good rule set stays active

This is the component `nano-siem run` and `nano-siem api` use internally
for live rule updates, and it's independently testable/usable via CLI.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from nano_siem.detection.validator import validate_rules_dir
from nano_siem.sigma.loader import (
    SigmaRule,
    load_rules_dir,
    reload_rules_if_changed,
)

logger = logging.getLogger(__name__)


@dataclass
class ReloadEvent:
    timestamp: float
    success: bool
    rule_count: int
    changed_files: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "success": self.success,
            "rule_count": self.rule_count,
            "changed_files": self.changed_files,
            "errors": self.errors,
        }


class HotReloadManager:
    """
    Manages live reloading of a Sigma rules directory.

    Usage:
        manager = HotReloadManager("rules/", check_interval=5.0)
        manager.set_on_reload(my_engine.set_rules)
        await manager.start()
        ...
        await manager.stop()

    Or for one-shot checks (used by CLI):
        manager = HotReloadManager("rules/")
        changed, rules, event = manager.check_once()
    """

    def __init__(
        self,
        rules_dir: str | Path,
        check_interval: float = 5.0,
        validate_before_swap: bool = True,
    ) -> None:
        self._rules_dir = Path(rules_dir)
        self._check_interval = check_interval
        self._validate_before_swap = validate_before_swap
        self._last_mtimes: dict[str, float] = {}
        self._current_rules: list[SigmaRule] = []
        self._history: list[ReloadEvent] = []
        self._on_reload: Callable[[list[SigmaRule]], None] | None = None
        self._task: asyncio.Task | None = None
        self._running = False

        # Initial load
        self._current_rules = load_rules_dir(self._rules_dir)
        for path in sorted(self._rules_dir.glob("**/*.yml")):
            try:
                self._last_mtimes[str(path)] = path.stat().st_mtime
            except OSError:
                pass

    @property
    def current_rules(self) -> list[SigmaRule]:
        return self._current_rules

    @property
    def rule_count(self) -> int:
        return len(self._current_rules)

    @property
    def history(self) -> list[ReloadEvent]:
        return list(self._history)

    @property
    def running(self) -> bool:
        return self._running

    def set_on_reload(self, callback: Callable[[list[SigmaRule]], None]) -> None:
        """Register a callback fired with the new rule list on successful reload."""
        self._on_reload = callback

    def check_once(self) -> tuple[bool, list[SigmaRule], ReloadEvent | None]:
        """
        Check for changes once (no async loop). Used by CLI for manual checks.

        Returns (changed, current_rules, event_or_none).
        If changed and validation fails, current_rules remains the OLD rules
        and the event records the validation errors.
        """
        new_rules, new_mtimes = reload_rules_if_changed(self._rules_dir, self._last_mtimes)

        if new_rules is None:
            return False, self._current_rules, None

        changed_files = self._diff_changed_files(self._last_mtimes, new_mtimes)

        if self._validate_before_swap:
            reports = validate_rules_dir(self._rules_dir)
            errors = []
            for report in reports:
                for result in report.errors:
                    errors.append(f"{report.rule_title}: {result.message}")

            if errors:
                event = ReloadEvent(
                    timestamp=time.time(),
                    success=False,
                    rule_count=len(self._current_rules),
                    changed_files=changed_files,
                    errors=errors,
                )
                self._history.append(event)
                logger.warning(
                    "Hot reload aborted — %d validation errors. Keeping previous rule set (%d rules).",
                    len(errors), len(self._current_rules),
                )
                # Do NOT update mtimes — retry next check until fixed
                return True, self._current_rules, event

        # Swap in new rules
        self._current_rules = new_rules
        self._last_mtimes = new_mtimes

        event = ReloadEvent(
            timestamp=time.time(),
            success=True,
            rule_count=len(new_rules),
            changed_files=changed_files,
        )
        self._history.append(event)
        logger.info(
            "Hot reload successful — %d rules loaded (%d files changed)",
            len(new_rules), len(changed_files),
        )

        if self._on_reload:
            self._on_reload(new_rules)

        return True, new_rules, event

    @staticmethod
    def _diff_changed_files(old: dict[str, float], new: dict[str, float]) -> list[str]:
        changed = []
        all_paths = set(old.keys()) | set(new.keys())
        for path in all_paths:
            if old.get(path) != new.get(path):
                changed.append(Path(path).name)
        return changed

    async def start(self) -> None:
        """Start the async watch loop."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._watch_loop())
        logger.info(
            "HotReloadManager started — watching %s every %.1fs (%d rules loaded)",
            self._rules_dir, self._check_interval, len(self._current_rules),
        )

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _watch_loop(self) -> None:
        while self._running:
            try:
                await asyncio.sleep(self._check_interval)
                self.check_once()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.exception("Hot reload check failed: %s", e)

    def get_stats(self) -> dict:
        successes = sum(1 for e in self._history if e.success)
        failures = sum(1 for e in self._history if not e.success)
        return {
            "rules_dir": str(self._rules_dir),
            "current_rule_count": len(self._current_rules),
            "check_interval": self._check_interval,
            "running": self._running,
            "total_reloads": len(self._history),
            "successful_reloads": successes,
            "failed_reloads": failures,
            "last_reload": self._history[-1].to_dict() if self._history else None,
        }
