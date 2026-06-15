"""
test_hot_reload.py — Tests for detection/hot_reload.py (Rule Hot Reload)
"""

import asyncio
import time
import pytest
from pathlib import Path

from nano_siem.detection.hot_reload import HotReloadManager, ReloadEvent


VALID_RULE = """
title: Reloadable Rule
id: hr-0001
status: stable
level: medium
description: A valid rule for hot reload testing with enough description length.
author: Test
tags:
  - attack.t1110
logsource:
  product: linux
detection:
  selection:
    - 'test keyword'
  condition: selection
falsepositives:
  - none
"""

INVALID_RULE = """
title: Broken Rule
id: hr-0002
status: stable
level: medium
description: A rule with a condition referencing an undefined group.
author: Test
tags:
  - attack.t1110
logsource:
  product: linux
detection:
  selection:
    - 'test'
  condition: selection and undefined_group
falsepositives:
  - none
"""

VALID_RULE_V2 = VALID_RULE.replace("Reloadable Rule", "Reloadable Rule Updated")


def setup_rules_dir(tmp_path: Path, *rules: tuple[str, str]) -> Path:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    for name, content in rules:
        (rules_dir / name).write_text(content)
    return rules_dir


class TestHotReloadManager:
    def test_initial_load(self, tmp_path):
        rules_dir = setup_rules_dir(tmp_path, ("rule1.yml", VALID_RULE))
        manager = HotReloadManager(rules_dir)
        assert manager.rule_count == 1

    def test_no_change_detected_when_unchanged(self, tmp_path):
        rules_dir = setup_rules_dir(tmp_path, ("rule1.yml", VALID_RULE))
        manager = HotReloadManager(rules_dir)
        changed, rules, event = manager.check_once()
        assert changed is False
        assert event is None

    def test_file_modification_detected(self, tmp_path):
        rules_dir = setup_rules_dir(tmp_path, ("rule1.yml", VALID_RULE))
        manager = HotReloadManager(rules_dir)

        time.sleep(0.05)  # ensure mtime differs
        (rules_dir / "rule1.yml").write_text(VALID_RULE_V2)

        changed, rules, event = manager.check_once()
        assert changed is True
        assert event is not None
        assert event.success is True
        assert rules[0].title == "Reloadable Rule Updated"

    def test_new_file_detected(self, tmp_path):
        rules_dir = setup_rules_dir(tmp_path, ("rule1.yml", VALID_RULE))
        manager = HotReloadManager(rules_dir)
        assert manager.rule_count == 1

        time.sleep(0.05)
        (rules_dir / "rule2.yml").write_text(VALID_RULE_V2)

        changed, rules, event = manager.check_once()
        assert changed is True
        assert event.success is True
        assert len(rules) == 2

    def test_invalid_rule_blocks_swap(self, tmp_path):
        rules_dir = setup_rules_dir(tmp_path, ("rule1.yml", VALID_RULE))
        manager = HotReloadManager(rules_dir, validate_before_swap=True)
        original_count = manager.rule_count

        time.sleep(0.05)
        (rules_dir / "rule2.yml").write_text(INVALID_RULE)

        changed, rules, event = manager.check_once()
        assert changed is True
        assert event.success is False
        assert len(event.errors) > 0
        # Previous rule set retained
        assert len(rules) == original_count

    def test_validation_disabled_allows_broken_rule(self, tmp_path):
        rules_dir = setup_rules_dir(tmp_path, ("rule1.yml", VALID_RULE))
        manager = HotReloadManager(rules_dir, validate_before_swap=False)

        time.sleep(0.05)
        (rules_dir / "rule2.yml").write_text(INVALID_RULE)

        changed, rules, event = manager.check_once()
        assert changed is True
        assert event.success is True

    def test_history_recorded(self, tmp_path):
        rules_dir = setup_rules_dir(tmp_path, ("rule1.yml", VALID_RULE))
        manager = HotReloadManager(rules_dir)

        time.sleep(0.05)
        (rules_dir / "rule1.yml").write_text(VALID_RULE_V2)
        manager.check_once()

        assert len(manager.history) == 1
        assert manager.history[0].success is True

    def test_callback_fired_on_success(self, tmp_path):
        rules_dir = setup_rules_dir(tmp_path, ("rule1.yml", VALID_RULE))
        manager = HotReloadManager(rules_dir)

        callback_called = []
        manager.set_on_reload(lambda rules: callback_called.append(len(rules)))

        time.sleep(0.05)
        (rules_dir / "rule1.yml").write_text(VALID_RULE_V2)
        manager.check_once()

        assert callback_called == [1]

    def test_callback_not_fired_on_failure(self, tmp_path):
        rules_dir = setup_rules_dir(tmp_path, ("rule1.yml", VALID_RULE))
        manager = HotReloadManager(rules_dir, validate_before_swap=True)

        callback_called = []
        manager.set_on_reload(lambda rules: callback_called.append(len(rules)))

        time.sleep(0.05)
        (rules_dir / "rule2.yml").write_text(INVALID_RULE)
        manager.check_once()

        assert callback_called == []

    def test_changed_files_listed(self, tmp_path):
        rules_dir = setup_rules_dir(tmp_path, ("rule1.yml", VALID_RULE))
        manager = HotReloadManager(rules_dir)

        time.sleep(0.05)
        (rules_dir / "rule1.yml").write_text(VALID_RULE_V2)
        changed, rules, event = manager.check_once()

        assert "rule1.yml" in event.changed_files

    def test_get_stats_structure(self, tmp_path):
        rules_dir = setup_rules_dir(tmp_path, ("rule1.yml", VALID_RULE))
        manager = HotReloadManager(rules_dir)
        stats = manager.get_stats()
        assert "current_rule_count" in stats
        assert "total_reloads" in stats
        assert stats["running"] is False

    def test_reload_event_to_dict(self, tmp_path):
        event = ReloadEvent(timestamp=123.0, success=True, rule_count=5)
        d = event.to_dict()
        assert d["success"] is True
        assert d["rule_count"] == 5


class TestAsyncWatchLoop:
    def test_start_stop(self, tmp_path):
        async def _go():
            rules_dir = setup_rules_dir(tmp_path, ("rule1.yml", VALID_RULE))
            manager = HotReloadManager(rules_dir, check_interval=0.1)
            await manager.start()
            assert manager.running is True
            await manager.stop()
            assert manager.running is False
        asyncio.get_event_loop().run_until_complete(_go())

    def test_watch_loop_detects_change(self, tmp_path):
        async def _go():
            rules_dir = setup_rules_dir(tmp_path, ("rule1.yml", VALID_RULE))
            manager = HotReloadManager(rules_dir, check_interval=0.05)
            await manager.start()

            await asyncio.sleep(0.02)
            (rules_dir / "rule1.yml").write_text(VALID_RULE_V2)

            await asyncio.sleep(0.15)
            await manager.stop()

            assert manager.current_rules[0].title == "Reloadable Rule Updated"
        asyncio.get_event_loop().run_until_complete(_go())
