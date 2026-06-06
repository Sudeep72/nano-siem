"""
loader.py — Sigma Rule Loader

Reads .yml Sigma rule files from disk, validates required fields,
and returns SigmaRule objects ready for the AST builder.

Sigma rule spec reference: https://github.com/SigmaHQ/sigma/wiki/Specification

Required fields we enforce:
  title, detection (with condition key), logsource

Optional but indexed:
  id, status, level, tags, description, author, falsepositives
"""

from __future__ import annotations
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

# Valid Sigma severity levels (ordered low → critical)
VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}
VALID_STATUSES = {"stable", "test", "experimental", "deprecated", "unsupported"}

LEVEL_PRIORITY = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass
class SigmaRule:
    """
    Parsed and validated Sigma rule.

    The `detection` dict is the raw detection block straight from YAML —
    the AST builder (ast.py) converts it into an evaluable tree.
    """
    title: str
    detection: dict[str, Any]          # raw detection block
    logsource: dict[str, str]          # product/service/category

    id: str = ""
    status: str = "experimental"
    level: str = "medium"
    description: str = ""
    author: str = ""
    tags: list[str] = field(default_factory=list)
    falsepositives: list[str] = field(default_factory=list)
    source_file: str = ""              # path to the .yml file

    @property
    def level_priority(self) -> int:
        return LEVEL_PRIORITY.get(self.level, 2)

    def __repr__(self) -> str:
        return f"SigmaRule(title={self.title!r}, level={self.level}, id={self.id[:8]})"


class SigmaLoadError(Exception):
    """Raised when a rule file is malformed or missing required fields."""
    pass


def load_rule(path: str | Path) -> SigmaRule:
    """
    Load and validate a single Sigma rule from a YAML file.

    Args:
        path: Path to the .yml rule file.

    Returns:
        Validated SigmaRule object.

    Raises:
        SigmaLoadError: If the file is missing, malformed, or invalid.
    """
    path = Path(path)
    try:
        with open(path, encoding="utf-8") as f:
            raw = yaml.safe_load(f)
    except FileNotFoundError:
        raise SigmaLoadError(f"Rule file not found: {path}")
    except yaml.YAMLError as e:
        raise SigmaLoadError(f"YAML parse error in {path}: {e}")

    if not isinstance(raw, dict):
        raise SigmaLoadError(f"Rule must be a YAML mapping, got {type(raw).__name__}: {path}")

    # ── Validate required fields ───────────────────────────────────────────────
    missing = []
    if "title" not in raw:
        missing.append("title")
    if "detection" not in raw:
        missing.append("detection")
    elif "condition" not in raw["detection"]:
        missing.append("detection.condition")
    if "logsource" not in raw:
        missing.append("logsource")
    if missing:
        raise SigmaLoadError(f"Rule {path} missing required fields: {missing}")

    # ── Normalize optional fields ──────────────────────────────────────────────
    level = str(raw.get("level", "medium")).lower()
    if level not in VALID_LEVELS:
        logger.warning("Unknown level %r in %s — defaulting to 'medium'", level, path)
        level = "medium"

    status = str(raw.get("status", "experimental")).lower()
    if status not in VALID_STATUSES:
        status = "experimental"

    tags = raw.get("tags", [])
    if isinstance(tags, str):
        tags = [tags]
    tags = [str(t) for t in tags]

    falsepositives = raw.get("falsepositives", [])
    if isinstance(falsepositives, str):
        falsepositives = [falsepositives]
    falsepositives = [str(fp) for fp in falsepositives]

    return SigmaRule(
        title=str(raw["title"]),
        detection=raw["detection"],
        logsource=raw.get("logsource", {}),
        id=str(raw.get("id", "")),
        status=status,
        level=level,
        description=str(raw.get("description", "")).strip(),
        author=str(raw.get("author", "")),
        tags=tags,
        falsepositives=falsepositives,
        source_file=str(path),
    )


def load_rules_dir(directory: str | Path, recursive: bool = True) -> list[SigmaRule]:
    """
    Load all .yml Sigma rules from a directory.

    Args:
        directory:  Path to directory containing .yml rule files.
        recursive:  If True, recurse into subdirectories.

    Returns:
        List of successfully loaded SigmaRule objects.
        Files that fail to load are logged and skipped (never crash the engine).
    """
    directory = Path(directory)
    if not directory.exists():
        logger.warning("Rules directory does not exist: %s", directory)
        return []

    pattern = "**/*.yml" if recursive else "*.yml"
    paths = sorted(directory.glob(pattern))

    rules: list[SigmaRule] = []
    errors: list[str] = []

    for path in paths:
        try:
            rule = load_rule(path)
            rules.append(rule)
            logger.debug("Loaded rule: %s (%s)", rule.title, path.name)
        except SigmaLoadError as e:
            errors.append(str(e))
            logger.warning("Skipping rule %s: %s", path.name, e)

    logger.info(
        "Loaded %d rules from %s (%d errors)", len(rules), directory, len(errors)
    )
    return rules


def reload_rules_if_changed(
    directory: str | Path,
    last_mtimes: dict[str, float],
) -> tuple[list[SigmaRule] | None, dict[str, float]]:
    """
    Check if any rule files have changed since last load.
    Returns (new_rules, new_mtimes) if changed, (None, last_mtimes) if not.

    Used by the hot-reload loop in the evaluator.
    """
    directory = Path(directory)
    current_mtimes: dict[str, float] = {}

    for path in sorted(directory.glob("**/*.yml")):
        try:
            current_mtimes[str(path)] = path.stat().st_mtime
        except OSError:
            pass

    if current_mtimes != last_mtimes:
        rules = load_rules_dir(directory)
        return rules, current_mtimes

    return None, last_mtimes
