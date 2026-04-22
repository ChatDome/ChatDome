"""
Sentinel check definitions — loads and validates ``sentinel.checks`` from config.

Each check maps a command (from Pack YAML) to a schedule + rule + severity.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Literal

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------

SEVERITY_LABELS: dict[int, str] = {
    1: "info", 2: "info",
    3: "low", 4: "low",
    5: "medium", 6: "medium",
    7: "high", 8: "high",
    9: "critical",
    10: "emergency",
}

SEVERITY_EMOJI: dict[str, str] = {
    "info": "ℹ️",
    "low": "🔵",
    "medium": "🟡",
    "high": "🟠",
    "critical": "🔴",
    "emergency": "🚨",
}


def severity_label(severity: int) -> str:
    """Numeric severity (1-10) → label string."""
    return SEVERITY_LABELS.get(max(1, min(severity, 10)), "info")


def severity_emoji(severity: int) -> str:
    """Numeric severity (1-10) → emoji string."""
    return SEVERITY_EMOJI.get(severity_label(severity), "ℹ️")


# ---------------------------------------------------------------------------
# Rule definition
# ---------------------------------------------------------------------------

@dataclass
class RuleDefinition:
    """Anomaly detection rule, parsed from config YAML."""

    type: str                   # line_count | regex_extract | regex_match | added_count
    operator: str = ">"         # > | >= | < | <= | == | !=
    threshold: float = 0
    pattern: str = ""           # regex for regex_extract / regex_match
    aggregation: str = "max"    # max | min | sum | avg  (for regex_extract)

    @classmethod
    def from_dict(cls, raw: dict[str, Any] | None) -> RuleDefinition | None:
        if raw is None:
            return None
        return cls(
            type=raw.get("type", ""),
            operator=raw.get("operator", ">"),
            threshold=float(raw.get("threshold", 0)),
            pattern=raw.get("pattern", ""),
            aggregation=raw.get("aggregation", "max"),
        )


# ---------------------------------------------------------------------------
# Check definition
# ---------------------------------------------------------------------------

@dataclass
class CheckDefinition:
    """
    A Sentinel check policy — defines *how* to use a command for monitoring.

    Loaded from ``config.yaml`` → ``sentinel.checks[]``.
    """

    name: str
    # Command source (one of two modes)
    check_id: str | None = None         # Template mode → maps to Pack command ID
    goal: str | None = None             # AI mode → describes the check goal
    ai_budget: int = 3                  # Max commands in AI mode

    # Schedule
    interval: int = 300                 # seconds

    # Parameters (template mode only)
    args: dict[str, Any] = field(default_factory=dict)
    mode: Literal["snapshot", "differential"] = "snapshot"

    # Alert settings
    severity: int = 5                   # 1-10 numeric level
    rule: RuleDefinition | None = None

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> CheckDefinition:
        """Parse a single check from config YAML dict."""
        return cls(
            name=raw.get("name", "Unnamed Check"),
            check_id=raw.get("check_id"),
            goal=raw.get("goal"),
            ai_budget=int(raw.get("ai_budget", 3)),
            interval=int(raw.get("interval", 300)),
            args=raw.get("args") or {},
            mode=raw.get("mode", "snapshot"),
            severity=int(raw.get("severity", 5)),
            rule=RuleDefinition.from_dict(raw.get("rule")),
        )


def load_checks(checks_raw: list[dict[str, Any]]) -> list[CheckDefinition]:
    """Parse all checks from config YAML list."""
    checks: list[CheckDefinition] = []
    for i, raw in enumerate(checks_raw):
        try:
            checks.append(CheckDefinition.from_dict(raw))
        except Exception:
            logger.exception("Failed to parse check #%d: %s", i, raw.get("name", "?"))
    logger.info("Loaded %d check definitions", len(checks))
    return checks
