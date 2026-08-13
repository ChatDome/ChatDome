"""Sentinel check definitions and the packaged policy loader."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import yaml

logger = logging.getLogger(__name__)

_CHECK_FIELDS = {
    "name", "check_id", "goal", "ai_budget", "interval", "args", "mode", "severity", "rule",
}
_RULE_FIELDS = {"type", "operator", "threshold", "pattern", "aggregation"}
_RULE_TYPES = {"line_count", "regex_extract", "regex_match", "added_count"}
_RULE_OPERATORS = {">", ">=", "<", "<=", "==", "!="}
_RULE_AGGREGATIONS = {"max", "min", "sum", "avg"}
_SPECIAL_CHECK_IDS = {"ssh_session_commands_patrol"}


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
    """Anomaly detection rule parsed from the packaged policy."""

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

    Loaded from the packaged Sentinel policy.
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
    """Parse check dictionaries supplied by trusted code or tests."""
    checks: list[CheckDefinition] = []
    for i, raw in enumerate(checks_raw):
        try:
            checks.append(CheckDefinition.from_dict(raw))
        except Exception:
            logger.exception("Failed to parse check #%d: %s", i, raw.get("name", "?"))
    logger.info("Loaded %d check definitions", len(checks))
    return checks


def load_builtin_checks(path: Path | None = None) -> list[CheckDefinition]:
    """Load the single Sentinel policy distributed with ChatDome."""
    policy_path = path or Path(__file__).with_name("default-checks.yaml")
    try:
        document = yaml.safe_load(policy_path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError(f"内置 Sentinel 策略无法读取：{policy_path}: {exc}") from None
    raw_checks = document.get("checks") if isinstance(document, dict) else None
    if not isinstance(raw_checks, list) or not raw_checks:
        raise ValueError(f"内置 Sentinel 策略未定义检查项：{policy_path}")
    issues = _validate_builtin_policy(raw_checks)
    if issues:
        rendered = "\n".join(f"- {issue}" for issue in issues)
        raise ValueError(f"内置 Sentinel 策略无效：{policy_path}\n{rendered}")
    checks = load_checks(raw_checks)
    if len(checks) != len(raw_checks):
        raise ValueError(f"内置 Sentinel 策略包含无效检查项：{policy_path}")
    return checks


def _validate_builtin_policy(raw_checks: list[Any]) -> list[str]:
    available_ids = _builtin_command_ids() | _SPECIAL_CHECK_IDS
    issues: list[str] = []
    for index, raw in enumerate(raw_checks):
        prefix = f"checks[{index}]"
        if not isinstance(raw, dict):
            issues.append(f"{prefix} 必须是映射")
            continue
        for field_name in sorted(set(raw) - _CHECK_FIELDS):
            issues.append(f"{prefix}.{field_name} 是未知字段")
        name = raw.get("name")
        if not isinstance(name, str) or not name.strip():
            issues.append(f"{prefix}.name 必须填写非空字符串")
        check_id = raw.get("check_id")
        goal = raw.get("goal")
        if not isinstance(check_id, str) or not check_id.strip():
            if not isinstance(goal, str) or not goal.strip():
                issues.append(f"{prefix}.check_id 必须填写已注册的命令编号")
        elif check_id not in available_ids:
            issues.append(f"{prefix}.check_id 引用了不存在的命令：{check_id}")
        _positive_int(raw, "interval", prefix, issues)
        _positive_int(raw, "ai_budget", prefix, issues, optional=True)
        if raw.get("mode", "snapshot") not in {"snapshot", "differential"}:
            issues.append(f"{prefix}.mode 取值无效")
        severity = raw.get("severity", 5)
        if isinstance(severity, bool) or not isinstance(severity, int) or not 1 <= severity <= 10:
            issues.append(f"{prefix}.severity 必须是 1 到 10 之间的整数")
        if "args" in raw and not isinstance(raw["args"], dict):
            issues.append(f"{prefix}.args 必须是映射")
        _validate_rule(raw.get("rule"), prefix, issues)
    return issues


def _positive_int(
    raw: dict[str, Any], key: str, prefix: str, issues: list[str], *, optional: bool = False,
) -> None:
    if optional and key not in raw:
        return
    value = raw.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        issues.append(f"{prefix}.{key} 必须是大于 0 的整数")


def _validate_rule(raw: Any, prefix: str, issues: list[str]) -> None:
    if raw is None:
        return
    path = f"{prefix}.rule"
    if not isinstance(raw, dict):
        issues.append(f"{path} 必须是映射")
        return
    for field_name in sorted(set(raw) - _RULE_FIELDS):
        issues.append(f"{path}.{field_name} 是未知字段")
    rule_type = raw.get("type")
    if rule_type not in _RULE_TYPES:
        issues.append(f"{path}.type 取值无效")
    if raw.get("operator", ">") not in _RULE_OPERATORS:
        issues.append(f"{path}.operator 取值无效")
    if raw.get("aggregation", "max") not in _RULE_AGGREGATIONS:
        issues.append(f"{path}.aggregation 取值无效")
    threshold = raw.get("threshold", 0)
    if isinstance(threshold, bool) or not isinstance(threshold, (int, float)):
        issues.append(f"{path}.threshold 必须是数字")
    pattern = raw.get("pattern", "")
    if rule_type in {"regex_extract", "regex_match"}:
        if not isinstance(pattern, str) or not pattern:
            issues.append(f"{path}.pattern 必须填写正则表达式")
        else:
            try:
                re.compile(pattern)
            except re.error as exc:
                issues.append(f"{path}.pattern 正则表达式无效：{exc}")


def _builtin_command_ids() -> set[str]:
    pack_dir = Path(__file__).parent.parent / "packs"
    command_ids: set[str] = set()
    for pack_path in pack_dir.glob("*.yaml"):
        try:
            document = yaml.safe_load(pack_path.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError):
            continue
        commands = document.get("commands") if isinstance(document, dict) else None
        if isinstance(commands, dict):
            command_ids.update(str(command_id) for command_id in commands)
    return command_ids
