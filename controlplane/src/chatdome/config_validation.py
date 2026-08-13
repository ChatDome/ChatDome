"""Strict, line-aware validation for ``config.yaml``."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode


APPROVAL_MODES = {
    "execute_without_approval",
    "require_approval_for_risky_commands",
    "require_approval_for_all_commands",
}

_ROOT_FIELDS = {"chatdome"}
_CHATDOME_FIELDS = {"telegram", "active_ai_profile", "ai_profiles", "agent", "sentinel"}
_TELEGRAM_FIELDS = {
    "bot_token", "allowed_ids", "admin_ids", "proxy_url", "max_message_length",
}
_AI_FIELDS = {
    "provider", "api_mode", "base_url", "api_key", "model", "temperature", "max_tokens",
    "codex_client_id", "codex_token_file", "codex_base_url",
}
_AGENT_FIELDS = {
    "command_approval_mode", "session_timeout", "pending_approval_timeout",
    "persisted_session_ttl", "max_rounds_per_turn", "max_history_tokens",
    "command_timeout", "max_output_chars", "persist_command_outputs",
    "command_output_retention_days", "command_output_max_chars",
}
_SENTINEL_FIELDS = {
    "enabled", "alert_targets", "alert_retention_days", "push_min_severity",
    "global_rate_limit", "global_rate_window",
    "learning_rounds", "aggregation_window", "daily_report", "daily_report_time",
    "ai_analysis_min_severity",
}
_PROFILE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_API_MODES = {
    "openai", "openai_api", "chat", "chat_completions", "chat_completion",
    "codex", "codex_responses", "codex_oauth",
}


@dataclass(frozen=True)
class ConfigIssue:
    path: str
    message: str
    line: int | None = None
    column: int | None = None

    def render(self) -> str:
        if self.line is None:
            return f"{self.path} {self.message}".strip()
        if self.column is not None:
            return f"第 {self.line} 行，第 {self.column} 列：{self.path} {self.message}".strip()
        return f"第 {self.line} 行：{self.path} {self.message}".strip()


class ConfigValidationError(ValueError):
    """One or more independently detectable configuration errors."""

    def __init__(self, issues: list[ConfigIssue]):
        self.issues = sorted(
            issues,
            key=lambda issue: (
                issue.line is None,
                issue.line or 0,
                issue.column or 0,
                issue.path,
                issue.message,
            ),
        )
        super().__init__(self._format())

    def _format(self) -> str:
        heading = f"配置检查失败，共 {len(self.issues)} 项："
        return "\n".join([heading, *(issue.render() for issue in self.issues)])


class _NodeIndex:
    def __init__(self) -> None:
        self.lines: dict[str, int] = {}
        self.duplicates: list[ConfigIssue] = []

    def line(self, path: str) -> int | None:
        return self.lines.get(path)

    def walk(self, node: Node, path: str = "") -> None:
        if isinstance(node, MappingNode):
            seen: set[str] = set()
            for key_node, value_node in node.value:
                if not isinstance(key_node, ScalarNode):
                    continue
                key = str(key_node.value)
                child = f"{path}.{key}" if path else key
                line = key_node.start_mark.line + 1
                self.lines[child] = line
                if key in seen:
                    self.duplicates.append(ConfigIssue(child, "字段重复", line=line))
                seen.add(key)
                self.walk(value_node, child)
        elif isinstance(node, SequenceNode):
            for index, value_node in enumerate(node.value):
                child = f"{path}[{index}]"
                self.lines[child] = value_node.start_mark.line + 1
                self.walk(value_node, child)


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


class _Validator:
    def __init__(self, document: Any, index: _NodeIndex, config_path: Path) -> None:
        self.document = document
        self.index = index
        self.config_path = config_path
        self.issues: list[ConfigIssue] = list(index.duplicates)

    def add(self, path: str, message: str, *, parent: str | None = None) -> None:
        self.issues.append(
            ConfigIssue(path, message, line=self.index.line(path) or self.index.line(parent or ""))
        )

    def mapping(self, value: Any, path: str, *, required: bool = False) -> dict[str, Any] | None:
        if value is None:
            if path == "配置文件" or self.index.line(path) is not None:
                self.add(path, "必须是对象")
            return None
        if not isinstance(value, dict):
            self.add(path, "必须是对象")
            return None
        return value

    def reject_unknown(self, data: dict[str, Any], allowed: set[str], path: str) -> None:
        for key in data:
            if str(key) not in allowed:
                self.add(f"{path}.{key}", "是未知字段")

    def require_nonempty_string(self, data: dict[str, Any], key: str, path: str) -> None:
        child = f"{path}.{key}"
        if key not in data:
            self.add(path, f"缺少必填字段 {key}")
        elif not isinstance(data[key], str) or not data[key].strip():
            self.add(child, "必须填写非空字符串")

    def optional_type(self, data: dict[str, Any], key: str, expected: type, path: str) -> None:
        if key not in data:
            return
        value = data[key]
        valid = isinstance(value, expected)
        if expected is int:
            valid = _is_int(value)
        if not valid:
            labels = {str: "字符串", bool: "布尔值", int: "整数", list: "列表", dict: "对象"}
            self.add(f"{path}.{key}", f"必须是{labels.get(expected, expected.__name__)}")

    def positive_int(self, data: dict[str, Any], key: str, path: str, *, allow_zero: bool = False) -> None:
        if key not in data:
            return
        value = data[key]
        valid = _is_int(value) and (value >= 0 if allow_zero else value > 0)
        if not valid:
            qualifier = "大于或等于 0" if allow_zero else "大于 0"
            self.add(f"{path}.{key}", f"必须是{qualifier} 的整数")

    def enum(self, data: dict[str, Any], key: str, values: set[str], path: str) -> None:
        if key in data and data[key] not in values:
            self.add(
                f"{path}.{key}",
                "取值无效，可选值：" + ", ".join(sorted(values)),
            )

    def run(self) -> list[ConfigIssue]:
        root = self.mapping(self.document, "配置文件", required=True)
        if root is None:
            return self.issues
        self.reject_unknown(root, _ROOT_FIELDS, "配置文件")
        chatdome = self.mapping(root.get("chatdome"), "chatdome", required=True)
        if chatdome is None:
            if "chatdome" not in root:
                self.add("配置文件", "缺少必填字段 chatdome")
            return self.issues
        self.reject_unknown(chatdome, _CHATDOME_FIELDS, "chatdome")
        self._telegram(chatdome)
        self._profiles(chatdome)
        self._agent(chatdome)
        self._sentinel(chatdome)
        return self.issues

    def _telegram(self, root: dict[str, Any]) -> None:
        if "telegram" not in root:
            return
        data = self.mapping(root.get("telegram"), "chatdome.telegram", required=True)
        if data is None:
            return
        self.reject_unknown(data, _TELEGRAM_FIELDS, "chatdome.telegram")
        self.optional_type(data, "bot_token", str, "chatdome.telegram")
        for key in ("allowed_ids", "admin_ids"):
            if key in data and not isinstance(data[key], (list, str, int)):
                self.add(f"chatdome.telegram.{key}", "必须是整数、字符串或列表")
        self.optional_type(data, "proxy_url", str, "chatdome.telegram")
        self.positive_int(data, "max_message_length", "chatdome.telegram")

    def _profiles(self, root: dict[str, Any]) -> None:
        active_present = "active_ai_profile" in root
        profiles_present = "ai_profiles" in root
        self.optional_type(root, "active_ai_profile", str, "chatdome")
        profiles = (
            self.mapping(root.get("ai_profiles"), "chatdome.ai_profiles", required=True)
            if profiles_present else {}
        )
        if profiles is None:
            return
        active = root.get("active_ai_profile")
        active_value = active.strip() if isinstance(active, str) else ""
        if profiles and not active_value:
            self.add(
                "chatdome.active_ai_profile",
                "必须填写非空字符串",
                parent="chatdome.ai_profiles",
            )
        if active_value and not profiles:
            self.add(
                "chatdome.ai_profiles",
                "必须至少定义一个模型配置",
                parent="chatdome.active_ai_profile",
            )
        for name, raw in profiles.items():
            path = f"chatdome.ai_profiles.{name}"
            if not _PROFILE_NAME_PATTERN.fullmatch(str(name)):
                self.add(path, "名称无效，只能使用 1 到 64 个字母、数字、点、下划线或连字符")
            profile = self.mapping(raw, path, required=True)
            if profile is None:
                continue
            self.reject_unknown(profile, _AI_FIELDS, path)
            for key in ("provider", "api_mode", "base_url", "api_key", "model", "codex_client_id", "codex_token_file", "codex_base_url"):
                self.optional_type(profile, key, str, path)
            self.require_nonempty_string(profile, "model", path)
            api_mode = profile.get("api_mode", "openai_api")
            if isinstance(api_mode, str):
                self.enum(profile, "api_mode", _API_MODES, path)
            api_key = profile.get("api_key")
            if isinstance(api_key, str) and api_key.strip().startswith("env:"):
                self.add(f"{path}.api_key", "不支持 env: 引用，请直接填写 API Key")
            if "temperature" in profile and not _is_number(profile["temperature"]):
                self.add(f"{path}.temperature", "必须是数字")
            self.positive_int(profile, "max_tokens", path)
        if active_value and active_value not in profiles:
            self.add("chatdome.active_ai_profile", "未在 chatdome.ai_profiles 中定义")

    def _agent(self, root: dict[str, Any]) -> None:
        data = self.mapping(root.get("agent"), "chatdome.agent", required=True)
        if data is None:
            if "agent" not in root:
                self.add("chatdome", "缺少必填字段 agent")
            return
        self.reject_unknown(data, _AGENT_FIELDS, "chatdome.agent")
        if "command_approval_mode" not in data:
            self.add("chatdome.agent", "缺少必填字段 command_approval_mode")
        else:
            self.optional_type(data, "command_approval_mode", str, "chatdome.agent")
            if isinstance(data["command_approval_mode"], str):
                self.enum(data, "command_approval_mode", APPROVAL_MODES, "chatdome.agent")
        for key in (
            "session_timeout", "pending_approval_timeout", "max_rounds_per_turn",
            "max_history_tokens", "command_timeout", "max_output_chars",
            "command_output_retention_days", "command_output_max_chars",
        ):
            self.positive_int(data, key, "chatdome.agent")
        self.positive_int(data, "persisted_session_ttl", "chatdome.agent", allow_zero=True)
        self.optional_type(data, "persist_command_outputs", bool, "chatdome.agent")

    def _sentinel(self, root: dict[str, Any]) -> None:
        data = self.mapping(root.get("sentinel"), "chatdome.sentinel")
        if data is None:
            return
        self.reject_unknown(data, _SENTINEL_FIELDS, "chatdome.sentinel")
        for key in ("enabled", "daily_report"):
            self.optional_type(data, key, bool, "chatdome.sentinel")
        self._alert_targets(root, data)
        self.optional_type(data, "daily_report_time", str, "chatdome.sentinel")
        for key in (
            "alert_retention_days", "global_rate_limit", "global_rate_window",
            "aggregation_window", "ai_analysis_min_severity",
        ):
            self.positive_int(data, key, "chatdome.sentinel")
        self.positive_int(data, "learning_rounds", "chatdome.sentinel", allow_zero=True)
        for key in ("push_min_severity", "ai_analysis_min_severity"):
            if key in data and _is_int(data[key]) and not 1 <= data[key] <= 10:
                self.add(f"chatdome.sentinel.{key}", "必须是 1 到 10 之间的整数")


    def _alert_targets(self, root: dict[str, Any], sentinel: dict[str, Any]) -> None:
        raw_targets = sentinel.get("alert_targets")
        if raw_targets is None:
            return
        targets = self.mapping(raw_targets, "chatdome.sentinel.alert_targets", required=True)
        if targets is None:
            return
        self.reject_unknown(targets, {"telegram"}, "chatdome.sentinel.alert_targets")
        telegram = targets.get("telegram")
        if telegram is None:
            return
        target = self.mapping(telegram, "chatdome.sentinel.alert_targets.telegram", required=True)
        if target is None:
            return
        self.reject_unknown(target, {"user_ids"}, "chatdome.sentinel.alert_targets.telegram")
        user_ids = target.get("user_ids")
        if not isinstance(user_ids, list):
            self.add("chatdome.sentinel.alert_targets.telegram.user_ids", "必须是列表")
            return
        telegram_config = root.get("telegram") if isinstance(root.get("telegram"), dict) else {}
        authorized: set[int] = set()
        for key in ("allowed_ids", "admin_ids"):
            authorized.update(_normalized_ids(telegram_config.get(key)))
        malformed = [value for value in user_ids if isinstance(value, bool) or not isinstance(value, int)]
        if malformed:
            self.add(
                "chatdome.sentinel.alert_targets.telegram.user_ids",
                "只能包含整数用户 ID",
            )
        invalid = [
            value for value in user_ids
            if isinstance(value, int) and not isinstance(value, bool) and value not in authorized
        ]
        if invalid:
            self.add(
                "chatdome.sentinel.alert_targets.telegram.user_ids",
                "包含未授权用户 ID：" + ", ".join(str(value) for value in invalid),
            )

def _normalized_ids(raw: Any) -> set[int]:
    if isinstance(raw, str):
        values: Any = raw.split(",")
    elif isinstance(raw, (list, tuple, set)):
        values = raw
    elif raw is None:
        values = []
    else:
        values = [raw]
    normalized: set[int] = set()
    for value in values:
        if isinstance(value, bool):
            continue
        try:
            normalized.add(int(str(value).strip()))
        except (TypeError, ValueError):
            continue
    return normalized


def load_and_validate_config_document(path: Path) -> dict[str, Any]:
    """Read one YAML document, aggregate validation issues, and return its data."""
    if not path.is_file():
        raise ConfigValidationError([ConfigIssue(str(path), "配置文件不存在")])
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigValidationError([ConfigIssue(str(path), f"无法读取：{exc}")]) from None
    try:
        node = yaml.compose(text)
        document = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        issue = ConfigIssue(
            "YAML",
            str(getattr(exc, "problem", None) or "语法错误"),
            line=(mark.line + 1) if mark is not None else None,
            column=(mark.column + 1) if mark is not None else None,
        )
        raise ConfigValidationError([issue]) from None

    index = _NodeIndex()
    if node is not None:
        index.walk(node)
    issues = _Validator(document, index, path).run()
    if issues:
        raise ConfigValidationError(issues)
    return document
