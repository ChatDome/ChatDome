"""Strict, line-aware validation for ``config.yaml``."""

from __future__ import annotations

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
    "bot_token", "allowed_chat_ids", "admin_chat_ids", "proxy_url", "max_message_length",
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
    "enabled", "alert_chat_ids", "alert_retention_days", "push_min_severity",
    "builtin_packs", "custom_packs_dir", "global_rate_limit", "global_rate_window",
    "learning_rounds", "aggregation_window", "daily_report", "daily_report_time",
    "ai_analysis_min_severity", "checks",
}
_CHECK_FIELDS = {
    "name", "check_id", "goal", "ai_budget", "interval", "args", "mode", "severity", "rule",
}
_RULE_FIELDS = {"type", "operator", "threshold", "pattern", "aggregation"}
_DEFAULT_PACKS = ["ssh_auth", "network", "system_resources", "processes_services", "logs"]
_SPECIAL_SENTINEL_CHECK_IDS = {"ssh_session_commands_patrol"}


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
        data = self.mapping(root.get("telegram"), "chatdome.telegram", required=True)
        if data is None:
            if "telegram" not in root:
                self.add("chatdome", "缺少必填字段 telegram")
            return
        self.reject_unknown(data, _TELEGRAM_FIELDS, "chatdome.telegram")
        self.require_nonempty_string(data, "bot_token", "chatdome.telegram")
        for key in ("allowed_chat_ids", "admin_chat_ids"):
            if key in data and not isinstance(data[key], (list, str, int)):
                self.add(f"chatdome.telegram.{key}", "必须是整数、字符串或列表")
        self.optional_type(data, "proxy_url", str, "chatdome.telegram")
        self.positive_int(data, "max_message_length", "chatdome.telegram")

    def _profiles(self, root: dict[str, Any]) -> None:
        self.require_nonempty_string(root, "active_ai_profile", "chatdome")
        profiles = self.mapping(root.get("ai_profiles"), "chatdome.ai_profiles", required=True)
        if profiles is None:
            if "ai_profiles" not in root:
                self.add("chatdome", "缺少必填字段 ai_profiles")
            return
        if not profiles:
            self.add("chatdome.ai_profiles", "必须至少定义一个模型配置")
        for name, raw in profiles.items():
            path = f"chatdome.ai_profiles.{name}"
            profile = self.mapping(raw, path, required=True)
            if profile is None:
                continue
            self.reject_unknown(profile, _AI_FIELDS, path)
            for key in ("provider", "api_mode", "base_url", "api_key", "model", "codex_client_id", "codex_token_file", "codex_base_url"):
                self.optional_type(profile, key, str, path)
            if "temperature" in profile and not _is_number(profile["temperature"]):
                self.add(f"{path}.temperature", "必须是数字")
            self.positive_int(profile, "max_tokens", path)
        active = root.get("active_ai_profile")
        if isinstance(active, str) and active.strip() and active not in profiles:
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
        for key in ("alert_chat_ids", "builtin_packs", "checks"):
            self.optional_type(data, key, list, "chatdome.sentinel")
        self.optional_type(data, "custom_packs_dir", str, "chatdome.sentinel")
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

        available_ids = self._available_check_ids(data)
        checks = data.get("checks")
        if not isinstance(checks, list):
            return
        for index, raw in enumerate(checks):
            path = f"chatdome.sentinel.checks[{index}]"
            check = self.mapping(raw, path, required=True)
            if check is None:
                continue
            self.reject_unknown(check, _CHECK_FIELDS, path)
            self.require_nonempty_string(check, "name", path)
            self.require_nonempty_string(check, "check_id", path)
            self.optional_type(check, "goal", str, path)
            self.optional_type(check, "args", dict, path)
            for key in ("ai_budget", "interval"):
                self.positive_int(check, key, path)
            if "severity" in check:
                if not _is_int(check["severity"]) or not 1 <= check["severity"] <= 10:
                    self.add(f"{path}.severity", "必须是 1 到 10 之间的整数")
            self.enum(check, "mode", {"snapshot", "differential"}, path)
            check_id = check.get("check_id")
            if isinstance(check_id, str) and check_id and check_id not in available_ids:
                self.add(f"{path}.check_id", "未在已启用的命令包中定义")
            rule = check.get("rule")
            if rule is not None:
                rule_path = f"{path}.rule"
                rule_data = self.mapping(rule, rule_path, required=True)
                if rule_data is not None:
                    self.reject_unknown(rule_data, _RULE_FIELDS, rule_path)
                    self.optional_type(rule_data, "type", str, rule_path)
                    self.optional_type(rule_data, "operator", str, rule_path)
                    self.optional_type(rule_data, "pattern", str, rule_path)
                    self.optional_type(rule_data, "aggregation", str, rule_path)
                    if "threshold" in rule_data and not _is_number(rule_data["threshold"]):
                        self.add(f"{rule_path}.threshold", "必须是数字")

    def _available_check_ids(self, sentinel: dict[str, Any]) -> set[str]:
        builtin_dir = Path(__file__).parent / "packs"
        requested = sentinel.get("builtin_packs", _DEFAULT_PACKS)
        pack_names = requested if isinstance(requested, list) else []
        available: set[str] = set(_SPECIAL_SENTINEL_CHECK_IDS)
        existing_packs = {path.stem for path in builtin_dir.glob("*.yaml")}
        for index, name in enumerate(pack_names):
            path = f"chatdome.sentinel.builtin_packs[{index}]"
            if not isinstance(name, str):
                self.add(path, "必须是字符串")
                continue
            if name not in existing_packs:
                self.add(path, "未找到对应的内置命令包")
                continue
            available.update(_read_pack_ids(builtin_dir / f"{name}.yaml"))

        custom = sentinel.get("custom_packs_dir")
        if isinstance(custom, str) and custom.strip():
            custom_dir = Path(custom).expanduser()
            if not custom_dir.is_absolute():
                custom_dir = self.config_path.parent / custom_dir
            if not custom_dir.is_dir():
                self.add("chatdome.sentinel.custom_packs_dir", "目录不存在")
            else:
                for path in custom_dir.glob("*.yaml"):
                    available.update(_read_pack_ids(path))
        return available


def _read_pack_ids(path: Path) -> set[str]:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return set()
    commands = raw.get("commands") if isinstance(raw, dict) else None
    if not isinstance(commands, dict):
        return set()
    return {str(key) for key in commands}


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
