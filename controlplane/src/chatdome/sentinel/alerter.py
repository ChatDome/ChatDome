"""Sentinel alert formatting, history storage, and status rendering."""

from __future__ import annotations

import json
import logging
import re
import time
import ipaddress
from collections import Counter, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from chatdome.sentinel.checks import severity_emoji

logger = logging.getLogger(__name__)


SSH_SUCCESS_CHECK_IDS = {"ssh_success_login", "ssh_success_login_offhours"}
SSH_FAILED_CHECK_IDS = {"ssh_failed_burst", "ssh_bruteforce"}
SSH_CHECK_IDS = SSH_SUCCESS_CHECK_IDS | SSH_FAILED_CHECK_IDS
SSH_SESSION_COMMAND_CHECK_IDS = {"ssh_session_commands_patrol"}


@dataclass
class AlertEvent:
    """A single alert event for history and audit."""

    timestamp: str
    check_name: str
    check_id: str
    mode: str
    severity: int
    severity_label: str
    rule: str
    current_value: float | None
    raw_output: str
    pushed: bool
    suppressed: bool
    action_reason: str = ""
    alert_state: str = ""
    previous_state: str = ""
    fingerprint: str = ""
    context: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        # Backward compatibility for existing jq/scripts that still read
        # `suppression_reason`.
        data["suppression_reason"] = self.action_reason
        return data

    @property
    def suppression_reason(self) -> str:
        """Backward-compatible alias for legacy field name."""
        return self.action_reason

    @suppression_reason.setter
    def suppression_reason(self, value: str) -> None:
        self.action_reason = value

@dataclass
class AlertCard:
    title: str
    level: str
    risk: str
    action: str
    timestamp: str
    facts: list[tuple[str, str]] = field(default_factory=list)
    status: str = ""
    sections: list[tuple[str, list[str]]] = field(default_factory=list)

    def render(self) -> str:
        lines = [f"{self.level}｜{self.title}", "", f"风险判断：{self.risk}"]

        clean_facts = [
            (str(label).strip(), str(value).strip())
            for label, value in self.facts
            if str(label).strip() and str(value).strip()
        ]
        if clean_facts:
            lines.extend(["", "关键对象："])
            lines.extend(f"- {label}：{value}" for label, value in clean_facts)

        if self.action:
            lines.extend(["", f"建议动作：{self.action}"])

        lines.extend(["", f"时间：{self.timestamp}"])
        if self.status:
            lines.append(f"状态：{self.status}")

        for title, items in self.sections:
            section_title = str(title).strip()
            section_lines = [str(item).rstrip() for item in items if str(item).strip()]
            if not section_title or not section_lines:
                continue
            lines.extend(["", f"{section_title}："])
            for item in section_lines:
                if item.startswith(("-", "  ", "...", "⚠️", "ℹ️")):
                    lines.append(item)
                else:
                    lines.append(f"- {item}")

        return "\n".join(lines)


class AlertHistory:
    """In-memory alert history with JSONL persistence."""

    def __init__(
        self,
        alerts_path: Path | None = None,
        max_items: int = 500,
        retention_days: int = 30,
        cleanup_interval_seconds: int = 3600,
    ) -> None:
        self._history: deque[AlertEvent] = deque(maxlen=max_items)
        self._alerts_path = alerts_path
        self._retention_days = max(1, int(retention_days or 30))
        self._cleanup_interval_seconds = max(60, int(cleanup_interval_seconds or 3600))
        self._last_cleanup_ts: float = 0.0
        if alerts_path:
            alerts_path.parent.mkdir(parents=True, exist_ok=True)
            self._maybe_cleanup(force=True)

    def record(self, event: AlertEvent) -> None:
        self._history.append(event)
        if self._alerts_path:
            try:
                with open(self._alerts_path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")
            except OSError:
                logger.exception("Failed to write alert to %s", self._alerts_path)
            self._maybe_cleanup()

    def recent(self, limit: int = 20) -> list[AlertEvent]:
        return list(self._history)[-limit:]

    def cleanup_old_records(self, now: datetime | None = None) -> int:
        if self._alerts_path is None or not self._alerts_path.exists():
            return 0

        now = now or datetime.now().astimezone()
        oldest_keep_date = now.date() - timedelta(days=self._retention_days - 1)
        removed = 0

        try:
            kept_lines: list[str] = []
            with self._alerts_path.open("r", encoding="utf-8") as src:
                for raw_line in src:
                    line = raw_line.strip()
                    if not line:
                        continue

                    keep = True
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        keep = True
                    else:
                        record_date = self._extract_event_date(record)
                        if record_date is not None and record_date < oldest_keep_date:
                            keep = False

                    if keep:
                        kept_lines.append(line + "\n")
                    else:
                        removed += 1

            if removed > 0:
                with self._alerts_path.open("w", encoding="utf-8") as dst:
                    dst.writelines(kept_lines)
            return removed
        except OSError:
            logger.exception("Sentinel alert retention cleanup failed: %s", self._alerts_path)
            return 0

    def _maybe_cleanup(self, force: bool = False) -> None:
        if self._alerts_path is None:
            return

        now_ts = time.time()
        if not force and (now_ts - self._last_cleanup_ts) < self._cleanup_interval_seconds:
            return

        deleted = self.cleanup_old_records()
        self._last_cleanup_ts = now_ts
        if deleted:
            logger.info(
                "Sentinel alert cleanup removed %d record(s) older than %d day(s)",
                deleted,
                self._retention_days,
            )

    @staticmethod
    def _extract_event_date(record: dict[str, Any]):
        for key in ("timestamp", "timestamp_iso"):
            parsed = AlertHistory._parse_event_date_value(record.get(key))
            if parsed is not None:
                return parsed
        return None

    @staticmethod
    def _parse_event_date_value(value: Any):
        if value is None:
            return None

        if isinstance(value, (int, float)):
            try:
                return datetime.fromtimestamp(float(value), tz=timezone.utc).date()
            except (OverflowError, ValueError):
                return None

        text = str(value).strip()
        if not text:
            return None

        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
            try:
                return datetime.strptime(text, fmt).date()
            except ValueError:
                continue

        try:
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            return datetime.fromisoformat(text).date()
        except ValueError:
            return None

    def stats_24h(self) -> dict[str, int]:
        cutoff = datetime.now(timezone.utc).isoformat()[:10]
        counts: dict[str, int] = {
            "emergency": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        pushed_count = 0

        for event in self._history:
            if event.timestamp[:10] >= cutoff[:10]:
                if event.severity_label in counts:
                    counts[event.severity_label] += 1
                if event.pushed:
                    pushed_count += 1

        return {**counts, "_pushed": pushed_count}


def _state_card(state: str) -> dict[str, str]:
    """Default interpretation per state."""
    cards: dict[str, dict[str, str]] = {
        "NEW": {
            "headline": "🆕 首次检测到该威胁",
            "label": "新威胁首次出现",
            "next_watch": "关注 10 分钟内是否继续出现同类异常，决定是否进入升级态。",
            "condition": "10分钟内事件数>=5或独立指纹数>=3 → 一级升级 (ESCALATED_L1)",
            "recovery": "20分钟内无新事件 → 观察期 (RECOVERED_CANDIDATE)",
        },
        "ESCALATED_L1": {
            "headline": "📈 威胁持续，已升级至一级",
            "label": "一级升级",
            "next_watch": "关注 20 分钟窗口内异常是否继续增多，判断是否升级到 L2。",
            "condition": "20分钟内事件数>=12或独立指纹数>=6 → 二级升级 (ESCALATED_L2)",
            "recovery": "20分钟内无新事件 → 观察期 (RECOVERED_CANDIDATE)",
        },
        "ESCALATED_L2": {
            "headline": "📈 威胁加剧，已升级至二级",
            "label": "二级升级",
            "next_watch": "关注 30 分钟窗口内是否达到高强度持续异常，可能升级到 L3。",
            "condition": "30分钟内事件数>=25或独立指纹数>=10 → 三级升级 (ESCALATED_L3)",
            "recovery": "20分钟内无新事件 → 观察期 (RECOVERED_CANDIDATE)",
        },
        "ESCALATED_L3": {
            "headline": "🔥 威胁严重，已升级至最高级",
            "label": "三级升级",
            "next_watch": "持续监控关键指标，直至进入观察期并确认威胁收敛。",
            "condition": "已达最高升级状态 (ESCALATED_L3)",
            "recovery": "20分钟内无新事件 → 观察期 (RECOVERED_CANDIDATE)",
        },
        "RECOVERED_CANDIDATE": {
            "headline": "📉 威胁趋缓，进入观察期",
            "label": "进入观察期",
            "next_watch": "观察期内若再次出现异常，将回弹到 ESCALATED_L1。",
            "condition": "有任何新事件 → 重新进入 一级升级 (ESCALATED_L1)",
            "recovery": "观察期满 15 分钟无新事件 → 威胁归档 (RECOVERED)",
        },
        "RECOVERED": {
            "headline": "✅ 威胁已归档",
            "label": "观察期通过，威胁归档",
            "next_watch": "后续若同类异常再次出现，将按新一轮威胁重新进入状态机。",
            "condition": "有新事件 → 重新进入 新威胁首次出现 (NEW)",
            "recovery": "已归档",
        },
    }
    return cards.get(
        state,
        {
            "headline": "",
            "label": "状态更新",
            "next_watch": "继续观察后续是否出现新的状态迁移。",
            "condition": "无",
            "recovery": "无",
        },
    )


def _display_number(value: float | None) -> str:
    if value is None:
        return "未知"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def _action_hint(check_id: str, state: str) -> str:
    """Return one actionable hint for supported alert types."""
    if state in {"RECOVERED_CANDIDATE", "RECOVERED"}:
        return "无需操作，持续观察。"

    hints = {
        "ssh_success_login": "请确认登录是否为本人操作；发现异常登录时立即修改密码并检查 authorized_keys。",
        "ssh_success_login_offhours": "请确认非工作时段登录是否为授权操作。",
        "ssh_failed_burst": "请检查来源 IP；确认持续攻击后封禁来源或启用 fail2ban。",
        "ssh_bruteforce": "请检查来源 IP；确认持续攻击后封禁来源并加固 SSH 配置。",
        "ssh_session_commands_patrol": "请确认新增命令是否为授权操作。",
        "open_ports": "请确认监听端口变化是否符合预期，并排查未知服务。",
    }
    return hints.get(check_id, "")


def _append_alert_guidance(lines: list[str], event: AlertEvent) -> None:
    if event.alert_state:
        headline = _state_card(event.alert_state).get("headline", "")
        if headline:
            lines.append(headline)

    hint = _action_hint(event.check_id, event.alert_state)
    if hint:
        lines.append(f"💡 {hint}")


_SEVERITY_TEXT = {
    "emergency": "紧急",
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "提示",
}


def _alert_level(event: AlertEvent) -> str:
    label = _SEVERITY_TEXT.get(event.severity_label, event.severity_label or "提示")
    return f"{severity_emoji(event.severity)} {label}"


def _alert_status(event: AlertEvent) -> str:
    if not event.alert_state:
        return ""
    return _state_card(event.alert_state).get("label", "状态更新")


def _state_risk_override(event: AlertEvent) -> str:
    if event.alert_state == "RECOVERED":
        return f"{event.check_name}已归档，当前无需处理。"
    if event.alert_state == "RECOVERED_CANDIDATE":
        return f"{event.check_name}已进入观察期，继续观察是否反复。"
    return ""


def _compact_items(items: list[str], max_items: int = 3, missing: str = "未提取到") -> str:
    cleaned: list[str] = []
    for item in items:
        value = str(item).strip()
        if value and value not in cleaned:
            cleaned.append(value)
    if not cleaned:
        return missing
    suffix = f" 等{len(cleaned)}项" if len(cleaned) > max_items else ""
    return "，".join(cleaned[:max_items]) + suffix


def _truncate_text(text: str, max_chars: int = 1200) -> str:
    value = (text or "").strip()
    if len(value) <= max_chars:
        return value
    return value[:max_chars] + "\n... (已截断)"


def _first_signal_line(raw_output: str) -> str:
    for line in _nonempty_lines(raw_output):
        lowered = line.lower()
        if lowered.startswith("delta:"):
            continue
        if line.startswith(("+", "-")):
            line = line[1:].strip()
        if line:
            return line
    return ""


def _change_summary(event: AlertEvent, added: list[str] | None = None, removed: list[str] | None = None) -> str:
    added = added or []
    removed = removed or []
    if event.mode == "differential":
        if added or removed:
            return f"新增 {len(added)} 项 / 消失 {len(removed)} 项"
        return f"新增 {_display_number(event.current_value)} 项"
    return _display_number(event.current_value)


def _generic_risk(event: AlertEvent) -> str:
    override = _state_risk_override(event)
    if override:
        return override
    if event.check_id == "open_ports":
        return "发现监听端口变化，请确认是否为预期服务。"
    if event.mode == "differential":
        return "检测到基线变化，请确认是否为预期变更。"
    return "检测结果达到告警阈值，请确认当前状态。"


def _generic_action(event: AlertEvent) -> str:
    return _action_hint(event.check_id, event.alert_state) or "确认该告警是否为预期状态。"


def _generic_facts(event: AlertEvent) -> list[tuple[str, str]]:
    raw = event.raw_output or ""
    added, removed = _extract_diff_items(raw)
    facts: list[tuple[str, str]] = []

    if event.mode == "differential":
        facts.append(("变化", _change_summary(event, added, removed)))
    else:
        facts.append(("当前值", _display_number(event.current_value)))

    if event.check_id == "open_ports":
        if added:
            facts.append(("新增端口", _compact_items(added, max_items=4)))
        if removed:
            facts.append(("消失端口", _compact_items(removed, max_items=4)))
        if not added and not removed:
            signal = _first_signal_line(raw)
            if signal:
                facts.append(("监听项", signal))
        return facts

    signal = _first_signal_line(raw)
    if signal:
        facts.append(("触发内容", signal))
    return facts

def format_alert_detail(event_data: dict[str, Any]) -> str:
    """Format state-machine details from a serialized alert event."""
    alert_state = str(event_data.get("alert_state") or "")
    if not alert_state:
        return "暂无详细状态信息。"

    card = _state_card(alert_state)
    previous_state = str(event_data.get("previous_state") or "")
    previous_label = _state_card(previous_state)["label"] if previous_state else "未监控"
    transition = (
        f"{previous_label} → {card['label']}"
        if previous_state != alert_state
        else card["label"]
    )

    lines = [
        "📋 告警详细信息",
        "",
        f"威胁阶段: {card['label']}",
        f"状态迁移: {transition}",
    ]
    rule = str(event_data.get("rule") or "").strip()
    if rule:
        lines.append(f"触发规则: {rule}")
    lines.extend(
        [
            f"升级条件: {card.get('condition', '')}",
            f"降级条件: {card.get('recovery', '')}",
            f"下一观察点: {card['next_watch']}",
        ]
    )

    raw_output = str(event_data.get("raw_output") or "").strip()
    if raw_output:
        lines.extend(["", "证据摘要:", _truncate_text(raw_output, 1200)])

    return "\n".join(lines)

def _nonempty_lines(raw_output: str) -> list[str]:
    return [line.strip() for line in (raw_output or "").splitlines() if line.strip()]


def _safe_ip_token(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip().strip(",;()[]{}<>")))
    except ValueError:
        return ""


def _extract_sshd_pid(line: str) -> str:
    for pattern in (r"\bsshd_pid=(\d+)\b", r"\bsshd\[(\d+)\]"):
        match = re.search(pattern, line)
        if match:
            return match.group(1)
    return ""


def _first_ip_with_index(parts: list[str]) -> tuple[str, int]:
    for index, token in enumerate(parts):
        ip_value = _safe_ip_token(token)
        if ip_value:
            return ip_value, index
    return "", -1


def _extract_ssh_user(parts: list[str], ip_index: int) -> str:
    for index, token in enumerate(parts):
        if token == "for" and (index + 1) < len(parts):
            if parts[index + 1] == "invalid" and (index + 3) < len(parts) and parts[index + 2] == "user":
                return parts[index + 3]
            return parts[index + 1]

    if ip_index > 0:
        candidate = parts[ip_index - 1].strip()
        ignored = {"from", "port", "ssh2", "Accepted", "Failed", "password", "publickey", "-"}
        if candidate and candidate not in ignored and not _safe_ip_token(candidate):
            return candidate
    return "unknown"


def _extract_ssh_port(parts: list[str], ip_index: int) -> str:
    for index, token in enumerate(parts):
        if token == "port" and (index + 1) < len(parts) and parts[index + 1].isdigit():
            return parts[index + 1]
    if ip_index >= 0 and (ip_index + 1) < len(parts) and parts[ip_index + 1].isdigit():
        return parts[ip_index + 1]
    return "22"


def _extract_ssh_method(parts: list[str], default: str = "unknown") -> str:
    for marker in ("Accepted", "Failed"):
        if marker in parts:
            index = parts.index(marker)
            if (index + 1) < len(parts):
                return parts[index + 1]

    known_methods = {
        "password",
        "publickey",
        "keyboard-interactive",
        "hostbased",
        "gssapi-with-mic",
        "certificate",
        "last",
    }
    for token in reversed(parts):
        cleaned = token.strip().strip(",;()[]{}<>")
        if cleaned in known_methods:
            return cleaned
    return default


def _ssh_time_label(parts: list[str]) -> str:
    if len(parts) >= 3:
        return " ".join(parts[:3])
    return "未知时间"


def _parse_ssh_line(line: str, success: bool) -> dict[str, str]:
    parts = line.split()
    ip_value, ip_index = _first_ip_with_index(parts)
    user = _extract_ssh_user(parts, ip_index)
    port = _extract_ssh_port(parts, ip_index)
    method = _extract_ssh_method(parts, default="unknown")
    return {
        "time": _ssh_time_label(parts),
        "ip": ip_value or "unknown",
        "user": user,
        "port": port,
        "method": method,
        "sshd_pid": _extract_sshd_pid(line),
        "result": "成功" if success else "失败",
    }


def _counter_summary(counter: Counter[str], max_items: int = 5) -> str:
    items = [(key, count) for key, count in counter.most_common(max_items) if key and key != "unknown"]
    if not items:
        return "未提取到"
    return ", ".join(f"{key} ({count}次)" for key, count in items)


def _unique_summary(values: list[str], max_items: int = 6) -> str:
    seen: list[str] = []
    for value in values:
        if value and value != "unknown" and value not in seen:
            seen.append(value)
    if not seen:
        return "未提取到"
    suffix = f" 等{len(seen)}个" if len(seen) > max_items else ""
    return ", ".join(seen[:max_items]) + suffix


def _ssh_sample_lines(records: list[dict[str, str]], max_items: int = 3) -> list[str]:
    samples: list[str] = []
    for record in records[:max_items]:
        samples.append(
            f"- {record['time']} {record['result']}: "
            f"{record['user']}@{record['ip']}"
        )
    return samples


def _ssh_time_summary(records: list[dict[str, str]], max_items: int = 5) -> str:
    times: list[str] = []
    for record in records:
        time_value = record.get("time", "")
        if time_value and time_value != "未知时间" and time_value not in times:
            times.append(time_value)
    if not times:
        return "未提取到"
    suffix = f" 等{len(times)}个时间点" if len(times) > max_items else ""
    return ", ".join(times[:max_items]) + suffix


def _session_tracking_status_label(status: str) -> str:
    labels = {
        "ok": "已启用",
        "no_pid": "登录日志未提供 sshd PID",
        "auditd_unavailable": "auditd 未安装或不可用",
        "execve_rule_missing": "auditd 缺少 execve 规则",
        "no_audit_session": "未找到 audit session ID",
        "no_commands": "暂未捕获到命令",
        "query_failed": "auditd 查询失败",
        "command_unavailable": "命令包未加载",
    }
    return labels.get(status or "", status or "未知")


def _suspicious_command_hints(commands: list[str]) -> list[str]:
    hints: list[str] = []
    patterns = [
        (re.compile(r"\b(wget|curl)\b.+\b(http|https|ftp)://", re.I), "检测到可疑下载行为"),
        (re.compile(r"\b(chmod|chown)\b.+\b(777|\+x)\b", re.I), "检测到权限放宽或可执行权限变更"),
        (re.compile(r"\b(iptables|nft)\b.*(?:\s|^)(-F|flush|delete)\b", re.I), "检测到防火墙规则清理行为"),
        (re.compile(r"\b(nohup|setsid)\b|\s&\s*$", re.I), "检测到后台驻留执行"),
        (re.compile(r"\b(useradd|adduser|passwd|visudo)\b", re.I), "检测到账号或权限配置变更"),
    ]
    for command in commands:
        for pattern, label in patterns:
            if pattern.search(command) and label not in hints:
                hints.append(label)
    return hints


def _format_session_identity(session: dict[str, Any]) -> str:
    user = str(session.get("user") or "unknown")
    ip_value = str(session.get("ip") or "unknown")
    port = str(session.get("port") or "22")
    identity = f"{user}@{ip_value}:{port}"

    details: list[str] = []
    session_id = str(session.get("audit_session_id") or "")
    sshd_pid = str(session.get("sshd_pid") or "")
    if session_id:
        details.append(f"ses={session_id}")
    if sshd_pid:
        details.append(f"sshd PID={sshd_pid}")
    return f"{identity} ({', '.join(details)})" if details else identity


def _format_ssh_login_session_context(context: dict[str, Any]) -> list[str]:
    sessions = context.get("ssh_sessions") if isinstance(context, dict) else None
    if not isinstance(sessions, list) or not sessions:
        return []

    lines = ["", "会话命令追踪:"]
    for item in sessions[:5]:
        if not isinstance(item, dict):
            continue
        status = str(item.get("tracking_status") or "")
        commands = [str(x) for x in item.get("commands", []) if str(x).strip()]
        session_id = str(item.get("audit_session_id") or "")
        identity = _format_session_identity(item)

        lines.append(f"- 会话: {identity}")
        if commands:
            title = f"  命令摘要 (ses={session_id}):" if session_id else "  命令摘要:"
            lines.append(title)
            for command in commands[:10]:
                lines.append(f"  - {command}")
            if len(commands) > 10:
                lines.append(f"  ... (+{len(commands) - 10} more)")
            for hint in _suspicious_command_hints(commands):
                lines.append(f"  ⚠️ {hint}")
            continue

        lines.append(f"  ℹ️ 会话命令追踪不可用: {_session_tracking_status_label(status)}")

    if len(sessions) > 5:
        lines.append(f"... (+{len(sessions) - 5} more sessions)")
    return lines


def _ssh_risk(event: AlertEvent, success: bool) -> str:
    override = _state_risk_override(event)
    if override:
        return override
    if success and event.check_id == "ssh_success_login_offhours":
        return "检测到非工作时段 SSH 成功登录，请确认是否为授权操作。"
    if success:
        return "检测到 SSH 成功登录，请确认是否为本人或授权操作。"
    if event.check_id == "ssh_bruteforce":
        return "检测到新的 SSH 暴力破解来源，请确认是否需要封禁。"
    return "短时间内出现多次 SSH 登录失败，疑似密码探测。"


def _format_ssh_session_commands_alert(event: AlertEvent) -> str:
    updates = event.context.get("ssh_command_updates", []) if isinstance(event.context, dict) else []
    facts: list[tuple[str, str]] = [("新增命令", _display_number(event.current_value))]
    sections: list[tuple[str, list[str]]] = []

    if isinstance(updates, list) and updates:
        command_lines: list[str] = []
        all_commands: list[str] = []
        first_session_added = False

        for update in updates[:5]:
            if not isinstance(update, dict):
                continue
            commands = [str(x).strip() for x in update.get("added_commands", []) if str(x).strip()]
            all_commands.extend(commands)
            if not first_session_added:
                facts.append(("会话", _format_session_identity(update)))
                first_session_added = True
            command_lines.append(f"- 会话：{_format_session_identity(update)}")
            for command in commands[:10]:
                command_lines.append(f"  - {command}")
            if len(commands) > 10:
                command_lines.append(f"  ... (+{len(commands) - 10} more)")

        if all_commands:
            facts.append(("重点命令", _compact_items(all_commands, max_items=2)))
        if command_lines:
            sections.append(("命令增量", command_lines))

        hints = _suspicious_command_hints(all_commands)
        if hints:
            sections.append(("风险提示", [f"⚠️ {hint}" for hint in hints]))
    else:
        raw = (event.raw_output or "").strip()
        if raw:
            output_label = "变更详情" if event.mode == "differential" else "检测结果"
            sections.append((output_label, [_truncate_text(raw, 800)]))

    return AlertCard(
        title=event.check_name,
        level=_alert_level(event),
        risk=_state_risk_override(event) or "已登录 SSH 会话出现新增命令，请确认是否为授权操作。",
        action=_action_hint(event.check_id, event.alert_state),
        timestamp=event.timestamp,
        facts=facts,
        status=_alert_status(event),
        sections=sections,
    ).render()


def _format_ssh_alert_message(event: AlertEvent) -> str:
    success = event.check_id in SSH_SUCCESS_CHECK_IDS
    lines_raw = _nonempty_lines(event.raw_output)
    records = [_parse_ssh_line(line, success=success) for line in lines_raw]
    count_text = _display_number(event.current_value if event.current_value is not None else float(len(records)))

    is_recovery_notice = event.alert_state in {"RECOVERED_CANDIDATE", "RECOVERED"}

    if is_recovery_notice:
        focus_label = "相关来源 IP"
    elif event.check_id == "ssh_bruteforce":
        focus_label = "新增来源 IP"
    elif success:
        focus_label = "登录来源 IP"
    else:
        focus_label = "失败来源 IP"

    ip_counter = Counter(record["ip"] for record in records)
    user_values = [record["user"] for record in records]
    method_values = [record["method"] for record in records]
    port_values = [record["port"] for record in records]

    facts: list[tuple[str, str]] = [("数量", count_text)]
    if records:
        facts.extend(
            [
                (focus_label, _counter_summary(ip_counter)),
                ("相关用户", _unique_summary(user_values)),
                ("登录方式", _unique_summary(method_values)),
                ("目标端口", _unique_summary(port_values)),
                ("时间", _ssh_time_summary(records)),
            ]
        )
    else:
        facts.append(("记录", "本次是状态变化通知，没有新的 SSH 日志记录。"))

    sections: list[tuple[str, list[str]]] = []
    samples = _ssh_sample_lines(records)
    if samples:
        record_title = "登录记录" if success else "失败记录"
        sections.append((record_title, samples))

    if success:
        session_lines = [line for line in _format_ssh_login_session_context(event.context) if line]
        if session_lines:
            sections.append((session_lines[0].rstrip(":："), session_lines[1:]))

    return AlertCard(
        title=event.check_name,
        level=_alert_level(event),
        risk=_ssh_risk(event, success),
        action=_action_hint(event.check_id, event.alert_state),
        timestamp=event.timestamp,
        facts=facts,
        status=_alert_status(event),
        sections=sections,
    ).render()


def format_alert_message(event: AlertEvent) -> str:
    """Format one alert message for Telegram push."""
    if event.check_id in SSH_SESSION_COMMAND_CHECK_IDS:
        return _format_ssh_session_commands_alert(event)

    if event.check_id in SSH_CHECK_IDS:
        return _format_ssh_alert_message(event)

    return AlertCard(
        title=event.check_name,
        level=_alert_level(event),
        risk=_generic_risk(event),
        action=_generic_action(event),
        timestamp=event.timestamp,
        facts=_generic_facts(event),
        status=_alert_status(event),
    ).render()

def _extract_ip_list(raw_output: str) -> list[str]:
    """Extract unique IPv4/IPv6 tokens from free-form output."""
    ips: list[str] = []
    seen: set[str] = set()

    for raw_line in (raw_output or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith(("+", "-")):
            line = line[1:].strip()

        for token in reversed(line.split()):
            normalized = token.strip().strip(",;()[]{}<>")
            if not normalized:
                continue
            try:
                parsed = str(ipaddress.ip_address(normalized))
            except ValueError:
                continue
            if parsed not in seen:
                seen.add(parsed)
                ips.append(parsed)
            break

    return ips


def _extract_diff_items(raw_output: str) -> tuple[list[str], list[str]]:
    added: list[str] = []
    removed: list[str] = []

    for raw_line in (raw_output or "").splitlines():
        line = raw_line.strip()
        if not line or len(line) < 2:
            continue
        if line.startswith("+"):
            item = line[1:].strip()
            if item:
                added.append(item)
        elif line.startswith("-"):
            item = line[1:].strip()
            if item:
                removed.append(item)

    return added, removed


def format_status_message(history: AlertHistory) -> str:
    stats = history.stats_24h()
    stats.pop("_pushed", None)

    lines = [
        "Sentinel 状态总览",
        "",
        "最近 24h 告警统计:",
    ]

    for level in ["emergency", "critical", "high", "medium", "low", "info"]:
        lines.append(f"- {level:10s}: {stats.get(level, 0)}")

    lines.extend(["", "使用 /sentinel_history 查看完整历史"])
    return "\n".join(lines)


def format_history_message(history: AlertHistory, limit: int = 15) -> str:
    recent = history.recent(limit)
    if not recent:
        return "暂无告警记录"

    lines = [f"最近 {len(recent)} 条告警:", ""]
    for event in reversed(recent):
        emoji = severity_emoji(event.severity)
        time_str = event.timestamp[11:19] if len(event.timestamp) > 19 else event.timestamp
        push_mark = "已推送" if event.pushed else "未推送"
        state_suffix = f" [{event.alert_state}]" if event.alert_state else ""
        lines.append(f"{emoji} {time_str} [{event.severity_label}] {event.check_name}{state_suffix} {push_mark}")

    return "\n".join(lines)
