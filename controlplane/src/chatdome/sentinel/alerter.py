"""Sentinel alert formatting, history storage, and status rendering."""

from __future__ import annotations

import json
import logging
import time
import ipaddress
from collections import Counter, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from chatdome.sentinel.checks import severity_emoji

logger = logging.getLogger(__name__)


SSH_SUCCESS_CHECK_IDS = {"ssh_success_login", "ssh_success_login_offhours"}
SSH_FAILED_CHECK_IDS = {"ssh_failed_burst", "ssh_bruteforce"}
SSH_CHECK_IDS = SSH_SUCCESS_CHECK_IDS | SSH_FAILED_CHECK_IDS


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
            "label": "新威胁首次出现",
            "risk": "中",
            "next_watch": "关注 10 分钟内是否继续出现同类异常，决定是否进入升级态。",
        },
        "ESCALATED_L1": {
            "label": "一级升级",
            "risk": "中-高",
            "next_watch": "关注 20 分钟窗口内异常是否继续增多，判断是否升级到 L2。",
        },
        "ESCALATED_L2": {
            "label": "二级升级",
            "risk": "高",
            "next_watch": "关注 30 分钟窗口内是否达到高强度持续异常，可能升级到 L3。",
        },
        "ESCALATED_L3": {
            "label": "三级升级",
            "risk": "严重",
            "next_watch": "持续监控关键指标，直至进入观察期并确认威胁收敛。",
        },
        "RECOVERED_CANDIDATE": {
            "label": "进入观察期",
            "risk": "中（待确认）",
            "next_watch": "观察期内若再次出现异常，将回弹到 ESCALATED_L1。",
        },
        "RECOVERED": {
            "label": "观察期通过，威胁归档",
            "risk": "低",
            "next_watch": "后续若同类异常再次出现，将按新一轮威胁重新进入状态机。",
        },
    }
    return cards.get(
        state,
        {
            "label": "状态更新",
            "risk": "未知",
            "next_watch": "继续观察后续是否出现新的状态迁移。",
        },
    )


def _display_number(value: float | None) -> str:
    if value is None:
        return "未知"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def _alert_transition(event: AlertEvent) -> str:
    if not event.alert_state:
        return "未进入状态机"
    if event.previous_state and event.previous_state != event.alert_state:
        return f"{event.previous_state} -> {event.alert_state}"
    return event.alert_state


def _nonempty_lines(raw_output: str) -> list[str]:
    return [line.strip() for line in (raw_output or "").splitlines() if line.strip()]


def _safe_ip_token(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip().strip(",;()[]{}<>")))
    except ValueError:
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


def _ssh_sample_lines(records: list[dict[str, str]], max_items: int = 5) -> list[str]:
    samples: list[str] = []
    for record in records[:max_items]:
        samples.append(
            f"- {record['time']} {record['result']}: "
            f"{record['user']}@{record['ip']}:{record['port']} via {record['method']}"
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


def _format_ssh_alert_message(event: AlertEvent) -> str:
    emoji = severity_emoji(event.severity)
    label = event.severity_label.upper()
    card = _state_card(event.alert_state) if event.alert_state else None
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

    lines = [
        f"{emoji} [{label}] {event.check_name}",
        "",
        f"告警时间: {event.timestamp}",
        f"数量: {count_text}",
    ]

    if card:
        lines.append(f"威胁状态: {card['label']} ({_alert_transition(event)})")
        lines.append(f"风险判断: {card['risk']}")

    if records:
        lines.extend(
            [
                "",
                f"- {focus_label}: {_counter_summary(ip_counter)}",
                f"- 相关用户: {_unique_summary(user_values)}",
                f"- 登录方式: {_unique_summary(method_values)}",
                f"- 目标端口: {_unique_summary(port_values)}",
            ]
        )
        lines.append(f"- 时间: {_ssh_time_summary(records)}")
    else:
        lines.extend(["", "- 本次是状态变化通知，没有新的 SSH 日志记录。"])

    samples = _ssh_sample_lines(records)
    if samples:
        record_title = "登录记录:" if success else "失败记录:"
        lines.extend(["", record_title])
        lines.extend(samples)

    return "\n".join(lines)


def format_alert_message(event: AlertEvent) -> str:
    """Format one alert message for Telegram push."""
    if event.check_id in SSH_CHECK_IDS:
        return _format_ssh_alert_message(event)

    emoji = severity_emoji(event.severity)
    label = event.severity_label.upper()
    mode_label = "新增变化" if event.mode == "differential" else "当前快照"
    value_text = _display_number(event.current_value)

    lines = [
        f"{emoji} [{label}] {event.check_name}",
        "",
        f"告警时间: {event.timestamp}",
        f"{mode_label}: {value_text}",
    ]

    if event.alert_state:
        card = _state_card(event.alert_state)
        lines.extend(
            [
                "",
                f"威胁状态: {card['label']} ({_alert_transition(event)})",
                f"风险判断: {card['risk']}",
                f"触发原因: {event.rule}",
                f"下一观察点: {card['next_watch']}",
            ]
        )

    raw = (event.raw_output or "").strip()
    if raw:
        if len(raw) > 800:
            raw = raw[:800] + "\n... (已截断)"
        lines.extend(["", "相关输出:", raw])

    return "\n".join(lines)


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
