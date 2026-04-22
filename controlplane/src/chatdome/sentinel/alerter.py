"""Sentinel alert formatting, history storage, and status rendering."""

from __future__ import annotations

import ipaddress
import json
import logging
import time
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from chatdome.sentinel.checks import severity_emoji

logger = logging.getLogger(__name__)


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
    """Default interpretation and suggestion per state."""
    cards: dict[str, dict[str, str]] = {
        "NEW": {
            "label": "新威胁首次出现",
            "risk": "中",
            "suggestion": "先确认是否为已知变更或可信来源，再决定是否封禁/隔离。",
            "next_watch": "关注 10 分钟内是否继续出现同类异常，决定是否进入升级态。",
        },
        "ESCALATED_L1": {
            "label": "一级升级",
            "risk": "中-高",
            "suggestion": "开始限制可疑来源（如临时封禁 IP/端口），并收集相关日志证据。",
            "next_watch": "关注 20 分钟窗口内异常是否继续增多，判断是否升级到 L2。",
        },
        "ESCALATED_L2": {
            "label": "二级升级",
            "risk": "高",
            "suggestion": "执行强化处置：收紧访问策略、启用更严格审计、准备应急隔离。",
            "next_watch": "关注 30 分钟窗口内是否达到高强度持续异常，可能升级到 L3。",
        },
        "ESCALATED_L3": {
            "label": "三级升级",
            "risk": "严重",
            "suggestion": "按高危事件流程处理：立即隔离受影响面、保留现场、进行应急响应。",
            "next_watch": "持续监控关键指标，直至进入观察期并确认威胁收敛。",
        },
        "RECOVERED_CANDIDATE": {
            "label": "进入观察期",
            "risk": "中（待确认）",
            "suggestion": "暂不放松防护，保持当前拦截与审计策略，验证是否真正恢复。",
            "next_watch": "观察期内若再次出现异常，将回弹到 ESCALATED_L1。",
        },
        "RECOVERED": {
            "label": "观察期通过，威胁归档",
            "risk": "低",
            "suggestion": "归档本次处置记录，评估是否需要固化长期防护策略。",
            "next_watch": "后续若同类异常再次出现，将按新一轮威胁重新进入状态机。",
        },
    }
    return cards.get(
        state,
        {
            "label": "状态更新",
            "risk": "未知",
            "suggestion": "请结合原始日志和上下文做人工复核。",
            "next_watch": "继续观察后续是否出现新的状态迁移。",
        },
    )


def format_alert_message(event: AlertEvent) -> str:
    """Format one alert message for Telegram push."""
    emoji = severity_emoji(event.severity)
    label = event.severity_label.upper()

    mode_label = "差异巡检" if event.mode == "differential" else "快照巡检"
    if event.current_value is None:
        current_value_text = "N/A"
    elif isinstance(event.current_value, float) and event.current_value.is_integer():
        current_value_text = str(int(event.current_value))
    else:
        current_value_text = str(event.current_value)

    lines = [
        f"{emoji} [{label}] {event.check_name}",
        "",
        f"检查项: {event.check_id}",
        f"巡检模式: {mode_label}",
        f"时间: {event.timestamp}",
        f"当前值: {current_value_text}",
    ]

    if event.alert_state:
        transition = (
            f"{event.previous_state} -> {event.alert_state}"
            if event.previous_state and event.previous_state != event.alert_state
            else event.alert_state
        )
        card = _state_card(event.alert_state)

        lines.extend(
            [
                "",
                "状态告警卡片",
                f"- 状态: {card['label']} ({transition})",
                f"- 依据: {event.rule}",
                f"- 风险: {card['risk']}",
                f"- 建议: {card['suggestion']}",
                f"- 下一观察点: {card['next_watch']}",
            ]
        )

        if event.fingerprint:
            lines.append(f"- 指纹: {event.fingerprint}")

    raw = (event.raw_output or "").strip()
    if raw:
        if len(raw) > 800:
            raw = raw[:800] + "\n... (已截断)"
        lines.extend(["", "原始数据:", raw])

    lines.extend(["", "提示: 调试阶段会推送每次状态变化，便于评估状态机与阈值配置。"])
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
