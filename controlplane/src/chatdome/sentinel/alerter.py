"""
Sentinel Alerter — alert formatting, history, and Telegram push.

Implements Push/Pull separation:
  - Push: severity >= push_min_severity → Telegram message
  - Pull: all alerts → recorded in history, queryable via /sentinel_status
"""

from __future__ import annotations

import json
import logging
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from chatdome.sentinel.checks import severity_emoji, severity_label

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Alert event
# ---------------------------------------------------------------------------

@dataclass
class AlertEvent:
    """A single alert event for history and audit."""

    timestamp: str
    check_name: str
    check_id: str
    severity: int
    severity_label: str
    rule: str
    current_value: float | None
    raw_output: str
    pushed: bool
    suppressed: bool
    suppression_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Alert History
# ---------------------------------------------------------------------------

class AlertHistory:
    """
    In-memory alert history with JSONL persistence.

    Keeps the most recent ``max_items`` alerts in memory.
    All alerts are appended to ``alerts_path`` for audit.
    """

    def __init__(
        self,
        alerts_path: Path | None = None,
        max_items: int = 500,
    ) -> None:
        self._history: deque[AlertEvent] = deque(maxlen=max_items)
        self._alerts_path = alerts_path
        if alerts_path:
            alerts_path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, event: AlertEvent) -> None:
        """Record an alert event."""
        self._history.append(event)
        if self._alerts_path:
            try:
                with open(self._alerts_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")
            except OSError:
                logger.exception("Failed to write alert to %s", self._alerts_path)

    def recent(self, limit: int = 20) -> list[AlertEvent]:
        """Get most recent alerts."""
        return list(self._history)[-limit:]

    def stats_24h(self) -> dict[str, int]:
        """Count alerts by severity label in last 24h."""
        cutoff = datetime.now(timezone.utc).isoformat()[:10]  # today's date
        counts: dict[str, int] = {
            "emergency": 0, "critical": 0, "high": 0,
            "medium": 0, "low": 0, "info": 0,
        }
        pushed_count = 0
        for event in self._history:
            if event.timestamp[:10] >= cutoff[:10]:
                label = event.severity_label
                if label in counts:
                    counts[label] += 1
                if event.pushed:
                    pushed_count += 1
        return {**counts, "_pushed": pushed_count}


# ---------------------------------------------------------------------------
# Alert Formatter
# ---------------------------------------------------------------------------

def format_alert_message(event: AlertEvent) -> str:
    """Format a single alert for Telegram push."""
    emoji = severity_emoji(event.severity)
    label = event.severity_label.upper()

    lines = [
        f"{emoji} [{label}] {event.check_name}",
        "",
        f"检查项: {event.check_id}",
        f"时间: {event.timestamp}",
        f"规则: {event.rule}",
        f"当前值: {event.current_value}",
    ]

    # Truncate raw output for readability
    raw = event.raw_output.strip()
    if raw:
        if len(raw) > 800:
            raw = raw[:800] + "\n... (已截断)"
        lines.append("")
        lines.append("原始数据:")
        lines.append(raw)

    lines.append("")
    lines.append("💡 回复任意消息可进入对话模式，获取 AI 详细分析。")

    return "\n".join(lines)


def format_status_message(history: AlertHistory) -> str:
    """Format /sentinel_status output."""
    stats = history.stats_24h()
    pushed = stats.pop("_pushed", 0)

    lines = [
        "🛡️ Sentinel 状态总览",
        "",
        "📊 最近 24h 告警统计:",
    ]

    emoji_map = {
        "emergency": "🚨", "critical": "🔴", "high": "🟠",
        "medium": "🟡", "low": "🔵", "info": "ℹ️",
    }

    for level in ["emergency", "critical", "high", "medium", "low", "info"]:
        count = stats.get(level, 0)
        e = emoji_map[level]
        suffix = " (已推送)" if level in ("emergency", "critical", "high") and count > 0 else ""
        if level in ("medium", "low") and count > 0:
            suffix = " (静默)"
        if level == "info" and count > 0:
            suffix = " (仅日志)"
        lines.append(f"  {e} {level:12s} {count}{suffix}")

    # Recent unpushed events
    recent = [e for e in history.recent(10) if not e.pushed and not e.suppressed]
    if recent:
        lines.append("")
        lines.append("最近未推送事件:")
        for e in recent[-5:]:
            time_str = e.timestamp[11:16] if len(e.timestamp) > 16 else "?"
            lines.append(f"  - {time_str} [{e.severity_label}] {e.check_name}")

    lines.append("")
    lines.append("使用 /sentinel_history 查看完整历史")
    return "\n".join(lines)


def format_history_message(history: AlertHistory, limit: int = 15) -> str:
    """Format /sentinel_history output."""
    recent = history.recent(limit)
    if not recent:
        return "📋 暂无告警记录"

    lines = [f"📋 最近 {len(recent)} 条告警:"]
    lines.append("")
    for e in reversed(recent):
        emoji = severity_emoji(e.severity)
        time_str = e.timestamp[11:19] if len(e.timestamp) > 19 else e.timestamp
        push_mark = "✅" if e.pushed else "🔇"
        lines.append(f"{emoji} {time_str} [{e.severity_label}] {e.check_name} {push_mark}")

    return "\n".join(lines)
