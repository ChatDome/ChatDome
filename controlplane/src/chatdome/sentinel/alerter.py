"""
Sentinel Alerter — alert formatting, history, and Telegram push.

Implements Push/Pull separation:
  - Push: severity >= push_min_severity → Telegram message
  - Pull: all alerts → recorded in history, queryable via /sentinel_status
"""

from __future__ import annotations

import ipaddress
import json
import logging
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
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
    mode: str
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
    All alerts are appended to ``alerts_path`` for audit, and
    old records are compacted by date retention policy.
    """

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
        """Record an alert event."""
        self._history.append(event)
        if self._alerts_path:
            try:
                with open(self._alerts_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")
            except OSError:
                logger.exception("Failed to write alert to %s", self._alerts_path)
            self._maybe_cleanup()

    def recent(self, limit: int = 20) -> list[AlertEvent]:
        """Get most recent alerts."""
        return list(self._history)[-limit:]

    def cleanup_old_records(self, now: datetime | None = None) -> int:
        """
        Compact sentinel_alerts.jsonl by retention date.

        Returns the number of removed records.
        """
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
                        # Keep malformed historical line to avoid data loss.
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
            value = record.get(key)
            parsed = AlertHistory._parse_event_date_value(value)
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

    if event.check_id == "ssh_bruteforce":
        new_attack_ips = _extract_ip_list(event.raw_output)
        lines = [
            f"{emoji} [{label}] {event.check_name}",
            "",
            f"检查项: {event.check_id}",
            f"时间: {event.timestamp}",
            "新增攻击IP:",
        ]
        if new_attack_ips:
            lines.extend([f"- {ip}" for ip in new_attack_ips[:80]])
            if len(new_attack_ips) > 80:
                lines.append(f"... (+{len(new_attack_ips) - 80} more)")
        else:
            lines.append("- (未解析到有效 IP)")
        return "\n".join(lines)

    if event.check_id == "open_ports":
        added_ports, removed_ports = _extract_diff_items(event.raw_output)
        lines = [
            f"{emoji} [{label}] {event.check_name}",
            "",
            f"检查项: {event.check_id}",
            f"时间: {event.timestamp}",
            f"变化摘要: 新增 {len(added_ports)}，减少 {len(removed_ports)}",
            "端口变化:",
        ]
        if added_ports or removed_ports:
            shown_added = added_ports[:80]
            shown_removed = removed_ports[:80]
            lines.extend([f"+ {item}" for item in shown_added])
            lines.extend([f"- {item}" for item in shown_removed])
            hidden = (len(added_ports) - len(shown_added)) + (len(removed_ports) - len(shown_removed))
            if hidden > 0:
                lines.append(f"... (+{hidden} more)")
        else:
            lines.append("- (无变化项)")
        return "\n".join(lines)

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
        f"规则阈值: {event.rule}",
        f"当前值: {current_value_text}",
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


def _extract_ip_list(raw_output: str) -> list[str]:
    """Extract unique IPv4/IPv6 tokens from free-form raw output."""
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
    """Extract +added/-removed items from differential payload text."""
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
