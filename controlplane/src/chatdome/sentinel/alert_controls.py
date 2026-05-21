"""Sentinel alert push control helpers.

This module is intentionally free of Telegram SDK imports so intent parsing can
be tested in lightweight environments.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, time as datetime_time
from typing import Any


def next_local_midnight(now: datetime, days: int) -> datetime:
    target_date = (now + timedelta(days=days)).date()
    return datetime.combine(target_date, datetime_time.min, tzinfo=now.tzinfo)


def end_of_current_week(now: datetime) -> datetime:
    days_until_next_monday = 7 - now.weekday()
    return next_local_midnight(now, days_until_next_monday)


def parse_alert_mute_until(text: str, now: datetime | None = None) -> datetime | None:
    """Parse a human-friendly mute duration. None means until manual resume."""
    now = now or datetime.now().astimezone()
    lowered = (text or "").strip().lower()

    if any(token in lowered for token in ("本周", "这周", "this week", "this_week")):
        return end_of_current_week(now)
    if any(token in lowered for token in ("今天", "今晚", "today")):
        return next_local_midnight(now, 1)
    if any(token in lowered for token in ("一周", "七天")):
        return now + timedelta(days=7)
    if any(token in lowered for token in ("一天", "24小时", "二十四小时")):
        return now + timedelta(days=1)

    match = re.search(
        r"(\d+)\s*(分钟|分|min|mins|minute|minutes|小时|时|h|hour|hours|天|日|d|day|days|周|星期|w|week|weeks)",
        lowered,
    )
    if not match:
        return None

    amount = max(1, int(match.group(1)))
    unit = match.group(2)
    if unit in {"分钟", "分", "min", "mins", "minute", "minutes"}:
        return now + timedelta(minutes=amount)
    if unit in {"小时", "时", "h", "hour", "hours"}:
        return now + timedelta(hours=amount)
    if unit in {"天", "日", "d", "day", "days"}:
        return now + timedelta(days=amount)
    if unit in {"周", "星期", "w", "week", "weeks"}:
        return now + timedelta(weeks=amount)
    return None


def format_alert_push_status(status: dict[str, Any], *, prefix: str = "") -> str:
    muted = bool(status.get("muted"))
    target_count = int(status.get("target_count") or 0)

    lines = [prefix] if prefix else []
    if muted:
        until = status.get("muted_until")
        if isinstance(until, datetime):
            until_text = until.strftime("%Y-%m-%d %H:%M %Z").strip()
        else:
            until_text = "手动恢复前"
        lines.extend(
            [
                "当前状态: Sentinel 告警推送已静默",
                f"恢复时间: {until_text}",
            ]
        )
    else:
        lines.extend(
            [
                "当前状态: Sentinel 告警推送已开启",
                f"推送目标: {target_count} 个聊天",
            ]
        )
        if target_count == 0:
            lines.append("注意: 当前未配置推送目标，告警仍只会记录。")
    return "\n".join(lines)
