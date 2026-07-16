"""Current-turn classification and LLM message framing."""

from __future__ import annotations

import json
import re
import secrets
from dataclasses import dataclass
from enum import Enum


class TurnIntent(str, Enum):
    """Deterministic intent classes used before the LLM can select tools."""

    TASK = "task"
    CONTINUATION = "continuation"
    SOCIAL = "social"


@dataclass(frozen=True)
class TurnContext:
    """Runtime policy for one user-authored turn."""

    turn_id: str
    raw_message: str
    intent: TurnIntent

    @property
    def tools_allowed(self) -> bool:
        return self.intent is not TurnIntent.SOCIAL


_SOCIAL_PATTERNS = (
    re.compile(r"^(?:hello|hi|hey|你好|您好|嗨|哈喽|在吗)[!！,.，。?？~～]*$", re.IGNORECASE),
    re.compile(r"^(?:测试|test|ping|消息测试)[!！,.，。?？~～]*$", re.IGNORECASE),
    re.compile(r"^(?:好的?|好吧|知道了|明白了|收到|谢谢|感谢)[!！,.，。?？~～]*$", re.IGNORECASE),
)
_CONTINUATION_PATTERN = re.compile(
    r"^(?:继续|接着|继续执行|继续处理|按刚才(?:的)?(?:方案)?(?:执行|处理)?|执行刚才(?:的)?(?:方案)?)"
)


def classify_turn(message: str) -> TurnIntent:
    """Classify only high-confidence social and continuation inputs."""
    normalized = " ".join(str(message or "").strip().split())
    if any(pattern.fullmatch(normalized) for pattern in _SOCIAL_PATTERNS):
        return TurnIntent.SOCIAL
    if _CONTINUATION_PATTERN.match(normalized):
        return TurnIntent.CONTINUATION
    return TurnIntent.TASK


def create_turn_context(message: str) -> TurnContext:
    """Create a unique policy scope for a user message."""
    return TurnContext(
        turn_id=f"turn-{secrets.token_hex(8)}",
        raw_message=str(message or ""),
        intent=classify_turn(message),
    )


def frame_current_turn(message: str, intent: TurnIntent) -> str:
    """Render the current request with an explicit boundary from history."""
    payload = json.dumps(
        {
            "explicit_history_continuation": intent is TurnIntent.CONTINUATION,
            "current_user_message": message,
        },
        ensure_ascii=False,
    )
    return (
        "[CHATDOME CURRENT TURN]\n"
        "The current_user_message field in the JSON object below is the user's current "
        "request and the only "
        "default source of task intent for this turn. Earlier messages, summaries, Memory "
        "Vault, and Engram are historical reference only. Do not resume or execute an earlier "
        "task unless this current message explicitly requests it. If the current request is "
        "insufficient to authorize an action, ask a concise clarifying question.\n"
        f"{payload}"
    )


def social_reply(message: str) -> str:
    """Return a deterministic response for inputs that cannot authorize tools."""
    normalized = " ".join(str(message or "").strip().split()).lower()
    normalized = normalized.rstrip("!！,.，。?？~～")
    if normalized in {"测试", "test", "ping", "消息测试"}:
        return "消息已收到。"
    if normalized in {"好的", "好", "好吧", "知道了", "明白了", "收到", "谢谢", "感谢"}:
        return "已收到。"
    return "你好。请发送需要处理的问题。"
