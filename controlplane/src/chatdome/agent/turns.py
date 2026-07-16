"""Current-turn identity and LLM message framing."""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass


@dataclass(frozen=True)
class TurnContext:
    """Runtime policy for one user-authored turn."""

    turn_id: str
    raw_message: str


def create_turn_context(message: str) -> TurnContext:
    """Create a unique policy scope for a user message."""
    return TurnContext(
        turn_id=f"turn-{secrets.token_hex(8)}",
        raw_message=str(message or ""),
    )


def frame_current_turn(message: str) -> str:
    """Render the current request with an explicit boundary from history."""
    payload = json.dumps(
        {"current_user_message": message},
        ensure_ascii=False,
    )
    return (
        "[CHATDOME CURRENT TURN]\n"
        "The current_user_message field in the JSON object below is the user's current "
        "request and the only "
        "default source of task intent for this turn. Earlier messages, summaries, Memory "
        "Vault, and Engram are reference context only. Do not infer that the user wants to "
        "resume, complete, or execute any earlier task unless current_user_message explicitly "
        "refers to it. Respond only to current_user_message. If it is ambiguous or lacks the "
        "information required to determine an action, ask a concise clarifying question and "
        "do not call tools.\n"
        f"{payload}"
    )
