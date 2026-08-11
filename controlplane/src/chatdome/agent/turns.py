"""Current-turn identity and LLM message framing."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any, Literal, cast


TurnState = Literal[
    "running",
    "waiting_approval",
    "answering_approval_question",
    "waiting_approval_decision",
    "waiting_round_limit",
    "completed",
    "failed",
    "cancelled",
]
TURN_STATES = frozenset(
    {
        "running",
        "waiting_approval",
        "answering_approval_question",
        "waiting_approval_decision",
        "waiting_round_limit",
        "completed",
        "failed",
        "cancelled",
    }
)
TERMINAL_TURN_STATES = frozenset({"completed", "failed", "cancelled"})


@dataclass(frozen=True)
class TurnContext:
    """Runtime policy for one user-authored turn."""

    turn_id: int
    raw_message: str
    user_id: int | None = None


@dataclass
class ActiveTurn:
    """Persisted state for the only active task in one chat."""

    turn_id: int
    raw_message: str
    state: TurnState
    started_at: float
    updated_at: float
    user_id: int | None = None

    def to_snapshot(self) -> dict[str, Any]:
        """Serialize the active turn to a JSON-safe payload."""
        return {
            "turn_id": self.turn_id,
            "raw_message": self.raw_message,
            "state": self.state,
            "started_at": self.started_at,
            "updated_at": self.updated_at,
            "user_id": self.user_id,
        }

    @classmethod
    def from_snapshot(cls, payload: dict[str, Any]) -> "ActiveTurn":
        """Restore and validate a persisted active turn."""
        turn_id = payload.get("turn_id")
        if isinstance(turn_id, bool) or not isinstance(turn_id, int) or turn_id < 1:
            raise ValueError("active turn_id must be a positive integer")

        state = str(payload.get("state") or "")
        if state not in TURN_STATES:
            raise ValueError("active turn state is invalid")

        user_id = payload.get("user_id")
        if isinstance(user_id, bool) or not isinstance(user_id, int):
            user_id = None

        now = time.time()
        try:
            started_at = float(payload.get("started_at", now))
        except (TypeError, ValueError):
            started_at = now
        try:
            updated_at = float(payload.get("updated_at", started_at))
        except (TypeError, ValueError):
            updated_at = started_at

        return cls(
            turn_id=turn_id,
            raw_message=str(payload.get("raw_message") or ""),
            state=cast(TurnState, state),
            started_at=started_at,
            updated_at=updated_at,
            user_id=user_id,
        )


def create_turn_context(
    turn_id: int,
    message: str,
    user_id: int | None = None,
) -> TurnContext:
    """Create the runtime policy scope for an allocated turn."""
    if isinstance(turn_id, bool) or not isinstance(turn_id, int) or turn_id < 1:
        raise ValueError("turn_id must be a positive integer")
    return TurnContext(
        turn_id=turn_id,
        raw_message=str(message or ""),
        user_id=user_id,
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
