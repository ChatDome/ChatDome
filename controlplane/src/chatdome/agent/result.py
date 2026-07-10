"""Typed result contract between Agent and presentation layers."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Literal


AgentResultKind = Literal["reply", "pending_approval", "round_limit"]

LEGACY_PENDING_APPROVAL_PREFIX = "__PENDING_APPROVAL__:"
LEGACY_ROUND_LIMIT_PREFIX = "__ROUND_LIMIT_CONFIRM__:"
_EMPTY_APPROVAL_REASONS = frozenset({"无说明", "not provided", "unknown"})


@dataclass(frozen=True)
class AgentResult:
    """Structured response from Agent to presentation layers."""

    kind: AgentResultKind
    content: str = ""
    payload: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def reply(cls, content: str) -> "AgentResult":
        return cls(kind="reply", content=content or "")

    @classmethod
    def pending_approval(cls, payload: dict[str, Any]) -> "AgentResult":
        return cls(kind="pending_approval", payload=dict(payload or {}))

    @classmethod
    def round_limit(cls, payload: dict[str, Any]) -> "AgentResult":
        return cls(kind="round_limit", payload=dict(payload or {}))


def format_approval_purpose(
    payload: dict[str, Any] | None,
    *,
    fallback: str,
    max_chars: int = 120,
) -> str:
    """Return a compact purpose line for an approval prompt."""
    reason = " ".join(str((payload or {}).get("reason") or "").split()).strip()
    if not reason or reason.casefold() in _EMPTY_APPROVAL_REASONS:
        reason = " ".join(str(fallback or "").split()).strip()

    limit = max(2, int(max_chars))
    if len(reason) <= limit:
        return reason
    return reason[: limit - 1].rstrip() + "…"


def coerce_agent_result(value: Any) -> AgentResult:
    """Convert legacy string results or typed results into AgentResult."""
    if isinstance(value, AgentResult):
        return value

    text = "" if value is None else str(value)
    for prefix, factory in (
        (LEGACY_PENDING_APPROVAL_PREFIX, AgentResult.pending_approval),
        (LEGACY_ROUND_LIMIT_PREFIX, AgentResult.round_limit),
    ):
        if text.startswith(prefix):
            try:
                payload = json.loads(text.split(":", 1)[1])
            except (json.JSONDecodeError, IndexError, TypeError):
                return AgentResult.reply(text)
            if isinstance(payload, dict):
                return factory(payload)
            return AgentResult.reply(text)

    return AgentResult.reply(text)
