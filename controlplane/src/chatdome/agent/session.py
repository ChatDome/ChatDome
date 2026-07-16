"""
Multi-turn conversation session management.

Manages per-chat session state, message history, token estimation,
idle timeout, and automatic cleanup.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from chatdome.runtime_paths import compression_log_path, data_dir, memory_file_path

logger = logging.getLogger(__name__)

_REDACTED = "[REDACTED]"
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)
_SENSITIVE_KEY_VALUE_RE = re.compile(
    r"(?i)([\"']?\b(?:telegram[_-]?bot[_-]?token|bot[_-]?token|api[_-]?key|openai[_-]?api[_-]?key|password|passwd|secret|access[_-]?token|refresh[_-]?token|client[_-]?secret|private[_-]?key|codex[_-]?token)\b[\"']?\s*[:=]\s*[\"']?)([^\"'\s,;}]+)([\"']?)"
)
_AUTH_BEARER_RE = re.compile(r"(?i)\b(authorization\s*[:=]\s*bearer\s+)([A-Za-z0-9._~+/=-]{10,})")
_TELEGRAM_BOT_TOKEN_RE = re.compile(r"\b\d{6,}:[A-Za-z0-9_-]{20,}\b")
_OPENAI_STYLE_KEY_RE = re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b")
_SESSION_SEARCH_TERM_RE = re.compile(r"[A-Za-z0-9_.:/@-]{2,}|[\u4e00-\u9fff]{2,}")

_TOOL_RESULT_SNIPPET_CHARS = 500
_TOOL_ARGUMENT_SNIPPET_CHARS = 600
_MEMORY_MERGE_THRESHOLD_CHARS = 1500
_MEMORY_UPDATE_MERGE_THRESHOLD = 2
_DEFERRED_VISIBLE_CONTEXT_LIMIT = 5
_CONTROL_EVENT_LIMIT = 200


def redact_sensitive_text(text: str) -> str:
    """Redact secrets before conversation summaries are persisted."""
    redacted = str(text or "")
    redacted = _PRIVATE_KEY_RE.sub(_REDACTED, redacted)
    redacted = _SENSITIVE_KEY_VALUE_RE.sub(lambda m: f"{m.group(1)}{_REDACTED}{m.group(3)}", redacted)
    redacted = _AUTH_BEARER_RE.sub(lambda m: f"{m.group(1)}{_REDACTED}", redacted)
    redacted = _TELEGRAM_BOT_TOKEN_RE.sub(_REDACTED, redacted)
    redacted = _OPENAI_STYLE_KEY_RE.sub(_REDACTED, redacted)
    return redacted


def _redact_control_field(key: str, value: Any) -> str:
    """Redact an event value using both its field name and content."""
    composite = redact_sensitive_text(f"{key}={value}")
    return composite.partition("=")[2]

def _truncate_context_text(text: Any, max_chars: int) -> str:
    value = redact_sensitive_text(str(text or "")).strip()
    if max_chars <= 0 or len(value) <= max_chars:
        return value
    return value[: max_chars - 12].rstrip() + "\n...(已截断)"



def _compact_context_value(value: Any, max_chars: int = 240) -> str:
    text = " ".join(str(value or "").split()).strip()
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 1].rstrip() + "…"


def _parse_tool_arguments(arguments: Any) -> Any:
    if isinstance(arguments, (dict, list)):
        return arguments
    if arguments in (None, ""):
        return {}
    text = str(arguments).strip()
    if not text:
        return {}
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return text


def _format_tool_argument_value(
    value: Any,
    max_chars: int = _TOOL_ARGUMENT_SNIPPET_CHARS,
) -> str:
    if isinstance(value, (dict, list)):
        text = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    elif value is None:
        text = ""
    else:
        text = str(value)
    text = " ".join(redact_sensitive_text(text).split()).replace('"', "'")
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 12].rstrip() + "...(已截断)"


def _format_tool_arguments(arguments: Any) -> str:
    parsed = _parse_tool_arguments(arguments)
    if isinstance(parsed, dict):
        parts = []
        for key, value in parsed.items():
            key_text = _compact_context_value(key, 80)
            if not key_text:
                continue
            value_text = _format_tool_argument_value(value)
            if isinstance(value, (dict, list)):
                parts.append(f"{key_text}={value_text}")
            else:
                parts.append(f'{key_text}="{value_text}"')
        return "; ".join(parts) if parts else "{}"
    return _format_tool_argument_value(parsed)


def _tool_call_id(tool_call: Any) -> str:
    if not isinstance(tool_call, dict):
        return ""
    return str(tool_call.get("call_id") or tool_call.get("id") or "")


def _tool_call_function(tool_call: Any) -> tuple[str, Any]:
    if not isinstance(tool_call, dict):
        return "unknown_tool", {}
    function = tool_call.get("function")
    if not isinstance(function, dict):
        function = {}
    name = function.get("name") or tool_call.get("name") or "unknown_tool"
    arguments = function.get("arguments", tool_call.get("arguments", {}))
    return str(name), arguments


def _format_tool_call_for_compression(tool_call: Any) -> str:
    name, arguments = _tool_call_function(tool_call)
    return f"AI 调用工具: {redact_sensitive_text(name)}\n  参数: {_format_tool_arguments(arguments)}"


def _format_tool_result_for_compression(
    message: dict[str, Any],
    tool_names: dict[str, str],
) -> str:
    call_id = str(message.get("tool_call_id") or "")
    tool_label = tool_names.get(call_id) or call_id or "unknown_tool"
    content = _truncate_context_text(message.get("content", ""), _TOOL_RESULT_SNIPPET_CHARS)
    if not content:
        content = "(empty)"
    return f"工具结果: {tool_label}\n  结果: {content}"


def _format_compression_history(messages: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    tool_names: dict[str, str] = {}

    for msg in messages:
        role = msg.get("role", "unknown")
        if role == "user":
            lines.append(f"User: {msg.get('content')}")
        elif role == "assistant":
            if msg.get("content"):
                lines.append(f"AI: {msg.get('content')}")
            tool_calls = msg.get("tool_calls") or []
            if isinstance(tool_calls, dict):
                tool_calls = [tool_calls]
            if isinstance(tool_calls, list):
                for tool_call in tool_calls:
                    call_id = _tool_call_id(tool_call)
                    name, _arguments = _tool_call_function(tool_call)
                    if call_id:
                        tool_names[call_id] = name
                    lines.append(_format_tool_call_for_compression(tool_call))
        elif role == "tool":
            lines.append(_format_tool_result_for_compression(msg, tool_names))

    return "\n".join(lines)


def _extract_search_terms(query: str) -> list[str]:
    text = str(query or "").lower()
    terms = []
    for term in _SESSION_SEARCH_TERM_RE.findall(text):
        term = term.strip().lower()
        if term and term not in terms:
            terms.append(term)
    return terms[:16]


def _message_search_content(message: dict[str, Any]) -> str:
    role = str(message.get("role") or "")
    if role == "system" or message.get("tool_calls"):
        return ""
    content = message.get("content")
    if content is None:
        return ""
    return str(content).strip()


def search_message_history(
    messages: list[dict[str, Any]],
    query: str,
    *,
    limit: int = 5,
    max_chars_per_item: int = 900,
) -> list[dict[str, Any]]:
    """Search persisted chat messages without invoking an index service."""
    bounded_limit = min(max(int(limit or 5), 1), 10)
    terms = _extract_search_terms(query)
    query_text = str(query or "").strip().lower()[:240]
    eligible: list[tuple[int, dict[str, Any], str]] = []

    for index, message in enumerate(messages or []):
        content = _message_search_content(message)
        if not content:
            continue
        eligible.append((index, message, content))

    scored: list[tuple[float, int, dict[str, Any], str]] = []
    total = max(len(messages or []), 1)
    for index, message, content in eligible:
        lower_content = content.lower()
        score = 0.0
        if query_text and query_text in lower_content:
            score += 8.0
        for term in terms:
            if term in lower_content:
                score += 2.0 + min(lower_content.count(term), 3)
        if not terms and not query_text:
            score += 1.0
        if score <= 0:
            continue
        score += index / total
        scored.append((score, index, message, content))

    if scored:
        selected = sorted(scored, key=lambda item: (item[0], item[1]), reverse=True)[:bounded_limit]
        match_type = "keyword"
    else:
        selected = [
            (0.0, index, message, content)
            for index, message, content in eligible[-bounded_limit:]
        ]
        match_type = "recent_fallback"

    results: list[dict[str, Any]] = []
    for score, index, message, content in selected:
        results.append(
            {
                "index": index,
                "role": str(message.get("role") or "unknown"),
                "score": round(score, 3),
                "match_type": match_type,
                "content": _truncate_context_text(content, max_chars_per_item),
            }
        )
    return results

# ---------------------------------------------------------------------------
# Single session
# ---------------------------------------------------------------------------

@dataclass
class AgentSession:
    """State for one Telegram chat's conversation with the AI agent."""

    chat_id: int
    messages: list[dict[str, Any]] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    last_active: float = field(default_factory=time.time)
    round_count: int = 0
    
    # Pause/Resume state for Human-in-the-loop
    pending_approval: bool = False
    pending_approval_id: str | None = None
    pending_run_id: str | None = None
    pending_tool_call_id: str | None = None
    pending_command: str | None = None
    pending_command_hash: str | None = None
    pending_since: float | None = None
    pending_followups: list[dict[str, str]] = field(default_factory=list)
    pending_reason: str | None = None
    pending_risk_level: str | None = None
    pending_analysis: dict[str, Any] | None = None
    task_auto_approve: bool = False
    pending_round_limit: bool = False
    pending_round_count: int = 0
    
    # UI Mode
    command_echo: bool = False
    agent_running: bool = False
    _deferred_visible_contexts: list[dict[str, Any]] = field(default_factory=list)

    def to_snapshot(self) -> dict[str, Any]:
        """Serialize this session to a JSON-safe payload."""
        return {
            "chat_id": self.chat_id,
            "messages": self.messages,
            "events": self.events,
            "created_at": self.created_at,
            "last_active": self.last_active,
            "round_count": self.round_count,
            "pending_approval": self.pending_approval,
            "pending_approval_id": self.pending_approval_id,
            "pending_run_id": self.pending_run_id,
            "pending_tool_call_id": self.pending_tool_call_id,
            "pending_command": self.pending_command,
            "pending_command_hash": self.pending_command_hash,
            "pending_since": self.pending_since,
            "pending_followups": self.pending_followups,
            "pending_reason": self.pending_reason,
            "pending_risk_level": self.pending_risk_level,
            "pending_analysis": self.pending_analysis,
            "task_auto_approve": self.task_auto_approve,
            "pending_round_limit": self.pending_round_limit,
            "pending_round_count": self.pending_round_count,
            "command_echo": self.command_echo,
        }

    @classmethod
    def from_snapshot(cls, payload: dict[str, Any]) -> "AgentSession":
        """Restore a session from persisted JSON payload."""
        raw_messages = payload.get("messages", [])
        messages = raw_messages if isinstance(raw_messages, list) else []
        raw_events = payload.get("events", [])
        events = (
            [item for item in raw_events if isinstance(item, dict)][-_CONTROL_EVENT_LIMIT:]
            if isinstance(raw_events, list)
            else []
        )

        raw_followups = payload.get("pending_followups", [])
        pending_followups = raw_followups if isinstance(raw_followups, list) else []

        try:
            chat_id = int(payload.get("chat_id", 0))
        except (TypeError, ValueError):
            chat_id = 0

        return cls(
            chat_id=chat_id,
            messages=messages,
            events=events,
            created_at=float(payload.get("created_at", time.time())),
            last_active=float(payload.get("last_active", time.time())),
            round_count=int(payload.get("round_count", 0)),
            pending_approval=bool(payload.get("pending_approval", False)),
            pending_approval_id=payload.get("pending_approval_id"),
            pending_run_id=payload.get("pending_run_id"),
            pending_tool_call_id=payload.get("pending_tool_call_id"),
            pending_command=payload.get("pending_command"),
            pending_command_hash=payload.get("pending_command_hash"),
            pending_since=(
                float(payload["pending_since"])
                if payload.get("pending_since") is not None
                else None
            ),
            pending_followups=pending_followups,
            pending_reason=payload.get("pending_reason"),
            pending_risk_level=payload.get("pending_risk_level"),
            pending_analysis=payload.get("pending_analysis")
            if isinstance(payload.get("pending_analysis"), dict)
            else None,
            task_auto_approve=bool(payload.get("task_auto_approve", False)),
            pending_round_limit=bool(payload.get("pending_round_limit", False)),
            pending_round_count=int(payload.get("pending_round_count", 0)),
            command_echo=bool(payload.get("command_echo", False)),
        )

    def add_system_message(self, content: str) -> None:
        """Add or replace the system prompt."""
        if self.messages and self.messages[0].get("role") == "system":
            self.messages[0]["content"] = content
        else:
            self.messages.insert(0, {"role": "system", "content": content})

    def add_user_message(self, content: str, *, turn_id: str | None = None) -> None:
        """Append a user message and reset round counter."""
        message: dict[str, Any] = {"role": "user", "content": content}
        if turn_id:
            message["_chatdome_turn_id"] = turn_id
        self.messages.append(message)
        self.last_active = time.time()
        self.round_count = 0
        # New user turn starts a new task scope.
        self.task_auto_approve = False
        self.clear_pending_round_limit()

    def build_llm_messages(self, turn_context: Any | None = None) -> list[dict[str, Any]]:
        """Build an API-safe message view with an explicit current-turn boundary."""
        from chatdome.agent.turns import frame_current_turn

        messages: list[dict[str, Any]] = []
        for item in self.messages:
            message = {
                key: value
                for key, value in item.items()
                if not str(key).startswith("_chatdome_")
            }
            if (
                turn_context is not None
                and item.get("_chatdome_turn_id") == turn_context.turn_id
                and item.get("role") == "user"
            ):
                message["content"] = frame_current_turn(
                    str(item.get("content", "") or ""),
                    turn_context.intent,
                )
            messages.append(message)
        return messages

    def add_assistant_message(self, content: str) -> None:
        """Append an assistant text response."""
        self.messages.append({"role": "assistant", "content": content})
        self.last_active = time.time()

    def add_assistant_tool_calls(self, tool_calls: list[dict[str, Any]]) -> None:
        """Append an assistant message containing tool calls."""
        self.messages.append({
            "role": "assistant",
            "content": None,
            "tool_calls": tool_calls,
        })
        self.last_active = time.time()

    def add_tool_result(self, tool_call_id: str, content: str) -> None:
        """Append a tool result message."""
        self.messages.append({
            "role": "tool",
            "tool_call_id": tool_call_id,
            "content": content,
        })
        self.last_active = time.time()

    def add_control_event(self, event: dict[str, Any]) -> None:
        """Append a redacted control event to the persistent session timeline."""

        safe_event: dict[str, Any] = {}
        for key, value in dict(event or {}).items():
            key_text = _compact_context_value(key, 80)
            if not key_text:
                continue
            if isinstance(value, str):
                safe_event[key_text] = _redact_control_field(key_text, value)
            elif isinstance(value, dict):
                safe_event[key_text] = {
                    nested_key: _redact_control_field(nested_key, item_value)
                    for item_key, item_value in value.items()
                    if (nested_key := _compact_context_value(item_key, 80))
                }
            elif isinstance(value, (bool, int, float)) or value is None:
                safe_event[key_text] = value
            else:
                safe_event[key_text] = _redact_control_field(key_text, value)
        safe_event.setdefault("created_at", time.time())
        self.events.append(safe_event)
        if len(self.events) > _CONTROL_EVENT_LIMIT:
            self.events = self.events[-_CONTROL_EVENT_LIMIT:]
        self.last_active = time.time()

    def _build_visible_context_messages(
        self,
        *,
        event_type: str,
        user_action: str,
        assistant_summary: str,
        refs: dict[str, Any] | None = None,
        max_summary_chars: int = 3500,
        source: str = "telegram",
    ) -> tuple[str, str]:
        event_label = _compact_context_value(event_type, 80) or "visible_event"
        source_value = _compact_context_value(source, 40).lower() or "chatdome"
        source_label = {
            "telegram": "Telegram",
            "cli": "CLI",
            "terminal": "CLI",
        }.get(source_value, source_value)
        action = _compact_context_value(user_action, 300) or f"用户查看了 {source_label} 可见结果"
        user_content = (
            f"[{source_label} 用户可见事件]\n"
            f"事件: {event_label}\n"
            f"用户操作: {action}"
        )

        lines = [
            f"[{source_label} 用户可见结果]",
            f"事件: {event_label}",
        ]
        cleaned_refs: list[str] = []
        for key, value in (refs or {}).items():
            key_text = _compact_context_value(key, 60)
            value_text = _compact_context_value(value, 500)
            if key_text and value_text:
                cleaned_refs.append(f"- {key_text}: {redact_sensitive_text(value_text)}")
        if cleaned_refs:
            lines.append("引用信息:")
            lines.extend(cleaned_refs[:16])

        summary = _truncate_context_text(assistant_summary, max_summary_chars)
        if summary:
            lines.extend(["结果摘要:", summary])
        assistant_content = "\n".join(lines)
        return user_content, assistant_content

    def _defer_visible_context(
        self,
        *,
        event_type: str,
        user_action: str,
        assistant_summary: str,
        refs: dict[str, Any] | None,
        max_summary_chars: int,
        source: str,
    ) -> bool:
        if len(self._deferred_visible_contexts) >= _DEFERRED_VISIBLE_CONTEXT_LIMIT:
            logger.warning("Deferred visible context queue full, dropping event: %s", event_type)
            self.last_active = time.time()
            return False
        self._deferred_visible_contexts.append(
            {
                "event_type": event_type,
                "user_action": user_action,
                "assistant_summary": assistant_summary,
                "refs": dict(refs or {}),
                "max_summary_chars": max_summary_chars,
                "source": source,
            }
        )
        self.last_active = time.time()
        return False

    def add_visible_context(
        self,
        *,
        event_type: str,
        user_action: str,
        assistant_summary: str,
        refs: dict[str, Any] | None = None,
        max_summary_chars: int = 3500,
        source: str = "telegram",
    ) -> bool:
        """Persist a platform-visible interaction as conversation context."""
        if self.agent_running:
            return self._defer_visible_context(
                event_type=event_type,
                user_action=user_action,
                assistant_summary=assistant_summary,
                refs=refs,
                max_summary_chars=max_summary_chars,
                source=source,
            )

        user_content, assistant_content = self._build_visible_context_messages(
            event_type=event_type,
            user_action=user_action,
            assistant_summary=assistant_summary,
            refs=refs,
            max_summary_chars=max_summary_chars,
            source=source,
        )

        if self.pending_approval:
            self.add_pending_followup("user", user_content)
            self.add_pending_followup("assistant", assistant_content)
            return True
        if self.pending_round_limit:
            self.last_active = time.time()
            return False

        self.messages.append({"role": "user", "content": user_content})
        self.messages.append({"role": "assistant", "content": assistant_content})
        self.last_active = time.time()
        return True

    def flush_deferred_visible_contexts(self) -> int:
        """Replay deferred visible context entries after the active agent run ends."""
        if self.agent_running or self.pending_round_limit:
            return 0

        flushed = 0
        while self._deferred_visible_contexts:
            entry = self._deferred_visible_contexts.pop(0)
            if self.add_visible_context(**entry):
                flushed += 1
            else:
                self._deferred_visible_contexts.insert(0, entry)
                break
        return flushed

    def deferred_visible_context_count(self) -> int:
        """Return the number of queued Telegram-visible context entries."""
        return len(self._deferred_visible_contexts)

    def repair_missing_tool_outputs(self) -> int:
        """Add fail-safe outputs for legacy assistant tool calls missing results."""
        existing_outputs = {
            str(msg.get("tool_call_id") or "")
            for msg in self.messages
            if msg.get("role") == "tool" and msg.get("tool_call_id")
        }
        pending_call_id = (
            str(self.pending_tool_call_id or "")
            if self.pending_approval and self.pending_tool_call_id
            else ""
        )
        repaired = 0

        for msg in list(self.messages):
            if msg.get("role") != "assistant" or not msg.get("tool_calls"):
                continue
            for tool_call in msg.get("tool_calls") or []:
                if not isinstance(tool_call, dict):
                    continue
                call_id = str(tool_call.get("call_id") or tool_call.get("id") or "")
                if not call_id or call_id in existing_outputs or call_id == pending_call_id:
                    continue
                self.add_tool_result(
                    call_id,
                    (
                        "Legacy tool output was missing from the persisted session. "
                        "ChatDome marked this tool call as unavailable without executing it. "
                        "Treat this tool call as failed. Do not retry or continue it unless "
                        "the user explicitly asks to continue this task."
                    ),
                )
                existing_outputs.add(call_id)
                repaired += 1

        if repaired:
            logger.warning(
                "Repaired %d missing tool output(s) for chat_id=%d",
                repaired,
                self.chat_id,
            )
        return repaired

    def add_pending_followup(self, role: str, content: str) -> None:
        """Append a side-thread message while waiting for human approval."""
        if role not in {"user", "assistant"}:
            return
        self.pending_followups.append({"role": role, "content": content})
        # Keep this side-thread bounded to avoid runaway context growth.
        if len(self.pending_followups) > 12:
            self.pending_followups = self.pending_followups[-12:]
        self.last_active = time.time()

    def clear_pending_state(self) -> None:
        """Reset all pending-approval related state."""
        self.pending_approval = False
        self.pending_approval_id = None
        self.pending_run_id = None
        self.pending_tool_call_id = None
        self.pending_command = None
        self.pending_command_hash = None
        self.pending_since = None
        self.pending_followups.clear()
        self.pending_reason = None
        self.pending_risk_level = None
        self.pending_analysis = None

    def clear_pending_round_limit(self) -> None:
        """Reset round-limit confirmation state."""
        self.pending_round_limit = False
        self.pending_round_count = 0

    def is_expired(self, timeout: int) -> bool:
        """Check if this session has been idle for too long."""
        return (time.time() - self.last_active) > timeout

    def estimate_tokens(self) -> int:
        """
        Rough token estimate for the current message history.

        Uses a simple heuristic: ~2 tokens per Chinese character,
        ~0.75 tokens per English word, ~4 chars per token average.
        """
        total_chars = sum(
            len(str(msg.get("content", "") or ""))
            for msg in self.messages
        )
        # Also account for tool call arguments
        for msg in self.messages:
            if msg.get("tool_calls"):
                for tc in msg["tool_calls"]:
                    fn = tc.get("function", {})
                    total_chars += len(fn.get("arguments", ""))
        return total_chars // 3  # rough: ~3 chars per token for mixed content

    def append_raw_log(self, text: str) -> None:
        """Append raw interaction text to persistent log file."""
        try:
            path = compression_log_path(self.chat_id)
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as f:
                f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {text}\n")
        except Exception as e:
            logger.error("Failed to write raw log: %s", e)

    async def _build_memory_summary(
        self,
        llm_client,
        existing_summary: str,
        summary: str,
    ) -> str:
        if not existing_summary:
            return summary

        appended_summary = existing_summary + "\n\n[UPDATE]\n" + summary
        if (
            len(existing_summary) <= _MEMORY_MERGE_THRESHOLD_CHARS
            and existing_summary.count("[UPDATE]") < _MEMORY_UPDATE_MERGE_THRESHOLD
        ):
            return appended_summary

        from chatdome.agent.prompts import MEMORY_MERGE_PROMPT

        prompt = (
            MEMORY_MERGE_PROMPT
            + "\n\n旧摘要:\n"
            + existing_summary
            + "\n\n新摘要:\n"
            + summary
        )
        try:
            merge_response = await llm_client.chat_completion(
                [{"role": "user", "content": redact_sensitive_text(prompt)}]
            )
            merged = redact_sensitive_text(merge_response.content or "").strip()
            if merged:
                return merged
        except Exception as e:
            logger.warning("Failed to merge Memory Vault summary: %s", e)
        return appended_summary

    def _format_compression_log(self, summary: str, compressed_messages: int) -> str:
        safe_summary = redact_sensitive_text(summary).strip() or "(empty summary)"
        indented_summary = "\n".join(
            f"  {line}" if line else ""
            for line in safe_summary.splitlines()
        )
        return (
            "=== Context Compressed ===\n"
            f"Chat ID : {self.chat_id}\n"
            f"Messages: {compressed_messages} compressed\n"
            "Summary :\n"
            f"{indented_summary}\n"
            "=========================================="
        )

    async def summarize_and_trim_history(self, llm_client, max_tokens: int) -> None:
        """Compress the oldest valid block when estimated context exceeds the limit."""
        estimated_tokens = self.estimate_tokens()
        if estimated_tokens <= max_tokens:
            return

        from chatdome.agent.prompts import COMPRESSION_PROMPT

        if len(self.messages) <= 3:
            return

        logger.info(
            "Context window limit reached (%d estimated tokens > %d), compressing history...",
            estimated_tokens,
            max_tokens,
        )

        cut_idx = len(self.messages) - 2
        while cut_idx > 1:
            if self.messages[cut_idx].get("role") == "tool":
                cut_idx -= 1
            elif self.messages[cut_idx].get("role") == "assistant" and self.messages[cut_idx].get("tool_calls"):
                cut_idx -= 1
            else:
                break

        if cut_idx <= 2:
            self.messages.pop(1)
            return

        messages_to_compress = self.messages[1:cut_idx]
        history_text = _format_compression_history(messages_to_compress)
        prompt = COMPRESSION_PROMPT + f"\n\n{redact_sensitive_text(history_text)}"

        try:
            summary_response = await llm_client.chat_completion([{"role": "user", "content": prompt}])
            summary = redact_sensitive_text(summary_response.content or "")

            summarized_msg = {
                "role": "system",
                "content": f"[System Context: The following is a summary of earlier conversation turns]\n{summary}",
            }

            self.messages = [self.messages[0], summarized_msg] + self.messages[cut_idx:]

            memory_file = memory_file_path(self.chat_id)
            existing_summary = ""
            if memory_file.exists():
                try:
                    with open(memory_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        existing_summary = redact_sensitive_text(data.get("summary", ""))
                except Exception:
                    pass

            new_summary = await self._build_memory_summary(llm_client, existing_summary, summary)

            memory_file.parent.mkdir(parents=True, exist_ok=True)
            with open(memory_file, "w", encoding="utf-8") as f:
                json.dump({"summary": new_summary, "last_updated": time.time()}, f, ensure_ascii=False, indent=2)

            self.append_raw_log(self._format_compression_log(summary, len(messages_to_compress)))
            logger.info("Context compressed successfully to Vault.")

        except Exception as e:
            logger.error("Failed to compress context: %s. Falling back to simple trim.", e)
            self.messages.pop(1)

    def trim_history(self, max_tokens: int) -> None:
        """
        Remove oldest non-system messages to stay within token budget.
        """
        while self.estimate_tokens() > max_tokens and len(self.messages) > 2:
            removed = self.messages.pop(1)
            logger.debug("Trimmed message from session %d: role=%s", self.chat_id, removed.get("role"))

    def clear(self) -> None:
        """Clear all messages except the system prompt."""
        system_msg = None
        if self.messages and self.messages[0].get("role") == "system":
            system_msg = self.messages[0]
        self.messages.clear()
        self.events.clear()
        if system_msg:
            self.messages.append(system_msg)
        self.round_count = 0
        self.agent_running = False
        self._deferred_visible_contexts.clear()
        self.clear_pending_state()
        self.clear_pending_round_limit()
        self.last_active = time.time()

    def get_turn_executed_commands(self) -> list[str]:
        """Extract commands executed since the last user message for the Echo Mode UI."""
        import json
        cmds = []
        for msg in reversed(self.messages):
            if msg.get("role") == "user":
                break
            if msg.get("tool_calls"):
                for tc in msg["tool_calls"]:
                    fn = tc.get("function", {})
                    name = fn.get("name", "")
                    try:
                        args = json.loads(fn.get("arguments", "{}"))
                    except Exception:
                        args = {}
                        
                    if name == "run_shell_command":
                        cmd_str = args.get("command", "(unknown)")
                        # Remove markdown backticks if AI added them
                        cmd_str = cmd_str.strip("`")
                        cmds.append(f"👨‍💻 `run_shell_command`: `{cmd_str}`")
                    elif name == "run_security_check":
                        cmds.append(f"🛡️ `run_security_check`: `{args.get('check_id', '')}`")
        cmds.reverse()
        return cmds


# ---------------------------------------------------------------------------
# Session Manager
# ---------------------------------------------------------------------------

class SessionManager:
    """
    Manages all active chat sessions.

    Responsibilities:
      - Create / retrieve sessions by chat_id
      - Expire idle sessions via background task
      - Manual session clearing
    """

    def __init__(
        self,
        session_timeout: int = 600,
        pending_approval_timeout: int = 86400,
        persisted_session_ttl: int = 604800,
        max_history_tokens: int = 16000,
        system_prompt: str = "",
        engram_store: 'Any' = None,
    ):
        self.session_timeout = session_timeout
        self.pending_approval_timeout = pending_approval_timeout
        self.persisted_session_ttl = max(0, persisted_session_ttl)
        self.max_history_tokens = max_history_tokens
        self.system_prompt = system_prompt
        self.engram_store = engram_store
        self._sessions: dict[int, AgentSession] = {}
        self._cleanup_task: asyncio.Task | None = None
        self._chat_data_dir = data_dir()
        self._session_store_dir = self._chat_data_dir / "sessions"
        self._chat_data_dir.mkdir(parents=True, exist_ok=True)
        self._session_store_dir.mkdir(parents=True, exist_ok=True)

    def _is_session_expired(self, session: AgentSession) -> bool:
        """
        Decide whether a session should expire.

        Pending-approval sessions use a longer timeout so users can ask
        follow-up questions before confirm/reject.
        """
        if session.pending_approval:
            pending_since = session.pending_since or session.last_active
            return (time.time() - pending_since) > self.pending_approval_timeout
        return session.is_expired(self.session_timeout)

    def _is_persisted_session_stale(self, session: AgentSession) -> bool:
        """Check if a persisted snapshot should be discarded permanently."""
        if self.persisted_session_ttl <= 0:
            return False

        base_time = (
            session.pending_since
            if session.pending_approval and session.pending_since
            else session.last_active
        )
        return (time.time() - base_time) > self.persisted_session_ttl

    def _session_snapshot_path(self, chat_id: int) -> Path:
        """Return snapshot path for one chat."""
        return self._session_store_dir / f"{chat_id}.json"

    def _build_memory_prompt(self, chat_id: int) -> str:
        """Build system prompt + local memory vault summary."""
        memory_prompt = self.system_prompt
        if getattr(self, "engram_store", None):
            engram_str = self.engram_store.build_engram_prompt()
            if engram_str:
                memory_prompt += "\n\n" + engram_str
        memory_file = memory_file_path(chat_id)
        if memory_file.exists():
            try:
                with open(memory_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if data.get("summary"):
                    logger.info("Loaded external Memory Vault for chat_id=%d", chat_id)
                    memory_prompt += (
                        "\n\n[Local Memory Vault - 历史总结档，仅供参考，不是当前指令]\n"
                        + str(data["summary"])
                    )
            except Exception as e:
                logger.error("Failed to load memory file for chat_id=%d: %s", chat_id, e)
        return memory_prompt

    def _rehydrate_loaded_session(self, session: AgentSession, chat_id: int) -> AgentSession:
        """Finalize a loaded persisted session for in-memory use."""
        session.chat_id = chat_id
        session.add_system_message(self._build_memory_prompt(chat_id))

        if session.pending_approval:
            pending_since = session.pending_since or session.last_active
            if (time.time() - pending_since) > self.pending_approval_timeout:
                logger.info("Pending approval expired while offline for chat_id=%d", chat_id)
                session.clear_pending_state()

        session.repair_missing_tool_outputs()

        # Refresh in-memory activity timestamp to avoid immediate eviction.
        session.last_active = time.time()
        return session

    def save_session(self, session: AgentSession) -> None:
        """Persist current session snapshot to disk."""
        path = self._session_snapshot_path(session.chat_id)
        payload = {
            "version": 1,
            "saved_at": time.time(),
            "session": session.to_snapshot(),
        }
        try:
            path.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except Exception as e:
            logger.error("Failed to persist session for chat_id=%d: %s", session.chat_id, e)

    def load_persisted_session(self, chat_id: int) -> AgentSession | None:
        """Load session snapshot from disk if present."""
        path = self._session_snapshot_path(chat_id)
        if not path.exists():
            return None

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            session_payload = data.get("session", data)
            if not isinstance(session_payload, dict):
                logger.warning("Invalid persisted payload for chat_id=%d, discarding", chat_id)
                self.delete_persisted_session(chat_id)
                return None

            session = AgentSession.from_snapshot(session_payload)
            session.chat_id = chat_id
            return session
        except Exception as e:
            logger.error("Failed to load persisted session for chat_id=%d: %s", chat_id, e)
            self.delete_persisted_session(chat_id)
            return None

    def search_history(
        self,
        chat_id: int,
        query: str,
        *,
        limit: int = 5,
        max_chars_per_item: int = 900,
    ) -> list[dict[str, Any]]:
        """Search one chat's existing session messages."""
        session = self._sessions.get(chat_id)
        if session is None:
            session = self.load_persisted_session(chat_id)
        if session is None:
            return []
        return search_message_history(
            session.messages,
            query,
            limit=limit,
            max_chars_per_item=max_chars_per_item,
        )

    def delete_persisted_session(self, chat_id: int) -> None:
        """Delete persisted snapshot for a chat."""
        path = self._session_snapshot_path(chat_id)
        if not path.exists():
            return

        for attempt in range(1, 4):
            try:
                path.unlink()
                return
            except OSError as e:
                if attempt == 3:
                    logger.warning("Failed to delete persisted session for chat_id=%d: %s", chat_id, e)
                    try:
                        tombstone = AgentSession(chat_id=chat_id)
                        tombstone.created_at = 0.0
                        tombstone.last_active = 0.0
                        path.write_text(
                            json.dumps(
                                {
                                    "version": 1,
                                    "saved_at": 0,
                                    "session": tombstone.to_snapshot(),
                                },
                                ensure_ascii=False,
                                indent=2,
                            ),
                            encoding="utf-8",
                        )
                        logger.warning(
                            "Persisted session for chat_id=%d replaced with tombstone (delete denied).",
                            chat_id,
                        )
                    except Exception as inner:
                        logger.error(
                            "Failed to tombstone persisted session for chat_id=%d: %s",
                            chat_id,
                            inner,
                        )
                else:
                    time.sleep(0.05)

    def get_or_create(self, chat_id: int) -> AgentSession:
        """Get an existing session or create a new one."""
        session = self._sessions.get(chat_id)
        if session is not None and not self._is_session_expired(session):
            return session

        if session is not None:
            logger.info("Session expired in memory for chat_id=%d, attempting restore", chat_id)
            self._sessions.pop(chat_id, None)

        loaded = self.load_persisted_session(chat_id)
        if loaded is not None:
            if self._is_persisted_session_stale(loaded):
                logger.info("Persisted session stale for chat_id=%d, discarding", chat_id)
                self.delete_persisted_session(chat_id)
            else:
                session = self._rehydrate_loaded_session(loaded, chat_id)
                self._sessions[chat_id] = session
                self.save_session(session)
                logger.info("Restored session from disk for chat_id=%d", chat_id)
                return session

        session = AgentSession(chat_id=chat_id)
        session.add_system_message(self._build_memory_prompt(chat_id))
        self._sessions[chat_id] = session
        self.save_session(session)
        logger.info("Created new session for chat_id=%d", chat_id)

        return session

    def record_control_event(self, chat_id: int, event: dict[str, Any]) -> None:
        """Persist a control event and its optional Agent-visible projection."""

        session = self.get_or_create(chat_id)
        session.add_control_event(event)
        if bool(event.get("visible_to_agent")):
            session.add_visible_context(
                event_type=str(event.get("event_type") or "control_command"),
                user_action=str(event.get("command") or "control command"),
                assistant_summary=str(event.get("display_text") or ""),
                refs=event.get("refs") if isinstance(event.get("refs"), dict) else None,
                source=str(event.get("source") or "chatdome"),
            )
        self.save_session(session)

    def clear_session(self, chat_id: int) -> bool:
        """Clear a specific chat session. Returns True if it existed."""
        session = self._sessions.get(chat_id)
        if session:
            session.clear()
            session.add_system_message(self._build_memory_prompt(chat_id))
            self.save_session(session)
            logger.info("Session cleared for chat_id=%d", chat_id)
            return True

        persisted = self.load_persisted_session(chat_id)
        if persisted is not None:
            self.delete_persisted_session(chat_id)
            logger.info("Cleared persisted session for chat_id=%d", chat_id)
            return True
        return False

    def remove_session(self, chat_id: int, delete_persisted: bool = False) -> None:
        """Completely remove a session, optionally including persisted snapshot."""
        self._sessions.pop(chat_id, None)
        if delete_persisted:
            self.delete_persisted_session(chat_id)

    @property
    def active_count(self) -> int:
        """Number of currently active sessions."""
        return len(self._sessions)

    def start_cleanup_task(self) -> None:
        """Start the background session cleanup task."""
        if self._cleanup_task is None or self._cleanup_task.done():
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())
            logger.info("Session cleanup task started (timeout=%ds)", self.session_timeout)

    def stop_cleanup_task(self) -> None:
        """Stop the background cleanup task."""
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
            logger.info("Session cleanup task stopped")

    async def _cleanup_loop(self) -> None:
        """Periodically remove expired sessions."""
        while True:
            try:
                await asyncio.sleep(60)  # check every minute
                self._expire_sessions()
                self._cleanup_persisted_sessions()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Error in session cleanup: %s", e)

    def _expire_sessions(self) -> None:
        """Evict expired in-memory sessions while keeping persisted snapshots."""
        expired = [
            chat_id
            for chat_id, session in self._sessions.items()
            if self._is_session_expired(session)
        ]
        for chat_id in expired:
            session = self._sessions.pop(chat_id, None)
            if session is not None:
                self.save_session(session)
            logger.info("Expired session evicted from memory: chat_id=%d", chat_id)

    def _cleanup_persisted_sessions(self) -> None:
        """Delete persisted snapshots that exceeded long-term retention TTL."""
        if self.persisted_session_ttl <= 0:
            return

        for snapshot_path in self._session_store_dir.glob("*.json"):
            chat_id: int | None = None
            try:
                chat_id = int(snapshot_path.stem)
                session = self.load_persisted_session(chat_id)
                if session is None:
                    continue

                if self._is_persisted_session_stale(session):
                    self.delete_persisted_session(chat_id)
                    logger.info("Persisted session expired and removed: chat_id=%d", chat_id)
            except ValueError:
                logger.warning("Unexpected session snapshot filename: %s", snapshot_path.name)
            except Exception as e:
                logger.error("Failed during persisted cleanup for %s: %s", snapshot_path, e)



def record_persisted_control_event(chat_id: int, event: dict[str, Any]) -> bool:
    """Append a control event without initializing an Agent runtime."""

    session_store_dir = data_dir() / "sessions"
    snapshot_path = session_store_dir / f"{int(chat_id)}.json"
    try:
        session_store_dir.mkdir(parents=True, exist_ok=True)
        if snapshot_path.exists():
            data = json.loads(snapshot_path.read_text(encoding="utf-8"))
            payload = data.get("session", data)
            if not isinstance(payload, dict):
                payload = {"chat_id": int(chat_id)}
            session = AgentSession.from_snapshot(payload)
        else:
            session = AgentSession(chat_id=int(chat_id))

        session.chat_id = int(chat_id)
        session.add_control_event(event)
        if bool(event.get("visible_to_agent")):
            session.add_visible_context(
                event_type=str(event.get("event_type") or "control_command"),
                user_action=str(event.get("command") or "control command"),
                assistant_summary=str(event.get("display_text") or ""),
                refs=event.get("refs") if isinstance(event.get("refs"), dict) else None,
                source=str(event.get("source") or "chatdome"),
            )
        snapshot = {
            "version": 1,
            "saved_at": time.time(),
            "session": session.to_snapshot(),
        }
        snapshot_path.write_text(
            json.dumps(snapshot, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return True
    except Exception as exc:
        logger.error(
            "Failed to persist control event for chat_id=%s: %s",
            chat_id,
            exc,
        )
        return False
