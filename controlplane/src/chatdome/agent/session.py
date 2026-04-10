"""
Multi-turn conversation session management.

Manages per-chat session state, message history, token estimation,
idle timeout, and automatic cleanup.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Single session
# ---------------------------------------------------------------------------

@dataclass
class AgentSession:
    """State for one Telegram chat's conversation with the AI agent."""

    chat_id: int
    messages: list[dict[str, Any]] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    last_active: float = field(default_factory=time.time)
    round_count: int = 0
    
    # Pause/Resume state for Human-in-the-loop
    pending_approval: bool = False
    pending_tool_call_id: str | None = None
    pending_command: str | None = None

    def add_system_message(self, content: str) -> None:
        """Add or replace the system prompt."""
        if self.messages and self.messages[0].get("role") == "system":
            self.messages[0]["content"] = content
        else:
            self.messages.insert(0, {"role": "system", "content": content})

    def add_user_message(self, content: str) -> None:
        """Append a user message and reset round counter."""
        self.messages.append({"role": "user", "content": content})
        self.last_active = time.time()
        self.round_count = 0

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
        self.round_count += 1
        self.last_active = time.time()

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

    def trim_history(self, max_tokens: int) -> None:
        """
        Remove oldest non-system messages to stay within token budget.

        Preserves the system prompt (first message) and the most recent
        messages.
        """
        while self.estimate_tokens() > max_tokens and len(self.messages) > 2:
            # Remove the second message (oldest non-system)
            removed = self.messages.pop(1)
            logger.debug(
                "Trimmed message from session %d: role=%s",
                self.chat_id, removed.get("role"),
            )

    def clear(self) -> None:
        """Clear all messages except the system prompt."""
        system_msg = None
        if self.messages and self.messages[0].get("role") == "system":
            system_msg = self.messages[0]
        self.messages.clear()
        if system_msg:
            self.messages.append(system_msg)
        self.round_count = 0
        self.last_active = time.time()


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
        max_history_tokens: int = 16000,
        system_prompt: str = "",
    ):
        self.session_timeout = session_timeout
        self.max_history_tokens = max_history_tokens
        self.system_prompt = system_prompt
        self._sessions: dict[int, AgentSession] = {}
        self._cleanup_task: asyncio.Task | None = None

    def get_or_create(self, chat_id: int) -> AgentSession:
        """Get an existing session or create a new one."""
        session = self._sessions.get(chat_id)

        if session is None or session.is_expired(self.session_timeout):
            if session is not None:
                logger.info("Session expired for chat_id=%d, creating new", chat_id)
            session = AgentSession(chat_id=chat_id)
            session.add_system_message(self.system_prompt)
            self._sessions[chat_id] = session
            logger.info("Created new session for chat_id=%d", chat_id)

        return session

    def clear_session(self, chat_id: int) -> bool:
        """Clear a specific chat session. Returns True if it existed."""
        session = self._sessions.get(chat_id)
        if session:
            session.clear()
            logger.info("Session cleared for chat_id=%d", chat_id)
            return True
        return False

    def remove_session(self, chat_id: int) -> None:
        """Completely remove a session."""
        self._sessions.pop(chat_id, None)

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
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Error in session cleanup: %s", e)

    def _expire_sessions(self) -> None:
        """Remove all expired sessions."""
        expired = [
            chat_id
            for chat_id, session in self._sessions.items()
            if session.is_expired(self.session_timeout)
        ]
        for chat_id in expired:
            del self._sessions[chat_id]
            logger.info("Expired session removed: chat_id=%d", chat_id)
