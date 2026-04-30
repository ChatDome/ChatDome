"""
Multi-turn conversation session management.

Manages per-chat session state, message history, token estimation,
idle timeout, and automatic cleanup.
"""

from __future__ import annotations

import asyncio
import logging
import time
import os
import json
from dataclasses import dataclass, field
from pathlib import Path
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

    def to_snapshot(self) -> dict[str, Any]:
        """Serialize this session to a JSON-safe payload."""
        return {
            "chat_id": self.chat_id,
            "messages": self.messages,
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

        raw_followups = payload.get("pending_followups", [])
        pending_followups = raw_followups if isinstance(raw_followups, list) else []

        try:
            chat_id = int(payload.get("chat_id", 0))
        except (TypeError, ValueError):
            chat_id = 0

        return cls(
            chat_id=chat_id,
            messages=messages,
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

    def add_user_message(self, content: str) -> None:
        """Append a user message and reset round counter."""
        self.messages.append({"role": "user", "content": content})
        self.last_active = time.time()
        self.round_count = 0
        # New user turn starts a new task scope.
        self.task_auto_approve = False
        self.clear_pending_round_limit()

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
            with open(f"chat_data/{self.chat_id}_raw.log", "a", encoding="utf-8") as f:
                f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {text}\n")
        except Exception as e:
            logger.error("Failed to write raw log: %s", e)

    async def summarize_and_trim_history(self, llm_client, max_tokens: int) -> None:
        """
        AI Context Compression. If tokens exceed max_tokens, summarize the oldest valid block,
        save to long-term memory vault, and inject into context as a system string.
        """
        if self.estimate_tokens() <= max_tokens:
            return
            
        from chatdome.agent.prompts import COMPRESSION_PROMPT
        
        # Don't try to compress if there are very few messages
        if len(self.messages) <= 3:
            return
            
        logger.info("Token limit reached (%d > %d), compressing history...", self.estimate_tokens(), max_tokens)
        
        # Safe cut point
        cut_idx = len(self.messages) - 2
        while cut_idx > 1:
            if self.messages[cut_idx].get("role") == "tool":
                cut_idx -= 1
            elif self.messages[cut_idx].get("role") == "assistant" and self.messages[cut_idx].get("tool_calls"):
                cut_idx -= 1
            else:
                break
                
        if cut_idx <= 2:
            self.messages.pop(1)  # Fallback
            return
            
        messages_to_compress = self.messages[1:cut_idx]
        history_text = ""
        for msg in messages_to_compress:
            role = msg.get("role", "unknown")
            if role == "user":
                history_text += f"\nUser: {msg.get('content')}"
            elif role == "assistant":
                if msg.get("content"):
                    history_text += f"\nAI: {msg.get('content')}"
                if msg.get("tool_calls"):
                    history_text += f"\nAI Tool Executed: {msg.get('tool_calls')}"
            elif role == "tool":
                content = str(msg.get("content", ""))[:500] 
                history_text += f"\nTool Result Snippet: {content}..."
                
        prompt = COMPRESSION_PROMPT + f"\n\n{history_text}"
        
        try:
            summary_response = await llm_client.chat_completion([{"role": "user", "content": prompt}])
            summary = summary_response.content or ""
            
            # Formulate the payload memory
            summarized_msg = {
                "role": "system",
                "content": f"[System Context: The following is a summary of earlier conversation turns]\n{summary}"
            }
            
            # Apply to memory list
            self.messages = [self.messages[0], summarized_msg] + self.messages[cut_idx:]
            
            # Dump to memory vault
            memory_file = f"chat_data/{self.chat_id}_memory.json"
            # Merge if exists
            existing_summary = ""
            if os.path.exists(memory_file):
                try:
                    with open(memory_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        existing_summary = data.get("summary", "")
                except Exception:
                    pass
            
            new_summary = existing_summary + "\n\n[UPDATE]\n" + summary if existing_summary else summary
                
            with open(memory_file, "w", encoding="utf-8") as f:
                json.dump({"summary": new_summary, "last_updated": time.time()}, f, ensure_ascii=False, indent=2)
                
            self.append_raw_log(f"--- Context Compressed ---\n{summary}\n-------------------------")
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
        if system_msg:
            self.messages.append(system_msg)
        self.round_count = 0
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
    ):
        self.session_timeout = session_timeout
        self.pending_approval_timeout = pending_approval_timeout
        self.persisted_session_ttl = max(0, persisted_session_ttl)
        self.max_history_tokens = max_history_tokens
        self.system_prompt = system_prompt
        self._sessions: dict[int, AgentSession] = {}
        self._cleanup_task: asyncio.Task | None = None
        self._chat_data_dir = Path("chat_data")
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
        memory_file = self._chat_data_dir / f"{chat_id}_memory.json"
        memory_prompt = self.system_prompt
        if memory_file.exists():
            try:
                with open(memory_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if data.get("summary"):
                    logger.info("Loaded external Memory Vault for chat_id=%d", chat_id)
                    memory_prompt += "\n\n[Local Memory Vault - 历史总结档]\n" + str(data["summary"])
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
