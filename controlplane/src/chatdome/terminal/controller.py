"""Session controller for terminal chat input routing."""

from __future__ import annotations

import inspect
from dataclasses import replace
from enum import Enum
from typing import Any, Callable

from chatdome.terminal.commands import CommandRegistry, CommandResult


class ChatSessionState(str, Enum):
    """Terminal chat controller states."""

    IDLE = "idle"
    WORKING = "working"
    APPROVAL_REQUIRED = "approval_required"
    APPROVAL_DETAILS = "approval_details"
    CONTINUATION_REQUIRED = "continuation_required"
    ERROR = "error"


APPROVAL_STATES = {ChatSessionState.APPROVAL_REQUIRED, ChatSessionState.APPROVAL_DETAILS}


class ChatSessionController:
    """Route terminal input to slash commands or the agent runtime."""

    def __init__(
        self,
        registry: CommandRegistry,
        *,
        message_handler: Callable[[str], Any],
        unknown_handler: Callable[[str], Any] | None = None,
        stop_handler: Callable[[], Any] | None = None,
        approval_handler: Callable[[str], Any] | None = None,
        continuation_handler: Callable[[str], Any] | None = None,
    ) -> None:
        self._registry = registry
        self._message_handler = message_handler
        self._unknown_handler = unknown_handler
        self._stop_handler = stop_handler
        self._approval_handler = approval_handler
        self._continuation_handler = continuation_handler
        self.state = ChatSessionState.IDLE

    @property
    def status_text(self) -> str:
        """Return a concise status line for terminal views."""

        if self.state == ChatSessionState.WORKING:
            return "assistant: working..."
        if self.state == ChatSessionState.APPROVAL_REQUIRED:
            return "approval: y=allow n=reject d=details"
        if self.state == ChatSessionState.APPROVAL_DETAILS:
            return "approval: y=allow n=reject"
        if self.state == ChatSessionState.CONTINUATION_REQUIRED:
            return "paused: y=continue n=stop"
        if self.state == ChatSessionState.ERROR:
            return "error: run /retry or send a new message"
        return ""

    async def handle_line(self, line: str) -> bool:
        """Handle one user input line."""

        text = str(line or "").strip()
        if not text:
            return True

        if text.startswith("/"):
            result = await self._registry.execute(text)
            if not result.handled:
                result = await self._run_unknown_handler(text)
            self._apply_result_state(result)
            return result.keep_running

        if self.state in APPROVAL_STATES and self._approval_handler is not None:
            result = await self._run_approval_handler(text)
            self._apply_result_state(result)
            return result.keep_running

        if self.state == ChatSessionState.CONTINUATION_REQUIRED and self._continuation_handler is not None:
            result = await self._run_continuation_handler(text)
            self._apply_result_state(result)
            return result.keep_running

        self.state = ChatSessionState.WORKING
        try:
            result = await self._run_message_handler(text)
        except Exception:
            self.state = ChatSessionState.ERROR
            raise
        self._apply_result_state(result)
        return result.keep_running

    async def stop(self) -> None:
        """Stop the attached runtime."""

        if self._stop_handler is None:
            return
        result = self._stop_handler()
        if inspect.isawaitable(result):
            await result

    async def _run_message_handler(self, text: str) -> CommandResult:
        result = self._message_handler(text)
        if inspect.isawaitable(result):
            result = await result
        return self._coerce_result(result, default_state=ChatSessionState.IDLE.value)

    async def _run_unknown_handler(self, text: str) -> CommandResult:
        if self._unknown_handler is None:
            return CommandResult()
        result = self._unknown_handler(text)
        if inspect.isawaitable(result):
            result = await result
        return self._coerce_result(result)

    async def _run_approval_handler(self, text: str) -> CommandResult:
        if self._approval_handler is None:
            return CommandResult(state=self._approval_default_state())
        result = self._approval_handler(text)
        if inspect.isawaitable(result):
            result = await result
        return self._coerce_result(result, default_state=self._approval_default_state())

    def _approval_default_state(self) -> str:
        if self.state == ChatSessionState.APPROVAL_DETAILS:
            return ChatSessionState.APPROVAL_DETAILS.value
        return ChatSessionState.APPROVAL_REQUIRED.value

    async def _run_continuation_handler(self, text: str) -> CommandResult:
        if self._continuation_handler is None:
            return CommandResult(state=ChatSessionState.CONTINUATION_REQUIRED.value)
        result = self._continuation_handler(text)
        if inspect.isawaitable(result):
            result = await result
        return self._coerce_result(result, default_state=ChatSessionState.CONTINUATION_REQUIRED.value)

    def _apply_result_state(self, result: CommandResult) -> None:
        if result.state:
            self.state = ChatSessionState(result.state)
        elif self.state == ChatSessionState.WORKING:
            self.state = ChatSessionState.IDLE

    @staticmethod
    def _coerce_result(result: Any, *, default_state: str | None = None) -> CommandResult:
        if isinstance(result, CommandResult):
            if result.state is None and default_state is not None:
                return replace(result, state=default_state)
            return result
        if isinstance(result, bool):
            return CommandResult(keep_running=result, state=default_state)
        if result is None:
            return CommandResult(state=default_state)
        return CommandResult(state=default_state)
