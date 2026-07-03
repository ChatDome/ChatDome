"""Terminal chat view interfaces and fallback implementation."""

from __future__ import annotations

from contextlib import nullcontext
from typing import Callable, Protocol


class TerminalChatView(Protocol):
    """UI boundary for terminal chat."""

    async def read_line(self, prompt: str) -> str:
        """Read one input line."""

    def write_message(self, text: str) -> None:
        """Write a chat message."""

    def write_line_break(self) -> None:
        """Write a line break after EOF or interruption."""

    def output_context(self):
        """Return a context manager used while the app is running."""


class PlainTerminalChatView:
    """Fallback terminal view for non-TTY and minimal environments."""

    def __init__(
        self,
        *,
        read_line: Callable[[str], str],
        write_message: Callable[[str], None],
    ) -> None:
        self._read_line = read_line
        self._write_message = write_message

    async def read_line(self, prompt: str) -> str:
        """Read one input line."""

        return self._read_line(prompt)

    def write_message(self, text: str) -> None:
        """Write a formatted chat message."""

        self._write_message(text)

    def write_line_break(self) -> None:
        """Write a line break after EOF or interruption."""

        print()

    def output_context(self):
        """Return a no-op output context."""

        return nullcontext()
