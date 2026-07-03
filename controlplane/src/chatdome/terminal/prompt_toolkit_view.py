"""prompt_toolkit-backed terminal chat view."""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from chatdome.terminal.commands import CommandRegistry


class PromptToolkitCommandCompleter:
    """Expose CommandRegistry completions to prompt_toolkit."""

    def __init__(self, registry: CommandRegistry) -> None:
        self._registry = registry

    def get_completions(self, document, complete_event):  # noqa: ANN001
        del complete_event
        from prompt_toolkit.completion import Completion

        for item in self._registry.completions(document.text_before_cursor):
            yield Completion(
                item.text,
                start_position=item.start_position or 0,
                display=item.display or item.text,
                display_meta=item.description,
            )


class PromptToolkitChatView:
    """Terminal view with history, completion, styling, and stdout protection."""

    def __init__(
        self,
        registry: CommandRegistry,
        *,
        history_path: Path,
        write_message: Callable[[str], None],
        status_provider: Callable[[], str] | None = None,
    ) -> None:
        from prompt_toolkit import PromptSession
        from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
        from prompt_toolkit.history import FileHistory
        from prompt_toolkit.key_binding import KeyBindings
        from prompt_toolkit.patch_stdout import patch_stdout
        from prompt_toolkit.styles import Style

        history_path.parent.mkdir(parents=True, exist_ok=True)
        self._write_message = write_message
        self._status_provider = status_provider or (lambda: "")
        self._patch_stdout = patch_stdout
        self._key_bindings = KeyBindings()
        self._style = Style.from_dict(
            {
                "prompt": "ansicyan bold",
                "completion-menu.completion": "bg:#1f2937 #e5e7eb",
                "completion-menu.completion.current": "bg:#2563eb #ffffff",
                "bottom-toolbar": "bg:#111827 #d1d5db",
            }
        )
        self._session = PromptSession(
            completer=PromptToolkitCommandCompleter(registry),
            complete_while_typing=True,
            auto_suggest=AutoSuggestFromHistory(),
            history=FileHistory(str(history_path)),
            key_bindings=self._key_bindings,
            reserve_space_for_menu=8,
            style=self._style,
        )

    async def read_line(self, prompt: str) -> str:
        """Read one input line."""

        return await self._session.prompt_async(
            [("class:prompt", prompt)],
            bottom_toolbar=self._bottom_toolbar,
        )

    def write_message(self, text: str) -> None:
        """Write a formatted chat message."""

        self._write_message(text)

    def write_line_break(self) -> None:
        """Write a line break after EOF or interruption."""

        print()

    def output_context(self):
        """Return a stdout patch context for background-safe output."""

        return self._patch_stdout(raw=True)

    def _bottom_toolbar(self) -> str:
        return self._status_provider()
