"""Terminal chat application loop."""

from __future__ import annotations

from chatdome.terminal.controller import ChatSessionController
from chatdome.terminal.views import TerminalChatView


class TerminalChatApp:
    """Run a terminal chat controller with a replaceable view."""

    def __init__(
        self,
        view: TerminalChatView,
        controller: ChatSessionController,
        *,
        prompt: str = "you > ",
    ) -> None:
        self._view = view
        self._controller = controller
        self._prompt = prompt

    async def run(self) -> None:
        """Read input until the controller asks to exit."""

        try:
            with self._view.output_context():
                while True:
                    try:
                        line = await self._view.read_line(self._prompt)
                    except EOFError:
                        self._view.write_line_break()
                        break
                    except KeyboardInterrupt:
                        self._view.write_line_break()
                        break

                    keep_running = await self._controller.handle_line(line)
                    if not keep_running:
                        break
        finally:
            await self._controller.stop()
