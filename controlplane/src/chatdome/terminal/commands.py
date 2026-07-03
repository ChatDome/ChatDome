"""Slash command registry and completion metadata."""

from __future__ import annotations

import inspect
from dataclasses import dataclass, replace
from typing import Any, Callable, Iterable


@dataclass(frozen=True)
class CompletionItem:
    """A UI-neutral completion candidate."""

    text: str
    display: str | None = None
    description: str = ""
    start_position: int | None = None


@dataclass(frozen=True)
class CommandResult:
    """Result returned by a slash command handler."""

    keep_running: bool = True
    handled: bool = True
    state: str | None = None


@dataclass(frozen=True)
class CommandDef:
    """Registered slash command metadata."""

    name: str
    description: str
    category: str
    aliases: tuple[str, ...] = ()
    args_hint: str = ""
    keywords: tuple[str, ...] = ()
    handler: Callable[["CommandInvocation"], Any] | None = None
    completer: Callable[[str], Iterable[CompletionItem | str]] | None = None

    @property
    def usage(self) -> str:
        """Return the user-facing usage string."""

        return f"{self.name} {self.args_hint}".strip()


@dataclass(frozen=True)
class CommandInvocation:
    """Parsed slash command input."""

    raw: str
    raw_name: str
    args: tuple[str, ...]
    arg_text: str
    command: CommandDef


class CommandRegistry:
    """Register, resolve, complete, and execute slash commands."""

    def __init__(self, commands: Iterable[CommandDef] = ()) -> None:
        self._commands: list[CommandDef] = []
        self._by_name: dict[str, CommandDef] = {}
        self._aliases: dict[str, str] = {}
        for command in commands:
            self.register(command)

    @property
    def commands(self) -> tuple[CommandDef, ...]:
        """Return registered commands in display order."""

        return tuple(self._commands)

    def register(self, command: CommandDef) -> None:
        """Register a slash command."""

        self._validate_name(command.name)
        key = command.name.lower()
        if key in self._by_name:
            raise ValueError(f"duplicate command: {command.name}")
        for alias in command.aliases:
            self._validate_name(alias)
            alias_key = alias.lower()
            if alias_key in self._aliases or alias_key in self._by_name:
                raise ValueError(f"duplicate command alias: {alias}")
            self._aliases[alias_key] = key
        self._commands.append(command)
        self._by_name[key] = command

    def specs(self) -> list[tuple[str, str]]:
        """Return usage and description pairs for help output."""

        return [(command.usage, command.description) for command in self._commands]

    def command_names(self) -> list[str]:
        """Return canonical command names in display order."""

        return [command.name for command in self._commands]

    def resolve_name(self, raw_name: str) -> CommandDef | None:
        """Resolve a canonical command name or alias."""

        key = str(raw_name or "").lower()
        command = self._by_name.get(key)
        if command is not None:
            return command
        alias_target = self._aliases.get(key)
        if alias_target:
            return self._by_name.get(alias_target)
        return None

    def parse(self, line: str) -> CommandInvocation | None:
        """Parse a slash command line."""

        stripped = str(line or "").strip()
        if not stripped.startswith("/"):
            return None
        parts = stripped.split()
        raw_name = parts[0].lower() if parts else ""
        command = self.resolve_name(raw_name)
        if command is None:
            return None
        arg_text = stripped[len(parts[0]) :].lstrip() if parts else ""
        return CommandInvocation(
            raw=stripped,
            raw_name=raw_name,
            args=tuple(parts[1:]),
            arg_text=arg_text,
            command=command,
        )

    def match_commands(self, text: str) -> list[CommandDef]:
        """Return command candidates for the current input text."""

        value = str(text or "")
        if not value.startswith("/"):
            return []
        token = value.split(maxsplit=1)[0].lower()
        if self._has_arguments(value, token) and self.resolve_name(token) is not None:
            return []

        query = token[1:]
        if not query:
            return list(self._commands)

        exact_matches = [
            command for command in self._commands if command.name.lower() == token
        ]
        prefix_matches = [
            command
            for command in self._commands
            if command.name.lower().startswith(token) and command not in exact_matches
        ]
        keyword_matches = []
        for command in self._commands:
            if command in exact_matches or command in prefix_matches:
                continue
            terms = tuple(command.name[1:].lower().split("_")) + tuple(
                keyword.lower() for keyword in command.keywords
            )
            if any(term.startswith(query) for term in terms):
                keyword_matches.append(command)
        return exact_matches + prefix_matches + keyword_matches

    def command_matches(self, text: str) -> list[str]:
        """Return canonical command names for compatibility callers."""

        return [command.name for command in self.match_commands(text)]

    def completions(self, text: str) -> list[CompletionItem]:
        """Return UI-neutral completion candidates for input text."""

        value = str(text or "")
        if not value.startswith("/"):
            return []
        token = value.split(maxsplit=1)[0]
        command = self.resolve_name(token.lower())
        if command is not None and self._has_arguments(value, token):
            return self._argument_completions(command, value, token)

        start_position = -len(token)
        return [
            CompletionItem(
                text=command.name,
                display=command.name,
                description=command.description,
                start_position=start_position,
            )
            for command in self.match_commands(value)
        ]

    async def execute(self, line: str) -> CommandResult:
        """Execute a registered command."""

        invocation = self.parse(line)
        if invocation is None:
            return CommandResult(handled=False)
        handler = invocation.command.handler
        if handler is None:
            return CommandResult()

        result = handler(invocation)
        if inspect.isawaitable(result):
            result = await result
        return self._coerce_result(result)

    @staticmethod
    def _validate_name(name: str) -> None:
        if not str(name or "").startswith("/"):
            raise ValueError(f"command name must start with /: {name}")

    @staticmethod
    def _has_arguments(value: str, token: str) -> bool:
        return len(value) > len(token) and value[len(token) : len(token) + 1].isspace()

    def _argument_completions(
        self,
        command: CommandDef,
        value: str,
        token: str,
    ) -> list[CompletionItem]:
        if command.completer is None:
            return []
        arg_text = value[len(token) :].lstrip()
        current_arg = "" if arg_text.endswith(" ") else arg_text.split()[-1] if arg_text else ""
        default_start = -len(current_arg)
        completions = []
        for item in command.completer(arg_text):
            if isinstance(item, str):
                completions.append(
                    CompletionItem(text=item, display=item, start_position=default_start)
                )
                continue
            if item.start_position is None:
                item = replace(item, start_position=default_start)
            completions.append(item)
        return completions

    @staticmethod
    def _coerce_result(result: Any) -> CommandResult:
        if isinstance(result, CommandResult):
            return result
        if isinstance(result, bool):
            return CommandResult(keep_running=result)
        if result is None:
            return CommandResult()
        return CommandResult()
