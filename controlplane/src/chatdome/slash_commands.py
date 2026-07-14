"""Platform-neutral slash command contracts and shared operations."""

from __future__ import annotations

import asyncio
import inspect
import logging
import uuid
from dataclasses import dataclass, field, replace
from typing import Any, Callable, Iterable, Mapping

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CompletionItem:
    """A UI-neutral completion candidate."""

    text: str
    display: str | None = None
    description: str = ""
    start_position: int | None = None


@dataclass(frozen=True)
class CommandContext:
    """Origin and persistence hooks for one slash command call."""

    source: str = "unknown"
    chat_id: int = 0
    actor_id: str = ""
    request_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    event_recorder: Callable[[dict[str, Any]], Any] | None = field(
        default=None,
        repr=False,
        compare=False,
    )


@dataclass(frozen=True)
class CommandResult:
    """Result returned by a slash command handler."""

    keep_running: bool = True
    handled: bool = True
    state: str | None = None
    outcome: str = "completed"
    event_summary: str = ""
    visible_to_agent: bool = False
    event_refs: Mapping[str, Any] = field(default_factory=dict)


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
    """Parsed platform-neutral slash command input."""

    raw: str
    raw_name: str
    args: tuple[str, ...]
    arg_text: str
    command: CommandDef
    context: CommandContext = field(default_factory=CommandContext)


class CommandRegistry:
    """Register, resolve, complete, and execute slash commands."""

    def __init__(
        self,
        commands: Iterable[CommandDef] = (),
        *,
        context_factory: Callable[[], CommandContext] | None = None,
    ) -> None:
        self._commands: list[CommandDef] = []
        self._by_name: dict[str, CommandDef] = {}
        self._aliases: dict[str, str] = {}
        self._context_factory = context_factory
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

    def parse(
        self,
        line: str,
        *,
        context: CommandContext | None = None,
    ) -> CommandInvocation | None:
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
            context=context or CommandContext(),
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

    async def execute(
        self,
        line: str,
        *,
        context: CommandContext | None = None,
    ) -> CommandResult:
        """Execute a registered command through the shared invocation path."""

        if context is None and self._context_factory is not None:
            context = self._context_factory()
        invocation = self.parse(line, context=context)
        if invocation is None:
            return CommandResult(handled=False)
        return await execute_command(invocation)

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


async def execute_command(
    invocation: CommandInvocation,
    handler: Callable[[CommandInvocation], Any] | None = None,
) -> CommandResult:
    """Execute one command with uniform logging and session event recording."""

    command_handler = handler or invocation.command.handler
    context = invocation.context
    command_name = invocation.command.name
    logger.info(
        "Control command received source=%s chat_id=%s actor_id=%s command=%s "
        "argument_count=%d request_id=%s",
        context.source,
        context.chat_id,
        context.actor_id or "-",
        command_name,
        len(invocation.args),
        context.request_id,
    )

    try:
        if command_handler is None:
            result = CommandResult()
        else:
            result = command_handler(invocation)
            if inspect.isawaitable(result):
                result = await result
            result = coerce_command_result(result)
    except asyncio.CancelledError:
        await _record_command_event(
            invocation,
            CommandResult(
                outcome="cancelled",
                event_summary=f"命令 {command_name} 已取消。",
            ),
        )
        logger.info(
            "Control command completed source=%s chat_id=%s command=%s "
            "outcome=cancelled request_id=%s",
            context.source,
            context.chat_id,
            command_name,
            context.request_id,
        )
        raise
    except Exception:
        await _record_command_event(
            invocation,
            CommandResult(
                outcome="failed",
                event_summary=f"命令 {command_name} 执行失败。",
            ),
        )
        logger.exception(
            "Control command failed source=%s chat_id=%s command=%s request_id=%s",
            context.source,
            context.chat_id,
            command_name,
            context.request_id,
        )
        raise

    await _record_command_event(invocation, result)
    logger.info(
        "Control command completed source=%s chat_id=%s command=%s outcome=%s request_id=%s",
        context.source,
        context.chat_id,
        command_name,
        result.outcome,
        context.request_id,
    )
    return result


def coerce_command_result(result: Any) -> CommandResult:
    """Normalize legacy handler return values."""

    if isinstance(result, CommandResult):
        return result
    if isinstance(result, bool):
        return CommandResult(keep_running=result)
    return CommandResult()


async def _record_command_event(
    invocation: CommandInvocation,
    result: CommandResult,
) -> None:
    recorder = invocation.context.event_recorder
    if recorder is None:
        return
    summary = result.event_summary.strip() or _default_event_summary(invocation, result)
    event = {
        "event_id": invocation.context.request_id,
        "event_type": "control_command",
        "source": invocation.context.source,
        "actor_id": invocation.context.actor_id,
        "command": invocation.command.name,
        "argument_count": len(invocation.args),
        "outcome": result.outcome,
        "display_text": summary,
        "visible_to_agent": result.visible_to_agent,
        "refs": dict(result.event_refs),
    }
    try:
        recorded = recorder(event)
        if inspect.isawaitable(recorded):
            await recorded
    except Exception:
        logger.exception(
            "Control command event persistence failed source=%s chat_id=%s command=%s",
            invocation.context.source,
            invocation.context.chat_id,
            invocation.command.name,
        )


def _default_event_summary(
    invocation: CommandInvocation,
    result: CommandResult,
) -> str:
    command_name = invocation.command.name
    if result.outcome == "completed":
        return f"用户通过 {invocation.context.source} 执行了 {command_name}。"
    return f"命令 {command_name} 结果：{result.outcome}。"


def clear_agent_session(agent: Any, chat_id: int) -> bool:
    """Clear one Agent session through the shared command operation."""

    return bool(agent.clear_session(chat_id))


async def stop_active_task(cancel_request: Callable[[], Any] | None) -> bool:
    """Stop a platform-owned task through one callback contract."""

    if cancel_request is None:
        return False
    result = cancel_request()
    if inspect.isawaitable(result):
        result = await result
    return bool(result)


def parse_audit_limit(args: Iterable[str]) -> int:
    """Parse the shared `/audit [N]` limit."""

    values = tuple(args)
    if not values:
        return 10
    try:
        value = int(values[0])
    except (TypeError, ValueError):
        return 10
    return min(max(value, 1), 30)


def get_user_command_audit_events(chat_id: int, limit: int) -> list[dict[str, Any]]:
    """Load user command audit events with the same filters for every platform."""

    from chatdome.agent.audit import CommandAuditTracker

    raw_events = CommandAuditTracker.get_recent_events(
        chat_id=chat_id,
        limit=max(100, limit * 10),
        audit_source="user",
    )
    direct_command_events = {"security_check_executed", "security_check_invalid"}
    events = []
    for event in raw_events:
        event_type = str(event.get("event_type", ""))
        if not event_type.startswith("command_") and event_type not in direct_command_events:
            continue
        events.append(event)
        if len(events) >= limit:
            break
    return events


def format_user_command_audit_events(events: Iterable[dict[str, Any]]) -> str:
    """Format command audit events with one cross-platform field order."""

    values = list(events)
    if not values:
        return "No user command audit events yet."
    lines = [f"User command audit events (latest {len(values)}):"]
    for event in values:
        timestamp = str(event.get("timestamp_iso", "unknown"))
        event_type = str(event.get("event_type", "unknown"))
        risk = str(event.get("risk_level", "-"))
        command = str(event.get("command", "")).replace("\n", " ").strip()
        if len(command) > 100:
            command = command[:100] + "..."
        line = f"- {timestamp} | {event_type} | risk={risk}"
        if command:
            line += f"\n  {command}"
        lines.append(line)
    return "\n".join(lines)


async def resume_agent_approval(
    agent: Any,
    chat_id: int,
    action: str,
    approval_id: str | None = None,
) -> Any:
    """Resolve one approval through the shared command operation."""

    _, result = await agent.resume_session(chat_id, action, approval_id=approval_id)
    return result


async def continue_agent_task(agent: Any, chat_id: int, action: str) -> Any:
    """Resolve one round-limit pause through the shared command operation."""

    return await agent.resolve_round_limit(chat_id, action)


async def get_agent_approval_details(
    agent: Any,
    chat_id: int,
    approval_id: str | None = None,
    *,
    include_llm: bool = True,
) -> dict[str, Any]:
    """Load approval details through the shared command operation."""

    return await agent.get_pending_approval_details(
        chat_id,
        approval_id=approval_id,
        include_llm=include_llm,
    )


def get_token_usage(chat_id: int) -> dict[str, int]:
    """Return one session's token counters."""

    from chatdome.agent.tracker import TokenTracker

    return TokenTracker.get_user_stats(chat_id)


def toggle_command_echo(agent: Any, chat_id: int) -> bool:
    """Toggle command echo and persist the session state."""

    manager = getattr(agent, "session_manager", None)
    if manager is None:
        raise RuntimeError("session manager is unavailable")
    session = manager.get_or_create(chat_id)
    session.command_echo = not bool(session.command_echo)
    manager.save_session(session)
    return bool(session.command_echo)
