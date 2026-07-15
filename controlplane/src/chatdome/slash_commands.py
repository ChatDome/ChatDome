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
    text: str = ""
    title: str = ""
    severity: str = "info"
    facts: Any = None
    outbound: Any = field(default=None, repr=False, compare=False)


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
    platforms: tuple[str, ...] = ("cli", "telegram")

    @property
    def usage(self) -> str:
        """Return the user-facing usage string."""

        return f"{self.name} {self.args_hint}".strip()

    def supports(self, platform: str) -> bool:
        """Return whether this command is exposed on a platform."""

        return str(platform or "").strip().lower() in self.platforms


COMMAND_CATALOG: tuple[CommandDef, ...] = (
    CommandDef("/help", "Show commands", "basic", aliases=("/start",)),
    CommandDef("/clear", "Clear the current session", "basic"),
    CommandDef(
        "/exit",
        "Exit terminal chat",
        "basic",
        aliases=("/quit",),
        platforms=("cli",),
    ),
    CommandDef("/stop", "Stop the current task", "control"),
    CommandDef("/env", "Show the runtime environment", "context"),
    CommandDef("/audit", "Show recent command audit events", "context", args_hint="[N]"),
    CommandDef("/token", "Show token usage", "context"),
    CommandDef("/cmd_echo", "Toggle command echo", "context"),
    CommandDef(
        "/engram",
        "List or delete persistent memory",
        "memory",
        args_hint="[delete <id>]",
    ),
    CommandDef(
        "/model",
        "Show or switch the active model profile",
        "model",
        aliases=("/llm",),
        args_hint="[profile]",
    ),
    CommandDef(
        "/model_list",
        "Show configured model profiles",
        "model",
        aliases=("/llm_list",),
        keywords=("list", "llm"),
    ),
    CommandDef("/model_add", "Add a model profile", "model", aliases=("/llm_add",)),
    CommandDef(
        "/model_delete",
        "Delete an inactive model profile",
        "model",
        aliases=("/llm_delete",),
        args_hint="<profile>",
    ),
    CommandDef(
        "/model_cancel",
        "Cancel the current model operation",
        "model",
        aliases=("/llm_cancel",),
    ),
    CommandDef(
        "/codex_login",
        "Authenticate a Codex profile",
        "model",
        args_hint="[profile]",
    ),
    CommandDef(
        "/details",
        "Show pending approval details",
        "approval",
        args_hint="[approval_id] [full]",
    ),
    CommandDef(
        "/confirm",
        "Approve a pending command",
        "approval",
        args_hint="[approval_id]",
    ),
    CommandDef(
        "/reject",
        "Reject a pending command or paused task",
        "approval",
        args_hint="[approval_id]",
    ),
    CommandDef("/continue", "Continue a paused task", "approval"),
    CommandDef("/sentinel_status", "Show Sentinel status", "sentinel"),
    CommandDef("/sentinel_trigger", "Run all Sentinel checks", "sentinel"),
    CommandDef("/sentinel_history", "Show recent Sentinel alerts", "sentinel"),
    CommandDef("/sentinel_packs", "Show loaded Sentinel command packs", "sentinel"),
    CommandDef(
        "/sentinel_mute",
        "Pause Sentinel alert pushes",
        "sentinel",
        args_hint="[duration]",
    ),
    CommandDef("/sentinel_resume", "Resume Sentinel alert pushes", "sentinel"),
)


def command_catalog(platform: str) -> tuple[CommandDef, ...]:
    """Return the canonical command definitions available on a platform."""

    return tuple(command for command in COMMAND_CATALOG if command.supports(platform))


def format_command_help(platform: str) -> str:
    """Render one command catalog as platform-neutral plain text."""

    lines = ["Commands:"]
    for command in command_catalog(platform):
        aliases = f" ({', '.join(command.aliases)})" if command.aliases else ""
        lines.append(f"  {command.usage}{aliases}  {command.description}")
    return "\n".join(lines)





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
        result_handler: Callable[
            ["CommandInvocation", CommandResult], Any
        ] | None = None,
    ) -> None:
        self._commands: list[CommandDef] = []
        self._by_name: dict[str, CommandDef] = {}
        self._aliases: dict[str, str] = {}
        self._context_factory = context_factory
        self._result_handler = result_handler
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
        if len(query) < 2:
            return exact_matches + prefix_matches
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
        result = await execute_command(invocation)
        if self._result_handler is not None:
            handled = self._result_handler(invocation, result)
            if inspect.isawaitable(handled):
                await handled
        return result

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

    from chatdome.outbound.builders import OutboundMessageBuilder

    result = replace(
        result,
        outbound=OutboundMessageBuilder().from_command_result(invocation, result),
    )
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


def parse_details_options(args: Iterable[str]) -> tuple[str | None, bool]:
    """Parse the shared `/details [approval_id] [full]` arguments."""

    approval_id: str | None = None
    full = False
    for arg in args:
        value = str(arg or "").strip()
        if not value:
            continue
        if value.lower() in {"full", "--full", "-f"}:
            full = True
        elif approval_id is None:
            approval_id = value
    return approval_id, full


async def reject_agent_action(
    agent: Any,
    chat_id: int,
    approval_id: str | None = None,
) -> Any:
    """Reject an approval or abandon a round-limit pause."""

    manager = getattr(agent, "session_manager", None)
    session = manager.get_or_create(chat_id) if manager is not None else None
    if (
        session is not None
        and getattr(session, "pending_round_limit", False)
        and not getattr(session, "pending_approval", False)
    ):
        return await continue_agent_task(agent, chat_id, "ABANDON")
    return await resume_agent_approval(
        agent,
        chat_id,
        "REJECT",
        approval_id=approval_id,
    )


def execute_engram_command(agent: Any, args: Iterable[str]) -> CommandResult:
    """List or delete Engram records with shared business rules."""

    values = tuple(str(item).strip() for item in args if str(item).strip())
    dispatcher = getattr(agent, "tool_dispatcher", None)
    store = getattr(dispatcher, "engram_store", None)
    if store is None:
        return CommandResult(
            outcome="unavailable",
            text="Engram storage is unavailable.",
        )
    if values and values[0].lower() == "delete":
        if len(values) != 2:
            return CommandResult(outcome="invalid_arguments", text="Usage: /engram delete <id>")
        removed = bool(store.remove(values[1]))
        return CommandResult(
            outcome="engram_deleted" if removed else "engram_not_found",
            event_summary=(
                f"用户删除了 Engram {values[1]}。"
                if removed
                else f"用户尝试删除不存在的 Engram {values[1]}。"
            ),
            text=(
                f"Engram deleted: {values[1]}"
                if removed
                else f"Engram not found: {values[1]}"
            ),
        )
    if values:
        return CommandResult(outcome="invalid_arguments", text="Usage: /engram [delete <id>]")

    import datetime

    records = store.list(include_superseded=False)
    if not records:
        return CommandResult(outcome="empty", text="No active Engram records.")
    lines = ["Engram records", ""]
    for item in records:
        created = datetime.datetime.fromtimestamp(item.created_at).strftime("%Y-%m-%d %H:%M")
        lines.append(f"- [{item.category}] {item.fact}")
        lines.append(f"  ID: {item.id} | {created}")
    lines.extend(["", "Delete: /engram delete <id>"])
    return CommandResult(
        outcome="engrams_listed",
        event_summary=f"用户查看了 {len(records)} 条 Engram 记录。",
        text="\n".join(lines),
    )


def format_model_profiles(manager: Any) -> str:
    """Format model profiles once for every command surface."""

    if manager is None:
        return "Model management is unavailable."
    profiles = manager.list_profiles()
    if not profiles:
        return "No model is configured. Run /model_add."
    active = next((item for item in profiles if item.active), None)
    active_name = active.name if active else manager.get_active_profile_name()
    lines = ["Model profiles", "", f"Active: {active_name}", "Switch: /model <profile>", "", "Profiles:"]
    for item in profiles:
        suffix = "  (current)" if item.active else ""
        lines.append(f"  /model {item.name}{suffix}")
    lines.extend(["", "Details:"])

    for item in profiles:
        marker = "active" if item.active else "available"
        lines.extend(
            [
                f"[{marker}] {item.name}",
                f"  Status: {item.status}",
                f"  Type: {item.provider}/{item.api_mode}",
                f"  Model: {item.model}",
            ]
        )
        if item.base_url:
            lines.append(f"  Base URL: {item.base_url}")
        if item.key_ref:
            lines.append(f"  Key: {item.key_ref}")
        lines.append("")
    return "\n".join(lines).rstrip()


def sentinel_status(sentinel: Any, pack_loader: Any = None) -> CommandResult:
    """Return Sentinel runtime and alert status."""

    if sentinel is None:
        return CommandResult(outcome="unavailable", text="Sentinel is not enabled.")
    from chatdome.sentinel.alerter import format_status_message

    push = sentinel.alert_push_status()
    if push.get("muted"):
        until = push.get("muted_until")
        push_line = f"muted until {until}" if until is not None else "muted until resumed"
    else:
        push_line = "enabled"
    lines = [
        "Sentinel status",
        f"- Scheduler: {'running' if sentinel.is_running else 'stopped'}",
        f"- Checks: {len(sentinel.checks)}",
        f"- Loaded commands: {getattr(pack_loader, 'command_count', 0)}",
        f"- Alert targets: {len(sentinel.alert_chat_ids)}",
        f"- Alert push: {push_line}",
        f"- Baseline learning: {'yes' if sentinel.suppressor.is_learning else 'no'}",
        "",
        format_status_message(sentinel.history),
    ]
    return CommandResult(outcome="sentinel_status_shown", text="\n".join(lines))


async def sentinel_trigger(sentinel: Any) -> CommandResult:
    """Run every Sentinel check."""

    if sentinel is None:
        return CommandResult(outcome="unavailable", text="Sentinel is not enabled.")
    result = await sentinel.trigger_all()
    return CommandResult(
        outcome="sentinel_triggered",
        event_summary="用户手动触发了 Sentinel 全量巡检。",
        visible_to_agent=True,
        text=f"Sentinel check completed\n\n{result}",
    )


def sentinel_history(sentinel: Any) -> CommandResult:
    """Return Sentinel alert history."""

    if sentinel is None:
        return CommandResult(outcome="unavailable", text="Sentinel is not enabled.")
    from chatdome.sentinel.alerter import format_history_message

    return CommandResult(
        outcome="sentinel_history_shown",
        text=format_history_message(sentinel.history),
    )


def sentinel_packs(pack_loader: Any) -> CommandResult:
    """Return loaded Sentinel command packs."""

    if pack_loader is None:
        return CommandResult(outcome="unavailable", text="Sentinel packs are unavailable.")
    from collections import defaultdict

    packs: dict[str, list[str]] = defaultdict(list)
    for command in pack_loader._commands.values():
        packs[command.pack].append(f"  - {command.id}: {command.name}")
    if not packs:
        return CommandResult(outcome="empty", text="No Sentinel command packs are loaded.")
    lines = [f"Loaded {pack_loader.command_count} commands from {len(packs)} packs", ""]
    for pack_name, commands in sorted(packs.items()):
        lines.append(f"{pack_name} ({len(commands)})")
        lines.extend(sorted(commands))
        lines.append("")
    return CommandResult(outcome="sentinel_packs_shown", text="\n".join(lines).rstrip())


def sentinel_mute(
    sentinel: Any,
    args: Iterable[str],
    *,
    chat_id: int,
    source: str,
) -> CommandResult:
    """Pause Sentinel alert pushes."""

    if sentinel is None:
        return CommandResult(outcome="unavailable", text="Sentinel is not enabled.")
    from chatdome.sentinel.alert_controls import format_alert_push_status, parse_alert_mute_until

    raw_args = " ".join(str(item) for item in args).strip()
    status = sentinel.mute_alert_push(
        until=parse_alert_mute_until(raw_args),
        reason=f"{source}_command:/sentinel_mute {raw_args}".strip(),
        chat_id=chat_id,
    )
    return CommandResult(
        outcome="sentinel_muted",
        event_summary="用户暂停了 Sentinel 告警推送。",
        text=format_alert_push_status(status, prefix="Sentinel alert pushes paused."),
    )


def sentinel_resume(sentinel: Any, *, chat_id: int) -> CommandResult:
    """Resume Sentinel alert pushes."""

    if sentinel is None:
        return CommandResult(outcome="unavailable", text="Sentinel is not enabled.")
    from chatdome.sentinel.alert_controls import format_alert_push_status

    status = sentinel.resume_alert_push(chat_id=chat_id)
    return CommandResult(
        outcome="sentinel_resumed",
        event_summary="用户恢复了 Sentinel 告警推送。",
        text=format_alert_push_status(status, prefix="Sentinel alert pushes resumed."),
    )
