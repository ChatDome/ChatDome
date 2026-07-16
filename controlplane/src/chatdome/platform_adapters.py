"""Platform boundaries for command ingress and outbound delivery."""

from __future__ import annotations

import inspect
from abc import ABC, abstractmethod
from typing import Any, Callable, Iterable
from dataclasses import dataclass

from chatdome.outbound.models import OutboundMessage, RenderedMessage
from chatdome.outbound.renderers.telegram import TelegramOutboundRenderer
from chatdome.outbound.renderers.terminal import TerminalOutboundRenderer
from chatdome.slash_commands import (
    CommandContext,
    CommandDef,
    CommandInvocation,
    CommandRegistry,
    CommandResult,
    execute_command,
)


RenderedSender = Callable[[Any, RenderedMessage], Any]


class PlatformAdapter(ABC):
    """Convert platform input and output without owning business decisions."""

    platform: str

    def __init__(self, sender: RenderedSender) -> None:
        self._sender = sender

    @staticmethod
    def receive_message(raw: Any) -> str:
        """Convert platform message content without applying business rules."""

        return str(raw or "")

    def receive_command(
        self,
        *,
        raw: str,
        command: CommandDef,
        args: Iterable[str],
        context: CommandContext,
        raw_name: str | None = None,
    ) -> CommandInvocation:
        """Convert one platform command event into the shared invocation contract."""

        values = tuple(str(item) for item in args)
        return CommandInvocation(
            raw=str(raw or command.name).strip(),
            raw_name=str(raw_name or command.name).strip().lower(),
            args=values,
            arg_text=" ".join(values),
            command=command,
            context=context,
        )

    @abstractmethod
    def render(self, message: OutboundMessage) -> RenderedMessage:
        """Render platform-neutral content into a platform representation."""

    async def deliver(
        self,
        message: OutboundMessage | None,
        *,
        target: Any = None,
    ) -> None:
        """Render and send one outbound message through the platform transport."""

        if message is None:
            return
        delivered = self._sender(target, self.render(message))
        if inspect.isawaitable(delivered):
            await delivered

    async def deliver_result(
        self,
        result: CommandResult,
        *,
        target: Any = None,
    ) -> None:
        """Deliver the outbound message already attached by the command executor."""

        await self.deliver(result.outbound, target=target)

    async def dispatch(
        self,
        invocation: CommandInvocation,
        *,
        handler: Callable[[CommandInvocation], Any] | None = None,
        target: Any = None,
    ) -> CommandResult:
        """Run one invocation through the shared executor and platform egress."""

        result = await execute_command(invocation, handler)
        await self.deliver_result(result, target=target)
        return result


class CLIPlatformAdapter(PlatformAdapter):
    """Terminal input, rendering, and output adapter."""

    platform = "cli"

    def __init__(
        self,
        sender: RenderedSender,
        *,
        ascii_mode: bool = False,
        full: bool = False,
    ) -> None:
        super().__init__(sender)
        self._renderer = TerminalOutboundRenderer(
            ascii_mode=ascii_mode,
            full=full,
        )

    def receive_terminal_input(
        self,
        registry: CommandRegistry,
        line: str,
        *,
        context: CommandContext,
    ) -> CommandInvocation | None:
        """Convert one terminal line into a shared invocation."""

        return registry.parse(line, context=context)

    async def execute_terminal_input(
        self,
        registry: CommandRegistry,
        line: str,
        *,
        context: CommandContext | None = None,
    ) -> CommandResult:
        """Adapt and execute one terminal line through the shared invocation path."""

        invocation = self.receive_terminal_input(
            registry,
            line,
            context=context or registry.create_context(),
        )
        if invocation is None:
            return CommandResult(handled=False)
        return await registry.execute_invocation(invocation)

    def render(self, message: OutboundMessage) -> RenderedMessage:
        return self._renderer.render(message)


@dataclass(frozen=True)
class TelegramDeliveryTarget:
    """Target for proactive Telegram delivery without an incoming message."""

    bot: Any
    chat_id: int


class TelegramPlatformAdapter(PlatformAdapter):
    """Telegram command, rendering, and message delivery adapter."""

    platform = "telegram"

    def __init__(self, sender: RenderedSender, *, full: bool = False) -> None:
        super().__init__(sender)
        self._renderer = TelegramOutboundRenderer(full=full)

    def receive_callback(
        self,
        *,
        data: str,
        command: CommandDef,
        args: Iterable[str],
        context: CommandContext,
    ) -> CommandInvocation:
        """Convert one Telegram button callback into a shared invocation."""

        return self.receive_command(
            raw=data,
            raw_name=command.name,
            command=command,
            args=args,
            context=context,
        )

    def render(self, message: OutboundMessage) -> RenderedMessage:
        return self._renderer.render(message)
