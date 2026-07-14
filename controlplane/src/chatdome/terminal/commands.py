"""Compatibility exports for the platform-neutral slash command API."""

from chatdome.slash_commands import (
    CommandContext,
    CommandDef,
    CommandInvocation,
    CommandRegistry,
    CommandResult,
    CompletionItem,
)

__all__ = [
    "CommandContext",
    "CommandDef",
    "CommandInvocation",
    "CommandRegistry",
    "CommandResult",
    "CompletionItem",
]
