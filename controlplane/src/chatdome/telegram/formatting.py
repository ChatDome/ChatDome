"""
Telegram message formatting helpers.

Design goal:
- Keep raw bot outputs plain text by default.
- Allow opt-in markdown rendering for specific messages when needed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


class MessageMarkup(str, Enum):
    """Channel-facing rendering mode."""

    PLAIN = "plain"
    TELEGRAM_MARKDOWN = "telegram_markdown"
    TELEGRAM_MARKDOWN_V2 = "telegram_markdown_v2"


@dataclass(frozen=True)
class RenderedMessage:
    """Rendered message payload for Telegram send APIs."""

    text: str
    parse_mode: str | None = None


class TelegramMessageFormatter:
    """
    Render outbound text for Telegram.

    By default markdown is disabled and all text is normalized into plain text.
    """

    def __init__(self, enable_markdown: bool = False) -> None:
        self.enable_markdown = enable_markdown

    def render(
        self,
        text: str,
        markup: MessageMarkup = MessageMarkup.PLAIN,
    ) -> RenderedMessage:
        raw = text or ""

        if markup == MessageMarkup.PLAIN or not self.enable_markdown:
            return RenderedMessage(text=self.to_plain_text(raw), parse_mode=None)

        if markup == MessageMarkup.TELEGRAM_MARKDOWN_V2:
            return RenderedMessage(text=raw, parse_mode="MarkdownV2")

        return RenderedMessage(text=raw, parse_mode="Markdown")

    @staticmethod
    def to_plain_text(text: str) -> str:
        """
        Convert markdown-ish text into readable plain text.

        Keeps content intact while removing common markdown control tokens.
        """
        if not text:
            return ""

        normalized = text.replace("\r\n", "\n")

        # Strip fenced code block markers but keep body.
        normalized = re.sub(r"```[a-zA-Z0-9_-]*\n?", "", normalized)
        normalized = normalized.replace("```", "")

        # Drop markdown heading markers.
        normalized = re.sub(r"(?m)^\s{0,3}#{1,6}\s*", "", normalized)

        # Remove common inline markdown wrappers.
        normalized = normalized.replace("**", "")
        normalized = normalized.replace("__", "")
        normalized = normalized.replace("`", "")

        # Unescape markdown-escaped symbols.
        normalized = re.sub(
            r"\\([\\`*_\[\]()#+\-.!|~>{}])",
            r"\1",
            normalized,
        )

        return normalized

