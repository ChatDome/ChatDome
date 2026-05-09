"""
ChatDome Logger — compact logging with optional ANSI colors.

Color is enabled only for interactive terminals by default, so redirected logs
such as chatdome.log stay plain and readable in less, grep, and log collectors.
"""

import logging
import os
import sys
from typing import Optional


class ChatDomeFormatter(logging.Formatter):
    """
    Custom log formatter that strips 'chatdome.' prefix and optionally applies ANSI colors.
    Format: [TIME] [LEVEL] [COMPONENT] Message
    """

    # ANSI Color Escapes
    GREY = "\033[90m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD_RED = "\033[1;91m"
    MAGENTA = "\033[95m"
    RESET = "\033[0m"

    LEVEL_COLORS = {
        logging.DEBUG: GREY,
        logging.INFO: GREEN,
        logging.WARNING: YELLOW,
        logging.ERROR: RED,
        logging.CRITICAL: BOLD_RED,
    }

    def __init__(
        self,
        fmt: Optional[str] = None,
        datefmt: Optional[str] = None,
        style: str = "%",
        use_colors: bool = True,
    ):
        super().__init__(fmt=fmt, datefmt=datefmt, style=style)
        self.use_colors = use_colors

    def _colorize(self, text: str, color: str) -> str:
        if not self.use_colors:
            return text
        return f"{color}{text}{self.RESET}"

    def format(self, record: logging.LogRecord) -> str:
        # 1. Simplify component name (strip chatdome. prefix)
        name = record.name
        if name.startswith("chatdome."):
            name = name[9:]

        # 2. Determine colors
        level_color = self.LEVEL_COLORS.get(record.levelno, self.RESET)
        component_color = self.CYAN  # Distinct color for component path
        time_color = self.GREY

        # 3. Build parts
        timestamp = self.formatTime(record, self.datefmt)
        timestamp_part = self._colorize(timestamp, time_color)

        level_name = record.levelname
        level_part = self._colorize(f"[{level_name:5s}]", level_color)

        component_part = self._colorize(f"[{name}]", component_color)

        message = record.getMessage()

        # 4. Assemble
        formatted = f"{timestamp_part} {level_part} {component_part} {message}"

        # Add stack trace if exists
        if record.exc_info:
            if not record.exc_text:
                record.exc_text = self.formatException(record.exc_info)
        if record.exc_text:
            if formatted[-1:] != "\n":
                formatted += "\n"
            formatted += self._colorize(record.exc_text, self.RED)
        if record.stack_info:
            if formatted[-1:] != "\n":
                formatted += "\n"
            formatted += self.formatStack(record.stack_info)

        return formatted


def _stream_supports_color(stream: object) -> bool:
    color_mode = os.environ.get("CHATDOME_LOG_COLOR", "auto").strip().lower()
    if color_mode in {"always", "1", "true", "yes", "on"}:
        return True
    if color_mode in {"never", "0", "false", "no", "off"}:
        return False
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("TERM", "").lower() == "dumb":
        return False
    isatty = getattr(stream, "isatty", None)
    return bool(isatty and isatty())


def setup_logging(level: int = logging.INFO, use_colors: Optional[bool] = None) -> None:
    """Configures the global logging system with ChatDome aesthetics."""
    handler = logging.StreamHandler(sys.stdout)
    if use_colors is None:
        use_colors = _stream_supports_color(sys.stdout)
    formatter = ChatDomeFormatter(
        datefmt="%Y-%m-%d %H:%M:%S",
        use_colors=use_colors,
    )
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Remove existing handlers to avoid duplicates
    for h in root_logger.handlers[:]:
        root_logger.removeHandler(h)

    root_logger.addHandler(handler)

    # Suppress noise from dependencies
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("openai").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("telegram").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)
