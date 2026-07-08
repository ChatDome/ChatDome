"""
ChatDome Logger — compact logging with optional ANSI colors.

Color is enabled only for interactive terminals by default, so redirected logs
such as chatdome.log stay plain and readable in less, grep, and log collectors.
"""

import contextvars
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import sys
from typing import Optional

_log_origin = contextvars.ContextVar("chatdome_log_origin", default="")
_CHATDOME_ORIGIN_FACTORY_ATTR = "_chatdome_origin_record_factory"


class log_origin:
    """Temporarily tag log records emitted in the current execution context."""

    def __init__(self, origin: str):
        self.origin = origin
        self._token: Optional[contextvars.Token] = None

    def __enter__(self) -> "log_origin":
        self._token = _log_origin.set(self.origin)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._token is not None:
            _log_origin.reset(self._token)
            self._token = None


def current_log_origin() -> str:
    """Return the current execution origin tag."""
    return _log_origin.get()


def _install_origin_record_factory() -> None:
    factory = logging.getLogRecordFactory()
    if getattr(factory, _CHATDOME_ORIGIN_FACTORY_ATTR, False):
        return

    def chatdome_record_factory(*args, **kwargs):
        record = factory(*args, **kwargs)
        if not hasattr(record, "chatdome_origin"):
            record.chatdome_origin = _log_origin.get()
        return record

    setattr(chatdome_record_factory, _CHATDOME_ORIGIN_FACTORY_ATTR, True)
    logging.setLogRecordFactory(chatdome_record_factory)


def _is_sentinel_record(record: logging.LogRecord) -> bool:
    return (
        getattr(record, "chatdome_origin", _log_origin.get()) == "sentinel"
        or record.name.startswith("chatdome.sentinel")
    )


class OriginFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "chatdome_origin"):
            record.chatdome_origin = _log_origin.get()
        return True


class ExcludeSentinelFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return not _is_sentinel_record(record)


class SentinelOnlyFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return _is_sentinel_record(record)


class ChatDomeFileHandler(RotatingFileHandler):
    """Rotating file handler that reopens files replaced by external rotation."""

    @staticmethod
    def _same_file(path_stat: os.stat_result, stream_stat: os.stat_result) -> bool:
        return (
            path_stat.st_dev == stream_stat.st_dev
            and path_stat.st_ino == stream_stat.st_ino
        )

    def _should_reopen(self) -> bool:
        if self.stream is None:
            return True
        try:
            path_stat = os.stat(self.baseFilename)
            stream_stat = os.fstat(self.stream.fileno())
        except (OSError, ValueError):
            return True
        return not self._same_file(path_stat, stream_stat)

    def _reopen_stream(self) -> None:
        Path(self.baseFilename).parent.mkdir(parents=True, exist_ok=True)
        if self.stream is not None:
            try:
                self.stream.flush()
            except (OSError, ValueError):
                pass
            try:
                self.stream.close()
            except (OSError, ValueError):
                pass
            self.stream = None
        if not self.delay:
            self.stream = self._open()

    def emit(self, record: logging.LogRecord) -> None:
        try:
            if self._should_reopen():
                self._reopen_stream()
            super().emit(record)
        except Exception:
            self.handleError(record)


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


def _build_file_handler(log_file: str, formatter: logging.Formatter) -> ChatDomeFileHandler:
    log_path = Path(log_file).expanduser()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    file_handler = ChatDomeFileHandler(
        log_path,
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    return file_handler

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
    _install_origin_record_factory()
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
        h.close()

    root_logger.addHandler(handler)

    file_formatter = ChatDomeFormatter(
        datefmt="%Y-%m-%d %H:%M:%S",
        use_colors=False,
    )

    log_file = os.environ.get("CHATDOME_LOG_FILE", "").strip()
    if log_file:
        file_handler = _build_file_handler(log_file, file_formatter)
        file_handler.addFilter(OriginFilter())
        file_handler.addFilter(ExcludeSentinelFilter())
        root_logger.addHandler(file_handler)

    sentinel_log_file = os.environ.get("CHATDOME_SENTINEL_LOG_FILE", "").strip()
    if sentinel_log_file:
        sentinel_handler = _build_file_handler(sentinel_log_file, file_formatter)
        sentinel_handler.addFilter(OriginFilter())
        sentinel_handler.addFilter(SentinelOnlyFilter())
        root_logger.addHandler(sentinel_handler)

    # Suppress noise from dependencies
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("openai").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("telegram").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)
