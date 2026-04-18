"""
ChatDome Logger — Custom ANSI colored logging for enhanced terminal readability.

Implements high-visibility visual hierarchy by positioning module tags at the front
and color-coding logs based on severity and source.
"""

import logging
import sys
from typing import Optional


class ChatDomeFormatter(logging.Formatter):
    """
    Custom log formatter that strips 'chatdome.' prefix and applies ANSI colors.
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
        timestamp_part = f"{time_color}{timestamp}{self.RESET}"
        
        level_name = record.levelname
        level_part = f"{level_color}[{level_name:5s}]{self.RESET}"
        
        component_part = f"{component_color}[{name}]{self.RESET}"
        
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
            formatted += f"{self.RED}{record.exc_text}{self.RESET}"
        if record.stack_info:
            if formatted[-1:] != "\n":
                formatted += "\n"
            formatted += self.formatStack(record.stack_info)
            
        return formatted


def setup_logging(level: int = logging.INFO) -> None:
    """Configures the global logging system with ChatDome aesthetics."""
    handler = logging.StreamHandler(sys.stdout)
    formatter = ChatDomeFormatter(datefmt="%Y-%m-%d %H:%M:%S")
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
