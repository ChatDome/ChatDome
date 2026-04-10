"""
Configuration loader.

Sensitive parameters (bot_token, api_key) are loaded EXCLUSIVELY from
environment variables — they must never be stored in local files.

Non-sensitive parameters (model, timeout, etc.) are loaded from a YAML
config file with optional environment variable override support.

Environment variables:
  CHATDOME_BOT_TOKEN        — Telegram Bot token  (required)
  CHATDOME_AI_API_KEY       — LLM API key         (required)
  CHATDOME_AI_BASE_URL      — LLM API base URL    (optional)
  CHATDOME_ALLOWED_CHAT_IDS — Comma-separated chat IDs (optional)
  CHATDOME_CONFIG           — Path to config.yaml (optional)
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration dataclasses
# ---------------------------------------------------------------------------

@dataclass
class TelegramConfig:
    """Telegram bot connection settings."""
    bot_token: str = ""
    allowed_chat_ids: list[int] = field(default_factory=list)
    max_message_length: int = 4000


@dataclass
class AIConfig:
    """LLM API connection settings."""
    base_url: str = "https://api.openai.com/v1"
    api_key: str = ""
    model: str = "gpt-4o"
    temperature: float = 0.1
    max_tokens: int = 2000


@dataclass
class AgentConfig:
    """Agent behavior settings."""
    allow_generated_commands: bool = False
    session_timeout: int = 600          # seconds
    max_rounds_per_turn: int = 10
    max_history_tokens: int = 16000
    command_timeout: int = 10           # seconds
    max_output_chars: int = 4000


@dataclass
class ChatDomeConfig:
    """Root configuration object."""
    telegram: TelegramConfig = field(default_factory=TelegramConfig)
    ai: AIConfig = field(default_factory=AIConfig)
    agent: AgentConfig = field(default_factory=AgentConfig)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _dict_to_dataclass(cls, data: dict) -> Any:
    """Map a dict to a dataclass, ignoring unknown keys."""
    if data is None:
        return cls()
    field_names = {f.name for f in cls.__dataclass_fields__.values()}
    filtered = {k: v for k, v in data.items() if k in field_names}
    return cls(**filtered)


def _parse_chat_ids(raw: str) -> list[int]:
    """Parse a comma-separated string of chat IDs into a list of ints."""
    ids = []
    for part in raw.split(","):
        part = part.strip()
        if part:
            try:
                ids.append(int(part))
            except ValueError:
                logger.warning("Invalid chat ID ignored: %s", part)
    return ids


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def load_config(config_path: str | Path | None = None) -> ChatDomeConfig:
    """
    Load ChatDome configuration.

    Sensitive parameters are read from environment variables ONLY.
    Non-sensitive parameters are read from a YAML config file.

    Config file lookup order:
      1. Explicit ``config_path`` argument
      2. ``CHATDOME_CONFIG`` environment variable
      3. ``./config.yaml`` in the current working directory

    If no config file is found, default values are used for all
    non-sensitive parameters.
    """

    # ── Load YAML config (non-sensitive settings) ──
    if config_path is None:
        config_path = os.environ.get("CHATDOME_CONFIG", "config.yaml")

    path = Path(config_path)
    yaml_data: dict = {}

    if path.is_file():
        logger.info("Loading configuration from %s", path.resolve())
        with open(path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
        if raw and "chatdome" in raw:
            yaml_data = raw["chatdome"]
    else:
        logger.info(
            "No config file found at %s, using defaults + environment variables",
            path.resolve(),
        )

    # Build config from YAML (non-sensitive fields only)
    config = ChatDomeConfig(
        telegram=_dict_to_dataclass(TelegramConfig, yaml_data.get("telegram")),
        ai=_dict_to_dataclass(AIConfig, yaml_data.get("ai")),
        agent=_dict_to_dataclass(AgentConfig, yaml_data.get("agent")),
    )

    # ── Override with environment variables (sensitive + optional) ──

    # Required: Telegram Bot Token
    bot_token = os.environ.get("CHATDOME_BOT_TOKEN", "")
    if bot_token:
        config.telegram.bot_token = bot_token

    # Required: AI API Key
    api_key = os.environ.get("CHATDOME_AI_API_KEY", "")
    if api_key:
        config.ai.api_key = api_key

    # Optional: AI Base URL
    base_url = os.environ.get("CHATDOME_AI_BASE_URL", "")
    if base_url:
        config.ai.base_url = base_url

    # Optional: Allowed Chat IDs (comma-separated)
    chat_ids_env = os.environ.get("CHATDOME_ALLOWED_CHAT_IDS", "")
    if chat_ids_env:
        config.telegram.allowed_chat_ids = _parse_chat_ids(chat_ids_env)

    # ── Validation ──

    if not config.telegram.bot_token:
        raise ValueError(
            "Telegram Bot Token is not configured.\n"
            "Set the CHATDOME_BOT_TOKEN environment variable:\n"
            "  export CHATDOME_BOT_TOKEN=\"your-telegram-bot-token\""
        )

    if not config.ai.api_key:
        raise ValueError(
            "AI API Key is not configured.\n"
            "Set the CHATDOME_AI_API_KEY environment variable:\n"
            "  export CHATDOME_AI_API_KEY=\"your-api-key\""
        )

    logger.info("Configuration loaded: model=%s, allowed_chats=%s",
                config.ai.model, config.telegram.allowed_chat_ids)
    return config
