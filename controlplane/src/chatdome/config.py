"""
YAML configuration loader with environment variable substitution.

Config lookup order:
  1. --config CLI argument
  2. CHATDOME_CONFIG environment variable
  3. ./config.yaml (current working directory)
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pattern to match ${ENV_VAR} references in config values
# ---------------------------------------------------------------------------
_ENV_VAR_PATTERN = re.compile(r"\$\{([^}]+)\}")


def _resolve_env_vars(value: Any) -> Any:
    """Recursively resolve ${VAR} references in config values."""
    if isinstance(value, str):
        def _replacer(match: re.Match) -> str:
            var_name = match.group(1)
            env_val = os.environ.get(var_name)
            if env_val is None:
                logger.warning("Environment variable %s is not set", var_name)
                return match.group(0)  # leave as-is
            return env_val
        return _ENV_VAR_PATTERN.sub(_replacer, value)
    if isinstance(value, dict):
        return {k: _resolve_env_vars(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve_env_vars(item) for item in value]
    return value


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
# Loader
# ---------------------------------------------------------------------------

def _dict_to_dataclass(cls, data: dict) -> Any:
    """Map a dict to a dataclass, ignoring unknown keys."""
    if data is None:
        return cls()
    field_names = {f.name for f in cls.__dataclass_fields__.values()}
    filtered = {k: v for k, v in data.items() if k in field_names}
    return cls(**filtered)


def load_config(config_path: str | Path | None = None) -> ChatDomeConfig:
    """
    Load ChatDome configuration from a YAML file.

    Lookup order:
      1. Explicit ``config_path`` argument
      2. ``CHATDOME_CONFIG`` environment variable
      3. ``./config.yaml`` in the current working directory
    """
    if config_path is None:
        config_path = os.environ.get("CHATDOME_CONFIG", "config.yaml")

    path = Path(config_path)
    if not path.is_file():
        raise FileNotFoundError(
            f"Configuration file not found: {path.resolve()}\n"
            "Create one by copying config.example.yaml → config.yaml"
        )

    logger.info("Loading configuration from %s", path.resolve())

    with open(path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)

    if not raw or "chatdome" not in raw:
        raise ValueError("Invalid configuration: missing top-level 'chatdome' key")

    # Resolve environment variable references
    resolved = _resolve_env_vars(raw["chatdome"])

    config = ChatDomeConfig(
        telegram=_dict_to_dataclass(TelegramConfig, resolved.get("telegram")),
        ai=_dict_to_dataclass(AIConfig, resolved.get("ai")),
        agent=_dict_to_dataclass(AgentConfig, resolved.get("agent")),
    )

    # Validation
    if not config.telegram.bot_token or config.telegram.bot_token.startswith("${"):
        raise ValueError(
            "Telegram bot_token is not configured. "
            "Set CHATDOME_BOT_TOKEN or edit config.yaml."
        )
    if not config.ai.api_key or config.ai.api_key.startswith("${"):
        raise ValueError(
            "AI api_key is not configured. "
            "Set CHATDOME_AI_API_KEY or edit config.yaml."
        )

    logger.info("Configuration loaded: model=%s, allowed_chats=%s",
                config.ai.model, config.telegram.allowed_chat_ids)
    return config
