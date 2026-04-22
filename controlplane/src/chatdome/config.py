"""
Configuration loader.

Sensitive parameters (bot_token, api_key) are loaded EXCLUSIVELY from
environment variables — they must never be stored in local files.

Non-sensitive parameters (model, timeout, etc.) are loaded from a YAML
config file with optional environment variable override support.

Environment variables:
  CHATDOME_BOT_TOKEN        — Telegram Bot token  (required)
  CHATDOME_AI_API_KEY       — LLM API key         (required)
  CHATDOME_AI_BASE_URL      – LLM API base URL    (optional)
  CHATDOME_ALLOWED_CHAT_IDS – Comma-separated chat IDs (optional)
  CHATDOME_PENDING_APPROVAL_TIMEOUT – Pending approval timeout in seconds (optional)
  CHATDOME_PERSISTED_SESSION_TTL – Persisted session retention in seconds (optional)
  CHATDOME_SENTINEL_ALERT_RETENTION_DAYS – Sentinel alert log retention days (optional)
  CHATDOME_CONFIG           – Path to config.yaml (optional)
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
    allow_unrestricted_commands: bool = False
    session_timeout: int = 600          # seconds
    pending_approval_timeout: int = 86400  # seconds
    persisted_session_ttl: int = 604800  # seconds (7 days)
    max_rounds_per_turn: int = 10
    max_history_tokens: int = 16000
    command_timeout: int = 10           # seconds
    max_output_chars: int = 4000


@dataclass
class SentinelConfig:
    """Sentinel 7×24 security monitoring configuration."""
    enabled: bool = False
    alert_chat_ids: list[int] = field(default_factory=list)
    alert_retention_days: int = 30                              # sentinel_alerts.jsonl retention window
    push_min_severity: int = 7                                  # ≥ 7 (high) pushes to Telegram
    builtin_packs: list[str] = field(default_factory=lambda: [
        "ssh_auth", "network", "system_resources", "processes_services", "logs",
    ])
    custom_packs_dir: str = ""
    global_rate_limit: int = 10                                 # max pushes per window
    global_rate_window: int = 300                               # rate window (seconds)
    learning_rounds: int = 1                                    # cold-start silent rounds
    aggregation_window: int = 10                                # Phase 2
    daily_report: bool = True
    daily_report_time: str = "09:00"                            # UTC
    ai_analysis_min_severity: int = 7
    checks: list[dict] = field(default_factory=list)


@dataclass
class ChatDomeConfig:
    """Root configuration object."""
    telegram: TelegramConfig = field(default_factory=TelegramConfig)
    ai: AIConfig = field(default_factory=AIConfig)
    agent: AgentConfig = field(default_factory=AgentConfig)
    sentinel: SentinelConfig = field(default_factory=SentinelConfig)


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
        sentinel=_dict_to_dataclass(SentinelConfig, yaml_data.get("sentinel")),
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

    # Optional: AI Model
    model = os.environ.get("CHATDOME_AI_MODEL", "")
    if model:
        config.ai.model = model

    # Optional: Allowed Chat IDs (comma-separated)
    chat_ids_env = os.environ.get("CHATDOME_ALLOWED_CHAT_IDS", "")
    if chat_ids_env:
        config.telegram.allowed_chat_ids = _parse_chat_ids(chat_ids_env)
        
    # Optional: Allow Generated Commands
    allow_gen_env = os.environ.get("CHATDOME_ALLOW_GENERATED_COMMANDS", "")
    if allow_gen_env:
        config.agent.allow_generated_commands = allow_gen_env.lower() in ("true", "1", "yes", "on")

    # Optional: Allow Unrestricted Commands (bypasses ALL validation)
    allow_unrestricted_env = os.environ.get("CHATDOME_ALLOW_UNRESTRICTED_COMMANDS", "")
    if allow_unrestricted_env:
        config.agent.allow_unrestricted_commands = allow_unrestricted_env.lower() in ("true", "1", "yes", "on")

    # Optional: Pending Approval Timeout (seconds)
    pending_timeout_env = os.environ.get("CHATDOME_PENDING_APPROVAL_TIMEOUT", "")
    if pending_timeout_env:
        try:
            parsed_timeout = int(pending_timeout_env)
            if parsed_timeout > 0:
                config.agent.pending_approval_timeout = parsed_timeout
            else:
                logger.warning("CHATDOME_PENDING_APPROVAL_TIMEOUT must be > 0, ignored: %s", pending_timeout_env)
        except ValueError:
            logger.warning("Invalid CHATDOME_PENDING_APPROVAL_TIMEOUT ignored: %s", pending_timeout_env)

    # Optional: Persisted Session TTL (seconds)
    persisted_ttl_env = os.environ.get("CHATDOME_PERSISTED_SESSION_TTL", "")
    if persisted_ttl_env:
        try:
            parsed_ttl = int(persisted_ttl_env)
            if parsed_ttl >= 0:
                config.agent.persisted_session_ttl = parsed_ttl
            else:
                logger.warning("CHATDOME_PERSISTED_SESSION_TTL must be >= 0, ignored: %s", persisted_ttl_env)
        except ValueError:
            logger.warning("Invalid CHATDOME_PERSISTED_SESSION_TTL ignored: %s", persisted_ttl_env)

    # Optional: Sentinel Enable Toggle
    sentinel_enabled_env = os.environ.get("CHATDOME_SENTINEL_ENABLED", "")
    if sentinel_enabled_env:
        config.sentinel.enabled = sentinel_enabled_env.lower() in ("true", "1", "yes", "on")

    # Optional: Sentinel alert retention days
    sentinel_retention_env = os.environ.get("CHATDOME_SENTINEL_ALERT_RETENTION_DAYS", "")
    if sentinel_retention_env:
        try:
            parsed_days = int(sentinel_retention_env)
            if parsed_days > 0:
                config.sentinel.alert_retention_days = parsed_days
            else:
                logger.warning(
                    "CHATDOME_SENTINEL_ALERT_RETENTION_DAYS must be > 0, ignored: %s",
                    sentinel_retention_env,
                )
        except ValueError:
            logger.warning(
                "Invalid CHATDOME_SENTINEL_ALERT_RETENTION_DAYS ignored: %s",
                sentinel_retention_env,
            )

    # Actionable guardrail: enabled sentinel without checks is a no-op.
    if config.sentinel.enabled and not config.sentinel.checks:
        logger.warning(
            "Sentinel is enabled but no checks are configured. "
            "Define chatdome.sentinel.checks in config.yaml (copy config.example.yaml as a base), "
            "or provide CHATDOME_CONFIG pointing to that file.",
        )

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
