"""
Configuration loader.

Runtime configuration is loaded from YAML plus a small set of operational
environment variables. LLM credentials are referenced from YAML with
``api_key: "env:ENV_NAME"`` and resolved by LLMManager when a profile is used.

Environment variables:
  CHATDOME_BOT_TOKEN        - Telegram Bot token (required)
  CHATDOME_ALLOWED_CHAT_IDS - Comma-separated chat IDs (optional)
  CHATDOME_PENDING_APPROVAL_TIMEOUT - Pending approval timeout in seconds (optional)
  CHATDOME_PERSISTED_SESSION_TTL - Persisted session retention in seconds (optional)
  CHATDOME_SENTINEL_ALERT_RETENTION_DAYS - Sentinel alert log retention days (optional)
  CHATDOME_CONFIG           - Path to config.yaml (optional)
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
    """LLM profile connection settings."""
    provider: str = "openai"
    api_mode: str = "openai_api"
    base_url: str = "https://api.openai.com/v1"
    api_key: str = ""
    model: str = "gpt-4o"
    temperature: float = 0.1
    max_tokens: int = 2000
    codex_client_id: str = ""
    codex_token_file: str = ""
    codex_base_url: str = "https://chatgpt.com/backend-api/codex"


@dataclass
class AgentConfig:
    """Agent behavior settings."""
    allow_generated_commands: bool = True
    allow_unrestricted_commands: bool = True
    session_timeout: int = 600
    pending_approval_timeout: int = 86400
    persisted_session_ttl: int = 604800
    max_rounds_per_turn: int = 10
    max_history_tokens: int = 16000
    command_timeout: int = 10
    max_output_chars: int = 4000


@dataclass
class SentinelConfig:
    """Sentinel 7x24 security monitoring configuration."""
    enabled: bool = False
    alert_chat_ids: list[int] = field(default_factory=list)
    alert_retention_days: int = 30
    push_min_severity: int = 7
    builtin_packs: list[str] = field(default_factory=lambda: [
        "ssh_auth", "network", "system_resources", "processes_services", "logs",
    ])
    custom_packs_dir: str = ""
    global_rate_limit: int = 10
    global_rate_window: int = 300
    learning_rounds: int = 1
    aggregation_window: int = 10
    daily_report: bool = True
    daily_report_time: str = "09:00"
    ai_analysis_min_severity: int = 7
    checks: list[dict] = field(default_factory=list)


@dataclass
class ChatDomeConfig:
    """Root configuration object."""
    telegram: TelegramConfig = field(default_factory=TelegramConfig)
    active_ai_profile: str = ""
    ai_profiles: dict[str, AIConfig] = field(default_factory=dict)
    agent: AgentConfig = field(default_factory=AgentConfig)
    sentinel: SentinelConfig = field(default_factory=SentinelConfig)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

PROFILE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


def _dict_to_dataclass(cls, data: dict | None) -> Any:
    """Map a dict to a dataclass, ignoring unknown keys."""
    if data is None:
        return cls()
    if not isinstance(data, dict):
        raise ValueError(f"{cls.__name__} configuration must be a mapping.")
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


def _parse_bool_env(raw: str) -> bool:
    """Parse common truthy strings used in environment toggles."""
    return raw.lower() in ("true", "1", "yes", "on")


def _normalize_api_mode(raw: str) -> str:
    """Normalize public API mode aliases to internal adapter ids."""
    value = (raw or "openai_api").strip().lower().replace("-", "_")
    aliases = {
        "openai": "openai_api",
        "openai_api": "openai_api",
        "chat": "openai_api",
        "chat_completions": "openai_api",
        "chat_completion": "openai_api",
        "codex": "codex_responses",
        "codex_responses": "codex_responses",
        "codex_oauth": "codex_responses",
    }
    if value not in aliases:
        raise ValueError(
            "Unsupported AI API mode: "
            f"{raw!r}. Supported modes: openai_api, codex_responses."
        )
    return aliases[value]


def _validate_profile_name(name: str) -> str:
    value = str(name or "").strip()
    if not PROFILE_NAME_PATTERN.match(value):
        raise ValueError(
            f"Invalid AI profile name: {name!r}. Use 1-64 letters, numbers, '.', '_' or '-'."
        )
    return value


def _is_env_key_ref(raw: str) -> bool:
    value = str(raw or "").strip()
    return value.startswith("env:") and bool(value[4:].strip())


def _normalize_ai_profile(name: str, raw: dict[str, Any]) -> AIConfig:
    if not isinstance(raw, dict):
        raise ValueError(f"AI profile {name!r} must be a mapping.")

    profile = _dict_to_dataclass(AIConfig, raw)
    profile.provider = (profile.provider or "openai").strip().lower()
    profile.api_mode = _normalize_api_mode(profile.api_mode)

    if profile.provider in {"codex", "codex_cli", "openai-codex", "openai_codex"}:
        profile.provider = "codex"
        if profile.api_mode == "openai_api":
            profile.api_mode = "codex_responses"

    if profile.api_mode == "codex_responses":
        profile.provider = "codex"

    profile.api_key = str(profile.api_key or "").strip()
    if profile.api_key and not _is_env_key_ref(profile.api_key):
        raise ValueError(
            f"AI profile {name!r} api_key must use env:<ENV_NAME>; plaintext keys are not allowed."
        )

    if profile.api_mode == "openai_api" and not _is_env_key_ref(profile.api_key):
        raise ValueError(
            f"AI profile {name!r} requires api_key: \"env:<ENV_NAME>\"."
        )

    profile.base_url = str(profile.base_url or "https://api.openai.com/v1").strip()
    profile.model = str(profile.model or "gpt-4o").strip()
    profile.codex_client_id = str(profile.codex_client_id or "").strip()
    profile.codex_token_file = str(profile.codex_token_file or "").strip()
    profile.codex_base_url = str(
        profile.codex_base_url or "https://chatgpt.com/backend-api/codex"
    ).strip()
    return profile


def _load_ai_profiles(yaml_data: dict[str, Any]) -> tuple[str, dict[str, AIConfig]]:
    if "ai" in yaml_data:
        raise ValueError(
            "Legacy chatdome.ai is no longer supported. "
            "Use chatdome.active_ai_profile and chatdome.ai_profiles."
        )

    active = str(yaml_data.get("active_ai_profile") or "").strip()
    if not active:
        raise ValueError("chatdome.active_ai_profile is required.")

    raw_profiles = yaml_data.get("ai_profiles")
    if not isinstance(raw_profiles, dict) or not raw_profiles:
        raise ValueError("chatdome.ai_profiles must contain at least one profile.")

    profiles: dict[str, AIConfig] = {}
    for raw_name, raw_profile in raw_profiles.items():
        name = _validate_profile_name(str(raw_name))
        profiles[name] = _normalize_ai_profile(name, raw_profile)

    if active not in profiles:
        raise ValueError(
            f"chatdome.active_ai_profile {active!r} does not exist in chatdome.ai_profiles."
        )
    return active, profiles


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def load_config(config_path: str | Path | None = None) -> ChatDomeConfig:
    """
    Load ChatDome configuration.

    Config file lookup order:
      1. Explicit ``config_path`` argument
      2. ``CHATDOME_CONFIG`` environment variable
      3. ``./config.yaml`` in the current working directory
    """

    if config_path is None:
        config_path = os.environ.get("CHATDOME_CONFIG", "config.yaml")

    path = Path(config_path)
    yaml_data: dict[str, Any] = {}

    if path.is_file():
        logger.info("Loading configuration from %s", path.resolve())
        with open(path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
        if raw and "chatdome" in raw:
            yaml_data = raw["chatdome"] or {}
    else:
        logger.info(
            "No config file found at %s, using defaults + environment variables",
            path.resolve(),
        )

    if not isinstance(yaml_data, dict):
        raise ValueError("chatdome configuration must be a mapping.")

    active_ai_profile, ai_profiles = _load_ai_profiles(yaml_data)

    config = ChatDomeConfig(
        telegram=_dict_to_dataclass(TelegramConfig, yaml_data.get("telegram")),
        active_ai_profile=active_ai_profile,
        ai_profiles=ai_profiles,
        agent=_dict_to_dataclass(AgentConfig, yaml_data.get("agent")),
        sentinel=_dict_to_dataclass(SentinelConfig, yaml_data.get("sentinel")),
    )

    bot_token = os.environ.get("CHATDOME_BOT_TOKEN", "")
    if bot_token:
        config.telegram.bot_token = bot_token

    chat_ids_env = os.environ.get("CHATDOME_ALLOWED_CHAT_IDS", "")
    if chat_ids_env:
        config.telegram.allowed_chat_ids = _parse_chat_ids(chat_ids_env)

    allow_gen_env = os.environ.get("CHATDOME_ALLOW_GENERATED_COMMANDS", "")
    if allow_gen_env:
        config.agent.allow_generated_commands = _parse_bool_env(allow_gen_env)

    allow_unrestricted_env = os.environ.get("CHATDOME_ALLOW_UNRESTRICTED_COMMANDS", "")
    if allow_unrestricted_env:
        config.agent.allow_unrestricted_commands = _parse_bool_env(allow_unrestricted_env)

    pending_timeout_env = os.environ.get("CHATDOME_PENDING_APPROVAL_TIMEOUT", "")
    if pending_timeout_env:
        try:
            parsed_timeout = int(pending_timeout_env)
            if parsed_timeout > 0:
                config.agent.pending_approval_timeout = parsed_timeout
            else:
                logger.warning(
                    "CHATDOME_PENDING_APPROVAL_TIMEOUT must be > 0, ignored: %s",
                    pending_timeout_env,
                )
        except ValueError:
            logger.warning("Invalid CHATDOME_PENDING_APPROVAL_TIMEOUT ignored: %s", pending_timeout_env)

    persisted_ttl_env = os.environ.get("CHATDOME_PERSISTED_SESSION_TTL", "")
    if persisted_ttl_env:
        try:
            parsed_ttl = int(persisted_ttl_env)
            if parsed_ttl >= 0:
                config.agent.persisted_session_ttl = parsed_ttl
            else:
                logger.warning(
                    "CHATDOME_PERSISTED_SESSION_TTL must be >= 0, ignored: %s",
                    persisted_ttl_env,
                )
        except ValueError:
            logger.warning("Invalid CHATDOME_PERSISTED_SESSION_TTL ignored: %s", persisted_ttl_env)

    sentinel_enabled_env = os.environ.get("CHATDOME_SENTINEL_ENABLED", "")
    if sentinel_enabled_env:
        config.sentinel.enabled = _parse_bool_env(sentinel_enabled_env)

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

    if config.sentinel.enabled and not config.sentinel.checks:
        logger.warning(
            "Sentinel is enabled but no checks are configured. "
            "Define chatdome.sentinel.checks in config.yaml (copy config.example.yaml as a base), "
            "or provide CHATDOME_CONFIG pointing to that file.",
        )

    if not config.telegram.bot_token:
        raise ValueError(
            "Telegram Bot Token is not configured.\n"
            "Set the CHATDOME_BOT_TOKEN environment variable:\n"
            "  export CHATDOME_BOT_TOKEN=\"your-telegram-bot-token\""
        )

    active_profile = config.ai_profiles[config.active_ai_profile]
    logger.info(
        "Configuration loaded: active_ai_profile=%s, provider=%s, api_mode=%s, model=%s, profile_count=%d, allowed_chats=%s",
        config.active_ai_profile,
        active_profile.provider,
        active_profile.api_mode,
        active_profile.model,
        len(config.ai_profiles),
        config.telegram.allowed_chat_ids,
    )
    return config

