"""Runtime manager for configured LLM profiles."""

from __future__ import annotations

import asyncio
import hashlib
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from chatdome.config import AIConfig
from chatdome.errors import LLMProfileError, LLMProfileNotFound, LLMProfileNotReady
from chatdome.llm import create_llm_client
from chatdome.llm.codex_auth import CodexOAuth, NotAuthenticatedError

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class LLMProfileInfo:
    """Safe profile information for status output."""

    name: str
    provider: str
    api_mode: str
    model: str
    base_url: str | None = None
    key_ref: str | None = None
    status: str = "unknown"
    active: bool = False


@dataclass(frozen=True)
class LLMSnapshot:
    """One-run snapshot binding a profile name to a concrete client."""

    profile_name: str
    client: Any
    profile: AIConfig


class LLMManager:
    """Manage LLM profiles, active profile selection, and client caching."""

    def __init__(self, profiles: dict[str, AIConfig], active_profile: str) -> None:
        if not profiles:
            raise LLMProfileError("LLMManager requires at least one AI profile.")
        if active_profile not in profiles:
            raise LLMProfileNotFound(f"Active AI profile does not exist: {active_profile}")

        self._profiles = dict(profiles)
        self._active_profile = active_profile
        self._clients: dict[str, Any] = {}
        self._lock: asyncio.Lock | None = None
        self._lock_loop: asyncio.AbstractEventLoop | None = None

    def _get_lock(self) -> asyncio.Lock:
        loop = asyncio.get_running_loop()
        if self._lock is None or self._lock_loop is not loop:
            self._lock = asyncio.Lock()
            self._lock_loop = loop
        return self._lock

    @property
    def profiles(self) -> dict[str, AIConfig]:
        """Return the configured profiles mapping."""
        return self._profiles

    def get_active_profile_name(self) -> str:
        """Return the active profile name."""
        return self._active_profile

    def get_profile_config(self, profile_name: str) -> AIConfig:
        """Return a configured profile or raise a not-found error."""
        if profile_name not in self._profiles:
            raise LLMProfileNotFound(f"Unknown LLM profile: {profile_name}")
        return self._profiles[profile_name]

    def list_profiles(self) -> list[LLMProfileInfo]:
        """Return safe profile status data without exposing secrets."""
        items: list[LLMProfileInfo] = []
        for name in sorted(self._profiles):
            profile = self._profiles[name]
            key_ref = self._safe_key_ref(profile)
            items.append(
                LLMProfileInfo(
                    name=name,
                    provider=profile.provider,
                    api_mode=profile.api_mode,
                    model=profile.model,
                    base_url=self._profile_base_url(profile),
                    key_ref=key_ref,
                    status=self._profile_status(profile),
                    active=name == self._active_profile,
                )
            )
        return items

    async def get_active_snapshot(self) -> LLMSnapshot:
        """Return a validated snapshot of the current active profile."""
        async with self._get_lock():
            profile_name = self._active_profile
            client = await self._get_client_locked(profile_name, validate=True)
            return LLMSnapshot(
                profile_name=profile_name,
                client=client,
                profile=self._profiles[profile_name],
            )

    async def reload_profiles(self, profiles: dict[str, AIConfig], active_profile: str) -> None:
        """
        Replace the profile pool and clear cached clients.

        This is used by the local management menu hot-reload path. It validates
        only the configuration shape; authentication is still checked lazily when
        a profile is used or selected.
        """
        if not profiles:
            raise LLMProfileError("LLMManager requires at least one AI profile.")
        if active_profile not in profiles:
            raise LLMProfileNotFound(f"Active AI profile does not exist: {active_profile}")

        async with self._get_lock():
            old_profile = self._active_profile
            self._profiles = dict(profiles)
            self._active_profile = active_profile
            self._clients.clear()
            logger.info(
                "LLM profiles reloaded: active=%s -> %s, profile_count=%d",
                old_profile,
                active_profile,
                len(self._profiles),
            )

    async def switch_profile(self, profile_name: str) -> LLMSnapshot:
        """
        Switch the active profile after validating the target.

        The active profile is updated only after authentication and client
        creation succeed.
        """
        async with self._get_lock():
            if profile_name not in self._profiles:
                raise LLMProfileNotFound(f"Unknown LLM profile: {profile_name}")

            old_profile = self._active_profile
            client = await self._get_client_locked(profile_name, validate=True)
            self._active_profile = profile_name
            logger.info("LLM profile switched: %s -> %s", old_profile, profile_name)
            return LLMSnapshot(
                profile_name=profile_name,
                client=client,
                profile=self._profiles[profile_name],
            )

    async def get_client(self, profile_name: str) -> Any:
        """Return a validated cached client for the given profile."""
        async with self._get_lock():
            return await self._get_client_locked(profile_name, validate=True)

    async def validate_profile_ready(self, profile_name: str) -> None:
        """Validate that a profile can be used without changing active state."""
        if profile_name not in self._profiles:
            raise LLMProfileNotFound(f"Unknown LLM profile: {profile_name}")
        await self._validate_profile_ready(profile_name, self._profiles[profile_name])

    async def _get_client_locked(self, profile_name: str, *, validate: bool) -> Any:
        if profile_name not in self._profiles:
            raise LLMProfileNotFound(f"Unknown LLM profile: {profile_name}")

        profile = self._profiles[profile_name]
        if validate:
            await self._validate_profile_ready(profile_name, profile)

        if profile_name not in self._clients:
            resolved = self._resolved_profile_for_client(profile_name, profile)
            self._clients[profile_name] = create_llm_client(resolved)
            logger.info(
                "LLM client created: profile=%s provider=%s api_mode=%s model=%s",
                profile_name,
                profile.provider,
                profile.api_mode,
                profile.model,
            )
        return self._clients[profile_name]

    async def _validate_profile_ready(self, profile_name: str, profile: AIConfig) -> None:
        if profile.api_mode == "openai_api":
            if not str(profile.api_key or "").strip():
                raise LLMProfileNotReady(
                    f"LLM profile {profile_name!r} is not authenticated: "
                    "api_key is not configured in config.yaml."
                )
            return

        if profile.api_mode == "codex_responses":
            oauth = CodexOAuth(
                client_id=profile.codex_client_id or None,
                token_file=profile.codex_token_file or None,
            )
            try:
                await oauth.ensure_valid_token()
            except NotAuthenticatedError as e:
                raise LLMProfileNotReady(
                    f"LLM profile {profile_name!r} is not authenticated. "
                    "Run /codex_login before switching to it."
                ) from e
            return

        raise LLMProfileNotReady(
            f"LLM profile {profile_name!r} uses unsupported api_mode: {profile.api_mode}"
        )

    def _resolved_profile_for_client(self, profile_name: str, profile: AIConfig) -> AIConfig:
        if profile.api_mode == "openai_api" and not str(profile.api_key or "").strip():
            raise LLMProfileNotReady(
                f"LLM profile {profile_name!r} is not authenticated: "
                "api_key is not configured in config.yaml."
            )
        return profile

    @classmethod
    def _safe_key_ref(cls, profile: AIConfig) -> str | None:
        if profile.api_mode != "openai_api":
            return None
        key = str(profile.api_key or "").strip()
        if not key:
            return "missing"
        if key.startswith("env:"):
            return "deprecated env: reference"
        fingerprint = hashlib.sha256(key.encode("utf-8")).hexdigest()[:8]
        return f"configured fp={fingerprint}"

    @staticmethod
    def _profile_base_url(profile: AIConfig) -> str | None:
        if profile.api_mode == "codex_responses":
            return profile.codex_base_url
        return profile.base_url

    @classmethod
    def _profile_status(cls, profile: AIConfig) -> str:
        if profile.api_mode == "openai_api":
            key = str(profile.api_key or "").strip()
            if key.startswith("env:"):
                return "invalid_key_ref"
            return "ready" if key else "missing_key"

        if profile.api_mode == "codex_responses":
            token_file = (
                Path(profile.codex_token_file).expanduser()
                if profile.codex_token_file
                else Path.home() / ".chatdome" / "auth.json"
            )
            return "token_file_present" if token_file.is_file() else "not_authenticated"

        return "unsupported"


__all__ = [
    "LLMManager",
    "LLMProfileError",
    "LLMProfileInfo",
    "LLMProfileNotFound",
    "LLMProfileNotReady",
    "LLMSnapshot",
]
