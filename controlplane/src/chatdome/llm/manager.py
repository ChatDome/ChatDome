"""Runtime manager for configured LLM profiles."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
from dataclasses import dataclass, replace
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
            env_name = self._api_key_env_name(profile)
            key = os.environ.get(env_name, "")
            if not key:
                raise LLMProfileNotReady(
                    f"LLM profile {profile_name!r} is not authenticated: "
                    f"environment variable {env_name} is not set."
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
        if profile.api_mode != "openai_api":
            return profile

        env_name = self._api_key_env_name(profile)
        key = os.environ.get(env_name, "")
        if not key:
            raise LLMProfileNotReady(
                f"LLM profile {profile_name!r} is not authenticated: "
                f"environment variable {env_name} is not set."
            )
        return replace(profile, api_key=key)

    @staticmethod
    def _api_key_env_name(profile: AIConfig) -> str:
        raw = str(profile.api_key or "").strip()
        if not raw.startswith("env:") or not raw[4:].strip():
            raise LLMProfileNotReady("api_key must use env:<ENV_NAME>.")
        return raw[4:].strip()

    @classmethod
    def _safe_key_ref(cls, profile: AIConfig) -> str | None:
        if profile.api_mode != "openai_api":
            return None
        try:
            env_name = cls._api_key_env_name(profile)
        except LLMProfileNotReady:
            return "invalid"
        if os.environ.get(env_name, ""):
            fingerprint = hashlib.sha256(os.environ[env_name].encode("utf-8")).hexdigest()[:8]
            return f"env:{env_name} loaded fp={fingerprint}"
        return f"env:{env_name} missing"

    @staticmethod
    def _profile_base_url(profile: AIConfig) -> str | None:
        if profile.api_mode == "codex_responses":
            return profile.codex_base_url
        return profile.base_url

    @classmethod
    def _profile_status(cls, profile: AIConfig) -> str:
        if profile.api_mode == "openai_api":
            try:
                env_name = cls._api_key_env_name(profile)
            except LLMProfileNotReady:
                return "invalid_key_ref"
            return "ready" if os.environ.get(env_name, "") else "missing_key"

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
