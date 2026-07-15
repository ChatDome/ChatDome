"""Shared Codex OAuth business workflow for command surfaces."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Callable

from chatdome.config import AIConfig, ChatDomeConfig, validate_profile_name
from chatdome.errors import LLMProfileNotFound, LLMProfileNotReady
from chatdome.llm.codex_auth import CodexOAuth, default_token_file_config_for_profile
from chatdome.llm.profile_admin import (
    CreateCodexProfileRequest,
    LLMProfileAdminService,
    ProfileActor,
    ProfileMutationResult,
)
from chatdome.outbound.models import CodexAuthorizationFacts

OAuthFactory = Callable[..., Any]


@dataclass
class CodexOAuthSession:
    oauth: Any
    profile_name: str
    profile: AIConfig
    actor: ProfileActor
    authorization: CodexAuthorizationFacts
    device_code: str
    interval: int
    persist_profile: bool
    overwrite_existing: bool
    expected_profile_fingerprint: str | None


class CodexOAuthService:
    """Resolve, authorize, exchange, and persist a Codex profile."""

    def __init__(
        self,
        profile_admin: LLMProfileAdminService | None,
        *,
        oauth_factory: OAuthFactory = CodexOAuth,
    ) -> None:
        self.profile_admin = profile_admin
        self.oauth_factory = oauth_factory

    @staticmethod
    def default_profile(profile_name: str) -> AIConfig:
        name = validate_profile_name(profile_name)
        return AIConfig(
            provider="codex",
            api_mode="codex_responses",
            model="gpt-5.5",
            temperature=0.1,
            max_tokens=2000,
            codex_client_id="",
            codex_token_file=default_token_file_config_for_profile(name),
            codex_base_url="https://chatgpt.com/backend-api/codex",
        )

    @staticmethod
    def _with_token_file(profile_name: str, profile: AIConfig) -> tuple[AIConfig, bool]:
        if str(profile.codex_token_file or "").strip():
            return profile, False
        return (
            replace(
                profile,
                codex_token_file=default_token_file_config_for_profile(profile_name),
            ),
            True,
        )

    def resolve_profile(
        self,
        config: ChatDomeConfig,
        requested_profile: str = "",
        *,
        active_profile: str = "",
    ) -> tuple[str, AIConfig, bool]:
        profiles = config.ai_profiles
        requested = str(requested_profile or "").strip()
        if requested:
            try:
                name = validate_profile_name(requested)
            except ValueError as exc:
                raise LLMProfileNotFound(f"Unknown model profile: {requested}") from exc
            profile = profiles.get(name)
            if profile is None:
                return name, self.default_profile(name), True
            if profile.api_mode != "codex_responses":
                raise LLMProfileNotReady(
                    f"Model profile {name} is not configured for Codex OAuth."
                )
            login_profile, changed = self._with_token_file(name, profile)
            return name, login_profile, changed

        active_name = str(active_profile or config.active_ai_profile or "").strip()
        active = profiles.get(active_name)
        if active is not None and active.api_mode == "codex_responses":
            login_profile, changed = self._with_token_file(active_name, active)
            return active_name, login_profile, changed

        codex_profiles = [
            (name, profile)
            for name, profile in profiles.items()
            if profile.api_mode == "codex_responses"
        ]
        if len(codex_profiles) == 1:
            name, profile = codex_profiles[0]
            login_profile, changed = self._with_token_file(name, profile)
            return name, login_profile, changed
        if not codex_profiles:
            return "codex", self.default_profile("codex"), True

        names = ", ".join(name for name, _ in codex_profiles)
        raise LLMProfileNotReady(
            "Specify a Codex profile with /codex_login <profile>. "
            f"Available profiles: {names}"
        )

    async def begin(
        self,
        config: ChatDomeConfig,
        actor: ProfileActor,
        *,
        requested_profile: str = "",
        active_profile: str = "",
        forced_profile: AIConfig | None = None,
        overwrite_existing: bool | None = None,
        expected_profile_fingerprint: str | None = None,
    ) -> CodexOAuthSession:
        if forced_profile is not None:
            profile_name = validate_profile_name(requested_profile)
            profile, _ = self._with_token_file(profile_name, forced_profile)
            persist_profile = True
        else:
            profile_name, profile, persist_profile = self.resolve_profile(
                config,
                requested_profile,
                active_profile=active_profile,
            )

        summary = None
        if persist_profile:
            if self.profile_admin is None:
                raise LLMProfileNotReady("Model management service is unavailable.")
            summary = await self.profile_admin.get_profile_summary(profile_name)
        if overwrite_existing is None:
            overwrite_existing = summary is not None
        if expected_profile_fingerprint is None and summary is not None:
            expected_profile_fingerprint = summary.fingerprint

        oauth = self.oauth_factory(
            client_id=profile.codex_client_id or None,
            token_file=profile.codex_token_file or None,
        )
        device_info = await oauth.request_device_code()
        expires_in = int(device_info.get("expires_in") or 300)
        authorization = CodexAuthorizationFacts(
            profile_name=profile_name,
            verification_uri=str(
                device_info.get("verification_uri")
                or "https://auth.openai.com/codex/device"
            ),
            user_code=str(device_info["user_code"]),
            expires_in=expires_in,
        )
        return CodexOAuthSession(
            oauth=oauth,
            profile_name=profile_name,
            profile=profile,
            actor=actor,
            authorization=authorization,
            device_code=str(device_info["device_code"]),
            interval=int(device_info.get("interval") or 5),
            persist_profile=persist_profile,
            overwrite_existing=bool(overwrite_existing),
            expected_profile_fingerprint=expected_profile_fingerprint,
        )

    async def complete(
        self,
        session: CodexOAuthSession,
    ) -> ProfileMutationResult | None:
        code, code_verifier = await session.oauth.poll_device_token(
            device_code=session.device_code,
            user_code=session.authorization.user_code,
            interval=session.interval,
            timeout=session.authorization.expires_in,
        )
        await session.oauth.exchange_token(code, code_verifier)
        if not session.persist_profile:
            return None
        if self.profile_admin is None:
            raise LLMProfileNotReady("Model management service is unavailable.")

        profile = session.profile
        return await self.profile_admin.create_codex(
            CreateCodexProfileRequest(
                name=session.profile_name,
                model=profile.model,
                client_id=profile.codex_client_id,
                token_file=profile.codex_token_file,
                base_url=profile.codex_base_url,
                temperature=profile.temperature,
                max_tokens=profile.max_tokens,
                overwrite_existing=session.overwrite_existing,
                expected_profile_fingerprint=session.expected_profile_fingerprint,
            ),
            session.actor,
        )
