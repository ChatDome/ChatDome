"""Shared model-management command business service."""

from __future__ import annotations

import inspect
from typing import Any, Awaitable, Callable, Optional

from chatdome.errors import LLMProfileDeleteForbidden, LLMProfileNotFound
from chatdome.llm.profile_admin import (
    CreateOpenAIProfileRequest,
    LLMProfileAdminService,
    ProfileActor,
    ProfileMutationResult,
    ProfileSummary,
)
from chatdome.outbound.models import ModelProfileFacts, ModelProfilesFacts
from chatdome.slash_commands import CommandResult

RuntimeSync = Callable[[], Optional[Awaitable[None]]]


class ModelCommandService:
    """Execute every /model* mutation through one platform-neutral service."""

    def __init__(
        self,
        manager: Any,
        profile_admin: LLMProfileAdminService | None,
        *,
        runtime_sync: RuntimeSync | None = None,
    ) -> None:
        self.manager = manager
        self.profile_admin = profile_admin
        self.runtime_sync = runtime_sync

    def profile_facts(self) -> ModelProfilesFacts:
        if self.manager is None:
            return ModelProfilesFacts(active_profile="", profiles=())
        profiles = tuple(
            ModelProfileFacts(
                name=str(item.name),
                provider=str(item.provider),
                api_mode=str(item.api_mode),
                model=str(item.model),
                base_url=str(item.base_url or ""),
                status=str(item.status or ""),
                key_ref=str(item.key_ref or ""),
                active=bool(item.active),
            )
            for item in self.manager.list_profiles()
        )
        active = next((item.name for item in profiles if item.active), "")
        if not active:
            active = str(self.manager.get_active_profile_name() or "")
        return ModelProfilesFacts(active_profile=active, profiles=profiles)

    def list_profiles(self) -> CommandResult:
        facts = self.profile_facts()
        if self.manager is None:
            return CommandResult(
                outcome="unavailable",
                title="Model profiles",
                text="Model management is unavailable.",
                severity="error",
                facts=facts,
            )
        if not facts.profiles:
            return CommandResult(
                outcome="empty",
                title="Model profiles",
                text="No model is configured. Run /model_add.",
                facts=facts,
            )
        return CommandResult(
            outcome="model_profiles_listed",
            title="Model profiles",
            facts=facts,
        )

    async def switch(self, profile_name: str, actor: ProfileActor) -> CommandResult:
        if self.profile_admin is None:
            return self._unavailable()
        result = await self.profile_admin.set_active_profile(profile_name, actor)
        await self._sync_runtime()
        facts = self.profile_facts()
        selected = next(
            (profile for profile in facts.profiles if profile.name == result.profile_name),
            None,
        )
        detail = ""
        if selected is not None:
            detail = f"{selected.provider}/{selected.api_mode}, model={selected.model}"
        text = f"model switched: {result.profile_name}"
        if detail:
            text = f"{text}\n{detail}"
        return CommandResult(
            outcome="model_switched",
            event_summary=f"????? model profile {result.profile_name}?",
            title="Model switched",
            text=text,
            facts=selected or facts,
        )

    async def create_openai(
        self,
        request: CreateOpenAIProfileRequest,
        actor: ProfileActor,
    ) -> CommandResult:
        if self.profile_admin is None:
            return self._unavailable()
        result = await self.profile_admin.create_openai(request, actor)
        await self._sync_runtime()
        return self._mutation_result(result, outcome="model_added")

    async def inspect_delete(self, profile_name: str) -> ProfileSummary:
        if self.profile_admin is None:
            raise LLMProfileNotFound("Model management service is unavailable.")
        summary = await self.profile_admin.get_profile_summary(profile_name)
        if summary is None:
            raise LLMProfileNotFound(f"Unknown model profile: {profile_name}")
        if summary.active:
            raise LLMProfileDeleteForbidden(
                f"Cannot delete active model profile: {profile_name}",
                user_message="???? model????? profile?",
            )
        return summary

    async def delete(self, profile_name: str, actor: ProfileActor) -> CommandResult:
        if self.profile_admin is None:
            return self._unavailable()
        result = await self.profile_admin.delete_profile(profile_name, actor)
        await self._sync_runtime()
        return self._mutation_result(result, outcome="model_deleted")

    @staticmethod
    def cancel(cancelled: bool) -> CommandResult:
        if cancelled:
            return CommandResult(
                outcome="model_operation_cancelled",
                title="Model operation",
                text="Model operation cancelled.",
            )
        return CommandResult(
            outcome="no_pending_operation",
            title="Model operation",
            text="No pending model operation.",
        )

    async def _sync_runtime(self) -> None:
        if self.runtime_sync is None:
            return
        result = self.runtime_sync()
        if inspect.isawaitable(result):
            await result

    @staticmethod
    def _mutation_result(
        result: ProfileMutationResult,
        *,
        outcome: str,
    ) -> CommandResult:
        action_labels = {
            "created": "added",
            "updated": "updated",
            "deleted": "deleted",
        }
        action = action_labels.get(result.action, result.action)
        return CommandResult(
            outcome=outcome,
            event_summary=f"??{action}? model profile {result.profile_name}?",
            title="Model profile",
            text=f"Model profile {action}: {result.profile_name}",
        )

    @staticmethod
    def _unavailable() -> CommandResult:
        return CommandResult(
            outcome="unavailable",
            title="Model management",
            text="Model management is unavailable.",
            severity="error",
        )
