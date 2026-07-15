from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

from chatdome.config import AIConfig, ChatDomeConfig
from chatdome.llm.codex_oauth_service import CodexOAuthService
from chatdome.llm.profile_admin import ProfileActor, ProfileMutationResult
from chatdome.model_commands import ModelCommandService
from chatdome.outbound.builders import EnvironmentFactsBuilder
from chatdome.outbound.models import EnvironmentFacts, OutboundMessageKind
from chatdome.slash_commands import (
    CommandContext,
    CommandDef,
    CommandRegistry,
    CommandResult,
)


class FakeOAuth:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.poll_args = None
        self.exchanged = None

    async def request_device_code(self):
        return {
            "device_code": "device",
            "user_code": "CODE-123",
            "verification_uri": "https://example.test/device",
            "interval": 1,
            "expires_in": 600,
        }

    async def poll_device_token(self, **kwargs):
        self.poll_args = kwargs
        return "authorization-code", "verifier"

    async def exchange_token(self, code, verifier):
        self.exchanged = (code, verifier)


class FakeProfileAdmin:
    def __init__(self):
        self.created_codex = []
        self.switched = []
        self.deleted = []

    async def get_profile_summary(self, _name):
        return None

    async def create_codex(self, request, actor):
        self.created_codex.append((request, actor))
        return ProfileMutationResult("created", request.name, request.name, 1)

    async def set_active_profile(self, name, actor):
        self.switched.append((name, actor))
        return ProfileMutationResult("switched", name, name, 2)

    async def delete_profile(self, name, actor):
        self.deleted.append((name, actor))
        return ProfileMutationResult("deleted", name, "base", 1)


class FakeManager:
    def __init__(self):
        self.active = "base"

    def get_active_profile_name(self):
        return self.active

    def list_profiles(self):
        return [
            SimpleNamespace(
                name="base",
                provider="openai",
                api_mode="openai_api",
                model="gpt-4o",
                base_url="https://api.openai.com/v1",
                status="ready",
                key_ref="configured",
                active=self.active == "base",
            ),
            SimpleNamespace(
                name="other",
                provider="openai",
                api_mode="openai_api",
                model="gpt-4o-mini",
                base_url="https://api.openai.com/v1",
                status="ready",
                key_ref="configured",
                active=self.active == "other",
            ),
        ]


def test_codex_oauth_service_runs_one_business_workflow() -> None:
    admin = FakeProfileAdmin()
    oauth_instances = []

    def oauth_factory(**kwargs):
        oauth = FakeOAuth(**kwargs)
        oauth_instances.append(oauth)
        return oauth

    service = CodexOAuthService(admin, oauth_factory=oauth_factory)
    config = ChatDomeConfig(
        active_ai_profile="openai",
        ai_profiles={
            "openai": AIConfig(
                provider="openai",
                api_mode="openai_api",
                model="gpt-4o",
                api_key="sk-test",
            )
        },
    )

    session = asyncio.run(
        service.begin(
            config,
            ProfileActor(source="test", chat_id=1),
            requested_profile="codex-test",
        )
    )
    result = asyncio.run(service.complete(session))

    assert session.authorization.profile_name == "codex-test"
    assert session.authorization.user_code == "CODE-123"
    assert result is not None
    assert result.profile_name == "codex-test"
    assert oauth_instances[0].poll_args["timeout"] == 600
    assert oauth_instances[0].exchanged == ("authorization-code", "verifier")
    assert admin.created_codex[0][0].token_file.endswith("codex-test.json")


def test_model_command_service_returns_shared_facts_and_results() -> None:
    manager = FakeManager()
    admin = FakeProfileAdmin()
    sync_calls = []

    async def sync_runtime():
        manager.active = "other"
        sync_calls.append(True)

    service = ModelCommandService(
        manager,
        admin,
        runtime_sync=sync_runtime,
    )

    listed = service.list_profiles()
    switched = asyncio.run(
        service.switch("other", ProfileActor(source="test", chat_id=1))
    )
    deleted = asyncio.run(
        service.delete("base", ProfileActor(source="test", chat_id=1))
    )

    assert listed.facts.active_profile == "base"
    assert len(listed.facts.profiles) == 2
    assert switched.outcome == "model_switched"
    assert switched.facts.name == "other"
    assert deleted.outcome == "model_deleted"
    assert len(sync_calls) == 2


def test_environment_facts_builder_parses_one_shared_profile(tmp_path: Path) -> None:
    profile = tmp_path / "profile.md"
    profile.write_text(
        "\n".join(
            [
                "- UTC: 2026-07-15T00:00:00Z",
                "- OS family: Linux",
                "- OS release: 6.8",
                "- OS version: test",
                "- Machine: x86_64",
                "- Python: 3.11",
                "- Shell: /bin/bash",
                "- Linux distro: Ubuntu",
                "- WSL: no",
                "- Available: bash, curl",
                "- Missing: powershell",
            ]
        ),
        encoding="utf-8",
    )

    facts = EnvironmentFactsBuilder().from_profile(profile)

    assert isinstance(facts, EnvironmentFacts)
    assert facts.available
    assert facts.available_commands == ("bash", "curl")
    assert facts.missing_commands == ("powershell",)


def test_command_registry_converts_result_before_platform_handler() -> None:
    delivered = []

    async def handler(_invocation):
        return CommandResult(
            outcome="done",
            title="Result",
            text="completed",
        )

    registry = CommandRegistry(
        [CommandDef("/test", "test", "test", handler=handler)],
        context_factory=lambda: CommandContext(source="cli"),
        result_handler=lambda _invocation, result: delivered.append(result.outbound),
    )

    result = asyncio.run(registry.execute("/test"))

    assert result.outbound is delivered[0]
    assert result.outbound.kind == OutboundMessageKind.OPERATION_RESULT
    assert result.outbound.body == "completed"
