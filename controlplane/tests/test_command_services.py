from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

from chatdome.agent.result import AgentResult
from chatdome.config import AIConfig, ChatDomeConfig
from chatdome.errors import LLMProfileDeleteForbidden
from chatdome.llm.codex_oauth_service import CodexOAuthService
from chatdome.llm.profile_admin import (
    ProfileActor,
    ProfileMutationResult,
    ProfileSummary,
)
from chatdome.model_commands import ModelCommandService
from chatdome.outbound.builders import EnvironmentFactsBuilder
from chatdome.outbound.models import (
    ActionKind,
    EnvironmentFacts,
    OutboundAction,
    OutboundMessageKind,
)
from chatdome.platform_adapters import CLIPlatformAdapter, TelegramPlatformAdapter
from chatdome.slash_commands import (
    CommandContext,
    CommandDef,
    CommandRegistry,
    CommandResult,
    command_catalog,
    continue_command_result,
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
        self.summaries = {}

    async def get_profile_summary(self, name):
        return self.summaries.get(name)

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
    assert switched.event_summary == "用户切换了 model profile other。"
    assert deleted.outcome == "model_deleted"
    assert deleted.event_summary == "用户删除了 model profile base。"
    assert len(sync_calls) == 2


@pytest.mark.parametrize(
    ("action", "expected"),
    (
        ("created", "用户新增了 model profile demo。"),
        ("updated", "用户更新了 model profile demo。"),
        ("deleted", "用户删除了 model profile demo。"),
    ),
)
def test_model_mutation_event_summary_is_readable(
    action: str,
    expected: str,
) -> None:
    result = ModelCommandService._mutation_result(
        ProfileMutationResult(action, "demo", "demo", 1),
        outcome="model_changed",
    )

    assert result.event_summary == expected


def test_active_model_delete_error_is_readable() -> None:
    admin = FakeProfileAdmin()
    admin.summaries["base"] = ProfileSummary(
        name="base",
        provider="openai",
        api_mode="openai_api",
        model="gpt-4o",
        base_url="https://api.openai.com/v1",
        fingerprint="fp",
        active=True,
        has_api_key=True,
    )
    service = ModelCommandService(FakeManager(), admin)

    with pytest.raises(LLMProfileDeleteForbidden) as caught:
        asyncio.run(service.inspect_delete("base"))

    assert caught.value.to_user_message().splitlines()[0] == "请先切换 LLM，再删除该 profile。"


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


def test_agent_followup_keeps_command_outcome_in_outbound_message() -> None:
    class FakeAgent:
        async def resolve_round_limit(self, _chat_id, _action):
            return AgentResult.reply("continued")

    result = asyncio.run(
        continue_command_result(FakeAgent(), CommandContext(source="cli", chat_id=1))
    )

    assert result.outcome == "task_continued"
    assert result.outbound.outcome == "task_continued"
    assert result.outbound.status == "idle"


def test_cli_and_telegram_share_task_approval_command() -> None:
    cli_names = {command.name for command in command_catalog("cli")}
    telegram_names = {command.name for command in command_catalog("telegram")}

    assert "/confirm_task" in cli_names
    assert "/confirm_task" in telegram_names
    assert cli_names - {"/exit"} == telegram_names


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


def test_platform_adapters_share_invocation_and_outbound_content() -> None:
    delivered = {"cli": [], "telegram": []}

    def cli_sender(_target, rendered):
        delivered["cli"].append(rendered)

    async def telegram_sender(_target, rendered):
        delivered["telegram"].append(rendered)

    cli = CLIPlatformAdapter(cli_sender)
    telegram = TelegramPlatformAdapter(telegram_sender)
    command = CommandDef("/test", "test", "test")

    async def handler(_invocation):
        return CommandResult(
            state="waiting",
            outcome="selection_required",
            title="Select",
            text="Select one option.",
            event_refs={"interaction_id": "I-1"},
            facts={"options": ("a", "b")},
            actions=(
                OutboundAction(ActionKind.SELECT, "A", "select:a"),
                OutboundAction(ActionKind.CANCEL, "Cancel", "cancel"),
            ),
        )

    cli_invocation = cli.receive_command(
        raw="/test",
        command=command,
        args=(),
        context=CommandContext(source="cli"),
    )
    telegram_invocation = telegram.receive_command(
        raw="/test",
        command=command,
        args=(),
        context=CommandContext(source="telegram"),
    )
    cli_result = asyncio.run(cli.dispatch(cli_invocation, handler=handler))
    telegram_result = asyncio.run(
        telegram.dispatch(telegram_invocation, handler=handler, target=object())
    )

    for result in (cli_result, telegram_result):
        assert result.outbound.status == "waiting"
        assert result.outbound.outcome == "selection_required"
        assert result.outbound.refs["interaction_id"] == "I-1"
        assert result.outbound.facts == {"options": ("a", "b")}
        assert [action.kind for action in result.outbound.actions] == [
            ActionKind.SELECT,
            ActionKind.CANCEL,
        ]
    assert delivered["cli"][0].text_parts == ("Select one option.",)
    assert [control.data for control in delivered["telegram"][0].controls] == [
        "select:a",
        "cancel",
    ]


def test_cli_platform_adapter_executes_terminal_input_through_registry() -> None:
    delivered = []
    adapter = CLIPlatformAdapter(
        lambda _target, rendered: delivered.extend(rendered.text_parts)
    )
    registry = CommandRegistry(
        [CommandDef("/test", "test", "test", handler=lambda _: CommandResult(text="done"))],
        context_factory=lambda: CommandContext(source="cli"),
        result_handler=lambda _invocation, result: adapter.deliver_result(result),
    )

    result = asyncio.run(adapter.execute_terminal_input(registry, "/test"))

    assert result.handled
    assert delivered == ["done"]


def test_telegram_callback_builds_structured_command_invocation() -> None:
    adapter = TelegramPlatformAdapter(lambda _target, _rendered: None)
    invocation = adapter.receive_callback(
        data="llm_admin:save_yes:interaction-1",
        command=CommandDef("/model_add", "add", "model"),
        args=(),
        context=CommandContext(source="telegram"),
        action="save_yes",
        interaction_id="interaction-1",
        params={"operation": "model_admin"},
    )

    assert invocation.command.name == "/model_add"
    assert invocation.action == "save_yes"
    assert invocation.interaction_id == "interaction-1"
    assert invocation.params == {"operation": "model_admin"}
