from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

from chatdome.config import AIConfig, ChatDomeConfig, TelegramConfig
from chatdome.llm.profile_admin import ProfileMutationResult, ProfileSummary
from chatdome.telegram.bot import TelegramBot


class FakeMessage:
    def __init__(self, text: str = "") -> None:
        self.text = text
        self.replies: list[str] = []
        self.deleted = False
        self.reply_markup = None

    async def reply_text(self, text, **kwargs):
        self.replies.append(text)
        self.reply_markup = kwargs.get("reply_markup")
        return self

    async def delete(self):
        self.deleted = True


class FakeQuery:
    def __init__(self, message: FakeMessage, data: str) -> None:
        self.message = message
        self.data = data
        self.answered = False

    async def answer(self):
        self.answered = True

    async def edit_message_reply_markup(self, reply_markup=None):
        self.message.reply_markup = reply_markup


class FakeUpdate:
    def __init__(
        self,
        message: FakeMessage,
        *,
        chat_id: int = 1,
        user_id: int = 2,
        chat_type: str = "private",
        query: FakeQuery | None = None,
    ) -> None:
        self.message = message
        self.effective_message = query.message if query is not None else message
        self.effective_chat = SimpleNamespace(id=chat_id, type=chat_type)
        self.effective_user = SimpleNamespace(id=user_id)
        self.callback_query = query


class FakeManager:
    def __init__(self, config: ChatDomeConfig) -> None:
        self.config = config

    def get_active_profile_name(self):
        return self.config.active_ai_profile

    def list_profiles(self):
        return []


class FakeAgent:
    def __init__(self, config: ChatDomeConfig) -> None:
        self.llm_manager = FakeManager(config)
        self.session_manager = SimpleNamespace(events=[])

        def record_control_event(chat_id, event):
            self.session_manager.events.append((chat_id, event))

        self.session_manager.record_control_event = record_control_event


class FakeProfileAdmin:
    def __init__(self, config: ChatDomeConfig) -> None:
        self.config = config
        self.summaries: dict[str, ProfileSummary] = {}
        self.created = []
        self.deleted = []
        self.switched = []

    async def get_profile_summary(self, name):
        return self.summaries.get(name)

    async def create_openai(self, request, actor):
        self.created.append((request, actor))
        action = "updated" if request.overwrite_existing else "created"
        self.config.ai_profiles[request.name] = AIConfig(
            provider="openai",
            api_mode="openai_api",
            model=request.model,
            base_url=request.base_url,
            api_key=request.api_key or "kept",
        )
        return ProfileMutationResult(
            action,
            request.name,
            self.config.active_ai_profile,
            len(self.config.ai_profiles),
        )

    async def delete_profile(self, name, actor):
        self.deleted.append((name, actor))
        self.config.ai_profiles.pop(name, None)
        return ProfileMutationResult(
            "deleted",
            name,
            self.config.active_ai_profile,
            len(self.config.ai_profiles),
        )

    async def set_active_profile(self, name, actor):
        self.switched.append((name, actor))
        self.config.active_ai_profile = name
        return ProfileMutationResult(
            "switched",
            name,
            name,
            len(self.config.ai_profiles),
        )


def make_bot(*, admin_ids=None, allowed_ids=None):
    config = ChatDomeConfig(
        telegram=TelegramConfig(
            allowed_chat_ids=list(allowed_ids if allowed_ids is not None else [1]),
            admin_chat_ids=list(admin_ids if admin_ids is not None else [1]),
        ),
        active_ai_profile="base",
        ai_profiles={
            "base": AIConfig(model="gpt-4o", api_key="sk-base"),
            "other": AIConfig(model="gpt-4o-mini", api_key="sk-other"),
        },
    )
    admin = FakeProfileAdmin(config)
    return TelegramBot(config, FakeAgent(config), admin), admin


def run(awaitable):
    return asyncio.run(awaitable)


def invoke(bot, update, name, *, args=(), action="", interaction_id="", params=None):
    command = bot._get_command_registry().resolve_name(name)
    context = bot._command_context_for_update(
        update,
        SimpleNamespace(args=list(args), bot=SimpleNamespace()),
    )
    invocation = bot._platform_adapter.receive_command(
        raw=" ".join((name, *args)),
        command=command,
        args=args,
        context=context,
        action=action,
        interaction_id=interaction_id,
        params=params,
    )
    return run(bot._get_command_registry().execute_invocation(invocation))


def callback(bot, message, context, action, nonce):
    query = FakeQuery(message, f"llm_admin:{action}:{nonce}")
    update = FakeUpdate(message, query=query)
    run(bot._handle_llm_admin_callback(update, context, query.data))


def test_registry_binds_all_telegram_commands_to_one_handler_service():
    bot, _ = make_bot()
    handlers = {command.handler for command in bot._get_command_registry().commands}

    assert handlers == {bot._command_service.handle}
    assert set(bot._command_service.registered_commands) >= {
        "/model",
        "/model_add",
        "/model_delete",
        "/codex_login",
    }


def test_non_admin_model_switch_is_rejected_by_shared_service():
    bot, admin = make_bot(admin_ids=[99])
    update = FakeUpdate(FakeMessage())

    result = invoke(bot, update, "/model", args=("other",))

    assert result.outcome == "unauthorized"
    assert not admin.switched


def test_allowed_private_chat_can_manage_when_admin_list_is_empty():
    bot, admin = make_bot(admin_ids=[], allowed_ids=[1])
    update = FakeUpdate(FakeMessage())

    result = invoke(bot, update, "/model", args=("other",))

    assert result.outcome == "model_switched"
    assert admin.switched[0][0] == "other"


def test_group_chat_cannot_manage_models():
    bot, admin = make_bot()
    update = FakeUpdate(FakeMessage(), chat_type="group")

    result = invoke(bot, update, "/model_add")

    assert result.outcome == "unauthorized"
    assert not admin.created


def test_openai_add_flow_uses_shared_workflow_and_redacts_key():
    bot, admin = make_bot()
    message = FakeMessage()
    update = FakeUpdate(message)
    context = SimpleNamespace(args=[], bot=SimpleNamespace())

    started = invoke(bot, update, "/model_add")
    nonce = started.event_refs["interaction_id"]
    callback(bot, message, context, "type_openai", nonce)

    for value in ("new-profile", "new-model", "https://example.com/v1"):
        message.text = value
        run(bot._handle_llm_admin_message(update, context))

    message.text = "sk-secret-value"
    run(bot._handle_llm_admin_message(update, context))
    assert message.deleted
    assert "sk-secret-value" not in "\n".join(message.replies)

    callback(bot, message, context, "save_yes", nonce)

    assert admin.created[0][0].name == "new-profile"
    assert admin.created[0][0].api_key == "sk-secret-value"
    assert not bot._command_service.model_workflow.sessions
    recorded = json.dumps(bot.agent.session_manager.events, ensure_ascii=False)
    assert "sk-secret-value" not in recorded
    assert any(
        event["command"] == "/model_add"
        and event["outcome"] == "model_added"
        for _, event in bot.agent.session_manager.events
    )


def test_existing_profile_requires_shared_overwrite_confirmation():
    bot, admin = make_bot()
    admin.summaries["base"] = ProfileSummary(
        name="base",
        provider="openai",
        api_mode="openai_api",
        model="gpt-4o",
        base_url="https://api.openai.com/v1",
        fingerprint="base-fingerprint",
        active=True,
        has_api_key=True,
    )
    message = FakeMessage()
    update = FakeUpdate(message)
    context = SimpleNamespace(args=[], bot=SimpleNamespace())

    started = invoke(bot, update, "/model_add")
    nonce = started.event_refs["interaction_id"]
    callback(bot, message, context, "type_openai", nonce)
    message.text = "base"
    run(bot._handle_llm_admin_message(update, context))

    session = next(iter(bot._command_service.model_workflow.sessions.values()))
    assert session["step"] == "confirm_overwrite"

    callback(bot, message, context, "overwrite_yes", nonce)
    for value in ("-", "-", "-"):
        message.text = value
        run(bot._handle_llm_admin_message(update, context))
    callback(bot, message, context, "save_yes", nonce)

    request = admin.created[0][0]
    assert request.overwrite_existing
    assert request.expected_profile_fingerprint == "base-fingerprint"
    assert request.api_key == ""


def test_delete_uses_prepare_confirm_execute_workflow():
    bot, admin = make_bot()
    admin.summaries["other"] = ProfileSummary(
        name="other",
        provider="openai",
        api_mode="openai_api",
        model="gpt-4o-mini",
        base_url="https://api.openai.com/v1",
        fingerprint="fp",
        active=False,
        has_api_key=True,
    )
    message = FakeMessage()
    update = FakeUpdate(message)
    context = SimpleNamespace(args=[], bot=SimpleNamespace())

    prepared = invoke(bot, update, "/model_delete", args=("other",))
    nonce = prepared.event_refs["interaction_id"]
    assert prepared.outcome == "model_delete_confirmation_requested"

    callback(bot, message, context, "delete_yes", nonce)

    assert admin.deleted[0][0] == "other"
    assert nonce not in bot._command_service.model_workflow.confirmations
    assert any(
        event["command"] == "/model_delete"
        and event["outcome"] == "model_deleted"
        for _, event in bot.agent.session_manager.events
    )


def test_model_cancel_clears_shared_workflow_state():
    bot, _ = make_bot()
    update = FakeUpdate(FakeMessage())

    invoke(bot, update, "/model_add")
    assert bot._command_service.model_workflow.sessions

    result = invoke(bot, update, "/model_cancel")

    assert result.outcome == "model_operation_cancelled"
    assert not bot._command_service.model_workflow.sessions
    assert not bot._command_service.model_workflow.confirmations
