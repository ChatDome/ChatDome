import asyncio
import json
import unittest
from types import SimpleNamespace

from chatdome.config import AIConfig, ChatDomeConfig, TelegramConfig
from chatdome.llm.profile_admin import ProfileMutationResult, ProfileSummary
from chatdome.telegram.bot import TelegramBot


class FakeMessage:
    def __init__(self, text=""):
        self.text = text
        self.replies = []
        self.deleted = False
        self.reply_markup = None

    async def reply_text(self, text, **kwargs):
        self.replies.append(text)
        self.reply_markup = kwargs.get("reply_markup")
        return self

    async def delete(self):
        self.deleted = True

    async def edit_text(self, text):
        self.replies.append(text)


class FakeQuery:
    def __init__(self, message, data):
        self.message = message
        self.data = data
        self.answered = False

    async def answer(self):
        self.answered = True

    async def edit_message_reply_markup(self, reply_markup=None):
        self.message.reply_markup = reply_markup


class FakeUpdate:
    def __init__(self, message, chat_id=1, user_id=2, chat_type="private", query=None):
        self.message = message
        self.effective_message = query.message if query is not None else message
        self.effective_chat = SimpleNamespace(id=chat_id, type=chat_type)
        self.effective_user = SimpleNamespace(id=user_id)
        self.callback_query = query


class FakeManager:
    def __init__(self, config):
        self.config = config

    def get_active_profile_name(self):
        return self.config.active_ai_profile

    def list_profiles(self):
        return []


class FakeAgent:
    def __init__(self, config):
        self.llm_manager = FakeManager(config)
        self.session_manager = SimpleNamespace(events=[])

        def record_control_event(chat_id, event):
            self.session_manager.events.append((chat_id, event))

        self.session_manager.record_control_event = record_control_event


class FakeProfileAdmin:
    def __init__(self, config):
        self.config = config
        self.summaries = {}
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
        return ProfileMutationResult(action, request.name, self.config.active_ai_profile, len(self.config.ai_profiles))

    async def delete_profile(self, name, actor):
        self.deleted.append((name, actor))
        self.config.ai_profiles.pop(name, None)
        return ProfileMutationResult("deleted", name, self.config.active_ai_profile, len(self.config.ai_profiles))

    async def set_active_profile(self, name, actor):
        self.switched.append((name, actor))
        self.config.active_ai_profile = name
        return ProfileMutationResult("switched", name, name, len(self.config.ai_profiles))


class TelegramLLMAdminTests(unittest.TestCase):
    def make_bot(self, admin_ids=None, allowed_ids=None):
        config = ChatDomeConfig(
            telegram=TelegramConfig(
                allowed_chat_ids=list(
                    allowed_ids if allowed_ids is not None else [1]
                ),
                admin_chat_ids=list(admin_ids if admin_ids is not None else [1]),
            ),
            active_ai_profile="base",
            ai_profiles={
                "base": AIConfig(model="gpt-4o", api_key="sk-base"),
                "other": AIConfig(model="gpt-4o-mini", api_key="sk-other"),
            },
        )
        service = FakeProfileAdmin(config)
        return TelegramBot(config, FakeAgent(config), service), service

    def run_async(self, awaitable):
        return asyncio.run(awaitable)

    def test_non_admin_cannot_switch(self):
        bot, service = self.make_bot(admin_ids=[99])
        message = FakeMessage()
        update = FakeUpdate(message)
        context = SimpleNamespace(args=["other"])

        self.run_async(bot._handle_llm(update, context))

        self.assertFalse(service.switched)
        self.assertIn("没有 model 管理权限", message.replies[-1])

    def test_allowed_private_chat_can_manage_when_admin_chat_ids_empty(self):
        bot, service = self.make_bot(admin_ids=[], allowed_ids=[1])
        message = FakeMessage()
        update = FakeUpdate(message)
        context = SimpleNamespace(args=["other"])

        result = self.run_async(bot._handle_llm(update, context))

        self.assertEqual(service.config.active_ai_profile, "other")
        self.assertEqual(service.switched[0][0], "other")
        self.assertEqual(result.outcome, "model_switched")
        self.assertIn("model switched", result.text)

    def test_empty_allowed_and_admin_chat_ids_do_not_grant_management(self):
        bot, service = self.make_bot(admin_ids=[], allowed_ids=[])
        message = FakeMessage()
        update = FakeUpdate(message)
        context = SimpleNamespace(args=["other"])

        self.run_async(bot._handle_llm(update, context))

        self.assertFalse(service.switched)
        self.assertIn("没有 model 管理权限", message.replies[-1])

    def test_admin_must_also_be_in_allowed_chat_ids(self):
        bot, service = self.make_bot(allowed_ids=[99])
        message = FakeMessage()
        update = FakeUpdate(message)

        self.run_async(
            bot._handle_llm_add(
                update, SimpleNamespace(args=[], bot=SimpleNamespace())
            )
        )

        self.assertFalse(service.created)
        self.assertFalse(bot._llm_admin_sessions)

    def test_admin_switch_is_persisted_through_service(self):
        bot, service = self.make_bot()
        message = FakeMessage()
        update = FakeUpdate(message)
        context = SimpleNamespace(args=["other"])

        result = self.run_async(bot._handle_llm(update, context))

        self.assertEqual(service.config.active_ai_profile, "other")
        self.assertEqual(service.switched[0][0], "other")
        self.assertEqual(result.outcome, "model_switched")
        self.assertIn("model switched", result.text)

    def test_openai_add_flow_deletes_key_message_and_confirms(self):
        bot, service = self.make_bot()
        message = FakeMessage()
        update = FakeUpdate(message)
        context = SimpleNamespace(args=[], bot=SimpleNamespace())

        self.run_async(bot._handle_llm_add(update, context))
        session = bot._llm_admin_sessions[(1, 2)]
        nonce = session["nonce"]

        query = FakeQuery(message, f"llm_admin:type_openai:{nonce}")
        callback_update = FakeUpdate(message, query=query)
        self.run_async(
            bot._handle_llm_admin_callback(
                callback_update,
                context,
                query.data,
            )
        )

        for value in ("new-profile", "new-model", "https://example.com/v1"):
            message.text = value
            self.run_async(bot._handle_llm_admin_message(update, context))

        message.text = "sk-secret-value"
        self.run_async(bot._handle_llm_admin_message(update, context))
        self.assertTrue(message.deleted)
        self.assertNotIn("sk-secret-value", "\n".join(message.replies))

        query = FakeQuery(message, f"llm_admin:save_yes:{nonce}")
        callback_update = FakeUpdate(message, query=query)
        self.run_async(
            bot._handle_llm_admin_callback(
                callback_update,
                context,
                query.data,
            )
        )

        self.assertEqual(service.created[0][0].name, "new-profile")
        self.assertEqual(service.created[0][0].api_key, "sk-secret-value")
        self.assertNotIn((1, 2), bot._llm_admin_sessions)
        recorded = json.dumps(bot.agent.session_manager.events, ensure_ascii=False)
        self.assertNotIn("sk-secret-value", recorded)
        self.assertTrue(
            any(
                event["command"] == "/model_add"
                and event["outcome"] == "model_added"
                for _, event in bot.agent.session_manager.events
            )
        )

    def test_llm_cancel_clears_session_secret_and_confirmation(self):
        bot, _ = self.make_bot()
        key = (1, 2)
        bot._llm_admin_sessions[key] = {
            "step": "confirm_save",
            "api_key": "sk-secret",
            "created_at": 1,
        }
        bot._llm_admin_confirmations["nonce"] = {"key": key}
        message = FakeMessage()

        result = self.run_async(
            bot._handle_llm_cancel(
                FakeUpdate(message), SimpleNamespace(args=[])
            )
        )

        self.assertNotIn(key, bot._llm_admin_sessions)
        self.assertFalse(bot._llm_admin_confirmations)
        self.assertEqual(result.outcome, "model_operation_cancelled")
        self.assertEqual(result.text, "Model operation cancelled.")

    def test_delete_confirmation_is_bound_and_one_time(self):
        bot, service = self.make_bot()
        service.summaries["other"] = ProfileSummary(
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
        context = SimpleNamespace(args=["other"], bot=SimpleNamespace())

        self.run_async(bot._handle_llm_delete(update, context))
        nonce = next(iter(bot._llm_admin_confirmations))
        query = FakeQuery(message, f"llm_admin:delete_yes:{nonce}")
        callback_update = FakeUpdate(message, query=query)
        self.run_async(
            bot._handle_llm_admin_callback(callback_update, context, query.data)
        )

        self.assertEqual(service.deleted[0][0], "other")
        self.assertNotIn(nonce, bot._llm_admin_confirmations)
        self.assertTrue(
            any(
                event["command"] == "/model_delete"
                and event["outcome"] == "model_deleted"
                for _, event in bot.agent.session_manager.events
            )
        )

    def test_codex_persistence_has_no_cli_subprocess_method(self):
        bot, _ = self.make_bot()
        self.assertFalse(hasattr(bot, "_persist_codex_login_profile"))


    def test_existing_profile_requires_overwrite_confirmation(self):
        bot, service = self.make_bot()
        service.summaries["base"] = ProfileSummary(
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

        self.run_async(bot._handle_llm_add(update, context))
        nonce = bot._llm_admin_sessions[(1, 2)]["nonce"]
        query = FakeQuery(message, f"llm_admin:type_openai:{nonce}")
        self.run_async(
            bot._handle_llm_admin_callback(
                FakeUpdate(message, query=query),
                context,
                query.data,
            )
        )
        message.text = "base"
        self.run_async(bot._handle_llm_admin_message(update, context))
        self.assertEqual(
            bot._llm_admin_sessions[(1, 2)]["step"],
            "confirm_overwrite",
        )

        query = FakeQuery(message, f"llm_admin:overwrite_yes:{nonce}")
        self.run_async(
            bot._handle_llm_admin_callback(
                FakeUpdate(message, query=query),
                context,
                query.data,
            )
        )
        for value in ("-", "-", "-"):
            message.text = value
            self.run_async(bot._handle_llm_admin_message(update, context))

        query = FakeQuery(message, f"llm_admin:save_yes:{nonce}")
        self.run_async(
            bot._handle_llm_admin_callback(
                FakeUpdate(message, query=query),
                context,
                query.data,
            )
        )

        request = service.created[0][0]
        self.assertTrue(request.overwrite_existing)
        self.assertEqual(request.expected_profile_fingerprint, "base-fingerprint")
        self.assertEqual(request.api_key, "")

    def test_group_chat_cannot_manage_llm(self):
        bot, service = self.make_bot()
        message = FakeMessage()
        update = FakeUpdate(message, chat_type="group")

        self.run_async(
            bot._handle_llm_add(update, SimpleNamespace(args=[], bot=SimpleNamespace()))
        )

        self.assertFalse(bot._llm_admin_sessions)
        self.assertIn("没有 model 管理权限", message.replies[-1])


    def test_codex_overwrite_passes_confirmed_fingerprint(self):
        bot, service = self.make_bot()
        service.summaries["base"] = ProfileSummary(
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
        captured = {}

        async def capture_login(_update, login_context):
            captured["context"] = login_context

        bot._handle_codex_login = capture_login
        self.run_async(bot._handle_llm_add(update, context))
        nonce = bot._llm_admin_sessions[(1, 2)]["nonce"]
        type_query = FakeQuery(message, f"llm_admin:type_codex:{nonce}")
        self.run_async(
            bot._handle_llm_admin_callback(
                FakeUpdate(message, query=type_query), context, type_query.data
            )
        )
        message.text = "base"
        self.run_async(bot._handle_llm_admin_message(update, context))
        overwrite_query = FakeQuery(message, f"llm_admin:overwrite_yes:{nonce}")
        self.run_async(
            bot._handle_llm_admin_callback(
                FakeUpdate(message, query=overwrite_query),
                context,
                overwrite_query.data,
            )
        )
        start_query = FakeQuery(message, f"llm_admin:codex_start:{nonce}")
        self.run_async(
            bot._handle_llm_admin_callback(
                FakeUpdate(message, query=start_query), context, start_query.data
            )
        )

        login_context = captured["context"]
        self.assertTrue(login_context.chatdome_codex_overwrite)
        self.assertEqual(
            login_context.chatdome_expected_fingerprint,
            "base-fingerprint",
        )


if __name__ == "__main__":
    unittest.main()
