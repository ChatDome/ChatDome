import unittest
from types import SimpleNamespace

from chatdome.config import AIConfig, ChatDomeConfig
from chatdome.telegram.bot import TelegramBot


class FakeLLMManager:
    def get_active_profile_name(self):
        return "codex-gpt5"

    def list_profiles(self):
        return [
            SimpleNamespace(
                name="codex-gpt5",
                provider="codex",
                api_mode="codex_responses",
                model="gpt-5.5",
                base_url="https://chatgpt.com/backend-api/codex",
                key_ref=None,
                status="token_file_present",
                active=True,
            ),
            SimpleNamespace(
                name="deepseek",
                provider="openai",
                api_mode="openai_api",
                model="deepseek-chat",
                base_url="https://api.deepseek.com/v1",
                key_ref="configured fp=12345678",
                status="ready",
                active=False,
            ),
        ]


class FakeAgent:
    llm_manager = FakeLLMManager()


class FakeOpenAIManager:
    def get_active_profile_name(self):
        return "openai"


class FakeOpenAIAgent:
    llm_manager = FakeOpenAIManager()


class FakeCodexManager:
    def get_active_profile_name(self):
        return "codex-old"


class FakeCodexAgent:
    llm_manager = FakeCodexManager()


class TelegramLLMListTests(unittest.TestCase):
    def test_llm_list_is_grouped_and_actionable(self):
        bot = TelegramBot(ChatDomeConfig(), FakeAgent())

        text = bot._format_llm_profile_list()

        self.assertIn("当前: codex-gpt5", text)
        self.assertIn("切换命令: /model <profile_name>", text)
        self.assertIn("  /model codex-gpt5  (current)", text)
        self.assertIn("  /model deepseek", text)
        self.assertNotIn("* /model codex-gpt5", text)
        self.assertIn("[当前] codex-gpt5", text)
        self.assertIn("[可选] deepseek", text)
        self.assertIn("状态: ready，可切换", text)
        self.assertIn("Key: configured fp=12345678", text)
        self.assertNotIn("deepseek | openai/openai_api", text)

    def test_telegram_command_log_is_structured(self):
        bot = TelegramBot(ChatDomeConfig(), FakeAgent())
        update = SimpleNamespace(
            effective_chat=SimpleNamespace(id=123456),
            effective_user=SimpleNamespace(id=789),
            effective_message=SimpleNamespace(text='/model deepseek\nnext "quoted"'),
        )

        with self.assertLogs("chatdome.telegram.bot", level="INFO") as captured:
            bot._log_telegram_command(update, "model")

        line = captured.output[0]
        self.assertIn("[Telegram command received]", line)
        self.assertIn("chat_id=123456", line)
        self.assertIn("user_id=789", line)
        self.assertIn('command="/model deepseek next \\"quoted\\""', line)

    def test_telegram_callback_log_is_structured(self):
        bot = TelegramBot(ChatDomeConfig(), FakeAgent())
        update = SimpleNamespace(
            effective_chat=SimpleNamespace(id=123456),
            effective_user=SimpleNamespace(id=789),
        )

        with self.assertLogs("chatdome.telegram.bot", level="INFO") as captured:
            bot._log_telegram_callback(update, 'approval:approve:AP-1\nnext "quoted"')

        line = captured.output[0]
        self.assertIn("[Telegram callback received]", line)
        self.assertIn("chat_id=123456", line)
        self.assertIn("user_id=789", line)
        self.assertIn('callback_data="approval:approve:AP-1 next \\"quoted\\""', line)

    def test_codex_login_default_profile_is_transient_until_success(self):
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
        bot = TelegramBot(config, FakeOpenAIAgent())

        name, profile, persist_profile = bot._resolve_codex_login_profile("")

        self.assertEqual(name, "codex")
        self.assertTrue(persist_profile)
        self.assertEqual(profile.api_mode, "codex_responses")
        self.assertEqual(profile.codex_token_file, "~/.chatdome/codex-auth/codex.json")
        self.assertNotIn("codex", config.ai_profiles)

    def test_codex_login_named_missing_profile_is_transient_until_success(self):
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
        bot = TelegramBot(config, FakeOpenAIAgent())

        name, profile, persist_profile = bot._resolve_codex_login_profile("codex-test")

        self.assertEqual(name, "codex-test")
        self.assertTrue(persist_profile)
        self.assertEqual(profile.codex_token_file, "~/.chatdome/codex-auth/codex-test.json")
        self.assertNotIn("codex-test", config.ai_profiles)

    def test_codex_login_migrates_existing_blank_token_file(self):
        config = ChatDomeConfig(
            active_ai_profile="codex-old",
            ai_profiles={
                "codex-old": AIConfig(
                    provider="codex",
                    api_mode="codex_responses",
                    model="gpt-5.5",
                    codex_token_file="",
                )
            },
        )
        bot = TelegramBot(config, FakeCodexAgent())

        name, profile, persist_profile = bot._resolve_codex_login_profile("")

        self.assertEqual(name, "codex-old")
        self.assertTrue(persist_profile)
        self.assertEqual(profile.codex_token_file, "~/.chatdome/codex-auth/codex-old.json")
        self.assertEqual(config.ai_profiles["codex-old"].codex_token_file, "")


if __name__ == "__main__":
    unittest.main()
