import unittest
from types import SimpleNamespace

from chatdome.config import ChatDomeConfig
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
                key_ref="env:DEEPSEEK_API_KEY loaded fp=12345678",
                status="ready",
                active=False,
            ),
        ]


class FakeAgent:
    llm_manager = FakeLLMManager()


class TelegramLLMListTests(unittest.TestCase):
    def test_llm_list_is_grouped_and_actionable(self):
        bot = TelegramBot(ChatDomeConfig(), FakeAgent())

        text = bot._format_llm_profile_list()

        self.assertIn("当前: codex-gpt5", text)
        self.assertIn("切换命令: /llm <profile_name>", text)
        self.assertIn("* /llm codex-gpt5", text)
        self.assertIn("  /llm deepseek", text)
        self.assertIn("[当前] codex-gpt5", text)
        self.assertIn("[可选] deepseek", text)
        self.assertIn("状态: ready，可切换", text)
        self.assertIn("Key: env:DEEPSEEK_API_KEY loaded fp=12345678", text)
        self.assertNotIn("deepseek | openai/openai_api", text)


if __name__ == "__main__":
    unittest.main()
