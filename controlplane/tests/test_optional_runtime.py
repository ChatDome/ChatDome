import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock

from chatdome.config import ChatDomeConfig
from chatdome.runtime import MODEL_SETUP_MESSAGE, RuntimeCapabilities
from chatdome.telegram.bot import TelegramBot


class OptionalRuntimeTests(unittest.TestCase):
    def test_capability_matrix_keeps_core_ready(self):
        for telegram, llm in ((False, False), (True, False), (False, True), (True, True)):
            with self.subTest(telegram=telegram, llm=llm):
                config = ChatDomeConfig()
                config.sentinel.enabled = True
                if telegram:
                    config.telegram.bot_token = "token"
                if llm:
                    config.active_ai_profile = "default"
                    config.ai_profiles["default"] = SimpleNamespace()

                status = RuntimeCapabilities.from_config(config)

                self.assertEqual(status.core.state, "ready")
                self.assertEqual(status.sentinel.state, "ready")
                self.assertEqual(
                    status.telegram.state,
                    "ready" if telegram else "not_configured",
                )
                self.assertEqual(
                    status.llm.state,
                    "ready" if llm else "not_configured",
                )

    def test_sentinel_disabled_is_reported_independently(self):
        status = RuntimeCapabilities.from_config(ChatDomeConfig())

        self.assertEqual(status.core.state, "ready")
        self.assertEqual(status.sentinel.state, "disabled")

    def test_telegram_without_agent_prompts_for_model(self):
        asyncio.run(self._run_telegram_without_agent_prompts_for_model())

    async def _run_telegram_without_agent_prompts_for_model(self):
        config = ChatDomeConfig()
        config.telegram.allowed_ids = [123]
        bot = TelegramBot(config, None)
        message = SimpleNamespace(text="检查磁盘", reply_text=AsyncMock())
        update = SimpleNamespace(
            effective_chat=SimpleNamespace(id=123, type="private"),
            effective_user=SimpleNamespace(id=123),
            effective_message=message,
            message=message,
        )

        await bot._handle_message(update, None)

        message.reply_text.assert_awaited_once_with(MODEL_SETUP_MESSAGE)
        self.assertEqual(bot._message_tasks, {})

    def test_post_init_without_agent_does_not_fail(self):
        asyncio.run(TelegramBot(ChatDomeConfig(), None).post_init(SimpleNamespace(bot=None)))


if __name__ == "__main__":
    unittest.main()
