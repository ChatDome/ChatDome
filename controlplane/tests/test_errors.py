import unittest

from chatdome.config import ChatDomeConfig
from chatdome.errors import (
    ChatDomeError,
    LLMAuthenticationError,
    LLMProfileNotReady,
    user_facing_error_message,
)
from chatdome.llm.codex_auth import NotAuthenticatedError
from chatdome.llm.manager import LLMProfileNotReady as ManagerLLMProfileNotReady
from chatdome.telegram.bot import TelegramBot


class FakeAgent:
    pass


class ErrorFormattingTests(unittest.TestCase):
    def test_chatdome_error_hides_detail_by_default(self):
        exc = ChatDomeError("provider secret", user_message="安全提示")

        self.assertEqual(user_facing_error_message(exc), "安全提示")

    def test_chatdome_error_can_expose_safe_detail(self):
        exc = ChatDomeError(
            "profile missing",
            user_message="LLM profile 配置异常。",
            expose_detail=True,
        )

        self.assertEqual(
            user_facing_error_message(exc),
            "LLM profile 配置异常。\n详情: profile missing",
        )

    def test_legacy_error_names_inherit_unified_tree(self):
        self.assertTrue(issubclass(ManagerLLMProfileNotReady, LLMProfileNotReady))
        self.assertTrue(issubclass(NotAuthenticatedError, LLMAuthenticationError))
        self.assertTrue(issubclass(NotAuthenticatedError, RuntimeError))

    def test_telegram_formatter_does_not_leak_unknown_exception(self):
        bot = TelegramBot(ChatDomeConfig(), FakeAgent())

        text = bot._format_error_text(
            RuntimeError("raw provider token leaked"),
            prefix="处理失败",
            fallback="处理失败，请稍后重试。",
        )

        self.assertEqual(text, "处理失败: 处理失败，请稍后重试。")


if __name__ == "__main__":
    unittest.main()
