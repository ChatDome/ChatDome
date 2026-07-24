import asyncio
import unittest
from types import SimpleNamespace

from chatdome.config import ChatDomeConfig
from chatdome.telegram.bot import TelegramBot


class FakeStatusMessage:
    def __init__(self):
        self.deleted = False

    async def edit_text(self, _text, **_kwargs):
        return None

    async def delete(self):
        self.deleted = True


class FakeMessage:
    def __init__(self):
        self.replies = []
        self.reply_kwargs = []
        self.status_messages = []

    async def reply_text(self, text, **kwargs):
        self.replies.append(text)
        self.reply_kwargs.append(kwargs)
        status = FakeStatusMessage()
        self.status_messages.append(status)
        return status


class BlockingRoundLimitAgent:
    def __init__(self):
        self.config = SimpleNamespace(max_rounds_per_turn=10)
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.calls = []

    async def resolve_round_limit(self, chat_id, action):
        self.calls.append((chat_id, action))
        self.started.set()
        await self.release.wait()
        return "continued result"


class TelegramRoundLimitTests(unittest.TestCase):
    def test_round_limit_prompt_uses_platform_adapter(self):
        asyncio.run(self._run_round_limit_prompt_uses_platform_adapter())

    def test_continue_round_limit_runs_in_background(self):
        asyncio.run(self._run_continue_round_limit_runs_in_background())

    async def _run_round_limit_prompt_uses_platform_adapter(self):
        agent = BlockingRoundLimitAgent()
        bot = TelegramBot(ChatDomeConfig(), agent)
        message = FakeMessage()

        await bot._send_round_limit_prompt(
            message,
            {"rounds": 10, "window": 10, "run_id": "RUN-1"},
        )

        self.assertIn("当前任务已执行 10 轮", message.replies[-1])
        keyboard = message.reply_kwargs[-1]["reply_markup"].inline_keyboard
        self.assertEqual(
            [button.text for button in keyboard[0]],
            ["▶️ 继续执行", "🛑 放弃任务"],
        )

    async def _run_continue_round_limit_runs_in_background(self):
        agent = BlockingRoundLimitAgent()
        bot = TelegramBot(ChatDomeConfig(), agent)
        message = FakeMessage()

        await bot._start_round_limit_resolution(message, chat_id=123, action="CONTINUE")
        await asyncio.wait_for(agent.started.wait(), timeout=1)

        self.assertEqual(agent.calls, [(123, "CONTINUE")])
        self.assertIn(123, bot._round_limit_tasks)
        self.assertEqual(message.replies[0], "⚙ 正在执行操作")
        self.assertFalse(bot._round_limit_tasks[123].done())

        agent.release.set()
        await asyncio.wait_for(bot._round_limit_tasks[123], timeout=1)
        await asyncio.sleep(0)

        self.assertIn("continued result", message.replies[-1])
        self.assertTrue(message.status_messages[0].deleted)
        self.assertNotIn(123, bot._round_limit_tasks)


if __name__ == "__main__":
    unittest.main()
