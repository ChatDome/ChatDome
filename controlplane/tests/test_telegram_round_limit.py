import asyncio
import unittest
from types import SimpleNamespace

from chatdome.config import ChatDomeConfig
from chatdome.telegram.bot import TelegramBot


class FakeStatusMessage:
    def __init__(self):
        self.deleted = False

    async def delete(self):
        self.deleted = True


class FakeMessage:
    def __init__(self):
        self.replies = []
        self.status_messages = []

    async def reply_text(self, text, **kwargs):
        del kwargs
        self.replies.append(text)
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
    def test_continue_round_limit_runs_in_background(self):
        asyncio.run(self._run_continue_round_limit_runs_in_background())

    async def _run_continue_round_limit_runs_in_background(self):
        agent = BlockingRoundLimitAgent()
        bot = TelegramBot(ChatDomeConfig(), agent)
        message = FakeMessage()

        await bot._start_round_limit_resolution(message, chat_id=123, action="CONTINUE")
        await asyncio.wait_for(agent.started.wait(), timeout=1)

        self.assertEqual(agent.calls, [(123, "CONTINUE")])
        self.assertIn(123, bot._round_limit_tasks)
        self.assertIn("已收到继续执行请求", message.replies[0])
        self.assertFalse(bot._round_limit_tasks[123].done())

        agent.release.set()
        await asyncio.wait_for(bot._round_limit_tasks[123], timeout=1)
        await asyncio.sleep(0)

        self.assertIn("continued result", message.replies[-1])
        self.assertTrue(message.status_messages[0].deleted)
        self.assertNotIn(123, bot._round_limit_tasks)


if __name__ == "__main__":
    unittest.main()
