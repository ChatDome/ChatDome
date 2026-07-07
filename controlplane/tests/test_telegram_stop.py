import asyncio
import unittest
from types import SimpleNamespace

from chatdome.config import ChatDomeConfig
from chatdome.telegram.bot import TelegramBot


class FakeStatusMessage:
    def __init__(self):
        self.deleted = False
        self.edited_text = None

    async def delete(self):
        self.deleted = True

    async def edit_text(self, text):
        self.edited_text = text


class FakeMessage:
    def __init__(self, text=""):
        self.text = text
        self.replies = []
        self.status_messages = []

    async def reply_text(self, text, **kwargs):
        del kwargs
        self.replies.append(text)
        status = FakeStatusMessage()
        self.status_messages.append(status)
        return status


class FakeUpdate:
    def __init__(self, message, chat_id=123):
        self.message = message
        self.effective_chat = SimpleNamespace(id=chat_id)
        self.effective_user = None


class BlockingAgent:
    def __init__(self):
        self.started = asyncio.Event()
        self.cancelled = asyncio.Event()
        self.release = asyncio.Event()
        self.calls = []

    async def handle_message(self, chat_id, user_message):
        self.calls.append((chat_id, user_message))
        self.started.set()
        try:
            await self.release.wait()
        except asyncio.CancelledError:
            self.cancelled.set()
            raise
        return "done"


class TelegramStopTests(unittest.TestCase):
    def test_stop_cancels_running_message_task(self):
        asyncio.run(self._run_stop_cancels_running_message_task())

    async def _run_stop_cancels_running_message_task(self):
        agent = BlockingAgent()
        bot = TelegramBot(ChatDomeConfig(), agent)
        first_message = FakeMessage("run task")

        await bot._handle_message(FakeUpdate(first_message), SimpleNamespace())
        await asyncio.wait_for(agent.started.wait(), timeout=1)

        self.assertEqual(agent.calls, [(123, "run task")])
        self.assertIn(123, bot._message_tasks)
        self.assertFalse(bot._message_tasks[123].done())

        second_message = FakeMessage("second task")
        await bot._handle_message(FakeUpdate(second_message), SimpleNamespace())
        self.assertEqual(second_message.replies[-1], "任务正在运行。\n发送 /stop 中止。")

        stop_message = FakeMessage("/stop")
        await bot._handle_stop(FakeUpdate(stop_message), SimpleNamespace())
        await asyncio.wait_for(agent.cancelled.wait(), timeout=1)
        await asyncio.sleep(0)

        self.assertTrue(first_message.status_messages[0].deleted)
        self.assertEqual(stop_message.replies[-1], "任务已停止。")
        self.assertNotIn(123, bot._message_tasks)

    def test_stop_reports_no_running_task(self):
        asyncio.run(self._run_stop_reports_no_running_task())

    async def _run_stop_reports_no_running_task(self):
        bot = TelegramBot(ChatDomeConfig(), BlockingAgent())
        stop_message = FakeMessage("/stop")

        await bot._handle_stop(FakeUpdate(stop_message), SimpleNamespace())

        self.assertEqual(stop_message.replies[-1], "当前没有运行中的任务。")


if __name__ == "__main__":
    unittest.main()