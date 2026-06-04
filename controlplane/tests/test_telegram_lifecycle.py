import asyncio
import unittest
from types import SimpleNamespace

from chatdome.config import ChatDomeConfig
from chatdome.telegram.bot import TelegramBot


class FakeAgent:
    pass


class FakeSentinel:
    def __init__(self):
        self.stopped = False

    async def stop_gracefully(self):
        self.stopped = True


class TelegramLifecycleTests(unittest.TestCase):
    def test_post_stop_stops_sentinel_gracefully(self):
        asyncio.run(self._run_post_stop_stops_sentinel_gracefully())

    async def _run_post_stop_stops_sentinel_gracefully(self):
        bot = TelegramBot(ChatDomeConfig(), FakeAgent())
        sentinel = FakeSentinel()
        bot.set_sentinel(sentinel)

        await bot.post_stop(SimpleNamespace(bot=None))

        self.assertTrue(sentinel.stopped)


if __name__ == "__main__":
    unittest.main()
