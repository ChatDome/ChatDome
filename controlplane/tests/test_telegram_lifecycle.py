import asyncio
import unittest
from types import SimpleNamespace

from chatdome.config import ChatDomeConfig
from chatdome.main import build_telegram_application
from chatdome.telegram.auth import Authenticator
from chatdome.telegram.bot import TelegramBot


class FakeAgent:
    pass


class FakeSentinel:
    def __init__(self):
        self.stopped = False

    async def stop_gracefully(self):
        self.stopped = True


class TelegramLifecycleTests(unittest.TestCase):
    def test_application_asyncio_primitives_belong_to_service_loop(self):
        async def scenario():
            config = ChatDomeConfig()
            config.telegram.bot_token = (
                "123456:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi"
            )
            bot = TelegramBot(config, FakeAgent())

            app = await build_telegram_application(bot)
            stop_event = getattr(
                app.updater,
                "_Updater__polling_task_stop_event",
            )
            waiter = asyncio.create_task(stop_event.wait())
            await asyncio.sleep(0)
            stop_event.set()
            await waiter

            self.assertIs(stop_event._loop, asyncio.get_running_loop())

        asyncio.run(scenario())

    def test_empty_user_lists_deny_every_user(self):
        auth = Authenticator([], [])

        self.assertFalse(auth.is_authorized(123))
        self.assertFalse(auth.is_admin(123))

    def test_admin_inherits_allowed_access(self):
        auth = Authenticator([], [123])

        self.assertTrue(auth.is_authorized(123))
        self.assertTrue(auth.is_admin(123))

    def test_bot_authorizes_private_sender_user_id(self):
        config = ChatDomeConfig()
        config.telegram.allowed_ids = [123]
        bot = TelegramBot(config, FakeAgent())
        update = SimpleNamespace(
            effective_chat=SimpleNamespace(id=999, type="private"),
            effective_user=SimpleNamespace(id=123),
        )

        self.assertTrue(bot._check_auth(update))

    def test_bot_rejects_group_even_for_allowed_user(self):
        config = ChatDomeConfig()
        config.telegram.allowed_ids = [123]
        bot = TelegramBot(config, FakeAgent())
        update = SimpleNamespace(
            effective_chat=SimpleNamespace(id=-999, type="group"),
            effective_user=SimpleNamespace(id=123),
        )

        self.assertFalse(bot._check_auth(update))

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
