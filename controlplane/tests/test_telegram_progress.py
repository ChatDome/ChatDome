import asyncio
import unittest

from chatdome.telegram.progress import TelegramProgressMessage


class FakeEditableMessage:
    def __init__(self, *, delete_error: bool = False, edit_error: bool = False):
        self.delete_error = delete_error
        self.edit_error = edit_error
        self.deleted = 0
        self.edits = []

    async def edit_text(self, text, **kwargs):
        self.edits.append((text, kwargs))
        if self.edit_error:
            raise RuntimeError("edit unavailable")

    async def delete(self):
        self.deleted += 1
        if self.delete_error:
            raise RuntimeError("delete unavailable")


class FakeTarget:
    def __init__(self, message):
        self.message = message
        self.replies = []

    async def reply_text(self, text):
        self.replies.append(text)
        return self.message


class TelegramProgressMessageTests(unittest.IsolatedAsyncioTestCase):
    def test_format_line_keeps_one_line_and_one_metric(self):
        elapsed = TelegramProgressMessage.format_line(
            "◌",
            "正在\n处理",
            elapsed_seconds=8,
        )
        counted = TelegramProgressMessage.format_line(
            "🔎",
            "正在分析命令",
            elapsed_seconds=8,
            progress=(3, 8),
        )

        self.assertEqual(elapsed, "◌ 正在 处理 · 8 秒")
        self.assertEqual(counted, "🔎 正在分析命令 · 3/8")
        self.assertNotIn("\n", elapsed)
        self.assertNotIn("秒", counted)

    async def test_updates_one_message_and_switches_stage(self):
        now = [100.0]
        message = FakeEditableMessage()
        target = FakeTarget(message)
        progress = await TelegramProgressMessage.create(
            target,
            symbol="◌",
            label="正在处理",
            update_interval=60,
            clock=lambda: now[0],
        )
        ticker = progress._ticker

        now[0] = 108.0
        await progress.refresh()
        await progress.set_stage(
            symbol="⚙",
            label="正在执行操作",
            show_elapsed=True,
        )
        await progress.set_stage(
            symbol="⌁",
            label="正在整理结果",
            show_elapsed=False,
        )
        deleted = await progress.delete()

        self.assertEqual(target.replies, ["◌ 正在处理"])
        self.assertEqual(
            [text for text, _ in message.edits],
            [
                "◌ 正在处理 · 8 秒",
                "⚙ 正在执行操作 · 8 秒",
                "⌁ 正在整理结果",
            ],
        )
        self.assertTrue(deleted)
        self.assertEqual(message.deleted, 1)
        self.assertIsNotNone(ticker)
        self.assertTrue(ticker.done())

    async def test_ticker_updates_elapsed_time_on_same_message(self):
        now = [10.0]
        message = FakeEditableMessage()
        progress = await TelegramProgressMessage.create(
            FakeTarget(message),
            symbol="◌",
            label="正在处理",
            update_interval=0.05,
            clock=lambda: now[0],
        )

        now[0] = 12.0
        await asyncio.sleep(0.12)
        await progress.delete()

        self.assertIn(("◌ 正在处理 · 2 秒", {}), message.edits)

    async def test_delete_is_idempotent_and_stops_late_updates(self):
        now = [10.0]
        message = FakeEditableMessage()
        progress = await TelegramProgressMessage.create(
            FakeTarget(message),
            symbol="◌",
            label="正在处理",
            update_interval=60,
            clock=lambda: now[0],
        )

        self.assertTrue(await progress.delete())
        now[0] = 30.0
        self.assertFalse(await progress.refresh())
        self.assertFalse(await progress.delete())

        self.assertEqual(message.deleted, 1)
        self.assertEqual(message.edits, [])

    async def test_delete_failure_retires_status_with_fallback(self):
        message = FakeEditableMessage(delete_error=True)
        progress = await TelegramProgressMessage.create(
            FakeTarget(message),
            symbol="◌",
            label="正在处理",
            update_interval=60,
        )

        retired = await progress.delete(fallback_text="处理完成。")

        self.assertTrue(retired)
        self.assertEqual(message.deleted, 1)
        self.assertEqual(message.edits[-1], ("处理完成。", {}))

    async def test_failed_replace_can_still_delete_status(self):
        message = FakeEditableMessage(edit_error=True)
        progress = await TelegramProgressMessage.create(
            FakeTarget(message),
            symbol="◌",
            label="正在处理",
            update_interval=60,
        )

        replaced = await progress.replace("处理失败。")
        message.edit_error = False
        retired = await progress.delete()

        self.assertFalse(replaced)
        self.assertTrue(retired)
        self.assertEqual(message.deleted, 1)


if __name__ == "__main__":
    unittest.main()
