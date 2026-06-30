import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock

from chatdome.sentinel.alerter import AlertEvent
from chatdome.telegram.bot import TelegramBot


def _event() -> AlertEvent:
    return AlertEvent(
        timestamp="2026-06-22 09:30:15",
        check_name="新增监听端口",
        check_id="open_ports",
        mode="differential",
        severity=9,
        severity_label="critical",
        rule="line count > 0",
        current_value=1,
        raw_output="+ 0.0.0.0:8080",
        pushed=True,
        suppressed=False,
        action_reason="state_transition (NONE -> NEW)",
        alert_state="NEW",
        previous_state="",
    )


def _bot() -> TelegramBot:
    bot = object.__new__(TelegramBot)
    bot.max_message_length = 4000
    bot._alert_analysis_cache = {}
    bot._alert_analysis_cache_max = 200
    bot._send_long_message = AsyncMock()
    return bot


class TelegramSentinelAlertTests(unittest.IsolatedAsyncioTestCase):
    async def test_send_alert_adds_detail_and_analysis_buttons_with_shared_token(self):
        bot = _bot()
        app_bot = object()
        bot._app = SimpleNamespace(bot=app_bot)
        bot._send_bot_text = AsyncMock()

        await bot.send_alert(123, "alert", _event())

        call = bot._send_bot_text.await_args
        self.assertEqual(call.args[:3], (app_bot, 123, "alert"))
        keyboard = call.kwargs["reply_markup"].inline_keyboard
        self.assertEqual(len(keyboard), 1)
        self.assertEqual([button.text for button in keyboard[0]], ["📋 查看详情", "🤖 告警分析"])

        detail_data = keyboard[0][0].callback_data
        analysis_data = keyboard[0][1].callback_data
        detail_token = detail_data.split(":", 1)[1]
        analysis_token = analysis_data.split(":", 1)[1]
        self.assertEqual(detail_token, analysis_token)
        self.assertLessEqual(len(detail_data.encode("utf-8")), 64)
        self.assertLessEqual(len(analysis_data.encode("utf-8")), 64)

    async def test_detail_handler_formats_cached_event_for_matching_chat(self):
        bot = _bot()
        bot._alert_analysis_cache["token"] = {
            "chat_id": 123,
            "event": _event().to_dict(),
        }
        query = SimpleNamespace(message=object())

        await bot._handle_sentinel_alert_detail(query, 123, "token")

        detail = bot._send_long_message.await_args.args[1]
        self.assertIn("威胁阶段: 新威胁首次出现", detail)
        self.assertIn("状态迁移: 未监控 → 新威胁首次出现", detail)
        self.assertNotIn("state_transition (", detail)

    async def test_detail_handler_rejects_missing_or_cross_chat_token(self):
        for cached, chat_id in ((None, 123), ({"chat_id": 456, "event": _event().to_dict()}, 123)):
            with self.subTest(cached=cached):
                bot = _bot()
                if cached is not None:
                    bot._alert_analysis_cache["token"] = cached
                query = SimpleNamespace(message=object())

                await bot._handle_sentinel_alert_detail(query, chat_id, "token")

                text = bot._send_long_message.await_args.args[1]
                self.assertEqual(text, "告警详情已过期。使用 /sentinel_history 查看告警记录。")

    async def test_detail_handler_handles_non_mapping_event(self):
        bot = _bot()
        bot._alert_analysis_cache["token"] = {"chat_id": 123, "event": "invalid"}
        query = SimpleNamespace(message=object())

        await bot._handle_sentinel_alert_detail(query, 123, "token")

        self.assertEqual(bot._send_long_message.await_args.args[1], "暂无详细状态信息。")

    async def test_approval_detail_callback_removes_original_buttons(self):
        bot = _bot()
        bot._check_auth = lambda update: True
        bot._start_approval_detail_analysis = AsyncMock()
        query = SimpleNamespace(
            answer=AsyncMock(),
            data="approval:details:AP-1",
            message=object(),
            edit_message_reply_markup=AsyncMock(),
        )
        update = SimpleNamespace(
            callback_query=query,
            effective_chat=SimpleNamespace(id=123),
        )

        await bot._handle_callback_query(update, None)

        query.edit_message_reply_markup.assert_awaited_once_with(reply_markup=None)
        bot._start_approval_detail_analysis.assert_awaited_once_with(query.message, 123, "AP-1")

    async def test_callback_router_dispatches_sentinel_detail(self):
        bot = _bot()
        bot._check_auth = lambda update: True
        bot._handle_sentinel_alert_detail = AsyncMock()
        query = SimpleNamespace(
            answer=AsyncMock(),
            data="sentinel_alert_detail:token",
            message=object(),
        )
        update = SimpleNamespace(
            callback_query=query,
            effective_chat=SimpleNamespace(id=123),
            effective_user=SimpleNamespace(id=456),
        )

        with self.assertLogs("chatdome.telegram.bot", level="INFO") as captured:
            await bot._handle_callback_query(update, None)

        log_line = captured.output[0]
        self.assertIn("[Telegram callback received]", log_line)
        self.assertIn("chat_id=123", log_line)
        self.assertIn("user_id=456", log_line)
        self.assertIn('callback_data="sentinel_alert_detail:token"', log_line)
        bot._handle_sentinel_alert_detail.assert_awaited_once_with(query, 123, "token")


if __name__ == "__main__":
    unittest.main()
