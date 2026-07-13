import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

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

    async def test_detail_handler_rejects_missing_or_cross_chat_token_and_removes_buttons(self):
        for cached, chat_id in ((None, 123), ({"chat_id": 456, "event": _event().to_dict()}, 123)):
            with self.subTest(cached=cached):
                bot = _bot()
                if cached is not None:
                    bot._alert_analysis_cache["token"] = cached
                query = SimpleNamespace(message=object(), edit_message_reply_markup=AsyncMock())

                await bot._handle_sentinel_alert_detail(query, chat_id, "token")

                query.edit_message_reply_markup.assert_awaited_once_with(reply_markup=None)
                text = bot._send_long_message.await_args.args[1]
                self.assertEqual(text, "告警详情已过期。使用 /sentinel_history 查看告警记录。")

    async def test_detail_handler_handles_non_mapping_event(self):
        bot = _bot()
        bot._alert_analysis_cache["token"] = {"chat_id": 123, "event": "invalid"}
        query = SimpleNamespace(message=object())

        await bot._handle_sentinel_alert_detail(query, 123, "token")

        self.assertEqual(bot._send_long_message.await_args.args[1], "暂无详细状态信息。")

    async def test_analysis_handler_rejects_expired_context_and_removes_buttons(self):
        bot = _bot()
        query = SimpleNamespace(message=object(), edit_message_reply_markup=AsyncMock())

        await bot._handle_sentinel_alert_analysis(query, 123, "missing")

        query.edit_message_reply_markup.assert_awaited_once_with(reply_markup=None)
        text = bot._send_long_message.await_args.args[1]
        self.assertEqual(text, "这条告警上下文已过期，请查看 /sentinel_history 或等待下一次告警。")

    async def test_analysis_handler_removes_only_analysis_button_for_matching_chat(self):
        class FakeClient:
            model = "fake-model"

            async def chat_completion(self, messages, tools=None):
                return SimpleNamespace(
                    content="分析内容",
                    prompt_tokens=1,
                    completion_tokens=2,
                    total_tokens=3,
                )

        bot = _bot()
        bot._alert_analysis_cache["token"] = {
            "chat_id": 123,
            "alert_text": "alert card",
            "event": _event().to_dict(),
        }
        bot._read_environment_profile_for_llm = Mock(return_value="env")
        bot._record_visible_context = Mock()
        bot.agent = SimpleNamespace(
            get_active_llm_snapshot=AsyncMock(return_value=SimpleNamespace(client=FakeClient()))
        )
        thinking_msg = SimpleNamespace(delete=AsyncMock())
        message = SimpleNamespace(reply_text=AsyncMock(return_value=thinking_msg))
        query = SimpleNamespace(message=message, edit_message_reply_markup=AsyncMock())

        with patch("chatdome.agent.tracker.TokenTracker.record_usage") as record_usage:
            await bot._handle_sentinel_alert_analysis(query, 123, "token")

        query.edit_message_reply_markup.assert_awaited_once()
        reply_markup = query.edit_message_reply_markup.await_args.kwargs["reply_markup"]
        keyboard = reply_markup.inline_keyboard
        self.assertEqual(len(keyboard), 1)
        self.assertEqual([button.text for button in keyboard[0]], ["📋 查看详情"])
        self.assertEqual(keyboard[0][0].callback_data, "sentinel_alert_detail:token")
        message.reply_text.assert_awaited_once_with("⏳")
        thinking_msg.delete.assert_awaited_once()
        bot._send_long_message.assert_awaited_once_with(message, "分析内容")
        record_usage.assert_called_once()
        bot._record_visible_context.assert_called_once()

    def test_approval_detail_text_groups_command_breakdown(self):
        details = {
            "ok": True,
            "approval_id": "AP-1",
            "run_id": "RUN-1",
            "command": "rm /root/show_time.sh",
            "command_hash": "abcdef1234567890",
            "reason": "delete old helper",
            "analysis": {
                "risk_level": "CRITICAL",
                "safety_status": "CRITICAL",
                "mutation_detected": True,
                "deletion_detected": True,
                "impact_analysis": "检测到删除操作，目标文件：/root/show_time.sh。",
                "command_breakdown": {
                    "tokens": [
                        {"token": "rm", "role": "command", "label": "命令", "meaning": "删除文件或目录"},
                        {
                            "token": "/root/show_time.sh",
                            "role": "target_file",
                            "label": "目标文件",
                            "meaning": "将被永久删除",
                        },
                    ],
                    "warnings": ["无 -i 标志，删除时不会提示确认"],
                },
            },
        }

        text = TelegramBot._format_approval_detail_text(details)

        self.assertIn("命令审批详情", text)
        self.assertIn("命令解析", text)
        self.assertIn("/root/show_time.sh", text)
        self.assertIn("目标文件（将被永久删除）", text)
        self.assertNotIn("静态信号", text)
        self.assertNotIn("Approval ID", text)

    async def test_approval_request_is_compact(self):
        bot = _bot()
        bot._reply_text = AsyncMock()
        message = object()

        await bot._send_approval_request(
            message,
            {
                "approval_id": "AP-1",
                "risk_level": "CRITICAL",
                "command_hash": "abcdef1234567890",
                "reason": "delete file",
                "impact_analysis": "will delete /root/show_time.sh",
            },
        )

        text = bot._reply_text.await_args.args[1]
        self.assertIn("待审批", text)
        self.assertIn("目的：delete file", text)
        self.assertIn("命令分析", text)
        self.assertNotIn("风险等级", text)
        self.assertNotIn("审批编号", text)
        self.assertNotIn("命令指纹", text)
        self.assertNotIn("show_time.sh", text)
        markup = bot._reply_text.await_args.kwargs["reply_markup"]
        labels = [button.text for row in markup.inline_keyboard for button in row]
        self.assertEqual(
            labels,
            ["✅ 允许", "✅ 本次任务允许", "❌ 拒绝", "🔎 命令分析"],
        )

        await bot._send_approval_request(message, {"approval_id": "AP-2", "reason": "无说明"})
        fallback_text = bot._reply_text.await_args.args[1]
        self.assertIn("目的：信息不可用，请先查看命令分析。", fallback_text)
        fallback_markup = bot._reply_text.await_args.kwargs["reply_markup"]
        fallback_labels = [button.text for row in fallback_markup.inline_keyboard for button in row]
        self.assertEqual(fallback_labels, ["❌ 拒绝", "🔎 命令分析"])

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
