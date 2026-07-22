import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from chatdome.agent.result import AgentResult
from chatdome.config import ChatDomeConfig
from chatdome.sentinel.alerter import AlertEvent
from chatdome.platform_adapters import TelegramPlatformAdapter
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
    agent = SimpleNamespace(
        session_manager=None,
        llm_manager=None,
    )
    bot = TelegramBot(ChatDomeConfig(), agent)
    bot._send_long_message = AsyncMock()
    bot._platform_adapter = TelegramPlatformAdapter(
        bot._deliver_telegram_rendered
    )
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

    @staticmethod
    def _callback_update(query, chat_id: int = 123):
        return SimpleNamespace(
            callback_query=query,
            effective_chat=SimpleNamespace(id=chat_id, type="private"),
            effective_user=SimpleNamespace(id=456),
            effective_message=query.message,
        )

    async def test_detail_action_uses_shared_handler_for_matching_chat(self):
        bot = _bot()
        token = bot._command_service.remember_sentinel_alert(
            chat_id=123,
            alert_text="alert",
            alert_event=_event(),
        )
        query = SimpleNamespace(message=object(), edit_message_reply_markup=AsyncMock())

        await bot._dispatch_sentinel_alert_action(
            self._callback_update(query),
            None,
            query,
            "sentinel_alert_detail",
            token,
        )

        detail = bot._send_long_message.await_args.args[1]
        self.assertIn("威胁阶段: 新威胁首次出现", detail)
        self.assertIn("状态迁移: 未监控 → 新威胁首次出现", detail)
        self.assertNotIn("state_transition (", detail)

    async def test_detail_action_rejects_missing_or_cross_chat_token(self):
        for cross_chat in (False, True):
            with self.subTest(cross_chat=cross_chat):
                bot = _bot()
                token = "missing"
                if cross_chat:
                    token = bot._command_service.remember_sentinel_alert(
                        chat_id=456,
                        alert_text="alert",
                        alert_event=_event(),
                    )
                query = SimpleNamespace(
                    message=object(),
                    edit_message_reply_markup=AsyncMock(),
                )

                await bot._dispatch_sentinel_alert_action(
                    self._callback_update(query),
                    None,
                    query,
                    "sentinel_alert_detail",
                    token,
                )

                query.edit_message_reply_markup.assert_awaited_once_with(reply_markup=None)
                text = bot._send_long_message.await_args.args[1]
                self.assertEqual(
                    text,
                    "告警详情已过期。使用 /sentinel_history 查看告警记录。",
                )

    async def test_detail_action_handles_non_mapping_event(self):
        bot = _bot()
        token = bot._command_service.remember_sentinel_alert(
            chat_id=123,
            alert_text="alert",
            alert_event="invalid",
        )
        query = SimpleNamespace(message=object(), edit_message_reply_markup=AsyncMock())

        await bot._dispatch_sentinel_alert_action(
            self._callback_update(query),
            None,
            query,
            "sentinel_alert_detail",
            token,
        )

        self.assertEqual(bot._send_long_message.await_args.args[1], "暂无详细状态信息。")

    async def test_analysis_action_rejects_expired_context_and_removes_buttons(self):
        bot = _bot()
        thinking = SimpleNamespace(delete=AsyncMock())
        message = SimpleNamespace(reply_text=AsyncMock(return_value=thinking))
        query = SimpleNamespace(message=message, edit_message_reply_markup=AsyncMock())

        await bot._dispatch_sentinel_alert_action(
            self._callback_update(query),
            None,
            query,
            "sentinel_alert_analysis",
            "missing",
        )

        self.assertEqual(
            query.edit_message_reply_markup.await_args.kwargs["reply_markup"],
            None,
        )
        self.assertEqual(
            bot._send_long_message.await_args.args[1],
            "告警上下文已过期。使用 /sentinel_history 查看告警记录。",
        )
        thinking.delete.assert_awaited_once()

    async def test_analysis_action_runs_shared_handler_and_preserves_platform_ui(self):
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
        manager = SimpleNamespace(record_control_event=Mock())
        bot.agent = SimpleNamespace(
            session_manager=manager,
            llm_manager=None,
            get_active_llm_snapshot=AsyncMock(
                return_value=SimpleNamespace(client=FakeClient())
            ),
        )
        token = bot._command_service.remember_sentinel_alert(
            chat_id=123,
            alert_text="alert card",
            alert_event=_event(),
        )
        thinking = SimpleNamespace(delete=AsyncMock())
        message = SimpleNamespace(reply_text=AsyncMock(return_value=thinking))
        query = SimpleNamespace(message=message, edit_message_reply_markup=AsyncMock())

        with patch("chatdome.agent.tracker.TokenTracker.record_usage") as record_usage:
            await bot._dispatch_sentinel_alert_action(
                self._callback_update(query),
                None,
                query,
                "sentinel_alert_analysis",
                token,
            )

        reply_markup = query.edit_message_reply_markup.await_args.kwargs["reply_markup"]
        keyboard = reply_markup.inline_keyboard
        self.assertEqual([button.text for button in keyboard[0]], ["📋 查看详情"])
        message.reply_text.assert_awaited_once_with("⏳")
        thinking.delete.assert_awaited_once()
        self.assertEqual(bot._send_long_message.await_args.args[:2], (message, "分析内容"))
        record_usage.assert_called_once()
        event = manager.record_control_event.call_args.args[1]
        self.assertEqual(event["command"], "/sentinel_alert_analysis")
        self.assertEqual(event["outcome"], "sentinel_alert_analysis_completed")
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

        text = bot._send_long_message.await_args.args[1]
        self.assertIn("待审批", text)
        self.assertIn("目的：delete file", text)
        self.assertIn("命令分析", text)
        self.assertNotIn("风险等级", text)
        self.assertNotIn("审批编号", text)
        self.assertNotIn("命令指纹", text)
        self.assertNotIn("show_time.sh", text)
        markup = bot._send_long_message.await_args.kwargs["reply_markup"]
        labels = [button.text for row in markup.inline_keyboard for button in row]
        self.assertEqual(
            labels,
            ["✅ 允许", "✅ 本次任务允许", "❌ 拒绝", "🔎 命令分析"],
        )

        await bot._send_approval_request(message, {"approval_id": "AP-2", "reason": "无说明"})
        fallback_text = bot._send_long_message.await_args.args[1]
        self.assertIn("目的：信息不可用，请先查看命令分析。", fallback_text)
        fallback_markup = bot._send_long_message.await_args.kwargs["reply_markup"]
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
        bot._start_approval_detail_analysis.assert_awaited_once()
        call_args = bot._start_approval_detail_analysis.await_args.args
        self.assertEqual(call_args[:3], (query.message, 123, "AP-1"))
        self.assertEqual(call_args[3].source, "telegram")
        self.assertEqual(call_args[3].chat_id, 123)

    async def test_approval_button_uses_shared_command_pipeline(self):
        bot = _bot()
        bot._check_auth = lambda update: True
        manager = SimpleNamespace(record_control_event=Mock())
        bot.agent = SimpleNamespace(
            session_manager=manager,
            resume_session=AsyncMock(
                return_value=(None, AgentResult.reply("approved"))
            ),
        )
        thinking = SimpleNamespace(delete=AsyncMock())
        message = SimpleNamespace(
            text="⚠️ 待审批\n目的：检查系统日志\n是否允许本次操作？",
            reply_text=AsyncMock(return_value=thinking),
        )
        query = SimpleNamespace(
            answer=AsyncMock(),
            data="approval:approve:AP-1",
            message=message,
            edit_message_reply_markup=AsyncMock(),
            edit_message_text=AsyncMock(),
        )
        update = SimpleNamespace(
            callback_query=query,
            effective_chat=SimpleNamespace(id=123),
            effective_user=SimpleNamespace(id=456),
        )

        await bot._handle_callback_query(update, None)
        await asyncio.sleep(0)
        await asyncio.sleep(0)

        query.edit_message_text.assert_awaited_once_with(
            text="✅ 已批准\n目的：检查系统日志",
            reply_markup=None,
        )
        bot.agent.resume_session.assert_awaited_once_with(
            123,
            "APPROVE",
            approval_id="AP-1",
        )
        bot._send_long_message.assert_awaited_once()
        self.assertEqual(
            bot._send_long_message.await_args.args[:2],
            (message, "approved"),
        )
        manager.record_control_event.assert_called_once()
        event = manager.record_control_event.call_args.args[1]
        self.assertEqual(event["command"], "/confirm")
        self.assertEqual(event["outcome"], "approval_confirmed")

    async def test_callback_router_dispatches_sentinel_detail(self):
        bot = _bot()
        bot._check_auth = lambda update: True
        bot._dispatch_sentinel_alert_action = AsyncMock()
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
        bot._dispatch_sentinel_alert_action.assert_awaited_once_with(
            update,
            None,
            query,
            "sentinel_alert_detail",
            "token",
        )


if __name__ == "__main__":
    unittest.main()
