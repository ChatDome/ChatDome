import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock

from chatdome.agent.session import AgentSession
from chatdome.config import ChatDomeConfig
from chatdome.outbound.builders import build_approval_request
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


class RecordingSessionManager:
    def __init__(self):
        self.events = []

    def record_control_event(self, chat_id, event):
        self.events.append((chat_id, event))


class BlockingAgent:
    def __init__(self):
        self.started = asyncio.Event()
        self.cancelled = asyncio.Event()
        self.release = asyncio.Event()
        self.calls = []
        self.session_manager = RecordingSessionManager()

    async def handle_message(self, chat_id, user_message):
        self.calls.append((chat_id, user_message))
        self.started.set()
        try:
            await self.release.wait()
        except asyncio.CancelledError:
            self.cancelled.set()
            raise
        return "done"


class PendingSessionManager(RecordingSessionManager):
    def __init__(self, session):
        super().__init__()
        self.session = session

    def get_or_create(self, chat_id):
        self.session.chat_id = chat_id
        return self.session


class PendingApprovalAgent:
    def __init__(self, session):
        self.session_manager = PendingSessionManager(session)
        self.abort_calls = []

    async def abort_pending_task(self, chat_id):
        self.abort_calls.append(chat_id)
        session = self.session_manager.get_or_create(chat_id)
        if not session.pending_approval:
            return False
        session.task_auto_approve = False
        session.clear_pending_state()
        return True


class FakeApprovalCard:
    def __init__(self, chat_id=123, text=""):
        self.chat_id = chat_id
        self.chat = SimpleNamespace(id=chat_id)
        self.text = text
        self.caption = None
        self.reply_markup = object()
        self.edits = []
        self.deleted = False

    async def edit_text(self, text, **kwargs):
        self.edits.append((text, kwargs))

    async def delete(self):
        self.deleted = True


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
        handler = bot._command_handler(
            "stop",
            command=bot._get_command_registry().resolve_name("/stop"),
        )
        await handler.callback(FakeUpdate(stop_message), SimpleNamespace(args=[]))
        await asyncio.wait_for(agent.cancelled.wait(), timeout=1)
        await asyncio.sleep(0)

        self.assertTrue(first_message.status_messages[0].deleted)
        self.assertEqual(stop_message.replies[-1], "⏹️ 任务已停止。")
        self.assertNotIn(123, bot._message_tasks)

        self.assertEqual(agent.session_manager.events[-1][0], 123)
        self.assertEqual(agent.session_manager.events[-1][1]["command"], "/stop")
        self.assertEqual(agent.session_manager.events[-1][1]["outcome"], "task_stopped")

    def test_stop_reports_no_running_task(self):
        asyncio.run(self._run_stop_reports_no_running_task())

    async def _run_stop_reports_no_running_task(self):
        bot = TelegramBot(ChatDomeConfig(), BlockingAgent())
        stop_message = FakeMessage("/stop")

        update = FakeUpdate(stop_message)
        command = bot._get_command_registry().resolve_name("/stop")
        invocation = bot._platform_adapter.receive_command(
            raw="/stop",
            command=command,
            args=(),
            context=bot._command_context_for_update(
                update,
                SimpleNamespace(args=[]),
            ),
        )
        result = await bot._get_command_registry().execute_invocation(invocation)

        self.assertEqual(result.outcome, "no_active_task")
        self.assertEqual(result.text, "No running task.")
        self.assertEqual(result.facts.operation, "stop_task")
        self.assertFalse(result.facts.changed)


    def test_stop_aborts_pending_approval_and_invalidates_tracked_card(self):
        asyncio.run(
            self._run_stop_aborts_pending_approval_and_invalidates_tracked_card()
        )

    async def _run_stop_aborts_pending_approval_and_invalidates_tracked_card(self):
        session = AgentSession(
            chat_id=123,
            pending_approval=True,
            pending_approval_id="AP-1",
            pending_tool_call_id="CALL-1",
            pending_command="systemctl restart chatdome",
            pending_reason="重启 ChatDome 服务",
        )
        agent = PendingApprovalAgent(session)
        bot = TelegramBot(ChatDomeConfig(), agent)
        card = FakeApprovalCard()
        target = SimpleNamespace(
            chat_id=123,
            reply_text=AsyncMock(return_value=card),
        )
        await bot._platform_adapter.deliver(
            build_approval_request(
                {
                    "approval_id": "AP-1",
                    "command": session.pending_command,
                    "reason": session.pending_reason,
                    "risk_level": "HIGH",
                }
            ),
            target=target,
        )

        self.assertEqual(bot._approval_messages[123], ("AP-1", card))

        stop_message = FakeMessage("/stop")
        handler = bot._command_handler(
            "stop",
            command=bot._get_command_registry().resolve_name("/stop"),
        )
        await handler.callback(
            FakeUpdate(stop_message),
            SimpleNamespace(args=[]),
        )

        self.assertEqual(agent.abort_calls, [123])
        self.assertFalse(session.pending_approval)
        self.assertNotIn(123, bot._approval_messages)
        self.assertEqual(
            card.edits[-1],
            ("⏹️ 已中止\n命令未执行。", {"reply_markup": None}),
        )
        self.assertEqual(stop_message.replies[-1], "⏹️ 任务已停止。")

    def test_stop_cancels_detail_analysis_before_aborting_approval(self):
        asyncio.run(
            self._run_stop_cancels_detail_analysis_before_aborting_approval()
        )

    async def _run_stop_cancels_detail_analysis_before_aborting_approval(self):
        session = AgentSession(
            chat_id=123,
            pending_approval=True,
            pending_approval_id="AP-1",
            pending_tool_call_id="CALL-1",
            pending_command="journalctl -n 20",
            pending_reason="检查系统日志",
        )
        agent = PendingApprovalAgent(session)
        bot = TelegramBot(ChatDomeConfig(), agent)
        started = asyncio.Event()

        async def block_detail(*_args, **_kwargs):
            started.set()
            await asyncio.Event().wait()

        bot._dispatch_callback_command = AsyncMock(side_effect=block_detail)
        original_text = "⚠️ 待审批\n目的：检查系统日志"
        original_markup = object()
        card = FakeApprovalCard(text=original_text)
        card.reply_markup = original_markup

        await bot._start_approval_detail_analysis(card, 123, "AP-1")
        await asyncio.wait_for(started.wait(), timeout=1)
        task_key = bot._approval_detail_task_key(123, "AP-1")
        detail_task = bot._approval_detail_tasks[task_key]

        stopped = await bot._stop_task_for_chat(123)
        await asyncio.sleep(0)

        self.assertTrue(stopped)
        self.assertTrue(detail_task.cancelled())
        self.assertNotIn(task_key, bot._approval_detail_tasks)
        self.assertFalse(session.pending_approval)
        self.assertEqual(agent.abort_calls, [123])
        self.assertEqual(
            card.edits,
            [
                (
                    "🔎 正在分析命令风险与影响…\n目的：检查系统日志",
                    {"reply_markup": None},
                ),
                (original_text, {"reply_markup": original_markup}),
                ("⏹️ 已中止\n命令未执行。", {"reply_markup": None}),
            ],
        )


    def test_stop_cancels_all_live_tasks_for_chat(self):
        asyncio.run(self._run_stop_cancels_all_live_tasks_for_chat())

    async def _run_stop_cancels_all_live_tasks_for_chat(self):
        bot = TelegramBot(ChatDomeConfig(), BlockingAgent())
        started = [asyncio.Event() for _ in range(3)]

        async def block(event):
            event.set()
            await asyncio.Event().wait()

        tasks = [
            asyncio.create_task(block(event))
            for event in started
        ]
        bot._message_tasks[123] = tasks[0]
        bot._approval_resolution_tasks[123] = tasks[1]
        bot._round_limit_tasks[123] = tasks[2]
        await asyncio.gather(*(event.wait() for event in started))

        stopped = await bot._cancel_active_task_for_chat(123)

        self.assertTrue(stopped)
        self.assertTrue(all(task.cancelled() for task in tasks))
        self.assertNotIn(123, bot._message_tasks)
        self.assertNotIn(123, bot._approval_resolution_tasks)
        self.assertNotIn(123, bot._round_limit_tasks)

    def test_resolution_cancels_followup_and_details_and_keeps_new_card(self):
        asyncio.run(
            self._run_resolution_cancels_followup_and_details_and_keeps_new_card()
        )

    async def _run_resolution_cancels_followup_and_details_and_keeps_new_card(self):
        session = AgentSession(
            chat_id=123,
            pending_approval=True,
            pending_approval_id="AP-1",
            pending_tool_call_id="CALL-1",
            pending_command="echo first",
            pending_reason="执行第一条命令",
        )
        bot = TelegramBot(ChatDomeConfig(), PendingApprovalAgent(session))
        followup_started = asyncio.Event()

        async def block_followup():
            followup_started.set()
            await asyncio.Event().wait()

        followup_task = asyncio.create_task(block_followup())
        bot._message_tasks[123] = followup_task
        await followup_started.wait()

        detail_started = asyncio.Event()

        async def block_detail():
            detail_started.set()
            await asyncio.Event().wait()

        detail_task = asyncio.create_task(block_detail())
        bot._approval_detail_tasks["123:AP-1"] = detail_task
        await detail_started.wait()

        old_card = FakeApprovalCard(text="⚠️ 待审批\n目的：执行第一条命令")
        new_card = FakeApprovalCard(text="⚠️ 待审批\n目的：执行第二条命令")

        async def dispatch_resolution(*_args, **_kwargs):
            self.assertTrue(followup_task.cancelled())
            self.assertTrue(detail_task.cancelled())
            bot._remember_approval_message(123, "AP-2", new_card)

        bot._dispatch_callback_command = AsyncMock(
            side_effect=dispatch_resolution
        )
        query = SimpleNamespace(edit_message_text=AsyncMock())

        await bot._run_approval_resolution(
            query=query,
            message=old_card,
            chat_id=123,
            action="APPROVE",
            reason="执行第一条命令",
            approval_id="AP-1",
            data="approval:approve:AP-1",
            command_name="/confirm",
            args=("AP-1",),
            command_context=SimpleNamespace(),
            original_text=old_card.text,
            original_reply_markup=old_card.reply_markup,
        )

        self.assertTrue(followup_task.cancelled())
        self.assertTrue(detail_task.cancelled())
        self.assertEqual(bot._approval_messages[123], ("AP-2", new_card))

if __name__ == "__main__":
    unittest.main()