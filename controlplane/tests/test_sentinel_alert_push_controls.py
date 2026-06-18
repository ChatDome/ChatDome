import asyncio
import json
import os
import tempfile
import unittest
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from chatdome.agent.tools import ToolDispatcher
from chatdome.sentinel.alert_controls import parse_alert_mute_until
from chatdome.sentinel.alerter import AlertEvent
from chatdome.sentinel.scheduler import SentinelScheduler


@dataclass
class FakeCommandResult:
    stdout: str = ""
    stderr: str = ""
    return_code: int = 0
    timed_out: bool = False


class FakeSandbox:
    async def execute_security_check(self, check_id: str, args=None):
        del check_id, args
        return FakeCommandResult()


class FakeConfig:
    alert_retention_days = 30
    global_rate_limit = 100
    global_rate_window = 300
    learning_rounds = 0
    checks = [
        {
            "name": "SSH success login",
            "check_id": "ssh_success_login",
            "interval": 60,
            "mode": "differential",
            "severity": 9,
            "rule": {"type": "added_count", "operator": ">", "threshold": 0},
        }
    ]


def _event(raw_output: str = "login", state: str = "NEW", previous_state: str = "") -> AlertEvent:
    return AlertEvent(
        timestamp="2026-05-18 13:41:23",
        check_name="SSH success login",
        check_id="ssh_success_login",
        mode="differential",
        severity=9,
        severity_label="critical",
        rule="new login",
        current_value=1,
        raw_output=raw_output,
        pushed=True,
        suppressed=False,
        alert_state=state,
        previous_state=previous_state,
    )


class SentinelAlertPushControlTests(unittest.TestCase):
    def test_muted_alert_is_recorded_without_telegram_push(self):
        asyncio.run(self._run_muted_alert_is_recorded_without_telegram_push())

    def test_recovery_alert_is_recorded_without_telegram_push(self):
        asyncio.run(self._run_recovery_alert_is_recorded_without_telegram_push())

    def test_repeat_state_alert_is_recorded_without_telegram_push(self):
        asyncio.run(self._run_repeat_state_alert_is_recorded_without_telegram_push())

    def test_alert_push_mute_state_persists(self):
        old_cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as temp_dir:
            os.chdir(temp_dir)
            try:
                scheduler = self._scheduler(send_alert_fn=self._noop_send_alert, alert_chat_ids=[123])
                until = datetime.now(timezone.utc) + timedelta(days=7)
                scheduler.mute_alert_push(until=until, reason="test", chat_id=123)

                restored = self._scheduler(send_alert_fn=self._noop_send_alert, alert_chat_ids=[123])
                status = restored.alert_push_status()

                self.assertTrue(status["muted"])
                self.assertIsNotNone(status["muted_until"])
            finally:
                os.chdir(old_cwd)

    def test_normalized_duration_for_current_week(self):
        now = datetime(2026, 5, 18, 10, 30, tzinfo=timezone(timedelta(hours=8)))

        until = parse_alert_mute_until("this_week", now=now)

        self.assertEqual(
            until,
            datetime(2026, 5, 25, 0, 0, tzinfo=timezone(timedelta(hours=8))),
        )

    def test_agent_tool_mutes_for_one_week(self):
        asyncio.run(self._run_agent_tool_mutes_for_one_week())

    def test_agent_tool_resumes_alert_push(self):
        asyncio.run(self._run_agent_tool_resumes_alert_push())

    def test_agent_tool_reports_disabled_sentinel(self):
        asyncio.run(self._run_agent_tool_reports_disabled_sentinel())

    def test_stop_gracefully_waits_for_current_check(self):
        asyncio.run(self._run_stop_gracefully_waits_for_current_check())

    async def _run_agent_tool_mutes_for_one_week(self):
        old_cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as temp_dir:
            os.chdir(temp_dir)
            try:
                scheduler = self._scheduler(send_alert_fn=self._noop_send_alert, alert_chat_ids=[123])
                dispatcher = ToolDispatcher(FakeSandbox())
                dispatcher.set_sentinel(scheduler)

                result = await dispatcher.dispatch(
                    "set_sentinel_alert_push_policy",
                    json.dumps(
                        {
                            "action": "mute",
                            "duration": "7d",
                            "reason": "用户要求未来一周不进行告警推送",
                        },
                        ensure_ascii=False,
                    ),
                    chat_id=123,
                )

                status = scheduler.alert_push_status()
                self.assertIn("已暂停 Sentinel 告警推送", result)
                self.assertTrue(status["muted"])
                self.assertIsNotNone(status["muted_until"])
            finally:
                os.chdir(old_cwd)

    async def _run_agent_tool_resumes_alert_push(self):
        old_cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as temp_dir:
            os.chdir(temp_dir)
            try:
                scheduler = self._scheduler(send_alert_fn=self._noop_send_alert, alert_chat_ids=[123])
                scheduler.mute_alert_push(reason="test", chat_id=123)
                dispatcher = ToolDispatcher(FakeSandbox(), sentinel=scheduler)

                result = await dispatcher.dispatch(
                    "set_sentinel_alert_push_policy",
                    json.dumps({"action": "resume", "reason": "用户要求恢复推送"}, ensure_ascii=False),
                    chat_id=123,
                )

                self.assertIn("已恢复 Sentinel 告警推送", result)
                self.assertFalse(scheduler.alert_push_status()["muted"])
            finally:
                os.chdir(old_cwd)

    async def _run_agent_tool_reports_disabled_sentinel(self):
        dispatcher = ToolDispatcher(FakeSandbox())
        result = await dispatcher.dispatch(
            "set_sentinel_alert_push_policy",
            json.dumps({"action": "mute", "duration": "manual"}, ensure_ascii=False),
            chat_id=123,
        )
        self.assertIn("Sentinel 未启用", result)

    async def _run_stop_gracefully_waits_for_current_check(self):
        started = asyncio.Event()
        release = asyncio.Event()

        async def send_alert(*args, **kwargs) -> None:
            del args, kwargs

        old_cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as temp_dir:
            os.chdir(temp_dir)
            try:
                scheduler = self._scheduler(send_alert_fn=send_alert, alert_chat_ids=[])

                async def blocking_check(check):
                    del check
                    started.set()
                    await release.wait()
                    return "✅ done"

                scheduler._run_single_check = blocking_check
                scheduler.start()
                await asyncio.wait_for(started.wait(), timeout=1)

                stop_task = asyncio.create_task(scheduler.stop_gracefully(timeout=1))
                await asyncio.sleep(0)

                self.assertFalse(stop_task.done())
                self.assertFalse(scheduler.is_running)

                release.set()
                await asyncio.wait_for(stop_task, timeout=1)

                self.assertIsNone(scheduler._task)
                self.assertFalse(scheduler.is_running)
            finally:
                os.chdir(old_cwd)

    async def _run_muted_alert_is_recorded_without_telegram_push(self):
        alerts: list[tuple[int, str]] = []

        async def send_alert(chat_id: int, text: str, alert_event=None) -> None:
            del alert_event
            alerts.append((chat_id, text))

        old_cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as temp_dir:
            os.chdir(temp_dir)
            try:
                scheduler = self._scheduler(send_alert_fn=send_alert, alert_chat_ids=[123])
                scheduler.mute_alert_push(reason="test", chat_id=123)

                pushed = await scheduler._record_and_maybe_push(_event())
                recent = scheduler.history.recent(1)

                self.assertFalse(pushed)
                self.assertEqual(alerts, [])
                self.assertFalse(recent[0].pushed)
                self.assertIn("alert_push_muted", recent[0].action_reason)

                scheduler.resume_alert_push(chat_id=123)
                pushed = await scheduler._record_and_maybe_push(_event("login2"))

                self.assertTrue(pushed)
                self.assertEqual(len(alerts), 1)
            finally:
                os.chdir(old_cwd)

    async def _run_recovery_alert_is_recorded_without_telegram_push(self):
        alerts: list[tuple[int, str]] = []

        async def send_alert(chat_id: int, text: str, alert_event=None) -> None:
            del alert_event
            alerts.append((chat_id, text))

        old_cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as temp_dir:
            os.chdir(temp_dir)
            try:
                scheduler = self._scheduler(send_alert_fn=send_alert, alert_chat_ids=[123])

                pushed = await scheduler._record_and_maybe_push(
                    _event(state="RECOVERED", previous_state="RECOVERED_CANDIDATE")
                )
                recent = scheduler.history.recent(1)

                self.assertFalse(pushed)
                self.assertEqual(alerts, [])
                self.assertFalse(recent[0].pushed)
                self.assertIn("first_seen_and_escalation_only", recent[0].action_reason)
            finally:
                os.chdir(old_cwd)

    async def _run_repeat_state_alert_is_recorded_without_telegram_push(self):
        alerts: list[tuple[int, str]] = []

        async def send_alert(chat_id: int, text: str, alert_event=None) -> None:
            del alert_event
            alerts.append((chat_id, text))

        old_cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as temp_dir:
            os.chdir(temp_dir)
            try:
                scheduler = self._scheduler(send_alert_fn=send_alert, alert_chat_ids=[123])

                pushed = await scheduler._record_and_maybe_push(
                    _event(state="NEW", previous_state="NEW")
                )
                recent = scheduler.history.recent(1)

                self.assertFalse(pushed)
                self.assertEqual(alerts, [])
                self.assertFalse(recent[0].pushed)
                self.assertIn("first_seen_and_escalation_only", recent[0].action_reason)
            finally:
                os.chdir(old_cwd)

    @staticmethod
    async def _noop_send_alert(*args, **kwargs) -> None:
        del args, kwargs

    @staticmethod
    def _scheduler(send_alert_fn, alert_chat_ids):
        return SentinelScheduler(
            config=FakeConfig(),
            pack_loader=None,
            sandbox=FakeSandbox(),
            send_alert_fn=send_alert_fn,
            alert_chat_ids=alert_chat_ids,
        )


if __name__ == "__main__":
    unittest.main()
