import asyncio
import os
import tempfile
import unittest
from dataclasses import dataclass

from chatdome.sentinel.scheduler import SentinelScheduler


@dataclass
class FakeCommandResult:
    stdout: str
    stderr: str = ""
    return_code: int = 0
    timed_out: bool = False


class FakeSandbox:
    def __init__(self, outputs: list[str]):
        self.outputs = list(outputs)

    async def execute_security_check(self, check_id: str, args=None):
        del check_id, args
        return FakeCommandResult(stdout=self.outputs.pop(0))


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


class SentinelSSHLoginRegressionTests(unittest.TestCase):
    def test_repeated_new_ssh_success_login_deltas_are_pushed(self):
        asyncio.run(self._run_repeated_new_ssh_success_login_deltas_are_pushed())

    def test_batch_ssh_success_login_delta_escalates_by_line_count(self):
        asyncio.run(self._run_batch_ssh_success_login_delta_escalates_by_line_count())

    async def _run_repeated_new_ssh_success_login_deltas_are_pushed(self):
        baseline = "Apr 23 10:00:00 root 203.0.113.10 22 publickey\n"
        first_delta = baseline + "Apr 23 10:01:00 root 203.0.113.10 22 publickey\n"
        second_delta = first_delta + "Apr 23 10:02:00 root 203.0.113.10 22 publickey\n"
        alerts: list[tuple[int, str]] = []

        async def send_alert(chat_id: int, text: str) -> None:
            alerts.append((chat_id, text))

        old_cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as temp_dir:
            os.chdir(temp_dir)
            try:
                scheduler = SentinelScheduler(
                    config=FakeConfig(),
                    pack_loader=None,
                    sandbox=FakeSandbox([baseline, first_delta, second_delta]),
                    send_alert_fn=send_alert,
                    alert_chat_ids=[123],
                )
                check = scheduler.checks[0]

                baseline_result = await scheduler._run_single_check(check)
                first_result = await scheduler._run_single_check(check)
                second_result = await scheduler._run_single_check(check)

                self.assertTrue(baseline_result.startswith("BASELINE_INIT:"))
                self.assertIn("pushed", first_result)
                self.assertIn("pushed", second_result)
                self.assertEqual(len(alerts), 2)

                events = scheduler.history.recent(2)
                self.assertEqual(events[0].action_reason[:16], "state_transition")
                self.assertEqual(events[1].action_reason, "repeat_event")
                self.assertFalse(events[1].suppressed)
            finally:
                os.chdir(old_cwd)

    async def _run_batch_ssh_success_login_delta_escalates_by_line_count(self):
        baseline = "Apr 23 10:00:00 root 203.0.113.10 22 publickey\n"
        burst = baseline + "".join(
            f"Apr 23 10:0{i}:00 root 203.0.113.10 22 publickey\n"
            for i in range(1, 6)
        )
        alerts: list[tuple[int, str]] = []

        async def send_alert(chat_id: int, text: str) -> None:
            alerts.append((chat_id, text))

        old_cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as temp_dir:
            os.chdir(temp_dir)
            try:
                scheduler = SentinelScheduler(
                    config=FakeConfig(),
                    pack_loader=None,
                    sandbox=FakeSandbox([baseline, burst]),
                    send_alert_fn=send_alert,
                    alert_chat_ids=[123],
                )
                check = scheduler.checks[0]

                await scheduler._run_single_check(check)
                burst_result = await scheduler._run_single_check(check)

                self.assertIn("pushed", burst_result)
                self.assertEqual(len(alerts), 1)

                event = scheduler.history.recent(1)[0]
                self.assertEqual(event.alert_state, "ESCALATED_L1")
                self.assertEqual(event.current_value, 5)
                self.assertIn("state_transition", event.action_reason)
            finally:
                os.chdir(old_cwd)


if __name__ == "__main__":
    unittest.main()
