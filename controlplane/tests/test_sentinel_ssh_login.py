import asyncio
import os
import tempfile
import unittest
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Union

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


class FakePackLoader:
    def __init__(self, command_ids: set[str]):
        self.command_ids = command_ids

    def get_command(self, check_id: str):
        return object() if check_id in self.command_ids else None


class RoutingFakeSandbox:
    def __init__(self, outputs: dict[str, Union[list[str], str]]):
        self.outputs: dict[str, list[str]] = {
            key: list(value) if isinstance(value, list) else [value]
            for key, value in outputs.items()
        }
        self.calls: list[tuple[str, Optional[dict]]] = []

    async def execute_security_check(self, check_id: str, args=None):
        self.calls.append((check_id, args))
        values = self.outputs.get(check_id, [""])
        if len(values) > 1:
            stdout = values.pop(0)
        else:
            stdout = values[0]
        self.outputs[check_id] = values
        return FakeCommandResult(stdout=stdout)


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


class PatrolConfig:
    alert_retention_days = 30
    global_rate_limit = 100
    global_rate_window = 300
    learning_rounds = 0
    checks = [
        {
            "name": "SSH session command patrol",
            "check_id": "ssh_session_commands_patrol",
            "interval": 900,
            "mode": "differential",
            "args": {"tracking_window_hours": 1, "limit": 50},
            "severity": 7,
            "rule": {"type": "added_count", "operator": ">", "threshold": 0},
        }
    ]


class SentinelSSHLoginRegressionTests(unittest.TestCase):
    def test_repeated_new_ssh_success_login_deltas_are_pushed(self):
        asyncio.run(self._run_repeated_new_ssh_success_login_deltas_are_pushed())

    def test_batch_ssh_success_login_delta_escalates_by_line_count(self):
        asyncio.run(self._run_batch_ssh_success_login_delta_escalates_by_line_count())

    def test_ssh_success_login_enriches_with_audit_session_commands(self):
        asyncio.run(self._run_ssh_success_login_enriches_with_audit_session_commands())

    def test_ssh_success_fingerprint_includes_sshd_pid(self):
        scheduler = SentinelScheduler(
            config=FakeConfig(),
            pack_loader=None,
            sandbox=FakeSandbox([]),
            send_alert_fn=lambda *args, **kwargs: None,
            alert_chat_ids=[],
        )
        fingerprints = scheduler._build_fingerprints(
            check_key="ssh_success_login",
            alert_output="Apr 23 10:01:00 root 203.0.113.10 22 publickey sshd_pid=12345",
            now=datetime.now(),
        )
        self.assertEqual(fingerprints, {"203.0.113.10|root|22|12345"})

    def test_ssh_session_commands_patrol_alerts_only_on_new_commands(self):
        asyncio.run(self._run_ssh_session_commands_patrol_alerts_only_on_new_commands())

    async def _run_repeated_new_ssh_success_login_deltas_are_pushed(self):
        baseline = "Apr 23 10:00:00 root 203.0.113.10 22 publickey\n"
        first_delta = baseline + "Apr 23 10:01:00 root 203.0.113.10 22 publickey\n"
        second_delta = first_delta + "Apr 23 10:02:00 root 203.0.113.10 22 publickey\n"
        alerts: list[tuple[int, str]] = []

        async def send_alert(chat_id: int, text: str, alert_event=None) -> None:
            del alert_event
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

    async def _run_ssh_success_login_enriches_with_audit_session_commands(self):
        baseline = "Apr 23 10:00:00 root 203.0.113.10 22 publickey sshd_pid=11111\n"
        delta_line = "Apr 23 10:01:00 root 203.0.113.10 22 publickey sshd_pid=12345"
        first_delta = baseline + delta_line + "\n"
        alerts: list[tuple[int, str]] = []

        async def send_alert(chat_id: int, text: str, alert_event=None) -> None:
            del alert_event
            alerts.append((chat_id, text))

        sandbox = RoutingFakeSandbox(
            {
                "ssh_success_login": [baseline, first_delta],
                "auditd_status": "=== auditd installed ===\nYES\n=== execve rules ===\n-a always,exit -S execve\n",
                "ssh_audit_session_for_pid": "ses=101\n",
                "ssh_session_commands": "whoami\ncat /etc/passwd\n",
            }
        )
        pack_loader = FakePackLoader(
            {"auditd_status", "ssh_audit_session_for_pid", "ssh_session_commands"}
        )

        old_cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as temp_dir:
            os.chdir(temp_dir)
            try:
                scheduler = SentinelScheduler(
                    config=FakeConfig(),
                    pack_loader=pack_loader,
                    sandbox=sandbox,
                    send_alert_fn=send_alert,
                    alert_chat_ids=[123],
                )
                check = scheduler.checks[0]

                await scheduler._run_single_check(check)
                result = await scheduler._run_single_check(check)

                self.assertIn("pushed", result)
                self.assertEqual(len(alerts), 1)
                self.assertIn("会话命令追踪:", alerts[0][1])
                self.assertIn("ses=101", alerts[0][1])
                self.assertIn("cat /etc/passwd", alerts[0][1])

                event = scheduler.history.recent(1)[0]
                sessions = event.context["ssh_sessions"]
                self.assertEqual(sessions[0]["sshd_pid"], "12345")
                self.assertEqual(sessions[0]["audit_session_id"], "101")
                self.assertEqual(sessions[0]["commands"], ["whoami", "cat /etc/passwd"])
            finally:
                os.chdir(old_cwd)

    async def _run_ssh_session_commands_patrol_alerts_only_on_new_commands(self):
        active_sessions = (
            "=== Active SSH Sessions ===\n"
            "user=root tty=pts/0 from=203.0.113.10 idle=0.00s cmd=bash\n"
            "\n"
            "=== sshd Session PIDs ===\n"
            "12345 1 root Tue Apr 28 10:00:00 2026 sshd: root@pts/0\n"
        )
        alerts: list[tuple[int, str]] = []

        async def send_alert(chat_id: int, text: str, alert_event=None) -> None:
            del alert_event
            alerts.append((chat_id, text))

        sandbox = RoutingFakeSandbox(
            {
                "auditd_status": "=== auditd installed ===\nYES\n=== execve rules ===\n-a always,exit -S execve\n",
                "ssh_active_sessions": active_sessions,
                "ssh_audit_session_for_pid": "ses=101\n",
                "ssh_session_commands": ["whoami\n", "whoami\niptables -F\n"],
            }
        )
        pack_loader = FakePackLoader(
            {"auditd_status", "ssh_active_sessions", "ssh_audit_session_for_pid", "ssh_session_commands"}
        )

        old_cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as temp_dir:
            os.chdir(temp_dir)
            try:
                scheduler = SentinelScheduler(
                    config=PatrolConfig(),
                    pack_loader=pack_loader,
                    sandbox=sandbox,
                    send_alert_fn=send_alert,
                    alert_chat_ids=[123],
                )
                check = scheduler.checks[0]

                first_result = await scheduler._run_single_check(check)
                second_result = await scheduler._run_single_check(check)

                self.assertTrue(first_result.startswith("BASELINE_INIT:"))
                self.assertIn("pushed", second_result)
                self.assertEqual(len(alerts), 1)
                self.assertIn("root@203.0.113.10:22 (ses=101, sshd PID=12345)", alerts[0][1])
                self.assertIn("iptables -F", alerts[0][1])

                event = scheduler.history.recent(1)[0]
                updates = event.context["ssh_command_updates"]
                self.assertEqual(updates[0]["added_commands"], ["iptables -F"])
            finally:
                os.chdir(old_cwd)

    async def _run_batch_ssh_success_login_delta_escalates_by_line_count(self):
        baseline = "Apr 23 10:00:00 root 203.0.113.10 22 publickey\n"
        burst = baseline + "".join(
            f"Apr 23 10:0{i}:00 root 203.0.113.10 22 publickey\n"
            for i in range(1, 6)
        )
        alerts: list[tuple[int, str]] = []

        async def send_alert(chat_id: int, text: str, alert_event=None) -> None:
            del alert_event
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
