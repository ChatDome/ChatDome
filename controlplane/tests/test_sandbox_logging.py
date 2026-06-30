import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from chatdome.agent.audit import CommandAuditTracker
from chatdome.executor.sandbox import CommandResult, CommandSandbox
from chatdome.logger import log_origin


class SandboxLoggingTests(unittest.TestCase):
    def test_command_log_excerpt_is_single_line_and_truncated(self):
        command = "echo one\n" + ("awk '{print $1}' /var/log/auth.log; " * 20)

        excerpt = CommandSandbox._command_log_excerpt(command, max_chars=80)

        self.assertNotIn("\n", excerpt)
        self.assertLessEqual(len(excerpt), 80)
        self.assertTrue(excerpt.endswith("..."))

    def test_command_log_hash_is_stable_short_sha256_prefix(self):
        command = "journalctl -u sshd --since '-24 hours'"

        first = CommandSandbox._command_log_hash(command)
        second = CommandSandbox._command_log_hash(command)

        self.assertEqual(first, second)
        self.assertEqual(len(first), 12)

    def test_command_output_archive_can_be_enabled_for_debug(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp) / "outputs"
            audit_dir = Path(tmp) / "audit"
            sandbox = CommandSandbox(
                allow_unrestricted_commands=True,
                persist_command_outputs=True,
                command_output_dir=output_dir,
            )

            with patch("chatdome.agent.audit.AUDIT_DIR", audit_dir):
                sandbox._record_execution_audit(
                    event_type="command_executed",
                    chat_id=123,
                    tool_call_id="call-debug",
                    command="echo archive-test",
                    reason="debug archive test",
                    result=CommandResult(
                        stdout="archive-test\n",
                        stderr="",
                        return_code=0,
                        command="echo archive-test",
                    ),
                    execution_mode="unrestricted",
                    duration_ms=12,
                )

            output_files = list(output_dir.glob("*/*.json"))
            self.assertEqual(len(output_files), 1)
            payload = json.loads(output_files[0].read_text(encoding="utf-8"))
            self.assertIn("archive-test", payload["stdout"])
            self.assertEqual(payload["tool_call_id"], "call-debug")

            audit_records = [
                json.loads(line)
                for path in audit_dir.glob("audit-*.jsonl")
                for line in path.read_text(encoding="utf-8").splitlines()
            ]
            self.assertTrue(any(record.get("output_persisted") for record in audit_records))
            self.assertTrue(any(record.get("output_ref") for record in audit_records))

    def test_command_output_archive_skips_sensitive_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp) / "outputs"
            audit_dir = Path(tmp) / "audit"
            sandbox = CommandSandbox(
                allow_unrestricted_commands=True,
                persist_command_outputs=True,
                command_output_dir=output_dir,
            )

            with patch("chatdome.agent.audit.AUDIT_DIR", audit_dir):
                sandbox._record_execution_audit(
                    event_type="command_executed",
                    chat_id=123,
                    tool_call_id="call-sensitive",
                    command="echo token-value",
                    reason="sensitive archive test",
                    result=CommandResult(
                        stdout="token-value\n",
                        stderr="",
                        return_code=0,
                        command="echo token-value",
                    ),
                    execution_mode="unrestricted",
                    duration_ms=12,
                )

            self.assertEqual(list(output_dir.glob("*/*.json")), [])
            audit_records = [
                json.loads(line)
                for path in audit_dir.glob("audit-*.jsonl")
                for line in path.read_text(encoding="utf-8").splitlines()
            ]
            self.assertTrue(
                any(
                    record.get("output_skip_reason") == "sensitive_command_pattern"
                    for record in audit_records
                )
            )

    def test_sentinel_command_audit_uses_dedicated_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            audit_dir = Path(tmp) / "audit"
            sandbox = CommandSandbox(allow_unrestricted_commands=True)

            with patch("chatdome.agent.audit.AUDIT_DIR", audit_dir):
                sandbox._record_execution_audit(
                    event_type="command_executed",
                    chat_id=123,
                    tool_call_id="user-call",
                    command="whoami",
                    reason="user command",
                    result=CommandResult(
                        stdout="root\n",
                        stderr="",
                        return_code=0,
                        command="whoami",
                    ),
                    execution_mode="unrestricted",
                    duration_ms=10,
                )
                with log_origin("sentinel"):
                    sandbox._record_execution_audit(
                        event_type="security_check_executed",
                        chat_id=0,
                        tool_call_id="",
                        command="uptime",
                        reason="security_check:uptime",
                        result=CommandResult(
                            stdout="up\n",
                            stderr="",
                            return_code=0,
                            command="uptime",
                        ),
                        execution_mode="pack",
                        duration_ms=12,
                    )

                user_events = CommandAuditTracker.get_recent_events(limit=10)
                sentinel_events = CommandAuditTracker.get_recent_events(
                    limit=10,
                    audit_source="sentinel",
                )

            self.assertEqual([event.get("command") for event in user_events], ["whoami"])
            self.assertEqual([event.get("audit_source") for event in user_events], ["user"])
            self.assertEqual([event.get("command") for event in sentinel_events], ["uptime"])
            self.assertEqual([event.get("audit_source") for event in sentinel_events], ["sentinel"])
            self.assertEqual(len(list(audit_dir.glob("audit-*.jsonl"))), 1)
            self.assertEqual(len(list(audit_dir.glob("sentinel-commands-*.jsonl"))), 1)


if __name__ == "__main__":
    unittest.main()
