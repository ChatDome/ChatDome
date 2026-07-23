from __future__ import annotations

import unittest

from chatdome.agent.result import AgentResult
from chatdome.outbound.builders import (
    OutboundMessageBuilder,
    build_approval_details,
    build_approval_request,
    build_sentinel_alert,
)
from chatdome.outbound.models import ActionKind, OutboundMessageKind
from chatdome.outbound.policy import OutboundContractError, validate_outbound_message
from chatdome.outbound.renderers.plaintext import PlainTextOutboundRenderer
from chatdome.outbound.renderers.telegram import TelegramOutboundRenderer, group_controls
from chatdome.outbound.renderers.terminal import TerminalOutboundRenderer


class OutboundMessageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.request_payload = {
            "approval_id": "AP-1",
            "run_id": "RUN-1",
            "command": "systemctl restart sshd",
            "command_hash": "abcdef1234567890",
            "reason": "Restart the SSH service.",
            "impact_analysis": "Existing SSH sessions may be interrupted briefly.",
            "risk_level": "HIGH",
            "safety_status": "NEEDS_APPROVAL",
            "mutation_detected": True,
            "deletion_detected": False,
            "requires_detail_expansion": True,
        }

    def test_approval_request_maps_legacy_payload_to_typed_facts(self):
        message = build_approval_request(self.request_payload)

        self.assertEqual(message.kind, OutboundMessageKind.APPROVAL_REQUEST)
        self.assertEqual(message.status, "approval_required")
        self.assertEqual(message.outcome, "approval_requested")
        self.assertEqual(message.refs["approval_id"], "AP-1")
        self.assertEqual(message.facts.reason, "Restart the SSH service.")
        self.assertEqual(message.facts.impact_analysis, self.request_payload["impact_analysis"])
        self.assertEqual(message.facts.safety_status, "NEEDS_APPROVAL")
        self.assertTrue(message.facts.mutation_detected)
        self.assertFalse(message.facts.deletion_detected)
        self.assertEqual(
            {action.kind for action in message.actions},
            {
                ActionKind.APPROVE,
                ActionKind.APPROVE_TASK,
                ActionKind.REJECT,
                ActionKind.SHOW_DETAILS,
            },
        )
        self.assertTrue(all(action.token == "AP-1" for action in message.actions))
        self.assertTrue(all(action.params["approval_id"] == "AP-1" for action in message.actions))
        validate_outbound_message(message)

    def test_missing_reason_blocks_approval_controls(self):
        payload = dict(self.request_payload, reason="无说明")
        message = build_approval_request(payload)

        self.assertNotIn(ActionKind.APPROVE, {action.kind for action in message.actions})
        self.assertNotIn(ActionKind.APPROVE_TASK, {action.kind for action in message.actions})
        self.assertIn(ActionKind.REJECT, {action.kind for action in message.actions})
        self.assertIn(ActionKind.SHOW_DETAILS, {action.kind for action in message.actions})
        terminal = TerminalOutboundRenderer().render(message).text_parts[0]
        plaintext = PlainTextOutboundRenderer().render(message).text_parts[0]
        self.assertIn("n=reject", terminal)
        self.assertNotIn("Allow operation", terminal)
        self.assertIn("/reject AP-1", plaintext)
        self.assertNotIn("/confirm AP-1", plaintext)
        with self.assertRaises(OutboundContractError):
            validate_outbound_message(message)

    def test_missing_approval_id_blocks_all_controls(self):
        payload = dict(self.request_payload)
        payload.pop("approval_id")
        message = build_approval_request(payload)

        self.assertEqual(message.actions, ())
        with self.assertRaises(OutboundContractError):
            validate_outbound_message(message)

    def test_request_renderers_share_purpose_without_exposing_command(self):
        message = build_approval_request(self.request_payload)
        terminal = TerminalOutboundRenderer().render(message).text_parts[0]
        telegram = TelegramOutboundRenderer().render(message)
        plaintext = PlainTextOutboundRenderer().render(message).text_parts[0]

        for text in (terminal, telegram.text_parts[0], plaintext):
            self.assertIn("Restart the SSH service.", text)
            self.assertNotIn("systemctl restart sshd", text)
        rows = group_controls(telegram.controls)
        self.assertEqual([control.label for control in rows[1]], ["❌ 拒绝", "🔎 命令分析"])
        self.assertEqual(rows[1][1].data, "approval:details:AP-1")

    def test_details_renderers_follow_cli_semantic_order(self):
        details = {
            "ok": True,
            **self.request_payload,
            "analysis": {
                "risk_level": "HIGH",
                "safety_status": "UNSAFE",
                "mutation_detected": True,
                "deletion_detected": False,
                "impact_analysis": "Existing SSH sessions may be interrupted briefly.",
                "command_breakdown": {
                    "tokens": [
                        {"token": "systemctl", "label": "命令", "meaning": "控制系统服务"},
                        {"token": "restart", "label": "子命令", "meaning": "重启服务"},
                        {"token": "sshd", "label": "目标服务", "meaning": "将被操作的服务"},
                    ],
                    "warnings": ["会改变服务运行状态"],
                },
            },
        }
        message = build_approval_details(details)
        terminal = TerminalOutboundRenderer().render(message).text_parts[0]
        telegram = TelegramOutboundRenderer().render(message).text_parts[0]

        self.assertLess(terminal.index("Risk:"), terminal.index("Command:"))
        self.assertLess(terminal.index("Command:"), terminal.index("Impact:"))
        self.assertIn("Flags: modifies system", terminal)
        self.assertLess(telegram.index("安全评估"), telegram.index("📋 命令"))
        self.assertLess(telegram.index("📋 命令"), telegram.index("影响说明"))
        self.assertIn("标记: 修改系统", telegram)
        self.assertIn("命令解析:", terminal)
        self.assertIn("命令解析:", telegram)

    def test_details_renderers_group_semicolon_separated_commands(self):
        details = {
            "ok": True,
            **self.request_payload,
            "command": "cd /srv; systemctl restart chatdome",
            "analysis": {
                "risk_level": "HIGH",
                "safety_status": "UNSAFE",
                "mutation_detected": True,
                "deletion_detected": False,
                "impact_analysis": "Switches directory and restarts ChatDome.",
                "command_breakdown": {
                    "summary": "切换目录并重启服务",
                    "commands": [
                        {
                            "index": 1,
                            "command": "cd /srv",
                            "separator": ";",
                            "summary": "切换工作目录",
                            "tokens": [
                                {"token": "cd", "label": "命令", "meaning": "切换目录"},
                                {"token": "/srv", "label": "目标目录", "meaning": "工作目录"},
                            ],
                            "warnings": [],
                        },
                        {
                            "index": 2,
                            "command": "systemctl restart chatdome",
                            "separator": "",
                            "summary": "重启服务",
                            "tokens": [
                                {"token": "systemctl", "label": "命令", "meaning": "控制系统服务"},
                                {"token": "restart", "label": "子命令", "meaning": "重启服务"},
                                {"token": "chatdome", "label": "目标服务", "meaning": "将被操作的服务"},
                            ],
                            "warnings": ["服务会短暂中断"],
                        },
                    ],
                    "tokens": [],
                    "warnings": ["服务会短暂中断"],
                },
            },
        }

        message = build_approval_details(details)
        terminal = TerminalOutboundRenderer().render(message).text_parts[0]
        telegram = TelegramOutboundRenderer().render(message).text_parts[0]

        self.assertEqual(len(message.facts.command_groups), 2)
        for text in (terminal, telegram):
            self.assertIn("[1] cd /srv", text)
            self.assertIn("[2] systemctl restart chatdome", text)
            self.assertLess(text.index("[1] cd /srv"), text.index("[2] systemctl restart chatdome"))
            self.assertEqual(text.count("服务会短暂中断"), 1)
    def test_sentinel_alert_uses_notification_facts_and_actions(self):
        message = build_sentinel_alert(
            "Critical alert",
            {"check_id": "open_ports", "severity_label": "critical", "severity": 9},
            interaction_id="ALERT-1",
        )

        self.assertEqual(message.kind, OutboundMessageKind.NOTIFICATION)
        self.assertEqual(message.status, "attention_required")
        self.assertEqual(message.outcome, "alert_pushed")
        self.assertEqual(message.refs["interaction_id"], "ALERT-1")
        self.assertEqual(message.refs["check_id"], "open_ports")
        self.assertEqual(message.facts["alert"]["severity"], 9)
        self.assertEqual(
            [action.kind for action in message.actions],
            [ActionKind.SHOW_DETAILS, ActionKind.ANALYZE],
        )
        self.assertTrue(
            all(action.params["interaction_id"] == "ALERT-1" for action in message.actions)
        )
        rendered = TelegramOutboundRenderer().render(message)
        self.assertEqual(
            [control.data for control in rendered.controls],
            [
                "sentinel_alert_detail:ALERT-1",
                "sentinel_alert_analysis:ALERT-1",
            ],
        )
        self.assertTrue(all(control.row == 0 for control in rendered.controls))

    def test_round_limit_maps_to_task_paused(self):
        message = OutboundMessageBuilder().from_agent_result(
            AgentResult.round_limit({"rounds": 10, "window": 10, "run_id": "RUN-1"})
        )

        self.assertEqual(message.kind, OutboundMessageKind.TASK_PAUSED)
        self.assertEqual(
            [action.kind for action in message.actions],
            [ActionKind.CONTINUE, ActionKind.STOP],
        )
        self.assertEqual(message.status, "continuation_required")
        self.assertEqual(message.outcome, "round_limit")
        self.assertTrue(all(action.params["run_id"] == "RUN-1" for action in message.actions))


if __name__ == "__main__":
    unittest.main()
