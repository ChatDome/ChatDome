import unittest

from chatdome.sentinel.alerter import AlertEvent, format_alert_detail, format_alert_message


class AlertFormatTests(unittest.TestCase):
    def _event(
        self,
        state: str,
        previous: str = "",
        fingerprint: str = "",
        check_id: str = "open_ports",
        check_name: str = "新增监听端口",
        rule: str = "state transition test",
        raw_output: str = "0.0.0.0:8080 (python:1234)",
        current_value=3,
    ) -> AlertEvent:
        return AlertEvent(
            timestamp="2026-04-22 21:00:00",
            check_name=check_name,
            check_id=check_id,
            mode="differential",
            severity=8,
            severity_label="high",
            rule=rule,
            current_value=current_value,
            raw_output=raw_output,
            pushed=True,
            suppressed=False,
            action_reason="",
            alert_state=state,
            previous_state=previous,
            fingerprint=fingerprint,
        )

    def test_generic_card_uses_operator_facing_sections(self):
        msg = format_alert_message(
            self._event(
                state="ESCALATED_L2",
                previous="ESCALATED_L1",
                fingerprint="1.2.3.4|22|unknown|failed",
            )
        )
        self.assertIn("告警时间:", msg)
        self.assertIn("📈 威胁加剧，已升级至二级", msg)
        self.assertIn("💡 请确认监听端口变化是否符合预期，并排查未知服务。", msg)
        self.assertNotIn("[DEBUG]", msg)
        self.assertNotIn("当前值:", msg)
        self.assertNotIn("指纹:", msg)
        self.assertNotIn("原始数据:", msg)
        self.assertNotIn("发生了什么", msg)
        self.assertNotIn("需要关注", msg)
        self.assertNotIn("建议处理", msg)

    def test_new_state_omits_default_suggestion(self):
        msg = format_alert_message(self._event(state="NEW"))
        self.assertIn("🆕 首次检测到该威胁", msg)
        self.assertNotIn("先确认是否为已知变更或可信来源", msg)
        self.assertNotIn("[DEBUG]", msg)

    def test_recovered_state_omits_archive_suggestion(self):
        msg = format_alert_message(self._event(state="RECOVERED", previous="RECOVERED_CANDIDATE"))
        self.assertIn("✅ 威胁已归档", msg)
        self.assertIn("💡 无需操作，持续观察。", msg)
        self.assertNotIn("固化长期防护策略", msg)
        self.assertNotIn("[DEBUG]", msg)

    def test_alert_detail_uses_readable_transition_without_internal_reason(self):
        detail = format_alert_detail(
            self._event(
                state="ESCALATED_L2",
                previous="ESCALATED_L1",
                rule="line count >= 12",
            ).to_dict()
        )

        self.assertIn("威胁阶段: 二级升级", detail)
        self.assertIn("状态迁移: 一级升级 → 二级升级", detail)
        self.assertIn("触发规则: line count >= 12", detail)
        self.assertNotIn("阶段风险", detail)
        self.assertNotIn("state_transition (", detail)

    def test_alert_detail_without_state_returns_unavailable_message(self):
        self.assertEqual(format_alert_detail({"alert_state": ""}), "暂无详细状态信息。")

    def test_ssh_failed_burst_focuses_on_source_ips(self):
        msg = format_alert_message(
            self._event(
                state="ESCALATED_L1",
                check_id="ssh_failed_burst",
                check_name="SSH 短时多次失败登录告警（3分钟）",
                rule="line count >= 10",
                current_value=12,
                raw_output=(
                    "Apr 23 10:10:16 host sshd[1]: Failed password for root "
                    "from 45.77.105.217 port 49768 ssh2\n"
                    "Apr 23 10:11:23 host sshd[2]: Failed password for root "
                    "from 45.77.105.217 port 49769 ssh2\n"
                    "Apr 23 10:11:37 host sshd[3]: Failed password for admin "
                    "from 114.246.239.136 port 51980 ssh2"
                ),
            )
        )

        self.assertIn("数量: 12", msg)
        self.assertIn("失败来源 IP: 45.77.105.217 (2次), 114.246.239.136 (1次)", msg)
        self.assertIn("相关用户: root, admin", msg)
        self.assertIn("📈 威胁持续，已升级至一级", msg)
        self.assertIn("💡 请检查来源 IP；确认持续攻击后封禁来源或启用 fail2ban。", msg)
        self.assertIn("失败记录:", msg)
        self.assertIn("时间: Apr 23 10:10:16, Apr 23 10:11:23, Apr 23 10:11:37", msg)
        self.assertNotIn("line count >= 10", msg)
        self.assertNotIn("[DEBUG]", msg)
        self.assertNotIn("原始数据", msg)
        self.assertNotIn("指纹:", msg)
        self.assertNotIn("发生了什么", msg)
        self.assertNotIn("需要关注", msg)
        self.assertNotIn("建议处理", msg)
        self.assertNotIn(" 至 ", msg)

    def test_ssh_success_login_focuses_on_login_details(self):
        msg = format_alert_message(
            self._event(
                state="NEW",
                check_id="ssh_success_login",
                check_name="SSH 成功登录告警",
                current_value=2,
                raw_output=(
                    "Apr 23 10:11:29 root 114.246.239.136 51979 publickey\n"
                    "Apr 23 10:11:37 root 114.246.239.136 51980 publickey"
                ),
            )
        )

        self.assertIn("数量: 2", msg)
        self.assertIn("登录来源 IP: 114.246.239.136 (2次)", msg)
        self.assertIn("🆕 首次检测到该威胁", msg)
        self.assertIn("💡 请确认登录是否为本人操作", msg)
        self.assertIn("相关用户: root", msg)
        self.assertIn("登录方式: publickey", msg)
        self.assertIn("root@114.246.239.136", msg)
        self.assertIn("登录记录:", msg)
        self.assertIn("时间: Apr 23 10:11:29, Apr 23 10:11:37", msg)
        self.assertNotIn("当前值", msg)
        self.assertNotIn("原始数据", msg)
        self.assertNotIn("指纹:", msg)
        self.assertNotIn("发生了什么", msg)
        self.assertNotIn("需要关注", msg)
        self.assertNotIn("建议处理", msg)
        self.assertNotIn(" 至 ", msg)
        self.assertLess(msg.index("💡"), msg.index("登录来源 IP:"))

    def test_ssh_success_login_appends_session_command_summary(self):
        event = self._event(
            state="NEW",
            check_id="ssh_success_login",
            check_name="SSH 成功登录告警",
            current_value=1,
            raw_output="Apr 23 10:11:29 root 114.246.239.136 22 publickey sshd_pid=12345",
        )
        event.context = {
            "ssh_sessions": [
                {
                    "user": "root",
                    "ip": "114.246.239.136",
                    "port": "22",
                    "sshd_pid": "12345",
                    "audit_session_id": "101",
                    "tracking_status": "ok",
                    "commands": ["whoami", "cat /etc/passwd"],
                }
            ]
        }

        msg = format_alert_message(event)

        self.assertIn("会话命令追踪:", msg)
        self.assertIn("root@114.246.239.136:22 (ses=101, sshd PID=12345)", msg)
        self.assertIn("- cat /etc/passwd", msg)

    def test_ssh_session_commands_patrol_formats_command_delta(self):
        event = self._event(
            state="NEW",
            check_id="ssh_session_commands_patrol",
            check_name="SSH 会话命令巡检",
            current_value=2,
            raw_output="",
        )
        event.context = {
            "ssh_command_updates": [
                {
                    "user": "root",
                    "ip": "203.0.113.10",
                    "port": "22",
                    "sshd_pid": "12345",
                    "audit_session_id": "101",
                    "added_commands": ["iptables -F", "chmod 777 /tmp/exploit"],
                }
            ]
        }

        msg = format_alert_message(event)

        self.assertIn("新增命令: 2", msg)
        self.assertIn("💡 请确认新增命令是否为授权操作。", msg)
        self.assertIn("命令增量:", msg)
        self.assertIn("root@203.0.113.10:22 (ses=101, sshd PID=12345)", msg)
        self.assertIn("iptables -F", msg)
        self.assertIn("检测到防火墙规则清理行为", msg)


if __name__ == "__main__":
    unittest.main()
