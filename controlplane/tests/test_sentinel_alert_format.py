import unittest

from chatdome.sentinel.alerter import AlertEvent, format_alert_message


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
        self.assertIn("发生了什么:", msg)
        self.assertIn("威胁状态:", msg)
        self.assertIn("风险判断:", msg)
        self.assertIn("触发原因:", msg)
        self.assertIn("建议处理:", msg)
        self.assertIn("下一观察点:", msg)
        self.assertNotIn("当前值:", msg)
        self.assertNotIn("指纹:", msg)
        self.assertNotIn("原始数据:", msg)

    def test_new_state_has_default_suggestion(self):
        msg = format_alert_message(self._event(state="NEW"))
        self.assertIn("新威胁首次出现", msg)
        self.assertIn("先确认是否为已知变更或可信来源", msg)

    def test_recovered_state_has_archive_hint(self):
        msg = format_alert_message(self._event(state="RECOVERED", previous="RECOVERED_CANDIDATE"))
        self.assertIn("观察期通过，威胁归档", msg)
        self.assertIn("固化长期防护策略", msg)

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

        self.assertIn("检测到 12 次 SSH 登录失败", msg)
        self.assertIn("失败来源 IP: 45.77.105.217 (2次), 114.246.239.136 (1次)", msg)
        self.assertIn("相关用户: root, admin", msg)
        self.assertIn("样例记录:", msg)
        self.assertNotIn("line count", msg)
        self.assertNotIn("原始数据", msg)
        self.assertNotIn("指纹", msg)

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

        self.assertIn("检测到 2 次新增 SSH 成功登录", msg)
        self.assertIn("登录来源 IP: 114.246.239.136 (2次)", msg)
        self.assertIn("相关用户: root", msg)
        self.assertIn("登录方式: publickey", msg)
        self.assertIn("root@114.246.239.136:51979", msg)
        self.assertNotIn("当前值", msg)
        self.assertNotIn("原始数据", msg)
        self.assertNotIn("指纹", msg)


if __name__ == "__main__":
    unittest.main()
