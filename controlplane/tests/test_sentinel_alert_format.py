import unittest

from chatdome.sentinel.alerter import AlertEvent, format_alert_message


class AlertFormatTests(unittest.TestCase):
    def _event(self, state: str, previous: str = "", fingerprint: str = "") -> AlertEvent:
        return AlertEvent(
            timestamp="2026-04-22 21:00:00",
            check_name="SSH 新访问来源检测",
            check_id="ssh_bruteforce",
            mode="differential",
            severity=8,
            severity_label="high",
            rule="state transition test",
            current_value=3,
            raw_output="1.2.3.4",
            pushed=True,
            suppressed=False,
            suppression_reason="",
            alert_state=state,
            previous_state=previous,
            fingerprint=fingerprint,
        )

    def test_card_contains_fixed_sections(self):
        msg = format_alert_message(
            self._event(
                state="ESCALATED_L2",
                previous="ESCALATED_L1",
                fingerprint="1.2.3.4|22|unknown|failed",
            )
        )
        self.assertIn("状态告警卡片", msg)
        self.assertIn("- 状态:", msg)
        self.assertIn("- 依据:", msg)
        self.assertIn("- 风险:", msg)
        self.assertIn("- 建议:", msg)
        self.assertIn("- 下一观察点:", msg)
        self.assertIn("- 指纹:", msg)

    def test_new_state_has_default_suggestion(self):
        msg = format_alert_message(self._event(state="NEW"))
        self.assertIn("新威胁首次出现", msg)
        self.assertIn("先确认是否为已知变更或可信来源", msg)

    def test_recovered_state_has_archive_hint(self):
        msg = format_alert_message(self._event(state="RECOVERED", previous="RECOVERED_CANDIDATE"))
        self.assertIn("观察期通过，威胁归档", msg)
        self.assertIn("固化长期防护策略", msg)


if __name__ == "__main__":
    unittest.main()