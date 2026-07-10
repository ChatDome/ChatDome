import unittest

from chatdome.agent.result import AgentResult, coerce_agent_result, format_approval_purpose


class AgentResultTests(unittest.TestCase):
    def test_structured_result_is_preserved(self):
        result = AgentResult.round_limit({"rounds": 10})

        coerced = coerce_agent_result(result)

        self.assertIs(coerced, result)
        self.assertEqual(coerced.kind, "round_limit")
        self.assertEqual(coerced.payload["rounds"], 10)

    def test_legacy_pending_approval_string_is_supported(self):
        result = coerce_agent_result('__PENDING_APPROVAL__:{"approval_id":"AP-1"}')

        self.assertEqual(result.kind, "pending_approval")
        self.assertEqual(result.payload["approval_id"], "AP-1")

    def test_plain_string_becomes_reply(self):
        result = coerce_agent_result("hello")

        self.assertEqual(result.kind, "reply")
        self.assertEqual(result.content, "hello")

    def test_approval_purpose_is_normalized_and_truncated(self):
        purpose = format_approval_purpose(
            {"reason": "  restart   the SSH service " + "safely " * 30},
            fallback="unavailable",
            max_chars=48,
        )

        self.assertLessEqual(len(purpose), 48)
        self.assertTrue(purpose.startswith("restart the SSH service safely"))
        self.assertTrue(purpose.endswith("…"))

    def test_approval_purpose_uses_actionable_fallback(self):
        purpose = format_approval_purpose(
            {"reason": "无说明"},
            fallback="review details before approval",
        )

        self.assertEqual(purpose, "review details before approval")


if __name__ == "__main__":
    unittest.main()
