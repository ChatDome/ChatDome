import unittest

from chatdome.agent.result import AgentResult, coerce_agent_result


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


if __name__ == "__main__":
    unittest.main()
