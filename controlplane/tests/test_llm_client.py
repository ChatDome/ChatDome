import unittest
from types import SimpleNamespace

from chatdome.llm.client import LLMClient


class LLMClientResponseTests(unittest.TestCase):
    def test_parse_response_preserves_finish_reason(self):
        response = SimpleNamespace(
            choices=[
                SimpleNamespace(
                    finish_reason="length",
                    message=SimpleNamespace(content="{}", tool_calls=None),
                )
            ],
            usage=SimpleNamespace(
                prompt_tokens=10,
                completion_tokens=20,
                total_tokens=30,
            ),
        )

        parsed = object.__new__(LLMClient)._parse_response(response)

        self.assertEqual(parsed.finish_reason, "length")

    def test_parse_response_defaults_missing_finish_reason(self):
        response = SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(content="{}", tool_calls=None),
                )
            ],
            usage=None,
        )

        parsed = object.__new__(LLMClient)._parse_response(response)

        self.assertEqual(parsed.finish_reason, "")


if __name__ == "__main__":
    unittest.main()
