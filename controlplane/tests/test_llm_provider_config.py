import asyncio
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from chatdome.config import load_config
from chatdome.llm.codex_cli import CodexCLIClient
from chatdome.llm.client import LLMResponse


class LLMProviderConfigTests(unittest.TestCase):
    def test_codex_cli_mode_does_not_require_api_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.yaml"
            config_path.write_text(
                """
chatdome:
  ai:
    provider: codex
    api_mode: codex_cli
    model: gpt-5.4
    codex_validate_auth: false
""",
                encoding="utf-8",
            )

            with patch.dict(os.environ, {"CHATDOME_BOT_TOKEN": "telegram-token"}, clear=True):
                config = load_config(config_path)

        self.assertEqual(config.ai.provider, "codex")
        self.assertEqual(config.ai.api_mode, "codex_cli")
        self.assertEqual(config.ai.model, "gpt-5.4")

    def test_openai_api_mode_still_requires_api_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.yaml"
            config_path.write_text(
                """
chatdome:
  ai:
    provider: openai
    api_mode: openai_api
""",
                encoding="utf-8",
            )

            with patch.dict(os.environ, {"CHATDOME_BOT_TOKEN": "telegram-token"}, clear=True):
                with self.assertRaisesRegex(ValueError, "AI API Key"):
                    load_config(config_path)

    def test_env_can_select_codex_cli_mode(self):
        env = {
            "CHATDOME_BOT_TOKEN": "telegram-token",
            "CHATDOME_AI_PROVIDER": "codex",
            "CHATDOME_AI_API_MODE": "codex_cli",
            "CHATDOME_AI_MODEL": "gpt-5.4",
            "CHATDOME_CODEX_VALIDATE_AUTH": "false",
        }

        with patch.dict(os.environ, env, clear=True):
            config = load_config("missing-config.yaml")

        self.assertEqual(config.ai.provider, "codex")
        self.assertEqual(config.ai.api_mode, "codex_cli")
        self.assertEqual(config.ai.model, "gpt-5.4")
        self.assertFalse(config.ai.codex_validate_auth)


class CodexCLIResponseParsingTests(unittest.TestCase):
    def test_parse_synthetic_tool_call_response(self):
        response = CodexCLIClient._parse_tool_response(
            """
{
  "content": null,
  "tool_calls": [
    {
      "id": "call_1",
      "name": "run_security_check",
      "arguments": {"check_id": "open_ports", "args": {}}
    }
  ]
}
"""
        )

        self.assertIsInstance(response, LLMResponse)
        self.assertIsNone(response.content)
        self.assertEqual(len(response.tool_calls), 1)
        self.assertEqual(response.tool_calls[0].name, "run_security_check")
        self.assertIn('"check_id": "open_ports"', response.tool_calls[0].arguments)

    def test_parse_non_json_as_final_text(self):
        response = CodexCLIClient._parse_tool_response("final answer")

        self.assertEqual(response.content, "final answer")
        self.assertEqual(response.tool_calls, [])

    def test_evaluate_command_safety_normalizes_codex_json(self):
        class FakeCodexClient(CodexCLIClient):
            def __init__(self):
                self.model = "fake-codex"

            async def _run_codex_exec(self, prompt, schema):
                self.prompt = prompt
                self.schema = schema
                return """
{
  "safety_status": "safe",
  "risk_level": "low",
  "mutation_detected": false,
  "deletion_detected": false,
  "impact_analysis": "只读取当前目录，不会修改系统状态。"
}
"""

        client = FakeCodexClient()
        result = asyncio.run(client.evaluate_command_safety("ls -la", "system", chat_id=0))

        self.assertEqual(result["safety_status"], "SAFE")
        self.assertEqual(result["risk_level"], "LOW")
        self.assertFalse(result["mutation_detected"])
        self.assertFalse(result["deletion_detected"])
        self.assertIn("不会修改", result["impact_analysis"])


if __name__ == "__main__":
    unittest.main()
