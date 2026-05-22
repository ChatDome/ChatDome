import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from chatdome.config import load_config


class LLMProviderConfigTests(unittest.TestCase):
    def test_codex_responses_mode_does_not_require_api_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.yaml"
            config_path.write_text(
                """
chatdome:
  ai:
    provider: codex
    api_mode: codex_responses
    model: gpt-5.5
""",
                encoding="utf-8",
            )

            with patch.dict(os.environ, {"CHATDOME_BOT_TOKEN": "telegram-token"}, clear=True):
                config = load_config(config_path)

        self.assertEqual(config.ai.provider, "codex")
        self.assertEqual(config.ai.api_mode, "codex_responses")
        self.assertEqual(config.ai.model, "gpt-5.5")

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

    def test_env_can_select_codex_responses_mode(self):
        env = {
            "CHATDOME_BOT_TOKEN": "telegram-token",
            "CHATDOME_AI_PROVIDER": "codex",
            "CHATDOME_AI_API_MODE": "codex_responses",
            "CHATDOME_AI_MODEL": "gpt-5.5",
            "CHATDOME_CODEX_CLIENT_ID": "env-client",
            "CHATDOME_CODEX_TOKEN_FILE": "/env/tokens.json",
        }

        with patch.dict(os.environ, env, clear=True):
            config = load_config("missing-config.yaml")

        self.assertEqual(config.ai.provider, "codex")
        self.assertEqual(config.ai.api_mode, "codex_responses")
        self.assertEqual(config.ai.model, "gpt-5.5")
        self.assertEqual(config.ai.codex_client_id, "env-client")
        self.assertEqual(config.ai.codex_token_file, "/env/tokens.json")


if __name__ == "__main__":
    unittest.main()
