import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from chatdome.config import load_config


class LLMProviderConfigTests(unittest.TestCase):
    def test_codex_profile_does_not_require_api_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.yaml"
            config_path.write_text(
                """
chatdome:
  active_ai_profile: codex-gpt5
  ai_profiles:
    codex-gpt5:
      provider: codex
      api_mode: codex_responses
      model: gpt-5.5
""",
                encoding="utf-8",
            )

            with patch.dict(os.environ, {"CHATDOME_BOT_TOKEN": "telegram-token"}, clear=True):
                config = load_config(config_path)

        self.assertEqual(config.active_ai_profile, "codex-gpt5")
        profile = config.ai_profiles["codex-gpt5"]
        self.assertEqual(profile.provider, "codex")
        self.assertEqual(profile.api_mode, "codex_responses")
        self.assertEqual(profile.model, "gpt-5.5")

    def test_legacy_ai_block_is_rejected(self):
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
                with self.assertRaisesRegex(ValueError, "Legacy chatdome.ai"):
                    load_config(config_path)

    def test_openai_profile_requires_env_key_reference(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.yaml"
            config_path.write_text(
                """
chatdome:
  active_ai_profile: openai-official
  ai_profiles:
    openai-official:
      provider: openai
      api_mode: openai_api
      model: gpt-4o
""",
                encoding="utf-8",
            )

            with patch.dict(os.environ, {"CHATDOME_BOT_TOKEN": "telegram-token"}, clear=True):
                with self.assertRaisesRegex(ValueError, "requires api_key"):
                    load_config(config_path)

    def test_plaintext_api_key_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.yaml"
            config_path.write_text(
                """
chatdome:
  active_ai_profile: openai-official
  ai_profiles:
    openai-official:
      provider: openai
      api_mode: openai_api
      model: gpt-4o
      api_key: sk-test
""",
                encoding="utf-8",
            )

            with patch.dict(os.environ, {"CHATDOME_BOT_TOKEN": "telegram-token"}, clear=True):
                with self.assertRaisesRegex(ValueError, "plaintext keys"):
                    load_config(config_path)

    def test_old_ai_environment_overrides_are_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.yaml"
            config_path.write_text(
                """
chatdome:
  active_ai_profile: codex-gpt5
  ai_profiles:
    codex-gpt5:
      provider: codex
      api_mode: codex_responses
      model: gpt-5.5
      codex_client_id: yaml-client
      codex_token_file: /yaml/auth.json
""",
                encoding="utf-8",
            )

            env = {
                "CHATDOME_BOT_TOKEN": "telegram-token",
                "CHATDOME_AI_PROVIDER": "openai",
                "CHATDOME_AI_MODEL": "env-model",
                "CHATDOME_CODEX_CLIENT_ID": "env-client",
                "CHATDOME_CODEX_TOKEN_FILE": "/env/auth.json",
            }
            with patch.dict(os.environ, env, clear=True):
                config = load_config(config_path)

        profile = config.ai_profiles["codex-gpt5"]
        self.assertEqual(profile.provider, "codex")
        self.assertEqual(profile.model, "gpt-5.5")
        self.assertEqual(profile.codex_client_id, "yaml-client")
        self.assertEqual(profile.codex_token_file, "/yaml/auth.json")

    def test_missing_active_profile_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.yaml"
            config_path.write_text(
                """
chatdome:
  active_ai_profile: missing
  ai_profiles:
    codex-gpt5:
      provider: codex
      api_mode: codex_responses
      model: gpt-5.5
""",
                encoding="utf-8",
            )

            with patch.dict(os.environ, {"CHATDOME_BOT_TOKEN": "telegram-token"}, clear=True):
                with self.assertRaisesRegex(ValueError, "does not exist"):
                    load_config(config_path)


if __name__ == "__main__":
    unittest.main()

