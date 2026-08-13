import tempfile
import unittest
from pathlib import Path

from chatdome.config import load_config, parse_config_document, validate_llm_config, validate_runtime_config


class LLMProviderConfigTests(unittest.TestCase):
    def test_codex_profile_does_not_require_api_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.yaml"
            config_path.write_text(
                """
chatdome:
  telegram:
    bot_token: telegram-token
  active_ai_profile: codex-gpt5
  ai_profiles:
    codex-gpt5:
      provider: codex
      api_mode: codex_responses
      model: gpt-5.5
  agent:
    command_approval_mode: require_approval_for_risky_commands
""",
                encoding="utf-8",
            )

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
  telegram:
    bot_token: telegram-token
  ai:
    provider: openai
    api_mode: openai_api
""",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "chatdome.ai .*未知字段"):
                load_config(config_path)

    def test_openai_profile_allows_direct_api_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.yaml"
            config_path.write_text(
                """
chatdome:
  telegram:
    bot_token: telegram-token
  active_ai_profile: openai-official
  ai_profiles:
    openai-official:
      provider: openai
      api_mode: openai_api
      model: gpt-4o
      api_key: sk-test
  agent:
    command_approval_mode: require_approval_for_risky_commands
""",
                encoding="utf-8",
            )

            config = load_config(config_path)

        self.assertEqual(config.ai_profiles["openai-official"].api_key, "sk-test")

    def test_env_api_key_reference_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.yaml"
            config_path.write_text(
                """
chatdome:
  telegram:
    bot_token: telegram-token
  active_ai_profile: openai-official
  ai_profiles:
    openai-official:
      provider: openai
      api_mode: openai_api
      model: gpt-4o
      api_key: env:CHATDOME_OPENAI_API_KEY
  agent:
    command_approval_mode: require_approval_for_risky_commands
""",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "api_key 不支持 env: 引用"):
                load_config(config_path)

    def test_old_ai_environment_overrides_are_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.yaml"
            config_path.write_text(
                """
chatdome:
  telegram:
    bot_token: telegram-token
  active_ai_profile: codex-gpt5
  ai_profiles:
    codex-gpt5:
      provider: codex
      api_mode: codex_responses
      model: gpt-5.5
      codex_client_id: yaml-client
      codex_token_file: /yaml/auth.json
  agent:
    command_approval_mode: require_approval_for_risky_commands
""",
                encoding="utf-8",
            )

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
  telegram:
    bot_token: telegram-token
  active_ai_profile: missing
  ai_profiles:
    codex-gpt5:
      provider: codex
      api_mode: codex_responses
      model: gpt-5.5
  agent:
    command_approval_mode: require_approval_for_risky_commands
""",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "未在 chatdome.ai_profiles 中定义"):
                load_config(config_path)

    def test_command_output_archive_config_is_opt_in(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.yaml"
            config_path.write_text(
                """
chatdome:
  telegram:
    bot_token: telegram-token
  active_ai_profile: codex-gpt5
  ai_profiles:
    codex-gpt5:
      provider: codex
      api_mode: codex_responses
      model: gpt-5.5
  agent:
    command_approval_mode: require_approval_for_risky_commands
    persist_command_outputs: true
    command_output_retention_days: 3
    command_output_max_chars: 1234
""",
                encoding="utf-8",
            )

            config = load_config(config_path)

        self.assertTrue(config.agent.persist_command_outputs)
        self.assertEqual(config.agent.command_output_retention_days, 3)
        self.assertEqual(config.agent.command_output_max_chars, 1234)

    def test_command_output_archive_env_override_is_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.yaml"
            config_path.write_text(
                """
chatdome:
  telegram:
    bot_token: telegram-token
  active_ai_profile: codex-gpt5
  ai_profiles:
    codex-gpt5:
      provider: codex
      api_mode: codex_responses
      model: gpt-5.5
  agent:
    command_approval_mode: require_approval_for_risky_commands
""",
                encoding="utf-8",
            )

            config = load_config(config_path)

        self.assertFalse(config.agent.persist_command_outputs)
        self.assertEqual(config.agent.command_output_retention_days, 7)
        self.assertEqual(config.agent.command_output_max_chars, 8000)


    def test_pure_llm_validation_does_not_require_telegram_token(self):
        config = parse_config_document(
            {
                "chatdome": {
                    "active_ai_profile": "base",
                    "ai_profiles": {
                        "base": {
                            "provider": "openai",
                            "api_mode": "openai_api",
                            "model": "gpt-4o",
                            "api_key": "sk-test",
                        }
                    },
                }
            }
        )

        validate_llm_config(config)
        self.assertEqual(validate_runtime_config(config), [])

    def test_empty_llm_configuration_is_valid_for_core_runtime(self):
        config = parse_config_document(
            {
                "chatdome": {
                    "telegram": {},
                    "active_ai_profile": "",
                    "ai_profiles": {},
                }
            }
        )

        validate_llm_config(config)
        self.assertEqual(validate_runtime_config(config), [])
        self.assertFalse(config.llm_configured)
        self.assertFalse(config.telegram_configured)

    def test_scalar_admin_id_is_normalized(self):
        config = parse_config_document(
            {
                "chatdome": {
                    "telegram": {"admin_ids": 123},
                    "active_ai_profile": "base",
                    "ai_profiles": {
                        "base": {
                            "provider": "openai",
                            "api_mode": "openai_api",
                            "model": "gpt-4o",
                            "api_key": "sk-test",
                        }
                    },
                }
            }
        )

        self.assertEqual(config.telegram.admin_ids, [123])

    def test_user_ids_are_normalized_without_logging(self):
        config = parse_config_document(
            {
                "chatdome": {
                    "telegram": {
                        "allowed_ids": ["1", "invalid"],
                        "admin_ids": "2,invalid,3",
                    },
                    "active_ai_profile": "base",
                    "ai_profiles": {
                        "base": {
                            "provider": "openai",
                            "api_mode": "openai_api",
                            "model": "gpt-4o",
                            "api_key": "sk-test",
                        }
                    },
                }
            }
        )

        self.assertEqual(config.telegram.allowed_ids, [1])
        self.assertEqual(config.telegram.admin_ids, [2, 3])


if __name__ == "__main__":
    unittest.main()
