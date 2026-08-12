import tempfile
import unittest
from pathlib import Path

import yaml

from chatdome.config import load_config
from chatdome.config_validation import ConfigValidationError


VALID_CONFIG = """\
chatdome:
  telegram:
    bot_token: telegram-token
  active_ai_profile: primary
  ai_profiles:
    primary:
      provider: openai
      api_mode: openai_api
      api_key: sk-test
      model: gpt-4o
  agent:
    command_approval_mode: require_approval_for_risky_commands
  sentinel:
    enabled: false
"""


class ConfigValidationTests(unittest.TestCase):
    def _load_text(self, text: str):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.yaml"
            path.write_text(text, encoding="utf-8")
            return load_config(path)

    def test_reports_all_independent_agent_errors_with_lines(self):
        text = """\
chatdome:
  telegram:
    bot_token: telegram-token
  active_ai_profile: primary
  ai_profiles:
    primary: {provider: openai, api_mode: openai_api, api_key: sk-test, model: gpt-4o}
  agent:
    unexpected: true
    command_approval_mode: sometimes
    command_timeout: 0
"""

        with self.assertRaises(ConfigValidationError) as raised:
            self._load_text(text)

        message = str(raised.exception)
        self.assertIn("配置检查失败，共 3 项", message)
        self.assertIn("第 8 行：chatdome.agent.unexpected 是未知字段", message)
        self.assertIn("第 9 行：chatdome.agent.command_approval_mode 取值无效", message)
        self.assertIn("第 10 行：chatdome.agent.command_timeout 必须是大于 0 的整数", message)

    def test_duplicate_key_reports_second_key_line(self):
        text = VALID_CONFIG.replace(
            "    command_approval_mode: require_approval_for_risky_commands\n",
            "    command_approval_mode: require_approval_for_risky_commands\n"
            "    command_approval_mode: require_approval_for_all_commands\n",
        )

        with self.assertRaises(ConfigValidationError) as raised:
            self._load_text(text)

        self.assertIn(
            "第 13 行：chatdome.agent.command_approval_mode 字段重复",
            str(raised.exception),
        )

    def test_missing_approval_mode_reports_agent_block_line(self):
        text = VALID_CONFIG.replace(
            "    command_approval_mode: require_approval_for_risky_commands\n",
            "    command_timeout: 10\n",
        )

        with self.assertRaises(ConfigValidationError) as raised:
            self._load_text(text)

        self.assertIn(
            "第 11 行：chatdome.agent 缺少必填字段 command_approval_mode",
            str(raised.exception),
        )

    def test_active_profile_reference_reports_value_line(self):
        text = VALID_CONFIG.replace("active_ai_profile: primary", "active_ai_profile: missing")

        with self.assertRaises(ConfigValidationError) as raised:
            self._load_text(text)

        self.assertIn(
            "第 4 行：chatdome.active_ai_profile 未在 chatdome.ai_profiles 中定义",
            str(raised.exception),
        )

    def test_unknown_sentinel_check_reports_check_id_line(self):
        text = VALID_CONFIG.replace(
            "  sentinel:\n    enabled: false\n",
            "  sentinel:\n"
            "    enabled: true\n"
            "    builtin_packs: [network]\n"
            "    checks:\n"
            "      - name: invalid\n"
            "        check_id: missing_check\n"
            "        interval: 60\n"
            "        mode: snapshot\n"
            "        severity: 5\n",
        )

        with self.assertRaises(ConfigValidationError) as raised:
            self._load_text(text)

        self.assertIn(
            "第 18 行：chatdome.sentinel.checks[0].check_id 未在已启用的命令包中定义",
            str(raised.exception),
        )

    def test_valid_document_loads(self):
        config = self._load_text(VALID_CONFIG)

        self.assertEqual(
            config.agent.command_approval_mode,
            "require_approval_for_risky_commands",
        )

    def test_null_required_sections_are_all_reported_with_lines(self):
        text = """\
chatdome:
  telegram:
  active_ai_profile: primary
  ai_profiles:
  agent:
  sentinel:
"""

        with self.assertRaises(ConfigValidationError) as raised:
            self._load_text(text)

        message = str(raised.exception)
        self.assertIn("配置检查失败，共 4 项", message)
        self.assertIn("第 2 行：chatdome.telegram 必须是对象", message)
        self.assertIn("第 4 行：chatdome.ai_profiles 必须是对象", message)
        self.assertIn("第 5 行：chatdome.agent 必须是对象", message)
        self.assertIn("第 6 行：chatdome.sentinel 必须是对象", message)

    def test_profile_errors_are_aggregated_before_dataclass_parsing(self):
        text = VALID_CONFIG.replace(
            "    primary:\n"
            "      provider: openai\n"
            "      api_mode: openai_api\n"
            "      api_key: sk-test\n"
            "      model: gpt-4o\n",
            "    invalid profile:\n"
            "      provider: openai\n"
            "      api_mode: unsupported\n"
            "      api_key: env:CHATDOME_KEY\n"
            "      model: ''\n",
        ).replace("active_ai_profile: primary", "active_ai_profile: invalid profile")

        with self.assertRaises(ConfigValidationError) as raised:
            self._load_text(text)

        message = str(raised.exception)
        self.assertIn("第 6 行：chatdome.ai_profiles.invalid profile 名称无效", message)
        self.assertIn("第 8 行：chatdome.ai_profiles.invalid profile.api_mode 取值无效", message)
        self.assertIn("第 9 行：chatdome.ai_profiles.invalid profile.api_key 不支持 env: 引用", message)
        self.assertIn("第 10 行：chatdome.ai_profiles.invalid profile.model 必须填写非空字符串", message)

    def test_invalid_sentinel_rule_values_are_aggregated(self):
        text = VALID_CONFIG.replace(
            "  sentinel:\n    enabled: false\n",
            "  sentinel:\n"
            "    enabled: true\n"
            "    builtin_packs: [network]\n"
            "    checks:\n"
            "      - name: invalid rule\n"
            "        check_id: open_ports\n"
            "        rule:\n"
            "          type: unsupported\n"
            "          operator: approximate\n"
            "          aggregation: median\n",
        )

        with self.assertRaises(ConfigValidationError) as raised:
            self._load_text(text)

        message = str(raised.exception)
        self.assertIn("第 20 行：chatdome.sentinel.checks[0].rule.type 取值无效", message)
        self.assertIn("第 21 行：chatdome.sentinel.checks[0].rule.operator 取值无效", message)
        self.assertIn("第 22 行：chatdome.sentinel.checks[0].rule.aggregation 取值无效", message)

    def test_example_config_becomes_valid_after_required_credentials_are_filled(self):
        example_path = Path(__file__).parents[2] / "config.example.yaml"
        document = yaml.safe_load(example_path.read_text(encoding="utf-8"))
        root = document["chatdome"]
        root["telegram"]["bot_token"] = "telegram-token"
        root["active_ai_profile"] = "primary"
        root["ai_profiles"] = {
            "primary": {
                "provider": "openai",
                "api_mode": "openai_api",
                "api_key": "sk-test",
                "model": "gpt-4o",
            }
        }

        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.yaml"
            config_path.write_text(
                yaml.safe_dump(document, allow_unicode=True, sort_keys=False),
                encoding="utf-8",
            )
            config = load_config(config_path)

        self.assertEqual(
            config.agent.command_approval_mode,
            "require_approval_for_risky_commands",
        )


if __name__ == "__main__":
    unittest.main()
