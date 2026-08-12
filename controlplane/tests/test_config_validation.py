import tempfile
import unittest
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()
