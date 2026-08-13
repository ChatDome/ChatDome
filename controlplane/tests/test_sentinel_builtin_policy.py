import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from chatdome.sentinel.checks import load_builtin_checks


class SentinelBuiltinPolicyTests(unittest.TestCase):
    def test_builtin_policy_contains_expected_checks(self):
        checks = load_builtin_checks()

        self.assertEqual(len(checks), 8)
        self.assertEqual(checks[0].check_id, "ssh_bruteforce")
        self.assertEqual(checks[-1].check_id, "open_ports")
        self.assertEqual(checks[-1].severity, 9)

    def test_builtin_policy_rejects_unknown_command(self):
        with TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "checks.yaml"
            path.write_text(
                "checks:\n"
                "  - name: Invalid\n"
                "    check_id: missing_command\n"
                "    interval: 60\n"
                "    mode: snapshot\n"
                "    severity: 5\n"
                "    rule: {type: line_count, operator: '>', threshold: 0}\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "missing_command"):
                load_builtin_checks(path)

    def test_builtin_policy_reports_all_invalid_fields(self):
        with TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "checks.yaml"
            path.write_text(
                "checks:\n"
                "  - name: ''\n"
                "    check_id: disk_usage\n"
                "    interval: 0\n"
                "    mode: invalid\n"
                "    severity: 11\n"
                "    rule: {type: regex_extract, pattern: '[', operator: invalid}\n",
                encoding="utf-8",
            )

            with self.assertRaises(ValueError) as context:
                load_builtin_checks(path)

            message = str(context.exception)
            self.assertIn("name", message)
            self.assertIn("interval", message)
            self.assertIn("mode", message)
            self.assertIn("severity", message)
            self.assertIn("pattern", message)
            self.assertIn("operator", message)


if __name__ == "__main__":
    unittest.main()
