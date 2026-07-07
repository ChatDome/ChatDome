import unittest

from chatdome.telegram.bot import HELP_TEXT


class TelegramHelpTests(unittest.TestCase):
    def test_help_lists_audit_and_engram_commands(self):
        self.assertIn("/audit \\[N\\]", HELP_TEXT)
        self.assertIn("/engram \\-", HELP_TEXT)
        self.assertIn("/engram delete <id>", HELP_TEXT)
        self.assertIn("/stop \\-", HELP_TEXT)


if __name__ == "__main__":
    unittest.main()
