import unittest

from chatdome.executor.sandbox import CommandSandbox


class SandboxLoggingTests(unittest.TestCase):
    def test_command_log_excerpt_is_single_line_and_truncated(self):
        command = "echo one\n" + ("awk '{print $1}' /var/log/auth.log; " * 20)

        excerpt = CommandSandbox._command_log_excerpt(command, max_chars=80)

        self.assertNotIn("\n", excerpt)
        self.assertLessEqual(len(excerpt), 80)
        self.assertTrue(excerpt.endswith("..."))

    def test_command_log_hash_is_stable_short_sha256_prefix(self):
        command = "journalctl -u sshd --since '-24 hours'"

        first = CommandSandbox._command_log_hash(command)
        second = CommandSandbox._command_log_hash(command)

        self.assertEqual(first, second)
        self.assertEqual(len(first), 12)


if __name__ == "__main__":
    unittest.main()
