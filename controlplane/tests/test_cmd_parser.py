import unittest

from chatdome.executor.cmd_parser import parse_shell_command


class CommandParserTests(unittest.TestCase):
    def test_rm_breakdown_marks_target_and_warnings(self):
        breakdown = parse_shell_command("rm -rf /root/show_time.sh")

        self.assertEqual(breakdown["base_cmd"], "rm")
        self.assertIn("/root/show_time.sh", breakdown["targets"])
        self.assertTrue(breakdown["irreversible"])
        meanings = [item["meaning"] for item in breakdown["tokens"]]
        self.assertIn("目标文件（将被永久删除）", meanings)
        self.assertIn("无 -i 标志，删除时不会提示确认", breakdown["warnings"])

    def test_systemctl_breakdown_marks_action_and_service(self):
        breakdown = parse_shell_command("systemctl restart nginx")

        roles = [item["role"] for item in breakdown["tokens"]]
        self.assertIn("子命令", roles)
        self.assertIn("目标服务", roles)
        self.assertIn("nginx", breakdown["targets"])
        self.assertIn("会改变服务运行状态", breakdown["warnings"])

    def test_network_download_marks_url(self):
        breakdown = parse_shell_command("wget https://example.com/pkg.tar.gz")

        self.assertEqual(breakdown["base_cmd"], "wget")
        self.assertIn("https://example.com/pkg.tar.gz", breakdown["targets"])
        self.assertIn("会访问外部网络", breakdown["warnings"])

    def test_unknown_command_keeps_original_arguments(self):
        breakdown = parse_shell_command("custom-tool --flag value")

        self.assertEqual(breakdown["base_cmd"], "custom-tool")
        self.assertEqual(breakdown["description"], "执行命令（未识别）")
        self.assertIn("value", breakdown["targets"])


if __name__ == "__main__":
    unittest.main()
