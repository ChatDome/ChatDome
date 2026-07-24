from __future__ import annotations

import unittest

from chatdome.executor.command_parser import split_shell_commands


class ShellCommandParserTests(unittest.TestCase):
    @staticmethod
    def _commands(command: str) -> tuple[str, ...]:
        return tuple(segment.command for segment in split_shell_commands(command))

    def test_splits_simple_semicolon_chain_and_preserves_separators(self):
        segments = split_shell_commands(
            "cd /srv/chatdome; git pull; systemctl restart chatdome"
        )

        self.assertEqual(
            tuple(segment.command for segment in segments),
            ("cd /srv/chatdome", "git pull", "systemctl restart chatdome"),
        )
        self.assertEqual(tuple(segment.separator for segment in segments), (";", ";", ""))

    def test_does_not_split_quoted_or_escaped_semicolons(self):
        cases = [
            ("printf '%s' 'a;b'; pwd", ("printf '%s' 'a;b'", "pwd")),
            ('printf "%s" "a;b"; pwd', ('printf "%s" "a;b"', "pwd")),
            (r"echo a\;b; pwd", (r"echo a\;b", "pwd")),
            (r"printf $'a\';b'; pwd", (r"printf $'a\';b'", "pwd")),
            ("echo `printf 'a;b'`; pwd", ("echo `printf 'a;b'`", "pwd")),
        ]

        for command, expected in cases:
            with self.subTest(command=command):
                self.assertEqual(self._commands(command), expected)

    def test_does_not_split_nested_shell_scopes(self):
        cases = [
            (
                'echo "$(printf "%s;a" x; echo b)"; pwd',
                ('echo "$(printf "%s;a" x; echo b)"', "pwd"),
            ),
            ("(cd /tmp; ls -la); pwd", ("(cd /tmp; ls -la)", "pwd")),
            ("{ cd /tmp; ls -la; }; pwd", ("{ cd /tmp; ls -la; }", "pwd")),
            ('echo "${fallback:-a;b}"; pwd', ('echo "${fallback:-a;b}"', "pwd")),
            ("echo ${#value}; pwd", ("echo ${#value}", "pwd")),
            (
                "diff <(printf 'a;b') <(printf 'c;d'); echo done",
                ("diff <(printf 'a;b') <(printf 'c;d')", "echo done"),
            ),
        ]

        for command, expected in cases:
            with self.subTest(command=command):
                self.assertEqual(self._commands(command), expected)

    def test_splits_top_level_sequence_operators_and_preserves_them(self):
        segments = split_shell_commands("echo a && echo b || echo c; echo d | cat")

        self.assertEqual(
            tuple(segment.command for segment in segments),
            ("echo a", "echo b", "echo c", "echo d | cat"),
        )
        self.assertEqual(
            tuple(segment.separator for segment in segments),
            ("&&", "||", ";", ""),
        )

    def test_does_not_split_sequence_operators_in_quotes_or_nested_scopes(self):
        cases = [
            ("printf '%s' 'a && b || c' && echo done", ("printf '%s' 'a && b || c'", "echo done")),
            (
                'echo "$(printf \'a && b || c\')" || echo failed',
                ('echo "$(printf \'a && b || c\')"', "echo failed"),
            ),
            ("(echo a && echo b) || echo failed", ("(echo a && echo b)", "echo failed")),
        ]

        for command, expected in cases:
            with self.subTest(command=command):
                self.assertEqual(self._commands(command), expected)

    def test_does_not_split_conditional_expression_operators(self):
        segments = split_shell_commands(
            "[[ -f /tmp/a && -r /tmp/a ]] && echo ready || echo unavailable"
        )

        self.assertEqual(
            tuple(segment.command for segment in segments),
            (
                "[[ -f /tmp/a && -r /tmp/a ]]",
                "echo ready",
                "echo unavailable",
            ),
        )
        self.assertEqual(
            tuple(segment.separator for segment in segments),
            ("&&", "||", ""),
        )

    def test_find_exec_terminator_is_not_a_top_level_separator(self):
        segments = split_shell_commands(
            r"find /tmp -exec sh -c 'echo a && echo b' \; && echo done"
        )

        self.assertEqual(
            tuple(segment.command for segment in segments),
            (r"find /tmp -exec sh -c 'echo a && echo b' \;", "echo done"),
        )
        self.assertEqual(tuple(segment.separator for segment in segments), ("&&", ""))

    def test_reserved_words_in_arguments_do_not_disable_segmentation(self):
        cases = [
            ("printf if && printf fi", ("printf if", "printf fi")),
            ("echo case || echo esac", ("echo case", "echo esac")),
            (
                "echo for && echo do && echo done",
                ("echo for", "echo do", "echo done"),
            ),
        ]

        for command, expected in cases:
            with self.subTest(command=command):
                self.assertEqual(self._commands(command), expected)

    def test_bracket_words_and_arithmetic_shifts_keep_operator_boundaries(self):
        cases = [
            ("echo [[ && echo ok", ("echo [[", "echo ok")),
            ("foo[[bar && echo ok", ("foo[[bar", "echo ok")),
            (
                "echo $((x << 1)) && echo done",
                ("echo $((x << 1))", "echo done"),
            ),
            (
                "((x <<= 1)) || echo failed",
                ("((x <<= 1))", "echo failed"),
            ),
        ]

        for command, expected in cases:
            with self.subTest(command=command):
                self.assertEqual(self._commands(command), expected)

    def test_invalid_sequence_operator_chains_fall_back_to_original(self):
        for command in ("&& echo a", "foo && || bar", "foo &&"):
            with self.subTest(command=command):
                self.assertEqual(self._commands(command), (command,))

    def test_compound_commands_and_heredocs_fall_back_to_original_command(self):
        cases = [
            'if test -f /tmp/a; then echo "yes"; fi; pwd',
            'for item in a b; do echo "$item"; done; pwd',
            "case $value in a) echo a;; esac; pwd",
            "cat <<EOF\na;b\nEOF\necho done; pwd",
        ]

        for command in cases:
            with self.subTest(command=command):
                self.assertEqual(self._commands(command), (command,))

    def test_unclosed_shell_scope_falls_back_to_original_command(self):
        cases = ["echo 'a;b; pwd", 'echo "a;b; pwd', "echo $(date; pwd"]

        for command in cases:
            with self.subTest(command=command):
                self.assertEqual(self._commands(command), (command,))


if __name__ == "__main__":
    unittest.main()
