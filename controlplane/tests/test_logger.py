import logging
import unittest
from unittest.mock import patch

from chatdome.logger import ChatDomeFormatter, _stream_supports_color


class _FakeStream:
    def __init__(self, isatty: bool):
        self._isatty = isatty

    def isatty(self) -> bool:
        return self._isatty


class LoggerTests(unittest.TestCase):
    def _record(self) -> logging.LogRecord:
        return logging.LogRecord(
            name="chatdome.telegram.bot",
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg="hello",
            args=(),
            exc_info=None,
        )

    def test_formatter_can_emit_plain_logs_without_ansi_escape_codes(self):
        formatter = ChatDomeFormatter(
            datefmt="%Y-%m-%d %H:%M:%S",
            use_colors=False,
        )

        output = formatter.format(self._record())

        self.assertNotIn("\033[", output)
        self.assertIn("[INFO ] [telegram.bot] hello", output)

    def test_formatter_can_emit_colored_logs_for_interactive_console(self):
        formatter = ChatDomeFormatter(
            datefmt="%Y-%m-%d %H:%M:%S",
            use_colors=True,
        )

        output = formatter.format(self._record())

        self.assertIn("\033[", output)
        self.assertIn("[INFO ]", output)
        self.assertIn("[telegram.bot]", output)

    def test_color_auto_detection_disables_color_for_redirected_streams(self):
        with patch.dict("os.environ", {}, clear=True):
            self.assertFalse(_stream_supports_color(_FakeStream(isatty=False)))
            self.assertTrue(_stream_supports_color(_FakeStream(isatty=True)))

    def test_color_auto_detection_honors_environment_overrides(self):
        with patch.dict("os.environ", {"CHATDOME_LOG_COLOR": "never"}, clear=True):
            self.assertFalse(_stream_supports_color(_FakeStream(isatty=True)))
        with patch.dict("os.environ", {"CHATDOME_LOG_COLOR": "always"}, clear=True):
            self.assertTrue(_stream_supports_color(_FakeStream(isatty=False)))
        with patch.dict("os.environ", {"NO_COLOR": "1"}, clear=True):
            self.assertFalse(_stream_supports_color(_FakeStream(isatty=True)))


if __name__ == "__main__":
    unittest.main()
