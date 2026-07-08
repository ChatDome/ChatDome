import logging
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from chatdome.logger import ChatDomeFormatter, _stream_supports_color, log_origin, setup_logging


class _FakeStream:
    def __init__(self, isatty: bool):
        self._isatty = isatty

    def isatty(self) -> bool:
        return self._isatty


class _CaptureHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


class LoggerTests(unittest.TestCase):
    @staticmethod
    def _clear_root_handlers() -> None:
        root = logging.getLogger()
        for handler in root.handlers[:]:
            root.removeHandler(handler)
            handler.close()

    @staticmethod
    def _flush_root_handlers() -> None:
        for handler in logging.getLogger().handlers:
            handler.flush()

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


    def test_file_handlers_route_sentinel_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            main_log = Path(tmp) / "chatdome.log"
            sentinel_log = Path(tmp) / "sentinel.log"
            env = {
                "CHATDOME_LOG_FILE": str(main_log),
                "CHATDOME_SENTINEL_LOG_FILE": str(sentinel_log),
            }
            try:
                with patch.dict(os.environ, env, clear=False):
                    setup_logging(use_colors=False)
                    logging.getLogger("chatdome.agent.core").info("main-runtime-entry")
                    logging.getLogger("chatdome.executor.sandbox").info("user-sandbox-entry")
                    logging.getLogger("chatdome.sentinel.scheduler").warning("sentinel-module-entry")
                    with log_origin("sentinel"):
                        logging.getLogger("chatdome.executor.sandbox").info("sentinel-sandbox-entry")
                    self._flush_root_handlers()
            finally:
                self._clear_root_handlers()

            main_text = main_log.read_text(encoding="utf-8")
            sentinel_text = sentinel_log.read_text(encoding="utf-8")
            self.assertIn("main-runtime-entry", main_text)
            self.assertIn("user-sandbox-entry", main_text)
            self.assertNotIn("sentinel-module-entry", main_text)
            self.assertNotIn("sentinel-sandbox-entry", main_text)
            self.assertIn("sentinel-module-entry", sentinel_text)
            self.assertIn("sentinel-sandbox-entry", sentinel_text)
            self.assertNotIn("main-runtime-entry", sentinel_text)
            self.assertNotIn("user-sandbox-entry", sentinel_text)

    def test_sentinel_records_do_not_fallback_to_main_log_without_sentinel_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            main_log = Path(tmp) / "chatdome.log"
            env = {
                "CHATDOME_LOG_FILE": str(main_log),
                "CHATDOME_SENTINEL_LOG_FILE": "",
            }
            try:
                with patch.dict(os.environ, env, clear=False):
                    setup_logging(use_colors=False)
                    logging.getLogger("chatdome.agent.core").info("main-only-entry")
                    logging.getLogger("chatdome.sentinel.scheduler").warning("sentinel-no-fallback")
                    with log_origin("sentinel"):
                        logging.getLogger("chatdome.executor.sandbox").info("sentinel-origin-no-fallback")
                    self._flush_root_handlers()
            finally:
                self._clear_root_handlers()

            main_text = main_log.read_text(encoding="utf-8")
            self.assertIn("main-only-entry", main_text)
            self.assertNotIn("sentinel-no-fallback", main_text)
            self.assertNotIn("sentinel-origin-no-fallback", main_text)

    def test_origin_tag_is_attached_when_record_is_created(self):
        capture = _CaptureHandler()
        try:
            with patch.dict(os.environ, {"CHATDOME_LOG_FILE": "", "CHATDOME_SENTINEL_LOG_FILE": ""}, clear=False):
                setup_logging(use_colors=False)
            logging.getLogger().addHandler(capture)
            with log_origin("sentinel"):
                logging.getLogger("chatdome.executor.sandbox").info("captured-origin")
        finally:
            self._clear_root_handlers()

        self.assertEqual(len(capture.records), 1)
        self.assertEqual(getattr(capture.records[0], "chatdome_origin", ""), "sentinel")

    def test_file_handler_reopens_closed_stream(self):
        with tempfile.TemporaryDirectory() as tmp:
            main_log = Path(tmp) / "chatdome.log"
            env = {
                "CHATDOME_LOG_FILE": str(main_log),
                "CHATDOME_SENTINEL_LOG_FILE": "",
            }
            try:
                with patch.dict(os.environ, env, clear=False):
                    setup_logging(use_colors=False)
                    logging.getLogger("chatdome.agent.core").info("before-close")
                    self._flush_root_handlers()
                    file_handler = next(
                        handler
                        for handler in logging.getLogger().handlers
                        if getattr(handler, "baseFilename", "") == str(main_log)
                    )
                    file_handler.stream.close()
                    logging.getLogger("chatdome.agent.core").info("after-close")
                    self._flush_root_handlers()
            finally:
                self._clear_root_handlers()

            main_text = main_log.read_text(encoding="utf-8")
            self.assertIn("before-close", main_text)
            self.assertIn("after-close", main_text)

    @unittest.skipIf(os.name == "nt", reason="requires POSIX rename of an open log file")
    def test_file_handler_reopens_after_external_log_replacement(self):
        with tempfile.TemporaryDirectory() as tmp:
            main_log = Path(tmp) / "chatdome.log"
            rotated_log = Path(tmp) / "chatdome.log.1"
            env = {
                "CHATDOME_LOG_FILE": str(main_log),
                "CHATDOME_SENTINEL_LOG_FILE": "",
            }
            try:
                with patch.dict(os.environ, env, clear=False):
                    setup_logging(use_colors=False)
                    logging.getLogger("chatdome.agent.core").info("before-replace")
                    self._flush_root_handlers()
                    main_log.rename(rotated_log)
                    main_log.write_text("", encoding="utf-8")
                    logging.getLogger("chatdome.agent.core").info("after-replace")
                    self._flush_root_handlers()
            finally:
                self._clear_root_handlers()

            self.assertIn("before-replace", rotated_log.read_text(encoding="utf-8"))
            main_text = main_log.read_text(encoding="utf-8")
            self.assertIn("after-replace", main_text)
            self.assertNotIn("before-replace", main_text)

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
