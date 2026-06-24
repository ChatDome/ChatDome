import asyncio
import importlib.util
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
CLI_PATH = REPO_ROOT / "chatdome-cli.py"


def _load_cli_module():
    spec = importlib.util.spec_from_file_location("chatdome_cli_under_test", CLI_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class ChatDomeCLITests(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp_dir.name)
        self.config_path = self.root / "config.yaml"
        self.example_path = self.root / "config.example.yaml"
        self.reload_request_path = self.root / "chat_data" / "reload_request.json"
        self.reload_status_path = self.root / "chat_data" / "reload_status.json"
        self.ready_path = self.root / "chat_data" / "ready.json"
        self.pid_path = self.root / "chat_data" / "chatdome.pid"
        self.config_path.write_text(
            yaml.safe_dump(
                {
                    "chatdome": {
                        "active_ai_profile": "base",
                        "ai_profiles": {
                            "base": {
                                "provider": "openai",
                                "api_mode": "openai_api",
                                "base_url": "https://api.openai.com/v1",
                                "model": "gpt-4o",
                                "api_key": "sk-base",
                            }
                        },
                    }
                },
                sort_keys=False,
            ),
            encoding="utf-8",
        )
        self.cli = _load_cli_module()
        self.cli.CONFIG_PATH = self.config_path
        self.cli.EXAMPLE_CONFIG_PATH = self.example_path
        self.cli.RELOAD_REQUEST_PATH = self.reload_request_path
        self.cli.RELOAD_STATUS_PATH = self.reload_status_path
        self.cli.READY_PATH = self.ready_path
        self.cli.PID_PATH = self.pid_path
        self.cli.DATA_DIR = self.root / "chat_data"
        self.cli.PROFILE_AUDIT_RECORDER = lambda *args, **kwargs: None

    def tearDown(self):
        self.tmp_dir.cleanup()

    def _load_profiles(self):
        data = yaml.safe_load(self.config_path.read_text(encoding="utf-8"))
        return data["chatdome"]["ai_profiles"]

    def test_validate_config_reports_error_without_traceback(self):
        self.config_path.write_text("chatdome: {}\n", encoding="utf-8")

        with self.assertRaisesRegex(
            SystemExit,
            "Configuration error: chatdome.active_ai_profile is required",
        ):
            self.cli.validate_config(SimpleNamespace())

    def test_llm_profile_state_reports_exact_name_match(self):
        with patch("builtins.print") as output:
            self.cli.llm_profile_state(SimpleNamespace(profile="base"))
            output.assert_called_once_with("exists")

        with patch("builtins.print") as output:
            self.cli.llm_profile_state(SimpleNamespace(profile="Base"))
            output.assert_called_once_with("missing")

    def test_set_openai_reports_created_and_updated(self):
        created_args = SimpleNamespace(
            profile="new-profile",
            model="new-model",
            base_url="https://example.com/v1",
            api_key="sk-new",
            temperature=0.2,
            max_tokens=3000,
        )
        with patch("builtins.print") as output:
            self.cli.set_openai(created_args)
            output.assert_called_once_with(
                "created OpenAI-compatible profile: new-profile"
            )

        summary = asyncio.run(
            self.cli._profile_admin_service("test").get_profile_summary("base")
        )
        updated_args = SimpleNamespace(
            profile="base",
            model="updated-model",
            base_url="https://example.com/v1",
            api_key="sk-updated",
            temperature=0.3,
            max_tokens=4000,
            overwrite=True,
            expected_profile_fingerprint=summary.fingerprint,
        )
        with patch("builtins.print") as output:
            self.cli.set_openai(updated_args)
            output.assert_called_once_with(
                "updated OpenAI-compatible profile: base"
            )

        profiles = self._load_profiles()
        self.assertEqual(profiles["new-profile"]["model"], "new-model")
        self.assertEqual(profiles["base"]["model"], "updated-model")

    def test_set_openai_blank_key_does_not_create_profile(self):
        args = SimpleNamespace(
            profile="empty-openai",
            model="gpt-4o",
            base_url="https://api.openai.com/v1",
            api_key="",
            temperature=0.1,
            max_tokens=2000,
        )

        with self.assertRaises(SystemExit):
            self.cli.set_openai(args)

        self.assertNotIn("empty-openai", self._load_profiles())

    def test_set_codex_missing_token_does_not_create_profile(self):
        args = SimpleNamespace(
            profile="codex-test",
            model="gpt-5.5",
            client_id="",
            token_file=str(self.root / "missing-auth.json"),
            base_url="https://chatgpt.com/backend-api/codex",
            temperature=0.1,
            max_tokens=2000,
        )

        with self.assertRaises(SystemExit):
            self.cli.set_codex(args)

        self.assertNotIn("codex-test", self._load_profiles())

    def test_set_codex_writes_profile_after_token_exists(self):
        token_file = self.root / "auth.json"
        token_file.write_text("{}", encoding="utf-8")
        args = SimpleNamespace(
            profile="codex-test",
            model="gpt-5.5",
            client_id="",
            token_file=str(token_file),
            base_url="https://chatgpt.com/backend-api/codex",
            temperature=0.1,
            max_tokens=2000,
        )

        self.cli.set_codex(args)

        profile = self._load_profiles()["codex-test"]
        self.assertEqual(profile["api_mode"], "codex_responses")
        self.assertEqual(profile["codex_token_file"], str(token_file))

    def test_new_codex_profile_uses_profile_scoped_default_token_file(self):
        token_file = self.root / "codex-test.json"
        token_file.write_text("{}", encoding="utf-8")
        args = SimpleNamespace(
            profile="codex-test",
            model="gpt-5.5",
            client_id="",
            token_file=None,
            base_url="https://chatgpt.com/backend-api/codex",
            temperature=0.1,
            max_tokens=2000,
        )

        with patch("chatdome.llm.profile_admin.Path.is_file", return_value=True):
            self.cli.set_codex(args)

        profile = self._load_profiles()["codex-test"]
        self.assertEqual(profile["codex_token_file"], "~/.chatdome/codex-auth/codex-test.json")

    def test_codex_login_migrates_blank_legacy_token_file(self):
        token_file = self.cli._resolve_codex_login_token_file(
            "codex-old",
            None,
            {"codex_token_file": ""},
        )

        self.assertEqual(token_file, "~/.chatdome/codex-auth/codex-old.json")

    def test_health_check_requires_matching_ready_process(self):
        self.pid_path.parent.mkdir(parents=True, exist_ok=True)
        self.pid_path.write_text("1234\n", encoding="utf-8")
        self.ready_path.write_text('{"pid": 1234}', encoding="utf-8")

        with patch.object(self.cli, "_process_running", return_value=True):
            self.cli.health_check(SimpleNamespace())

    def test_health_check_rejects_stale_ready_file(self):
        self.pid_path.parent.mkdir(parents=True, exist_ok=True)
        self.pid_path.write_text("1234\n", encoding="utf-8")
        self.ready_path.write_text('{"pid": 9999}', encoding="utf-8")

        with patch.object(self.cli, "_process_running", return_value=True):
            with self.assertRaises(SystemExit):
                self.cli.health_check(SimpleNamespace())


    def test_delete_profile_and_profile_info(self):
        args = SimpleNamespace(
            profile="second",
            model="gpt-4o-mini",
            base_url="https://api.openai.com/v1",
            api_key="sk-second",
            temperature=0.1,
            max_tokens=2000,
        )
        self.cli.set_openai(args)

        with patch("builtins.print") as output:
            self.cli.llm_profile_info(
                SimpleNamespace(profile="second", field="model")
            )
            output.assert_called_once_with("gpt-4o-mini")

        self.cli.delete_profile(SimpleNamespace(profile="second"))
        self.assertNotIn("second", self._load_profiles())


if __name__ == "__main__":
    unittest.main()
