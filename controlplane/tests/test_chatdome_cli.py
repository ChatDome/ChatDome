import asyncio
import importlib.util
import subprocess
import sys
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
        self.run_dir = self.root / "chat_data" / "run"
        self.reload_request_path = self.run_dir / "reload_request.json"
        self.reload_status_path = self.run_dir / "reload_status.json"
        self.ready_path = self.run_dir / "ready.json"
        self.pid_path = self.run_dir / "chatdome.pid"
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
        self.cli.RUN_DIR = self.run_dir
        self.cli.ENV_PROFILE_PATH = self.cli.DATA_DIR / "environment" / "profile.md"
        self.cli.LEGACY_ENV_PROFILE_PATH = self.cli.DATA_DIR / "environment_profile.md"
        self.cli.LLM_PROFILE_LOCK_PATH = self.run_dir / "llm-profile.lock"
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

    def test_codex_login_logs_auth_error_without_traceback_output(self):
        from chatdome.errors import CodexAuthError

        async def fail_login(_args):
            raise CodexAuthError(
                "Unexpected OAuth polling HTTP status: 429 - <html>Just a moment</html>",
                user_message="Codex 认证轮询被限流，请稍后重试或切换网络。",
                retryable=True,
            )

        with patch.object(self.cli, "_codex_login_async", fail_login):
            with patch("builtins.print") as output:
                with self.assertRaises(SystemExit) as raised:
                    self.cli.codex_login(SimpleNamespace())

        self.assertEqual(raised.exception.code, 1)
        printed = "\n".join(str(call.args[0]) for call in output.call_args_list)
        self.assertIn("Codex 认证轮询被限流，请稍后重试或切换网络。", printed)
        self.assertIn("操作: 稍后重试，或切换网络后重新认证。", printed)
        self.assertIn("查看日志: tail -n 80", printed)
        self.assertNotIn("Traceback", printed)

        log_text = (self.cli.DATA_DIR / "chatdome-cli.log").read_text(encoding="utf-8")
        self.assertIn("Traceback", log_text)
        self.assertIn("Unexpected OAuth polling HTTP status: 429", log_text)

    def test_hello_runs_terminal_chat_loop_with_fake_agent(self):
        class FakeAgent:
            def __init__(self):
                self.messages = []
                self.stopped = False

            async def handle_message(self, chat_id, message):
                self.messages.append((chat_id, message))
                return SimpleNamespace(kind="reply", content="pong", payload={})

            async def stop(self):
                self.stopped = True

            def clear_session(self, chat_id):
                raise AssertionError("clear_session should not be called")

        fake_agent = FakeAgent()
        runtime = self.cli._TerminalChatRuntime(fake_agent, -42)

        with patch.object(self.cli, "_create_terminal_chat_runtime", return_value=runtime):
            with patch("builtins.input", side_effect=["hello", "/exit"]):
                with patch("builtins.print") as output:
                    self.cli.hello(SimpleNamespace(chat_id=-42))

        self.assertEqual(fake_agent.messages, [(-42, "hello")])
        self.assertTrue(fake_agent.stopped)
        printed = "\n".join(str(call.args[0]) for call in output.call_args_list)
        self.assertIn("____  _   _", printed)
        self.assertIn("ChatDome\n│ pong", printed)

    def test_terminal_compact_start_can_be_enabled_by_flag_or_env(self):
        async def noop_loop(_args):
            return None

        with patch.object(self.cli, "_terminal_chat_loop", noop_loop):
            with patch("builtins.print") as output:
                self.cli.hello(SimpleNamespace(chat_id=-1, quiet=True))

        printed = "\n".join(str(call.args[0]) for call in output.call_args_list)
        self.assertIn("ChatDome terminal · model: base", printed)
        self.assertNotIn("____  _   _", printed)
        self.assertNotIn("session: local", printed)

        with patch.dict("os.environ", {"CHATDOME_COMPACT": "1"}):
            with patch.object(self.cli, "_terminal_chat_loop", noop_loop):
                with patch("builtins.print") as output:
                    self.cli.hello(SimpleNamespace(chat_id=-1))

        printed = "\n".join(str(call.args[0]) for call in output.call_args_list)
        self.assertIn("ChatDome terminal · model: base", printed)
        self.assertNotIn("____  _   _", printed)


    def test_terminal_chat_handles_help_and_clear_commands(self):
        class FakeAgent:
            def __init__(self):
                self.cleared = []
                self.stopped = False

            def clear_session(self, chat_id):
                self.cleared.append(chat_id)

            async def stop(self):
                self.stopped = True

        fake_agent = FakeAgent()
        runtime = self.cli._TerminalChatRuntime(fake_agent, -9)

        with patch.object(self.cli, "_create_terminal_chat_runtime", return_value=runtime):
            with patch("builtins.input", side_effect=["/help", "/clear", "/exit"]):
                with patch("builtins.print") as output:
                    self.cli.hello(SimpleNamespace(chat_id=-9))

        self.assertEqual(fake_agent.cleared, [-9])
        self.assertTrue(fake_agent.stopped)
        printed = "\n".join(str(call.args[0]) for call in output.call_args_list)
        self.assertIn("/audit [N]", printed)
        self.assertIn("ChatDome\n│ ✅ Session cleared.", printed)

    def test_terminal_audit_filters_command_events(self):
        events = [
            {"timestamp_iso": "2026-07-02T00:00:02Z", "event_type": "llm_profile_updated"},
            {
                "timestamp_iso": "2026-07-02T00:00:01Z",
                "event_type": "command_pending_approval",
                "risk_level": "high",
                "command": "systemctl restart sshd",
            },
        ]
        with patch.object(self.cli.CommandAuditTracker, "get_recent_events", return_value=events):
            text = self.cli._format_terminal_audit_events(-1, 10)

        self.assertIn("command_pending_approval", text)
        self.assertIn("systemctl restart sshd", text)
        self.assertNotIn("llm_profile_updated", text)

    def test_terminal_audit_command_does_not_initialize_agent_runtime(self):
        events = [
            {
                "timestamp_iso": "2026-07-02T00:00:01Z",
                "event_type": "command_executed",
                "risk_level": "low",
                "command": "whoami",
            }
        ]
        with patch.object(self.cli.CommandAuditTracker, "get_recent_events", return_value=events):
            with patch.object(self.cli, "_create_terminal_chat_runtime", side_effect=AssertionError("runtime initialized")):
                with patch("builtins.input", side_effect=["/audit 1", "/exit"]):
                    with patch("builtins.print") as output:
                        self.cli.hello(SimpleNamespace(chat_id=-1))

        printed = "\n".join(str(call.args[0]) for call in output.call_args_list)
        self.assertIn("command_executed", printed)
        self.assertIn("whoami", printed)

    def test_terminal_details_outputs_pending_approval(self):
        class FakeAgent:
            async def get_pending_approval_details(self, chat_id, approval_id=None, include_llm=True):
                self.request = (chat_id, approval_id, include_llm)
                return {
                    "ok": True,
                    "approval_id": "AP-1",
                    "command": "systemctl restart sshd",
                    "command_hash": "abcdef1234567890",
                    "reason": "restart ssh service",
                    "analysis": {
                        "risk_level": "HIGH",
                        "safety_status": "UNSAFE",
                        "mutation_detected": True,
                        "deletion_detected": False,
                        "impact_analysis": "Restarts SSH service.",
                    },
                }

            async def stop(self):
                pass

        fake_agent = FakeAgent()
        runtime = self.cli._TerminalChatRuntime(fake_agent, -5)
        with patch.object(self.cli, "_create_terminal_chat_runtime", return_value=runtime):
            with patch("builtins.input", side_effect=["/details", "/exit"]):
                with patch("builtins.print") as output:
                    self.cli.hello(SimpleNamespace(chat_id=-5))

        self.assertEqual(fake_agent.request, (-5, None, True))
        printed = "\n".join(str(call.args[0]) for call in output.call_args_list)
        self.assertIn("ChatDome · details", printed)
        self.assertIn("Approval details", printed)
        self.assertIn("systemctl restart sshd", printed)
        self.assertIn("Risk: HIGH    Safety: UNSAFE", printed)
        self.assertIn("Flags: modifies system", printed)
        self.assertNotIn("Command hash:", printed)
        self.assertNotIn("Mutation:", printed)
        self.assertNotIn("Deletion:", printed)
        self.assertIn("\nAllow operation? [y/n]", printed)
        self.assertNotIn("│ Allow operation? [y/n]", printed)
        self.assertNotIn("Approval ID:", printed)

    def test_terminal_pending_approval_accepts_yes_no_and_details_choice(self):
        compact = self.cli._format_terminal_pending_approval(
            {
                "approval_id": "AP-1",
                "risk_level": "HIGH",
                "command": "systemctl restart sshd",
                "command_hash": "abcdef1234567890",
            }
        )
        self.assertIn("Approval required", compact)
        self.assertIn("Allow operation? [y/n]  d=details", compact)
        self.assertNotIn("Approval ID", compact)
        self.assertNotIn("systemctl restart sshd", compact)

        class FakeAgent:
            def __init__(self):
                self.messages = []
                self.detail_requests = []
                self.resume_calls = []

            async def handle_message(self, chat_id, message):
                self.messages.append((chat_id, message))
                return SimpleNamespace(
                    kind="pending_approval",
                    content="",
                    payload={
                        "approval_id": "AP-1",
                        "risk_level": "HIGH",
                        "command": "systemctl restart sshd",
                        "command_hash": "abcdef1234567890",
                    },
                )

            async def get_pending_approval_details(self, chat_id, approval_id=None, include_llm=True):
                self.detail_requests.append((chat_id, approval_id, include_llm))
                return {
                    "ok": True,
                    "approval_id": "AP-1",
                    "command": "systemctl restart sshd",
                    "command_hash": "abcdef1234567890",
                    "reason": "restart ssh service",
                    "analysis": {
                        "risk_level": "HIGH",
                        "safety_status": "UNSAFE",
                        "mutation_detected": True,
                        "deletion_detected": False,
                        "impact_analysis": "Restarts SSH service.",
                    },
                }

            async def resume_session(self, chat_id, action, approval_id=None):
                self.resume_calls.append((chat_id, action, approval_id))
                return "", SimpleNamespace(kind="reply", content=f"{action.lower()} ok", payload={})

            async def stop(self):
                pass

        fake_agent = FakeAgent()
        runtime = self.cli._TerminalChatRuntime(fake_agent, -11)
        prompts = []
        values = iter(["task", "d", "y", "task", "n", "/exit"])

        def fake_input(prompt):
            prompts.append(prompt)
            return next(values)

        with patch.object(self.cli, "_create_terminal_chat_runtime", return_value=runtime):
            with patch("builtins.input", side_effect=fake_input):
                with patch("builtins.print") as output:
                    self.cli.hello(SimpleNamespace(chat_id=-11))

        self.assertEqual(fake_agent.messages, [(-11, "task"), (-11, "task")])
        self.assertEqual(fake_agent.detail_requests, [(-11, None, True)])
        self.assertEqual(fake_agent.resume_calls, [(-11, "APPROVE", None), (-11, "REJECT", None)])
        self.assertEqual(
            prompts,
            ["› ", "approve [y/n/d]> ", "approve [y/n]> ", "› ", "approve [y/n/d]> ", "› "],
        )
        printed = "\n".join(str(call.args[0]) for call in output.call_args_list)
        self.assertIn("ChatDome · approval", printed)
        self.assertIn("Allow operation? [y/n]  d=details", printed)
        self.assertIn("Approval details", printed)
        self.assertNotIn("│ Allow operation? [y/n]", printed)
        self.assertIn("approve ok", printed)
        self.assertIn("reject ok", printed)
        self.assertNotIn("Approval ID:", printed)


    def test_terminal_details_full_expands_reason_and_impact_without_hash(self):
        class FakeAgent:
            async def get_pending_approval_details(self, chat_id, approval_id=None, include_llm=True):
                self.request = (chat_id, approval_id, include_llm)
                return {
                    "ok": True,
                    "approval_id": "AP-1",
                    "command": "rm -rf /tmp/chatdome-old",
                    "command_hash": "abcdef1234567890",
                    "reason": "clean old temporary files",
                    "analysis": {
                        "risk_level": "HIGH",
                        "safety_status": "UNSAFE",
                        "mutation_detected": True,
                        "deletion_detected": True,
                        "impact_analysis": "Removes old temporary files and may delete data if the path is wrong.",
                    },
                }

            async def stop(self):
                pass

        fake_agent = FakeAgent()
        runtime = self.cli._TerminalChatRuntime(fake_agent, -12)
        with patch.object(self.cli, "_create_terminal_chat_runtime", return_value=runtime):
            with patch("builtins.input", side_effect=["/details full", "/exit"]):
                with patch("builtins.print") as output:
                    self.cli.hello(SimpleNamespace(chat_id=-12))

        self.assertEqual(fake_agent.request, (-12, None, True))
        printed = "\n".join(str(call.args[0]) for call in output.call_args_list)
        self.assertIn("Flags: modifies system, deletes files", printed)
        self.assertIn("Reason:", printed)
        self.assertIn("clean old temporary files", printed)
        self.assertIn("Removes old temporary files and may delete data if the path is wrong.", printed)
        self.assertNotIn("Command hash:", printed)


    def test_terminal_continue_uses_round_limit_resolution(self):
        class FakeAgent:
            def __init__(self):
                self.continued = []
                self.resume_calls = []

            async def resolve_round_limit(self, chat_id, action):
                self.continued.append((chat_id, action))
                return SimpleNamespace(kind="reply", content="continued", payload={})

            async def resume_session(self, chat_id, action, approval_id=None):
                self.resume_calls.append((chat_id, action, approval_id))
                return "", SimpleNamespace(kind="reply", content="approved", payload={})

            async def stop(self):
                pass

        fake_agent = FakeAgent()
        runtime = self.cli._TerminalChatRuntime(fake_agent, -6)
        with patch.object(self.cli, "_create_terminal_chat_runtime", return_value=runtime):
            with patch("builtins.input", side_effect=["/continue", "/confirm AP-1", "/exit"]):
                with patch("builtins.print"):
                    self.cli.hello(SimpleNamespace(chat_id=-6))

        self.assertEqual(fake_agent.continued, [(-6, "CONTINUE")])
        self.assertEqual(fake_agent.resume_calls, [(-6, "APPROVE", "AP-1")])

    def test_terminal_round_limit_accepts_yes_no_choice(self):
        class FakeSessionManager:
            def get_or_create(self, _chat_id):
                return SimpleNamespace(pending_round_limit=True, pending_approval=False)

        class FakeAgent:
            def __init__(self):
                self.messages = []
                self.resolutions = []
                self.session_manager = FakeSessionManager()

            async def handle_message(self, chat_id, message):
                self.messages.append((chat_id, message))
                return SimpleNamespace(
                    kind="round_limit",
                    content="",
                    payload={"rounds": 10, "window": 5},
                )

            async def resolve_round_limit(self, chat_id, action):
                self.resolutions.append((chat_id, action))
                return SimpleNamespace(kind="reply", content=f"resolved {action}", payload={})

            async def stop(self):
                pass

        fake_agent = FakeAgent()
        runtime = self.cli._TerminalChatRuntime(fake_agent, -10)
        with patch.object(self.cli, "_create_terminal_chat_runtime", return_value=runtime):
            with patch("builtins.input", side_effect=["task", "y", "task", "n", "/exit"]):
                with patch("builtins.print") as output:
                    self.cli.hello(SimpleNamespace(chat_id=-10))

        self.assertEqual(fake_agent.messages, [(-10, "task"), (-10, "task")])
        self.assertEqual(fake_agent.resolutions, [(-10, "CONTINUE"), (-10, "ABANDON")])
        printed = "\n".join(str(call.args[0]) for call in output.call_args_list)
        self.assertIn("Continue? [y/n]", printed)
        self.assertIn("resolved CONTINUE", printed)
        self.assertIn("resolved ABANDON", printed)

    def test_read_terminal_line_handles_ctrl_h_backspace(self):
        class FakeIn:
            def __init__(self):
                self.chars = iter("ab\x08c\n")

            def isatty(self):
                return True

            def fileno(self):
                return 0

            def read(self, _size):
                return next(self.chars)

        class FakeOut:
            def __init__(self):
                self.text = ""

            def isatty(self):
                return True

            def write(self, value):
                self.text += value

            def flush(self):
                pass

        fake_in = FakeIn()
        fake_out = FakeOut()
        fake_termios = SimpleNamespace(
            TCSADRAIN=0,
            tcgetattr=lambda _fd: ["old"],
            tcsetattr=lambda _fd, _when, _attrs: None,
        )
        fake_tty = SimpleNamespace(setraw=lambda _fd: None)
        modules = {"termios": fake_termios, "tty": fake_tty}
        with patch.dict(sys.modules, modules):
            with patch.object(sys, "stdin", fake_in):
                with patch.object(sys, "stdout", fake_out):
                    line = self.cli._read_terminal_line("you> ")

        self.assertEqual(line, "ac")
        self.assertIn("\b \b", fake_out.text)

    def test_terminal_command_completion_matches_model_commands(self):
        self.assertEqual(self.cli._terminal_command_matches("/l"), ["/model_list"])
        self.assertEqual(self.cli._terminal_command_matches("/m")[0], "/model")
        self.assertEqual(self.cli._terminal_command_matches("/model other"), [])

    def test_terminal_command_registry_completes_model_profiles(self):
        registry = self.cli._build_terminal_command_registry()

        self.assertEqual(registry.command_matches("/l"), ["/model_list"])
        self.assertEqual(registry.completions("/m")[0].text, "/model")
        self.assertEqual(registry.completions("/model ")[0].text, "base")

    def test_prompt_toolkit_completer_exposes_async_interface(self):
        from chatdome.terminal.prompt_toolkit_view import PromptToolkitCommandCompleter

        class FakeCompletion:
            def __init__(self, text, **_kwargs):
                self.text = text

        fake_completion_module = SimpleNamespace(Completion=FakeCompletion)
        fake_prompt_module = SimpleNamespace(completion=fake_completion_module)
        registry = self.cli._build_terminal_command_registry()
        completer = PromptToolkitCommandCompleter(registry)

        async def collect():
            document = SimpleNamespace(text_before_cursor="/m")
            with patch.dict(
                sys.modules,
                {
                    "prompt_toolkit": fake_prompt_module,
                    "prompt_toolkit.completion": fake_completion_module,
                },
            ):
                return [item.text async for item in completer.get_completions_async(document, None)]

        self.assertIn("/model", asyncio.run(collect()))

    def test_terminal_prompt_reflects_approval_and_continue_state(self):
        self.assertEqual(
            self.cli._terminal_prompt_for_state(self.cli.ChatSessionState.APPROVAL_REQUIRED),
            "approve [y/n/d]> ",
        )
        self.assertEqual(
            self.cli._terminal_prompt_for_state(self.cli.ChatSessionState.APPROVAL_DETAILS),
            "approve [y/n]> ",
        )
        self.assertEqual(
            self.cli._terminal_prompt_for_state(self.cli.ChatSessionState.CONTINUATION_REQUIRED),
            "continue [y/n]> ",
        )

        class FakeSessionManager:
            def __init__(self, agent):
                self._agent = agent

            def get_or_create(self, _chat_id):
                return SimpleNamespace(
                    pending_round_limit=self._agent.pending_kind == "round_limit",
                    pending_approval=self._agent.pending_kind == "approval",
                )

        class FakeAgent:
            def __init__(self):
                self.messages = []
                self.resume_calls = []
                self.resolutions = []
                self.pending_kind = None
                self.session_manager = FakeSessionManager(self)

            async def handle_message(self, chat_id, message):
                self.messages.append((chat_id, message))
                if message == "needs approval":
                    self.pending_kind = "approval"
                    return SimpleNamespace(kind="pending_approval", content="", payload={})
                self.pending_kind = "round_limit"
                return SimpleNamespace(kind="round_limit", content="", payload={"rounds": 10})

            async def resume_session(self, chat_id, action, approval_id=None):
                self.pending_kind = None
                self.resume_calls.append((chat_id, action, approval_id))
                return "", SimpleNamespace(kind="reply", content="rejected", payload={})

            async def resolve_round_limit(self, chat_id, action):
                self.pending_kind = None
                self.resolutions.append((chat_id, action))
                return SimpleNamespace(kind="reply", content="stopped", payload={})

            async def stop(self):
                pass

        fake_agent = FakeAgent()
        runtime = self.cli._TerminalChatRuntime(fake_agent, -13)
        prompts = []
        values = iter(["needs approval", "n", "needs continue", "n", "/exit"])

        def fake_input(prompt):
            prompts.append(prompt)
            return next(values)

        with patch.object(self.cli, "_create_terminal_chat_runtime", return_value=runtime):
            with patch("builtins.input", side_effect=fake_input):
                with patch("builtins.print"):
                    self.cli.hello(SimpleNamespace(chat_id=-13))

        self.assertEqual(prompts, ["› ", "approve [y/n/d]> ", "› ", "continue [y/n]> ", "› "])
        self.assertEqual(fake_agent.resume_calls, [(-13, "REJECT", None)])
        self.assertEqual(fake_agent.resolutions, [(-13, "ABANDON")])


    def test_terminal_prompt_can_be_overridden(self):
        with patch.dict("os.environ", {}, clear=True):
            self.assertEqual(self.cli._terminal_prompt(), "› ")
        with patch.dict("os.environ", {"CHATDOME_PROMPT": ""}):
            self.assertEqual(self.cli._terminal_prompt(), "")
        with patch.dict("os.environ", {"CHATDOME_PROMPT": "chat> "}):
            self.assertEqual(self.cli._terminal_prompt(), "chat> ")
            self.assertEqual(self.cli._terminal_prompt_for_state(self.cli.ChatSessionState.IDLE), "chat> ")
    def test_terminal_retry_replays_last_failed_message(self):
        class FakeAgent:
            def __init__(self):
                self.messages = []
                self.stopped = False

            async def handle_message(self, chat_id, message):
                self.messages.append((chat_id, message))
                if len(self.messages) == 1:
                    raise RuntimeError("boom")
                return SimpleNamespace(kind="reply", content=f"retried {message}", payload={})

            async def stop(self):
                self.stopped = True

        fake_agent = FakeAgent()
        runtime = self.cli._TerminalChatRuntime(fake_agent, -8)

        with patch.object(self.cli, "_create_terminal_chat_runtime", return_value=runtime):
            with patch("builtins.input", side_effect=["fail", "/retry", "/exit"]):
                with patch("builtins.print") as output:
                    self.cli.hello(SimpleNamespace(chat_id=-8))

        self.assertEqual(fake_agent.messages, [(-8, "fail"), (-8, "fail")])
        self.assertTrue(fake_agent.stopped)
        printed = "\n".join(str(call.args[0]) for call in output.call_args_list)
        self.assertIn("ChatDome · error", printed)
        self.assertIn("Request failed.", printed)
        self.assertIn("Run: /retry", printed)
        self.assertIn("retried fail", printed)

    def test_read_terminal_line_completes_single_slash_command_match(self):
        class FakeIn:
            def __init__(self):
                self.chars = iter("/l\n")

            def isatty(self):
                return True

            def fileno(self):
                return 0

            def read(self, _size):
                return next(self.chars)

        class FakeOut:
            def __init__(self):
                self.text = ""

            def isatty(self):
                return True

            def write(self, value):
                self.text += value

            def flush(self):
                pass

        fake_in = FakeIn()
        fake_out = FakeOut()
        fake_termios = SimpleNamespace(
            TCSADRAIN=0,
            tcgetattr=lambda _fd: ["old"],
            tcsetattr=lambda _fd, _when, _attrs: None,
        )
        fake_tty = SimpleNamespace(setraw=lambda _fd: None)
        modules = {"termios": fake_termios, "tty": fake_tty}
        with patch.dict(sys.modules, modules):
            with patch.object(sys, "stdin", fake_in):
                with patch.object(sys, "stdout", fake_out):
                    line = self.cli._read_terminal_line("you> ")

        self.assertEqual(line, "/model_list")
        self.assertIn("/model_list", fake_out.text)

    def test_terminal_model_commands_list_and_switch(self):
        class FakeManager:
            def __init__(self):
                self.switched = []

            def get_active_profile_name(self):
                return "base"

            def list_profiles(self):
                return [
                    SimpleNamespace(
                        name="base",
                        provider="openai",
                        api_mode="openai_api",
                        model="gpt-4o",
                        base_url="https://api.openai.com/v1",
                        key_ref="configured fp=12345678",
                        status="ready",
                        active=True,
                    ),
                    SimpleNamespace(
                        name="other",
                        provider="openai",
                        api_mode="openai_api",
                        model="gpt-4o-mini",
                        base_url="https://api.openai.com/v1",
                        key_ref="configured fp=87654321",
                        status="ready",
                        active=False,
                    ),
                ]

            async def switch_profile(self, profile_name):
                self.switched.append(profile_name)
                return SimpleNamespace(
                    profile_name=profile_name,
                    profile=SimpleNamespace(
                        provider="openai",
                        api_mode="openai_api",
                        model="gpt-4o-mini",
                    ),
                )

        class FakeAgent:
            def __init__(self):
                self.llm_manager = FakeManager()

        fake_agent = FakeAgent()
        runtime = self.cli._TerminalChatRuntime(fake_agent, -7)

        with patch("builtins.print") as output:
            asyncio.run(self.cli._handle_terminal_command(runtime, "/model_list"))
            asyncio.run(self.cli._handle_terminal_command(runtime, "/model other"))
            asyncio.run(self.cli._handle_terminal_command(runtime, "/llm_list"))

        self.assertEqual(fake_agent.llm_manager.switched, ["other"])
        printed = "\n".join(str(call.args[0]) for call in output.call_args_list)
        self.assertIn("Switch: /model <profile_name>", printed)
        self.assertIn("  /model other", printed)
        self.assertIn("model switched for this terminal session: other", printed)

    def test_set_admin_chat_ids_writes_telegram_config(self):
        with patch("builtins.print") as output:
            self.cli.set_admin_chat_ids(SimpleNamespace(chat_ids="1, 2"))
            output.assert_called_once_with(
                "admin_chat_ids updated. Restart ChatDome for this change to take effect."
            )

        data = yaml.safe_load(self.config_path.read_text(encoding="utf-8"))
        self.assertEqual(data["chatdome"]["telegram"]["admin_chat_ids"], [1, 2])

    def test_telegram_status_shows_effective_llm_admin_chat_ids(self):
        with patch("builtins.print"):
            self.cli.set_chat_ids(SimpleNamespace(chat_ids="123"))

        with patch("builtins.print") as output:
            self.cli.telegram_status(SimpleNamespace())

        output.assert_any_call("- allowed chat ids: [123]")
        output.assert_any_call("- model admin chat ids: [123]")

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




class ChatDomeCLIHelloTests(unittest.TestCase):
    def test_hello_starts_terminal_chat_and_exits(self):
        result = subprocess.run(
            [sys.executable, str(CLI_PATH), "hello"],
            text=True,
            input="/exit\n",
            capture_output=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("CHATDOME", result.stdout)
        self.assertIn("____  _   _", result.stdout)
        self.assertIn("|_____|", result.stdout)
        self.assertLessEqual(max(len(line) for line in result.stdout.splitlines()), 72)


if __name__ == "__main__":
    unittest.main()
