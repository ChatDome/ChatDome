#!/usr/bin/env python3
"""Local management helper for the ChatDome interactive menu."""

from __future__ import annotations

import argparse
import asyncio
import inspect
import json
import logging
import os
import re
import shlex
import stat
import sys
import time
import traceback
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parent
CONFIG_PATH = Path(os.environ.get("CHATDOME_CONFIG", str(ROOT / "config.yaml"))).expanduser()
EXAMPLE_CONFIG_PATH = ROOT / "config.example.yaml"
DATA_DIR = Path(os.environ.get("CHATDOME_DATA_DIR", str(ROOT / "chat_data"))).expanduser()
RUN_DIR = Path(os.environ.get("CHATDOME_RUN_DIR", str(DATA_DIR / "run"))).expanduser()
PID_PATH = RUN_DIR / "chatdome.pid"
READY_PATH = RUN_DIR / "ready.json"
RELOAD_REQUEST_PATH = RUN_DIR / "reload_request.json"
RELOAD_STATUS_PATH = RUN_DIR / "reload_status.json"
ENV_PROFILE_PATH = DATA_DIR / "environment" / "profile.md"
LEGACY_ENV_PROFILE_PATH = DATA_DIR / "environment_profile.md"
LLM_PROFILE_LOCK_PATH = RUN_DIR / "llm-profile.lock"
SUPPORTED_RELOAD_DOMAINS = {"llm", "sentinel", "agent", "all"}
CONTROLPLANE_SRC = ROOT / "controlplane" / "src"
TOKEN_NAME_PATTERN = re.compile(r"[^A-Za-z0-9_.-]+")

if CONTROLPLANE_SRC.is_dir():
    sys.path.insert(0, str(CONTROLPLANE_SRC))

from chatdome import __version__
from chatdome.agent.audit import CommandAuditTracker
from chatdome.config import validate_profile_name
from chatdome.errors import ChatDomeError, user_facing_error_message
from chatdome.executor.cmd_parser import parse_shell_command
from chatdome.logger import ChatDomeFormatter, ExcludeSentinelFilter, OriginFilter, _build_file_handler
from chatdome.llm.profile_admin import (
    CreateCodexProfileRequest,
    CreateOpenAIProfileRequest,
    LLMProfileAdminService,
    ProfileActor,
    ProfileConfigStore,
)
from chatdome.terminal import (
    ChatSessionController,
    ChatSessionState,
    CommandDef,
    CommandInvocation,
    CommandRegistry,
    CommandResult,
    CompletionItem,
    PlainTerminalChatView,
    TerminalChatApp,
)

PROFILE_AUDIT_RECORDER = CommandAuditTracker.record_event
CHATDOME_LOGO = r"""    ____  _   _   ___   _____  ____    ___   __  __  _____
   / ___|| | | | / _ \ |_   _||  _ \  / _ \ |  \/  || ____|
  / /    | |_| |/ /_\ \  | |  | | | |/ / \ \| |\/| ||  _|
 / /___  |  _  ||  _  |  | |  | |_| |\ \_/ /| |  | || |___
 \_____| |_| |_||_| |_|  |_|  |____/  \___/ |_|  |_||_____|"""


def _cli_error_log_candidates() -> list[Path]:
    candidates: list[Path] = []
    if os.environ.get("CHATDOME_CLI_LOG_FILE"):
        candidates.append(Path(os.environ["CHATDOME_CLI_LOG_FILE"]).expanduser())
    if os.environ.get("CHATDOME_LOG_DIR"):
        candidates.append(Path(os.environ["CHATDOME_LOG_DIR"]).expanduser() / "chatdome-cli.log")
    candidates.append(DATA_DIR / "chatdome-cli.log")

    unique: list[Path] = []
    seen: set[str] = set()
    for path in candidates:
        key = str(path)
        if key not in seen:
            seen.add(key)
            unique.append(path)
    return unique


def _append_cli_exception_log(action: str, exc: BaseException) -> tuple[Path, bool]:
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    detail = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))

    candidates = _cli_error_log_candidates()
    for log_path in candidates:
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with log_path.open("a", encoding="utf-8") as handle:
                handle.write(f"\n[{timestamp}] {action} failed\n")
                handle.write(detail)
                if not detail.endswith("\n"):
                    handle.write("\n")
            return log_path, True
        except OSError:
            continue
    return candidates[0], False


def _setup_cli_file_logging() -> None:
    log_file = str(os.environ.get("CHATDOME_LOG_FILE") or "").strip()
    if not log_file:
        return

    root_logger = logging.getLogger()
    target = str(Path(log_file).expanduser())
    for handler in root_logger.handlers:
        if (
            getattr(handler, "_chatdome_cli_file_handler", False)
            and getattr(handler, "baseFilename", "") == target
        ):
            return

    formatter = ChatDomeFormatter(
        datefmt="%Y-%m-%d %H:%M:%S",
        use_colors=False,
    )
    handler = _build_file_handler(log_file, formatter)
    handler.addFilter(OriginFilter())
    handler.addFilter(ExcludeSentinelFilter())
    handler._chatdome_cli_file_handler = True
    root_logger.addHandler(handler)
    root_logger.setLevel(logging.INFO)


def _tail_log_command(log_path: Path) -> str:
    return f"tail -n 80 {shlex.quote(str(log_path))}"


def _exit_with_logged_error(action: str, exc: BaseException, *, fallback: str) -> None:
    log_path, logged = _append_cli_exception_log(action, exc)
    print(user_facing_error_message(exc, fallback=fallback))
    if isinstance(exc, ChatDomeError) and exc.retryable:
        print("操作: 稍后重试，或切换网络后重新认证。")
    if logged:
        print(f"查看日志: {_tail_log_command(log_path)}")
    else:
        print(f"日志写入失败。检查目录权限: {log_path.parent}")
    raise SystemExit(1) from None


def _chmod_owner_only(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _load_yaml(path: Path | None = None) -> dict[str, Any]:
    path = path or CONFIG_PATH
    if not path.exists():
        ensure_config()
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise SystemExit(f"Invalid YAML object: {path}")
    data.setdefault("chatdome", {})
    if not isinstance(data["chatdome"], dict):
        raise SystemExit("chatdome root must be a mapping")
    return data


def _write_yaml(data: dict[str, Any], path: Path | None = None) -> None:
    path = path or CONFIG_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(data, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )
    _chmod_owner_only(path)


def ensure_config(args: argparse.Namespace | None = None) -> None:
    del args
    if CONFIG_PATH.exists():
        _chmod_owner_only(CONFIG_PATH)
        print(f"config exists: {CONFIG_PATH}")
        return
    if not EXAMPLE_CONFIG_PATH.exists():
        raise SystemExit(f"missing template: {EXAMPLE_CONFIG_PATH}")
    CONFIG_PATH.write_text(EXAMPLE_CONFIG_PATH.read_text(encoding="utf-8"), encoding="utf-8")
    _chmod_owner_only(CONFIG_PATH)
    print(f"created: {CONFIG_PATH}")


def _chatdome_root(data: dict[str, Any]) -> dict[str, Any]:
    return data.setdefault("chatdome", {})


def _section(root: dict[str, Any], name: str) -> dict[str, Any]:
    value = root.setdefault(name, {})
    if not isinstance(value, dict):
        value = {}
        root[name] = value
    return value


def _mask_secret(value: str, keep: int = 4) -> str:
    text = str(value or "")
    if not text:
        return "(empty)"
    if len(text) <= keep * 2:
        return "*" * len(text)
    return f"{text[:keep]}...{text[-keep:]}"


def _parse_chat_ids(raw: str) -> list[int]:
    values: list[int] = []
    for part in str(raw or "").split(","):
        item = part.strip()
        if not item:
            continue
        try:
            values.append(int(item))
        except ValueError as exc:
            raise SystemExit(f"invalid chat id: {item}") from exc
    return values


def _llm_admin_chat_ids_display(telegram: dict[str, Any]) -> list[int] | str:
    admin_chat_ids = telegram.get("admin_chat_ids") or []
    if admin_chat_ids:
        return admin_chat_ids
    allowed_chat_ids = telegram.get("allowed_chat_ids") or []
    return allowed_chat_ids or "(none)"


def _validate_profile_name(profile: str) -> str:
    try:
        return validate_profile_name(profile)
    except ValueError as exc:
        raise SystemExit("invalid profile name") from exc


def _default_codex_token_file(profile: str) -> str:
    name = TOKEN_NAME_PATTERN.sub("_", _validate_profile_name(profile))
    name = name.strip("._-") or "codex"
    return f"~/.chatdome/codex-auth/{name}.json"


def _codex_token_file_path(token_file: str) -> Path:
    if str(token_file or "").strip():
        return Path(token_file).expanduser()
    return Path.home() / ".chatdome" / "auth.json"


def _resolve_codex_token_file(
    profile_name: str,
    requested_token_file: str | None,
    existing_profile: dict[str, Any] | None = None,
) -> str:
    requested = None if requested_token_file is None else str(requested_token_file).strip()
    if requested:
        return requested
    if isinstance(existing_profile, dict) and "codex_token_file" in existing_profile:
        return str(existing_profile.get("codex_token_file") or "")
    return _default_codex_token_file(profile_name)


def _resolve_codex_login_token_file(
    profile_name: str,
    requested_token_file: str | None,
    existing_profile: dict[str, Any] | None = None,
) -> str:
    requested = None if requested_token_file is None else str(requested_token_file).strip()
    if requested:
        return requested
    if isinstance(existing_profile, dict):
        existing_token_file = str(existing_profile.get("codex_token_file") or "").strip()
        if existing_token_file:
            return existing_token_file
    return _default_codex_token_file(profile_name)


def _truthy(raw: str) -> bool:
    value = str(raw or "").strip().lower()
    if value in {"1", "true", "yes", "on", "enable", "enabled"}:
        return True
    if value in {"0", "false", "no", "off", "disable", "disabled"}:
        return False
    raise SystemExit(f"invalid boolean value: {raw}")


def _process_running(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _read_pid() -> int:
    try:
        return int(PID_PATH.read_text(encoding="utf-8").strip())
    except (FileNotFoundError, ValueError):
        return 0


def validate_config(args: argparse.Namespace) -> None:
    del args
    from chatdome.config import load_config

    try:
        load_config(CONFIG_PATH)
    except Exception as exc:
        raise SystemExit(f"Configuration error: {exc}") from None
    print(f"config valid: {CONFIG_PATH}")


def health_check(args: argparse.Namespace) -> None:
    del args
    pid = _read_pid()
    if not _process_running(pid):
        raise SystemExit("ChatDome process is not running.")
    try:
        ready = json.loads(READY_PATH.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError) as exc:
        raise SystemExit("ChatDome application is not ready.") from exc
    if int(ready.get("pid", 0)) != pid:
        raise SystemExit("ChatDome health state does not match the running process.")
    print(f"ChatDome healthy: pid={pid}")


def _config_root_for_report() -> tuple[dict[str, Any], str]:
    if not CONFIG_PATH.exists():
        return {}, "missing"
    try:
        data = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        return {}, f"invalid: {exc}"
    if not isinstance(data, dict):
        return {}, "invalid: YAML root must be a mapping"
    root = data.get("chatdome") or {}
    if not isinstance(root, dict):
        return {}, "invalid: chatdome root must be a mapping"
    return root, "ready"


def _profile_status(root: dict[str, Any]) -> tuple[str, str]:
    active = str(root.get("active_ai_profile") or "").strip()
    profiles = root.get("ai_profiles") if isinstance(root.get("ai_profiles"), dict) else {}
    if not active:
        return "missing", "active profile not set"
    profile = profiles.get(active) if isinstance(profiles, dict) else None
    if not isinstance(profile, dict):
        return "missing", f"profile not found: {active}"
    provider = str(profile.get("provider") or "openai").strip() or "openai"
    api_mode = str(profile.get("api_mode") or "openai_api").strip() or "openai_api"
    model = str(profile.get("model") or "(unset)").strip() or "(unset)"
    if api_mode in {"codex", "codex_responses", "codex_oauth"} or provider == "codex":
        token_file = str(profile.get("codex_token_file") or "~/.chatdome/auth.json")
        status = "ready" if _codex_token_file_path(token_file).is_file() else "missing token"
    else:
        status = "ready" if str(profile.get("api_key") or "").strip() else "missing api_key"
    return status, f"{provider} / {model} (profile={active})"


def _sentinel_status(root: dict[str, Any]) -> str:
    sentinel = root.get("sentinel") if isinstance(root.get("sentinel"), dict) else {}
    if not sentinel.get("enabled", False):
        return "disabled"
    checks = sentinel.get("checks") if isinstance(sentinel.get("checks"), list) else []
    return f"enabled, checks={len(checks)}"


def _telegram_status(root: dict[str, Any]) -> str:
    telegram = root.get("telegram") if isinstance(root.get("telegram"), dict) else {}
    return "ready" if str(telegram.get("bot_token") or "").strip() else "missing bot_token"


def show_status(args: argparse.Namespace) -> None:
    del args
    root, config_status = _config_root_for_report()
    pid = _read_pid()
    running = _process_running(pid)
    llm_status, llm_detail = _profile_status(root)

    print("ChatDome status")
    print(f"- Version: {__version__}")
    print(f"- Config: {config_status} ({CONFIG_PATH})")
    print(f"- Service: {'running' if running else 'stopped'}")
    print(f"- Model: {llm_status} ({llm_detail})")
    print(f"- Telegram: {_telegram_status(root)}")
    print(f"- Sentinel: {_sentinel_status(root)}")
    print(f"- Logs: {os.environ.get('CHATDOME_LOG_DIR', str(DATA_DIR))}")


class _TerminalChatRuntime:
    def __init__(self, agent: Any, chat_id: int) -> None:
        self.agent = agent
        self.chat_id = chat_id


class _TerminalRuntimeProvider:
    def __init__(self, args: argparse.Namespace) -> None:
        self._args = args
        self._runtime: _TerminalChatRuntime | None = None
        self.last_message: str | None = None
        self.last_failed_message: str | None = None

    @property
    def runtime(self) -> _TerminalChatRuntime | None:
        return self._runtime

    @property
    def chat_id(self) -> int:
        return _terminal_chat_id(self._args)

    def get(self) -> _TerminalChatRuntime:
        if self._runtime is None:
            self._runtime = _create_terminal_chat_runtime(self._args)
        return self._runtime

    async def stop(self) -> None:
        runtime = self._runtime
        if runtime is None:
            return
        stop = getattr(runtime.agent, "stop", None)
        if not callable(stop):
            return
        try:
            await stop()
        except Exception:
            pass


class _StaticTerminalRuntimeProvider:
    def __init__(self, runtime: _TerminalChatRuntime) -> None:
        self._runtime = runtime
        self.last_failed_message: str | None = None

    @property
    def runtime(self) -> _TerminalChatRuntime:
        return self._runtime

    @property
    def chat_id(self) -> int:
        return self._runtime.chat_id

    def get(self) -> _TerminalChatRuntime:
        return self._runtime

    async def stop(self) -> None:
        return None


def _terminal_chat_id(args: argparse.Namespace) -> int:
    raw = getattr(args, "chat_id", None)
    if raw is None:
        raw = os.environ.get("CHATDOME_CLI_CHAT_ID", "-1")
    try:
        return int(raw)
    except (TypeError, ValueError):
        return -1


def _sync_terminal_runtime_paths() -> None:
    os.environ["CHATDOME_CONFIG"] = str(CONFIG_PATH)
    os.environ["CHATDOME_DATA_DIR"] = str(DATA_DIR)
    os.environ["CHATDOME_RUN_DIR"] = str(RUN_DIR)
    try:
        import chatdome.agent.audit as audit_module

        audit_module.AUDIT_DIR = DATA_DIR / "audit"
    except Exception:
        pass


def _load_terminal_chat_config() -> Any:
    from chatdome.config import parse_config_document, validate_llm_config

    if not CONFIG_PATH.exists():
        raise FileNotFoundError(f"missing config: {CONFIG_PATH}")
    raw_document = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8")) or {}
    if not isinstance(raw_document, dict):
        raise ValueError("configuration document must be a mapping")
    config = parse_config_document(raw_document)
    validate_llm_config(config)
    return config


def _create_terminal_chat_runtime(args: argparse.Namespace) -> _TerminalChatRuntime:
    _sync_terminal_runtime_paths()
    config = _load_terminal_chat_config()

    from chatdome.agent.core import Agent
    from chatdome.agent.engram import EngramStore
    from chatdome.executor.sandbox import CommandSandbox
    from chatdome.llm.manager import LLMManager
    from chatdome.runtime_environment import collect_and_persist_runtime_environment
    from chatdome.sentinel.pack_loader import PackLoader
    from chatdome.sentinel.user_context import UserContextLedger

    pack_loader = PackLoader(builtin_dir=CONTROLPLANE_SRC / "chatdome" / "packs")
    pack_loader.load(enabled_packs=config.sentinel.builtin_packs)
    llm_manager = LLMManager(config.ai_profiles, config.active_ai_profile)
    sandbox = CommandSandbox(
        default_timeout=config.agent.command_timeout,
        max_output_chars=config.agent.max_output_chars,
        allow_generated_commands=config.agent.allow_generated_commands,
        allow_unrestricted_commands=config.agent.allow_unrestricted_commands,
        persist_command_outputs=config.agent.persist_command_outputs,
        command_output_retention_days=config.agent.command_output_retention_days,
        command_output_max_chars=config.agent.command_output_max_chars,
        pack_loader=pack_loader,
    )
    try:
        _, runtime_environment_context = collect_and_persist_runtime_environment(ENV_PROFILE_PATH)
    except Exception:
        runtime_environment_context = ""

    agent = Agent(
        llm=None,
        llm_manager=llm_manager,
        sandbox=sandbox,
        config=config.agent,
        runtime_environment_context=runtime_environment_context,
        pack_loader=pack_loader,
        user_context_ledger=UserContextLedger(),
        valid_check_ids=[str(c.get("check_id")) for c in config.sentinel.checks if c.get("check_id")],
        engram_store=EngramStore(),
    )
    return _TerminalChatRuntime(agent=agent, chat_id=_terminal_chat_id(args))



def _terminal_symbol(emoji: str, fallback: str) -> str:
    if os.environ.get("CHATDOME_PLAIN", "").strip().lower() in {"1", "true", "yes", "on"}:
        return fallback
    encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
    try:
        emoji.encode(encoding)
        return emoji
    except UnicodeEncodeError:
        return fallback


def _status_label(emoji: str, fallback: str, text: str) -> str:
    symbol = _terminal_symbol(emoji, fallback)
    return f"{symbol} {text}" if symbol else text


def _terminal_model_completion_items(arg_text: str) -> list[CompletionItem]:
    current_arg = "" if arg_text.endswith(" ") else arg_text.split()[-1] if arg_text else ""
    root, status = _config_root_for_report()
    if status != "ready":
        return []
    profiles = root.get("ai_profiles") if isinstance(root.get("ai_profiles"), dict) else {}
    active = str(root.get("active_ai_profile") or "").strip()
    items = []
    for name in sorted(str(key) for key in profiles):
        if current_arg and not name.startswith(current_arg):
            continue
        description = "current model profile" if name == active else "model profile"
        items.append(CompletionItem(text=name, display=name, description=description))
    return items


def _build_terminal_command_registry(
    runtime_provider: Any | None = None,
    stop_request_handler: Any | None = None,
) -> CommandRegistry:
    registry = CommandRegistry()

    def require_provider() -> Any:
        if runtime_provider is None:
            raise RuntimeError("terminal runtime unavailable")
        return runtime_provider

    async def help_handler(_invocation: CommandInvocation) -> CommandResult:
        _print_chatdome_message(_terminal_help_text())
        return CommandResult()

    async def clear_handler(_invocation: CommandInvocation) -> CommandResult:
        runtime = require_provider().get()
        runtime.agent.clear_session(runtime.chat_id)
        _print_chatdome_message(_status_label("✅", "[ok]", "Session cleared."))
        return CommandResult()

    async def exit_handler(_invocation: CommandInvocation) -> CommandResult:
        return CommandResult(keep_running=False)

    async def stop_handler(_invocation: CommandInvocation) -> CommandResult:
        stopped = False
        if stop_request_handler is not None:
            result = stop_request_handler()
            if inspect.isawaitable(result):
                result = await result
            stopped = bool(result)
        if stopped:
            _print_chatdome_message(_status_label("⏹️", "[stop]", "Task stopped."))
            return CommandResult(state=ChatSessionState.IDLE.value)
        _print_chatdome_message(_status_label("ℹ️", "[i]", "No running task."))
        return CommandResult()

    async def env_handler(_invocation: CommandInvocation) -> CommandResult:
        _print_chatdome_message(_terminal_environment_summary())
        return CommandResult()

    async def audit_handler(invocation: CommandInvocation) -> CommandResult:
        _sync_terminal_runtime_paths()
        provider = runtime_provider
        chat_id = provider.chat_id if provider is not None else -1
        parts = [invocation.command.name, *invocation.args]
        _print_chatdome_message(_format_terminal_audit_events(chat_id, _terminal_audit_limit(parts)))
        return CommandResult()

    async def model_handler(invocation: CommandInvocation) -> CommandResult:
        runtime = require_provider().get()
        profile_name = invocation.args[0] if invocation.args else None
        await _switch_terminal_model(runtime, profile_name)
        return CommandResult()

    async def model_list_handler(_invocation: CommandInvocation) -> CommandResult:
        runtime = require_provider().get()
        _print_chatdome_message(_format_terminal_model_profiles(runtime))
        return CommandResult()

    async def details_handler(invocation: CommandInvocation) -> CommandResult:
        runtime = require_provider().get()
        approval_id, full = _terminal_details_options(invocation.args)
        shown = await _show_terminal_details(runtime, approval_id, full=full)
        state = ChatSessionState.APPROVAL_DETAILS if shown else ChatSessionState.IDLE
        return CommandResult(state=state.value)


    async def confirm_handler(invocation: CommandInvocation) -> CommandResult:
        runtime = require_provider().get()
        approval_id = invocation.args[0] if invocation.args else None
        state = await _resolve_terminal_confirm(runtime, approval_id)
        return CommandResult(state=state)

    async def continue_handler(_invocation: CommandInvocation) -> CommandResult:
        runtime = require_provider().get()
        state = await _resolve_terminal_continue(runtime)
        return CommandResult(state=state)

    async def reject_handler(invocation: CommandInvocation) -> CommandResult:
        runtime = require_provider().get()
        approval_id = invocation.args[0] if invocation.args else None
        state = await _resolve_terminal_reject(runtime, approval_id)
        return CommandResult(state=state)

    async def retry_handler(_invocation: CommandInvocation) -> CommandResult:
        provider = require_provider()
        message = getattr(provider, "last_failed_message", None)
        if not message:
            _print_chatdome_message(_status_label("ℹ️", "[i]", "No failed request to retry."))
            return CommandResult()
        return await _send_terminal_user_message(provider, message)

    registry.register(CommandDef("/help", "Show commands", "basic", handler=help_handler))
    registry.register(CommandDef("/clear", "Clear this terminal session", "basic", handler=clear_handler))
    registry.register(CommandDef("/exit", "Exit terminal chat", "basic", aliases=("/quit",), handler=exit_handler))
    registry.register(CommandDef("/stop", "Stop current task", "control", handler=stop_handler))
    registry.register(CommandDef("/env", "Show environment summary", "context", handler=env_handler))
    registry.register(CommandDef("/audit", "Show recent command audit events", "context", args_hint="[N]", handler=audit_handler))
    registry.register(CommandDef("/model", "Switch current model profile", "model", aliases=("/llm",), args_hint="<profile>", handler=model_handler, completer=_terminal_model_completion_items))
    registry.register(CommandDef("/model_list", "Show configured model profiles", "model", aliases=("/llm_list", "/l"), keywords=("list", "llm"), handler=model_list_handler))
    registry.register(CommandDef("/details", "Show pending approval details", "approval", args_hint="[full]", handler=details_handler))
    registry.register(CommandDef("/confirm", "Approve pending command", "approval", handler=confirm_handler))
    registry.register(CommandDef("/reject", "Reject pending command or stop task", "approval", handler=reject_handler))
    registry.register(CommandDef("/continue", "Continue paused task", "approval", handler=continue_handler))
    registry.register(CommandDef("/retry", "Retry the last failed request", "recovery", handler=retry_handler))
    return registry


def _terminal_command_specs() -> list[tuple[str, str]]:
    return _build_terminal_command_registry().specs()


def _terminal_command_names() -> list[str]:
    return _build_terminal_command_registry().command_names()


def _terminal_command_matches(text: str) -> list[str]:
    return _build_terminal_command_registry().command_matches(text)


def _terminal_command_token(text: str) -> str:
    value = str(text or "")
    return value.split(maxsplit=1)[0] if value.strip() else value


def _replace_terminal_command_token(text: str, command: str) -> str:
    value = str(text or "")
    token = _terminal_command_token(value)
    suffix = value[len(token):] if token else ""
    return f"{command}{suffix}"


def _terminal_completion_line(matches: list[str], selected_index: int) -> str:
    visible = matches[:8]
    parts = []
    for index, command in enumerate(visible):
        parts.append(f"[{command}]" if index == selected_index else command)
    if len(matches) > len(visible):
        parts.append("...")
    return f"{_status_label('⌨️', '[cmd]', 'Commands:')} {'  '.join(parts)}"


def _print_terminal_completion(prompt: str, text: str, matches: list[str], selected_index: int) -> None:
    if not matches:
        return
    sys.stdout.write("\n")
    sys.stdout.write(_format_chatdome_block(_terminal_completion_line(matches, selected_index)) + "\n")
    sys.stdout.write(f"{prompt}{text}")
    sys.stdout.flush()


def _terminal_help_text() -> str:
    lines = [_status_label("🧭", "[i]", "Commands")]
    for usage, description in _terminal_command_specs():
        lines.append(f"  {usage:<18} {description}")
    return "\n".join(lines)

def _terminal_ascii_mode() -> bool:
    return os.environ.get("CHATDOME_PLAIN", "").strip().lower() in {"1", "true", "yes", "on"}


def _terminal_can_encode(value: str) -> bool:
    encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
    try:
        value.encode(encoding)
        return True
    except UnicodeEncodeError:
        return False


def _terminal_block_bar() -> str:
    return "|" if _terminal_ascii_mode() or not _terminal_can_encode("│") else "│"


def _terminal_default_prompt() -> str:
    return "> " if _terminal_ascii_mode() or not _terminal_can_encode("›") else "› "


def _terminal_message_title(first_line: str) -> str:
    normalized = " ".join(str(first_line or "").lower().split())
    if "approval required" in normalized:
        return "ChatDome · approval"
    if "approval details" in normalized or "loading approval details" in normalized:
        return "ChatDome · details"
    if "task paused" in normalized:
        return "ChatDome · paused"
    if "request failed" in normalized or "unknown command" in normalized:
        return "ChatDome · error"
    return "ChatDome"


_TERMINAL_APPROVAL_ACTION = "Allow operation? [y/n]"
_TERMINAL_APPROVAL_ACTION_WITH_DETAILS = "Allow operation? [y/n]  d=details"
_TERMINAL_ACTION_LINES = frozenset(
    {
        _TERMINAL_APPROVAL_ACTION,
        _TERMINAL_APPROVAL_ACTION_WITH_DETAILS,
    }
)


def _format_chatdome_block(text: str) -> str:
    value = str(text or "").rstrip()
    if not value:
        return "ChatDome"
    lines = value.splitlines()
    action_lines: list[str] = []
    while lines and lines[-1].strip() in _TERMINAL_ACTION_LINES:
        action_lines.insert(0, lines.pop().strip())
    while lines and not lines[-1].strip():
        lines.pop()
    if not lines:
        return "\n".join(action_lines) if action_lines else "ChatDome"
    title = _terminal_message_title(lines[0])
    bar = _terminal_block_bar()
    body = [f"{bar} {line}" if line else bar for line in lines]
    return "\n".join([title, *body, *action_lines])


def _print_chatdome_message(text: str) -> None:
    print(_format_chatdome_block(str(text or "")))


def _format_terminal_pending_approval(payload: dict[str, Any]) -> str:
    del payload
    return "\n".join(
        [
            _status_label("⚠️", "[!]", "Approval required"),
            _TERMINAL_APPROVAL_ACTION_WITH_DETAILS,
        ]
    )


def _format_terminal_round_limit(payload: dict[str, Any]) -> str:
    rounds = int((payload or {}).get("rounds") or 0)
    title = _status_label("⏸️", "[pause]", f"Task paused after {rounds} rounds.")
    return f"{title}\nContinue? [y/n]"


def _print_terminal_agent_result(result: Any) -> str:
    kind = str(getattr(result, "kind", "reply") or "reply")
    if kind == "pending_approval":
        _print_chatdome_message(_format_terminal_pending_approval(getattr(result, "payload", {}) or {}))
        return ChatSessionState.APPROVAL_REQUIRED.value
    if kind == "round_limit":
        _print_chatdome_message(_format_terminal_round_limit(getattr(result, "payload", {}) or {}))
        return ChatSessionState.CONTINUATION_REQUIRED.value
    _print_chatdome_message(str(getattr(result, "content", result) or ""))
    return ChatSessionState.IDLE.value


def _terminal_environment_summary(max_chars: int = 4000) -> str:
    path = ENV_PROFILE_PATH if ENV_PROFILE_PATH.exists() or not LEGACY_ENV_PROFILE_PATH.exists() else LEGACY_ENV_PROFILE_PATH
    if not path.exists():
        return _status_label("🧭", "[i]", "Environment profile not found.") + "\nRun: chatdome doctor"
    try:
        text = path.read_text(encoding="utf-8").strip()
    except OSError:
        return _status_label("❌", "[x]", "Environment profile unreadable.") + "\nRun: chatdome doctor"
    if not text:
        return _status_label("🧭", "[i]", "Environment profile is empty.") + "\nRun: chatdome doctor"
    if len(text) > max_chars:
        return text[:max_chars].rstrip() + "\n..."
    return text


def _terminal_audit_limit(parts: list[str]) -> int:
    if len(parts) < 2:
        return 10
    try:
        value = int(parts[1])
    except (TypeError, ValueError):
        return 10
    return min(max(value, 1), 30)


def _format_terminal_audit_events(chat_id: int, limit: int) -> str:
    raw_events = CommandAuditTracker.get_recent_events(
        chat_id=chat_id,
        limit=max(100, limit * 10),
        audit_source="user",
    )
    direct_command_events = {"security_check_executed", "security_check_invalid"}
    events = []
    for event in raw_events:
        event_type = str(event.get("event_type", ""))
        if not event_type.startswith("command_") and event_type not in direct_command_events:
            continue
        events.append(event)
        if len(events) >= limit:
            break

    if not events:
        return _status_label("🧾", "[audit]", "No user command audit events yet.")

    lines = [f"User command audit events (latest {len(events)}):"]
    for event in events:
        ts = str(event.get("timestamp_iso", "unknown"))
        event_type = str(event.get("event_type", "unknown"))
        risk = str(event.get("risk_level", "-"))
        command = str(event.get("command", "")).replace("\n", " ").strip()
        if len(command) > 100:
            command = command[:100] + "..."
        line = f"- {ts} | {event_type} | risk={risk}"
        if command:
            line += f"\n  {command}"
        lines.append(line)
    return "\n".join(lines)



def _get_terminal_model_manager(runtime: _TerminalChatRuntime) -> Any:
    return getattr(runtime.agent, "llm_manager", None)


def _terminal_model_status(status: str) -> str:
    labels = {
        "ready": "ready",
        "missing_key": "missing_key, configure api_key",
        "token_file_present": "token_file_present",
        "not_authenticated": "not_authenticated, run chatdome setup",
        "invalid_key_ref": "invalid_key_ref, update config.yaml",
        "unsupported": "unsupported",
    }
    return labels.get(status, status)


def _format_terminal_model_profiles(runtime: _TerminalChatRuntime) -> str:
    manager = _get_terminal_model_manager(runtime)
    if manager is None:
        return "model manager is not available.\nRun: chatdome setup"

    profiles = manager.list_profiles()
    if not profiles:
        return "No model is configured.\nRun: chatdome setup"

    active = next((item for item in profiles if item.active), None)
    active_name = active.name if active else manager.get_active_profile_name()
    lines = [
        "Model profiles",
        "",
        f"Active: {active_name}",
        "Switch: /model <profile_name>",
        "",
        "Commands:",
    ]
    for item in profiles:
        suffix = "  (current)" if item.active else ""
        lines.append(f"  /model {item.name}{suffix}")

    lines.extend(["", "Details:"])
    for item in profiles:
        marker = "[active]" if item.active else "[available]"
        lines.extend([
            "",
            f"{marker} {item.name}",
            f"  Status: {_terminal_model_status(item.status)}",
            f"  Type: {item.provider}/{item.api_mode}",
            f"  Model: {item.model}",
        ])
        if item.base_url:
            lines.append(f"  Base URL: {item.base_url}")
        if item.key_ref:
            lines.append(f"  Key: {item.key_ref}")
    return "\n".join(lines)


def _terminal_model_error_text(exc: BaseException) -> str:
    text = user_facing_error_message(exc, fallback="model switch failed. Run: /model_list")
    replacements = {
        "LLM profile": "model profile",
        "LLM is": "model is",
        "LLM": "model",
        "Run /codex_login before switching to it.": "Run: chatdome setup",
        "Run /codex_login": "Run: chatdome setup",
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    return text


async def _switch_terminal_model(runtime: _TerminalChatRuntime, profile_name: str | None) -> None:
    manager = _get_terminal_model_manager(runtime)
    if manager is None:
        _print_chatdome_message("model manager is not available.\nRun: chatdome setup")
        return
    if not profile_name:
        _print_chatdome_message(_format_terminal_model_profiles(runtime))
        return
    try:
        snapshot = await manager.switch_profile(profile_name)
    except Exception as exc:
        _print_chatdome_message(
            _status_label("❌", "[x]", "model switch failed.")
            + "\n"
            + _terminal_model_error_text(exc)
        )
        return

    profile = snapshot.profile
    _print_chatdome_message(
        _status_label("✅", "[ok]", f"model switched for this terminal session: {snapshot.profile_name}")
        + f"\n{profile.provider}/{profile.api_mode}, model={profile.model}"
    )

def _indent_terminal_block(text: Any, max_chars: int = 3000) -> str:
    value = str(text or "").strip()
    if len(value) > max_chars:
        value = value[: max_chars - 20].rstrip() + "\n... (truncated)"
    return "\n".join(f"  {line}" for line in value.splitlines()) if value else "  (empty)"


def _terminal_bool(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on"}
    return bool(value)


def _terminal_approval_flags(analysis: dict[str, Any]) -> str:
    flags = []
    if _terminal_bool(analysis.get("mutation_detected")):
        flags.append("modifies system")
    if _terminal_bool(analysis.get("deletion_detected")):
        flags.append("deletes files")
    return ", ".join(flags)


def _split_approval_impact_and_signals(impact: str, analysis: dict[str, Any]) -> tuple[str, list[str]]:
    text = str(impact or "").strip()
    signals = _approval_static_signals(analysis)
    marker = "[静态护栏信号]"
    if marker in text:
        before, after = text.split(marker, 1)
        text = before.strip()
        signals.extend(_parse_legacy_static_signal_lines(after))
    return (text or "review required"), _dedupe_text(signals)


def _approval_static_signals(analysis: dict[str, Any]) -> list[str]:
    raw = analysis.get("static_signals") if isinstance(analysis, dict) else None
    signals: list[str] = []
    if isinstance(raw, list):
        signals.extend(str(item).strip() for item in raw if str(item or "").strip())
    elif isinstance(raw, str) and raw.strip():
        signals.extend(_parse_legacy_static_signal_lines(raw))
    static_reason = str((analysis or {}).get("static_reason") or "").strip()
    if static_reason and not signals:
        signals.append(static_reason)
    return _dedupe_text(signals)


def _parse_legacy_static_signal_lines(text: str) -> list[str]:
    signals = []
    for line in str(text or "").splitlines():
        value = line.strip().lstrip("-• ").strip()
        if value:
            signals.append(value)
    return signals


def _dedupe_text(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if text and text not in seen:
            seen.add(text)
            result.append(text)
    return result


def _terminal_command_breakdown(command: str, analysis: dict[str, Any]) -> dict[str, Any]:
    breakdown = analysis.get("command_breakdown") if isinstance(analysis, dict) else None
    if isinstance(breakdown, dict) and breakdown.get("tokens"):
        return breakdown
    return parse_shell_command(command)


def _format_terminal_command_breakdown(breakdown: dict[str, Any]) -> str:
    entries = [item for item in breakdown.get("tokens", []) if isinstance(item, dict)]
    if not entries:
        return ""
    arrow = "->" if _terminal_ascii_mode() else "→"
    warning_prefix = "[!]" if _terminal_ascii_mode() else "⚠"
    token_width = min(max(len(str(item.get("token") or "")) for item in entries), 28)
    lines = ["命令解析:"]
    for item in entries:
        token = str(item.get("token") or "").strip()
        role = str(item.get("role") or "").strip()
        meaning = str(item.get("meaning") or role or "命令组成部分").strip()
        if role and role not in meaning:
            meaning = f"{role}（{meaning}）"
        padded = token if len(token) > token_width else token.ljust(token_width)
        lines.append(f"  {padded} {arrow} {meaning}")
    for warning in breakdown.get("warnings", []) or []:
        text = str(warning or "").strip()
        if text:
            lines.append(f"  {warning_prefix} {text}")
    return "\n".join(lines)


def _compact_terminal_impact(text: str, *, full: bool, max_chars: int = 220) -> str:
    value = " ".join(str(text or "").split()).strip() or "review required"
    if full or len(value) <= max_chars:
        return value
    suffix = " Run /details full for full analysis."
    return value[: max_chars - len(suffix) - 3].rstrip() + "..." + suffix


def _normalized_terminal_text(value: str) -> str:
    return " ".join(str(value or "").lower().split())


def _terminal_reason_adds_context(reason: str, impact: str) -> bool:
    normalized_reason = _normalized_terminal_text(reason)
    normalized_impact = _normalized_terminal_text(impact)
    if not normalized_reason or normalized_reason == "not provided":
        return False
    if not normalized_impact:
        return True
    return normalized_reason not in normalized_impact and normalized_impact not in normalized_reason


def _format_terminal_approval_details(details: dict[str, Any], *, full: bool = False) -> str:
    if not details.get("ok"):
        return _status_label("ℹ️", "[i]", str(details.get("message", "No pending approval.")))

    analysis = details.get("analysis") if isinstance(details.get("analysis"), dict) else {}
    command = str(details.get("command") or "").strip()
    reason = str(details.get("reason") or "not provided").strip()
    risk = str(analysis.get("risk_level") or details.get("risk_level") or "unknown").strip()
    safety = str(analysis.get("safety_status") or "unknown").strip()
    impact, static_signals = _split_approval_impact_and_signals(
        str(analysis.get("impact_analysis") or "review required"), analysis
    )
    breakdown = _terminal_command_breakdown(command, analysis)
    flags = _terminal_approval_flags(analysis)

    lines = [_status_label("🔎", "[details]", "Approval details")]
    lines.append(f"Risk: {risk}    Safety: {safety}")
    if flags:
        lines.append(f"Flags: {flags}")
    if full and _terminal_reason_adds_context(reason, impact):
        lines.append("")
        lines.append("Reason:")
        lines.append(_indent_terminal_block(reason, max_chars=1600))
    lines.append("")
    lines.append("Command:")
    lines.append("```bash")
    lines.append(command or "(empty)")
    lines.append("```")
    breakdown_text = _format_terminal_command_breakdown(breakdown)
    if breakdown_text:
        lines.append("")
        lines.append(breakdown_text)
    lines.append("")
    lines.append("Impact:")
    lines.append(_indent_terminal_block(_compact_terminal_impact(impact, full=full), max_chars=4000))
    if static_signals:
        lines.append("")
        lines.append("静态信号:")
        for signal in static_signals[:6]:
            if len(signal) > 260:
                signal = signal[:257].rstrip() + "..."
            lines.append(f"  • {signal}")
    lines.append("")
    lines.append(_TERMINAL_APPROVAL_ACTION)
    return "\n".join(lines)


def _read_terminal_line(prompt: str) -> str:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        return input(prompt)

    try:
        import termios
        import tty
    except ImportError:
        return input(prompt)

    fd = sys.stdin.fileno()
    old_attrs = termios.tcgetattr(fd)
    buffer: list[str] = []
    completion_matches: list[str] = []
    selected_index = 0
    last_completion_state: tuple[str, tuple[str, ...], int] | None = None

    def current_text() -> str:
        return "".join(buffer)

    def redraw_prompt() -> None:
        sys.stdout.write("\r\x1b[2K" + prompt + current_text())
        sys.stdout.flush()

    def refresh_completion(force: bool = False) -> None:
        nonlocal completion_matches, selected_index, last_completion_state
        matches = _terminal_command_matches(current_text())
        if matches != completion_matches:
            completion_matches = matches
            selected_index = 0
        if not completion_matches:
            last_completion_state = None
            return
        if selected_index >= len(completion_matches):
            selected_index = 0
        state = (current_text(), tuple(completion_matches[:8]), selected_index)
        if force or state != last_completion_state:
            _print_terminal_completion(prompt, current_text(), completion_matches, selected_index)
            last_completion_state = state

    def apply_completion(command: str) -> None:
        buffer[:] = list(_replace_terminal_command_token(current_text(), command))
        redraw_prompt()

    sys.stdout.write(prompt)
    sys.stdout.flush()
    try:
        tty.setraw(fd)
        while True:
            char = sys.stdin.read(1)
            if char in {"\r", "\n"}:
                if completion_matches:
                    token = _terminal_command_token(current_text()).lower()
                    known = {name.lower() for name in _terminal_command_names()}
                    if token not in known and len(completion_matches) == 1:
                        buffer[:] = list(
                            _replace_terminal_command_token(current_text(), completion_matches[0])
                        )
                sys.stdout.write("\n")
                sys.stdout.flush()
                return current_text()
            if char == "\x03":
                raise KeyboardInterrupt
            if char == "\x04":
                if not buffer:
                    raise EOFError
                continue
            if char in {"\x08", "\x7f"}:
                if buffer:
                    buffer.pop()
                    sys.stdout.write("\b \b")
                    sys.stdout.flush()
                    refresh_completion()
                continue
            if char == "\t":
                matches = completion_matches or _terminal_command_matches(current_text())
                if matches:
                    if selected_index >= len(matches):
                        selected_index = 0
                    completion_matches = matches
                    apply_completion(matches[selected_index])
                    refresh_completion(force=True)
                continue
            if char == "\x1b":
                leader = sys.stdin.read(1)
                if leader != "[":
                    continue
                code = sys.stdin.read(1)
                if code not in {"A", "B"}:
                    continue
                if not completion_matches:
                    completion_matches = _terminal_command_matches(current_text())
                    selected_index = 0
                if completion_matches:
                    delta = -1 if code == "A" else 1
                    selected_index = (selected_index + delta) % len(completion_matches)
                    apply_completion(completion_matches[selected_index])
                    _print_terminal_completion(prompt, current_text(), completion_matches, selected_index)
                continue
            if char >= " ":
                buffer.append(char)
                sys.stdout.write(char)
                sys.stdout.flush()
                refresh_completion()
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_attrs)


def _terminal_session(runtime: _TerminalChatRuntime) -> Any:
    manager = getattr(runtime.agent, "session_manager", None)
    getter = getattr(manager, "get_or_create", None)
    if not callable(getter):
        return None
    try:
        return getter(runtime.chat_id)
    except Exception:
        return None


def _terminal_details_options(args: tuple[str, ...]) -> tuple[str | None, bool]:
    full = False
    approval_id: str | None = None
    for arg in args:
        value = str(arg or "").strip()
        if not value:
            continue
        if value.lower() in {"full", "--full", "-f"}:
            full = True
            continue
        if approval_id is None:
            approval_id = value
    return approval_id, full


async def _show_terminal_details(runtime: _TerminalChatRuntime, approval_id: str | None, *, full: bool = False) -> bool:
    _print_chatdome_message(_status_label("🔎", "[details]", "Loading approval details..."))
    details = await runtime.agent.get_pending_approval_details(
        runtime.chat_id,
        approval_id=approval_id,
        include_llm=True,
    )
    _print_chatdome_message(_format_terminal_approval_details(details, full=full))
    return bool(details.get("ok"))


async def _resolve_terminal_confirm(runtime: _TerminalChatRuntime, approval_id: str | None) -> str:
    _, result = await runtime.agent.resume_session(runtime.chat_id, "APPROVE", approval_id=approval_id)
    return _print_terminal_agent_result(result)


async def _resolve_terminal_continue(runtime: _TerminalChatRuntime) -> str:
    result = await runtime.agent.resolve_round_limit(runtime.chat_id, "CONTINUE")
    return _print_terminal_agent_result(result)


async def _resolve_terminal_reject(runtime: _TerminalChatRuntime, approval_id: str | None) -> str:
    session = _terminal_session(runtime)
    if session is not None and getattr(session, "pending_round_limit", False) and not getattr(session, "pending_approval", False):
        result = await runtime.agent.resolve_round_limit(runtime.chat_id, "ABANDON")
        return _print_terminal_agent_result(result)
    _, result = await runtime.agent.resume_session(runtime.chat_id, "REJECT", approval_id=approval_id)
    return _print_terminal_agent_result(result)


async def _handle_terminal_approval_choice(provider: Any, text: str, *, details_shown: bool = False) -> CommandResult:
    value = str(text or "").strip().lower()
    if value in {"y", "yes"}:
        state = await _resolve_terminal_confirm(provider.get(), None)
        return CommandResult(state=state)
    if value in {"n", "no"}:
        state = await _resolve_terminal_reject(provider.get(), None)
        return CommandResult(state=state)
    if value in {"d", "detail", "details"}:
        shown = await _show_terminal_details(provider.get(), None)
        state = ChatSessionState.APPROVAL_DETAILS if shown else ChatSessionState.APPROVAL_REQUIRED
        return CommandResult(state=state.value)
    if value in {"f", "full", "detail full", "details full"}:
        shown = await _show_terminal_details(provider.get(), None, full=True)
        state = ChatSessionState.APPROVAL_DETAILS if shown else ChatSessionState.APPROVAL_REQUIRED
        return CommandResult(state=state.value)
    action = _TERMINAL_APPROVAL_ACTION if details_shown else _TERMINAL_APPROVAL_ACTION_WITH_DETAILS
    _print_chatdome_message(action)
    state = ChatSessionState.APPROVAL_DETAILS if details_shown else ChatSessionState.APPROVAL_REQUIRED
    return CommandResult(state=state.value)


async def _handle_terminal_continuation_choice(provider: Any, text: str) -> CommandResult:
    value = str(text or "").strip().lower()
    if value in {"y", "yes"}:
        state = await _resolve_terminal_continue(provider.get())
        return CommandResult(state=state)
    if value in {"n", "no"}:
        state = await _resolve_terminal_reject(provider.get(), None)
        return CommandResult(state=state)
    _print_chatdome_message("Continue? [y/n]")
    return CommandResult(state=ChatSessionState.CONTINUATION_REQUIRED.value)

async def _handle_terminal_command(runtime: _TerminalChatRuntime, line: str) -> bool:
    provider = _StaticTerminalRuntimeProvider(runtime)
    result = await _build_terminal_command_registry(provider).execute(line)
    if not result.handled:
        result = await _handle_unknown_terminal_command(line)
    return result.keep_running


async def _handle_unknown_terminal_command(_line: str) -> CommandResult:
    _print_chatdome_message(_status_label("ℹ️", "[i]", "Unknown command.") + "\nRun: /help")
    return CommandResult()


async def _send_terminal_user_message(provider: Any, text: str) -> CommandResult:
    provider.last_message = text
    _print_chatdome_message(_status_label("⏳", "[...]", "Working..."))
    try:
        runtime = provider.get()
        logging.getLogger("chatdome.terminal.chat").info(
            "Message from chat_id=%d via terminal: %s",
            runtime.chat_id,
            _terminal_log_excerpt(text),
        )
        result = await runtime.agent.handle_message(runtime.chat_id, text)
    except Exception as exc:
        provider.last_failed_message = text
        log_path, logged = _append_cli_exception_log("Terminal chat request", exc)
        message = user_facing_error_message(exc, fallback="Request failed.")
        lines = [message, "Run: /retry"]
        if logged:
            lines.append(f"Log: {_tail_log_command(log_path)}")
        _print_chatdome_message("\n".join(lines))
        return CommandResult(state=ChatSessionState.ERROR.value)
    provider.last_failed_message = None
    state = _print_terminal_agent_result(result)
    return CommandResult(state=state)


def _terminal_history_path() -> Path:
    return DATA_DIR / "terminal_history"


def _create_terminal_chat_view(registry: CommandRegistry, status_provider) -> Any:
    if sys.stdin.isatty() and sys.stdout.isatty():
        try:
            from chatdome.terminal.prompt_toolkit_view import PromptToolkitChatView

            return PromptToolkitChatView(
                registry,
                history_path=_terminal_history_path(),
                write_message=_print_chatdome_message,
                status_provider=status_provider,
            )
        except ImportError:
            pass
        except OSError:
            pass
    return PlainTerminalChatView(
        read_line=_read_terminal_line,
        write_message=_print_chatdome_message,
    )


def _terminal_model_name() -> str:
    root, status = _config_root_for_report()
    active = str(root.get("active_ai_profile") or "").strip() if status == "ready" else ""
    return active or "not configured"


def _terminal_start_status() -> str:
    return f"model: {_terminal_model_name()}\nsession: local"


def _terminal_start_line() -> str:
    return f"ChatDome terminal · model: {_terminal_model_name()}"


def _terminal_compact_start(args: argparse.Namespace) -> bool:
    env_value = os.environ.get("CHATDOME_COMPACT", "").strip().lower()
    return bool(getattr(args, "quiet", False)) or env_value in {"1", "true", "yes", "on"}


def _print_terminal_start(args: argparse.Namespace) -> None:
    if _terminal_compact_start(args):
        print(_terminal_start_line())
        return
    print(CHATDOME_LOGO)
    print("")
    print(_terminal_start_status())
    print("")



def _terminal_prompt() -> str:
    return os.environ.get("CHATDOME_PROMPT", _terminal_default_prompt())


def _terminal_log_excerpt(text: str, max_len: int = 200) -> str:
    value = " ".join(str(text or "").replace("\r", " ").replace("\n", " ").replace("\t", " ").split())
    if len(value) > max_len:
        value = value[: max_len - 3] + "..."
    return value


def _terminal_prompt_for_state(state: ChatSessionState | str) -> str:
    value = ChatSessionState(state)
    if value == ChatSessionState.APPROVAL_REQUIRED:
        return "approve [y/n/d]> "
    if value == ChatSessionState.APPROVAL_DETAILS:
        return "approve [y/n]> "
    if value == ChatSessionState.CONTINUATION_REQUIRED:
        return "continue [y/n]> "
    return _terminal_prompt()


async def _terminal_chat_loop(args: argparse.Namespace) -> None:
    provider = _TerminalRuntimeProvider(args)
    controller_ref: dict[str, ChatSessionController] = {}

    async def stop_request() -> bool:
        controller = controller_ref.get("controller")
        if controller is None:
            return False
        return await controller.cancel_active_message()

    registry = _build_terminal_command_registry(provider, stop_request_handler=stop_request)

    async def approval_handler(text: str) -> CommandResult:
        return await _handle_terminal_approval_choice(
            provider,
            text,
            details_shown=controller.state == ChatSessionState.APPROVAL_DETAILS,
        )

    async def busy_handler(_text: str) -> CommandResult:
        _print_chatdome_message("Task is running.\nRun: /stop")
        return CommandResult(state=ChatSessionState.WORKING.value)

    controller = ChatSessionController(
        registry,
        message_handler=lambda text: _send_terminal_user_message(provider, text),
        unknown_handler=_handle_unknown_terminal_command,
        stop_handler=provider.stop,
        approval_handler=approval_handler,
        continuation_handler=lambda text: _handle_terminal_continuation_choice(provider, text),
        busy_handler=busy_handler,
    )
    controller_ref["controller"] = controller
    view = _create_terminal_chat_view(registry, lambda: controller.status_text)
    controller.set_background_messages(bool(getattr(view, "supports_background_input", False)))
    app = TerminalChatApp(view, controller, prompt=lambda: _terminal_prompt_for_state(controller.state))
    await app.run()


def hello(args: argparse.Namespace) -> None:
    _setup_cli_file_logging()
    _print_terminal_start(args)
    try:
        asyncio.run(_terminal_chat_loop(args))
    except KeyboardInterrupt:
        print()
    except ChatDomeError as exc:
        _exit_with_logged_error("Terminal chat", exc, fallback="Terminal chat failed. Run chatdome doctor.")
    except Exception as exc:
        _exit_with_logged_error("Terminal chat", exc, fallback="Terminal chat failed. Run chatdome doctor.")


def _doctor_line(level: str, name: str, message: str) -> bool:
    print(f"[{level}] {name}: {message}")
    return level == "fail"


def doctor(args: argparse.Namespace) -> None:
    del args
    failures = 0
    root, config_status = _config_root_for_report()

    print("ChatDome doctor")
    if config_status == "ready":
        failures += _doctor_line("ok", "config", str(CONFIG_PATH))
    else:
        message = f"create config: {CONFIG_PATH}" if config_status == "missing" else config_status
        failures += _doctor_line("fail", "config", message)

    if CONFIG_PATH.exists() and os.name == "posix":
        mode = stat.S_IMODE(CONFIG_PATH.stat().st_mode)
        if mode & 0o077:
            failures += _doctor_line("warn", "config-permission", f"chmod 600 {CONFIG_PATH}")
        else:
            failures += _doctor_line("ok", "config-permission", "0600")

    llm_status, llm_detail = _profile_status(root)
    llm_message = f"ready ({llm_detail})" if llm_status == "ready" else f"configure active model profile ({llm_detail})"
    failures += _doctor_line("ok" if llm_status == "ready" else "fail", "model", llm_message)

    telegram = root.get("telegram") if isinstance(root.get("telegram"), dict) else {}
    token_ready = bool(str(telegram.get("bot_token") or "").strip())
    failures += _doctor_line("ok" if token_ready else "fail", "telegram", "ready" if token_ready else "set chatdome.telegram.bot_token")

    sentinel = root.get("sentinel") if isinstance(root.get("sentinel"), dict) else {}
    allowed_chat_ids = telegram.get("allowed_chat_ids") if isinstance(telegram.get("allowed_chat_ids"), list) else []
    alert_chat_ids = sentinel.get("alert_chat_ids") if isinstance(sentinel.get("alert_chat_ids"), list) else []
    if allowed_chat_ids or alert_chat_ids:
        failures += _doctor_line("ok", "chat-ids", "configured")
    else:
        failures += _doctor_line("warn", "chat-ids", "set allowed_chat_ids or sentinel.alert_chat_ids")

    pid = _read_pid()
    running = _process_running(pid)
    failures += _doctor_line("ok" if running else "warn", "service", f"pid={pid}" if running else "start ChatDome from menu")

    sentinel_enabled = bool(sentinel.get("enabled", False))
    checks = sentinel.get("checks") if isinstance(sentinel.get("checks"), list) else []
    if sentinel_enabled and not checks:
        failures += _doctor_line("warn", "sentinel", "set sentinel checks or disable sentinel")
    else:
        failures += _doctor_line("ok", "sentinel", "enabled" if sentinel_enabled else "disabled")

    for label, path in (("logs", Path(os.environ.get("CHATDOME_LOG_DIR", str(DATA_DIR)))), ("run", RUN_DIR)):
        if path.exists() and os.access(path, os.W_OK):
            failures += _doctor_line("ok", label, str(path))
        else:
            failures += _doctor_line("warn", label, f"create writable directory: {path}")

    if failures:
        raise SystemExit(1)

def show_env_summary(args: argparse.Namespace) -> None:
    del args
    path = ENV_PROFILE_PATH if ENV_PROFILE_PATH.exists() or not LEGACY_ENV_PROFILE_PATH.exists() else LEGACY_ENV_PROFILE_PATH
    if not path.exists():
        print(f"environment profile not found: {path}")
        return
    text = path.read_text(encoding="utf-8").strip()
    print(text[:4000] if text else "(empty environment profile)")


def _profile_items(root: dict[str, Any]) -> dict[str, Any]:
    profiles = root.setdefault("ai_profiles", {})
    if not isinstance(profiles, dict):
        profiles = {}
        root["ai_profiles"] = profiles
    return profiles


def _record_profile_audit(event_type: str, actor: ProfileActor, fields: dict[str, Any]) -> None:
    PROFILE_AUDIT_RECORDER(
        event_type,
        chat_id=actor.chat_id,
        source=actor.source,
        user_id=actor.user_id,
        **fields,
    )


def _profile_admin_service(source: str) -> LLMProfileAdminService:
    async def apply_runtime(_config, action: str) -> None:
        _request_reload(["llm"], f"{source}:{action}")

    return LLMProfileAdminService(
        ProfileConfigStore(CONFIG_PATH, LLM_PROFILE_LOCK_PATH),
        runtime_apply=apply_runtime,
        audit_recorder=_record_profile_audit,
    )


def _run_profile_admin(awaitable):
    try:
        return asyncio.run(awaitable)
    except Exception as exc:
        raise SystemExit(str(exc)) from None


def llm_list(args: argparse.Namespace) -> None:
    del args
    data = _load_yaml()
    root = _chatdome_root(data)
    active = str(root.get("active_ai_profile") or "")
    print("Model profiles")
    print(f"- active: {active or '(unset)'}")
    for name, profile in sorted(_profile_items(root).items()):
        if not isinstance(profile, dict):
            continue
        api_mode = profile.get("api_mode", "openai_api")
        key = str(profile.get("api_key") or "")
        if api_mode == "openai_api":
            auth = "ready" if key else "missing api_key"
        else:
            token_file = str(profile.get("codex_token_file") or "~/.chatdome/auth.json")
            token_status = "ready" if _codex_token_file_path(token_file).is_file() else "missing"
            auth = f"oauth {token_status} token_file={token_file}"
        marker = " (active)" if name == active else ""
        print(f"- {name}{marker}: {profile.get('provider')}/{api_mode} model={profile.get('model')} auth={auth}")


def llm_profile_state(args: argparse.Namespace) -> None:
    summary = _run_profile_admin(
        _profile_admin_service("menu:profile-state").get_profile_summary(args.profile)
    )
    print("exists" if summary is not None else "missing")


def llm_profile_info(args: argparse.Namespace) -> None:
    summary = _run_profile_admin(
        _profile_admin_service("menu:profile-info").get_profile_summary(args.profile)
    )
    if summary is None:
        raise SystemExit(f"unknown profile: {args.profile}")
    values = {
        "provider": summary.provider,
        "api-mode": summary.api_mode,
        "model": summary.model,
        "base-url": summary.base_url,
        "fingerprint": summary.fingerprint,
        "active": "true" if summary.active else "false",
        "has-api-key": "true" if summary.has_api_key else "false",
    }
    print(values[args.field])


def set_openai(args: argparse.Namespace) -> None:
    api_key = str(getattr(args, "api_key", "") or "")
    if getattr(args, "api_key_stdin", False):
        api_key = sys.stdin.readline().rstrip("\r\n")
    request = CreateOpenAIProfileRequest(
        name=args.profile,
        model=args.model,
        base_url=args.base_url,
        api_key=api_key,
        temperature=args.temperature,
        max_tokens=args.max_tokens,
        overwrite_existing=bool(getattr(args, "overwrite", False)),
        expected_profile_fingerprint=getattr(args, "expected_profile_fingerprint", None),
    )
    result = _run_profile_admin(
        _profile_admin_service("menu:set-openai").create_openai(
            request,
            ProfileActor(source="menu"),
        )
    )
    print(f"{result.action} OpenAI-compatible profile: {result.profile_name}")


def _codex_request(args: argparse.Namespace, token_file: str) -> CreateCodexProfileRequest:
    return CreateCodexProfileRequest(
        name=args.profile,
        model=args.model,
        client_id=args.client_id,
        token_file=token_file,
        base_url=args.base_url,
        temperature=args.temperature,
        max_tokens=args.max_tokens,
        overwrite_existing=bool(getattr(args, "overwrite", False)),
        expected_profile_fingerprint=getattr(args, "expected_profile_fingerprint", None),
    )


def set_codex(args: argparse.Namespace) -> None:
    args.profile = _validate_profile_name(args.profile)
    data = _load_yaml()
    profiles = _profile_items(_chatdome_root(data))
    token_file = _resolve_codex_token_file(args.profile, args.token_file, profiles.get(args.profile))
    result = _run_profile_admin(
        _profile_admin_service("menu:set-codex").create_codex(
            _codex_request(args, token_file),
            ProfileActor(source="menu"),
        )
    )
    print(f"{result.action} Codex profile: {result.profile_name}")


async def _codex_login_async(args: argparse.Namespace) -> None:
    args.profile = _validate_profile_name(args.profile)
    data = _load_yaml()
    profiles = _profile_items(_chatdome_root(data))
    token_file = _resolve_codex_login_token_file(args.profile, args.token_file, profiles.get(args.profile))

    from chatdome.llm.codex_auth import CodexOAuth

    oauth = CodexOAuth(
        client_id=args.client_id or None,
        token_file=token_file or None,
    )
    device_info = await oauth.request_device_code()
    verification_uri = device_info.get("verification_uri", "https://auth.openai.com/codex/device")
    user_code = device_info["user_code"]
    interval = int(device_info.get("interval", 5))
    expires_in = int(device_info.get("expires_in", 300))

    print("Codex OAuth")
    print(f"- open: {verification_uri}")
    print(f"- code: {user_code}")
    print("- waiting for authorization...")

    code, code_verifier = await oauth.poll_device_token(
        device_code=device_info["device_code"],
        user_code=user_code,
        interval=interval,
        timeout=expires_in,
    )
    await oauth.exchange_token(code, code_verifier)
    try:
        result = await _profile_admin_service("menu:codex-login").create_codex(
            _codex_request(args, token_file),
            ProfileActor(source="menu"),
        )
    except Exception as exc:
        raise SystemExit(str(exc)) from None
    print(f"{result.action} Codex profile: {result.profile_name}")


def codex_login(args: argparse.Namespace) -> None:
    try:
        asyncio.run(_codex_login_async(args))
    except KeyboardInterrupt as exc:
        raise SystemExit("cancelled") from exc
    except ChatDomeError as exc:
        _exit_with_logged_error("Codex OAuth", exc, fallback="Codex 认证失败，请查看日志。")
    except Exception as exc:
        _exit_with_logged_error("Codex OAuth", exc, fallback="Codex 认证失败，请查看日志。")

def set_active_profile(args: argparse.Namespace) -> None:
    result = _run_profile_admin(
        _profile_admin_service("menu:set-active-profile").set_active_profile(
            args.profile,
            ProfileActor(source="menu"),
        )
    )
    print(f"active profile set to: {result.profile_name}")


def delete_profile(args: argparse.Namespace) -> None:
    result = _run_profile_admin(
        _profile_admin_service("menu:delete-profile").delete_profile(
            args.profile,
            ProfileActor(source="menu"),
        )
    )
    print(f"deleted model profile: {result.profile_name}")


def telegram_status(args: argparse.Namespace) -> None:
    del args
    data = _load_yaml()
    telegram = _section(_chatdome_root(data), "telegram")
    print("Telegram")
    print(f"- bot token: {_mask_secret(telegram.get('bot_token', ''))}")
    print(f"- allowed chat ids: {telegram.get('allowed_chat_ids') or '(all)'}")
    print(f"- model admin chat ids: {_llm_admin_chat_ids_display(telegram)}")
    print(f"- proxy_url: {telegram.get('proxy_url') or '(none)'}")


def set_bot_token(args: argparse.Namespace) -> None:
    data = _load_yaml()
    telegram = _section(_chatdome_root(data), "telegram")
    telegram["bot_token"] = args.token
    _write_yaml(data)
    print("Telegram bot token updated. Restart ChatDome for this change to take effect.")


def set_chat_ids(args: argparse.Namespace) -> None:
    data = _load_yaml()
    telegram = _section(_chatdome_root(data), "telegram")
    telegram["allowed_chat_ids"] = _parse_chat_ids(args.chat_ids)
    _write_yaml(data)
    print("allowed_chat_ids updated. Restart ChatDome for this change to take effect.")


def set_admin_chat_ids(args: argparse.Namespace) -> None:
    data = _load_yaml()
    telegram = _section(_chatdome_root(data), "telegram")
    telegram["admin_chat_ids"] = _parse_chat_ids(args.chat_ids)
    _write_yaml(data)
    print("admin_chat_ids updated. Restart ChatDome for this change to take effect.")


def set_telegram_proxy(args: argparse.Namespace) -> None:
    data = _load_yaml()
    telegram = _section(_chatdome_root(data), "telegram")
    telegram["proxy_url"] = args.proxy_url
    _write_yaml(data)
    print("Telegram proxy_url updated. Restart ChatDome for this change to take effect.")


def _telegram_api_request(method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    data = _load_yaml()
    telegram = _section(_chatdome_root(data), "telegram")
    token = str(telegram.get("bot_token") or "").strip()
    if not token:
        raise SystemExit("telegram.bot_token is empty")
    url = f"https://api.telegram.org/bot{token}/{method}"
    body = None
    if params:
        body = urllib.parse.urlencode(params).encode("utf-8")
    proxy_url = str(telegram.get("proxy_url") or "").strip()
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
    ) if proxy_url else urllib.request.build_opener()
    with opener.open(url, data=body, timeout=15) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if not payload.get("ok"):
        raise SystemExit(f"Telegram API failed: {payload}")
    return payload


def check_telegram(args: argparse.Namespace) -> None:
    del args
    payload = _telegram_api_request("getMe")
    user = payload.get("result") or {}
    print(f"Telegram API OK: @{user.get('username', '(unknown)')} id={user.get('id')}")


def send_test_message(args: argparse.Namespace) -> None:
    data = _load_yaml()
    telegram = _section(_chatdome_root(data), "telegram")
    chat_ids = telegram.get("allowed_chat_ids") or []
    if not chat_ids:
        raise SystemExit("allowed_chat_ids is empty; no target for test message")
    for chat_id in chat_ids:
        _telegram_api_request("sendMessage", {"chat_id": int(chat_id), "text": args.text})
        print(f"sent test message to {chat_id}")


def sentinel_status(args: argparse.Namespace) -> None:
    del args
    data = _load_yaml()
    sentinel = _section(_chatdome_root(data), "sentinel")
    checks = sentinel.get("checks") or []
    print("Sentinel")
    print(f"- enabled: {sentinel.get('enabled', False)}")
    print(f"- checks: {len(checks)}")
    print(f"- push_min_severity: {sentinel.get('push_min_severity')}")
    print(f"- global_rate_limit: {sentinel.get('global_rate_limit')}")
    print(f"- global_rate_window: {sentinel.get('global_rate_window')}")


def set_sentinel_enabled(args: argparse.Namespace) -> None:
    data = _load_yaml()
    sentinel = _section(_chatdome_root(data), "sentinel")
    sentinel["enabled"] = _truthy(args.enabled)
    _write_yaml(data)
    _request_reload(["sentinel"], "menu:set-sentinel-enabled")
    print(f"Sentinel enabled={sentinel['enabled']}")


def list_sentinel_checks(args: argparse.Namespace) -> None:
    del args
    data = _load_yaml()
    checks = _section(_chatdome_root(data), "sentinel").get("checks") or []
    for index, check in enumerate(checks, start=1):
        rule = check.get("rule") or {}
        print(
            f"{index}. {check.get('name')} "
            f"check_id={check.get('check_id')} interval={check.get('interval')} "
            f"severity={check.get('severity')} rule={rule.get('type')} {rule.get('operator')} {rule.get('threshold')}"
        )


def set_sentinel_policy(args: argparse.Namespace) -> None:
    data = _load_yaml()
    sentinel = _section(_chatdome_root(data), "sentinel")
    if args.push_min_severity is not None:
        sentinel["push_min_severity"] = args.push_min_severity
    if args.global_rate_limit is not None:
        sentinel["global_rate_limit"] = args.global_rate_limit
    _write_yaml(data)
    _request_reload(["sentinel"], "menu:set-sentinel-policy")
    print("Sentinel policy updated")


def agent_status(args: argparse.Namespace) -> None:
    del args
    data = _load_yaml()
    agent = _section(_chatdome_root(data), "agent")
    print("Agent security policy")
    for key in (
        "allow_generated_commands",
        "allow_unrestricted_commands",
        "session_timeout",
        "pending_approval_timeout",
        "max_rounds_per_turn",
        "command_timeout",
        "max_output_chars",
    ):
        print(f"- {key}: {agent.get(key)}")


def set_agent_mode(args: argparse.Namespace) -> None:
    data = _load_yaml()
    agent = _section(_chatdome_root(data), "agent")
    if args.mode == "restricted":
        agent["allow_generated_commands"] = False
        agent["allow_unrestricted_commands"] = False
    elif args.mode == "generated":
        agent["allow_generated_commands"] = True
        agent["allow_unrestricted_commands"] = False
    elif args.mode == "unrestricted":
        agent["allow_generated_commands"] = True
        agent["allow_unrestricted_commands"] = True
    else:
        raise SystemExit(f"unknown mode: {args.mode}")
    _write_yaml(data)
    _request_reload(["agent"], "menu:set-agent-mode")
    print(f"agent mode set to: {args.mode}")


def set_agent_params(args: argparse.Namespace) -> None:
    data = _load_yaml()
    agent = _section(_chatdome_root(data), "agent")
    for key in ("session_timeout", "max_rounds_per_turn", "command_timeout"):
        value = getattr(args, key)
        if value is not None:
            agent[key] = int(value)
    _write_yaml(data)
    _request_reload(["agent"], "menu:set-agent-params")
    print("agent parameters updated")


def _request_reload(domains: list[str], source: str) -> None:
    domains = _normalize_reload_domains(domains)
    RELOAD_REQUEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": 1,
        "request_id": f"reload-{int(time.time())}-{os.getpid()}",
        "domains": domains,
        "requested_at": time.time(),
        "source": source,
        "config_path": str(CONFIG_PATH),
    }
    tmp = RELOAD_REQUEST_PATH.with_name(f"{RELOAD_REQUEST_PATH.name}.tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(RELOAD_REQUEST_PATH)


def _normalize_reload_domains(domains: list[str]) -> list[str]:
    normalized: list[str] = []
    for raw_domain in domains:
        domain = str(raw_domain or "").strip().lower()
        if not domain:
            continue
        if domain not in SUPPORTED_RELOAD_DOMAINS:
            raise SystemExit(
                f"unsupported reload domain: {domain}. "
                f"supported: {', '.join(sorted(SUPPORTED_RELOAD_DOMAINS))}"
            )
        if domain == "all":
            return ["all"]
        if domain not in normalized:
            normalized.append(domain)
    if not normalized:
        raise SystemExit("at least one reload domain is required")
    return normalized


def request_reload_cmd(args: argparse.Namespace) -> None:
    domains = [part.strip() for part in args.domains.split(",") if part.strip()]
    normalized = _normalize_reload_domains(domains)
    _request_reload(normalized, args.source)
    print(f"reload requested: {', '.join(normalized)}")


def reload_status(args: argparse.Namespace) -> None:
    del args
    if not RELOAD_STATUS_PATH.exists():
        print("no reload status yet")
        return
    print(RELOAD_STATUS_PATH.read_text(encoding="utf-8").strip())


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="ChatDome local management helper")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("ensure-config").set_defaults(func=ensure_config)
    sub.add_parser("validate-config").set_defaults(func=validate_config)
    sub.add_parser("health-check").set_defaults(func=health_check)
    p = sub.add_parser("hello")
    p.add_argument("--chat-id", type=int, default=None, help=argparse.SUPPRESS)
    p.add_argument("--quiet", action="store_true", help="Use compact terminal startup output")
    p.set_defaults(func=hello)
    sub.add_parser("status").set_defaults(func=show_status)
    sub.add_parser("doctor").set_defaults(func=doctor)
    sub.add_parser("env-summary").set_defaults(func=show_env_summary)
    sub.add_parser("llm-list").set_defaults(func=llm_list)
    p = sub.add_parser("llm-profile-state")
    p.add_argument("profile")
    p.set_defaults(func=llm_profile_state)
    p = sub.add_parser("llm-profile-info")
    p.add_argument("profile")
    p.add_argument(
        "--field",
        required=True,
        choices=["provider", "api-mode", "model", "base-url", "fingerprint", "active", "has-api-key"],
    )
    p.set_defaults(func=llm_profile_info)

    p = sub.add_parser("set-openai")
    p.add_argument("--profile", default="my-openai-profile")
    p.add_argument("--model", required=True)
    p.add_argument("--base-url", default="https://api.openai.com/v1")
    p.add_argument("--api-key", default="")
    p.add_argument("--api-key-stdin", action="store_true")
    p.add_argument("--temperature", type=float, default=0.1)
    p.add_argument("--max-tokens", type=int, default=2000)
    p.add_argument("--overwrite", action="store_true")
    p.add_argument("--expected-profile-fingerprint")
    p.set_defaults(func=set_openai)

    p = sub.add_parser("set-codex")
    p.add_argument("--profile", default="codex")
    p.add_argument("--model", default="gpt-5.5")
    p.add_argument("--client-id", default="")
    p.add_argument("--token-file", default=None)
    p.add_argument("--base-url", default="https://chatgpt.com/backend-api/codex")
    p.add_argument("--temperature", type=float, default=0.1)
    p.add_argument("--max-tokens", type=int, default=2000)
    p.add_argument("--overwrite", action="store_true")
    p.add_argument("--expected-profile-fingerprint")
    p.set_defaults(func=set_codex)

    p = sub.add_parser("codex-login")
    p.add_argument("--profile", default="codex")
    p.add_argument("--model", default="gpt-5.5")
    p.add_argument("--client-id", default="")
    p.add_argument("--token-file", default=None)
    p.add_argument("--base-url", default="https://chatgpt.com/backend-api/codex")
    p.add_argument("--temperature", type=float, default=0.1)
    p.add_argument("--max-tokens", type=int, default=2000)
    p.add_argument("--overwrite", action="store_true")
    p.add_argument("--expected-profile-fingerprint")
    p.set_defaults(func=codex_login)

    p = sub.add_parser("set-active-profile")
    p.add_argument("profile")
    p.set_defaults(func=set_active_profile)
    p = sub.add_parser("delete-profile")
    p.add_argument("profile")
    p.set_defaults(func=delete_profile)

    sub.add_parser("telegram-status").set_defaults(func=telegram_status)
    p = sub.add_parser("set-bot-token")
    p.add_argument("token")
    p.set_defaults(func=set_bot_token)
    p = sub.add_parser("set-chat-ids")
    p.add_argument("chat_ids")
    p.set_defaults(func=set_chat_ids)
    p = sub.add_parser("set-admin-chat-ids")
    p.add_argument("chat_ids")
    p.set_defaults(func=set_admin_chat_ids)
    p = sub.add_parser("set-telegram-proxy")
    p.add_argument("proxy_url")
    p.set_defaults(func=set_telegram_proxy)
    sub.add_parser("check-telegram").set_defaults(func=check_telegram)
    p = sub.add_parser("send-test-message")
    p.add_argument("--text", default="ChatDome test message")
    p.set_defaults(func=send_test_message)

    sub.add_parser("sentinel-status").set_defaults(func=sentinel_status)
    p = sub.add_parser("set-sentinel-enabled")
    p.add_argument("enabled")
    p.set_defaults(func=set_sentinel_enabled)
    sub.add_parser("list-sentinel-checks").set_defaults(func=list_sentinel_checks)
    p = sub.add_parser("set-sentinel-policy")
    p.add_argument("--push-min-severity", type=int)
    p.add_argument("--global-rate-limit", type=int)
    p.set_defaults(func=set_sentinel_policy)

    sub.add_parser("agent-status").set_defaults(func=agent_status)
    p = sub.add_parser("set-agent-mode")
    p.add_argument("mode", choices=["restricted", "generated", "unrestricted"])
    p.set_defaults(func=set_agent_mode)
    p = sub.add_parser("set-agent-params")
    p.add_argument("--session-timeout", type=int)
    p.add_argument("--max-rounds-per-turn", type=int)
    p.add_argument("--command-timeout", type=int)
    p.set_defaults(func=set_agent_params)

    p = sub.add_parser("reload")
    p.add_argument("domains")
    p.add_argument("--source", default="manual")
    p.set_defaults(func=request_reload_cmd)
    sub.add_parser("reload-status").set_defaults(func=reload_status)
    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
