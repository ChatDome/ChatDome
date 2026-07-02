#!/usr/bin/env python3
"""Local management helper for the ChatDome interactive menu."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import stat
import sys
import time
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
from chatdome.llm.profile_admin import (
    CreateCodexProfileRequest,
    CreateOpenAIProfileRequest,
    LLMProfileAdminService,
    ProfileActor,
    ProfileConfigStore,
)

PROFILE_AUDIT_RECORDER = CommandAuditTracker.record_event
CHATDOME_LOGO = r"""    ____  _   _   ___   _____  ____    ___   __  __  _____
   / ___|| | | | / _ \ |_   _||  _ \  / _ \ |  \/  || ____|
  / /    | |_| |/ /_\ \  | |  | | | |/ / \ \| |\/| ||  _|
 / /___  |  _  ||  _  |  | |  | |_| |\ \_/ /| |  | || |___
 \_____| |_| |_||_| |_|  |_|  |____/  \___/ |_|  |_||_____|"""

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
    print(f"- LLM: {llm_status} ({llm_detail})")
    print(f"- Telegram: {_telegram_status(root)}")
    print(f"- Sentinel: {_sentinel_status(root)}")
    print(f"- Logs: {os.environ.get('CHATDOME_LOG_DIR', str(DATA_DIR))}")


def hello(args: argparse.Namespace) -> None:
    del args
    print(CHATDOME_LOGO)


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
    llm_message = f"ready ({llm_detail})" if llm_status == "ready" else f"configure active LLM profile ({llm_detail})"
    failures += _doctor_line("ok" if llm_status == "ready" else "fail", "llm", llm_message)

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
    print("LLM profiles")
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
    print(f"deleted LLM profile: {result.profile_name}")


def telegram_status(args: argparse.Namespace) -> None:
    del args
    data = _load_yaml()
    telegram = _section(_chatdome_root(data), "telegram")
    print("Telegram")
    print(f"- bot token: {_mask_secret(telegram.get('bot_token', ''))}")
    print(f"- allowed chat ids: {telegram.get('allowed_chat_ids') or '(all)'}")
    print(f"- LLM admin chat ids: {_llm_admin_chat_ids_display(telegram)}")
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
    sub.add_parser("hello").set_defaults(func=hello)
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
