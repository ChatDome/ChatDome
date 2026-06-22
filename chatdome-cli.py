#!/usr/bin/env python3
"""Local management helper for the ChatDome interactive menu."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
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
PID_PATH = DATA_DIR / "chatdome.pid"
READY_PATH = DATA_DIR / "ready.json"
RELOAD_REQUEST_PATH = DATA_DIR / "reload_request.json"
RELOAD_STATUS_PATH = DATA_DIR / "reload_status.json"
SUPPORTED_RELOAD_DOMAINS = {"llm", "sentinel", "agent", "all"}
CONTROLPLANE_SRC = ROOT / "controlplane" / "src"
PROFILE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
TOKEN_NAME_PATTERN = re.compile(r"[^A-Za-z0-9_.-]+")

if CONTROLPLANE_SRC.is_dir():
    sys.path.insert(0, str(CONTROLPLANE_SRC))


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


def _validate_profile_name(profile: str) -> str:
    value = str(profile or "").strip()
    if not PROFILE_NAME_PATTERN.match(value):
        raise SystemExit("invalid profile name")
    return value


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


def _write_codex_profile(
    data: dict[str, Any],
    root: dict[str, Any],
    profiles: dict[str, Any],
    args: argparse.Namespace,
    token_file: str,
    *,
    reload_source: str,
) -> None:
    profile = profiles.setdefault(args.profile, {})
    profile.update(
        {
            "provider": "codex",
            "api_mode": "codex_responses",
            "model": args.model,
            "temperature": args.temperature,
            "max_tokens": args.max_tokens,
            "codex_client_id": args.client_id,
            "codex_token_file": token_file,
            "codex_base_url": args.base_url,
        }
    )
    if not str(root.get("active_ai_profile") or "").strip():
        root["active_ai_profile"] = args.profile
    _write_yaml(data)
    _request_reload(["llm"], reload_source)


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

    load_config(CONFIG_PATH)
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


def show_status(args: argparse.Namespace) -> None:
    del args
    data = _load_yaml()
    root = _chatdome_root(data)
    telegram = _section(root, "telegram")
    sentinel = _section(root, "sentinel")
    agent = _section(root, "agent")
    active_profile = str(root.get("active_ai_profile") or "(unset)")
    pid = _read_pid()
    running = _process_running(pid)

    print("ChatDome status")
    print(f"- root: {ROOT}")
    print(f"- config: {CONFIG_PATH}")
    print(f"- data: {DATA_DIR}")
    print(f"- running: {'yes' if running else 'no'}")
    print(f"- pid: {pid or '(none)'}")
    print(f"- active LLM: {active_profile}")
    print(f"- Sentinel: {'enabled' if sentinel.get('enabled') else 'disabled'}")
    print(f"- generated commands: {agent.get('allow_generated_commands', True)}")
    print(f"- unrestricted commands: {agent.get('allow_unrestricted_commands', True)}")
    print(f"- Telegram token: {_mask_secret(telegram.get('bot_token', ''))}")
    print(f"- allowed chats: {telegram.get('allowed_chat_ids') or '(all)'}")


def show_env_summary(args: argparse.Namespace) -> None:
    del args
    path = DATA_DIR / "environment_profile.md"
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


def set_openai(args: argparse.Namespace) -> None:
    args.profile = _validate_profile_name(args.profile)
    if not str(args.api_key or "").strip():
        raise SystemExit("api_key is required")
    data = _load_yaml()
    root = _chatdome_root(data)
    profiles = _profile_items(root)
    profile = profiles.setdefault(args.profile, {})
    profile.update(
        {
            "provider": "openai",
            "api_mode": "openai_api",
            "base_url": args.base_url,
            "model": args.model,
            "temperature": args.temperature,
            "max_tokens": args.max_tokens,
            "api_key": args.api_key,
        }
    )
    if not str(root.get("active_ai_profile") or "").strip():
        root["active_ai_profile"] = args.profile
    _write_yaml(data)
    _request_reload(["llm"], "menu:set-openai")
    print(f"updated OpenAI-compatible profile: {args.profile}")


def set_codex(args: argparse.Namespace) -> None:
    args.profile = _validate_profile_name(args.profile)
    data = _load_yaml()
    root = _chatdome_root(data)
    profiles = _profile_items(root)
    token_file = _resolve_codex_token_file(args.profile, args.token_file, profiles.get(args.profile))
    if not _codex_token_file_path(token_file).is_file():
        raise SystemExit("codex token file is missing; run codex-login first")
    _write_codex_profile(
        data,
        root,
        profiles,
        args,
        token_file,
        reload_source="menu:set-codex",
    )
    print(f"updated Codex profile: {args.profile}")


async def _codex_login_async(args: argparse.Namespace) -> None:
    args.profile = _validate_profile_name(args.profile)
    data = _load_yaml()
    root = _chatdome_root(data)
    profiles = _profile_items(root)
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
    data = _load_yaml()
    root = _chatdome_root(data)
    profiles = _profile_items(root)
    _write_codex_profile(
        data,
        root,
        profiles,
        args,
        token_file,
        reload_source="menu:codex-login",
    )
    print(f"Codex profile ready: {args.profile}")


def codex_login(args: argparse.Namespace) -> None:
    try:
        asyncio.run(_codex_login_async(args))
    except KeyboardInterrupt as exc:
        raise SystemExit("cancelled") from exc


def set_active_profile(args: argparse.Namespace) -> None:
    data = _load_yaml()
    root = _chatdome_root(data)
    profiles = _profile_items(root)
    if args.profile not in profiles:
        raise SystemExit(f"unknown profile: {args.profile}")
    root["active_ai_profile"] = args.profile
    _write_yaml(data)
    _request_reload(["llm"], "menu:set-active-profile")
    print(f"active profile set to: {args.profile}")


def telegram_status(args: argparse.Namespace) -> None:
    del args
    data = _load_yaml()
    telegram = _section(_chatdome_root(data), "telegram")
    print("Telegram")
    print(f"- bot token: {_mask_secret(telegram.get('bot_token', ''))}")
    print(f"- allowed chat ids: {telegram.get('allowed_chat_ids') or '(all)'}")
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
    sub.add_parser("status").set_defaults(func=show_status)
    sub.add_parser("env-summary").set_defaults(func=show_env_summary)
    sub.add_parser("llm-list").set_defaults(func=llm_list)

    p = sub.add_parser("set-openai")
    p.add_argument("--profile", default="my-openai-profile")
    p.add_argument("--model", required=True)
    p.add_argument("--base-url", default="https://api.openai.com/v1")
    p.add_argument("--api-key", required=True)
    p.add_argument("--temperature", type=float, default=0.1)
    p.add_argument("--max-tokens", type=int, default=2000)
    p.set_defaults(func=set_openai)

    p = sub.add_parser("set-codex")
    p.add_argument("--profile", default="codex")
    p.add_argument("--model", default="gpt-5.5")
    p.add_argument("--client-id", default="")
    p.add_argument("--token-file", default=None)
    p.add_argument("--base-url", default="https://chatgpt.com/backend-api/codex")
    p.add_argument("--temperature", type=float, default=0.1)
    p.add_argument("--max-tokens", type=int, default=2000)
    p.set_defaults(func=set_codex)

    p = sub.add_parser("codex-login")
    p.add_argument("--profile", default="codex")
    p.add_argument("--model", default="gpt-5.5")
    p.add_argument("--client-id", default="")
    p.add_argument("--token-file", default=None)
    p.add_argument("--base-url", default="https://chatgpt.com/backend-api/codex")
    p.add_argument("--temperature", type=float, default=0.1)
    p.add_argument("--max-tokens", type=int, default=2000)
    p.set_defaults(func=codex_login)

    p = sub.add_parser("set-active-profile")
    p.add_argument("profile")
    p.set_defaults(func=set_active_profile)

    sub.add_parser("telegram-status").set_defaults(func=telegram_status)
    p = sub.add_parser("set-bot-token")
    p.add_argument("token")
    p.set_defaults(func=set_bot_token)
    p = sub.add_parser("set-chat-ids")
    p.add_argument("chat_ids")
    p.set_defaults(func=set_chat_ids)
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
