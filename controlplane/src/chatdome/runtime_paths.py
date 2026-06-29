"""Runtime filesystem locations shared by the server components."""

from __future__ import annotations

import os
from pathlib import Path


def data_dir() -> Path:
    """Return the writable runtime data directory."""
    return Path(os.environ.get("CHATDOME_DATA_DIR", "chat_data")).expanduser()


def data_path(*parts: str) -> Path:
    """Return one path below the writable runtime data directory."""
    return data_dir().joinpath(*parts)


def run_dir() -> Path:
    """Return the writable runtime state directory."""
    return Path(os.environ.get("CHATDOME_RUN_DIR", str(data_path("run")))).expanduser()


def run_path(*parts: str) -> Path:
    """Return one path below the runtime state directory."""
    return run_dir().joinpath(*parts)


def log_dir() -> Path:
    """Return the writable runtime log directory."""
    return Path(os.environ.get("CHATDOME_LOG_DIR", str(data_dir()))).expanduser()


def log_path(name: str = "chatdome.log") -> Path:
    """Return one path below the writable runtime log directory."""
    return log_dir() / name


def _migrate_legacy_file(new_path: Path, legacy_paths: list[Path]) -> Path:
    """Move one legacy file to the new layout when possible."""
    if new_path.exists():
        return new_path

    for legacy_path in legacy_paths:
        if not legacy_path.exists():
            continue
        if legacy_path.resolve() == new_path.resolve():
            return new_path
        try:
            new_path.parent.mkdir(parents=True, exist_ok=True)
            legacy_path.replace(new_path)
            return new_path
        except OSError:
            return legacy_path

    return new_path


def memory_file_path(chat_id: int | str) -> Path:
    """Return the compressed conversation memory file for one chat."""
    return _migrate_legacy_file(
        data_path("memory", f"{chat_id}.json"),
        [data_path(f"{chat_id}_memory.json")],
    )


def compression_log_path(chat_id: int | str) -> Path:
    """Return the context compression event log for one chat."""
    return _migrate_legacy_file(
        data_path("compression", f"{chat_id}.log"),
        [data_path(f"{chat_id}_raw.log")],
    )


def engram_store_path() -> Path:
    """Return the Agent long-term memory store path."""
    return _migrate_legacy_file(
        data_path("memory", "engram.json"),
        [data_path("engram.json")],
    )


def sentinel_alerts_path() -> Path:
    """Return the Sentinel alert history path."""
    return _migrate_legacy_file(
        data_path("sentinel", "alerts.jsonl"),
        [data_path("sentinel_alerts.jsonl")],
    )


def sentinel_push_state_path() -> Path:
    """Return the Sentinel alert push state path."""
    return _migrate_legacy_file(
        data_path("sentinel", "push_state.json"),
        [data_path("sentinel_alert_push_state.json")],
    )


def sentinel_user_context_path() -> Path:
    """Return the Sentinel user context ledger path."""
    return _migrate_legacy_file(
        data_path("sentinel", "user_context.json"),
        [data_path("user_context.json")],
    )


def token_usage_path() -> Path:
    """Return the LLM token usage JSONL path."""
    return _migrate_legacy_file(
        data_path("usage", "token_usage.jsonl"),
        [data_path("token_usage.jsonl")],
    )


def environment_profile_path() -> Path:
    """Return the runtime environment profile path."""
    return _migrate_legacy_file(
        data_path("environment", "profile.md"),
        [data_path("environment_profile.md")],
    )


def llm_profile_lock_path() -> Path:
    """Return the runtime lock file for LLM profile mutations."""
    return run_path("llm-profile.lock")
