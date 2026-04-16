"""
Runtime environment profiler for command compatibility.

Collects host OS information at startup, persists a markdown report,
and returns a concise prompt context so the agent can generate
platform-compatible commands.
"""

from __future__ import annotations

import os
import platform
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_REPORT_PATH = Path("chat_data/environment_profile.md")


_COMMAND_CANDIDATES = [
    "sh", "bash", "zsh", "fish",
    "cmd", "powershell", "pwsh",
    "apt", "apt-get", "yum", "dnf", "apk", "pacman", "brew",
    "systemctl", "journalctl",
    "ss", "netstat", "ip", "ifconfig",
    "ps", "top",
    "awk", "grep", "sed", "find", "sort", "uniq", "head", "tail",
    "curl", "wget",
]


@dataclass
class RuntimeEnvironmentSnapshot:
    """Collected runtime environment attributes."""

    collected_at_utc: str
    os_family: str
    os_release: str
    os_version: str
    machine: str
    python_version: str
    shell: str
    distro_name: str
    distro_id: str
    distro_version_id: str
    is_wsl: bool
    available_commands: list[str]
    missing_commands: list[str]


def _read_os_release() -> dict[str, str]:
    """Parse /etc/os-release on Linux, if available."""
    path = Path("/etc/os-release")
    if not path.exists():
        return {}

    data: dict[str, str] = {}
    try:
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            data[key] = value.strip().strip('"')
    except OSError:
        return {}
    return data


def _detect_shell() -> str:
    """Detect user shell from common environment variables."""
    return (
        os.environ.get("SHELL")
        or os.environ.get("COMSPEC")
        or os.environ.get("TERM_PROGRAM")
        or "unknown"
    )


def _detect_wsl() -> bool:
    """Best-effort detection for WSL."""
    if platform.system().lower() != "linux":
        return False

    if os.environ.get("WSL_DISTRO_NAME"):
        return True

    try:
        proc_version = Path("/proc/version")
        if proc_version.exists():
            text = proc_version.read_text(encoding="utf-8", errors="ignore").lower()
            return "microsoft" in text or "wsl" in text
    except OSError:
        pass
    return False


def collect_runtime_environment() -> RuntimeEnvironmentSnapshot:
    """Collect OS, shell, distro, and command availability."""
    os_release_data = _read_os_release()

    available: list[str] = []
    missing: list[str] = []
    for cmd in _COMMAND_CANDIDATES:
        if shutil.which(cmd):
            available.append(cmd)
        else:
            missing.append(cmd)

    return RuntimeEnvironmentSnapshot(
        collected_at_utc=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        os_family=platform.system() or "unknown",
        os_release=platform.release() or "unknown",
        os_version=platform.version() or "unknown",
        machine=platform.machine() or "unknown",
        python_version=platform.python_version() or "unknown",
        shell=_detect_shell(),
        distro_name=os_release_data.get("PRETTY_NAME", ""),
        distro_id=os_release_data.get("ID", ""),
        distro_version_id=os_release_data.get("VERSION_ID", ""),
        is_wsl=_detect_wsl(),
        available_commands=available,
        missing_commands=missing,
    )


def _build_markdown_report(snapshot: RuntimeEnvironmentSnapshot) -> str:
    """Render markdown report for persistent environment documentation."""
    distro_display = (
        snapshot.distro_name
        or f"{snapshot.distro_id or 'unknown'} {snapshot.distro_version_id or ''}".strip()
        or "N/A"
    )
    available = ", ".join(snapshot.available_commands) if snapshot.available_commands else "none"
    missing = ", ".join(snapshot.missing_commands) if snapshot.missing_commands else "none"

    return f"""# ChatDome Runtime Environment Profile

This file is auto-generated at startup and should be treated as an execution baseline.

## Collected At

- UTC: {snapshot.collected_at_utc}

## Host Summary

- OS family: {snapshot.os_family}
- OS release: {snapshot.os_release}
- OS version: {snapshot.os_version}
- Machine: {snapshot.machine}
- Python: {snapshot.python_version}
- Shell: {snapshot.shell}
- Linux distro: {distro_display}
- WSL: {"yes" if snapshot.is_wsl else "no"}

## Command Availability Probe

- Available: {available}
- Missing: {missing}
"""


def _build_prompt_context(snapshot: RuntimeEnvironmentSnapshot, report_path: Path) -> str:
    """Create compact runtime context injected into system prompt."""
    distro_display = (
        snapshot.distro_name
        or f"{snapshot.distro_id or 'unknown'} {snapshot.distro_version_id or ''}".strip()
        or "N/A"
    )
    available = ", ".join(snapshot.available_commands[:25]) if snapshot.available_commands else "none"
    missing = ", ".join(snapshot.missing_commands[:20]) if snapshot.missing_commands else "none"
    report_abs = str(report_path.resolve())

    return (
        "运行环境信息（启动时自动采集）:\n"
        f"- 环境档案文件: {report_abs}\n"
        f"- OS: {snapshot.os_family} {snapshot.os_release}\n"
        f"- OS Version: {snapshot.os_version}\n"
        f"- Linux Distro: {distro_display}\n"
        f"- Shell: {snapshot.shell}\n"
        f"- WSL: {'yes' if snapshot.is_wsl else 'no'}\n"
        f"- 可用命令(节选): {available}\n"
        f"- 不可用命令(节选): {missing}\n"
        "要求: 你生成和建议的所有命令必须与上述环境兼容；"
        "若某命令在当前环境不可用，先选择等价命令。"
    )


def collect_and_persist_runtime_environment(
    report_path: str | Path = DEFAULT_REPORT_PATH,
) -> tuple[RuntimeEnvironmentSnapshot, str]:
    """
    Collect runtime environment, persist markdown report, and return prompt context.

    Returns:
        (snapshot, prompt_context)
    """
    target = Path(report_path)
    target.parent.mkdir(parents=True, exist_ok=True)

    snapshot = collect_runtime_environment()
    target.write_text(_build_markdown_report(snapshot), encoding="utf-8")

    return snapshot, _build_prompt_context(snapshot, target)

