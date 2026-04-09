"""
Pre-defined security audit command registry.

Each command entry contains:
  - name: Human-readable name
  - template: Shell command template with {param} placeholders
  - params: Parameter schema (type, default, max)
  - timeout: Max execution time in seconds
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Command Registry
# ---------------------------------------------------------------------------

COMMAND_REGISTRY: dict[str, dict[str, Any]] = {
    # ── SSH / Authentication ──
    "ssh_bruteforce": {
        "name": "SSH 暴力破解检测",
        "template": (
            "awk '/Failed password/ {{print $(NF-3)}}' /var/log/auth.log "
            "| sort | uniq -c | sort -nr | head -{limit}"
        ),
        "params": {"limit": {"type": "int", "default": 10, "max": 50}},
        "timeout": 10,
    },
    "ssh_success_login": {
        "name": "SSH 成功登录记录",
        "template": (
            "awk '/Accepted/ {{print $1, $2, $3, $9, $11}}' /var/log/auth.log "
            "| tail -{limit}"
        ),
        "params": {"limit": {"type": "int", "default": 20, "max": 100}},
        "timeout": 10,
    },
    "failed_sudo": {
        "name": "sudo 失败记录",
        "template": (
            "grep 'sudo:.*COMMAND' /var/log/auth.log | grep 'NOT' | tail -{limit}"
        ),
        "params": {"limit": {"type": "int", "default": 20, "max": 100}},
        "timeout": 10,
    },

    # ── Network ──
    "active_connections": {
        "name": "当前活跃连接",
        "template": "ss -tunapl | head -{limit}",
        "params": {"limit": {"type": "int", "default": 30, "max": 100}},
        "timeout": 10,
    },
    "open_ports": {
        "name": "监听端口",
        "template": "ss -tlnp",
        "params": {},
        "timeout": 10,
    },
    "firewall_rules": {
        "name": "防火墙规则",
        "template": (
            "iptables -L -n --line-numbers 2>/dev/null "
            "|| nft list ruleset 2>/dev/null "
            "|| echo 'No firewall detected'"
        ),
        "params": {},
        "timeout": 10,
    },

    # ── System Status ──
    "disk_usage": {
        "name": "磁盘使用",
        "template": "df -h",
        "params": {},
        "timeout": 10,
    },
    "memory_usage": {
        "name": "内存使用",
        "template": "free -h",
        "params": {},
        "timeout": 10,
    },
    "system_load": {
        "name": "系统负载",
        "template": "uptime; echo '---'; top -bn1 | head -20",
        "params": {},
        "timeout": 15,
    },
    "last_reboot": {
        "name": "重启历史",
        "template": "last reboot | head -{limit}",
        "params": {"limit": {"type": "int", "default": 10, "max": 30}},
        "timeout": 10,
    },

    # ── Processes / Files ──
    "suspicious_processes": {
        "name": "可疑进程检测",
        "template": "ps aux --sort=-%cpu | head -{limit}",
        "params": {"limit": {"type": "int", "default": 20, "max": 50}},
        "timeout": 10,
    },
    "recent_cron_jobs": {
        "name": "最近 cron 执行",
        "template": (
            "journalctl -u cron --since '{since}' --no-pager | tail -{limit}"
        ),
        "params": {
            "since": {"type": "str", "default": "1 hour ago"},
            "limit": {"type": "int", "default": 30, "max": 100},
        },
        "timeout": 15,
    },
    "large_files": {
        "name": "大文件检测",
        "template": (
            "find / -xdev -type f -size +{min_size} 2>/dev/null | head -{limit}"
        ),
        "params": {
            "min_size": {"type": "str", "default": "100M"},
            "limit": {"type": "int", "default": 20, "max": 50},
        },
        "timeout": 30,
    },

    # ── Logs ──
    "recent_syslog": {
        "name": "最近系统日志",
        "template": (
            "journalctl --since '{since}' --no-pager --priority={priority} "
            "| tail -{limit}"
        ),
        "params": {
            "since": {"type": "str", "default": "1 hour ago"},
            "priority": {"type": "str", "default": "warning"},
            "limit": {"type": "int", "default": 50, "max": 200},
        },
        "timeout": 15,
    },
    "kernel_errors": {
        "name": "内核错误",
        "template": "dmesg --level=err,warn | tail -{limit}",
        "params": {"limit": {"type": "int", "default": 30, "max": 100}},
        "timeout": 10,
    },
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

@dataclass
class RenderedCommand:
    """A command ready for execution."""
    check_id: str
    name: str
    command: str
    timeout: int


def list_checks() -> list[dict[str, str]]:
    """Return a summary list of all available check IDs and names."""
    return [
        {"check_id": cid, "name": entry["name"]}
        for cid, entry in COMMAND_REGISTRY.items()
    ]


def get_command(check_id: str) -> dict[str, Any] | None:
    """Look up a command definition by ID. Returns None if not found."""
    return COMMAND_REGISTRY.get(check_id)


def render_command(check_id: str, args: dict[str, Any] | None = None) -> RenderedCommand:
    """
    Render a command template with validated parameters.

    Args:
        check_id: Pre-defined command ID.
        args: Optional parameter overrides.

    Returns:
        RenderedCommand ready for execution.

    Raises:
        ValueError: If check_id is unknown or parameters are invalid.
    """
    entry = COMMAND_REGISTRY.get(check_id)
    if entry is None:
        available = ", ".join(COMMAND_REGISTRY.keys())
        raise ValueError(
            f"Unknown check_id: '{check_id}'. Available: {available}"
        )

    # Merge defaults with user-provided args
    resolved_params: dict[str, Any] = {}
    param_schema = entry["params"]

    for param_name, schema in param_schema.items():
        user_value = (args or {}).get(param_name, schema["default"])

        if schema["type"] == "int":
            try:
                user_value = int(user_value)
            except (TypeError, ValueError):
                user_value = schema["default"]
            # Enforce max
            if "max" in schema and user_value > schema["max"]:
                logger.warning(
                    "Parameter %s=%d exceeds max %d for %s, clamping",
                    param_name, user_value, schema["max"], check_id,
                )
                user_value = schema["max"]
        elif schema["type"] == "str":
            user_value = str(user_value)

        resolved_params[param_name] = user_value

    # Render template
    command = entry["template"].format(**resolved_params)

    return RenderedCommand(
        check_id=check_id,
        name=entry["name"],
        command=command,
        timeout=entry.get("timeout", 10),
    )
