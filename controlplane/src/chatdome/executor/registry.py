"""
Pre-defined security audit command registry.

run_security_check is Linux-first for now:
templates are selected from Linux command packs and non-Linux
hosts will receive a clear "unsupported" error.
"""

from __future__ import annotations

import logging
import platform
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------

_DEBIAN_DISTROS = {
    "debian", "ubuntu", "linuxmint", "kali", "raspbian", "elementary",
    "pop", "popos", "zorin",
}
_RHEL_DISTROS = {
    "rhel", "centos", "rocky", "almalinux", "fedora", "ol", "oracle",
}


def _read_linux_distro_id() -> str:
    """Best-effort Linux distro detection via /etc/os-release."""
    path = Path("/etc/os-release")
    if not path.exists():
        return ""

    try:
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if line.startswith("ID="):
                return line.split("=", 1)[1].strip().strip('"').lower()
    except OSError:
        return ""
    return ""


def _runtime_platform_candidates() -> list[str]:
    """
    Resolve platform candidate keys in priority order.

    Linux-first policy:
      - Linux: return distro-specific keys first, then "linux"
      - Non-Linux: return empty list (run_security_check currently Linux-only)
    """
    os_family = platform.system().lower()

    if os_family != "linux":
        return []

    distro_id = _read_linux_distro_id()
    keys: list[str] = []
    if distro_id:
        if distro_id in _DEBIAN_DISTROS:
            keys.append("linux:debian")
        elif distro_id in _RHEL_DISTROS:
            keys.append("linux:rhel")
        keys.append(f"linux:{distro_id}")
    keys.append("linux")
    return keys


# ---------------------------------------------------------------------------
# Command Registry
# ---------------------------------------------------------------------------

# Variant item:
#   "some command string"
# or
#   {"template": "...", "requires": ["cmd1", "cmd2"]}

COMMAND_REGISTRY: dict[str, dict[str, Any]] = {
    # ── SSH / Authentication (Linux-first) ──
    "ssh_bruteforce": {
        "name": "SSH 暴力破解检测",
        "params": {"limit": {"type": "int", "default": 10, "max": 50}},
        "timeout": 10,
        "templates": {
            "linux": [
                {
                    "template": (
                        "(if [ -f /var/log/auth.log ]; then "
                        "awk '/Failed password/ {{print $(NF-3)}}' /var/log/auth.log; "
                        "elif [ -f /var/log/secure ]; then "
                        "awk '/Failed password/ {{print $(NF-3)}}' /var/log/secure; "
                        "else echo 'No SSH auth log found'; fi) "
                        "| sort | uniq -c | sort -nr | head -{limit}"
                    ),
                    "requires": ["awk", "sort", "uniq", "head"],
                },
            ],
        },
    },
    "ssh_success_login": {
        "name": "SSH 成功登录记录",
        "params": {"limit": {"type": "int", "default": 20, "max": 100}},
        "timeout": 10,
        "templates": {
            "linux": [
                {
                    "template": (
                        "(if [ -f /var/log/auth.log ]; then "
                        "awk '/Accepted/ {{print $1, $2, $3, $9, $11}}' /var/log/auth.log; "
                        "elif [ -f /var/log/secure ]; then "
                        "awk '/Accepted/ {{print $1, $2, $3, $9, $11}}' /var/log/secure; "
                        "else echo 'No SSH auth log found'; fi) "
                        "| tail -{limit}"
                    ),
                    "requires": ["awk", "tail"],
                },
            ],
        },
    },
    "failed_sudo": {
        "name": "sudo 失败记录",
        "params": {"limit": {"type": "int", "default": 20, "max": 100}},
        "timeout": 10,
        "templates": {
            "linux": [
                {
                    "template": (
                        "(if [ -f /var/log/auth.log ]; then "
                        "grep 'sudo:.*COMMAND' /var/log/auth.log | grep 'NOT'; "
                        "elif [ -f /var/log/secure ]; then "
                        "grep 'sudo:.*COMMAND' /var/log/secure | grep 'NOT'; "
                        "else echo 'No sudo log found'; fi) "
                        "| tail -{limit}"
                    ),
                    "requires": ["grep", "tail"],
                },
            ],
        },
    },

    # ── Network ──
    "active_connections": {
        "name": "当前活跃连接",
        "params": {"limit": {"type": "int", "default": 30, "max": 100}},
        "timeout": 10,
        "templates": {
            "linux": [
                {"template": "ss -tunapl | head -{limit}", "requires": ["ss", "head"]},
                {"template": "netstat -tunap | head -{limit}", "requires": ["netstat", "head"]},
            ],
            "darwin": [
                {"template": "netstat -anv -p tcp | head -{limit}", "requires": ["netstat", "head"]},
            ],
            "windows": [
                {
                    "template": (
                        "powershell -NoProfile -Command "
                        "\"Get-NetTCPConnection | Select-Object -First {limit} "
                        "LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess "
                        "| Format-Table -AutoSize\""
                    ),
                    "requires": ["powershell"],
                },
                {
                    "template": (
                        "powershell -NoProfile -Command "
                        "\"netstat -ano | Select-Object -First {limit}\""
                    ),
                    "requires": ["powershell", "netstat"],
                },
            ],
        },
    },
    "open_ports": {
        "name": "监听端口",
        "params": {},
        "timeout": 10,
        "templates": {
            "linux": [
                {"template": "ss -tlnp", "requires": ["ss"]},
                {"template": "netstat -tlnp", "requires": ["netstat"]},
            ],
            "darwin": [
                {"template": "lsof -nP -iTCP -sTCP:LISTEN", "requires": ["lsof"]},
                {"template": "netstat -anv -p tcp | grep LISTEN", "requires": ["netstat", "grep"]},
            ],
            "windows": [
                {
                    "template": (
                        "powershell -NoProfile -Command "
                        "\"Get-NetTCPConnection -State Listen "
                        "| Select-Object LocalAddress,LocalPort,OwningProcess "
                        "| Format-Table -AutoSize\""
                    ),
                    "requires": ["powershell"],
                },
                {"template": "netstat -ano | findstr LISTENING", "requires": ["netstat"]},
            ],
        },
    },
    "firewall_rules": {
        "name": "防火墙规则",
        "params": {},
        "timeout": 10,
        "templates": {
            "linux": [
                {
                    "template": (
                        "iptables -L -n --line-numbers 2>/dev/null "
                        "|| nft list ruleset 2>/dev/null "
                        "|| echo 'No firewall detected'"
                    ),
                },
            ],
            "darwin": [
                {"template": "pfctl -sr 2>/dev/null || echo 'pf is disabled or unavailable'"},
            ],
            "windows": [
                {
                    "template": (
                        "powershell -NoProfile -Command "
                        "\"Get-NetFirewallProfile | Select-Object Name,Enabled,"
                        "DefaultInboundAction,DefaultOutboundAction | Format-Table -AutoSize\""
                    ),
                    "requires": ["powershell"],
                },
                {"template": "netsh advfirewall show allprofiles", "requires": ["netsh"]},
            ],
        },
    },

    # ── System Status ──
    "disk_usage": {
        "name": "磁盘使用",
        "params": {},
        "timeout": 10,
        "templates": {
            "linux": [{"template": "df -h", "requires": ["df"]}],
            "darwin": [{"template": "df -h", "requires": ["df"]}],
            "windows": [
                {
                    "template": (
                        "powershell -NoProfile -Command "
                        "\"Get-PSDrive -PSProvider FileSystem | Format-Table -AutoSize Name,Used,Free\""
                    ),
                    "requires": ["powershell"],
                },
                {"template": "wmic logicaldisk get caption,freespace,size", "requires": ["wmic"]},
            ],
        },
    },
    "memory_usage": {
        "name": "内存使用",
        "params": {},
        "timeout": 10,
        "templates": {
            "linux": [{"template": "free -h", "requires": ["free"]}],
            "darwin": [{"template": "vm_stat | head -20", "requires": ["vm_stat", "head"]}],
            "windows": [
                {
                    "template": (
                        "powershell -NoProfile -Command "
                        "\"Get-CimInstance Win32_OperatingSystem "
                        "| Select-Object CSName,TotalVisibleMemorySize,FreePhysicalMemory "
                        "| Format-List\""
                    ),
                    "requires": ["powershell"],
                },
            ],
        },
    },
    "system_load": {
        "name": "系统负载",
        "params": {},
        "timeout": 15,
        "templates": {
            "linux": [{"template": "uptime; echo '---'; top -bn1 | head -20", "requires": ["uptime", "top", "head"]}],
            "darwin": [{"template": "uptime; echo '---'; top -l 1 | head -20", "requires": ["uptime", "top", "head"]}],
            "windows": [
                {"template": "wmic cpu get loadpercentage", "requires": ["wmic"]},
                {
                    "template": (
                        "powershell -NoProfile -Command "
                        "\"Get-Process | Sort-Object CPU -Descending "
                        "| Select-Object -First 15 Name,CPU,Id | Format-Table -AutoSize\""
                    ),
                    "requires": ["powershell"],
                },
            ],
        },
    },
    "last_reboot": {
        "name": "重启历史",
        "params": {"limit": {"type": "int", "default": 10, "max": 30}},
        "timeout": 10,
        "templates": {
            "linux": [{"template": "last reboot | head -{limit}", "requires": ["last", "head"]}],
            "darwin": [{"template": "who -b", "requires": ["who"]}],
            "windows": [
                {"template": "systeminfo | findstr /i \"System Boot Time\"", "requires": ["systeminfo"]},
            ],
        },
    },

    # ── Processes / Files ──
    "suspicious_processes": {
        "name": "可疑进程检测",
        "params": {"limit": {"type": "int", "default": 20, "max": 50}},
        "timeout": 10,
        "templates": {
            "linux": [{"template": "ps aux --sort=-%cpu | head -{limit}", "requires": ["ps", "head"]}],
            "darwin": [{"template": "ps aux | sort -nr -k 3 | head -{limit}", "requires": ["ps", "sort", "head"]}],
            "windows": [
                {
                    "template": (
                        "powershell -NoProfile -Command "
                        "\"Get-Process | Sort-Object CPU -Descending "
                        "| Select-Object -First {limit} Name,CPU,Id "
                        "| Format-Table -AutoSize\""
                    ),
                    "requires": ["powershell"],
                },
            ],
        },
    },
    "recent_cron_jobs": {
        "name": "最近 cron 执行",
        "params": {
            "since": {"type": "str", "default": "1 hour ago"},
            "limit": {"type": "int", "default": 30, "max": 100},
        },
        "timeout": 15,
        "templates": {
            "linux:debian": [
                {"template": "journalctl -u cron --since '{since}' --no-pager | tail -{limit}", "requires": ["journalctl", "tail"]},
            ],
            "linux:rhel": [
                {"template": "journalctl -u crond --since '{since}' --no-pager | tail -{limit}", "requires": ["journalctl", "tail"]},
            ],
            "linux": [
                {"template": "journalctl -u cron --since '{since}' --no-pager | tail -{limit}", "requires": ["journalctl", "tail"]},
                {"template": "journalctl -u crond --since '{since}' --no-pager | tail -{limit}", "requires": ["journalctl", "tail"]},
            ],
            "darwin": [
                {"template": "crontab -l 2>/dev/null | tail -{limit}", "requires": ["crontab", "tail"]},
            ],
            "windows": [
                {
                    "template": (
                        "powershell -NoProfile -Command "
                        "\"Get-ScheduledTask | Select-Object -First {limit} TaskName,State,TaskPath "
                        "| Format-Table -AutoSize\""
                    ),
                    "requires": ["powershell"],
                },
            ],
        },
    },
    "large_files": {
        "name": "大文件检测",
        "params": {
            "min_size": {"type": "str", "default": "100M"},
            "limit": {"type": "int", "default": 20, "max": 50},
        },
        "timeout": 30,
        "templates": {
            "linux": [{"template": "find / -xdev -type f -size +{min_size} 2>/dev/null | head -{limit}", "requires": ["find", "head"]}],
            "darwin": [{"template": "find / -xdev -type f -size +{min_size} 2>/dev/null | head -{limit}", "requires": ["find", "head"]}],
            "windows": [
                {
                    "template": (
                        "powershell -NoProfile -Command "
                        "\"Get-ChildItem -Path C:\\ -File -Recurse -ErrorAction SilentlyContinue "
                        "| Sort-Object Length -Descending "
                        "| Select-Object -First {limit} FullName,Length | Format-Table -AutoSize\""
                    ),
                    "requires": ["powershell"],
                },
            ],
        },
    },

    # ── Logs (Linux-first) ──
    "recent_syslog": {
        "name": "最近系统日志",
        "params": {
            "since": {"type": "str", "default": "1 hour ago"},
            "priority": {"type": "str", "default": "warning"},
            "limit": {"type": "int", "default": 50, "max": 200},
        },
        "timeout": 15,
        "templates": {
            "linux": [
                {
                    "template": (
                        "journalctl --since '{since}' --no-pager --priority={priority} "
                        "| tail -{limit}"
                    ),
                    "requires": ["journalctl", "tail"],
                },
            ],
        },
    },
    "kernel_errors": {
        "name": "内核错误",
        "params": {"limit": {"type": "int", "default": 30, "max": 100}},
        "timeout": 10,
        "templates": {
            "linux": [{"template": "dmesg --level=err,warn | tail -{limit}", "requires": ["dmesg", "tail"]}],
            "darwin": [{"template": "dmesg | tail -{limit}", "requires": ["dmesg", "tail"]}],
            "windows": [
                {
                    "template": (
                        "powershell -NoProfile -Command "
                        "\"Get-WinEvent -LogName System -MaxEvents {limit} "
                        "| Select-Object TimeCreated,Id,LevelDisplayName,Message "
                        "| Format-Table -AutoSize\""
                    ),
                    "requires": ["powershell"],
                },
            ],
        },
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


def _normalize_variant(raw_variant: Any) -> dict[str, Any]:
    """Normalize variant item to {'template': str, 'requires': list[str]}."""
    if isinstance(raw_variant, str):
        return {"template": raw_variant, "requires": []}
    if isinstance(raw_variant, dict) and "template" in raw_variant:
        requires = raw_variant.get("requires") or []
        return {"template": str(raw_variant["template"]), "requires": [str(x) for x in requires]}
    raise ValueError(f"Invalid command variant: {raw_variant!r}")


def _requirements_met(requires: list[str]) -> bool:
    """Check if required binaries are available on current host."""
    if not requires:
        return True
    return all(shutil.which(cmd) is not None for cmd in requires)


def _select_template(entry: dict[str, Any], check_id: str) -> str:
    """Select command template based on runtime platform and command availability."""
    # Backward compatibility: old single-template format
    if "template" in entry:
        return str(entry["template"])

    template_map = entry.get("templates")
    if not isinstance(template_map, dict):
        raise ValueError(f"Invalid registry entry for '{check_id}': missing template(s)")

    platform_candidates = _runtime_platform_candidates()
    if not platform_candidates:
        family = platform.system().lower()
        raise ValueError(
            "run_security_check currently only supports Linux command packs. "
            f"Current platform: '{family}'."
        )

    for key in platform_candidates:
        raw_variants = template_map.get(key)
        if not raw_variants:
            continue

        variants = raw_variants if isinstance(raw_variants, list) else [raw_variants]
        normalized = [_normalize_variant(v) for v in variants]

        for variant in normalized:
            if _requirements_met(variant["requires"]):
                return variant["template"]

        # Requirements not met: fallback to first variant and let execution layer report failure
        missing_req = normalized[0].get("requires", [])
        logger.warning(
            "No fully-matched command variant for %s on key=%s; fallback to first template (requires=%s)",
            check_id, key, missing_req,
        )
        return normalized[0]["template"]

    family = platform.system().lower()
    raise ValueError(
        f"check_id '{check_id}' has no Linux template for current platform '{family}'."
    )


def render_command(check_id: str, args: dict[str, Any] | None = None) -> RenderedCommand:
    """
    Render a command template with validated parameters.

    Args:
        check_id: Pre-defined command ID.
        args: Optional parameter overrides.

    Returns:
        RenderedCommand ready for execution.

    Raises:
        ValueError: If check_id is unknown, unsupported, or parameters are invalid.
    """
    entry = COMMAND_REGISTRY.get(check_id)
    if entry is None:
        available = ", ".join(COMMAND_REGISTRY.keys())
        raise ValueError(
            f"Unknown check_id: '{check_id}'. Available: {available}",
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

    template = _select_template(entry, check_id)
    command = template.format(**resolved_params)

    return RenderedCommand(
        check_id=check_id,
        name=entry["name"],
        command=command,
        timeout=entry.get("timeout", 10),
    )
