"""
Safety validator for AI-generated shell commands.

Implements a regex-based dangerous command blocklist (design doc §5.2)
and optional recognition of known read-only commands.
"""

from __future__ import annotations

import logging
import re
import shlex
from dataclasses import dataclass

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Critical command patterns — EXTREME danger, /confirm ONLY (no button approve)
# These can cause irreversible data loss or system compromise.
# ---------------------------------------------------------------------------

CRITICAL_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Destructive file operations
    (re.compile(r"\brm\b"), "rm — 删除文件"),
    (re.compile(r"\bdd\b"), "dd — 磁盘写入"),
    (re.compile(r"\bmkfs\b"), "mkfs — 格式化文件系统"),
    (re.compile(r"\bformat\b"), "format — 格式化"),

    # System control
    (re.compile(r"\breboot\b"), "reboot — 重启系统"),
    (re.compile(r"\bshutdown\b"), "shutdown — 关机"),
    (re.compile(r"\bhalt\b"), "halt — 停止系统"),

    # Privilege escalation
    (re.compile(r"\bsudo\b"), "sudo — 提权"),
    (re.compile(r"\bsu\b"), "su — 切换用户"),

    # Permission / ownership modification
    (re.compile(r"\bchmod\b"), "chmod — 修改权限"),
    (re.compile(r"\bchown\b"), "chown — 修改所有者"),
    (re.compile(r"\bchattr\b"), "chattr — 修改文件属性"),

    # Code execution
    (re.compile(r"\beval\b"), "eval — 代码执行"),
    (re.compile(r"\bexec\b"), "exec — 代码执行"),
    (re.compile(r"\bsource\b"), "source — 加载脚本"),

    # Sensitive file direct access
    (re.compile(r"/etc/shadow"), "读取 /etc/shadow"),
]


# ---------------------------------------------------------------------------
# Risky command patterns — moderate danger, button approve OK
# ---------------------------------------------------------------------------

RISKY_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Write / move / copy
    (re.compile(r"\bmv\b"), "mv — 移动/重命名"),
    (re.compile(r"\bcp\b"), "cp — 复制文件"),

    # Process control
    (re.compile(r"\bkill\b"), "kill — 终止进程"),
    (re.compile(r"\bkillall\b"), "killall — 终止进程"),
    (re.compile(r"\bpkill\b"), "pkill — 终止进程"),

    # Network download (curl -I is allowed, blocked below)
    (re.compile(r"\bcurl\b(?!.*-I)"), "curl — 网络请求 (curl -I 除外)"),
    (re.compile(r"\bwget\b"), "wget — 下载"),

    # Interpreters
    (re.compile(r"(?:^|[|;&]\s*)python(?:\s|$)"), "python — 解释器"),
    (re.compile(r"(?:^|[|;&]\s*)perl(?:\s|$)"), "perl — 解释器"),
    (re.compile(r"(?:^|[|;&]\s*)ruby(?:\s|$)"), "ruby — 解释器"),
    (re.compile(r"(?:^|[|;&]\s*)node(?:\s|$)"), "node — 解释器"),

    # Redirects and pipe-to-shell
    (re.compile(r">\s"), "重定向写入"),
    (re.compile(r">>"), "追加重定向"),
    (re.compile(r"\|.*\bsh\b"), "管道到 sh"),
    (re.compile(r"\|.*\bbash\b"), "管道到 bash"),

    # Sensitive file direct access
    (re.compile(r"/etc/passwd"), "读取 /etc/passwd"),
]


# Combined list for backward compatibility
DANGEROUS_PATTERNS: list[tuple[re.Pattern, str]] = CRITICAL_PATTERNS + RISKY_PATTERNS


# ---------------------------------------------------------------------------
# Recognized read-only commands (optional second layer)
# ---------------------------------------------------------------------------

READ_ONLY_COMMANDS = {
    "awk", "grep", "egrep", "fgrep", "cat", "head", "tail", "sort", "uniq",
    "wc", "find", "ls", "ps", "ss", "netstat", "journalctl", "dmesg",
    "df", "free", "uptime", "last", "who", "id", "uname", "hostnamectl",
    "ip", "whois", "dig", "nslookup", "top", "lsof", "stat", "file",
    "strings", "hexdump", "md5sum", "sha256sum", "date", "hostname",
}

_SHELL_COMMAND_SEPARATORS = {"|", "||", "&&", ";", "&"}
_SHELL_STRUCTURE_TOKENS = {"(", ")", "{", "}"}
_ASSIGNMENT_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


# ---------------------------------------------------------------------------
# Write-intent detector (fail-safe guardrail)
# ---------------------------------------------------------------------------

# NOTE:
# This detector is intentionally conservative and is used as a hard guardrail.
# Final risk adjudication can still leverage the LLM reviewer, but any hit here
# should require human approval.
WRITE_INTENT_PATTERNS: list[re.Pattern] = [
    # In-place file editing
    re.compile(r"\bsed\b[^\n\r;|&]*\s-i(?:\s|$)"),
    re.compile(r"\bperl\b[^\n\r;|&]*\s-pi(?:\s|$)"),

    # Shell write redirection
    re.compile(r">>"),
    re.compile(r">\s"),

    # Common file mutation commands
    re.compile(r"\btouch\b"),
    re.compile(r"\btruncate\b"),
    re.compile(r"\btee\b"),
    re.compile(r"\bmkdir\b"),
    re.compile(r"\binstall\b"),

    # Service/package/system state changes
    re.compile(r"\bsystemctl\b\s+(start|stop|restart|reload|enable|disable)\b"),
    re.compile(r"\b(service|rc-service)\b\s+\S+\s+(start|stop|restart|reload)\b"),
    re.compile(r"\b(apt|apt-get|yum|dnf|apk|pacman|brew)\b"),
]


# ---------------------------------------------------------------------------
# Validation result
# ---------------------------------------------------------------------------

@dataclass
class ValidationResult:
    """Result of command safety validation."""
    is_safe: bool
    reason: str = ""


def _extract_command_names(command: str) -> tuple[list[str], str]:
    """Return command names at shell pipeline/sequence boundaries."""
    if "$(" in command or "`" in command:
        return [], "命令包含无法静态确认的命令替换"
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars="|&;()<>")
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
    except ValueError:
        return [], "命令语法无法解析"

    names: list[str] = []
    expects_command = True
    for token in tokens:
        if token in _SHELL_STRUCTURE_TOKENS:
            return [], "命令包含无法静态确认的 Shell 结构"
        if token in _SHELL_COMMAND_SEPARATORS:
            expects_command = True
            continue
        if not expects_command:
            continue
        if token == "!" or _ASSIGNMENT_PATTERN.match(token):
            continue
        if token in {"<", ">", ">>", "<<", "<<<"}:
            return [], "命令包含无法静态确认的重定向结构"
        names.append(token.rsplit("/", 1)[-1])
        expects_command = False

    if expects_command or not names:
        return [], "未识别到可执行命令"
    return names, ""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def is_critical_command(command: str) -> bool:
    """
    Check if a command matches CRITICAL patterns (extreme danger).

    Critical commands can only be confirmed via /confirm text command,
    never via inline button, to prevent accidental approval.
    """
    for pattern, _ in CRITICAL_PATTERNS:
        if pattern.search(command):
            return True
    return False


def has_write_intent(command: str) -> bool:
    """
    Check whether command likely mutates system state or files.

    This is a conservative lexical detector and should be treated as
    a hard fail-safe signal for requiring human approval.
    """
    if not command or not command.strip():
        return False

    for pattern in WRITE_INTENT_PATTERNS:
        if pattern.search(command):
            return True
    return False


def validate_command(
    command: str,
    require_recognized_read_only: bool = False,
) -> ValidationResult:
    """
    Validate a shell command for safety.

    Args:
        command: The shell command string to validate.
        require_recognized_read_only: If True, require every base command to
                                      be recognized as read-only.

    Returns:
        ValidationResult with is_safe flag and rejection reason.
    """
    if not command or not command.strip():
        return ValidationResult(is_safe=False, reason="空命令")

    # Check dangerous patterns
    for pattern, description in DANGEROUS_PATTERNS:
        if pattern.search(command):
            logger.warning("Dangerous command blocked: %s (matched: %s)", command, description)
            return ValidationResult(
                is_safe=False,
                reason=f"命令包含危险操作: {description}",
            )

    # Optional: require every base command to be recognized as read-only.
    if require_recognized_read_only:
        command_names, parse_error = _extract_command_names(command)
        if parse_error:
            return ValidationResult(is_safe=False, reason=parse_error)
        for base_cmd in command_names:
            if base_cmd in READ_ONLY_COMMANDS:
                continue
            logger.warning(
                "Command not recognized as read-only: %s (base: %s)",
                command,
                base_cmd,
            )
            return ValidationResult(
                is_safe=False,
                reason=f"本地规则未将 '{base_cmd}' 识别为只读命令",
            )

    return ValidationResult(is_safe=True)
