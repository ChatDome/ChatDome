"""
Command execution sandbox.

Provides a secure wrapper around asyncio.subprocess with:
  - Enforced timeouts
  - Output truncation
  - Unified result format
  - Integration with registry and validator
"""

from __future__ import annotations

import asyncio
import logging
import shlex
from dataclasses import dataclass
from typing import Any

from chatdome.executor.registry import render_command
from chatdome.executor.validator import validate_command

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class CommandResult:
    """Unified command execution result."""
    stdout: str
    stderr: str
    return_code: int | None
    timed_out: bool = False
    truncated: bool = False
    command: str = ""


# ---------------------------------------------------------------------------
# Sandbox
# ---------------------------------------------------------------------------

class CommandSandbox:
    """
    Secure command execution sandbox.

    All commands are executed via asyncio subprocess with enforced
    timeouts and output size limits.
    """

    def __init__(
        self,
        default_timeout: int = 10,
        max_output_chars: int = 4000,
        allow_generated_commands: bool = False,
    ):
        self.default_timeout = default_timeout
        self.max_output_chars = max_output_chars
        self.allow_generated_commands = allow_generated_commands

    async def _execute(
        self,
        command: str,
        timeout: int | None = None,
    ) -> CommandResult:
        """
        Low-level command execution with timeout and output truncation.

        Uses shell=True because many audit commands involve pipes,
        redirects, and shell builtins. Safety is enforced at higher
        layers (registry templates + validator).
        """
        effective_timeout = timeout or self.default_timeout
        logger.info("Executing command (timeout=%ds): %s", effective_timeout, command)

        try:
            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=effective_timeout,
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                logger.warning("Command timed out after %ds: %s", effective_timeout, command)
                return CommandResult(
                    stdout="",
                    stderr=f"命令执行超时 ({effective_timeout}s)",
                    return_code=None,
                    timed_out=True,
                    command=command,
                )

            stdout = stdout_bytes.decode("utf-8", errors="replace")
            stderr = stderr_bytes.decode("utf-8", errors="replace")

            # Truncate output
            truncated = False
            if len(stdout) > self.max_output_chars:
                stdout = stdout[: self.max_output_chars] + f"\n\n... [输出已截断，共 {len(stdout_bytes)} 字符]"
                truncated = True

            return CommandResult(
                stdout=stdout,
                stderr=stderr,
                return_code=proc.returncode,
                timed_out=False,
                truncated=truncated,
                command=command,
            )

        except Exception as e:
            logger.error("Command execution failed: %s — %s", command, e)
            return CommandResult(
                stdout="",
                stderr=f"命令执行异常: {e}",
                return_code=None,
                command=command,
            )

    async def execute_security_check(
        self,
        check_id: str,
        args: dict[str, Any] | None = None,
    ) -> CommandResult:
        """
        Execute a pre-defined security audit command.

        Args:
            check_id: Registered command ID (e.g., 'ssh_bruteforce').
            args: Optional parameter overrides.

        Returns:
            CommandResult with execution output.
        """
        try:
            rendered = render_command(check_id, args)
        except ValueError as e:
            return CommandResult(
                stdout="",
                stderr=str(e),
                return_code=None,
                command=f"[check:{check_id}]",
            )

        logger.info("Running security check: %s (%s)", rendered.name, rendered.check_id)
        return await self._execute(rendered.command, timeout=rendered.timeout)

    async def execute_shell_command(
        self,
        command: str,
        reason: str = "",
    ) -> CommandResult:
        """
        Execute an AI-generated shell command after safety validation.

        Args:
            command: The shell command to execute.
            reason: Why the AI wants to run this command.

        Returns:
            CommandResult with execution output.
        """
        if not self.allow_generated_commands:
            return CommandResult(
                stdout="",
                stderr="自定义命令执行已禁用。请使用预定义的安全审计命令 (run_security_check)。",
                return_code=None,
                command=command,
            )

        # Validate safety
        result = validate_command(command, check_allowlist=True)
        if not result.is_safe:
            logger.warning(
                "AI-generated command blocked: %s — reason: %s (AI reason: %s)",
                command, result.reason, reason,
            )
            return CommandResult(
                stdout="",
                stderr=f"命令安全检查未通过: {result.reason}",
                return_code=None,
                command=command,
            )

        logger.info("Executing AI-generated command (reason: %s): %s", reason, command)
        return await self._execute(command)
