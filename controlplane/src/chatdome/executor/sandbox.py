"""
Command execution sandbox.

Provides a wrapper around asyncio subprocess execution with:
  - enforced timeouts
  - output truncation
  - unified result format
  - validator integration
  - command audit events
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Any

from chatdome.agent.audit import CommandAuditTracker
from chatdome.executor.registry import render_command
from chatdome.executor.validator import validate_command

logger = logging.getLogger(__name__)


@dataclass
class CommandResult:
    """Unified command execution result."""

    stdout: str
    stderr: str
    return_code: int | None
    timed_out: bool = False
    truncated: bool = False
    command: str = ""


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
        allow_unrestricted_commands: bool = False,
    ):
        self.default_timeout = default_timeout
        self.max_output_chars = max_output_chars
        self.allow_generated_commands = allow_generated_commands
        self.allow_unrestricted_commands = allow_unrestricted_commands

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

            truncated = False
            if len(stdout) > self.max_output_chars:
                stdout = (
                    stdout[: self.max_output_chars]
                    + f"\n\n... [输出已截断，原始字节数={len(stdout_bytes)}]"
                )
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
            logger.error("Command execution failed: %s - %s", command, e)
            return CommandResult(
                stdout="",
                stderr=f"命令执行异常: {e}",
                return_code=None,
                command=command,
            )

    @staticmethod
    def _record_execution_audit(
        *,
        event_type: str,
        chat_id: int,
        tool_call_id: str,
        command: str,
        reason: str,
        result: CommandResult | None = None,
        execution_mode: str = "",
        duration_ms: int = 0,
        block_reason: str = "",
        extra_fields: dict[str, Any] | None = None,
    ) -> None:
        fields: dict[str, Any] = {
            "tool_call_id": tool_call_id,
            "command": command,
            "reason": reason,
            "execution_mode": execution_mode,
            "duration_ms": duration_ms,
        }
        if block_reason:
            fields["block_reason"] = block_reason
        if extra_fields:
            fields.update(extra_fields)

        if result is not None:
            fields.update(
                {
                    "return_code": result.return_code,
                    "timed_out": result.timed_out,
                    "truncated": result.truncated,
                    "stdout_bytes": len((result.stdout or "").encode("utf-8", errors="replace")),
                    "stderr_bytes": len((result.stderr or "").encode("utf-8", errors="replace")),
                    "stdout_hash": CommandAuditTracker.sha256_text(result.stdout or ""),
                    "stderr_hash": CommandAuditTracker.sha256_text(result.stderr or ""),
                }
            )

        CommandAuditTracker.record_event(
            event_type,
            chat_id=chat_id,
            **fields,
        )

    async def execute_security_check(
        self,
        check_id: str,
        args: dict[str, Any] | None = None,
        chat_id: int = 0,
        tool_call_id: str = "",
    ) -> CommandResult:
        """
        Execute a pre-defined security audit command.

        Args:
            check_id: Registered command ID (e.g., 'ssh_bruteforce').
            args: Optional parameter overrides.
            chat_id: Chat context for audit logging.
            tool_call_id: Optional tool call ID for trace linkage.

        Returns:
            CommandResult with execution output.
        """
        try:
            rendered = render_command(check_id, args)
        except ValueError as e:
            self._record_execution_audit(
                event_type="security_check_invalid",
                chat_id=chat_id,
                tool_call_id=tool_call_id,
                command=f"[check:{check_id}]",
                reason="security_check_render_failed",
                block_reason=str(e),
            )
            return CommandResult(
                stdout="",
                stderr=str(e),
                return_code=None,
                command=f"[check:{check_id}]",
            )

        logger.info("Running security check: %s (%s)", rendered.name, rendered.check_id)
        started = time.monotonic()
        result = await self._execute(rendered.command, timeout=rendered.timeout)
        duration_ms = int((time.monotonic() - started) * 1000)
        self._record_execution_audit(
            event_type="security_check_executed",
            chat_id=chat_id,
            tool_call_id=tool_call_id,
            command=rendered.command,
            reason=f"security_check:{rendered.check_id}",
            result=result,
            execution_mode="registry",
            duration_ms=duration_ms,
            extra_fields={
                "check_id": rendered.check_id,
                "check_name": rendered.name,
                "timeout_seconds": rendered.timeout,
            },
        )
        return result

    async def execute_shell_command(
        self,
        command: str,
        reason: str = "",
        chat_id: int = 0,
        tool_call_id: str = "",
    ) -> CommandResult:
        """
        Execute an AI-generated shell command after safety validation.

        Args:
            command: The shell command to execute.
            reason: Why the AI wants to run this command.
            chat_id: Chat context for audit logging.
            tool_call_id: Optional tool call ID for trace linkage.

        Returns:
            CommandResult with execution output.
        """
        if self.allow_unrestricted_commands:
            logger.warning("UNRESTRICTED execution (reason: %s): %s", reason, command)
            started = time.monotonic()
            executed = await self._execute(command)
            self._record_execution_audit(
                event_type="command_executed",
                chat_id=chat_id,
                tool_call_id=tool_call_id,
                command=command,
                reason=reason,
                result=executed,
                execution_mode="unrestricted",
                duration_ms=int((time.monotonic() - started) * 1000),
            )
            return executed

        if not self.allow_generated_commands:
            self._record_execution_audit(
                event_type="command_blocked",
                chat_id=chat_id,
                tool_call_id=tool_call_id,
                command=command,
                reason=reason,
                block_reason="generated_commands_disabled",
            )
            return CommandResult(
                stdout="",
                stderr="自定义命令执行已禁用。请使用 run_security_check。",
                return_code=None,
                command=command,
            )

        validation = validate_command(command, check_allowlist=True)
        if not validation.is_safe:
            logger.warning(
                "AI-generated command blocked: %s (validator reason: %s, AI reason: %s)",
                command,
                validation.reason,
                reason,
            )
            self._record_execution_audit(
                event_type="command_blocked",
                chat_id=chat_id,
                tool_call_id=tool_call_id,
                command=command,
                reason=reason,
                block_reason=validation.reason,
            )
            return CommandResult(
                stdout="",
                stderr=f"命令被校验器拦截: {validation.reason}",
                return_code=None,
                command=command,
            )

        logger.info("Executing AI-generated command (reason: %s): %s", reason, command)
        started = time.monotonic()
        executed = await self._execute(command)
        self._record_execution_audit(
            event_type="command_executed",
            chat_id=chat_id,
            tool_call_id=tool_call_id,
            command=command,
            reason=reason,
            result=executed,
            execution_mode="validated",
            duration_ms=int((time.monotonic() - started) * 1000),
        )
        return executed
