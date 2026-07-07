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
import json
import logging
import time
import os
import signal
import shutil
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from chatdome.agent.audit import CommandAuditTracker
from chatdome.logger import current_log_origin
from chatdome.sentinel.pack_loader import PackLoader
from chatdome.executor.validator import validate_command

logger = logging.getLogger(__name__)

SENSITIVE_OUTPUT_COMMAND_MARKERS = (
    "/etc/shadow",
    "/etc/passwd",
    ".env",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "auth.json",
    "credential",
    "credentials",
    "secret",
    "token",
    "private_key",
    "private key",
    ".pem",
    ".key",
    "printenv",
    "/environ",
    " environ",
)


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
        persist_command_outputs: bool = False,
        command_output_retention_days: int = 7,
        command_output_max_chars: int = 8000,
        command_output_dir: str | Path | None = None,
        pack_loader: PackLoader | None = None,
    ):
        self.default_timeout = default_timeout
        self.max_output_chars = max_output_chars
        self.allow_generated_commands = allow_generated_commands
        self.allow_unrestricted_commands = allow_unrestricted_commands
        self.persist_command_outputs = persist_command_outputs
        self.command_output_retention_days = max(1, int(command_output_retention_days))
        self.command_output_max_chars = max(1, int(command_output_max_chars))
        if command_output_dir is None:
            from chatdome.runtime_paths import data_path

            command_output_dir = data_path("command_outputs")
        self.command_output_dir = Path(command_output_dir)
        self._pack_loader = pack_loader
        self._last_output_cleanup_ts = 0.0

    @staticmethod
    def _command_log_excerpt(command: str, max_chars: int = 240) -> str:
        """Return a compact one-line command excerpt for INFO/WARNING logs."""
        excerpt = " ".join((command or "").split())
        if len(excerpt) > max_chars:
            excerpt = excerpt[: max_chars - 3].rstrip() + "..."
        return excerpt

    @staticmethod
    def _command_log_hash(command: str) -> str:
        return CommandAuditTracker.sha256_text(command or "")[:12]

    @staticmethod
    async def _kill_process(proc: asyncio.subprocess.Process) -> None:
        if proc.returncode is not None:
            return
        if sys.platform != "win32":
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:
            proc.kill()
        try:
            await asyncio.wait_for(proc.wait(), timeout=2)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            pass

    async def _execute(
        self,
        command: str,
        timeout: int | None = None,
        log_label: str = "command",
    ) -> CommandResult:
        """
        Low-level command execution with timeout and output truncation.

        Uses shell=True because many audit commands involve pipes,
        redirects, and shell builtins. Safety is enforced at higher
        layers (registry templates + validator).
        """
        effective_timeout = timeout or self.default_timeout
        command_hash = self._command_log_hash(command)
        command_excerpt = self._command_log_excerpt(command)
        logger.info(
            "Executing command (label=%s, timeout=%ds, chars=%d, sha256=%s): %s",
            log_label,
            effective_timeout,
            len(command or ""),
            command_hash,
            command_excerpt,
        )
        logger.debug("Full command (label=%s, sha256=%s):\n%s", log_label, command_hash, command)

        try:

            kwargs = {
                "stdout": asyncio.subprocess.PIPE,
                "stderr": asyncio.subprocess.PIPE,
            }
            if sys.platform != "win32":
                kwargs["preexec_fn"] = os.setsid
                
            proc = await asyncio.create_subprocess_shell(
                command,
                **kwargs
            )

            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=effective_timeout,
                )
            except asyncio.TimeoutError:
                await self._kill_process(proc)
                logger.warning(
                    "Command timed out after %ds (label=%s, sha256=%s): %s",
                    effective_timeout,
                    log_label,
                    command_hash,
                    command_excerpt,
                )
                return CommandResult(
                    stdout="",
                    stderr=f"命令执行超时 ({effective_timeout}s)",
                    return_code=None,
                    timed_out=True,
                    command=command,
                )
            except asyncio.CancelledError:
                await self._kill_process(proc)
                logger.warning(
                    "Command cancelled (label=%s, sha256=%s): %s",
                    log_label,
                    command_hash,
                    command_excerpt,
                )
                raise

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
            logger.error(
                "Command execution failed (label=%s, sha256=%s): %s\n  [Error]: %s",
                log_label,
                command_hash,
                command_excerpt,
                e,
            )
            return CommandResult(
                stdout="",
                stderr=f"命令执行异常: {e}",
                return_code=None,
                command=command,
            )

    def _record_execution_audit(
        self,
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
        audit_source = "sentinel" if current_log_origin() == "sentinel" else "user"
        fields: dict[str, Any] = {
            "audit_source": audit_source,
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
            fields.update(
                self._persist_command_output_if_enabled(
                    chat_id=chat_id,
                    tool_call_id=tool_call_id,
                    command=command,
                    reason=reason,
                    result=result,
                    execution_mode=execution_mode,
                    duration_ms=duration_ms,
                )
            )

        CommandAuditTracker.record_event(
            event_type,
            chat_id=chat_id,
            **fields,
        )

    def _persist_command_output_if_enabled(
        self,
        *,
        chat_id: int,
        tool_call_id: str,
        command: str,
        reason: str,
        result: CommandResult,
        execution_mode: str,
        duration_ms: int,
    ) -> dict[str, Any]:
        """Optionally persist command output for debug/forensics without logging it."""
        if not self.persist_command_outputs:
            return {"output_persisted": False}

        if self._looks_sensitive_for_output_archive(command):
            logger.warning(
                "Command output archive skipped due to sensitive command marker (sha256=%s)",
                self._command_log_hash(command),
            )
            return {
                "output_persisted": False,
                "output_skip_reason": "sensitive_command_pattern",
            }

        now = datetime.now(timezone.utc)
        self._cleanup_old_command_outputs(now)
        day_dir = self.command_output_dir / now.strftime("%Y-%m-%d")
        day_dir.mkdir(parents=True, exist_ok=True)

        stdout, stdout_truncated = self._truncate_archive_text(result.stdout or "")
        stderr, stderr_truncated = self._truncate_archive_text(result.stderr or "")
        output_id = f"{now.strftime('%H%M%S')}-{int(chat_id)}-{uuid4().hex[:12]}"
        path = day_dir / f"{output_id}.json"
        payload = {
            "version": 1,
            "timestamp": int(now.timestamp()),
            "timestamp_iso": now.isoformat().replace("+00:00", "Z"),
            "chat_id": int(chat_id),
            "tool_call_id": str(tool_call_id or ""),
            "command": command,
            "reason": reason,
            "execution_mode": execution_mode,
            "duration_ms": duration_ms,
            "return_code": result.return_code,
            "timed_out": result.timed_out,
            "sandbox_truncated": result.truncated,
            "archive_stdout_truncated": stdout_truncated,
            "archive_stderr_truncated": stderr_truncated,
            "stdout_hash": CommandAuditTracker.sha256_text(result.stdout or ""),
            "stderr_hash": CommandAuditTracker.sha256_text(result.stderr or ""),
            "stdout": stdout,
            "stderr": stderr,
        }
        try:
            path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        except OSError as e:
            logger.error("Failed to persist command output archive: %s", e)
            return {
                "output_persisted": False,
                "output_skip_reason": "archive_write_failed",
            }

        output_ref = path.as_posix()
        logger.info(
            "Command output archived (sha256=%s, ref=%s)",
            self._command_log_hash(command),
            output_ref,
        )
        return {
            "output_persisted": True,
            "output_ref": output_ref,
            "output_archive_stdout_truncated": stdout_truncated,
            "output_archive_stderr_truncated": stderr_truncated,
        }

    @staticmethod
    def _looks_sensitive_for_output_archive(command: str) -> bool:
        normalized = " ".join((command or "").lower().split())
        return any(marker in normalized for marker in SENSITIVE_OUTPUT_COMMAND_MARKERS)

    def _truncate_archive_text(self, text: str) -> tuple[str, bool]:
        if len(text) <= self.command_output_max_chars:
            return text, False
        return (
            text[: self.command_output_max_chars]
            + f"\n\n... [command output archive truncated at {self.command_output_max_chars} chars]",
            True,
        )

    def _cleanup_old_command_outputs(self, now: datetime) -> None:
        now_ts = time.time()
        if (now_ts - self._last_output_cleanup_ts) < 3600:
            return
        self._last_output_cleanup_ts = now_ts
        if not self.command_output_dir.exists():
            return

        oldest_keep_date = now.date() - timedelta(days=self.command_output_retention_days - 1)
        for child in self.command_output_dir.iterdir():
            if not child.is_dir():
                continue
            try:
                child_date = datetime.strptime(child.name, "%Y-%m-%d").date()
            except ValueError:
                continue
            if child_date >= oldest_keep_date:
                continue
            try:
                shutil.rmtree(child)
                logger.info("Command output archive cleanup removed %s", child)
            except OSError as e:
                logger.warning("Failed to remove old command output archive %s: %s", child, e)

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
        if self._pack_loader is None:
            return CommandResult(
                stdout="",
                stderr="PackLoader not initialized",
                return_code=None,
                command=f"[check:{check_id}]",
            )
        try:
            rendered = self._pack_loader.render_command(check_id, args)
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
        result = await self._execute(
            rendered.command,
            timeout=rendered.timeout,
            log_label=f"security_check:{rendered.check_id}",
        )
        duration_ms = int((time.monotonic() - started) * 1000)
        self._record_execution_audit(
            event_type="security_check_executed",
            chat_id=chat_id,
            tool_call_id=tool_call_id,
            command=rendered.command,
            reason=f"security_check:{rendered.check_id}",
            result=result,
            execution_mode="pack",
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
            logger.warning(
                "UNRESTRICTED execution (reason: %s, sha256=%s): %s",
                reason,
                self._command_log_hash(command),
                self._command_log_excerpt(command),
            )
            started = time.monotonic()
            executed = await self._execute(command, log_label="ai_command:unrestricted")
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
                "AI-generated command blocked (sha256=%s): %s "
                "(validator reason: %s, AI reason: %s)",
                self._command_log_hash(command),
                self._command_log_excerpt(command),
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

        logger.info(
            "Executing AI-generated command (reason: %s, sha256=%s): %s",
            reason,
            self._command_log_hash(command),
            self._command_log_excerpt(command),
        )
        started = time.monotonic()
        executed = await self._execute(command, log_label="ai_command:validated")
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
