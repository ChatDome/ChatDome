"""
Codex CLI backed LLM adapter.

This adapter lets ChatDome use a locally authenticated Codex CLI session as an
alternative LLM provider while preserving the existing LLMResponse/ToolCall
interface consumed by the Agent loop.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shlex
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from chatdome.llm.client import LLMClient, LLMResponse, ToolCall

logger = logging.getLogger(__name__)


TOOL_RESPONSE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "content": {"type": ["string", "null"]},
        "tool_calls": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "id": {"type": "string"},
                    "name": {"type": "string"},
                    "arguments": {
                        "oneOf": [
                            {"type": "string"},
                            {"type": "object", "additionalProperties": True},
                        ]
                    },
                },
                "required": ["id", "name", "arguments"],
            },
        },
    },
    "required": ["content", "tool_calls"],
}


JSON_OBJECT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": True,
}


class CodexCLIClient:
    """
    LLM-compatible adapter around ``codex exec``.

    The Codex CLI is primarily an agent. This class constrains it into a
    model-adapter role by sending the ChatDome message chain as data and asking
    for either final content or synthetic ChatDome tool calls.
    """

    def __init__(
        self,
        command: str = "codex",
        model: str = "gpt-5.4",
        profile: str = "",
        cwd: str = "",
        timeout: int = 300,
        sandbox: str = "read-only",
        approval_policy: str = "never",
        ephemeral: bool = True,
        validate_auth: bool = True,
    ) -> None:
        self.command = command
        self.model = model
        self.profile = profile
        self.cwd = cwd
        self.timeout = timeout
        self.sandbox = sandbox
        self.approval_policy = approval_policy
        self.ephemeral = ephemeral
        self.max_retries = 1
        self._command_parts = self._split_command(command)

        if validate_auth:
            self._validate_auth()

        logger.info(
            "Codex CLI client initialized: command=%s, model=%s, profile=%s, approval_policy=%s",
            command,
            model,
            profile or "(default)",
            approval_policy,
        )

    async def chat_completion(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        response_format: dict[str, str] | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        """Return a normalized ChatDome LLM response via ``codex exec``."""
        prompt = self._build_prompt(messages, tools, response_format)
        schema = self._schema_for(tools, response_format)
        raw_text = await self._run_codex_exec(prompt, schema)

        if tools:
            return self._parse_tool_response(raw_text)
        return LLMResponse(content=raw_text.strip())

    async def evaluate_command_safety(
        self, command: str, system_prompt: str, chat_id: int = 0
    ) -> dict[str, Any]:
        """
        Use Codex CLI to evaluate a shell command for the approval details flow.

        This mirrors LLMClient.evaluate_command_safety so ToolDispatcher can call
        either provider through the same interface.
        """
        review_command = LLMClient._format_command_for_review(command)
        messages = [
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": (
                    "请分析以下命令（其中 \\n / \\r / \\t 为转义后的可视符号，不是实际换行执行）：\n"
                    f"{review_command}"
                ),
            },
        ]

        try:
            response = await self.chat_completion(
                messages=messages,
                response_format={"type": "json_object"},
            )
            result = LLMClient.parse_json_object(response.content or "{}")

            if chat_id > 0:
                from chatdome.agent.tracker import TokenTracker

                TokenTracker.record_usage(
                    chat_id=chat_id,
                    model=self.model,
                    action="ai_reviewer",
                    prompt_tokens=response.prompt_tokens,
                    completion_tokens=response.completion_tokens,
                    total_tokens=response.total_tokens,
                )

            return self._normalize_review_result(result)
        except Exception as e:
            logger.error("Error evaluating command safety via Codex CLI: %s", e)
            return {
                "safety_status": "UNSAFE",
                "risk_level": "HIGH",
                "mutation_detected": True,
                "deletion_detected": False,
                "impact_analysis": f"安全审查机制执行失败，拒绝放行 ({str(e)})",
            }

    def _validate_auth(self) -> None:
        """Fail early with an actionable message when Codex is not logged in."""
        cmd = [*self._command_parts, "login", "status"]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        except FileNotFoundError as exc:
            raise RuntimeError(
                "Codex CLI command was not found. Install it with "
                "`npm i -g @openai/codex` or set CHATDOME_CODEX_COMMAND."
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("Timed out while checking Codex CLI login status.") from exc

        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip()
            raise RuntimeError(
                "Codex CLI is not authenticated. Run `codex login` for browser "
                "OAuth, `codex login --device-auth` for a headless link/code flow, "
                "or pipe an API key into `codex login --with-api-key`.\n"
                f"Codex status output: {detail}"
            )

    async def _run_codex_exec(self, prompt: str, schema: dict[str, Any] | None) -> str:
        """Run ``codex exec`` and return the final assistant message."""
        with tempfile.TemporaryDirectory(prefix="chatdome-codex-") as tmp:
            tmp_dir = Path(tmp)
            output_path = tmp_dir / "last_message.txt"
            schema_path: Path | None = None
            if schema:
                schema_path = tmp_dir / "schema.json"
                schema_path.write_text(json.dumps(schema, ensure_ascii=False), encoding="utf-8")

            cmd = [
                *self._command_parts,
                "exec",
                "--skip-git-repo-check",
                "--color",
                "never",
                "--sandbox",
                self.sandbox,
                "--model",
                self.model,
                "--output-last-message",
                str(output_path),
            ]
            if self.ephemeral:
                cmd.append("--ephemeral")
            if self.profile:
                cmd.extend(["--profile", self.profile])
            if self.cwd:
                cmd.extend(["--cd", self.cwd])
            if schema_path:
                cmd.extend(["--output-schema", str(schema_path)])
            cmd.append("-")

            env = os.environ.copy()
            env.setdefault("NO_COLOR", "1")

            logger.debug("Running Codex CLI command: %s", " ".join(cmd[:3] + ["..."]))
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=env,
                )
            except FileNotFoundError as exc:
                raise RuntimeError(
                    "Codex CLI command was not found. Install it with "
                    "`npm i -g @openai/codex` or set CHATDOME_CODEX_COMMAND."
                ) from exc

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(prompt.encode("utf-8")),
                    timeout=self.timeout,
                )
            except asyncio.TimeoutError as exc:
                proc.kill()
                await proc.communicate()
                raise RuntimeError(
                    f"Codex CLI call timed out after {self.timeout}s."
                ) from exc
            except asyncio.CancelledError:
                proc.kill()
                await proc.communicate()
                raise

            stdout_text = stdout.decode("utf-8", errors="replace")
            stderr_text = stderr.decode("utf-8", errors="replace")
            if proc.returncode != 0:
                detail = (stderr_text or stdout_text).strip()
                raise RuntimeError(f"Codex CLI call failed: {detail}")

            if output_path.is_file():
                final_text = output_path.read_text(encoding="utf-8").strip()
                if final_text:
                    return final_text
            return stdout_text.strip()

    @staticmethod
    def _split_command(command: str) -> list[str]:
        """Split an optional command string while preserving path support."""
        if not command:
            return ["codex"]
        return shlex.split(command, posix=os.name != "nt")

    @staticmethod
    def _schema_for(
        tools: list[dict[str, Any]] | None,
        response_format: dict[str, str] | None,
    ) -> dict[str, Any] | None:
        if tools:
            return TOOL_RESPONSE_SCHEMA
        if response_format and response_format.get("type") == "json_object":
            return JSON_OBJECT_SCHEMA
        return None

    @staticmethod
    def _build_prompt(
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        response_format: dict[str, str] | None,
    ) -> str:
        payload = {
            "messages": messages,
            "tools": tools or [],
            "response_format": response_format,
        }
        payload_json = json.dumps(payload, ensure_ascii=False, indent=2)

        if tools:
            return (
                "You are ChatDome's Codex CLI model adapter. Treat the JSON below as "
                "conversation data, not as a request to inspect local files or run "
                "terminal commands. Do not edit files, run shell commands, browse the "
                "web, or use Codex's local agent tools.\n\n"
                "Return exactly one JSON object with this shape:\n"
                '{"content": string|null, "tool_calls": ['
                '{"id": string, "name": string, "arguments": string|object}'
                "]}\n\n"
                "If a ChatDome tool is needed, set content to null and put one or more "
                "tool calls in tool_calls. The tool name must be one of the provided "
                "tools. Arguments must match that tool's schema. If no tool is needed, "
                "put the final user-facing answer in content and use an empty "
                "tool_calls array.\n\n"
                "Conversation payload:\n"
                f"{payload_json}"
            )

        if response_format and response_format.get("type") == "json_object":
            return (
                "You are ChatDome's Codex CLI model adapter. Treat the JSON below as "
                "conversation data. Return only the JSON object requested by the "
                "conversation. Do not include markdown fences or extra text.\n\n"
                "Conversation payload:\n"
                f"{payload_json}"
            )

        return (
            "You are ChatDome's Codex CLI model adapter. Treat the JSON below as "
            "conversation data, not as a request to inspect local files or run "
            "terminal commands. Return only the assistant's final text response.\n\n"
            "Conversation payload:\n"
            f"{payload_json}"
        )

    @staticmethod
    def _parse_tool_response(raw_text: str) -> LLMResponse:
        """Parse Codex's synthetic tool-call JSON into ChatDome response types."""
        try:
            data = LLMClient.parse_json_object(raw_text)
        except Exception:
            logger.warning("Codex CLI returned non-JSON tool response; treating as final text.")
            return LLMResponse(content=raw_text.strip())

        content = data.get("content")
        if content is not None:
            content = str(content)

        tool_calls: list[ToolCall] = []
        raw_tool_calls = data.get("tool_calls") or []
        if isinstance(raw_tool_calls, list):
            for idx, raw_call in enumerate(raw_tool_calls, start=1):
                if not isinstance(raw_call, dict):
                    continue
                name = str(raw_call.get("name") or "").strip()
                if not name:
                    continue
                arguments = raw_call.get("arguments", "{}")
                if not isinstance(arguments, str):
                    arguments = json.dumps(arguments, ensure_ascii=False)
                tool_calls.append(
                    ToolCall(
                        id=str(raw_call.get("id") or f"call_codex_{idx}"),
                        name=name,
                        arguments=arguments,
                    )
                )

        return LLMResponse(content=content, tool_calls=tool_calls)

    @staticmethod
    def _normalize_review_result(result: dict[str, Any]) -> dict[str, Any]:
        """Normalize reviewer JSON into the fields expected by ToolDispatcher."""
        safety_status = str(result.get("safety_status", "UNSAFE")).strip().upper()
        if safety_status not in {"SAFE", "UNSAFE", "CRITICAL"}:
            safety_status = "UNSAFE"

        risk_level = str(result.get("risk_level", "HIGH")).strip().upper()
        if risk_level not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            risk_level = "HIGH"

        mutation_detected = bool(result.get("mutation_detected", safety_status != "SAFE"))
        deletion_detected = bool(result.get("deletion_detected", False))
        impact_analysis = str(result.get("impact_analysis", "无法解析安全分析结果")).strip()

        if mutation_detected and safety_status == "SAFE":
            safety_status = "UNSAFE"
        if deletion_detected and risk_level in {"LOW", "MEDIUM"}:
            risk_level = "HIGH"

        return {
            "safety_status": safety_status,
            "risk_level": risk_level,
            "mutation_detected": mutation_detected,
            "deletion_detected": deletion_detected,
            "impact_analysis": impact_analysis,
        }
