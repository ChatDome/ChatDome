"""
Tool dispatch — routes LLM tool_calls to the appropriate executor.

Handles:
  - run_security_check → CommandSandbox.execute_security_check
  - run_shell_command  → CommandSandbox.execute_shell_command
  - whois_lookup       → HTTP call to ip-api.com
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from chatdome.executor.sandbox import CommandSandbox, CommandResult

logger = logging.getLogger(__name__)


class PendingApprovalError(Exception):
    """Raised when a tool call requires user confirmation before execution."""
    def __init__(self, command: str, safety_status: str, impact_analysis: str, tool_call_id: str):
        self.command = command
        self.safety_status = safety_status
        self.impact_analysis = impact_analysis
        self.tool_call_id = tool_call_id
        super().__init__(f"Command requires approval: {command}")


class ToolDispatcher:
    """
    Routes tool calls from the LLM to the appropriate handler
    and formats results as strings for the conversation.
    """

    def __init__(self, sandbox: CommandSandbox, llm: Any = None):
        self.sandbox = sandbox
        self.llm = llm
        self._http_client: httpx.AsyncClient | None = None

    async def _get_http_client(self) -> httpx.AsyncClient:
        """Lazy-init the HTTP client."""
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(timeout=10.0)
        return self._http_client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._http_client and not self._http_client.is_closed:
            await self._http_client.aclose()

    async def dispatch(self, tool_name: str, arguments_json: str, tool_call_id: str = "", chat_id: int = 0) -> str:
        """
        Dispatch a tool call and return the formatted result string.
        Raises PendingApprovalError if the command needs human confirmation.

        Args:
            tool_name: The function name from the LLM tool_call.
            arguments_json: The raw JSON arguments string.
            tool_call_id: The ID of this tool call.
            chat_id: The ID of the chat context.

        Returns:
            Formatted result string to feed back to the LLM.
        """
        try:
            args = json.loads(arguments_json) if arguments_json else {}
        except json.JSONDecodeError as e:
            return f"参数解析失败: {e}"

        try:
            if tool_name == "run_security_check":
                return await self._handle_security_check(args)
            elif tool_name == "run_shell_command":
                return await self._handle_shell_command(args, tool_call_id, chat_id)
            elif tool_name == "whois_lookup":
                return await self._handle_whois_lookup(args)
            else:
                return f"未知工具: {tool_name}"
        except PendingApprovalError:
            raise
        except Exception as e:
            logger.error("Tool execution failed: %s — %s", tool_name, e)
            return f"工具执行异常: {e}"

    # ----- Handlers -----

    async def _handle_security_check(self, args: dict[str, Any]) -> str:
        """Execute a pre-defined security check."""
        check_id = args.get("check_id", "")
        check_args = args.get("args")

        result = await self.sandbox.execute_security_check(check_id, check_args)
        return self._format_command_result(result)

    async def _handle_shell_command(self, args: dict[str, Any], tool_call_id: str, chat_id: int = 0) -> str:
        """Evaluate and suspend an AI-generated shell command for user approval."""
        command = args.get("command", "")
        
        if not command:
            return "缺少 command 参数"

        # 1. AI Reviewer Analysis
        if self.llm:
            from chatdome.agent.prompts import REVIEWER_SYSTEM_PROMPT
            logger.info("Running AI Reviewer for shell command: %s", command)
            review = await self.llm.evaluate_command_safety(command, REVIEWER_SYSTEM_PROMPT, chat_id=chat_id)
            safety_status = review.get("safety_status", "UNSAFE")
            impact_analysis = review.get("impact_analysis", "分析失败")
            
            # Suspend loop and wait for human confirmation
            raise PendingApprovalError(command, safety_status, impact_analysis, tool_call_id)
        
        # 2. Fallback (should not be reached normally)
        result = await self.sandbox.execute_shell_command(command, "LLM Generated")
        return self._format_command_result(result)

    async def _handle_whois_lookup(self, args: dict[str, Any]) -> str:
        """Look up IP geolocation via ip-api.com."""
        ip = args.get("ip", "")
        if not ip:
            return "缺少 IP 地址参数"

        try:
            client = await self._get_http_client()
            response = await client.get(
                f"http://ip-api.com/json/{ip}",
                params={"lang": "zh-CN", "fields": "status,message,country,regionName,city,isp,org,as,query"},
            )
            data = response.json()

            if data.get("status") == "fail":
                return f"IP 查询失败: {data.get('message', '未知错误')}"

            lines = [
                f"IP: {data.get('query', ip)}",
                f"国家: {data.get('country', '未知')}",
                f"地区: {data.get('regionName', '未知')}",
                f"城市: {data.get('city', '未知')}",
                f"ISP: {data.get('isp', '未知')}",
                f"组织: {data.get('org', '未知')}",
                f"AS: {data.get('as', '未知')}",
            ]
            return "\n".join(lines)

        except httpx.TimeoutException:
            return f"IP 查询超时: {ip}"
        except Exception as e:
            logger.error("Whois lookup failed for %s: %s", ip, e)
            return f"IP 查询异常: {e}"

    # ----- Formatting -----

    @staticmethod
    def _format_command_result(result: CommandResult) -> str:
        """Format a CommandResult into a string for the LLM."""
        parts = []

        if result.command:
            parts.append(f"[命令] {result.command}")

        if result.timed_out:
            parts.append("[状态] 执行超时")
        elif result.return_code is not None:
            parts.append(f"[状态] 退出码: {result.return_code}")

        if result.stdout:
            parts.append(f"[输出]\n{result.stdout}")
        elif result.stderr:
            parts.append(f"[错误]\n{result.stderr}")
        else:
            parts.append("[输出] (无输出)")

        if result.truncated:
            parts.append("[注意] 输出已截断")

        return "\n".join(parts)
