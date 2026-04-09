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


class ToolDispatcher:
    """
    Routes tool calls from the LLM to the appropriate handler
    and formats results as strings for the conversation.
    """

    def __init__(self, sandbox: CommandSandbox):
        self.sandbox = sandbox
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

    async def dispatch(self, tool_name: str, arguments_json: str) -> str:
        """
        Dispatch a tool call and return the formatted result string.

        Args:
            tool_name: The function name from the LLM tool_call.
            arguments_json: The raw JSON arguments string.

        Returns:
            Formatted result string to feed back to the LLM.
        """
        try:
            args = json.loads(arguments_json) if arguments_json else {}
        except json.JSONDecodeError as e:
            return f"参数解析失败: {e}"

        handler = {
            "run_security_check": self._handle_security_check,
            "run_shell_command": self._handle_shell_command,
            "whois_lookup": self._handle_whois_lookup,
        }.get(tool_name)

        if handler is None:
            return f"未知工具: {tool_name}"

        try:
            return await handler(args)
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

    async def _handle_shell_command(self, args: dict[str, Any]) -> str:
        """Execute an AI-generated shell command."""
        command = args.get("command", "")
        reason = args.get("reason", "")

        result = await self.sandbox.execute_shell_command(command, reason)
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
