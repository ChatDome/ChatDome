"""
Tool dispatch — routes LLM tool_calls to the appropriate executor.

Handles:
  - run_security_check → CommandSandbox.execute_security_check
  - run_shell_command  → CommandSandbox.execute_shell_command
  - whois_lookup       → HTTP call to ip-api.com
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from chatdome.agent.audit import CommandAuditTracker
from chatdome.executor.sandbox import CommandSandbox, CommandResult
from chatdome.llm.client import LLMClient

logger = logging.getLogger(__name__)


class PendingApprovalError(Exception):
    """Raised when a tool call requires user confirmation before execution."""
    def __init__(
        self,
        command: str,
        safety_status: str,
        impact_analysis: str,
        tool_call_id: str,
        reason: str = "",
        risk_level: str = "HIGH",
        mutation_detected: bool = False,
        deletion_detected: bool = False,
    ):
        self.command = command
        self.safety_status = safety_status
        self.impact_analysis = impact_analysis
        self.tool_call_id = tool_call_id
        self.reason = reason
        self.risk_level = risk_level
        self.mutation_detected = mutation_detected
        self.deletion_detected = deletion_detected
        super().__init__(f"Command requires approval: {command}")


class ToolDispatcher:
    """
    Routes tool calls from the LLM to the appropriate handler
    and formats results as strings for the conversation.
    """

    def __init__(self, sandbox: CommandSandbox, llm: Any = None, user_context_ledger: Any = None):
        self.sandbox = sandbox
        self.llm = llm
        self.user_context_ledger = user_context_ledger
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
            args = LLMClient.parse_json_object(arguments_json) if arguments_json else {}
        except Exception as e:
            logger.warning(
                "Tool argument parse failed for %s (tool_call_id=%s): %s | raw=%r",
                tool_name,
                tool_call_id,
                e,
                (arguments_json or "")[:200],
            )
            return f"参数解析失败: {e}"

        try:
            if tool_name == "run_security_check":
                return await self._handle_security_check(args, tool_call_id, chat_id)
            elif tool_name == "run_shell_command":
                return await self._handle_shell_command(args, tool_call_id, chat_id)
            elif tool_name == "whois_lookup":
                return await self._handle_whois_lookup(args)
            elif tool_name == "add_user_context":
                return await self._handle_add_user_context(args)
            else:
                return f"未知工具: {tool_name}"
        except PendingApprovalError:
            raise
        except Exception as e:
            logger.error("Tool execution failed: %s — %s", tool_name, e)
            return f"工具执行异常: {e}"

    # ----- Handlers -----

    async def _handle_security_check(
        self,
        args: dict[str, Any],
        tool_call_id: str = "",
        chat_id: int = 0,
    ) -> str:
        """Execute a pre-defined security check."""
        check_id = args.get("check_id", "")
        check_args = args.get("args")

        result = await self.sandbox.execute_security_check(
            check_id,
            check_args,
            chat_id=chat_id,
            tool_call_id=tool_call_id,
        )
        return self._format_command_result(result)

    async def _handle_shell_command(self, args: dict[str, Any], tool_call_id: str, chat_id: int = 0) -> str:
        """Evaluate and suspend an AI-generated shell command for user approval."""
        command = args.get("command", "")
        reason = args.get("reason", "无说明")
        
        if not command:
            return "缺少 command 参数"

        from chatdome.executor.validator import (
            has_write_intent,
            is_critical_command,
            validate_command,
        )

        review_status = "UNSAFE"
        review_risk_level = "HIGH"
        review_mutation = True
        review_deletion = False
        review_impact = "AI Reviewer unavailable，已按保守策略处理。"
        if self.llm:
            from chatdome.agent.prompts import REVIEWER_SYSTEM_PROMPT

            logger.info("Running AI Reviewer for shell command: %s", command)
            review = await self.llm.evaluate_command_safety(
                command,
                REVIEWER_SYSTEM_PROMPT,
                chat_id=chat_id,
            )
            review_status = str(review.get("safety_status", "UNSAFE")).strip().upper() or "UNSAFE"
            if review_status not in {"SAFE", "UNSAFE", "CRITICAL"}:
                review_status = "UNSAFE"
            review_risk_level = str(review.get("risk_level", "HIGH")).strip().upper() or "HIGH"
            if review_risk_level not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
                review_risk_level = "HIGH"
            review_mutation = bool(review.get("mutation_detected", review_status != "SAFE"))
            review_deletion = bool(review.get("deletion_detected", False))
            review_impact = str(review.get("impact_analysis", "")).strip() or "分析失败"

        static_check = validate_command(command, check_allowlist=False)
        static_critical = is_critical_command(command)
        static_write = has_write_intent(command)

        mutation_detected = review_mutation or static_write
        deletion_detected = review_deletion or ("删除" in (static_check.reason or ""))
        safety_status = review_status
        risk_level = review_risk_level

        # LLM-first decision with static fail-safe escalation.
        if mutation_detected and safety_status == "SAFE":
            safety_status = "UNSAFE"
        if deletion_detected and risk_level in {"LOW", "MEDIUM"}:
            risk_level = "HIGH"
        if static_critical:
            safety_status = "CRITICAL"
            risk_level = "CRITICAL"
        elif risk_level == "CRITICAL":
            safety_status = "CRITICAL"

        static_signals: list[str] = []
        if static_write:
            static_signals.append("检测到写入/状态变更意图")
        if not static_check.is_safe and static_check.reason:
            static_signals.append(static_check.reason)
        if static_critical:
            static_signals.append("命令匹配极端高危模式")

        impact_analysis = review_impact
        if static_signals:
            impact_analysis = f"{review_impact}\n\n[静态护栏信号]\n- " + "\n- ".join(static_signals)

        CommandAuditTracker.record_event(
            "command_reviewed",
            chat_id=chat_id,
            tool_call_id=tool_call_id,
            command=command,
            reason=reason,
            safety_status=safety_status,
            risk_level=risk_level,
            mutation_detected=mutation_detected,
            deletion_detected=deletion_detected,
            reviewer_status=review_status,
            reviewer_risk_level=review_risk_level,
            static_is_safe=static_check.is_safe,
            static_reason=static_check.reason,
            static_write_detected=static_write,
            static_critical=static_critical,
            unrestricted_mode=self.sandbox.allow_unrestricted_commands,
        )

        # Unrestricted mode auto-exec only for clearly low-risk read-only commands.
        if self.sandbox.allow_unrestricted_commands:
            can_auto_execute = (
                safety_status == "SAFE"
                and risk_level == "LOW"
                and not mutation_detected
                and not deletion_detected
                and static_check.is_safe
                and not static_critical
            )
            if can_auto_execute:
                logger.info(
                    "Unrestricted auto-execute (LLM SAFE+LOW, reason: %s): %s",
                    reason,
                    command,
                )
                result = await self.sandbox.execute_shell_command(
                    command,
                    reason,
                    chat_id=chat_id,
                    tool_call_id=tool_call_id,
                )
                return self._format_command_result(result)

            CommandAuditTracker.record_event(
                "command_pending_approval",
                chat_id=chat_id,
                tool_call_id=tool_call_id,
                command=command,
                reason=reason,
                safety_status=safety_status,
                risk_level=risk_level,
                mutation_detected=mutation_detected,
                deletion_detected=deletion_detected,
                mode="unrestricted_guardrail",
            )
            raise PendingApprovalError(
                command=command,
                safety_status=safety_status,
                impact_analysis=impact_analysis,
                tool_call_id=tool_call_id,
                reason=reason,
                risk_level=risk_level,
                mutation_detected=mutation_detected,
                deletion_detected=deletion_detected,
            )

        # Restricted mode: every generated command requires approval.
        if self.llm:
            CommandAuditTracker.record_event(
                "command_pending_approval",
                chat_id=chat_id,
                tool_call_id=tool_call_id,
                command=command,
                reason=reason,
                safety_status=safety_status,
                risk_level=risk_level,
                mutation_detected=mutation_detected,
                deletion_detected=deletion_detected,
                mode="restricted_default",
            )
            raise PendingApprovalError(
                command=command,
                safety_status=safety_status,
                impact_analysis=impact_analysis,
                tool_call_id=tool_call_id,
                reason=reason,
                risk_level=risk_level,
                mutation_detected=mutation_detected,
                deletion_detected=deletion_detected,
            )
        
        # 2. Fallback (should not be reached normally)
        result = await self.sandbox.execute_shell_command(
            command,
            "LLM Generated",
            chat_id=chat_id,
            tool_call_id=tool_call_id,
        )
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

    async def _handle_add_user_context(self, args: dict[str, Any]) -> str:
        """Handle adding user context overrides to prevent Sentinel false alarms."""
        if not self.user_context_ledger:
            return "内部错误: 暂不支持用户上下文功能，UserContextLedger 未初始化。"
        
        check_id = str(args.get("check_id", ""))
        pattern = str(args.get("pattern", ""))
        summary = str(args.get("summary", ""))

        if not check_id or not summary:
            return "参数错误: check_id 和 summary 是必填字段。"

        try:
            self.user_context_ledger.add_context(check_id, pattern, summary)
            return f"成功: 已将用户上下文 (check_id={check_id}, pattern='{pattern}') 写入 ledger，后续匹配时将自动静默。\n摘要: {summary}"
        except Exception as e:
            return f"写入用户上下文失败: {e}"

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
