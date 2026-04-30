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

        # New approval flow:
        # - Do static-only precheck first (no LLM call here)
        # - Show minimal approval prompt
        # - Run full LLM analysis only when user asks for details
        analysis = await self.analyze_command_for_approval(
            command=command,
            reason=reason,
            chat_id=chat_id,
            tool_call_id=tool_call_id,
            include_llm=False,
        )
        static_is_safe = bool(analysis.get("static_is_safe", False))
        static_critical = bool(analysis.get("static_critical", False))
        mutation_detected = bool(analysis.get("mutation_detected", False))
        deletion_detected = bool(analysis.get("deletion_detected", False))
        safety_status = str(analysis.get("safety_status", "UNSAFE"))
        risk_level = str(analysis.get("risk_level", "HIGH"))
        impact_summary = self._build_initial_impact_summary(analysis)

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
            reviewer_mode="deferred",
            static_is_safe=static_is_safe,
            static_reason=analysis.get("static_reason", ""),
            static_write_detected=bool(analysis.get("static_write_detected", False)),
            static_critical=static_critical,
            unrestricted_mode=self.sandbox.allow_unrestricted_commands,
        )

        if self.sandbox.allow_unrestricted_commands:
            can_auto_execute = (
                static_is_safe
                and not static_critical
                and not mutation_detected
                and not deletion_detected
            )
            if can_auto_execute:
                result = await self.sandbox.execute_shell_command(
                    command,
                    reason,
                    chat_id=chat_id,
                    tool_call_id=tool_call_id,
                )
                return self._format_command_result(result)
            pending_mode = "unrestricted_guardrail"
        else:
            pending_mode = "restricted_default"

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
            mode=pending_mode,
        )
        raise PendingApprovalError(
            command=command,
            safety_status=safety_status,
            impact_analysis=impact_summary,
            tool_call_id=tool_call_id,
            reason=reason,
            risk_level=risk_level,
            mutation_detected=mutation_detected,
            deletion_detected=deletion_detected,
        )

    async def get_command_approval_details(
        self,
        command: str,
        reason: str,
        chat_id: int = 0,
        tool_call_id: str = "",
        include_llm: bool = True,
    ) -> dict[str, Any]:
        """Return full approval details, including optional LLM analysis."""
        analysis = await self.analyze_command_for_approval(
            command=command,
            reason=reason,
            chat_id=chat_id,
            tool_call_id=tool_call_id,
            include_llm=include_llm,
        )
        CommandAuditTracker.record_event(
            "command_detail_requested",
            chat_id=chat_id,
            tool_call_id=tool_call_id,
            command=command,
            reason=reason,
            safety_status=analysis.get("safety_status"),
            risk_level=analysis.get("risk_level"),
            mutation_detected=analysis.get("mutation_detected"),
            deletion_detected=analysis.get("deletion_detected"),
            reviewer_mode=analysis.get("reviewer_mode"),
        )
        return analysis

    async def analyze_command_for_approval(
        self,
        command: str,
        reason: str,
        chat_id: int = 0,
        tool_call_id: str = "",
        include_llm: bool = False,
    ) -> dict[str, Any]:
        """Run static + optional LLM analysis for one command."""
        from chatdome.executor.validator import (
            has_write_intent,
            is_critical_command,
            validate_command,
        )

        static_check = validate_command(command, check_allowlist=False)
        static_critical = is_critical_command(command)
        static_write = has_write_intent(command)
        static_delete = self._has_delete_intent(command)

        if static_critical:
            safety_status = "CRITICAL"
            risk_level = "CRITICAL"
        elif static_write or not static_check.is_safe:
            safety_status = "UNSAFE"
            risk_level = "HIGH"
        else:
            safety_status = "SAFE"
            risk_level = "LOW"

        mutation_detected = static_write
        deletion_detected = static_delete
        impact_analysis = self._build_initial_impact_summary(
            {
                "static_is_safe": static_check.is_safe,
                "mutation_detected": mutation_detected,
                "deletion_detected": deletion_detected,
                "static_critical": static_critical,
            }
        )
        reviewer_mode = "static_only"
        reviewer_status = safety_status
        reviewer_risk_level = risk_level

        if include_llm and self.llm:
            from chatdome.agent.prompts import REVIEWER_SYSTEM_PROMPT

            logger.info("Running deferred AI reviewer for command details: %s", command)
            review = await self.llm.evaluate_command_safety(
                command,
                REVIEWER_SYSTEM_PROMPT,
                chat_id=chat_id,
            )
            reviewer_mode = "llm"
            reviewer_status = str(review.get("safety_status", "UNSAFE")).strip().upper() or "UNSAFE"
            if reviewer_status not in {"SAFE", "UNSAFE", "CRITICAL"}:
                reviewer_status = "UNSAFE"
            reviewer_risk_level = str(review.get("risk_level", "HIGH")).strip().upper() or "HIGH"
            if reviewer_risk_level not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
                reviewer_risk_level = "HIGH"
            mutation_detected = mutation_detected or bool(
                review.get("mutation_detected", reviewer_status != "SAFE")
            )
            deletion_detected = deletion_detected or bool(review.get("deletion_detected", False))
            impact_analysis = str(review.get("impact_analysis", "")).strip() or "LLM analysis unavailable."
            safety_status = reviewer_status
            risk_level = reviewer_risk_level

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
            static_signals.append("检测到写入或系统状态变更意图。")
        if not static_check.is_safe and static_check.reason:
            static_signals.append(str(static_check.reason))
        if static_critical:
            static_signals.append("命中高危命令模式。")
        if static_delete:
            static_signals.append("检测到删除或破坏性意图。")
        if static_signals:
            impact_analysis = (
                f"{impact_analysis}\n\n[静态护栏信号]\n- "
                + "\n- ".join(static_signals)
            )

        return {
            "safety_status": safety_status,
            "risk_level": risk_level,
            "mutation_detected": mutation_detected,
            "deletion_detected": deletion_detected,
            "impact_analysis": impact_analysis,
            "reviewer_mode": reviewer_mode,
            "reviewer_status": reviewer_status,
            "reviewer_risk_level": reviewer_risk_level,
            "static_is_safe": static_check.is_safe,
            "static_reason": static_check.reason,
            "static_write_detected": static_write,
            "static_critical": static_critical,
        }

    @staticmethod
    def _has_delete_intent(command: str) -> bool:
        """Lightweight lexical detector for delete/destructive intent."""
        text = f" {str(command or '').lower()} "
        tokens = (" rm ", " rmdir ", " del ", " unlink ", " shred ", " wipe ")
        return any(tok in text for tok in tokens)

    @staticmethod
    def _build_initial_impact_summary(analysis: dict[str, Any]) -> str:
        """Build a short, command-free impact summary for the first approval card."""
        if bool(analysis.get("static_critical", False)):
            return "静态预检命中高危命令模式，可能造成不可逆或高破坏性影响。"
        if bool(analysis.get("deletion_detected", False)):
            return "检测到删除或清理意图，可能导致数据丢失，需要谨慎确认。"
        if bool(analysis.get("mutation_detected", False)):
            return "检测到写入或状态变更意图，执行后可能修改系统文件、配置或服务状态。"
        if not bool(analysis.get("static_is_safe", False)):
            return "未通过只读命令静态校验，需要人工确认后再执行。"
        return "静态预检显示偏只读查询，预计不修改系统状态；仍建议确认执行目的。"

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
