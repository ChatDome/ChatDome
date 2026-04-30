"""
AI Agent core — ReAct loop implementation.

Orchestrates the cycle:
  User message → LLM → tool_calls → execute → feed results → LLM → ... → final reply
"""

from __future__ import annotations

import logging
import secrets
import time
from typing import Any

from chatdome.agent.audit import CommandAuditTracker
from chatdome.agent.prompts import build_system_prompt, build_tools
from chatdome.agent.session import SessionManager
from chatdome.agent.tools import ToolDispatcher
from chatdome.config import AgentConfig
from chatdome.executor.sandbox import CommandSandbox
from chatdome.llm.client import LLMClient

logger = logging.getLogger(__name__)


class Agent:
    """
    The AI Agent that drives the ReAct loop.

    Receives user messages, manages sessions, calls the LLM,
    dispatches tool calls, and produces final responses.
    """

    def __init__(
        self,
        llm: LLMClient,
        sandbox: CommandSandbox,
        config: AgentConfig,
        runtime_environment_context: str = "",
        pack_loader: Any = None,
        user_context_ledger: Any = None,
        valid_check_ids: list[str] | None = None,
    ):
        self.llm = llm
        self.config = config
        self.tools = build_tools(
            allow_unrestricted_commands=config.allow_unrestricted_commands,
            pack_loader=pack_loader,
            valid_check_ids=valid_check_ids,
        )
        self.tool_dispatcher = ToolDispatcher(sandbox, llm=llm, user_context_ledger=user_context_ledger)
        self.session_manager = SessionManager(
            session_timeout=config.session_timeout,
            pending_approval_timeout=config.pending_approval_timeout,
            persisted_session_ttl=config.persisted_session_ttl,
            max_history_tokens=config.max_history_tokens,
            system_prompt=build_system_prompt(
                allow_unrestricted_commands=config.allow_unrestricted_commands,
                runtime_environment_context=runtime_environment_context,
                pack_loader=pack_loader,
            ),
        )

    def _persist_session(self, session: Any) -> None:
        """Best-effort persistence for session durability."""
        try:
            self.session_manager.save_session(session)
        except Exception as e:
            logger.warning("Session persistence failed for chat_id=%s: %s", getattr(session, "chat_id", "?"), e)

    @staticmethod
    def _new_approval_id() -> str:
        """Generate a short user-facing approval identifier."""
        return f"AP-{time.strftime('%Y%m%d-%H%M%S', time.localtime())}-{secrets.token_hex(3).upper()}"

    @staticmethod
    def _new_run_id(chat_id: int) -> str:
        """Generate a lightweight run id for binding the pending approval."""
        return f"RUN-{chat_id}-{time.strftime('%Y%m%d-%H%M%S', time.localtime())}-{secrets.token_hex(3).upper()}"

    @staticmethod
    def _command_hash(command: str | None) -> str:
        """Stable command digest used to bind approval to exactly one command."""
        normalized = (command or "").strip()
        return CommandAuditTracker.sha256_text(normalized)

    async def handle_message(self, chat_id: int, user_message: str) -> str:
        """Process a user message through the full ReAct loop."""
        session = self.session_manager.get_or_create(chat_id)

        if session.pending_approval:
            # Allow natural-language rejection while waiting approval.
            if self._is_reject_intent(user_message):
                session.add_pending_followup("user", user_message)
                self._persist_session(session)
                _, final_answer = await self.resume_session(chat_id, "REJECT")
                return final_answer
            return await self._handle_pending_followup(chat_id, session, user_message)

        if session.pending_round_limit:
            if self._is_reject_intent(user_message):
                return await self.resolve_round_limit(chat_id, "ABANDON")
            if self._is_continue_intent(user_message):
                return await self.resolve_round_limit(chat_id, "CONTINUE")
            return (
                f"\u5f53\u524d\u4efb\u52a1\u5df2\u6267\u884c {session.pending_round_count} \u8f6e\uff0c\u4ecd\u672a\u5b8c\u6210\u3002\n"
                "\u8bf7\u56de\u590d\u2018\u7ee7\u7eed\u2019\u4ee5\u518d\u6267\u884c 10 \u8f6e\uff0c\u6216\u56de\u590d\u2018\u653e\u5f03\u2019\u7ed3\u675f\u5f53\u524d\u4efb\u52a1\u3002"
            )

        session.add_user_message(user_message)

        # Trim or compress history if needed using the Local Memory Vault
        await session.summarize_and_trim_history(self.llm, self.config.max_history_tokens)
        self._persist_session(session)

        return await self._run_loop(chat_id, session)

    async def resolve_round_limit(self, chat_id: int, action: str) -> str:
        """Resolve a round-limit confirmation by continuing or abandoning the task."""
        session = self.session_manager.get_or_create(chat_id)
        if not session.pending_round_limit:
            return "\u2139\ufe0f \u5f53\u524d\u6ca1\u6709\u7b49\u5f85\u7ee7\u7eed\u6267\u884c\u7684\u4efb\u52a1\u3002"

        normalized_action = (action or "").strip().upper()
        if normalized_action == "CONTINUE":
            reached = session.pending_round_count
            session.clear_pending_round_limit()
            self._persist_session(session)
            logger.info("User chose to continue task after %d rounds (chat_id=%d)", reached, chat_id)
            return await self._run_loop(chat_id, session)

        reached = session.pending_round_count
        session.task_auto_approve = False
        session.clear_pending_round_limit()
        final_text = f"\u5df2\u653e\u5f03\u5f53\u524d\u4efb\u52a1\uff08\u7d2f\u8ba1\u6267\u884c {reached} \u8f6e\uff09\u3002\u5982\u9700\u7ee7\u7eed\uff0c\u8bf7\u53d1\u9001\u65b0\u7684\u6307\u4ee4\u3002"
        session.add_assistant_message(final_text)
        self._persist_session(session)
        logger.info("User abandoned task after %d rounds (chat_id=%d)", reached, chat_id)
        return final_text

    async def resume_session(
        self,
        chat_id: int,
        action: str,
        approval_id: str | None = None,
    ) -> tuple[str, str]:
        """Resume a suspended session after user approval/rejection. Returns (raw_result, llm_response)."""
        session = self.session_manager.get_or_create(chat_id)
        if not session.pending_approval or not session.pending_tool_call_id:
            return "", "ℹ️ 当前没有等待确认的命令。"

        tool_call_id = session.pending_tool_call_id
        command = session.pending_command or ""
        pending_approval_id = session.pending_approval_id or ""
        pending_run_id = session.pending_run_id or ""
        pending_command_hash = session.pending_command_hash or self._command_hash(command)
        requested_approval_id = (approval_id or "").strip()

        if requested_approval_id and pending_approval_id and requested_approval_id != pending_approval_id:
            return (
                "",
                (
                    "⚠️ 审批编号不匹配，未执行任何命令。\n\n"
                    f"当前待审批编号: {pending_approval_id}\n"
                    f"收到的审批编号: {requested_approval_id}"
                ),
            )

        normalized_action = (action or "").strip().upper()
        if normalized_action not in {"APPROVE", "APPROVE_TASK", "REJECT"}:
            normalized_action = "REJECT"
        followup_summary = self._summarize_pending_followups(session)
        if normalized_action == "APPROVE_TASK":
            session.task_auto_approve = True

        current_command_hash = self._command_hash(command)
        if normalized_action in {"APPROVE", "APPROVE_TASK"} and pending_command_hash != current_command_hash:
            logger.warning(
                "Pending approval command hash mismatch: approval_id=%s expected=%s actual=%s",
                pending_approval_id,
                pending_command_hash,
                current_command_hash,
            )
            CommandAuditTracker.record_event(
                "command_approval_hash_mismatch",
                chat_id=chat_id,
                approval_id=pending_approval_id,
                run_id=pending_run_id,
                tool_call_id=tool_call_id,
                command=command,
                expected_command_hash=pending_command_hash,
                actual_command_hash=current_command_hash,
                approval_action=normalized_action,
            )
            session.task_auto_approve = False
            session.clear_pending_state()
            tool_result_for_llm = (
                "审批恢复失败：待执行命令的哈希与审批单不一致。"
                "系统已按 fail-safe 策略拒绝执行该命令。"
            )
            session.add_tool_result(tool_call_id, tool_result_for_llm)
            self._persist_session(session)
            final_answer = await self._run_loop(chat_id, session)
            return "命令校验失败，已拒绝执行。", final_answer

        # Clear pending state before continuing the normal loop.
        session.clear_pending_state()
        self._persist_session(session)

        if normalized_action == "REJECT":
            session.task_auto_approve = False
            logger.info("User rejected command: %s", command)
            CommandAuditTracker.record_event(
                "command_rejected",
                chat_id=chat_id,
                approval_id=pending_approval_id,
                run_id=pending_run_id,
                tool_call_id=tool_call_id,
                command=command,
                command_hash=pending_command_hash,
                approval_action="REJECT",
            )
            tool_result_for_llm = "由于存在安全风险，用户已拒绝执行该命令。请提供其他解决方案或向用户解释。"
            if followup_summary:
                tool_result_for_llm += (
                    "\n\n[审批等待阶段的补充对话]\n"
                    f"{followup_summary}"
                )
            session.add_tool_result(tool_call_id, tool_result_for_llm)
            raw_result = "用户已拒绝执行该命令。"
        else:
            logger.info("User approved command: %s", command)
            CommandAuditTracker.record_event(
                "command_approved",
                chat_id=chat_id,
                approval_id=pending_approval_id,
                run_id=pending_run_id,
                tool_call_id=tool_call_id,
                command=command,
                command_hash=pending_command_hash,
                approval_action=normalized_action,
            )
            try:
                # Bypass Reviewer, go straight to sandbox
                res = await self.tool_dispatcher.sandbox.execute_shell_command(
                    command,
                    "User Approved",
                    chat_id=chat_id,
                    tool_call_id=tool_call_id,
                )
                raw_result = self.tool_dispatcher._format_command_result(res)
            except Exception as e:
                raw_result = f"执行过程中发生异常: {e}"

            tool_result_for_llm = raw_result
            if followup_summary:
                tool_result_for_llm += (
                    "\n\n[审批等待阶段的补充对话]\n"
                    f"{followup_summary}"
                )
            session.add_tool_result(tool_call_id, tool_result_for_llm)
        self._persist_session(session)

        final_answer = await self._run_loop(chat_id, session)
        return raw_result, final_answer

    async def get_pending_approval_details(
        self,
        chat_id: int,
        approval_id: str | None = None,
        include_llm: bool = True,
    ) -> dict[str, Any]:
        """
        Return full details for the currently pending approval.

        Safety analysis is computed lazily and cached in session state.
        """
        session = self.session_manager.get_or_create(chat_id)
        if not session.pending_approval or not session.pending_command:
            return {
                "ok": False,
                "message": "No pending command requires approval.",
            }

        requested_approval_id = (approval_id or "").strip()
        current_approval_id = session.pending_approval_id or ""
        if requested_approval_id and current_approval_id and requested_approval_id != current_approval_id:
            return {
                "ok": False,
                "message": (
                    "Approval ID mismatch. "
                    f"Current pending approval is {current_approval_id}, not {requested_approval_id}."
                ),
            }

        cached_analysis = session.pending_analysis if isinstance(session.pending_analysis, dict) else None
        cached_reviewer_mode = str((cached_analysis or {}).get("reviewer_mode", ""))
        needs_analysis = cached_analysis is None or (include_llm and cached_reviewer_mode != "llm")

        if needs_analysis:
            pending_approval_id = session.pending_approval_id or ""
            pending_command = session.pending_command or ""
            pending_command_hash = session.pending_command_hash or self._command_hash(pending_command)
            pending_reason = session.pending_reason or ""
            pending_tool_call_id = session.pending_tool_call_id or ""

            analysis = await self.tool_dispatcher.get_command_approval_details(
                command=pending_command,
                reason=pending_reason,
                chat_id=chat_id,
                tool_call_id=pending_tool_call_id,
                include_llm=include_llm,
            )

            current_command = session.pending_command or ""
            current_command_hash = session.pending_command_hash or self._command_hash(current_command)
            if (
                not session.pending_approval
                or (pending_approval_id and session.pending_approval_id != pending_approval_id)
                or current_command_hash != pending_command_hash
            ):
                return {
                    "ok": False,
                    "message": "Approval is no longer pending or has changed.",
                }

            session.pending_analysis = analysis
            self._persist_session(session)

        return {
            "ok": True,
            "approval_id": session.pending_approval_id or "",
            "run_id": session.pending_run_id or "",
            "command": session.pending_command,
            "command_hash": session.pending_command_hash or self._command_hash(session.pending_command or ""),
            "reason": session.pending_reason or "",
            "risk_level": session.pending_risk_level or "",
            "analysis": session.pending_analysis,
        }

    @staticmethod
    def _is_reject_intent(user_message: str) -> bool:
        """Heuristic for natural-language reject/cancel intent."""
        text = (user_message or "").strip().lower()
        if not text:
            return False

        reject_keywords = (
            "拒绝", "取消", "不执行", "不要执行", "别执行", "算了", "停止", "终止",
            "reject", "deny", "cancel", "abort", "stop",
        )
        return any(k in text for k in reject_keywords)

    @staticmethod
    def _is_continue_intent(user_message: str) -> bool:
        """Heuristic for continue intent when a task hits round limit."""
        text = (user_message or "").strip().lower()
        if not text:
            return False

        continue_keywords = (
            "\u7ee7\u7eed", "\u7ee7\u7eed\u6267\u884c", "\u7ee7\u7eed\u4efb\u52a1", "\u63a5\u7740\u8dd1", "\u7ee7\u7eed\u8dd1",
            "continue", "go on", "proceed",
        )
        return any(k in text for k in continue_keywords)

    @staticmethod
    def _summarize_pending_followups(session: Any, max_chars: int = 1500) -> str:
        """Build a compact transcript of follow-up chat during pending approval."""
        if not session.pending_followups:
            return ""

        lines: list[str] = []
        for item in session.pending_followups:
            role = item.get("role", "")
            content = str(item.get("content", "")).strip()
            if not content:
                continue
            if Agent._looks_like_tool_call_text(content):
                continue
            prefix = "用户" if role == "user" else "助手"
            lines.append(f"{prefix}: {content}")

        summary = "\n".join(lines)
        if len(summary) > max_chars:
            summary = summary[:max_chars] + "\n...(已截断)"
        return summary

    @staticmethod
    def _looks_like_tool_call_text(content: str) -> bool:
        """Detect pseudo tool-call text that should never enter side-thread memory."""
        text = (content or "").strip().lower()
        if not text:
            return False
        markers = (
            "<tool_call",
            "</tool_call>",
            "<function=",
            "</function>",
            "<parameter=",
            "</parameter>",
        )
        return any(marker in text for marker in markers)

    @staticmethod
    def _is_new_execution_request_while_pending(user_message: str) -> bool:
        """Detect requests that would require starting another command while one is pending."""
        text = (user_message or "").strip().lower()
        if not text:
            return False

        explanation_keywords = (
            "为什么", "原因", "风险", "危险", "安全吗", "安全么", "影响", "会做什么",
            "什么意思", "解释", "详细", "命令内容", "这个命令", "这条命令", "替代方案",
            "why", "risk", "safe", "explain", "detail", "details", "alternative",
        )
        if any(keyword in text for keyword in explanation_keywords):
            return False

        execution_keywords = (
            "查询", "查看", "检查", "执行", "运行", "跑一下", "看一下", "看下",
            "多少", "有没有", "是否", "列出", "统计", "状态", "封禁", "拉取",
            "show", "list", "check", "status", "run", "execute", "how many",
        )
        return any(keyword in text for keyword in execution_keywords)

    @staticmethod
    def _pending_command_waiting_message(command: str, approval_id: str | None = None) -> str:
        """Deterministic response for new requests while a command waits for approval."""
        approval_line = f"审批编号: `{approval_id}`\n" if approval_id else ""
        return (
            "当前已有一条命令等待确认。你可以继续问不需要执行命令的问题；"
            "但涉及实时主机状态的新查询，需要先处理这条待确认命令。\n\n"
            f"{approval_line}"
            f"待确认命令: `{command or '(unknown)'}`\n\n"
            "如果你想得到这条命令的结果，请点击“允许”或发送 `/confirm <审批编号>`；"
            "如果不想执行，请点击“拒绝”或发送 `/reject <审批编号>`。"
        )

    @classmethod
    def _prune_pending_followups(cls, session: Any) -> None:
        """Drop malformed side-thread entries, including old persisted pseudo tool calls."""
        cleaned: list[dict[str, str]] = []
        for item in getattr(session, "pending_followups", []) or []:
            role = item.get("role")
            content = str(item.get("content", "")).strip()
            if role not in {"user", "assistant"} or not content:
                continue
            if cls._looks_like_tool_call_text(content):
                continue
            cleaned.append({"role": role, "content": content})
        session.pending_followups = cleaned[-12:]

    async def _handle_pending_followup(self, chat_id: int, session: Any, user_message: str) -> str:
        """
        Handle user follow-up while a risky command is pending approval.

        Keep these follow-ups out of the main message chain to avoid breaking
        tool_call -> tool_result ordering required by the LLM API.
        """
        self._prune_pending_followups(session)
        pending_cmd = session.pending_command or "(unknown)"
        pending_approval_id = session.pending_approval_id or ""
        pending_reason = session.pending_reason or ""

        if self._is_new_execution_request_while_pending(user_message):
            session.last_active = time.time()
            self._persist_session(session)
            return self._pending_command_waiting_message(pending_cmd, pending_approval_id)

        session.add_pending_followup("user", user_message)
        self._persist_session(session)

        followup_messages = [
            {"role": item["role"], "content": item["content"]}
            for item in session.pending_followups
            if item.get("role") in {"user", "assistant"} and item.get("content")
        ]

        approval_context = (
            "现在有一条命令正在等待人工确认，尚未执行。\n"
            f"待确认命令: {pending_cmd}\n"
            f"申请理由: {pending_reason or '未提供'}\n\n"
            "你只能解释这条待确认命令的目的、风险、影响和替代方案。"
            "不要调用工具，不要输出 tool_call/XML/函数调用，不要声称已经执行命令。"
            "如果用户要求查询新的系统状态或执行新任务，请说明必须先允许或拒绝当前待确认命令。"
            "最后提醒用户：发送 /confirm 执行，或回复“拒绝/取消”来拒绝。"
        )

        ephemeral_messages = [{"role": "system", "content": approval_context}] + followup_messages

        try:
            response = await self.llm.chat_completion(
                messages=ephemeral_messages,
                tools=None,
            )
            content = response.content or "我已记录你的问题。该命令还在等待确认，我可以继续解释风险与替代方案。"
            if response.tool_calls or self._looks_like_tool_call_text(content):
                logger.warning("LLM returned tool-like content during pending approval follow-up")
                content = self._pending_command_waiting_message(pending_cmd, pending_approval_id)

            from chatdome.agent.tracker import TokenTracker
            TokenTracker.record_usage(
                chat_id=chat_id,
                model=self.config.model if hasattr(self.config, "model") else self.llm.model,
                action="pending_followup",
                prompt_tokens=response.prompt_tokens,
                completion_tokens=response.completion_tokens,
                total_tokens=response.total_tokens,
            )
        except Exception as e:
            logger.error("Pending follow-up handling failed: %s", e)
            content = (
                "我收到你的追问了，但这条命令还在审批等待中。"
                "你可以继续问风险和替代方案；若决定执行请发 /confirm，若放弃请回复“拒绝执行”。"
            )

        if not self._looks_like_tool_call_text(content):
            session.add_pending_followup("assistant", content)
        self._persist_session(session)
        return content

    async def _run_loop(self, chat_id: int, session: Any) -> str:
        """Drive the ReAct loop forward."""

        start_round = session.round_count
        window_limit = max(1, int(self.config.max_rounds_per_turn))
        end_round_exclusive = start_round + window_limit + 1
        for round_num in range(start_round + 1, end_round_exclusive):
            logger.info(
                "Agent loop round %d/%d for chat_id=%d",
                round_num, start_round + window_limit, chat_id,
            )

            try:
                response = await self.llm.chat_completion(
                    messages=session.messages,
                    tools=self.tools,
                )
            except Exception as e:
                error_msg = f"LLM 调用失败: {e}"
                logger.error(error_msg)
                return f"⚠️ {error_msg}"

            logger.debug(
                "LLM response: content=%s, tool_calls=%d, tokens=%d",
                bool(response.content),
                len(response.tool_calls),
                response.total_tokens,
            )
            
            from chatdome.agent.tracker import TokenTracker
            TokenTracker.record_usage(
                chat_id=chat_id,
                model=self.config.model if hasattr(self.config, 'model') else self.llm.model,
                action="react_loop",
                prompt_tokens=response.prompt_tokens,
                completion_tokens=response.completion_tokens,
                total_tokens=response.total_tokens
            )

            if response.tool_calls:
                # Build the assistant message with tool_calls for the session
                tool_calls_for_session = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.name,
                            "arguments": tc.arguments,
                        },
                    }
                    for tc in response.tool_calls
                ]
                session.add_assistant_tool_calls(tool_calls_for_session)
                self._persist_session(session)

                # Execute each tool call
                from chatdome.agent.tools import PendingApprovalError
                import json
                
                for tc in response.tool_calls:
                    logger.info("Executing tool: %s (id=%s)", tc.name, tc.id)
                    try:
                        result = await self.tool_dispatcher.dispatch(tc.name, tc.arguments, tc.id, chat_id)
                        session.add_tool_result(tc.id, result)
                        self._persist_session(session)
                        logger.debug("Tool result for %s: %s", tc.id, result[:200])
                    except PendingApprovalError as e:
                        if session.task_auto_approve and e.command:
                            logger.info("Task-scope auto-approval applied for command: %s", e.command)
                            CommandAuditTracker.record_event(
                                "command_auto_approved_task_scope",
                                chat_id=chat_id,
                                tool_call_id=tc.id,
                                command=e.command,
                            )
                            try:
                                res = await self.tool_dispatcher.sandbox.execute_shell_command(
                                    e.command,
                                    "Task Scope Approved",
                                    chat_id=chat_id,
                                    tool_call_id=tc.id,
                                )
                                session.add_tool_result(tc.id, self.tool_dispatcher._format_command_result(res))
                            except Exception as ex:
                                session.add_tool_result(tc.id, f"Command execution failed: {ex}")
                            self._persist_session(session)
                            continue

                        logger.info("Execution suspended for user approval: %s", tc.id)
                        approval_id = self._new_approval_id()
                        run_id = self._new_run_id(chat_id)
                        command_hash = self._command_hash(e.command)
                        session.pending_approval = True
                        session.pending_approval_id = approval_id
                        session.pending_run_id = run_id
                        session.pending_tool_call_id = e.tool_call_id
                        session.pending_command = e.command
                        session.pending_command_hash = command_hash
                        session.pending_reason = getattr(e, "reason", "")
                        session.pending_risk_level = getattr(e, "risk_level", "")
                        session.pending_analysis = None
                        session.pending_since = time.time()
                        session.pending_followups.clear()
                        CommandAuditTracker.record_event(
                            "command_approval_created",
                            chat_id=chat_id,
                            approval_id=approval_id,
                            run_id=run_id,
                            tool_call_id=e.tool_call_id,
                            command=e.command,
                            command_hash=command_hash,
                            reason=getattr(e, "reason", ""),
                            risk_level=getattr(e, "risk_level", ""),
                            impact_analysis=getattr(e, "impact_analysis", ""),
                        )
                        payload = {
                            "approval_id": approval_id,
                            "run_id": run_id,
                            "command": e.command,
                            "command_hash": command_hash,
                            "reason": getattr(e, 'reason', ''),
                            "risk_level": getattr(e, "risk_level", ""),
                            "impact_analysis": getattr(e, "impact_analysis", ""),
                            "requires_detail_expansion": True,
                        }
                        self._persist_session(session)
                        return f"__PENDING_APPROVAL__:{json.dumps(payload)}"

                # Continue the loop — send results back to LLM
                continue

            else:
                # No tool calls — this is the final response
                final_content = response.content or "（AI 未返回有效回复）"
                
                if session.command_echo:
                    cmds = session.get_turn_executed_commands()
                    if cmds:
                        echo_text = "\n\n---\n*🔍 Command Echo 模式*\n" + "\n".join(cmds)
                        final_content += echo_text
                        
                session.task_auto_approve = False
                session.clear_pending_round_limit()
                session.add_assistant_message(final_content)
                self._persist_session(session)
                logger.info("Agent completed for chat_id=%d in %d rounds", chat_id, round_num)
                return final_content
        # Reached one execution window; ask user whether to continue.
        reached_rounds = session.round_count
        session.pending_round_limit = True
        session.pending_round_count = reached_rounds
        session.task_auto_approve = False
        self._persist_session(session)
        logger.warning("Round limit window reached for chat_id=%d (rounds=%d)", chat_id, reached_rounds)
        return f'__ROUND_LIMIT_CONFIRM__:{json.dumps({"rounds": reached_rounds, "window": window_limit})}'

    def clear_session(self, chat_id: int) -> bool:
        """Clear a chat session. Returns True if it existed."""
        return self.session_manager.clear_session(chat_id)

    def start(self) -> None:
        """Start background tasks (session cleanup)."""
        self.session_manager.start_cleanup_task()

    async def stop(self) -> None:
        """Stop background tasks and clean up resources."""
        self.session_manager.stop_cleanup_task()
        await self.tool_dispatcher.close()
