"""
AI Agent core — ReAct loop implementation.

Orchestrates the cycle:
  User message → LLM → tool_calls → execute → feed results → LLM → ... → final reply
"""

from __future__ import annotations

import logging
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

        session.add_user_message(user_message)

        # Trim or compress history if needed using the Local Memory Vault
        await session.summarize_and_trim_history(self.llm, self.config.max_history_tokens)
        self._persist_session(session)

        return await self._run_loop(chat_id, session)

    async def resume_session(self, chat_id: int, action: str) -> tuple[str, str]:
        """Resume a suspended session after user approval/rejection. Returns (raw_result, llm_response)."""
        session = self.session_manager.get_or_create(chat_id)
        if not session.pending_approval or not session.pending_tool_call_id:
            return "", "ℹ️ 当前没有等待确认的命令。"

        tool_call_id = session.pending_tool_call_id
        command = session.pending_command
        followup_summary = self._summarize_pending_followups(session)

        # Clear pending state before continuing the normal loop.
        session.clear_pending_state()
        self._persist_session(session)

        if action == "REJECT":
            logger.info("User rejected command: %s", command)
            CommandAuditTracker.record_event(
                "command_rejected",
                chat_id=chat_id,
                tool_call_id=tool_call_id,
                command=command,
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
                tool_call_id=tool_call_id,
                command=command,
                approval_action="APPROVE",
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
            prefix = "用户" if role == "user" else "助手"
            lines.append(f"{prefix}: {content}")

        summary = "\n".join(lines)
        if len(summary) > max_chars:
            summary = summary[:max_chars] + "\n...(已截断)"
        return summary

    async def _handle_pending_followup(self, chat_id: int, session: Any, user_message: str) -> str:
        """
        Handle user follow-up while a risky command is pending approval.

        Keep these follow-ups out of the main message chain to avoid breaking
        tool_call -> tool_result ordering required by the LLM API.
        """
        session.add_pending_followup("user", user_message)
        self._persist_session(session)

        pending_cmd = session.pending_command or "(unknown)"
        pending_tool_call_id = session.pending_tool_call_id or "pending_tool_call"
        followup_messages = [
            {"role": item["role"], "content": item["content"]}
            for item in session.pending_followups
            if item.get("role") in {"user", "assistant"} and item.get("content")
        ]

        guidance = (
            "你正在处理审批等待阶段的追问。现在有一条高风险命令等待人工确认。\n"
            f"待确认命令: {pending_cmd}\n"
            "要求:\n"
            "1) 回答用户关于该命令的疑问、风险、替代方案；\n"
            "2) 不要调用工具，不要声称已执行任何命令；\n"
            "3) 最后提醒：发送 /confirm 执行，或回复“拒绝/取消”来拒绝。"
        )

        # Inject an ephemeral tool result so this temporary side-thread remains
        # protocol-valid even when the main chain is paused at tool-call stage.
        ephemeral_messages = (
            session.messages
            + [{
                "role": "tool",
                "tool_call_id": pending_tool_call_id,
                "content": "[Command execution is paused pending user confirmation. No execution yet.]",
            }]
            + [{"role": "system", "content": guidance}]
            + followup_messages
        )

        try:
            response = await self.llm.chat_completion(
                messages=ephemeral_messages,
                tools=None,
            )
            content = response.content or "我已记录你的问题。该命令还在等待确认，我可以继续解释风险与替代方案。"

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

        session.add_pending_followup("assistant", content)
        self._persist_session(session)
        return content

    async def _run_loop(self, chat_id: int, session: Any) -> str:
        """Drive the ReAct loop forward."""

        for round_num in range(session.round_count + 1, self.config.max_rounds_per_turn + 1):
            logger.info(
                "Agent loop round %d/%d for chat_id=%d",
                round_num, self.config.max_rounds_per_turn, chat_id,
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
                        logger.info("Execution suspended for user approval: %s", tc.id)
                        session.pending_approval = True
                        session.pending_tool_call_id = e.tool_call_id
                        session.pending_command = e.command
                        session.pending_since = time.time()
                        session.pending_followups.clear()
                        payload = {
                            "command": e.command, 
                            "safety_status": e.safety_status, 
                            "impact_analysis": e.impact_analysis,
                            "reason": getattr(e, 'reason', ''),
                            "risk_level": getattr(e, "risk_level", "HIGH"),
                            "mutation_detected": bool(getattr(e, "mutation_detected", False)),
                            "deletion_detected": bool(getattr(e, "deletion_detected", False)),
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
                        
                session.add_assistant_message(final_content)
                self._persist_session(session)
                logger.info("Agent completed for chat_id=%d in %d rounds", chat_id, round_num)
                return final_content

        # Exceeded max rounds
        max_rounds_msg = (
            f"⚠️ 已达到最大执行轮次 ({self.config.max_rounds_per_turn})，"
            "请尝试缩小问题范围或重新描述你的需求。"
        )
        
        if session.command_echo:
            cmds = session.get_turn_executed_commands()
            if cmds:
                echo_text = "\n\n---\n*🔍 Command Echo 模式*\n" + "\n".join(cmds)
                max_rounds_msg += echo_text
                
        session.add_assistant_message(max_rounds_msg)
        self._persist_session(session)
        logger.warning(
            "Max rounds reached for chat_id=%d", chat_id,
        )
        return max_rounds_msg

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
