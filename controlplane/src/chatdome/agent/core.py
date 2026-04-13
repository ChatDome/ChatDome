"""
AI Agent core — ReAct loop implementation.

Orchestrates the cycle:
  User message → LLM → tool_calls → execute → feed results → LLM → ... → final reply
"""

from __future__ import annotations

import logging
from typing import Any

from chatdome.agent.prompts import SYSTEM_PROMPT, TOOLS
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
    ):
        self.llm = llm
        self.config = config
        self.tool_dispatcher = ToolDispatcher(sandbox, llm=llm)
        self.session_manager = SessionManager(
            session_timeout=config.session_timeout,
            max_history_tokens=config.max_history_tokens,
            system_prompt=SYSTEM_PROMPT,
        )

    async def handle_message(self, chat_id: int, user_message: str) -> str:
        """Process a user message through the full ReAct loop."""
        session = self.session_manager.get_or_create(chat_id)
        
        # If there is a pending request, we cannot accept a new message
        if session.pending_approval:
            return "⚠️ 上一个命令仍在等待你的确认，请先处理（使用键盘或 /confirm）。"
            
        session.add_user_message(user_message)

        # Trim or compress history if needed using the Local Memory Vault
        await session.summarize_and_trim_history(self.llm, self.config.max_history_tokens)

        return await self._run_loop(chat_id, session)

    async def resume_session(self, chat_id: int, action: str) -> str:
        """Resume a suspended session after user approval/rejection."""
        session = self.session_manager.get_or_create(chat_id)
        if not session.pending_approval or not session.pending_tool_call_id:
            return "ℹ️ 当前没有等待确认的命令。"
            
        tool_call_id = session.pending_tool_call_id
        command = session.pending_command
        
        # Clear pending state
        session.pending_approval = False
        session.pending_tool_call_id = None
        session.pending_command = None
        
        if action == "REJECT":
            logger.info("User rejected command: %s", command)
            session.add_tool_result(tool_call_id, "由于存在安全风险，用户已拒绝执行该命令。请提供其他解决方案或向用户解释。")
        else:
            logger.info("User approved command: %s", command)
            try:
                # Bypass Reviewer, go straight to sandbox
                res = await self.tool_dispatcher.sandbox.execute_shell_command(command, "User Approved")
                result = self.tool_dispatcher._format_command_result(res)
            except Exception as e:
                result = f"执行过程中发生异常: {e}"
                
            session.add_tool_result(tool_call_id, result)
            
        return await self._run_loop(chat_id, session)

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
                    tools=TOOLS,
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

                # Execute each tool call
                from chatdome.agent.tools import PendingApprovalError
                import json
                
                for tc in response.tool_calls:
                    logger.info("Executing tool: %s (id=%s)", tc.name, tc.id)
                    try:
                        result = await self.tool_dispatcher.dispatch(tc.name, tc.arguments, tc.id, chat_id)
                        session.add_tool_result(tc.id, result)
                        logger.debug("Tool result for %s: %s", tc.id, result[:200])
                    except PendingApprovalError as e:
                        logger.info("Execution suspended for user approval: %s", tc.id)
                        session.pending_approval = True
                        session.pending_tool_call_id = e.tool_call_id
                        session.pending_command = e.command
                        return f"__PENDING_APPROVAL__:{json.dumps({'command': e.command, 'safety_status': e.safety_status, 'impact_analysis': e.impact_analysis})}"

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
