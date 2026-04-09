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
        self.tool_dispatcher = ToolDispatcher(sandbox)
        self.session_manager = SessionManager(
            session_timeout=config.session_timeout,
            max_history_tokens=config.max_history_tokens,
            system_prompt=SYSTEM_PROMPT,
        )

    async def handle_message(self, chat_id: int, user_message: str) -> str:
        """
        Process a user message through the full ReAct loop.

        Args:
            chat_id: Telegram chat ID (used as session key).
            user_message: The user's text message.

        Returns:
            The final text response to send back to the user.
        """
        session = self.session_manager.get_or_create(chat_id)
        session.add_user_message(user_message)

        # Trim history if needed
        session.trim_history(self.config.max_history_tokens)

        for round_num in range(1, self.config.max_rounds_per_turn + 1):
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
                for tc in response.tool_calls:
                    logger.info(
                        "Executing tool: %s (id=%s)", tc.name, tc.id,
                    )
                    result = await self.tool_dispatcher.dispatch(
                        tc.name, tc.arguments,
                    )
                    session.add_tool_result(tc.id, result)
                    logger.debug("Tool result for %s: %s", tc.id, result[:200])

                # Continue the loop — send results back to LLM
                continue

            else:
                # No tool calls — this is the final response
                final_content = response.content or "（AI 未返回有效回复）"
                session.add_assistant_message(final_content)
                logger.info(
                    "Agent completed for chat_id=%d in %d rounds",
                    chat_id, round_num,
                )
                return final_content

        # Exceeded max rounds
        max_rounds_msg = (
            f"⚠️ 已达到最大执行轮次 ({self.config.max_rounds_per_turn})，"
            "请尝试缩小问题范围或重新描述你的需求。"
        )
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
