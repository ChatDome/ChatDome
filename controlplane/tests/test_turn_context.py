from __future__ import annotations

import asyncio
from types import SimpleNamespace

from chatdome.agent.core import Agent
from chatdome.agent.result import AgentResult
from chatdome.agent.session import AgentSession
from chatdome.agent.turns import TurnIntent, classify_turn, create_turn_context
from chatdome.llm.client import LLMResponse, ToolCall


class _SessionManager:
    def __init__(self, session: AgentSession) -> None:
        self.session = session

    def get_or_create(self, _chat_id: int) -> AgentSession:
        return self.session

    def save_session(self, _session: AgentSession) -> None:
        return None


class _LLM:
    model = "test-model"

    def __init__(self, response: LLMResponse) -> None:
        self.response = response
        self.calls: list[dict] = []

    async def chat_completion(self, messages, tools=None):
        self.calls.append({"messages": messages, "tools": tools})
        return self.response


def _agent(session: AgentSession, llm: _LLM) -> Agent:
    agent = object.__new__(Agent)
    agent.llm = llm
    agent.llm_manager = None
    agent.config = SimpleNamespace(max_history_tokens=16000, max_rounds_per_turn=10)
    agent.tools = []
    agent.session_manager = _SessionManager(session)
    agent.tool_dispatcher = SimpleNamespace()
    return agent


def test_social_turn_is_answered_without_llm_or_tools():
    session = AgentSession(chat_id=1, messages=[
        {"role": "system", "content": "system"},
        {"role": "user", "content": "查看升级日志"},
        {"role": "assistant", "content": "准备查询日志"},
    ])
    llm = _LLM(
        LLMResponse(
            content=None,
            tool_calls=[ToolCall(id="call-1", name="run_shell_command", arguments="{}")],
        )
    )
    agent = _agent(session, llm)

    result = asyncio.run(agent.handle_message(1, "hello"))

    assert result == AgentResult.reply("你好。请发送需要处理的问题。")
    assert llm.calls == []
    assert session.messages[-2]["content"] == "hello"
    assert session.messages[-1]["content"] == "你好。请发送需要处理的问题。"


def test_llm_view_marks_current_turn_and_keeps_raw_session_message():
    session = AgentSession(chat_id=1, messages=[
        {"role": "system", "content": "system"},
        {"role": "user", "content": "查看升级日志"},
        {"role": "assistant", "content": "旧任务回答"},
    ])
    context = create_turn_context("检查当前磁盘使用率")
    session.add_user_message(context.raw_message, turn_id=context.turn_id)

    messages = session.build_llm_messages(context)

    assert session.messages[-1]["content"] == "检查当前磁盘使用率"
    assert "[CHATDOME CURRENT TURN]" in messages[-1]["content"]
    assert '"explicit_history_continuation": false' in messages[-1]["content"]
    assert "检查当前磁盘使用率" in messages[-1]["content"]
    assert "_chatdome_turn_id" not in messages[-1]
    assert messages[1]["content"] == "查看升级日志"


def test_explicit_continuation_is_marked_and_allows_tools():
    assert classify_turn("继续查看刚才的日志") is TurnIntent.CONTINUATION
    context = create_turn_context("继续查看刚才的日志")
    assert context.tools_allowed

    session = AgentSession(chat_id=1, messages=[{"role": "system", "content": "system"}])
    session.add_user_message(context.raw_message, turn_id=context.turn_id)
    messages = session.build_llm_messages(context)

    assert '"explicit_history_continuation": true' in messages[-1]["content"]


def test_actionable_turn_reaches_llm_with_boundary():
    session = AgentSession(chat_id=1, messages=[{"role": "system", "content": "system"}])
    llm = _LLM(LLMResponse(content="磁盘状态正常"))
    agent = _agent(session, llm)

    result = asyncio.run(agent.handle_message(1, "检查当前磁盘使用率"))

    assert result.content == "磁盘状态正常"
    assert len(llm.calls) == 1
    assert "[CHATDOME CURRENT TURN]" in llm.calls[0]["messages"][-1]["content"]
