from __future__ import annotations

import asyncio
from types import SimpleNamespace

from chatdome.agent.core import Agent
from chatdome.agent.session import AgentSession
from chatdome.agent.turns import create_turn_context
from chatdome.llm.client import LLMResponse


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


def test_short_turn_reaches_llm_with_current_turn_boundary():
    session = AgentSession(chat_id=1, messages=[
        {"role": "system", "content": "system"},
        {"role": "user", "content": "查看升级日志"},
        {"role": "assistant", "content": "准备查询日志"},
    ])
    llm = _LLM(LLMResponse(content="你好。"))
    agent = _agent(session, llm)

    result = asyncio.run(agent.handle_message(1, "hello"))

    assert result.content == "你好。"
    assert len(llm.calls) == 1
    current_message = llm.calls[0]["messages"][-1]["content"]
    assert "[CHATDOME CURRENT TURN]" in current_message
    assert '"current_user_message": "hello"' in current_message
    assert session.messages[-2]["content"] == "hello"
    assert session.messages[-1]["content"] == "你好。"


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
    assert "检查当前磁盘使用率" in messages[-1]["content"]
    assert "_chatdome_turn_id" not in messages[-1]
    assert messages[1]["content"] == "查看升级日志"


def test_continuation_text_is_preserved_without_keyword_classification():
    context = create_turn_context("继续查看刚才的日志")

    session = AgentSession(chat_id=1, messages=[{"role": "system", "content": "system"}])
    session.add_user_message(context.raw_message, turn_id=context.turn_id)
    messages = session.build_llm_messages(context)

    assert '"current_user_message": "继续查看刚才的日志"' in messages[-1]["content"]
    assert "explicit_history_continuation" not in messages[-1]["content"]


def test_actionable_turn_reaches_llm_with_boundary():
    session = AgentSession(chat_id=1, messages=[{"role": "system", "content": "system"}])
    llm = _LLM(LLMResponse(content="磁盘状态正常"))
    agent = _agent(session, llm)

    result = asyncio.run(agent.handle_message(1, "检查当前磁盘使用率"))

    assert result.content == "磁盘状态正常"
    assert len(llm.calls) == 1
    assert "[CHATDOME CURRENT TURN]" in llm.calls[0]["messages"][-1]["content"]
