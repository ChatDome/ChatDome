from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from chatdome.agent.core import Agent
from chatdome.agent import session as session_module
from chatdome.agent.session import AgentSession, SessionManager
from chatdome.llm.client import LLMResponse, ToolCall
from chatdome.logger import current_log_context


class _SessionManager:
    def __init__(self, session: AgentSession) -> None:
        self.session = session
        self.lock: asyncio.Lock | None = None

    def get_or_create(self, chat_id: int) -> AgentSession:
        self.session.chat_id = chat_id
        return self.session

    def save_session(self, session: AgentSession) -> None:
        self.session = session

    def get_turn_lock(self, _chat_id: int) -> asyncio.Lock:
        if self.lock is None:
            self.lock = asyncio.Lock()
        return self.lock


class _SequenceLLM:
    model = "test-model"

    def __init__(self, *responses: LLMResponse) -> None:
        self.responses = list(responses)
        self.calls: list[dict] = []

    async def chat_completion(self, messages, tools=None):
        self.calls.append({"messages": messages, "tools": tools})
        if not self.responses:
            raise AssertionError("unexpected LLM call")
        return self.responses.pop(0)


class _Dispatcher:
    def __init__(self) -> None:
        self.sandbox = self

    async def dispatch(self, name, arguments, tool_call_id, chat_id):
        del name, arguments, tool_call_id, chat_id
        return "tool result"

    async def execute_shell_command(self, command, reason, chat_id=0, tool_call_id=""):
        del command, reason, chat_id, tool_call_id
        return SimpleNamespace(stdout="ok", stderr="", return_code=0, timed_out=False)

    @staticmethod
    def _format_command_result(result) -> str:
        return result.stdout


def _agent(session: AgentSession, llm: _SequenceLLM, *, max_rounds: int = 10) -> Agent:
    agent = object.__new__(Agent)
    agent.llm = llm
    agent.llm_manager = None
    agent.config = SimpleNamespace(
        max_history_tokens=16000,
        max_rounds_per_turn=max_rounds,
    )
    agent.tools = []
    agent.session_manager = _SessionManager(session)
    agent.tool_dispatcher = _Dispatcher()
    return agent


def test_session_allocates_monotonic_numeric_turn_ids():
    session = AgentSession(chat_id=7)

    first = session.begin_turn("first", user_id=70)
    session.finish_turn("completed")
    second = session.begin_turn("second", user_id=70)

    assert first.turn_id == 1
    assert second.turn_id == 2
    assert session.next_turn_id == 3


def test_session_rejects_second_active_turn_without_allocating_id():
    session = AgentSession(chat_id=7)
    session.begin_turn("first", user_id=70)

    with pytest.raises(RuntimeError, match="active turn already exists"):
        session.begin_turn("second", user_id=70)

    assert session.next_turn_id == 2


def test_snapshot_restores_active_turn_and_deferred_message():
    session = AgentSession(chat_id=7)
    context = session.begin_turn("inspect nginx", user_id=70)
    session.transition_turn("waiting_approval_decision")
    session.defer_user_message("inspect disk", user_id=71)

    restored = AgentSession.from_snapshot(session.to_snapshot())

    assert restored.active_turn is not None
    assert restored.active_turn.turn_id == context.turn_id
    assert restored.active_turn.state == "waiting_approval_decision"
    assert restored.deferred_user_message == "inspect disk"
    assert restored.deferred_user_id == 71


def test_snapshot_drops_terminal_active_turn_without_reusing_its_id():
    session = AgentSession(chat_id=7)
    session.begin_turn("first", user_id=70)
    session.active_turn.state = "completed"

    restored = AgentSession.from_snapshot(session.to_snapshot())

    assert restored.active_turn is None
    assert restored.begin_turn("second", user_id=70).turn_id == 2


def test_session_manager_restart_preserves_turn_counter(tmp_path, monkeypatch):
    monkeypatch.setattr(session_module, "data_dir", lambda: tmp_path)
    first_manager = SessionManager(system_prompt="system")
    first_session = first_manager.get_or_create(7)
    first_session.begin_turn("first", user_id=70)
    first_session.finish_turn("completed")
    first_manager.save_session(first_session)

    restored_manager = SessionManager(system_prompt="system")
    restored_session = restored_manager.get_or_create(7)
    second = restored_session.begin_turn("second", user_id=70)

    assert second.turn_id == 2


def test_session_manager_marks_interrupted_running_turn_failed(tmp_path, monkeypatch):
    monkeypatch.setattr(session_module, "data_dir", lambda: tmp_path)
    first_manager = SessionManager(system_prompt="system")
    session = first_manager.get_or_create(7)
    context = session.begin_turn("first", user_id=70)
    first_manager.save_session(session)

    restored = SessionManager(system_prompt="system").get_or_create(7)

    assert restored.active_turn is None
    assert restored.events[-1]["turn_id"] == context.turn_id
    assert restored.events[-1]["outcome"] == "failed"
    assert restored.events[-1]["reason"] == "interrupted_during_restart"
    assert restored.begin_turn("second", user_id=70).turn_id == 2


def test_expired_offline_approval_cancels_turn_and_discards_deferred_message(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(session_module, "data_dir", lambda: tmp_path)
    first_manager = SessionManager(
        system_prompt="system",
        pending_approval_timeout=1,
    )
    session = first_manager.get_or_create(7)
    context = session.begin_turn("restart nginx", user_id=70)
    session.transition_turn("waiting_approval_decision")
    session.pending_approval = True
    session.pending_approval_id = "AP-1"
    session.pending_tool_call_id = "call-1"
    session.pending_command = "systemctl restart nginx"
    session.pending_command_hash = Agent._command_hash(session.pending_command)
    session.pending_since = time.time() - 10
    session.defer_user_message("inspect disk")
    first_manager.save_session(session)

    restored_manager = SessionManager(
        system_prompt="system",
        pending_approval_timeout=1,
    )
    restored = restored_manager.get_or_create(7)

    assert restored.active_turn is None
    assert not restored.pending_approval
    assert restored.deferred_user_message is None
    assert restored.events[-1]["event_type"] == "turn_completed"
    assert restored.events[-1]["turn_id"] == context.turn_id
    assert restored.events[-1]["outcome"] == "cancelled"
    assert restored.events[-1]["reason"] == "approval_expired"
    assert restored.begin_turn("new task", user_id=70).turn_id == 2


def test_incomplete_offline_approval_fails_turn_without_becoming_executable(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(session_module, "data_dir", lambda: tmp_path)
    first_manager = SessionManager(system_prompt="system")
    session = first_manager.get_or_create(7)
    context = session.begin_turn("restart nginx", user_id=70)
    session.transition_turn("waiting_approval")
    session.pending_approval = True
    session.pending_tool_call_id = "call-1"
    session.pending_command = "systemctl restart nginx"
    first_manager.save_session(session)

    restored = SessionManager(system_prompt="system").get_or_create(7)

    assert restored.active_turn is None
    assert not restored.pending_approval
    assert restored.events[-1]["event_type"] == "turn_completed"
    assert restored.events[-1]["turn_id"] == context.turn_id
    assert restored.events[-1]["outcome"] == "failed"
    assert restored.events[-1]["reason"] == "invalid_approval_snapshot"


def test_clear_discards_activity_but_keeps_monotonic_counter():
    session = AgentSession(chat_id=7)
    session.begin_turn("first", user_id=70)
    session.defer_user_message("second", user_id=71)

    session.clear()
    next_context = session.begin_turn("third", user_id=70)

    assert next_context.turn_id == 2
    assert session.deferred_user_message is None
    assert session.deferred_user_id is None


def test_handle_message_uses_one_turn_for_final_reply():
    session = AgentSession(
        chat_id=7,
        messages=[{"role": "system", "content": "system"}],
    )
    agent = _agent(session, _SequenceLLM(LLMResponse(content="done")))

    result = asyncio.run(agent.handle_message(7, "inspect", user_id=70))

    assert result.content == "done"
    assert session.active_turn is None
    assert session.next_turn_id == 2
    assert session.messages[-2]["_chatdome_turn_id"] == 1
    assert [event["event_type"] for event in session.events] == [
        "turn_started",
        "turn_completed",
    ]
    assert session.events[0]["user_id"] == 70
    assert session.events[-1]["outcome"] == "completed"


def test_turn_started_log_has_chat_user_and_turn_context():
    session = AgentSession(
        chat_id=7,
        messages=[{"role": "system", "content": "system"}],
    )
    agent = _agent(session, _SequenceLLM(LLMResponse(content="done")))
    contexts = []

    def capture(message, *_args, **_kwargs):
        if message == "Turn started":
            contexts.append(current_log_context())

    with patch("chatdome.agent.core.logger.info", side_effect=capture):
        asyncio.run(agent.handle_message(7, "inspect", user_id=70))

    assert contexts == [{"chat_id": "7", "user_id": "70", "turn_id": "1"}]


def test_running_turn_rejects_new_message_without_allocating_id():
    session = AgentSession(chat_id=7)
    session.begin_turn("first", user_id=70)
    llm = _SequenceLLM()
    agent = _agent(session, llm)

    result = asyncio.run(agent.handle_message(7, "second", user_id=70))

    assert result.content == "任务正在运行。发送 /stop 中止。"
    assert session.next_turn_id == 2
    assert llm.calls == []


def test_round_limit_remains_same_active_turn():
    session = AgentSession(
        chat_id=7,
        messages=[{"role": "system", "content": "system"}],
    )
    llm = _SequenceLLM(
        LLMResponse(
            tool_calls=[
                ToolCall(
                    id="call-1",
                    name="read_file",
                    arguments='{"path":"/tmp/example"}',
                )
            ]
        )
    )
    agent = _agent(session, llm, max_rounds=1)

    result = asyncio.run(agent.handle_message(7, "long task", user_id=70))

    assert result.kind == "round_limit"
    assert session.active_turn is not None
    assert session.active_turn.state == "waiting_round_limit"
    assert session.active_turn.turn_id == 1
    assert session.next_turn_id == 2


def test_llm_failure_finishes_turn_as_failed():
    session = AgentSession(
        chat_id=7,
        messages=[{"role": "system", "content": "system"}],
    )
    agent = _agent(session, _SequenceLLM())

    result = asyncio.run(agent.handle_message(7, "inspect", user_id=70))

    assert result.content.startswith("⚠️ ")
    assert session.active_turn is None
    assert session.events[-1]["outcome"] == "failed"


def test_approval_resume_returns_same_turn_to_running_before_completion():
    session = AgentSession(
        chat_id=7,
        messages=[{"role": "system", "content": "system"}],
    )
    context = session.begin_turn("inspect", user_id=70)
    session.add_user_message("inspect", turn_id=context.turn_id)
    session.add_assistant_tool_calls(
        [
            {
                "id": "call-1",
                "type": "function",
                "function": {"name": "run_shell_command", "arguments": "{}"},
            }
        ]
    )
    session.transition_turn("waiting_approval")
    session.pending_approval = True
    session.pending_approval_id = "AP-1"
    session.pending_tool_call_id = "call-1"
    session.pending_command = "whoami"
    session.pending_command_hash = Agent._command_hash("whoami")
    session.pending_reason = "检查当前运行用户"
    agent = _agent(session, _SequenceLLM(LLMResponse(content="done")))

    _, result = asyncio.run(agent.resume_session(7, "APPROVE", approval_id="AP-1"))

    assert result.content == "done"
    assert session.active_turn is None
    state_changes = [
        event["state"]
        for event in session.events
        if event.get("event_type") == "turn_state_changed"
    ]
    assert state_changes == ["running"]
    assert session.events[-1]["turn_id"] == 1


def test_resume_fails_closed_when_approval_binding_is_incomplete():
    session = AgentSession(
        chat_id=7,
        messages=[{"role": "system", "content": "system"}],
    )
    context = session.begin_turn("inspect", user_id=70)
    session.add_user_message("inspect", turn_id=context.turn_id)
    session.add_assistant_tool_calls(
        [
            {
                "id": "call-1",
                "type": "function",
                "function": {"name": "run_shell_command", "arguments": "{}"},
            }
        ]
    )
    session.transition_turn("waiting_approval")
    session.pending_approval = True
    session.pending_tool_call_id = "call-1"
    session.pending_command = "whoami"
    session.pending_reason = "检查当前运行用户"
    agent = _agent(session, _SequenceLLM())

    _, result = asyncio.run(agent.resume_session(7, "APPROVE"))

    assert result.content == "命令校验失败，任务已终止。"
    assert session.active_turn is None


def test_deferred_turn_is_consumed_only_when_continuation_starts():
    session = AgentSession(
        chat_id=7,
        messages=[{"role": "system", "content": "system"}],
    )
    session.defer_user_message("inspect disk", user_id=71)
    agent = _agent(session, _SequenceLLM(LLMResponse(content="done")))

    result = asyncio.run(
        agent.handle_message(
            7,
            "inspect disk",
            user_id=70,
            deferred=True,
        )
    )

    assert result.content == "done"
    assert session.deferred_user_message is None
    assert session.deferred_user_id is None
    assert session.events[0]["user_id"] == 71
