import asyncio
import json
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

from chatdome.agent.context_budget import ContextBudgetService, ContextTokenCounter
from chatdome.agent.context_compactor import ContextCompactor
from chatdome.agent.event_store import EventStore
from chatdome.agent.memory_vault import MemoryVaultStore
from chatdome.agent.session import AgentSession, SessionManager


class CharacterEncoder:
    def encode(self, text: str) -> list[int]:
        return list(range(len(text)))


class FakeLLM:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    async def chat_completion(self, messages):
        self.calls.append(messages)
        response = self.responses[min(len(self.calls) - 1, len(self.responses) - 1)]
        return response


def _response(payload: dict, finish_reason: str = "stop") -> SimpleNamespace:
    return SimpleNamespace(
        content=json.dumps(payload, ensure_ascii=False),
        finish_reason=finish_reason,
    )


def _summary_payload(source_event_ids: list[str]) -> dict:
    return {
        "version": 1,
        "current_goal": "完成当前检查",
        "current_state": "正在分析活动回合的工具结果",
        "completed": [],
        "key_results": [],
        "files": [],
        "commands": [],
        "pending": [],
        "user_constraints": [],
        "source_event_ids": source_event_ids,
    }


def _oversized_session(events: EventStore) -> AgentSession:
    session = AgentSession(chat_id=7)
    session.add_system_message("system")
    for turn_id in range(1, 6):
        user = events.append(7, "message.user", {"content": f"历史任务 {turn_id}"}, turn_id=turn_id)
        assistant = events.append(
            7,
            "message.assistant",
            {"content": f"历史结果 {turn_id}"},
            turn_id=turn_id,
        )
        session.add_user_message("用" * 3_600, turn_id=turn_id, event_id=user.event_id)
        session.add_assistant_message("果" * 3_600, event_id=assistant.event_id)
    session.next_turn_id = 6
    turn = session.begin_turn("完成当前检查")
    user = events.append(7, "message.user", {"content": "完成当前检查"}, turn_id=turn.turn_id)
    call = events.append(7, "tool.call", {"name": "run", "arguments": {}}, turn_id=turn.turn_id)
    result = events.append(7, "tool.result", {"content": "活动结果"}, turn_id=turn.turn_id)
    session.add_user_message("查" * 1_000, turn_id=turn.turn_id, event_id=user.event_id)
    session.add_assistant_tool_calls(
        [{"id": "call-1", "type": "function", "function": {"name": "run", "arguments": "{}"}}],
        event_id=call.event_id,
    )
    session.add_tool_result("call-1", "活动工具结果", event_id=result.event_id)
    return session


def _compactor(tmp_path: Path, events: EventStore, manager: SessionManager) -> ContextCompactor:
    counter = ContextTokenCounter(model="test", encoder=CharacterEncoder())
    budget = ContextBudgetService(counter, limit_tokens=32_000, target_ratio=0.70)
    memory = MemoryVaultStore(tmp_path, token_counter=counter, event_store=events)
    return ContextCompactor(
        budget_service=budget,
        event_store=events,
        memory_vault_store=memory,
        session_saver=manager.save_session,
    )


def test_compactor_keeps_active_tool_pair_and_targets_seventy_percent(tmp_path: Path) -> None:
    events = EventStore(tmp_path, retention_days=30)
    manager = SessionManager(data_root=tmp_path, event_store=events)
    session = _oversized_session(events)
    source_ids = [
        message["_chatdome_event_id"]
        for message in session.messages
        if message.get("_chatdome_event_id")
    ]
    llm = FakeLLM(
        [_response({"working_summary": _summary_payload(source_ids), "memory_candidates": []})]
    )
    compactor = _compactor(tmp_path, events, manager)

    result = asyncio.run(compactor.ensure_budget(session, llm, tools=[], trigger_reason="test"))

    assert result.status == "completed"
    assert result.tokens_after <= 22_400
    assert result.tokens_after < result.tokens_before
    assert result.reduction_percent > 0
    assert session.messages[-2]["role"] == "assistant"
    assert session.messages[-1]["role"] == "tool"
    assert session.messages[-1]["tool_call_id"] == "call-1"
    assert session.working_summary is not None
    assert session.working_summary.current_goal == "完成当前检查"
    assert session.context_state.last_compaction is not None
    assert any(event.type == "context.compaction_completed" for event in events.read_events(7))


def test_invalid_summary_keeps_previous_session_and_memory(tmp_path: Path) -> None:
    events = EventStore(tmp_path, retention_days=30)
    manager = SessionManager(data_root=tmp_path, event_store=events)
    session = _oversized_session(events)
    before = deepcopy(session.to_snapshot())
    memory_path = tmp_path / "memory" / "7.json"
    memory_path.parent.mkdir(parents=True)
    memory_path.write_text(
        json.dumps({"version": 2, "last_updated": "", "token_count": 0, "entries": []}),
        encoding="utf-8",
    )
    memory_before = memory_path.read_bytes()
    llm = FakeLLM(
        [
            _response({"working_summary": {"current_goal": "缺少字段"}}),
            _response({"working_summary": {"current_goal": "仍缺少字段"}}),
        ]
    )
    compactor = _compactor(tmp_path, events, manager)

    result = asyncio.run(compactor.ensure_budget(session, llm, tools=[], trigger_reason="test"))

    assert result.status == "rejected"
    assert len(llm.calls) == 2
    assert session.to_snapshot() == before
    assert memory_path.read_bytes() == memory_before
    assert any(event.type == "context.compaction_rejected" for event in events.read_events(7))


def test_not_needed_does_not_call_llm_or_write_events(tmp_path: Path) -> None:
    events = EventStore(tmp_path, retention_days=30)
    manager = SessionManager(data_root=tmp_path, event_store=events)
    session = AgentSession(chat_id=7)
    session.add_system_message("system")
    session.add_user_message("short")
    compactor = _compactor(tmp_path, events, manager)
    llm = FakeLLM([])

    result = asyncio.run(compactor.ensure_budget(session, llm, tools=[], trigger_reason="test"))

    assert result.status == "not_needed"
    assert llm.calls == []
    assert events.read_events(7) == []
