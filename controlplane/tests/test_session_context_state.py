import json
import re
from pathlib import Path

from chatdome.agent.context_models import ContextState, SummaryItem, WorkingSummary
from chatdome.agent.event_store import EventStore
from chatdome.agent.session import AgentSession, SessionManager


def _summary() -> WorkingSummary:
    return WorkingSummary(
        current_goal="检查日志",
        current_state="等待用户确认来源",
        completed=[SummaryItem("已读取 SSH 登录记录", ["EV-1"])],
        source_event_ids=["EV-1"],
        updated_at="2026-08-16 10:00:00+08:00",
        token_count=24,
    )


def test_build_llm_messages_strips_event_metadata_and_injects_summary() -> None:
    session = AgentSession(chat_id=7)
    session.add_system_message("system")
    session.working_summary = _summary()
    session.add_user_message("继续", event_id="EV-2")

    messages = session.build_llm_messages()

    assert session.messages[-1]["_chatdome_event_id"] == "EV-2"
    assert all("_chatdome_event_id" not in message for message in messages)
    assert messages[0]["content"] == "system"
    assert "[Working Summary" in messages[1]["content"]
    assert messages[-1]["content"] == "继续"


def test_message_helpers_preserve_event_references_in_snapshot_only() -> None:
    session = AgentSession(chat_id=7)
    session.add_assistant_message("完成", event_id="EV-A")
    session.add_assistant_tool_calls(
        [{"id": "call-1", "type": "function", "function": {"name": "run", "arguments": "{}"}}],
        event_id="EV-CALL",
    )
    session.add_tool_result("call-1", "ok", event_id="EV-RESULT")

    assert [message["_chatdome_event_id"] for message in session.messages] == [
        "EV-A",
        "EV-CALL",
        "EV-RESULT",
    ]
    assert all(
        "_chatdome_event_id" not in message
        for message in session.build_llm_messages()
    )


def test_session_v3_round_trip_preserves_working_summary(tmp_path: Path) -> None:
    manager = SessionManager(data_root=tmp_path)
    session = manager.get_or_create(7)
    session.working_summary = _summary()
    session.context_state = ContextState(last_compaction_status="completed")

    assert manager.save_session(session) is True

    payload = json.loads((tmp_path / "sessions" / "7.json").read_text(encoding="utf-8"))
    restored = manager.load_persisted_session(7)
    assert payload["version"] == 3
    assert re.fullmatch(
        r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}",
        payload["saved_at"],
    )
    assert restored is not None
    assert restored.working_summary is not None
    assert restored.working_summary.current_goal == "检查日志"
    assert restored.context_state.last_compaction_status == "completed"
    assert list((tmp_path / "sessions").glob(".7.json.*.tmp")) == []


def test_clear_appends_boundary_before_resetting_session(tmp_path: Path) -> None:
    events = EventStore(tmp_path, retention_days=30)
    manager = SessionManager(data_root=tmp_path, event_store=events)
    session = manager.get_or_create(7)
    session.add_user_message("旧任务")
    session.working_summary = _summary()
    manager.save_session(session)

    result = manager.clear_session(7, source="cli")

    assert result.status == "cleared"
    assert result.clear_event_id
    assert events.latest_clear_event_id(7) == result.clear_event_id
    assert session.working_summary is None
    assert session.context_state.last_compaction is None
    assert session.messages == [{"role": "system", "content": ""}]


def test_clear_refuses_active_running_turn_without_writing_event(tmp_path: Path) -> None:
    events = EventStore(tmp_path, retention_days=30)
    manager = SessionManager(data_root=tmp_path, event_store=events)
    session = manager.get_or_create(7)
    session.begin_turn("检查日志")

    result = manager.clear_session(7)

    assert result.status == "running_task"
    assert bool(result) is False
    assert events.read_events(7) == []
    assert session.active_turn is not None
