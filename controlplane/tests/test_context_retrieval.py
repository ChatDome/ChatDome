import json
import logging
from pathlib import Path
from types import SimpleNamespace

from chatdome.agent.context_models import SummaryItem, WorkingSummary
from chatdome.agent.context_retrieval import ContextRetrievalPolicy
from chatdome.agent.event_store import EventStore
from chatdome.agent.session import AgentSession, SessionManager
from chatdome.agent.tools import ToolDispatcher


def test_explicit_history_reference_triggers_retrieval() -> None:
    decision = ContextRetrievalPolicy().evaluate("继续查看刚才那些 SSH IP", AgentSession(7))

    assert decision.should_retrieve is True
    assert decision.reason == "explicit_history_reference"
    assert "SSH" in decision.query


def test_evidence_request_uses_working_summary_sources() -> None:
    session = AgentSession(7)
    session.working_summary = WorkingSummary(
        current_goal="检查 SSH",
        current_state="已有摘要",
        key_results=[SummaryItem("发现异常登录", ["EV-1"])],
    )

    decision = ContextRetrievalPolicy().evaluate("给出精确证据", session)

    assert decision.should_retrieve is True
    assert decision.reason == "summary_evidence_requested"


def test_direct_current_request_does_not_trigger_retrieval() -> None:
    decision = ContextRetrievalPolicy().evaluate("检查当前磁盘使用率", AgentSession(7))

    assert decision.should_retrieve is False


def test_session_history_search_reads_events_and_respects_clear(tmp_path: Path) -> None:
    events = EventStore(tmp_path, retention_days=30)
    events.append(7, "message.user", {"content": "旧任务 nginx"})
    events.append(7, "session.cleared", {})
    current = events.append(7, "tool.result", {"content": "SSH 地址 114.1.2.3"})
    manager = SessionManager(data_root=tmp_path, event_store=events)

    assert manager.search_history(7, "nginx") == []
    matches = manager.search_history(7, "SSH", limit=3)
    assert matches[0]["event_id"] == current.event_id
    assert matches[0]["type"] == "tool.result"


def test_history_tool_logs_trigger_and_hit_event_ids(tmp_path: Path, caplog) -> None:
    events = EventStore(tmp_path, retention_days=30)
    event = events.append(7, "message.user", {"content": "历史 SSH 地址"})
    manager = SessionManager(data_root=tmp_path, event_store=events)
    dispatcher = ToolDispatcher(SimpleNamespace(), session_manager=manager)

    with caplog.at_level(logging.INFO, logger="chatdome.agent.tools"):
        result = dispatcher._handle_search_session_history({"query": "SSH"}, chat_id=7)

    payload = json.loads(result)
    assert payload["source"] == "events/7.jsonl"
    assert payload["matches"][0]["event_id"] == event.event_id
    assert "trigger_reason=tool_request" in caplog.text
    assert f"hit_event_ids={event.event_id}" in caplog.text
