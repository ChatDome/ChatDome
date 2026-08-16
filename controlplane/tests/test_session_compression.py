import asyncio
import json
import logging
import os
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

from chatdome.agent.session import AgentSession, SessionManager, redact_sensitive_text
from chatdome.agent.tools import ToolDispatcher


def test_session_cleanup_stop_awaits_task_and_clears_reference() -> None:
    async def scenario() -> None:
        manager = SessionManager(session_timeout=600, system_prompt="system")
        manager.start_cleanup_task()
        cleanup_task = manager._cleanup_task

        await manager.stop_cleanup_task()
        await manager.stop_cleanup_task()

        assert cleanup_task is not None
        assert cleanup_task.done()
        assert manager._cleanup_task is None

    asyncio.run(scenario())


def test_redact_sensitive_text_removes_common_secret_shapes() -> None:
    raw = "\n".join(
        [
            "bot_token: 123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef",
            "api_key=sk-live_1234567890abc",
            "Authorization: Bearer abcdefghijklmnop",
            "-----BEGIN PRIVATE KEY-----\nsecret-key-body\n-----END PRIVATE KEY-----",
        ]
    )

    redacted = redact_sensitive_text(raw)

    assert "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef" not in redacted
    assert "sk-live_1234567890abc" not in redacted
    assert "abcdefghijklmnop" not in redacted
    assert "secret-key-body" not in redacted
    assert redacted.count("[REDACTED]") >= 4


def test_visible_context_uses_messages_and_pending_followups() -> None:
    session = AgentSession(chat_id=123)
    session.add_system_message("system")

    added = session.add_visible_context(
        event_type="sentinel_alert_analysis",
        user_action="点击告警分析",
        assistant_summary="结论: 8080 新增监听，需要核实进程。",
        refs={"check_id": "open_ports", "端口": "8080"},
    )

    assert added is True
    assert [msg["role"] for msg in session.messages] == ["system", "user", "assistant"]
    assert "点击告警分析" in session.messages[-2]["content"]
    assert "8080" in session.messages[-1]["content"]

    pending = AgentSession(chat_id=123)
    pending.add_system_message("system")
    pending.pending_approval = True
    assert pending.add_visible_context(
        event_type="approval_detail",
        user_action="查看待审批命令详细分析",
        assistant_summary="命令会修改系统配置。",
        refs={"approval_id": "AP-1"},
    )
    assert len(pending.messages) == 1
    assert [item["role"] for item in pending.pending_followups] == ["user", "assistant"]


def test_visible_context_defers_and_flushes_while_agent_runs() -> None:
    session = AgentSession(chat_id=123)
    session.add_system_message("system")
    session.agent_running = True

    added = session.add_visible_context(
        event_type="sentinel_alert_push",
        user_action="收到 Sentinel 告警推送",
        assistant_summary="SSH 成功登录告警。",
        refs={"check_id": "ssh_success_login", "IP": "114.246.239.99"},
    )

    assert added is False
    assert session.deferred_visible_context_count() == 1
    session.agent_running = False
    assert session.flush_deferred_visible_contexts() == 1
    assert session.deferred_visible_context_count() == 0
    assert "114.246.239.99" in session.messages[-1]["content"]


def test_deferred_visible_context_queue_is_bounded(caplog) -> None:
    session = AgentSession(chat_id=123)
    session.agent_running = True

    with caplog.at_level(logging.WARNING, logger="chatdome.agent.session"):
        for index in range(6):
            session.add_visible_context(
                event_type=f"event_{index}",
                user_action="收到 Sentinel 告警推送",
                assistant_summary=f"summary {index}",
            )

    assert session.deferred_visible_context_count() == 5
    assert "Deferred visible context queue full" in caplog.text


def test_deferred_visible_context_waits_until_round_limit_resolves() -> None:
    session = AgentSession(chat_id=123)
    session.add_system_message("system")
    session.agent_running = True
    session.add_visible_context(
        event_type="sentinel_alert_push",
        user_action="收到 Sentinel 告警推送",
        assistant_summary="open_ports 告警。",
    )
    session.agent_running = False
    session.pending_round_limit = True

    assert session.flush_deferred_visible_contexts() == 0
    session.clear_pending_round_limit()
    assert session.flush_deferred_visible_contexts() == 1


def test_visible_context_runtime_guard_is_not_serialized() -> None:
    session = AgentSession(chat_id=123)
    session.agent_running = True
    session.add_visible_context(
        event_type="sentinel_alert_push",
        user_action="收到 Sentinel 告警推送",
        assistant_summary="SSH 成功登录告警。",
    )

    payload = session.to_snapshot()
    restored = AgentSession.from_snapshot(payload)

    assert "agent_running" not in payload
    assert "_deferred_visible_contexts" not in payload
    assert "_transient_contexts" not in payload
    assert restored.agent_running is False
    assert restored.deferred_visible_context_count() == 0


def test_search_session_history_tool_reads_archived_events() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        with patch.dict(os.environ, {"CHATDOME_DATA_DIR": tmp}, clear=False):
            manager = SessionManager(session_timeout=600, system_prompt="system")
            manager.event_store.append(
                123,
                "message.assistant",
                {
                    "content": "open_ports 告警显示 0.0.0.0:8080 新增监听。",
                    "check_id": "open_ports",
                    "severity": "9",
                },
            )
            dispatcher = ToolDispatcher(SimpleNamespace(), session_manager=manager)
            result = asyncio.run(
                dispatcher.dispatch(
                    "search_session_history",
                    '{"query": "8080 open_ports", "limit": 3}',
                    chat_id=123,
                )
            )

    payload = json.loads(result)
    encoded = json.dumps(payload, ensure_ascii=False)
    assert payload["ok"] is True
    assert payload["matches"]
    assert "8080" in encoded
    assert "open_ports" in encoded
