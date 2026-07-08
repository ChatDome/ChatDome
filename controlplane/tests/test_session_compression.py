import asyncio
import json
import logging
import os
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from chatdome.agent.session import AgentSession, SessionManager, redact_sensitive_text
from chatdome.agent.prompts import COMPRESSION_PROMPT, MEMORY_MERGE_PROMPT
from chatdome.agent.tools import ToolDispatcher


class FakeCompressionLLM:
    def __init__(self, content):
        self.contents = list(content) if isinstance(content, list) else [content]
        self.prompts: list[str] = []

    async def chat_completion(self, messages):
        self.prompts.append(messages[0]["content"])
        index = min(len(self.prompts) - 1, len(self.contents) - 1)
        return SimpleNamespace(content=self.contents[index])


def test_redact_sensitive_text_removes_common_secret_shapes():
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


def test_compression_prompt_and_persisted_summary_are_redacted():
    raw_bot_token = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
    raw_api_key = "sk-live_1234567890abc"
    raw_summary_key = "sk-summary_1234567890abc"

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        memory_path = root / "memory" / "123.json"
        compression_path = root / "compression" / "123.log"
        session = AgentSession(chat_id=123)
        session.messages = [
            {"role": "system", "content": "system"},
            {"role": "user", "content": f"bot_token: {raw_bot_token}\napi_key={raw_api_key}"},
            {"role": "assistant", "content": "Configured token for Telegram access."},
            {"role": "user", "content": "Keep investigating auth errors."},
            {"role": "assistant", "content": "Working on it."},
        ]
        llm = FakeCompressionLLM(
            f"The bot token is {raw_bot_token}. Use api_key={raw_summary_key} for calls."
        )

        with patch("chatdome.agent.session.memory_file_path", return_value=memory_path), patch(
            "chatdome.agent.session.compression_log_path",
            return_value=compression_path,
        ):
            asyncio.run(session.summarize_and_trim_history(llm, max_tokens=1))

        prompt = llm.prompts[0]
        memory = json.loads(memory_path.read_text(encoding="utf-8"))["summary"]
        compression_log = compression_path.read_text(encoding="utf-8")
        session_summary = session.messages[1]["content"]

    assert "敏感值" in COMPRESSION_PROMPT
    assert "[REDACTED]" in COMPRESSION_PROMPT
    assert "=== Context Compressed ===" in compression_log
    assert "Chat ID : 123" in compression_log
    assert "Summary :" in compression_log
    for text in [prompt, memory, compression_log, session_summary]:
        assert raw_bot_token not in text
        assert raw_api_key not in text
        assert raw_summary_key not in text
        assert "[REDACTED]" in text


def test_compression_formats_tool_calls_without_python_repr(caplog):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        memory_path = root / "memory" / "123.json"
        compression_path = root / "compression" / "123.log"
        session = AgentSession(chat_id=123)
        session.messages = [
            {"role": "system", "content": "system"},
            {"role": "user", "content": "查看监听端口"},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_1",
                        "type": "function",
                        "function": {
                            "name": "run_shell_command",
                            "arguments": json.dumps(
                                {"command": "ss -tulnp", "reason": "检查监听端口"},
                                ensure_ascii=False,
                            ),
                        },
                    }
                ],
            },
            {"role": "tool", "tool_call_id": "call_1", "content": "tcp LISTEN 0 128 0.0.0.0:8080"},
            {"role": "assistant", "content": "8080 正在监听。"},
            {"role": "user", "content": "继续分析"},
            {"role": "assistant", "content": "继续分析中。"},
        ]
        llm = FakeCompressionLLM("摘要：8080 正在监听。")

        with patch("chatdome.agent.session.memory_file_path", return_value=memory_path), patch(
            "chatdome.agent.session.compression_log_path",
            return_value=compression_path,
        ), caplog.at_level(logging.INFO, logger="chatdome.agent.session"):
            asyncio.run(session.summarize_and_trim_history(llm, max_tokens=1))

    prompt = llm.prompts[0]
    assert "AI 调用工具: run_shell_command" in prompt
    assert 'command="ss -tulnp"' in prompt
    assert 'reason="检查监听端口"' in prompt
    assert "工具结果: run_shell_command" in prompt
    assert "0.0.0.0:8080" in prompt
    assert "AI Tool Executed" not in prompt
    assert "[{'id'" not in prompt
    assert "Context window limit reached" in caplog.text
    assert "Token limit reached" not in caplog.text


def test_existing_memory_summary_is_merged_after_repeated_updates():
    existing_summary = "旧摘要 A\n\n[UPDATE]\n旧摘要 B\n\n[UPDATE]\n旧摘要 C"

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        memory_path = root / "memory" / "123.json"
        compression_path = root / "compression" / "123.log"
        memory_path.parent.mkdir(parents=True, exist_ok=True)
        memory_path.write_text(
            json.dumps({"summary": existing_summary, "last_updated": 1}, ensure_ascii=False),
            encoding="utf-8",
        )
        session = AgentSession(chat_id=123)
        session.messages = [
            {"role": "system", "content": "system"},
            {"role": "user", "content": "排查 8080"},
            {"role": "assistant", "content": "旧分析"},
            {"role": "user", "content": "继续"},
            {"role": "assistant", "content": "继续分析"},
        ]
        llm = FakeCompressionLLM(["新摘要：8080 已确认是内部服务。", "合并摘要：8080 是内部服务。"])

        with patch("chatdome.agent.session.memory_file_path", return_value=memory_path), patch(
            "chatdome.agent.session.compression_log_path",
            return_value=compression_path,
        ):
            asyncio.run(session.summarize_and_trim_history(llm, max_tokens=1))

        memory = json.loads(memory_path.read_text(encoding="utf-8"))["summary"]

    assert len(llm.prompts) == 2
    assert MEMORY_MERGE_PROMPT.splitlines()[0] in llm.prompts[1]
    assert "旧摘要 A" in llm.prompts[1]
    assert "新摘要：8080 已确认是内部服务。" in llm.prompts[1]
    assert memory == "合并摘要：8080 是内部服务。"

def test_visible_context_uses_messages_and_pending_followups():
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

    added_pending = pending.add_visible_context(
        event_type="approval_detail",
        user_action="查看待审批命令详细分析",
        assistant_summary="命令会修改系统配置。",
        refs={"approval_id": "AP-1"},
    )

    assert added_pending is True
    assert len(pending.messages) == 1
    assert [item["role"] for item in pending.pending_followups] == ["user", "assistant"]
    assert "AP-1" in pending.pending_followups[-1]["content"]


def test_search_session_history_tool_reads_existing_messages():
    with tempfile.TemporaryDirectory() as tmp:
        with patch.dict(os.environ, {"CHATDOME_DATA_DIR": tmp}, clear=False):
            manager = SessionManager(session_timeout=600, system_prompt="system")
            session = manager.get_or_create(123)
            session.add_visible_context(
                event_type="sentinel_alert_detail",
                user_action="查看告警详情",
                assistant_summary="open_ports 告警显示 0.0.0.0:8080 新增监听。",
                refs={"check_id": "open_ports", "severity": "9"},
            )
            manager.save_session(session)

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
