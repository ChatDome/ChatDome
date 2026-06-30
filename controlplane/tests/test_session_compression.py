import asyncio
import json
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from chatdome.agent.session import AgentSession, redact_sensitive_text
from chatdome.agent.prompts import COMPRESSION_PROMPT


class FakeCompressionLLM:
    def __init__(self, content: str):
        self.content = content
        self.prompts: list[str] = []

    async def chat_completion(self, messages):
        self.prompts.append(messages[0]["content"])
        return SimpleNamespace(content=self.content)


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
    for text in [prompt, memory, compression_log, session_summary]:
        assert raw_bot_token not in text
        assert raw_api_key not in text
        assert raw_summary_key not in text
        assert "[REDACTED]" in text