from __future__ import annotations

import asyncio

from chatdome.agent.approval_input import classify_approval_input
from chatdome.llm.client import LLMResponse, ToolCall


class FakeLLM:
    model = "test-model"

    def __init__(self, response: LLMResponse | Exception) -> None:
        self.response = response
        self.calls: list[dict] = []

    async def chat_completion(self, messages, tools=None, response_format=None):
        self.calls.append(
            {
                "messages": messages,
                "tools": tools,
                "response_format": response_format,
            }
        )
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def _classify(llm: FakeLLM):
    return asyncio.run(
        classify_approval_input(
            llm,
            command="ss -tlnH",
            reason="检查监听端口",
            risk_level="LOW",
            user_message="有什么风险？",
        )
    )


def test_classifier_uses_one_tool_free_llm_call():
    llm = FakeLLM(
        LLMResponse(
            content='{"classification":"approval_question","answer":"该命令只读取端口。"}'
        )
    )

    decision = _classify(llm)

    assert decision.classification == "approval_question"
    assert decision.answer == "该命令只读取端口。"
    assert len(llm.calls) == 1
    assert llm.calls[0]["tools"] is None
    assert llm.calls[0]["response_format"] == {"type": "json_object"}


def test_missing_question_answer_falls_back_to_unknown():
    llm = FakeLLM(
        LLMResponse(content='{"classification":"approval_question","answer":""}')
    )

    decision = _classify(llm)

    assert decision.classification == "unknown"
    assert decision.answer == ""


def test_tool_call_response_falls_back_to_unknown():
    llm = FakeLLM(
        LLMResponse(
            content='{"classification":"approve","answer":""}',
            tool_calls=[ToolCall(id="call-1", name="run_shell_command", arguments="{}")],
        )
    )

    assert _classify(llm).classification == "unknown"


def test_malformed_or_failed_response_falls_back_to_unknown():
    malformed = FakeLLM(LLMResponse(content="not json"))
    failed = FakeLLM(RuntimeError("offline"))

    assert _classify(malformed).classification == "unknown"
    assert _classify(failed).classification == "unknown"
    assert len(malformed.calls) == 1
    assert len(failed.calls) == 1


def test_pseudo_tool_text_and_unsupported_label_fall_back_to_unknown():
    pseudo_tool = FakeLLM(
        LLMResponse(
            content=(
                '{"classification":"approval_question",'
                '"answer":"<tool_call>run_shell_command</tool_call>"}'
            )
        )
    )
    unsupported = FakeLLM(
        LLMResponse(content='{"classification":"continue","answer":""}')
    )

    assert _classify(pseudo_tool).classification == "unknown"
    assert _classify(unsupported).classification == "unknown"
