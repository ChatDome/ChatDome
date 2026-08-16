import json
from types import SimpleNamespace

import pytest

from chatdome.agent.context_budget import ContextBudgetService, ContextTokenCounter
from chatdome.agent.core import Agent
from chatdome.agent.context_models import ContextState, WorkingSummary
from chatdome.config import AgentConfig, parse_config_document


class CharacterEncoder:
    def encode(self, text: str) -> list[int]:
        return list(range(len(text)))


def _valid_summary_payload() -> dict:
    return {
        "version": 1,
        "current_goal": "检查系统日志",
        "current_state": "等待确认异常来源",
        "completed": [
            {"text": "读取 SSH 登录记录", "source_event_ids": ["EV-1"]},
        ],
        "key_results": [],
        "files": [],
        "commands": [],
        "pending": [],
        "user_constraints": [],
        "source_event_ids": ["EV-1"],
    }


def test_count_request_includes_tool_schema_and_arguments() -> None:
    counter = ContextTokenCounter(model="gpt-4o", encoder=CharacterEncoder())
    messages = [
        {"role": "user", "content": "检查日志"},
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": "call-1",
                    "type": "function",
                    "function": {"name": "run", "arguments": '{"path":"/var/log"}'},
                }
            ],
        },
    ]
    without_tools = counter.count_request(messages, tools=[])
    with_tools = counter.count_request(
        messages,
        tools=[
            {
                "type": "function",
                "function": {
                    "name": "run",
                    "parameters": {
                        "type": "object",
                        "properties": {"path": {"type": "string"}},
                    },
                },
            }
        ],
    )

    assert with_tools.tokens > without_tools.tokens
    assert with_tools.method == "model_tokenizer"


def test_count_request_uses_serialized_payload_not_python_repr() -> None:
    counter = ContextTokenCounter(model="gpt-4o", encoder=CharacterEncoder())
    messages = [{"role": "user", "content": "中文日志"}]

    result = counter.count_request(messages, tools=[])

    serialized = json.dumps(
        {"messages": messages, "tools": []},
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    assert result.tokens == len(serialized)


def test_unknown_model_without_tiktoken_uses_heuristic() -> None:
    counter = ContextTokenCounter(
        model="unknown-model",
        encoder=None,
        encoder_loader=lambda _model: (None, "heuristic"),
    )

    result = counter.count_request([{"role": "user", "content": "检查日志"}], tools=[])

    assert result.tokens >= 1
    assert result.method == "heuristic"


def test_working_summary_rejects_missing_goal() -> None:
    payload = _valid_summary_payload()
    payload.pop("current_goal")

    with pytest.raises(ValueError, match="current_goal"):
        WorkingSummary.from_dict(payload)


def test_working_summary_normalizes_source_ids_and_renders_stable_prompt() -> None:
    payload = _valid_summary_payload()
    payload["source_event_ids"] = ["EV-1", "EV-1", "", 7]

    summary = WorkingSummary.from_dict(payload)
    block = summary.to_prompt_block()

    assert summary.source_event_ids == ["EV-1"]
    assert "当前目标：检查系统日志" in block
    assert "当前状态：等待确认异常来源" in block
    assert "EV-1" in block


def test_context_state_round_trip_preserves_last_compaction() -> None:
    state = ContextState.from_dict(
        {
            "last_compaction": {
                "compaction_id": "CP-1",
                "completed_at": "2026-08-16 10:00:00+08:00",
                "tokens_before": 34210,
                "tokens_after": 21520,
                "reduction_percent": 37,
                "working_summary_tokens": 1420,
                "preserved_tail_tokens": 18940,
            }
        }
    )

    assert state.to_dict()["last_compaction"]["tokens_before"] == 34210
    assert state.to_dict()["last_compaction"]["reduction_percent"] == 37


def test_agent_config_defaults_to_32k_and_30_day_events() -> None:
    config = AgentConfig()

    assert config.max_history_tokens == 32000
    assert config.event_retention_days == 30


def test_event_retention_zero_is_preserved_by_config_parser() -> None:
    config = parse_config_document(
        {
            "chatdome": {
                "agent": {
                    "command_approval_mode": "require_approval_for_risky_commands",
                    "event_retention_days": 0,
                }
            }
        }
    )

    assert config.agent.event_retention_days == 0


def test_refresh_context_settings_updates_live_budget_and_retention() -> None:
    agent = Agent.__new__(Agent)
    agent.config = SimpleNamespace(max_history_tokens=48_000, event_retention_days=0)
    agent.context_budget_service = ContextBudgetService(
        ContextTokenCounter(encoder=CharacterEncoder()),
        limit_tokens=32_000,
    )
    agent.session_manager = SimpleNamespace(
        max_history_tokens=32_000,
        event_store=SimpleNamespace(retention_days=30),
    )

    agent.refresh_context_settings()

    assert agent.context_budget_service.limit_tokens == 48_000
    assert agent.context_budget_service.target_tokens == 33_600
    assert agent.session_manager.max_history_tokens == 48_000
    assert agent.session_manager.event_store.retention_days == 0
