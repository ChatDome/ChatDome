import asyncio
from pathlib import Path
from types import SimpleNamespace

from chatdome.agent.context_budget import ContextTokenCounter
from chatdome.agent.event_store import EventStore
from chatdome.agent.memory_vault import MemoryCandidate, MemoryVaultStore
from chatdome.command_handlers import CommandHandlerRuntime, CommandHandlerService
from chatdome.outbound.builders import OutboundMessageBuilder
from chatdome.outbound.models import ContextUsageFacts, DecisionOperationFacts
from chatdome.outbound.renderers.telegram import TelegramOutboundRenderer
from chatdome.outbound.renderers.terminal import TerminalOutboundRenderer
from chatdome.slash_commands import (
    CommandContext,
    CommandDef,
    CommandInvocation,
    context_usage_command_result,
)


class CharacterEncoder:
    def encode(self, text: str) -> list[int]:
        return list(range(len(text)))


def _invocation(
    args=(),
    *,
    action: str = "",
    interaction_id: str = "",
) -> CommandInvocation:
    return CommandInvocation(
        raw="/memory" + (" " + " ".join(args) if args else ""),
        raw_name="/memory",
        args=tuple(args),
        arg_text=" ".join(args),
        command=CommandDef("/memory", "memory", "memory"),
        context=CommandContext(source="telegram", chat_id=7, actor_id="7"),
        action=action,
        interaction_id=interaction_id,
    )


def test_context_command_uses_one_shared_progress_bar_rendering() -> None:
    agent = SimpleNamespace(
        get_context_status=lambda _chat_id: {
            "current_tokens": 21_760,
            "limit_tokens": 32_000,
            "usage_percent": 68,
            "status": "正常",
            "working_summary_tokens": 1_420,
            "last_tokens_before": 34_210,
            "last_tokens_after": 21_520,
            "last_reduction_percent": 37,
            "token_count_method": "heuristic",
        }
    )

    result = context_usage_command_result(agent, CommandContext(chat_id=7))
    message = OutboundMessageBuilder().from_command_result(_invocation(), result)
    terminal = TerminalOutboundRenderer().render(message).text_parts[0]
    telegram = TelegramOutboundRenderer().render(message).text_parts[0]

    assert isinstance(result.facts, ContextUsageFacts)
    assert terminal == telegram
    assert "21,760 / 32,000 tokens（68%）" in terminal
    assert "34,210 → 21,520 tokens（减少 37%）" in terminal
    assert "████████░░░░" in terminal


def test_memory_delete_uses_decision_prompt_then_callback_confirmation(tmp_path: Path) -> None:
    events = EventStore(tmp_path, retention_days=30)
    user_event = events.append(7, "message.user", {"content": "回复使用中文"})
    store = MemoryVaultStore(
        tmp_path,
        token_counter=ContextTokenCounter(model="test", encoder=CharacterEncoder()),
        event_store=events,
    )
    accepted = store.accept_candidates(
        7,
        [MemoryCandidate("user_preference", "回复使用中文", [user_event.event_id])],
        allowed_event_ids={user_event.event_id},
    )
    entry_id = accepted.accepted_entry_ids[0]
    agent = SimpleNamespace(memory_vault_store=store)
    service = CommandHandlerService(
        lambda _invocation: CommandHandlerRuntime(agent=agent)
    )

    requested = asyncio.run(service.handle(_invocation(("delete", entry_id))))

    assert requested.outcome == "memory_confirmation_requested"
    assert isinstance(requested.facts, DecisionOperationFacts)
    assert requested.facts.decision.intent == f"删除长期记忆 {entry_id}"
    nonce = requested.event_refs["interaction_id"]
    confirmed = asyncio.run(
        service.handle(
            _invocation(
                action="memory_delete_yes",
                interaction_id=nonce,
            )
        )
    )
    assert confirmed.outcome == "memory_deleted"
    assert store.load(7).entries == []


def test_memory_clear_requires_explicit_confirm_argument(tmp_path: Path) -> None:
    events = EventStore(tmp_path, retention_days=30)
    user_event = events.append(7, "message.user", {"content": "回复使用中文"})
    store = MemoryVaultStore(
        tmp_path,
        token_counter=ContextTokenCounter(model="test", encoder=CharacterEncoder()),
        event_store=events,
    )
    store.accept_candidates(
        7,
        [MemoryCandidate("user_preference", "回复使用中文", [user_event.event_id])],
        allowed_event_ids={user_event.event_id},
    )
    service = CommandHandlerService(
        lambda _invocation: CommandHandlerRuntime(
            agent=SimpleNamespace(memory_vault_store=store)
        )
    )

    requested = asyncio.run(service.handle(_invocation(("clear",))))
    assert requested.outcome == "memory_confirmation_requested"
    assert store.load(7).entries

    cleared = asyncio.run(service.handle(_invocation(("clear", "confirm"))))
    assert cleared.outcome == "memory_cleared"
    assert not store.path_for(7).exists()
