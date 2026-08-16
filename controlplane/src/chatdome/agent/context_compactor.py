"""Transactional context compression with structured Working Summary output."""

from __future__ import annotations

import inspect
import json
import logging
import uuid
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Literal, Union

from chatdome.agent.context_budget import ContextBudgetService
from chatdome.agent.context_models import LastCompaction, WorkingSummary, local_timestamp
from chatdome.agent.event_store import EventStore
from chatdome.agent.memory_vault import MemoryCandidate, MemoryVaultStore
from chatdome.agent.redaction import redact_sensitive_text
from chatdome.agent.session import AgentSession

logger = logging.getLogger(__name__)

_COMPLETE_FINISH_REASONS = frozenset({"stop", "completed", "end_turn", "eos", "eos_token"})
_COMPACTION_PROMPT = """\
你负责压缩 ChatDome 的历史上下文。只输出一个 JSON 对象，不要使用 Markdown。

输出结构：
{
  "working_summary": {
    "version": 1,
    "current_goal": "当前目标",
    "current_state": "当前状态",
    "completed": [{"text": "已完成事项", "source_event_ids": ["EV-..."]}],
    "key_results": [{"text": "关键结果", "source_event_ids": ["EV-..."]}],
    "files": [{"text": "文件信息", "source_event_ids": ["EV-..."]}],
    "commands": [{"text": "命令及结果", "source_event_ids": ["EV-..."]}],
    "pending": [{"text": "仍有效待办", "source_event_ids": ["EV-..."]}],
    "user_constraints": [{"text": "用户约束", "source_event_ids": ["EV-..."]}],
    "source_event_ids": ["EV-..."]
  },
  "memory_candidates": [
    {
      "category": "confirmed_fact|user_preference|user_constraint|confirmed_decision|reusable_result",
      "content": "跨任务仍有价值的信息",
      "source_event_ids": ["EV-..."]
    }
  ]
}

要求：
- working_summary 必须完整，合并旧 Working Summary 与待压缩历史，并保持当前任务状态。
- 每个事实、约束、结果和待办都引用输入中真实存在的 event_id。
- memory_candidates 可以为空；当前目标、临时待办、一次性命令结果和未确认推测不得进入长期记忆。
- 不输出密码、密钥、token、cookie、私钥或 Authorization 值，统一写 [REDACTED]。
- 内容精炼，确保压缩后的上下文显著小于输入。
"""
_RETRY_SUFFIX = """

上一次结果未通过校验。进一步缩短各字段，只保留继续当前任务必需的信息；必须输出完整、可解析且符合结构的 JSON。
"""


CompactionStatus = Literal["not_needed", "completed", "failed", "rejected"]
SessionSaver = Callable[[AgentSession], Union[bool, Awaitable[bool]]]


@dataclass(frozen=True)
class CompactionResult:
    status: CompactionStatus
    tokens_before: int
    tokens_after: int
    working_summary_tokens: int = 0
    preserved_tail_tokens: int = 0
    reduction_percent: int = 0
    reason: str = ""
    compaction_id: str = ""


class ContextCompactor:
    """Replace an old complete-turn prefix only after all validation succeeds."""

    def __init__(
        self,
        *,
        budget_service: ContextBudgetService,
        event_store: EventStore,
        memory_vault_store: MemoryVaultStore,
        session_saver: SessionSaver | None = None,
    ) -> None:
        self.budget_service = budget_service
        self.event_store = event_store
        self.memory_vault_store = memory_vault_store
        self.session_saver = session_saver

    async def ensure_budget(
        self,
        session: AgentSession,
        llm_client: Any,
        *,
        tools: list[dict[str, Any]] | None,
        trigger_reason: str,
        progress_callback: Any = None,
    ) -> CompactionResult:
        tools = list(tools or [])
        before_snapshot = self.budget_service.snapshot(session.build_llm_messages(), tools)
        if not before_snapshot.requires_compaction:
            return CompactionResult(
                status="not_needed",
                tokens_before=before_snapshot.current_tokens,
                tokens_after=before_snapshot.current_tokens,
            )

        compaction_id = f"CP-{uuid.uuid4().hex[:12].upper()}"
        try:
            self.event_store.append(
                session.chat_id,
                "context.compaction_started",
                {
                    "compaction_id": compaction_id,
                    "tokens_before": before_snapshot.current_tokens,
                    "trigger_reason": trigger_reason,
                    "token_count_method": before_snapshot.method,
                },
                turn_id=self._active_turn_id(session),
            )
        except OSError as exc:
            return CompactionResult(
                status="failed",
                tokens_before=before_snapshot.current_tokens,
                tokens_after=before_snapshot.current_tokens,
                reason=f"event_write_failed:{exc}",
                compaction_id=compaction_id,
            )

        await self._publish_progress(progress_callback, "context_compacting")
        cut_index = self._select_cut_index(session, tools)
        if cut_index is None:
            return self._reject(
                session,
                compaction_id,
                before_snapshot.current_tokens,
                "no_complete_turn_prefix",
            )

        compressed_messages = session.messages[1:cut_index]
        retained_messages = [session.messages[0], *session.messages[cut_index:]]
        allowed_event_ids = self._allowed_event_ids(session)
        prompt = self._build_prompt(session, compressed_messages, retained_messages)
        last_reason = "invalid_response"
        for attempt in range(2):
            try:
                response = await llm_client.chat_completion(
                    [
                        {"role": "system", "content": _COMPACTION_PROMPT},
                        {
                            "role": "user",
                            "content": prompt + (_RETRY_SUFFIX if attempt else ""),
                        },
                    ]
                )
                summary, candidates = self._parse_response(response)
                self._validate_summary(session.working_summary, summary, allowed_event_ids)
                summary.updated_at = local_timestamp()
                summary.token_count = self.budget_service.counter.count_text(
                    summary.to_prompt_block()
                ).tokens
                candidate_messages = self._provider_messages(
                    retained_messages,
                    summary,
                    transient_contexts=session._transient_contexts,
                )
                after_snapshot = self.budget_service.snapshot(candidate_messages, tools)
                if after_snapshot.current_tokens >= before_snapshot.current_tokens:
                    raise ValueError("compression_not_smaller")
                if after_snapshot.current_tokens > self.budget_service.target_tokens:
                    raise ValueError("compression_target_not_met")
                return await self._commit(
                    session=session,
                    compaction_id=compaction_id,
                    retained_messages=retained_messages,
                    summary=summary,
                    candidates=candidates,
                    allowed_event_ids=allowed_event_ids,
                    tokens_before=before_snapshot.current_tokens,
                    tokens_after=after_snapshot.current_tokens,
                    tools=tools,
                    compressed_messages=compressed_messages,
                )
            except (json.JSONDecodeError, TypeError, ValueError, KeyError) as exc:
                last_reason = str(exc) or exc.__class__.__name__
                logger.warning(
                    "Context compaction response rejected: chat_id=%s compaction_id=%s "
                    "attempt=%d reason=%s",
                    session.chat_id,
                    compaction_id,
                    attempt + 1,
                    last_reason,
                )
            except Exception as exc:
                logger.exception(
                    "Context compaction failed: chat_id=%s compaction_id=%s",
                    session.chat_id,
                    compaction_id,
                )
                self._record_terminal_event(
                    session,
                    "context.compaction_failed",
                    compaction_id,
                    before_snapshot.current_tokens,
                    before_snapshot.current_tokens,
                    str(exc),
                )
                return CompactionResult(
                    status="failed",
                    tokens_before=before_snapshot.current_tokens,
                    tokens_after=before_snapshot.current_tokens,
                    reason=str(exc),
                    compaction_id=compaction_id,
                )
        return self._reject(
            session,
            compaction_id,
            before_snapshot.current_tokens,
            last_reason,
        )

    async def _commit(
        self,
        *,
        session: AgentSession,
        compaction_id: str,
        retained_messages: list[dict[str, Any]],
        summary: WorkingSummary,
        candidates: list[MemoryCandidate],
        allowed_event_ids: set[str],
        tokens_before: int,
        tokens_after: int,
        tools: list[dict[str, Any]],
        compressed_messages: list[dict[str, Any]],
    ) -> CompactionResult:
        original = deepcopy(session.__dict__)
        preserved_tail_tokens = self.budget_service.counter.count_request(
            self._provider_messages(retained_messages, None),
            tools,
        ).tokens
        reduction = round((tokens_before - tokens_after) / tokens_before * 100)
        last_compaction = LastCompaction(
            compaction_id=compaction_id,
            completed_at=local_timestamp(),
            tokens_before=tokens_before,
            tokens_after=tokens_after,
            reduction_percent=reduction,
            working_summary_tokens=summary.token_count,
            preserved_tail_tokens=preserved_tail_tokens,
        )
        session.messages = retained_messages
        session.working_summary = summary
        session.context_state.last_compaction = last_compaction
        session.context_state.last_compaction_status = "completed"
        if self.session_saver is not None:
            saved = self.session_saver(session)
            if inspect.isawaitable(saved):
                saved = await saved
            if not saved:
                session.__dict__.clear()
                session.__dict__.update(original)
                self._record_terminal_event(
                    session,
                    "context.compaction_failed",
                    compaction_id,
                    tokens_before,
                    tokens_before,
                    "session_save_failed",
                )
                return CompactionResult(
                    status="failed",
                    tokens_before=tokens_before,
                    tokens_after=tokens_before,
                    reason="session_save_failed",
                    compaction_id=compaction_id,
                )

        memory_error = ""
        try:
            memory_result = self.memory_vault_store.accept_candidates(
                session.chat_id,
                candidates,
                allowed_event_ids=allowed_event_ids,
            )
            accepted_memory = memory_result.accepted
            rejected_memory = memory_result.rejected
        except Exception as exc:
            logger.exception(
                "Memory candidates could not be persisted: chat_id=%s compaction_id=%s",
                session.chat_id,
                compaction_id,
            )
            accepted_memory = 0
            rejected_memory = len(candidates)
            memory_error = str(exc)

        self.event_store.append(
            session.chat_id,
            "context.compaction_completed",
            {
                "compaction_id": compaction_id,
                "tokens_before": tokens_before,
                "working_summary_tokens": summary.token_count,
                "preserved_tail_tokens": preserved_tail_tokens,
                "tokens_after": tokens_after,
                "reduction_percent": reduction,
                "compressed_event_ids": self._message_event_ids(compressed_messages),
                "memory_candidates_accepted": accepted_memory,
                "memory_candidates_rejected": rejected_memory,
                "memory_error": memory_error,
                "token_count_method": self.budget_service.counter.method,
            },
            turn_id=self._active_turn_id(session),
        )
        logger.info(
            "Context compaction completed: chat_id=%s compaction_id=%s "
            "tokens_before=%d working_summary_tokens=%d preserved_tail_tokens=%d "
            "tokens_after=%d reduction_percent=%d token_count_method=%s",
            session.chat_id,
            compaction_id,
            tokens_before,
            summary.token_count,
            preserved_tail_tokens,
            tokens_after,
            reduction,
            self.budget_service.counter.method,
        )
        return CompactionResult(
            status="completed",
            tokens_before=tokens_before,
            tokens_after=tokens_after,
            working_summary_tokens=summary.token_count,
            preserved_tail_tokens=preserved_tail_tokens,
            reduction_percent=reduction,
            compaction_id=compaction_id,
        )

    def _select_cut_index(
        self,
        session: AgentSession,
        tools: list[dict[str, Any]],
    ) -> int | None:
        starts = [
            index
            for index, message in enumerate(session.messages)
            if index > 0 and message.get("role") == "user"
        ]
        if not starts:
            return None
        active_start = len(session.messages)
        active_turn_id = self._active_turn_id(session)
        if active_turn_id is not None:
            for index in starts:
                if session.messages[index].get("_chatdome_turn_id") == active_turn_id:
                    active_start = index
                    break
        completed_starts = [index for index in starts if index < active_start]
        if len(completed_starts) <= 2:
            return None
        preserve_count = 2
        tail_budget = int(self.budget_service.limit_tokens * 0.30)
        for candidate_count in range(3, min(4, len(completed_starts)) + 1):
            candidate_start = completed_starts[-candidate_count]
            tail = [session.messages[0], *session.messages[candidate_start:]]
            tail_tokens = self.budget_service.counter.count_messages(
                self._provider_messages(tail, None)
            ).tokens
            if tail_tokens <= tail_budget:
                preserve_count = candidate_count
            else:
                break
        cut_index = completed_starts[-preserve_count]
        return cut_index if cut_index > 1 else None

    def _build_prompt(
        self,
        session: AgentSession,
        compressed_messages: list[dict[str, Any]],
        retained_messages: list[dict[str, Any]],
    ) -> str:
        payload = {
            "existing_working_summary": (
                session.working_summary.to_dict() if session.working_summary is not None else None
            ),
            "history_to_compress": self._provider_messages(compressed_messages, None),
            "preserved_tail_reference": self._provider_messages(retained_messages[1:], None),
            "allowed_event_ids": sorted(self._allowed_event_ids(session)),
        }
        return redact_sensitive_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))

    @staticmethod
    def _parse_response(response: Any) -> tuple[WorkingSummary, list[MemoryCandidate]]:
        finish_reason = str(getattr(response, "finish_reason", "") or "").strip().lower()
        if finish_reason not in _COMPLETE_FINISH_REASONS:
            raise ValueError(f"incomplete_finish_reason:{finish_reason or 'missing'}")
        content = str(getattr(response, "content", "") or "").strip()
        if content.startswith("```"):
            lines = content.splitlines()
            content = "\n".join(lines[1:-1]).strip()
        payload = json.loads(content)
        if not isinstance(payload, dict):
            raise ValueError("response_must_be_object")
        summary = WorkingSummary.from_dict(payload.get("working_summary"))
        raw_candidates = payload.get("memory_candidates", [])
        if not isinstance(raw_candidates, list):
            raise ValueError("memory_candidates_must_be_list")
        candidates = [MemoryCandidate.from_value(item) for item in raw_candidates]
        return summary, candidates

    @staticmethod
    def _validate_summary(
        previous: WorkingSummary | None,
        summary: WorkingSummary,
        allowed_event_ids: set[str],
    ) -> None:
        source_ids = set(summary.all_source_event_ids())
        if allowed_event_ids and not source_ids:
            raise ValueError("working_summary_missing_sources")
        if not source_ids.issubset(allowed_event_ids):
            raise ValueError("working_summary_unknown_source")
        if previous is None:
            return
        for field_name in ("pending", "user_constraints"):
            previous_items = {
                " ".join(item.text.casefold().split())
                for item in getattr(previous, field_name)
            }
            current_items = {
                " ".join(item.text.casefold().split())
                for item in getattr(summary, field_name)
            }
            if not previous_items.issubset(current_items):
                raise ValueError(f"working_summary_lost_{field_name}")

    def _reject(
        self,
        session: AgentSession,
        compaction_id: str,
        tokens_before: int,
        reason: str,
    ) -> CompactionResult:
        self._record_terminal_event(
            session,
            "context.compaction_rejected",
            compaction_id,
            tokens_before,
            tokens_before,
            reason,
        )
        return CompactionResult(
            status="rejected",
            tokens_before=tokens_before,
            tokens_after=tokens_before,
            reason=reason,
            compaction_id=compaction_id,
        )

    def _record_terminal_event(
        self,
        session: AgentSession,
        event_type: str,
        compaction_id: str,
        tokens_before: int,
        tokens_after: int,
        reason: str,
    ) -> None:
        try:
            self.event_store.append(
                session.chat_id,
                event_type,
                {
                    "compaction_id": compaction_id,
                    "tokens_before": tokens_before,
                    "tokens_after": tokens_after,
                    "reason": reason,
                    "token_count_method": self.budget_service.counter.method,
                },
                turn_id=self._active_turn_id(session),
            )
        except OSError:
            logger.exception(
                "Failed to persist compaction terminal event: chat_id=%s compaction_id=%s",
                session.chat_id,
                compaction_id,
            )

    @staticmethod
    def _provider_messages(
        messages: list[dict[str, Any]],
        summary: WorkingSummary | None,
        *,
        transient_contexts: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for index, item in enumerate(messages):
            result.append(
                {
                    key: value
                    for key, value in item.items()
                    if not str(key).startswith("_chatdome_")
                }
            )
            if index == 0 and summary is not None:
                result.append({"role": "system", "content": summary.to_prompt_block()})
            if index == 0:
                result.extend(
                    {"role": "system", "content": block}
                    for block in (transient_contexts or [])
                    if block
                )
        return result

    @staticmethod
    def _message_event_ids(messages: list[dict[str, Any]]) -> list[str]:
        result: list[str] = []
        for message in messages:
            event_id = message.get("_chatdome_event_id")
            if isinstance(event_id, str) and event_id and event_id not in result:
                result.append(event_id)
        return result

    def _allowed_event_ids(self, session: AgentSession) -> set[str]:
        result = set(self._message_event_ids(session.messages))
        if session.working_summary is not None:
            result.update(session.working_summary.all_source_event_ids())
        return result

    @staticmethod
    def _active_turn_id(session: AgentSession) -> int | None:
        return session.active_turn.turn_id if session.active_turn is not None else None

    @staticmethod
    async def _publish_progress(callback: Any, stage: str) -> None:
        if not callable(callback):
            return
        result = callback(stage)
        if inspect.isawaitable(result):
            await result
