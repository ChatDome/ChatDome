"""
AI Agent core — ReAct loop implementation.

Orchestrates the cycle:
  User message → LLM → tool_calls → execute → feed results → LLM → ... → final reply
"""

from __future__ import annotations

import asyncio
import json
import logging
import inspect
import secrets
import time
from datetime import datetime
from typing import Any

from chatdome.agent.approval_input import (
    ApprovalInputDecision,
    classify_approval_input,
)
from chatdome.agent.audit import CommandAuditTracker
from chatdome.agent.context_budget import ContextBudgetService, ContextTokenCounter
from chatdome.agent.context_compactor import CompactionResult, ContextCompactor
from chatdome.agent.context_retrieval import ContextRetrievalPolicy
from chatdome.agent.global_turn import GlobalTurnCoordinator, GlobalTurnLease
from chatdome.agent.prompts import build_system_prompt, build_tools
from chatdome.agent.result import AgentResult, coerce_agent_result
from chatdome.agent.session import ClearSessionResult, SessionManager
from chatdome.agent.tools import ToolDispatcher
from chatdome.agent.turns import TurnContext
from chatdome.config import AgentConfig
from chatdome.errors import LLMProfileNotReady, user_facing_error_message
from chatdome.executor.sandbox import CommandSandbox
from chatdome.llm.client import LLMClient
from chatdome.llm.manager import LLMManager, LLMSnapshot
from chatdome.logger import log_context
from chatdome.outbound.policy import has_meaningful_approval_reason

logger = logging.getLogger(__name__)


class Agent:
    """
    The AI Agent that drives the ReAct loop.

    Receives user messages, manages sessions, calls the LLM,
    dispatches tool calls, and produces final responses.
    """

    DUPLICATE_TOOL_STOP_THRESHOLD = 3
    DUPLICATE_TOOL_RESULT_MAX_CHARS = 1800

    def __init__(
        self,
        llm: LLMClient | None,
        sandbox: CommandSandbox,
        config: AgentConfig,
        runtime_environment_context: str = "",
        user_context_ledger: Any = None,
        engram_store: 'Any' = None,
        llm_manager: LLMManager | None = None,
        global_turn_coordinator: GlobalTurnCoordinator | None = None,
    ):
        self.llm = llm
        self.llm_manager = llm_manager
        self.config = config
        self.global_turn_coordinator = global_turn_coordinator or GlobalTurnCoordinator()
        self._global_turn_lease: GlobalTurnLease | None = None
        self._global_turn_chat_id: int | None = None
        self._global_turn_release_pending_chat_id: int | None = None
        self.tools = build_tools()
        self.tool_dispatcher = ToolDispatcher(
            sandbox,
            llm=llm,
            user_context_ledger=user_context_ledger,
            engram_store=engram_store,
            command_approval_mode=config.command_approval_mode,
        )
        self.session_manager = SessionManager(
            session_timeout=config.session_timeout,
            pending_approval_timeout=config.pending_approval_timeout,
            persisted_session_ttl=config.persisted_session_ttl,
            max_history_tokens=config.max_history_tokens,
            event_retention_days=getattr(config, "event_retention_days", 30),
            system_prompt=build_system_prompt(
                runtime_environment_context=runtime_environment_context,
            ),
            engram_store=engram_store,
        )
        self.event_store = self.session_manager.event_store
        self.memory_vault_store = self.session_manager.memory_vault_store
        self.context_retrieval_policy = ContextRetrievalPolicy()
        counter = ContextTokenCounter(model=getattr(llm, "model", ""))
        self.context_budget_service = ContextBudgetService(
            counter,
            limit_tokens=config.max_history_tokens,
            target_ratio=0.70,
        )
        self.memory_vault_store.token_counter = counter
        self.context_compactor = ContextCompactor(
            budget_service=self.context_budget_service,
            event_store=self.event_store,
            memory_vault_store=self.memory_vault_store,
            session_saver=self.session_manager.save_session,
        )
        if hasattr(self.tool_dispatcher, "set_session_manager"):
            self.tool_dispatcher.set_session_manager(self.session_manager)

    async def get_active_llm_snapshot(self) -> LLMSnapshot:
        """Return the LLM snapshot for a new user-facing run."""
        llm_manager = getattr(self, "llm_manager", None)
        if llm_manager is not None:
            snapshot = await llm_manager.get_active_snapshot()
            # Keep legacy attributes coherent for code paths/tests that inspect agent.llm.
            self.llm = snapshot.client
            self.tool_dispatcher.llm = snapshot.client
            return snapshot
        if self.llm is None:
            raise LLMProfileNotReady("No LLM client is configured.")
        return LLMSnapshot(profile_name="legacy", client=self.llm, profile=None)

    async def _llm_unavailable_message(self, exc: Exception) -> str:
        logger.error("LLM profile is not ready: %s", exc)
        detail = user_facing_error_message(exc, fallback="LLM is currently unavailable, please try again later.")
        return f"⚠️ {detail}"

    @staticmethod
    async def _publish_progress(progress_callback: Any, stage: str) -> None:
        if not callable(progress_callback):
            return
        try:
            published = progress_callback(stage)
            if inspect.isawaitable(published):
                await published
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.debug("Failed to publish agent progress stage=%s", stage, exc_info=True)

    def _append_context_event(
        self,
        session: Any,
        event_type: str,
        payload: dict[str, Any],
        *,
        source: str = "chatdome",
    ) -> str | None:
        store = getattr(self, "event_store", None) or getattr(
            getattr(self, "session_manager", None),
            "event_store",
            None,
        )
        if store is None:
            return None
        active_turn = getattr(session, "active_turn", None)
        try:
            event = store.append(
                session.chat_id,
                event_type,
                payload,
                turn_id=(active_turn.turn_id if active_turn is not None else None),
                source=source,
            )
            return event.event_id
        except OSError:
            logger.exception(
                "Context event persistence failed: chat_id=%s event_type=%s",
                getattr(session, "chat_id", "?"),
                event_type,
            )
            return None

    def _add_user_message(
        self,
        session: Any,
        content: str,
        *,
        turn_id: int | None = None,
        source: str = "unknown",
    ) -> str | None:
        event_id = self._append_context_event(
            session,
            "message.user",
            {"content": content},
            source=source,
        )
        try:
            session.add_user_message(content, turn_id=turn_id, event_id=event_id)
        except TypeError:
            session.add_user_message(content, turn_id=turn_id)
        return event_id

    def _add_assistant_message(self, session: Any, content: str) -> str | None:
        event_id = self._append_context_event(
            session,
            "message.assistant",
            {"content": content},
        )
        try:
            session.add_assistant_message(content, event_id=event_id)
        except TypeError:
            session.add_assistant_message(content)
        return event_id

    def _add_assistant_tool_calls(
        self,
        session: Any,
        tool_calls: list[dict[str, Any]],
    ) -> str | None:
        event_id = self._append_context_event(
            session,
            "tool.call",
            {"tool_calls": tool_calls},
        )
        try:
            session.add_assistant_tool_calls(tool_calls, event_id=event_id)
        except TypeError:
            session.add_assistant_tool_calls(tool_calls)
        return event_id

    def _add_tool_result(
        self,
        session: Any,
        tool_call_id: str,
        content: str,
    ) -> str | None:
        text = str(content or "")
        max_event_chars = 20_000
        payload = {
            "tool_call_id": tool_call_id,
            "content": text[:max_event_chars],
            "truncated": len(text) > max_event_chars,
            "original_chars": len(text),
        }
        event_id = self._append_context_event(session, "tool.result", payload)
        try:
            session.add_tool_result(tool_call_id, content, event_id=event_id)
        except TypeError:
            session.add_tool_result(tool_call_id, content)
        return event_id

    def _configure_context_counter(self, llm: Any) -> None:
        service = getattr(self, "context_budget_service", None)
        compactor = getattr(self, "context_compactor", None)
        if service is None or compactor is None:
            return
        model = str(getattr(llm, "model", "") or "")
        if service.counter.model == model:
            return
        counter = ContextTokenCounter(model=model)
        service.counter = counter
        memory_store = getattr(self, "memory_vault_store", None)
        if memory_store is not None:
            memory_store.token_counter = counter

    def refresh_context_settings(self) -> None:
        """Apply reloadable context limits to the active runtime services."""
        limit_tokens = max(1, int(getattr(self.config, "max_history_tokens", 32_000)))
        retention_days = max(0, int(getattr(self.config, "event_retention_days", 30)))
        self.session_manager.max_history_tokens = limit_tokens
        self.session_manager.event_store.retention_days = retention_days
        service = getattr(self, "context_budget_service", None)
        if service is not None:
            service.limit_tokens = limit_tokens
            service.target_tokens = max(1, int(limit_tokens * 0.70))

    async def _ensure_context_budget(
        self,
        *,
        session: Any,
        snapshot: LLMSnapshot,
        progress_callback: Any,
        trigger_reason: str,
    ) -> CompactionResult | None:
        compactor = getattr(self, "context_compactor", None)
        if compactor is None:
            return None
        self._configure_context_counter(snapshot.client)
        result = await compactor.ensure_budget(
            session,
            snapshot.client,
            tools=self.tools,
            trigger_reason=trigger_reason,
            progress_callback=progress_callback,
        )
        logger.info(
            "Context budget preflight: chat_id=%s trigger_reason=%s status=%s "
            "tokens_before=%d working_summary_tokens=%d preserved_tail_tokens=%d "
            "tokens_after=%d reduction_percent=%d token_count_method=%s",
            getattr(session, "chat_id", "?"),
            trigger_reason,
            result.status,
            result.tokens_before,
            result.working_summary_tokens,
            result.preserved_tail_tokens,
            result.tokens_after,
            result.reduction_percent,
            compactor.budget_service.counter.method,
        )
        return result

    def _prepare_context_retrieval(
        self,
        session: Any,
        user_text: str,
        *,
        current_event_id: str | None,
    ) -> None:
        if hasattr(session, "clear_transient_contexts"):
            session.clear_transient_contexts()
        policy = getattr(self, "context_retrieval_policy", None)
        store = getattr(self, "event_store", None)
        if policy is None or store is None:
            return
        decision = policy.evaluate(user_text, session)
        if not decision.should_retrieve:
            return
        retrieval_id = f"RT-{secrets.token_hex(6).upper()}"
        clear_boundary = store.latest_clear_event_id(session.chat_id)
        self._append_context_event(
            session,
            "context.retrieval_triggered",
            {
                "retrieval_id": retrieval_id,
                "trigger_reason": decision.reason,
                "query": decision.query,
                "clear_boundary_event_id": clear_boundary,
            },
        )
        try:
            result = store.search(session.chat_id, decision.query, limit=6)
            matches = [
                event
                for event in result.matches
                if event.event_id != current_event_id
            ][:5]
            hit_ids = [event.event_id for event in matches]
            if matches and hasattr(session, "set_transient_contexts"):
                payload = {
                    "retrieval_id": retrieval_id,
                    "matches": [
                        {
                            "event_id": event.event_id,
                            "timestamp": event.timestamp,
                            "type": event.type,
                            "excerpt": str(
                                event.payload.get("content")
                                or json.dumps(event.payload, ensure_ascii=False)
                            )[:900],
                        }
                        for event in matches
                    ],
                }
                session.set_transient_contexts(
                    [
                        "[Retrieved Session Events - 临时历史证据，仅供当前回合参考]\n"
                        + json.dumps(payload, ensure_ascii=False, indent=2)
                    ]
                )
            self._append_context_event(
                session,
                "context.retrieval_completed",
                {
                    "retrieval_id": retrieval_id,
                    "trigger_reason": decision.reason,
                    "query": decision.query,
                    "clear_boundary_event_id": result.clear_boundary_event_id,
                    "match_count": len(matches),
                    "hit_event_ids": hit_ids,
                },
            )
            logger.info(
                "Context retrieval completed: chat_id=%s retrieval_id=%s "
                "trigger_reason=%s query=%s clear_boundary_event_id=%s "
                "match_count=%d hit_event_ids=%s",
                session.chat_id,
                retrieval_id,
                decision.reason,
                json.dumps(decision.query, ensure_ascii=False),
                result.clear_boundary_event_id or "-",
                len(matches),
                ",".join(hit_ids) or "-",
            )
        except Exception as exc:
            self._append_context_event(
                session,
                "context.retrieval_failed",
                {
                    "retrieval_id": retrieval_id,
                    "trigger_reason": decision.reason,
                    "query": decision.query,
                    "reason": str(exc),
                },
            )
            logger.exception(
                "Context retrieval failed: chat_id=%s retrieval_id=%s trigger_reason=%s",
                session.chat_id,
                retrieval_id,
                decision.reason,
            )

    async def _run_loop_compat(
        self,
        chat_id: int,
        session: Any,
        snapshot: LLMSnapshot,
        turn_context: TurnContext | None = None,
        progress_callback: Any = None,
    ) -> AgentResult:
        """Call _run_loop while tolerating older test doubles without snapshot."""
        try:
            params = inspect.signature(self._run_loop).parameters
        except (TypeError, ValueError):
            params = {}
        if "snapshot" not in params:
            return coerce_agent_result(await self._run_loop(chat_id, session))

        kwargs: dict[str, Any] = {}
        if "turn_context" in params:
            kwargs["turn_context"] = turn_context
        if "progress_callback" in params:
            kwargs["progress_callback"] = progress_callback
        return coerce_agent_result(
            await self._run_loop(chat_id, session, snapshot, **kwargs)
        )

    async def _dispatch_tool_compat(
        self,
        tool_name: str,
        arguments: str,
        tool_call_id: str,
        chat_id: int,
        llm: Any,
    ) -> str:
        """Call ToolDispatcher.dispatch while tolerating older test doubles."""
        dispatch = self.tool_dispatcher.dispatch
        try:
            params = inspect.signature(dispatch).parameters
        except (TypeError, ValueError):
            params = {}
        if "llm" in params:
            return await dispatch(tool_name, arguments, tool_call_id, chat_id, llm=llm)
        return await dispatch(tool_name, arguments, tool_call_id, chat_id)

    def set_sentinel(self, sentinel: Any) -> None:
        """Inject Sentinel scheduler tools after runtime wiring."""
        self.tool_dispatcher.set_sentinel(sentinel)

    def _persist_session(self, session: Any) -> None:
        """Best-effort persistence for session durability."""
        try:
            self.session_manager.save_session(session)
        except Exception as e:
            logger.warning("Session persistence failed for chat_id=%s: %s", getattr(session, "chat_id", "?"), e)
            return
        if (
            getattr(self, "_global_turn_release_pending_chat_id", None)
            == getattr(session, "chat_id", None)
            and getattr(session, "active_turn", None) is None
        ):
            self._global_turn_release_pending_chat_id = None
            self._release_global_turn_lease(getattr(session, "chat_id", None))

    @staticmethod
    def _latest_user_message(session: Any) -> str:
        """Return the latest persisted user message for legacy turn recovery."""
        return next(
            (
                str(message.get("content") or "")
                for message in reversed(getattr(session, "messages", []))
                if isinstance(message, dict) and message.get("role") == "user"
            ),
            "",
        )

    def _record_turn_started(self, session: Any) -> None:
        active_turn = getattr(session, "active_turn", None)
        if active_turn is None:
            return
        session.add_control_event(
            {
                "event_type": "turn_started",
                "turn_id": active_turn.turn_id,
                "user_id": active_turn.user_id,
                "state": active_turn.state,
                "round_count": session.round_count,
            }
        )
        logger.info("Turn started")

    def _transition_turn(self, session: Any, state: str) -> None:
        active_turn = getattr(session, "active_turn", None)
        if active_turn is None or active_turn.state == state:
            return
        previous_state = active_turn.state
        transitioned = session.transition_turn(state)
        session.add_control_event(
            {
                "event_type": "turn_state_changed",
                "turn_id": transitioned.turn_id,
                "from_state": previous_state,
                "state": transitioned.state,
                "round_count": session.round_count,
            }
        )
        logger.info("Turn state changed: %s -> %s", previous_state, state)
        self._update_global_turn_lease(session)

    def _finish_turn(self, session: Any, outcome: str) -> None:
        if getattr(session, "active_turn", None) is None:
            return
        completed = session.finish_turn(outcome)
        session.add_control_event(
            {
                "event_type": "turn_completed",
                "turn_id": completed.turn_id,
                "outcome": completed.state,
                "round_count": session.round_count,
            }
        )
        logger.info("Turn completed: outcome=%s rounds=%d", outcome, session.round_count)
        if hasattr(session, "clear_transient_contexts"):
            session.clear_transient_contexts()
        self._global_turn_release_pending_chat_id = session.chat_id

    def _claim_global_turn(
        self,
        session: Any,
        *,
        source: str,
        user_id: int | None,
    ) -> bool:
        """Claim or reuse the process-safe lease before mutating a turn."""
        return self._claim_global_turn_identity(
            session.chat_id,
            source=source,
            user_id=user_id,
        )

    def _claim_global_turn_identity(
        self,
        chat_id: int,
        *,
        source: str,
        user_id: int | None,
    ) -> bool:
        """Claim a lease without loading or creating a session."""
        lease = getattr(self, "_global_turn_lease", None)
        owner_chat_id = getattr(self, "_global_turn_chat_id", None)
        if lease is not None:
            return owner_chat_id == chat_id
        coordinator = getattr(self, "global_turn_coordinator", None)
        if coordinator is None:
            return True
        lease = coordinator.try_acquire(source, chat_id, user_id)
        if lease is None:
            return False
        self._global_turn_lease = lease
        self._global_turn_chat_id = chat_id
        return True

    def _recover_global_turn_lease(self) -> None:
        """Reclaim the newest persisted waiting turn after process restart."""
        if getattr(self, "_global_turn_lease", None) is not None:
            return
        store_dir = getattr(self.session_manager, "_session_store_dir", None)
        if store_dir is None or not hasattr(store_dir, "glob"):
            return
        candidates: list[tuple[float, int]] = []
        try:
            paths = list(store_dir.glob("*.json"))
        except (AttributeError, OSError):
            return
        for path in paths:
            try:
                chat_id = int(path.stem)
                document = json.loads(path.read_text(encoding="utf-8"))
                raw_saved_at = document.get("saved_at", 0) if isinstance(document, dict) else 0
                try:
                    saved_at = float(raw_saved_at)
                except (TypeError, ValueError):
                    saved_at = datetime.fromisoformat(str(raw_saved_at)).timestamp()
                session = self.session_manager.load_persisted_session(chat_id)
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                continue
            if session is not None and (
                session.pending_approval or session.pending_round_limit
            ):
                candidates.append((saved_at, chat_id))
        if not candidates:
            return

        candidates.sort(reverse=True)
        selected_chat_id = candidates[0][1]
        selected_session = self.session_manager.load_persisted_session(selected_chat_id)
        active_turn = getattr(selected_session, "active_turn", None)
        user_id = active_turn.user_id if active_turn is not None else None
        if not self._claim_global_turn_identity(
            selected_chat_id,
            source="recovered",
            user_id=user_id,
        ):
            return
        selected_session = self.session_manager.get_or_create(selected_chat_id)
        if not (
            selected_session.pending_approval
            or selected_session.pending_round_limit
        ):
            self._release_global_turn_lease(selected_chat_id)
            self._recover_global_turn_lease()
            return
        self._update_global_turn_lease(selected_session)

        for _, chat_id in candidates[1:]:
            session = self.session_manager.get_or_create(chat_id)
            session.clear_pending_state()
            session.clear_pending_round_limit()
            session.take_deferred_message()
            if session.active_turn is not None:
                self._finish_turn(session, "cancelled")
            self._persist_session(session)
            logger.warning(
                "Cancelled extra persisted waiting turn during global recovery: chat_id=%d",
                chat_id,
            )
        logger.info("Recovered global waiting turn: chat_id=%d", selected_chat_id)

    def _update_global_turn_lease(self, session: Any) -> None:
        lease = getattr(self, "_global_turn_lease", None)
        if lease is None or getattr(self, "_global_turn_chat_id", None) != session.chat_id:
            return
        active_turn = getattr(session, "active_turn", None)
        if active_turn is not None:
            lease.update(active_turn.turn_id, active_turn.state)

    def _release_global_turn_lease(self, chat_id: int | None = None) -> None:
        lease = getattr(self, "_global_turn_lease", None)
        if lease is None:
            return
        if chat_id is not None and getattr(self, "_global_turn_chat_id", None) != chat_id:
            return
        self._global_turn_lease = None
        self._global_turn_chat_id = None
        self._global_turn_release_pending_chat_id = None
        lease.release()

    @staticmethod
    def _global_turn_busy_result() -> AgentResult:
        return AgentResult.reply("已有任务正在执行。请等待当前任务完成或取消后再试。")

    @staticmethod
    def _release_deferred_after_terminal(
        session: Any,
        result: AgentResult,
    ) -> AgentResult:
        """Attach deferred input only after the active turn has ended."""
        if getattr(session, "active_turn", None) is not None:
            return result
        deferred_message, deferred_user_id = session.peek_deferred_input()
        if not deferred_message:
            return result
        payload = dict(result.payload)
        payload["deferred_user_message"] = deferred_message
        payload["deferred_user_id"] = deferred_user_id
        return AgentResult(
            kind=result.kind,
            content=result.content,
            payload=payload,
        )

    def _ensure_active_turn(self, session: Any, state: str) -> TurnContext:
        """Recover a lifecycle for legacy in-memory pending state."""
        context = session.current_turn_context()
        if context is None:
            context = session.begin_turn(self._latest_user_message(session))
            with log_context(
                chat_id=session.chat_id,
                user_id=context.user_id,
                turn_id=context.turn_id,
            ):
                self._record_turn_started(session)
        self._transition_turn(session, state)
        return context

    async def _run_session_task_scope(self, chat_id: int, session: Any, runner: Any) -> Any:
        """Guard a live agent task against concurrent visible-context writes."""
        was_running = bool(getattr(session, "agent_running", False))
        session.agent_running = True
        try:
            return await runner()
        except asyncio.CancelledError:
            session.task_auto_approve = False
            session.clear_pending_state()
            session.clear_pending_round_limit()
            session.take_deferred_message()
            self._finish_turn(session, "cancelled")
            self._persist_session(session)
            raise
        except Exception:
            session.task_auto_approve = False
            session.clear_pending_state()
            session.clear_pending_round_limit()
            session.take_deferred_message()
            self._finish_turn(session, "failed")
            self._persist_session(session)
            raise
        finally:
            if was_running:
                session.agent_running = True
            else:
                session.agent_running = False
                flushed = session.flush_deferred_visible_contexts()
                if flushed:
                    logger.info("Flushed %d deferred visible contexts for chat_id=%d", flushed, chat_id)
                retained = session.deferred_visible_context_count()
                if retained:
                    logger.info("Retained %d deferred visible contexts for chat_id=%d", retained, chat_id)
                self._persist_session(session)

    @staticmethod
    def _new_approval_id() -> str:
        """Generate a short user-facing approval identifier."""
        return f"AP-{time.strftime('%Y%m%d-%H%M%S', time.localtime())}-{secrets.token_hex(3).upper()}"

    @staticmethod
    def _command_hash(command: str | None) -> str:
        """Stable command digest used to bind approval to exactly one command."""
        normalized = (command or "").strip()
        return CommandAuditTracker.sha256_text(normalized)

    @staticmethod
    def _canonical_tool_arguments(arguments_json: str | None) -> str:
        """Return a stable representation for tool-call arguments."""
        raw = arguments_json or ""
        try:
            parsed = LLMClient.parse_json_object(raw) if raw else {}
        except Exception:
            parsed = {"__raw_arguments__": raw}
        return json.dumps(parsed, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    @classmethod
    def _tool_call_signature(cls, tool_name: str, arguments_json: str | None) -> str:
        """Stable identity for duplicate tool-call detection."""
        return f"{tool_name}:{cls._canonical_tool_arguments(arguments_json)}"

    @staticmethod
    def _truncate_tool_text(text: str | None, max_chars: int) -> str:
        """Keep cached tool output small when feeding duplicate guard messages."""
        value = str(text or "").strip()
        if len(value) <= max_chars:
            return value
        return value[: max_chars - 20].rstrip() + "\n... (truncated)"

    @classmethod
    def _tool_call_stats_since_last_user(cls, session: Any) -> tuple[dict[str, int], dict[str, str]]:
        """Count trailing completed tool calls and cache latest results for this turn."""
        messages = getattr(session, "messages", []) or []
        last_user_index = -1
        for idx, msg in enumerate(messages):
            if msg.get("role") == "user":
                last_user_index = idx

        tool_signature_order: list[str] = []
        latest_results: dict[str, str] = {}
        call_id_to_signature: dict[str, str] = {}

        for msg in messages[last_user_index + 1:]:
            if msg.get("tool_calls"):
                for tc in msg.get("tool_calls", []) or []:
                    function = tc.get("function", {}) if isinstance(tc, dict) else {}
                    signature = cls._tool_call_signature(
                        str(function.get("name", "")),
                        str(function.get("arguments", "") or ""),
                    )
                    call_id = str(tc.get("call_id") or tc.get("id", "") or "")
                    if call_id:
                        call_id_to_signature[call_id] = signature
                    response_id = str(tc.get("id", "") or "")
                    if response_id:
                        call_id_to_signature[response_id] = signature
                continue

            if msg.get("role") == "tool":
                signature = call_id_to_signature.get(str(msg.get("tool_call_id", "") or ""))
                if signature:
                    content = str(msg.get("content", "") or "")
                    if not cls._tool_result_counts_for_duplicate_guard(content):
                        continue
                    tool_signature_order.append(signature)
                    if cls._is_duplicate_tool_result(content):
                        latest_results.setdefault(signature, content)
                    else:
                        latest_results[signature] = content
        consecutive_counts: dict[str, int] = {}
        if tool_signature_order:
            last_signature = tool_signature_order[-1]
            count = 0
            for signature in reversed(tool_signature_order):
                if signature != last_signature:
                    break
                count += 1
            consecutive_counts[last_signature] = count

        return consecutive_counts, latest_results

    @staticmethod
    def _is_duplicate_tool_result(content: str | None) -> bool:
        return str(content or "").lstrip().startswith("[Duplicate tool call suppressed]")

    @staticmethod
    def _tool_result_counts_for_duplicate_guard(content: str | None) -> bool:
        text = str(content or "").strip()
        if not text:
            return False
        ignored_prefixes = (
            "Tool call was not executed because an earlier command is waiting for user approval.",
            "Legacy tool output was missing from the persisted session.",
        )
        return not any(text.startswith(prefix) for prefix in ignored_prefixes)

    @classmethod
    def _duplicate_tool_result(cls, signature: str, repeat_count: int, cached_result: str | None) -> str:
        """Tool result used when an identical call is requested again."""
        label = signature[:300]
        cached = cls._truncate_tool_text(cached_result, cls.DUPLICATE_TOOL_RESULT_MAX_CHARS)
        if cached:
            return (
                "[Duplicate tool call suppressed]\n"
                f"The model requested the same tool call again (repeat_count={repeat_count}). "
                "ChatDome did not execute the command again. Use the previous result below.\n"
                f"signature={label}\n\n"
                f"[Previous result]\n{cached}"
            )
        return (
            "[Duplicate tool call suppressed]\n"
            f"The model requested the same tool call again (repeat_count={repeat_count}). "
            "ChatDome did not execute the command again. Use the existing conversation context."
        )

    @classmethod
    def _tool_storm_final_response(
        cls,
        signature: str,
        repeat_count: int,
        cached_result: str | None,
    ) -> str:
        """Deterministic final response when the model loops on the same tool call."""
        label = signature[:300]
        cached = cls._truncate_tool_text(cached_result, 1200)
        lines = [
            "检测到重复工具调用，已停止继续执行，避免命令风暴和 token 继续消耗。",
            "",
            f"重复次数: {repeat_count}",
            f"工具签名: {label}",
        ]
        if cached:
            lines.extend(["", "最近一次工具结果摘录:", cached])
        lines.extend([
            "",
            "请基于上面的已有结果判断；如果还需要继续，请发送更具体的新指令，或使用 /clear 开始一个新任务。",
        ])
        return "\n".join(lines)

    async def handle_message(
        self,
        chat_id: int,
        user_message: str,
        *,
        user_id: int | None = None,
        progress_callback: Any = None,
        deferred: bool = False,
        source: str = "unknown",
    ) -> AgentResult:
        """Process a user message through the full ReAct loop."""
        if not self._claim_global_turn_identity(
            chat_id,
            source=source,
            user_id=user_id,
        ):
            return self._global_turn_busy_result()
        session = self.session_manager.get_or_create(chat_id)
        turn_lock = self.session_manager.get_turn_lock(chat_id)
        route = "new"
        turn_context: TurnContext | None = None
        async with turn_lock:
            if session.repair_missing_tool_outputs():
                self._persist_session(session)
            if (
                deferred
                and not session.pending_approval
                and not session.pending_round_limit
                and session.active_turn is None
            ):
                deferred_message, _ = session.peek_deferred_input()
                if deferred_message != user_message:
                    self._release_global_turn_lease(chat_id)
                    return AgentResult.reply("该暂存任务已处理。")
            needs_lease = bool(
                session.pending_approval
                or session.pending_round_limit
                or session.active_turn is None
            )
            if needs_lease:
                self._update_global_turn_lease(session)
            if session.pending_approval:
                if session.approval_processing:
                    processing_id = session.processing_approval_id or "当前命令"
                    return AgentResult(
                        kind="reply",
                        content=f"ℹ️ {processing_id} 已完成审批，正在处理中。",
                        payload={"approval_status": "processing"},
                    )
                pending_state = (
                    session.active_turn.state
                    if session.active_turn is not None
                    and session.active_turn.state
                    in {
                        "waiting_approval",
                        "answering_approval_question",
                        "waiting_approval_decision",
                    }
                    else "waiting_approval"
                )
                turn_context = self._ensure_active_turn(session, pending_state)
                route = "approval"
            elif session.pending_round_limit:
                turn_context = self._ensure_active_turn(session, "waiting_round_limit")
                route = "round_limit"
            elif session.active_turn is not None:
                return AgentResult.reply("任务正在运行。发送 /stop 中止。")
            else:
                if deferred:
                    deferred_message, deferred_user_id = session.peek_deferred_input()
                    session.take_deferred_input()
                    if deferred_user_id is not None:
                        user_id = deferred_user_id
                turn_context = session.begin_turn(user_message, user_id=user_id)
                user_event_id = self._add_user_message(
                    session,
                    user_message,
                    turn_id=turn_context.turn_id,
                    source=source,
                )
                self._prepare_context_retrieval(
                    session,
                    user_message,
                    current_event_id=user_event_id,
                )
                with log_context(
                    chat_id=chat_id,
                    user_id=turn_context.user_id,
                    turn_id=turn_context.turn_id,
                ):
                    self._record_turn_started(session)
                self._persist_session(session)

            self._update_global_turn_lease(session)

        assert turn_context is not None
        context_fields = {
            "chat_id": chat_id,
            "user_id": turn_context.user_id,
            "turn_id": turn_context.turn_id,
            "approval_id": session.pending_approval_id,
        }

        if route == "approval":
            self._append_context_event(
                session,
                "message.user",
                {"content": user_message},
                source=source,
            )
            with log_context(**context_fields):
                return await self._handle_pending_input(
                    chat_id,
                    session,
                    user_message,
                    user_id=user_id,
                )

        if route == "round_limit":
            self._append_context_event(
                session,
                "message.user",
                {"content": user_message},
                source=source,
            )
            with log_context(**context_fields):
                if self._is_reject_intent(user_message):
                    return await self.resolve_round_limit(chat_id, "ABANDON")
                if self._is_continue_intent(user_message):
                    return await self.resolve_round_limit(chat_id, "CONTINUE")
                window_limit = max(1, int(self.config.max_rounds_per_turn))
                return AgentResult.reply(
                    f"\u5f53\u524d\u4efb\u52a1\u5df2\u6267\u884c {session.pending_round_count} \u8f6e\uff0c\u4ecd\u672a\u5b8c\u6210\u3002\n"
                    f"\u8bf7\u56de\u590d\u2018\u7ee7\u7eed\u2019\u4ee5\u518d\u6267\u884c {window_limit} \u8f6e\uff0c\u6216\u56de\u590d\u2018\u653e\u5f03\u2019\u7ed3\u675f\u5f53\u524d\u4efb\u52a1\u3002"
                )

        async def run_task() -> AgentResult:
            try:
                snapshot = await self.get_active_llm_snapshot()
            except Exception as e:
                content = await self._llm_unavailable_message(e)
                self._add_assistant_message(session, content)
                self._finish_turn(session, "failed")
                self._persist_session(session)
                return AgentResult.reply(content)

            return await self._run_loop_compat(
                chat_id,
                session,
                snapshot,
                turn_context=turn_context,
                progress_callback=progress_callback,
            )

        with log_context(**context_fields):
            return await self._run_session_task_scope(chat_id, session, run_task)

    async def resolve_round_limit(self, chat_id: int, action: str) -> AgentResult:
        """Resolve a round-limit confirmation by continuing or abandoning the task."""
        if not self._claim_global_turn_identity(
            chat_id,
            source="control",
            user_id=None,
        ):
            return self._global_turn_busy_result()
        session = self.session_manager.get_or_create(chat_id)
        if not session.pending_round_limit:
            if session.active_turn is None and not session.pending_approval:
                self._release_global_turn_lease(chat_id)
            return AgentResult.reply("ℹ️ 当前没有等待继续执行的任务。")

        turn_context = self._ensure_active_turn(session, "waiting_round_limit")

        async def resolve_task() -> AgentResult:
            normalized_action = (action or "").strip().upper()
            if normalized_action == "CONTINUE":
                reached = session.pending_round_count
                session.clear_pending_round_limit()
                self._transition_turn(session, "running")
                self._persist_session(session)
                logger.info("User chose to continue task after %d rounds (chat_id=%d)", reached, chat_id)
                try:
                    snapshot = await self.get_active_llm_snapshot()
                except Exception as e:
                    content = await self._llm_unavailable_message(e)
                    self._add_assistant_message(session, content)
                    self._finish_turn(session, "failed")
                    self._persist_session(session)
                    return AgentResult.reply(content)
                return await self._run_loop_compat(
                    chat_id,
                    session,
                    snapshot,
                    turn_context=turn_context,
                )

            reached = session.pending_round_count
            session.task_auto_approve = False
            session.clear_pending_round_limit()
            final_text = f"已放弃当前任务（累计执行 {reached} 轮）。如需继续，请发送新的指令。"
            self._add_assistant_message(session, final_text)
            self._finish_turn(session, "cancelled")
            self._persist_session(session)
            logger.info("User abandoned task after %d rounds (chat_id=%d)", reached, chat_id)
            return AgentResult.reply(final_text)

        with log_context(
            chat_id=chat_id,
            user_id=turn_context.user_id,
            turn_id=turn_context.turn_id,
        ):
            return await self._run_session_task_scope(chat_id, session, resolve_task)

    async def resume_session(
        self,
        chat_id: int,
        action: str,
        approval_id: str | None = None,
    ) -> tuple[str, AgentResult]:
        """Resume a suspended session after user approval/rejection. Returns (raw_result, agent_result)."""
        if not self._claim_global_turn_identity(
            chat_id,
            source="control",
            user_id=None,
        ):
            return "", self._global_turn_busy_result()
        turn_lock = self.session_manager.get_turn_lock(chat_id)
        async with turn_lock:
            session = self.session_manager.get_or_create(chat_id)
            if not session.pending_approval and session.active_turn is None:
                self._release_global_turn_lease(chat_id)
            return await self._resume_session_locked(chat_id, action, approval_id)

    async def _resume_session_locked(
        self,
        chat_id: int,
        action: str,
        approval_id: str | None = None,
    ) -> tuple[str, AgentResult]:
        """Resolve an approval while holding the chat turn lock."""
        session = self.session_manager.get_or_create(chat_id)
        if session.approval_processing:
            processing_id = session.processing_approval_id or "当前命令"
            return "", AgentResult(
                kind="reply",
                content=f"ℹ️ {processing_id} 已完成审批，正在处理中。",
                payload={"approval_status": "processing"},
            )
        if not session.pending_approval or not session.pending_tool_call_id:
            return "", AgentResult(
                kind="reply",
                content="ℹ️ 当前没有等待确认的命令。",
                payload={"approval_status": "unavailable"},
            )

        tool_call_id = session.pending_tool_call_id
        command = session.pending_command or ""
        pending_approval_id = session.pending_approval_id or ""
        pending_command_hash = session.pending_command_hash or ""
        requested_approval_id = (approval_id or "").strip()
        normalized_action = (action or "").strip().upper()
        if normalized_action not in {"APPROVE", "REJECT"}:
            normalized_action = "REJECT"

        if requested_approval_id and pending_approval_id and requested_approval_id != pending_approval_id:
            return (
                "",
                AgentResult.reply(
                    "⚠️ 审批编号不匹配，未执行任何命令。\n\n"
                    f"当前待审批编号: {pending_approval_id}\n"
                    f"收到的审批编号: {requested_approval_id}"
                ),
            )

        if (
            normalized_action == "APPROVE"
            and not has_meaningful_approval_reason(session.pending_reason)
            and not isinstance(session.pending_analysis, dict)
        ):
            return "", AgentResult(
                kind="reply",
                content="请先使用 /details 查看当前命令分析，再决定是否执行。",
                payload={"approval_status": "review_required"},
            )

        turn_context = self._ensure_active_turn(session, "waiting_approval")

        async def resume_task() -> tuple[str, AgentResult]:
            followup_summary = self._summarize_pending_followups(session)
            turn_id = turn_context.turn_id

            current_command_hash = self._command_hash(command)
            approval_binding_complete = bool(
                pending_approval_id
                and tool_call_id
                and command
                and pending_command_hash
            )
            if normalized_action == "APPROVE" and (
                not approval_binding_complete
                or pending_command_hash != current_command_hash
            ):
                logger.warning(
                    "Pending approval command hash mismatch: approval_id=%s expected=%s actual=%s",
                    pending_approval_id,
                    pending_command_hash,
                    current_command_hash,
                )
                CommandAuditTracker.record_event(
                    "command_approval_hash_mismatch",
                    chat_id=chat_id,
                    turn_id=turn_id,
                    approval_id=pending_approval_id,
                    tool_call_id=tool_call_id,
                    command=command,
                    expected_command_hash=pending_command_hash,
                    actual_command_hash=current_command_hash,
                    approval_action=normalized_action,
                )
                session.task_auto_approve = False
                session.clear_pending_state()
                self._add_tool_result(
                    session,
                    tool_call_id,
                    "审批恢复失败：待执行命令的哈希与审批单不一致。"
                    "该命令未执行，当前任务已终止。",
                )
                final_text = "命令校验失败，任务已终止。"
                self._add_assistant_message(session, final_text)
                self._finish_turn(session, "failed")
                result = self._release_deferred_after_terminal(
                    session,
                    AgentResult.reply(final_text),
                )
                self._persist_session(session)
                return "命令校验失败，已拒绝执行。", result

            if normalized_action == "REJECT":
                session.task_auto_approve = False
                self._append_context_event(
                    session,
                    "approval.rejected",
                    {
                        "approval_id": pending_approval_id,
                        "tool_call_id": tool_call_id,
                        "command": command,
                    },
                )
                logger.info(
                    "User rejected command: approval_id=%s tool_call_id=%s command_hash=%s",
                    pending_approval_id or "-",
                    tool_call_id,
                    pending_command_hash or "-",
                )
                CommandAuditTracker.record_event(
                    "command_rejected",
                    chat_id=chat_id,
                    turn_id=turn_id,
                    approval_id=pending_approval_id,
                    tool_call_id=tool_call_id,
                    command=command,
                    command_hash=pending_command_hash,
                    approval_action="REJECT",
                )
                tool_result_for_llm = "用户已拒绝当前命令。该命令未执行，当前任务已取消。"
                if followup_summary:
                    tool_result_for_llm += (
                        "\n\n[审批等待阶段的补充对话]\n"
                        f"{followup_summary}"
                    )
                session.clear_pending_state()
                self._add_tool_result(session, tool_call_id, tool_result_for_llm)
                final_text = "已拒绝当前命令，任务已取消。"
                self._add_assistant_message(session, final_text)
                self._finish_turn(session, "cancelled")
                result = self._release_deferred_after_terminal(
                    session,
                    AgentResult.reply(final_text),
                )
                self._persist_session(session)
                return "用户已拒绝执行该命令。", result

            session.task_auto_approve = False
            self._append_context_event(
                session,
                "approval.approved",
                {
                    "approval_id": pending_approval_id,
                    "tool_call_id": tool_call_id,
                    "command": command,
                },
            )
            logger.info(
                "User approved command: approval_id=%s tool_call_id=%s command_hash=%s",
                pending_approval_id,
                tool_call_id,
                pending_command_hash,
            )
            CommandAuditTracker.record_event(
                "command_approved",
                chat_id=chat_id,
                turn_id=turn_id,
                approval_id=pending_approval_id,
                tool_call_id=tool_call_id,
                command=command,
                command_hash=pending_command_hash,
                approval_action=normalized_action,
            )
            session.clear_pending_state()
            self._transition_turn(session, "running")
            self._persist_session(session)

            try:
                res = await self.tool_dispatcher.sandbox.execute_shell_command(
                    command,
                    "User Approved",
                    chat_id=chat_id,
                    tool_call_id=tool_call_id,
                )
                raw_result = self.tool_dispatcher._format_command_result(res)
            except Exception as e:
                raw_result = f"执行过程中发生异常: {e}"

            tool_result_for_llm = raw_result
            if followup_summary:
                tool_result_for_llm += (
                    "\n\n[审批等待阶段的补充对话]\n"
                    f"{followup_summary}"
                )
            self._add_tool_result(session, tool_call_id, tool_result_for_llm)
            self._persist_session(session)

            try:
                snapshot = await self.get_active_llm_snapshot()
            except Exception as e:
                content = await self._llm_unavailable_message(e)
                self._add_assistant_message(session, content)
                self._finish_turn(session, "failed")
                result = self._release_deferred_after_terminal(
                    session,
                    AgentResult.reply(content),
                )
                self._persist_session(session)
                return raw_result, result
            final_answer = await self._run_loop_compat(
                chat_id,
                session,
                snapshot,
                turn_context=turn_context,
            )
            final_answer = self._release_deferred_after_terminal(
                session,
                final_answer,
            )
            self._persist_session(session)
            return raw_result, final_answer

        session.approval_processing = True
        session.processing_approval_id = pending_approval_id or None
        self._persist_session(session)
        try:
            with log_context(
                chat_id=chat_id,
                user_id=turn_context.user_id,
                turn_id=turn_context.turn_id,
                approval_id=pending_approval_id,
            ):
                return await self._run_session_task_scope(chat_id, session, resume_task)
        finally:
            session.approval_processing = False
            session.processing_approval_id = None
            self._persist_session(session)

    async def abort_pending_task(
        self,
        chat_id: int,
        approval_id: str | None = None,
    ) -> bool:
        """Abort a pending approval without resuming the agent loop."""
        if not self._claim_global_turn_identity(
            chat_id,
            source="control",
            user_id=None,
        ):
            return ClearSessionResult("running_task")
        session = self.session_manager.get_or_create(chat_id)
        if session.approval_processing or not session.pending_approval:
            if session.active_turn is None and not session.pending_round_limit:
                self._release_global_turn_lease(chat_id)
            return False

        pending_approval_id = session.pending_approval_id or ""
        requested_approval_id = (approval_id or "").strip()
        if requested_approval_id and pending_approval_id != requested_approval_id:
            return False

        turn_context = self._ensure_active_turn(session, "waiting_approval")
        tool_call_id = session.pending_tool_call_id or ""
        command = session.pending_command or ""
        command_hash = session.pending_command_hash or self._command_hash(command)

        if tool_call_id:
            self._add_tool_result(
                session,
                tool_call_id,
                (
                    "The user stopped the current task with /stop. This command was not "
                    "executed. Do not retry or continue it unless the user explicitly "
                    "starts a new task."
                ),
            )
        session.task_auto_approve = False
        session.clear_pending_state()
        session.clear_pending_round_limit()
        session.take_deferred_message()
        self._finish_turn(session, "cancelled")
        self._persist_session(session)

        CommandAuditTracker.record_event(
            "command_task_aborted",
            chat_id=chat_id,
            turn_id=turn_context.turn_id,
            approval_id=pending_approval_id,
            tool_call_id=tool_call_id,
            command=command,
            command_hash=command_hash,
            approval_action="ABORT",
        )
        logger.info(
            "Pending command task aborted: chat_id=%d approval_id=%s",
            chat_id,
            pending_approval_id,
        )
        return True

    async def get_pending_approval_details(
        self,
        chat_id: int,
        approval_id: str | None = None,
        include_llm: bool = True,
    ) -> dict[str, Any]:
        """
        Return full details for the currently pending approval.

        Safety analysis is computed lazily and cached in session state.
        """
        if not self._claim_global_turn_identity(
            chat_id,
            source="control",
            user_id=None,
        ):
            return {
                "ok": False,
                "message": self._global_turn_busy_result().content,
            }
        session = self.session_manager.get_or_create(chat_id)
        if not session.pending_approval or not session.pending_command:
            if session.active_turn is None and not session.pending_round_limit:
                self._release_global_turn_lease(chat_id)
            return {
                "ok": False,
                "message": "No pending command requires approval.",
            }

        requested_approval_id = (approval_id or "").strip()
        current_approval_id = session.pending_approval_id or ""
        if requested_approval_id and current_approval_id and requested_approval_id != current_approval_id:
            return {
                "ok": False,
                "message": (
                    "Approval ID mismatch. "
                    f"Current pending approval is {current_approval_id}, not {requested_approval_id}."
                ),
            }

        cached_analysis = session.pending_analysis if isinstance(session.pending_analysis, dict) else None
        cached_reviewer_mode = str((cached_analysis or {}).get("reviewer_mode", ""))
        needs_analysis = cached_analysis is None or (include_llm and cached_reviewer_mode != "llm")

        if needs_analysis:
            pending_approval_id = session.pending_approval_id or ""
            pending_command = session.pending_command or ""
            pending_command_hash = session.pending_command_hash or self._command_hash(pending_command)
            pending_reason = session.pending_reason or ""
            pending_tool_call_id = session.pending_tool_call_id or ""

            detail_llm = None
            if include_llm:
                try:
                    detail_llm = (await self.get_active_llm_snapshot()).client
                except Exception as e:
                    return {
                        "ok": False,
                        "message": user_facing_error_message(
                            e,
                            fallback="LLM profile 尚未就绪，请稍后重试。",
                        ),
                    }

            details_fn = self.tool_dispatcher.get_command_approval_details
            try:
                details_params = inspect.signature(details_fn).parameters
            except (TypeError, ValueError):
                details_params = {}
            if "llm" in details_params:
                analysis = await details_fn(
                    command=pending_command,
                    reason=pending_reason,
                    chat_id=chat_id,
                    tool_call_id=pending_tool_call_id,
                    include_llm=include_llm,
                    llm=detail_llm,
                )
            else:
                analysis = await details_fn(
                    command=pending_command,
                    reason=pending_reason,
                    chat_id=chat_id,
                    tool_call_id=pending_tool_call_id,
                    include_llm=include_llm,
                )

            current_command = session.pending_command or ""
            current_command_hash = session.pending_command_hash or self._command_hash(current_command)
            if (
                not session.pending_approval
                or (pending_approval_id and session.pending_approval_id != pending_approval_id)
                or current_command_hash != pending_command_hash
            ):
                return {
                    "ok": False,
                    "message": "Approval is no longer pending or has changed.",
                }

            session.pending_analysis = analysis
            self._persist_session(session)

        return {
            "ok": True,
            "approval_id": session.pending_approval_id or "",
            "run_id": session.pending_run_id or "",
            "command": session.pending_command,
            "command_hash": session.pending_command_hash or self._command_hash(session.pending_command or ""),
            "reason": session.pending_reason or "",
            "risk_level": session.pending_risk_level or "",
            "analysis": session.pending_analysis,
        }

    @staticmethod
    def _is_reject_intent(user_message: str) -> bool:
        """Heuristic for natural-language reject/cancel intent."""
        text = (user_message or "").strip().lower()
        if not text:
            return False

        reject_keywords = (
            "拒绝", "取消", "不执行", "不要执行", "别执行", "算了", "停止", "终止",
            "reject", "deny", "cancel", "abort", "stop",
        )
        return any(k in text for k in reject_keywords)

    @staticmethod
    def _is_continue_intent(user_message: str) -> bool:
        """Heuristic for continue intent when a task hits round limit."""
        text = (user_message or "").strip().lower()
        if not text:
            return False

        continue_keywords = (
            "\u7ee7\u7eed", "\u7ee7\u7eed\u6267\u884c", "\u7ee7\u7eed\u4efb\u52a1", "\u63a5\u7740\u8dd1", "\u7ee7\u7eed\u8dd1",
            "continue", "go on", "proceed",
        )
        return any(k in text for k in continue_keywords)

    @staticmethod
    def _summarize_pending_followups(session: Any, max_chars: int = 1500) -> str:
        """Build a compact transcript of follow-up chat during pending approval."""
        if not session.pending_followups:
            return ""

        lines: list[str] = []
        for item in session.pending_followups:
            role = item.get("role", "")
            content = str(item.get("content", "")).strip()
            if not content:
                continue
            if Agent._looks_like_tool_call_text(content):
                continue
            prefix = "用户" if role == "user" else "助手"
            lines.append(f"{prefix}: {content}")

        summary = "\n".join(lines)
        if len(summary) > max_chars:
            summary = summary[:max_chars] + "\n...(已截断)"
        return summary

    @staticmethod
    def _looks_like_tool_call_text(content: str) -> bool:
        """Detect pseudo tool-call text that should never enter side-thread memory."""
        text = (content or "").strip().lower()
        if not text:
            return False
        markers = (
            "<tool_call",
            "</tool_call>",
            "<function=",
            "</function>",
            "<parameter=",
            "</parameter>",
        )
        return any(marker in text for marker in markers)

    @staticmethod
    def _pending_approval_decision_message() -> str:
        """Prompt for the only two decisions accepted while input is deferred."""
        return "当前命令等待处理。发送 /confirm 执行，或发送 /reject 取消。"

    @classmethod
    def _prune_pending_followups(cls, session: Any) -> None:
        """Drop malformed side-thread entries, including old persisted pseudo tool calls."""
        cleaned: list[dict[str, str]] = []
        for item in getattr(session, "pending_followups", []) or []:
            role = item.get("role")
            content = str(item.get("content", "")).strip()
            if role not in {"user", "assistant"} or not content:
                continue
            if cls._looks_like_tool_call_text(content):
                continue
            cleaned.append({"role": role, "content": content})
        session.pending_followups = cleaned[-12:]

    async def _handle_pending_input(
        self,
        chat_id: int,
        session: Any,
        user_message: str,
        *,
        user_id: int | None = None,
    ) -> AgentResult:
        """Classify one message received while a command waits for approval."""
        turn_lock = self.session_manager.get_turn_lock(chat_id)
        async with turn_lock:
            self._prune_pending_followups(session)
            if session.approval_processing:
                processing_id = session.processing_approval_id or "当前命令"
                return AgentResult(
                    kind="reply",
                    content=f"ℹ️ {processing_id} 已完成审批，正在处理中。",
                    payload={"approval_status": "processing"},
                )
            if not session.pending_approval:
                return AgentResult.reply("当前审批已处理。")
            if (
                session.active_turn is not None
                and session.active_turn.state == "answering_approval_question"
            ):
                return AgentResult.reply("上一条审批消息正在处理中。")
            if (
                session.active_turn is not None
                and session.active_turn.state == "waiting_approval_decision"
            ):
                return AgentResult.reply(self._pending_approval_decision_message())

            pending_cmd = session.pending_command or ""
            pending_approval_id = session.pending_approval_id or ""
            pending_tool_call_id = session.pending_tool_call_id or ""
            pending_command_hash = session.pending_command_hash or ""
            pending_reason = session.pending_reason or ""
            pending_risk_level = session.pending_risk_level or ""
            turn_id = session.active_turn.turn_id if session.active_turn is not None else None
            approval_binding = (
                turn_id,
                pending_approval_id,
                pending_tool_call_id,
                pending_command_hash,
            )
            self._transition_turn(session, "answering_approval_question")
            self._persist_session(session)

        try:
            snapshot = await self.get_active_llm_snapshot()
            decision = await classify_approval_input(
                snapshot.client,
                command=pending_cmd,
                reason=pending_reason,
                risk_level=pending_risk_level,
                user_message=user_message,
            )
            from chatdome.agent.tracker import TokenTracker
            TokenTracker.record_usage(
                chat_id=chat_id,
                model=getattr(snapshot.client, "model", "unknown"),
                action="approval_input_classification",
                prompt_tokens=decision.prompt_tokens,
                completion_tokens=decision.completion_tokens,
                total_tokens=decision.total_tokens,
            )
        except Exception as exc:
            logger.warning("Approval input classification unavailable: %s", exc)
            decision = ApprovalInputDecision(classification="unknown")

        async with turn_lock:
            current_turn_id = (
                session.active_turn.turn_id
                if session.active_turn is not None
                else None
            )
            current_binding = (
                current_turn_id,
                session.pending_approval_id or "",
                session.pending_tool_call_id or "",
                session.pending_command_hash or "",
            )
            if session.approval_processing:
                processing_id = session.processing_approval_id or "当前命令"
                return AgentResult(
                    kind="reply",
                    content=f"ℹ️ {processing_id} 已完成审批，正在处理中。",
                    payload={"approval_status": "processing"},
                )
            if not session.pending_approval or current_binding != approval_binding:
                return AgentResult.reply("审批状态已变化，请查看最新消息。")

            if decision.classification == "approve":
                outcome = (
                    "approval_resumed"
                    if has_meaningful_approval_reason(session.pending_reason)
                    or isinstance(session.pending_analysis, dict)
                    else "review_required"
                )
            elif decision.classification == "reject":
                outcome = "approval_resumed"
            elif decision.classification == "approval_question":
                outcome = "answered"
            else:
                outcome = "decision_required"

            event = {
                "event_type": "approval_input_classified",
                "turn_id": turn_id,
                "user_id": user_id,
                "approval_id": pending_approval_id,
                "classification": decision.classification,
                "outcome": outcome,
            }
            session.add_control_event(event)
            CommandAuditTracker.record_event(
                "approval_input_classified",
                chat_id=chat_id,
                user_id=user_id,
                turn_id=turn_id,
                approval_id=pending_approval_id,
                classification=decision.classification,
                outcome=outcome,
            )
            logger.info(
                "Approval input classified: classification=%s outcome=%s",
                decision.classification,
                outcome,
            )

            if decision.classification == "approval_question":
                session.add_pending_followup("user", user_message)
                session.add_pending_followup("assistant", decision.answer)
                self._transition_turn(session, "waiting_approval")
                self._persist_session(session)
                return AgentResult.reply(decision.answer)

            if decision.classification not in {"approve", "reject"}:
                if session.deferred_user_message is None:
                    session.defer_user_message(user_message, user_id=user_id)
                self._transition_turn(session, "waiting_approval_decision")
                self._persist_session(session)
                return AgentResult.reply(self._pending_approval_decision_message())

            self._persist_session(session)

        _, result = await self.resume_session(
            chat_id,
            "APPROVE" if decision.classification == "approve" else "REJECT",
            approval_id=pending_approval_id or None,
        )
        return result

    async def _run_loop(
        self,
        chat_id: int,
        session: Any,
        snapshot: LLMSnapshot | None = None,
        *,
        turn_context: TurnContext | None = None,
        progress_callback: Any = None,
    ) -> AgentResult:
        """Drive the ReAct loop forward."""

        if snapshot is None:
            snapshot = await self.get_active_llm_snapshot()
        if turn_context is None:
            turn_context = session.current_turn_context()
        llm = snapshot.client
        self.llm = llm
        start_round = session.round_count
        window_limit = max(1, int(self.config.max_rounds_per_turn))
        end_round_exclusive = start_round + window_limit + 1
        for round_num in range(start_round + 1, end_round_exclusive):
            compaction = await self._ensure_context_budget(
                session=session,
                snapshot=snapshot,
                progress_callback=progress_callback,
                trigger_reason=f"before_round_{round_num}",
            )
            if compaction is not None and compaction.status in {"failed", "rejected"}:
                final_content = "上下文压缩未完成。请重试，或使用 /clear 清除当前上下文。"
                self._add_assistant_message(session, final_content)
                self._finish_turn(session, "failed")
                self._persist_session(session)
                return AgentResult.reply(final_content)
            await self._publish_progress(progress_callback, "processing")
            logger.info(
                "Agent loop progress %d/%d for chat_id=%d",
                round_num, start_round + window_limit, chat_id,
            )

            try:
                llm_messages = (
                    session.build_llm_messages(turn_context)
                    if hasattr(session, "build_llm_messages")
                    else list(session.messages)
                )
                response = await llm.chat_completion(
                    messages=llm_messages,
                    tools=self.tools,
                )
            except Exception as e:
                logger.error("LLM call failed: %s", e)
                detail = user_facing_error_message(e, fallback="LLM 调用失败，请稍后重试。")
                final_content = f"⚠️ {detail}"
                self._add_assistant_message(session, final_content)
                self._finish_turn(session, "failed")
                self._persist_session(session)
                return AgentResult.reply(final_content)

            logger.debug(
                "LLM response: content=%s, tool_calls=%d, tokens=%d",
                bool(response.content),
                len(response.tool_calls),
                response.total_tokens,
            )
            session.round_count = round_num
            self._persist_session(session)
            
            from chatdome.agent.tracker import TokenTracker
            TokenTracker.record_usage(
                chat_id=chat_id,
                model=getattr(llm, "model", "unknown"),
                action="react_loop",
                prompt_tokens=response.prompt_tokens,
                completion_tokens=response.completion_tokens,
                total_tokens=response.total_tokens
            )

            if response.tool_calls:
                await self._publish_progress(progress_callback, "executing")
                prior_tool_counts, prior_tool_results = self._tool_call_stats_since_last_user(session)
                current_tool_counts: dict[str, int] = {}
                tool_call_plans: list[tuple[Any, str, int, bool]] = []
                for tc in response.tool_calls:
                    signature = self._tool_call_signature(tc.name, tc.arguments)
                    current_seen = current_tool_counts.get(signature, 0)
                    repeat_count = prior_tool_counts.get(signature, 0) + current_seen + 1
                    is_duplicate = prior_tool_counts.get(signature, 0) > 0 or current_seen > 0
                    tool_call_plans.append((tc, signature, repeat_count, is_duplicate))
                    current_tool_counts[signature] = current_seen + 1

                # Build the assistant message with tool_calls for the session
                tool_calls_for_session = [
                    {
                        "id": getattr(tc, "response_id", None) or tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.name,
                            "arguments": tc.arguments,
                        },
                        **(
                            {"call_id": tc.id}
                            if getattr(tc, "response_id", None) and getattr(tc, "response_id", None) != tc.id
                            else {}
                        ),
                    }
                    for tc in response.tool_calls
                ]
                self._add_assistant_tool_calls(session, tool_calls_for_session)
                self._persist_session(session)

                # Execute each tool call
                from chatdome.agent.tools import PendingApprovalError

                storm_signature: str | None = None
                storm_repeat_count = 0
                storm_cached_result = ""

                for index, (tc, signature, repeat_count, is_duplicate) in enumerate(tool_call_plans):
                    if is_duplicate:
                        cached_result = prior_tool_results.get(signature, "")
                        result = self._duplicate_tool_result(signature, repeat_count, cached_result)
                        self._add_tool_result(session, tc.id, result)
                        self._persist_session(session)
                        logger.warning(
                            "Suppressed duplicate tool call for chat_id=%d repeat_count=%d signature=%s",
                            chat_id,
                            repeat_count,
                            signature[:300],
                        )
                        if repeat_count >= self.DUPLICATE_TOOL_STOP_THRESHOLD:
                            storm_signature = signature
                            storm_repeat_count = max(storm_repeat_count, repeat_count)
                            storm_cached_result = cached_result or result
                        continue

                    logger.info("Executing tool: %s (id=%s)", tc.name, tc.id)
                    try:
                        result = await self._dispatch_tool_compat(
                            tc.name,
                            tc.arguments,
                            tc.id,
                            chat_id,
                            llm,
                        )
                        self._add_tool_result(session, tc.id, result)
                        prior_tool_results[signature] = result
                        self._persist_session(session)
                        logger.debug("Tool result for %s: %s", tc.id, result[:200])
                    except PendingApprovalError as e:
                        logger.info("Execution suspended for user approval: %s", tc.id)
                        approval_id = self._new_approval_id()
                        command_hash = self._command_hash(e.command)
                        session.pending_approval = True
                        session.pending_approval_id = approval_id
                        session.pending_run_id = None
                        session.pending_tool_call_id = e.tool_call_id
                        session.pending_command = e.command
                        session.pending_command_hash = command_hash
                        session.pending_reason = getattr(e, "reason", "")
                        session.pending_risk_level = getattr(e, "risk_level", "")
                        session.pending_static_is_safe = bool(
                            getattr(e, "static_is_safe", False)
                        )
                        session.pending_mutation_detected = bool(
                            getattr(e, "mutation_detected", False)
                        )
                        session.pending_deletion_detected = bool(
                            getattr(e, "deletion_detected", False)
                        )
                        session.pending_analysis = None
                        session.pending_since = time.time()
                        session.pending_followups.clear()
                        self._append_context_event(
                            session,
                            "approval.requested",
                            {
                                "approval_id": approval_id,
                                "tool_call_id": e.tool_call_id,
                                "command": e.command,
                                "reason": getattr(e, "reason", ""),
                                "risk_level": getattr(e, "risk_level", ""),
                            },
                        )
                        self._transition_turn(session, "waiting_approval")
                        CommandAuditTracker.record_event(
                            "command_approval_created",
                            chat_id=chat_id,
                            turn_id=(
                                session.active_turn.turn_id
                                if session.active_turn is not None
                                else None
                            ),
                            approval_id=approval_id,
                            tool_call_id=e.tool_call_id,
                            command=e.command,
                            command_hash=command_hash,
                            reason=getattr(e, "reason", ""),
                            risk_level=getattr(e, "risk_level", ""),
                            impact_analysis=getattr(e, "impact_analysis", ""),
                        )
                        for skipped_tc, _, _, _ in tool_call_plans[index + 1:]:
                            skipped_result = (
                                "Tool call was not executed because an earlier command is waiting "
                                "for user approval. Re-request this tool call after the approval "
                                "decision if the result is still needed."
                            )
                            self._add_tool_result(session, skipped_tc.id, skipped_result)
                            logger.info(
                                "Deferred tool call due to pending approval: %s",
                                skipped_tc.id,
                            )
                        payload = {
                            "approval_id": approval_id,
                            "turn_id": (
                                session.active_turn.turn_id
                                if session.active_turn is not None
                                else None
                            ),
                            "command": e.command,
                            "command_hash": command_hash,
                            "reason": getattr(e, 'reason', ''),
                            "risk_level": getattr(e, "risk_level", ""),
                            "impact_analysis": getattr(e, "impact_analysis", ""),
                            "safety_status": getattr(e, "safety_status", ""),
                            "static_is_safe": bool(
                                getattr(e, "static_is_safe", False)
                            ),
                            "mutation_detected": bool(getattr(e, "mutation_detected", False)),
                            "deletion_detected": bool(getattr(e, "deletion_detected", False)),
                            "requires_detail_expansion": True,
                        }
                        self._persist_session(session)
                        return AgentResult.pending_approval(payload)

                if storm_signature is not None:
                    final_content = self._tool_storm_final_response(
                        storm_signature,
                        storm_repeat_count,
                        storm_cached_result,
                    )
                    session.task_auto_approve = False
                    session.clear_pending_round_limit()
                    self._add_assistant_message(session, final_content)
                    self._finish_turn(session, "completed")
                    self._persist_session(session)
                    logger.warning(
                        "Tool storm stopped for chat_id=%d repeat_count=%d signature=%s",
                        chat_id,
                        storm_repeat_count,
                        storm_signature[:300],
                    )
                    return AgentResult.reply(final_content)

                # Continue the loop — send results back to LLM
                continue

            else:
                # No tool calls — this is the final response
                final_content = response.content or "（AI 未返回有效回复）"
                
                if session.command_echo:
                    cmds = session.get_turn_executed_commands()
                    if cmds:
                        echo_text = "\n\n---\n*🔍 Command Echo 模式*\n" + "\n".join(cmds)
                        final_content += echo_text
                        
                session.task_auto_approve = False
                session.clear_pending_round_limit()
                self._add_assistant_message(session, final_content)
                self._finish_turn(session, "completed")
                self._persist_session(session)
                logger.info("Agent completed for chat_id=%d in %d rounds", chat_id, round_num)
                return AgentResult.reply(final_content)
        # Reached one execution window; ask user whether to continue.
        reached_rounds = session.round_count
        session.pending_round_limit = True
        session.pending_round_count = reached_rounds
        session.task_auto_approve = False
        self._transition_turn(session, "waiting_round_limit")
        self._persist_session(session)
        logger.warning("Round limit window reached for chat_id=%d (rounds=%d)", chat_id, reached_rounds)
        return AgentResult.round_limit({"rounds": reached_rounds, "window": window_limit})

    def get_context_status(self, chat_id: int) -> dict[str, Any]:
        """Calculate `/context` from the same request counter used by preflight."""
        session = self.session_manager.get_or_create(chat_id)
        service = getattr(self, "context_budget_service", None)
        if service is None:
            counter = ContextTokenCounter(model=getattr(self.llm, "model", ""))
            service = ContextBudgetService(
                counter,
                limit_tokens=getattr(self.config, "max_history_tokens", 32_000),
                target_ratio=0.70,
            )
        snapshot = service.snapshot(session.build_llm_messages(), self.tools)
        summary = getattr(session, "working_summary", None)
        summary_tokens = int(getattr(summary, "token_count", 0) or 0)
        if summary is not None and summary_tokens <= 0:
            summary_tokens = service.counter.count_text(summary.to_prompt_block()).tokens
        last = getattr(getattr(session, "context_state", None), "last_compaction", None)
        latest_compaction_event = next(
            (
                event.type
                for event in reversed(self.event_store.read_events(chat_id))
                if event.type.startswith("context.compaction_")
            ),
            "",
        )
        if snapshot.usage_percent < 80:
            status = "正常"
        elif snapshot.current_tokens < snapshot.limit_tokens:
            status = "接近压缩阈值"
        elif getattr(session, "agent_running", False):
            status = "正在压缩"
        elif latest_compaction_event in {
            "context.compaction_failed",
            "context.compaction_rejected",
        }:
            status = "压缩待重试"
        else:
            status = "达到压缩阈值"
        return {
            "current_tokens": snapshot.current_tokens,
            "limit_tokens": snapshot.limit_tokens,
            "usage_percent": snapshot.usage_percent,
            "status": status,
            "working_summary_tokens": summary_tokens,
            "last_tokens_before": int(getattr(last, "tokens_before", 0) or 0),
            "last_tokens_after": int(getattr(last, "tokens_after", 0) or 0),
            "last_reduction_percent": int(getattr(last, "reduction_percent", 0) or 0),
            "token_count_method": snapshot.method,
        }

    def clear_session(self, chat_id: int) -> Any:
        """Clear a chat session after acquiring the global task lease."""
        if not self._claim_global_turn_identity(
            chat_id,
            source="control",
            user_id=None,
        ):
            return False
        cleared = self.session_manager.clear_session(chat_id, source="control")
        self._release_global_turn_lease(chat_id)
        return cleared

    def start(self) -> None:
        """Start background tasks (session cleanup)."""
        self._recover_global_turn_lease()
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return
        self.session_manager.start_cleanup_task()

    async def stop(self) -> None:
        """Stop background tasks and clean up resources."""
        await self.session_manager.stop_cleanup_task()
        await self.tool_dispatcher.close()
        self._release_global_turn_lease()
