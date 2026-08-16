"""Unified business handlers for every command-capable platform."""

from __future__ import annotations

import asyncio
import inspect
import logging
import json
import time
import uuid
from dataclasses import dataclass, replace
from typing import Any, Awaitable, Callable, Mapping

from chatdome.errors import ChatDomeError, user_facing_error_message
from chatdome.llm.codex_oauth_service import CodexOAuthService, CodexOAuthSession
from chatdome.llm.profile_admin import ProfileActor
from chatdome.model_commands import ModelCommandService
from chatdome.model_workflow import CodexWorkflowRequest, ModelCommandWorkflow
from chatdome.outbound.models import (
    ActionKind,
    DecisionEffect,
    DecisionEffectKind,
    DecisionOperationFacts,
    DecisionPromptFacts,
    DecisionQuestion,
    OutboundAction,
)
from chatdome.runtime_paths import environment_profile_path
from chatdome.slash_commands import (
    CommandDef,
    CommandInvocation,
    CommandResult,
    abandon_command_result,
    approval_details_command_result,
    approve_command_result,
    audit_command_result,
    clear_session_command_result,
    context_usage_command_result,
    command_echo_command_result,
    command_help_result,
    continue_command_result,
    environment_command_result,
    execute_engram_command,
    publish_command_result,
    reject_command_result,
    sentinel_history,
    sentinel_mute,
    sentinel_packs,
    sentinel_resume,
    sentinel_status,
    sentinel_trigger,
    stop_task_command_result,
    token_usage_command_result,
)

logger = logging.getLogger(__name__)

DeferredPublisher = Callable[[CommandResult], Any]
TaskScheduler = Callable[[Awaitable[Any]], Any]
RuntimeProvider = Callable[[CommandInvocation], "CommandHandlerRuntime"]


@dataclass
class CommandHandlerRuntime:
    """Platform-neutral dependencies available to command business handlers."""

    agent: Any = None
    model_service: ModelCommandService | None = None
    codex_oauth: CodexOAuthService | None = None
    config: Any = None
    sentinel: Any = None
    pack_loader: Any = None
    profile_actor: ProfileActor | None = None
    cancel_request: Callable[[], Any] | None = None
    sync_model: Callable[[], Any] | None = None
    reload_domains: Callable[[tuple[str, ...], str], Any] | None = None
    publish_deferred: DeferredPublisher | None = None
    schedule_task: TaskScheduler | None = None
    defer_commands: bool = False
    admin_allowed: bool = False
    abort_pending_request: Callable[[], Any] | None = None
    handle_deferred_message: Callable[[str, int | None], Any] | None = None


class CommandErrorMapper:
    """Convert domain failures into one stable CommandResult contract."""

    _TITLES: Mapping[str, str] = {
        "/model": "Model switch failed",
        "/model_add": "Model add failed",
        "/model_delete": "Model delete failed",
        "/model_cancel": "Model operation failed",
        "/codex_login": "Codex OAuth failed",
        "/sentinel_alert_detail": "Sentinel alert detail failed",
        "/sentinel_alert_analysis": "Sentinel alert analysis failed",
    }
    _FALLBACKS: Mapping[str, str] = {
        "/model": "Model profile could not be switched.",
        "/model_add": "Model profile could not be saved.",
        "/model_delete": "Model profile could not be deleted.",
        "/model_cancel": "Model operation failed.",
        "/codex_login": "Codex authentication failed.",
        "/sentinel_alert_detail": "Sentinel alert detail is unavailable.",
        "/sentinel_alert_analysis": "Sentinel alert analysis failed. Retry the operation.",
    }

    def from_exception(
        self,
        invocation: CommandInvocation,
        exc: BaseException,
        *,
        lifecycle_phase: str = "final",
    ) -> CommandResult:
        command = invocation.command.name
        code = str(getattr(exc, "code", "command.failed") or "command.failed")
        return CommandResult(
            outcome="failed",
            title=self._TITLES.get(command, "Command failed"),
            text=user_facing_error_message(
                exc,
                fallback=self._FALLBACKS.get(command, "Command failed. Retry the operation."),
            ),
            severity="error",
            facts={"error_code": code, "retryable": bool(getattr(exc, "retryable", False))},
            event_summary=f"命令 {command} 执行失败。",
            lifecycle_phase=lifecycle_phase,
        )


class CommandHandlerService:
    """Canonical command and action registry shared by every platform."""

    def __init__(
        self,
        runtime_provider: RuntimeProvider,
        *,
        model_workflow: ModelCommandWorkflow | None = None,
        error_mapper: CommandErrorMapper | None = None,
    ) -> None:
        self.runtime_provider = runtime_provider
        self.model_workflow = model_workflow or ModelCommandWorkflow()
        self.error_mapper = error_mapper or CommandErrorMapper()
        self._action_handlers: dict[
            str, Callable[[CommandInvocation, CommandHandlerRuntime], Any]
        ] = {
            "sentinel_alert_detail": self._sentinel_alert_detail,
            "sentinel_alert_analysis": self._sentinel_alert_analysis,
            "memory_delete_yes": self._memory,
            "memory_delete_no": self._memory,
            "memory_clear_yes": self._memory,
            "memory_clear_no": self._memory,
        }
        self._sentinel_alerts: dict[str, dict[str, Any]] = {}
        self._sentinel_alert_limit = 200
        self._memory_confirmations: dict[str, dict[str, Any]] = {}
        self._handlers: dict[str, Callable[[CommandInvocation, CommandHandlerRuntime], Any]] = {
            "/help": self._help,
            "/clear": self._clear,
            "/stop": self._stop,
            "/env": self._env,
            "/audit": self._audit,
            "/token": self._token,
            "/context": self._context,
            "/cmd_echo": self._cmd_echo,
            "/engram": self._engram,
            "/memory": self._memory,
            "/model": self._model,
            "/model_list": self._model_list,
            "/model_add": self._model_add,
            "/model_delete": self._model_delete,
            "/model_cancel": self._model_cancel,
            "/codex_login": self._codex_login,
            "/details": self._details,
            "/confirm": self._confirm,
            "/reject": self._reject,
            "/continue": self._continue,
            "/sentinel_status": self._sentinel_status,
            "/sentinel_trigger": self._sentinel_trigger,
            "/sentinel_history": self._sentinel_history,
            "/sentinel_packs": self._sentinel_packs,
            "/sentinel_mute": self._sentinel_mute,
            "/sentinel_resume": self._sentinel_resume,
        }

    @property
    def registered_commands(self) -> tuple[str, ...]:
        return tuple(self._handlers)

    @property
    def registered_actions(self) -> tuple[str, ...]:
        return tuple(self._action_handlers)

    def action_definition(self, action: str) -> CommandDef | None:
        """Return non-public command metadata for one semantic action."""

        if action not in self._action_handlers:
            return None
        return CommandDef(
            name=f"/{action}",
            description="Execute semantic action",
            category="action",
            handler=self.handle,
        )

    def remember_sentinel_alert(
        self,
        *,
        chat_id: int,
        alert_text: str,
        alert_event: Any | None,
    ) -> str:
        """Store platform-neutral Sentinel context for later semantic actions."""

        event_payload: Any = None
        if alert_event is not None:
            if hasattr(alert_event, "to_dict"):
                event_payload = alert_event.to_dict()
            elif isinstance(alert_event, dict):
                event_payload = dict(alert_event)
            else:
                event_payload = str(alert_event)
        token = uuid.uuid4().hex[:16]
        self._sentinel_alerts[token] = {
            "chat_id": chat_id,
            "alert_text": alert_text,
            "event": event_payload,
            "created_at": time.time(),
        }
        while len(self._sentinel_alerts) > self._sentinel_alert_limit:
            oldest = min(
                self._sentinel_alerts,
                key=lambda key: float(self._sentinel_alerts[key].get("created_at", 0.0)),
            )
            self._sentinel_alerts.pop(oldest, None)
        return token


    async def handle(self, invocation: CommandInvocation) -> CommandResult:
        handler = self._action_handlers.get(
            invocation.action
        ) or self._handlers.get(invocation.command.name)
        if handler is None:
            return CommandResult(
                outcome="unsupported_command",
                text=f"Unsupported command: {invocation.command.name}",
                severity="error",
            )
        try:
            runtime = self.runtime_provider(invocation)
            result = handler(invocation, runtime)
            if inspect.isawaitable(result):
                result = await result
            return self._attach_deferred_post_delivery(result, runtime)
        except asyncio.CancelledError:
            raise
        except (ChatDomeError, ValueError) as exc:
            logger.warning(
                "Command domain failure command=%s code=%s",
                invocation.command.name,
                getattr(exc, "code", type(exc).__name__),
            )
            return self.error_mapper.from_exception(invocation, exc)
        except Exception as exc:
            logger.exception(
                "Command business failure command=%s",
                invocation.command.name,
            )
            return self.error_mapper.from_exception(invocation, exc)

    @staticmethod
    def _attach_deferred_post_delivery(
        result: CommandResult,
        runtime: CommandHandlerRuntime,
    ) -> CommandResult:
        message = str(result.deferred_user_message or "")
        callback = runtime.handle_deferred_message
        if not message or callback is None:
            return result

        executed = False
        execution_lock: asyncio.Lock | None = None

        async def run_once() -> Any:
            nonlocal executed, execution_lock
            if execution_lock is None:
                execution_lock = asyncio.Lock()
            async with execution_lock:
                if executed:
                    return None
                try:
                    callback_params = inspect.signature(callback).parameters
                except (TypeError, ValueError):
                    callback_params = {}
                supports_user_id = len(callback_params) >= 2 or any(
                    parameter.kind == inspect.Parameter.VAR_POSITIONAL
                    for parameter in callback_params.values()
                )
                value = (
                    callback(message, result.deferred_user_id)
                    if supports_user_id
                    else callback(message)
                )
                if inspect.isawaitable(value):
                    value = await value
                executed = True
                return value
        return replace(result, post_delivery=run_once)

    @staticmethod
    def _require(value: Any, label: str) -> Any:
        if value is None:
            raise RuntimeError(f"{label} is unavailable")
        return value

    @staticmethod
    def _require_admin(runtime: CommandHandlerRuntime) -> CommandResult | None:
        if runtime.admin_allowed:
            return None
        return CommandResult(
            outcome="unauthorized",
            title="Administrator access",
            text="需要管理员权限。",
            severity="error",
        )

    @staticmethod
    def _actor(invocation: CommandInvocation, runtime: CommandHandlerRuntime) -> ProfileActor:
        if runtime.profile_actor is not None:
            return runtime.profile_actor
        raw_user = str(invocation.context.actor_id or "")
        return ProfileActor(
            source=invocation.context.source,
            chat_id=invocation.context.chat_id,
            user_id=int(raw_user) if raw_user.isdigit() else 0,
        )

    @staticmethod
    def _help(_invocation: CommandInvocation, _runtime: CommandHandlerRuntime) -> CommandResult:
        return command_help_result()

    async def _clear(self, invocation: CommandInvocation, runtime: CommandHandlerRuntime) -> CommandResult:
        return clear_session_command_result(self._require(runtime.agent, "agent"), invocation.context)

    async def _stop(self, _invocation: CommandInvocation, runtime: CommandHandlerRuntime) -> CommandResult:
        return await stop_task_command_result(
            runtime.cancel_request,
            runtime.abort_pending_request,
        )

    @staticmethod
    def _env(_invocation: CommandInvocation, _runtime: CommandHandlerRuntime) -> CommandResult:
        return environment_command_result(environment_profile_path())

    @staticmethod
    def _audit(invocation: CommandInvocation, _runtime: CommandHandlerRuntime) -> CommandResult:
        return audit_command_result(invocation.context, invocation.args)

    @staticmethod
    def _token(invocation: CommandInvocation, _runtime: CommandHandlerRuntime) -> CommandResult:
        return token_usage_command_result(invocation.context)

    @staticmethod
    def _context(invocation: CommandInvocation, runtime: CommandHandlerRuntime) -> CommandResult:
        return context_usage_command_result(
            CommandHandlerService._require(runtime.agent, "agent"),
            invocation.context,
        )

    async def _cmd_echo(self, invocation: CommandInvocation, runtime: CommandHandlerRuntime) -> CommandResult:
        return command_echo_command_result(self._require(runtime.agent, "agent"), invocation.context)

    async def _engram(self, invocation: CommandInvocation, runtime: CommandHandlerRuntime) -> CommandResult:
        return execute_engram_command(self._require(runtime.agent, "agent"), invocation.args)

    async def _memory(
        self,
        invocation: CommandInvocation,
        runtime: CommandHandlerRuntime,
    ) -> CommandResult:
        """List Memory Vault entries or run one confirmed deletion."""
        agent = self._require(runtime.agent, "agent")
        store = getattr(agent, "memory_vault_store", None) or getattr(
            getattr(agent, "session_manager", None),
            "memory_vault_store",
            None,
        )
        if store is None:
            return CommandResult(outcome="unavailable", text="Memory Vault is unavailable.")
        chat_id = invocation.context.chat_id
        action = str(invocation.action or "")
        if action in {
            "memory_delete_yes",
            "memory_delete_no",
            "memory_clear_yes",
            "memory_clear_no",
        }:
            nonce = str(invocation.interaction_id or "")
            pending = self._memory_confirmations.pop(nonce, None)
            if (
                pending is None
                or float(pending.get("expires_at", 0)) < time.time()
                or int(pending.get("chat_id", 0)) != chat_id
            ):
                return CommandResult(
                    outcome="invalid_interaction_state",
                    text="该记忆操作已失效。请重新执行 /memory。",
                )
            if action.endswith("_no"):
                return CommandResult(outcome="memory_operation_cancelled", text="已取消。")
            return self._execute_memory_mutation(
                store,
                chat_id,
                str(pending["operation"]),
                str(pending.get("entry_id") or ""),
            )

        values = tuple(str(value).strip() for value in invocation.args if str(value).strip())
        if values and values[0].lower() == "delete":
            if len(values) not in {2, 3} or (len(values) == 3 and values[2].lower() != "confirm"):
                return CommandResult(
                    outcome="invalid_arguments",
                    text="Usage: /memory delete <id> [confirm]",
                )
            entry_id = values[1]
            if not any(entry.id == entry_id for entry in store.load(chat_id).entries):
                return CommandResult(outcome="memory_not_found", text=f"Memory not found: {entry_id}")
            if len(values) == 3:
                return self._execute_memory_mutation(store, chat_id, "delete", entry_id)
            return self._memory_confirmation(invocation, "delete", entry_id)
        if values and values[0].lower() == "clear":
            if len(values) not in {1, 2} or (len(values) == 2 and values[1].lower() != "confirm"):
                return CommandResult(
                    outcome="invalid_arguments",
                    text="Usage: /memory clear [confirm]",
                )
            if not store.load(chat_id).entries:
                return CommandResult(outcome="memory_empty", text="Memory Vault is empty.")
            if len(values) == 2:
                return self._execute_memory_mutation(store, chat_id, "clear", "")
            return self._memory_confirmation(invocation, "clear", "")
        if values:
            return CommandResult(
                outcome="invalid_arguments",
                text="Usage: /memory [delete <id>|clear]",
            )

        vault = store.load(chat_id)
        if not vault.entries:
            return CommandResult(outcome="memory_empty", text="Memory Vault is empty.")
        lines = ["Memory Vault", ""]
        for entry in vault.entries:
            lines.append(f"- [{entry.category}] {entry.content}")
            lines.append(f"  ID: {entry.id} | {entry.status} | {entry.updated_at}")
        lines.extend(["", "Delete: /memory delete <id>", "Clear: /memory clear"])
        return CommandResult(
            outcome="memory_listed",
            event_summary=f"用户查看了 {len(vault.entries)} 条 Memory Vault 记录。",
            text="\n".join(lines),
        )

    def _memory_confirmation(
        self,
        invocation: CommandInvocation,
        operation: str,
        entry_id: str,
    ) -> CommandResult:
        nonce = uuid.uuid4().hex[:12]
        self._memory_confirmations[nonce] = {
            "chat_id": invocation.context.chat_id,
            "operation": operation,
            "entry_id": entry_id,
            "expires_at": time.time() + 300,
        }
        target = f"长期记忆 {entry_id}" if operation == "delete" else "全部 Memory Vault 长期记忆"
        yes_action = "memory_delete_yes" if operation == "delete" else "memory_clear_yes"
        no_action = "memory_delete_no" if operation == "delete" else "memory_clear_no"
        typed_confirmation = (
            f"/memory delete {entry_id} confirm"
            if operation == "delete"
            else "/memory clear confirm"
        )
        return CommandResult(
            outcome="memory_confirmation_requested",
            event_refs={"interaction_id": nonce, "memory_id": entry_id},
            text=f"CLI 确认命令：{typed_confirmation}",
            facts=DecisionOperationFacts(
                operation=f"memory_{operation}",
                stage="confirm_delete",
                decision=DecisionPromptFacts(
                    intent=f"删除{target}",
                    effects=(DecisionEffect(DecisionEffectKind.DELETE, target),),
                    question=DecisionQuestion.CONFIRM_DELETE,
                ),
            ),
            actions=tuple(
                OutboundAction(
                    kind,
                    label,
                    f"memory_admin:{action}:{nonce}",
                    destructive=destructive,
                    params={
                        "command": "/memory",
                        "action": action,
                        "interaction_id": nonce,
                    },
                )
                for kind, label, action, destructive in (
                    (ActionKind.CONFIRM, "确认删除", yes_action, True),
                    (ActionKind.CANCEL, "取消", no_action, False),
                )
            ),
        )

    @staticmethod
    def _execute_memory_mutation(
        store: Any,
        chat_id: int,
        operation: str,
        entry_id: str,
    ) -> CommandResult:
        if operation == "delete":
            changed = bool(store.delete(chat_id, entry_id))
            return CommandResult(
                outcome="memory_deleted" if changed else "memory_not_found",
                event_summary=(
                    f"用户删除了 Memory Vault 记录 {entry_id}。"
                    if changed
                    else f"用户尝试删除不存在的 Memory Vault 记录 {entry_id}。"
                ),
                text=f"Memory deleted: {entry_id}" if changed else f"Memory not found: {entry_id}",
            )
        changed = bool(store.clear(chat_id))
        return CommandResult(
            outcome="memory_cleared" if changed else "memory_empty",
            event_summary="用户清空了 Memory Vault。" if changed else "Memory Vault 已为空。",
            text="Memory Vault cleared." if changed else "Memory Vault is empty.",
        )

    async def _model(self, invocation: CommandInvocation, runtime: CommandHandlerRuntime) -> CommandResult:
        service = self._require(runtime.model_service, "model service")
        if not invocation.args:
            return service.list_profiles()
        denied = self._require_admin(runtime)
        if denied:
            return denied
        return await service.switch(invocation.args[0], self._actor(invocation, runtime))

    async def _model_list(self, _invocation: CommandInvocation, runtime: CommandHandlerRuntime) -> CommandResult:
        return self._require(runtime.model_service, "model service").list_profiles()

    async def _model_add(self, invocation: CommandInvocation, runtime: CommandHandlerRuntime) -> CommandResult:
        denied = self._require_admin(runtime)
        if denied:
            return denied
        service = self._require(runtime.model_service, "model service")
        outcome = await self.model_workflow.handle_add(
            invocation, service, self._actor(invocation, runtime)
        )
        if outcome.codex_request is not None:
            return await self._start_codex(invocation, runtime, outcome.codex_request)
        return outcome.result

    async def _model_delete(self, invocation: CommandInvocation, runtime: CommandHandlerRuntime) -> CommandResult:
        denied = self._require_admin(runtime)
        if denied:
            return denied
        service = self._require(runtime.model_service, "model service")
        if invocation.action in {"delete_yes", "delete_no"}:
            return await self.model_workflow.confirm_delete(
                invocation, service, self._actor(invocation, runtime)
            )
        return await self.model_workflow.prepare_delete(invocation, service)

    async def _model_cancel(self, invocation: CommandInvocation, runtime: CommandHandlerRuntime) -> CommandResult:
        denied = self._require_admin(runtime)
        if denied:
            return denied
        return self.model_workflow.cancel(
            invocation, self._require(runtime.model_service, "model service")
        )

    async def _codex_login(self, invocation: CommandInvocation, runtime: CommandHandlerRuntime) -> CommandResult:
        denied = self._require_admin(runtime)
        if denied:
            return denied
        request = CodexWorkflowRequest(
            profile_name=invocation.args[0] if invocation.args else ""
        )
        return await self._start_codex(invocation, runtime, request)

    async def _start_codex(
        self,
        invocation: CommandInvocation,
        runtime: CommandHandlerRuntime,
        request: CodexWorkflowRequest,
    ) -> CommandResult:
        oauth = self._require(runtime.codex_oauth, "Codex OAuth service")
        config = self._require(runtime.config, "configuration")
        model_service = runtime.model_service
        active_profile = (
            model_service.manager.get_active_profile_name()
            if model_service is not None and model_service.manager is not None
            else ""
        )
        session = await oauth.begin(
            config,
            self._actor(invocation, runtime),
            requested_profile=request.profile_name,
            active_profile=active_profile,
            forced_profile=request.forced_profile,
            overwrite_existing=request.overwrite_existing,
            expected_profile_fingerprint=request.expected_profile_fingerprint,
        )
        pending = CommandResult(
            outcome="codex_authorization_pending",
            event_summary=f"用户为 Codex profile {session.profile_name} 启动了认证。",
            title="Codex OAuth",
            facts=session.authorization,
            event_refs={"profile": session.profile_name},
            lifecycle_phase="pending",
        )
        if runtime.defer_commands:
            self._schedule(runtime, self._complete_and_publish(invocation, runtime, session))
            return pending

        published = await publish_command_result(invocation, pending)
        await self._publish(runtime.publish_deferred, published)
        return await self._complete_codex(invocation, runtime, session)

    async def _complete_codex(
        self,
        invocation: CommandInvocation,
        runtime: CommandHandlerRuntime,
        session: CodexOAuthSession,
    ) -> CommandResult:
        try:
            await self._require(runtime.codex_oauth, "Codex OAuth service").complete(session)
            await self._invoke(runtime.sync_model)
            return CommandResult(
                outcome="codex_authenticated",
                event_summary=f"用户完成了 Codex profile {session.profile_name} 认证。",
                title="Codex OAuth",
                text=f"Codex profile authenticated: {session.profile_name}",
                event_refs={"profile": session.profile_name},
                lifecycle_phase="final",
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            return self.error_mapper.from_exception(invocation, exc, lifecycle_phase="final")

    async def _complete_and_publish(
        self,
        invocation: CommandInvocation,
        runtime: CommandHandlerRuntime,
        session: CodexOAuthSession,
    ) -> None:
        try:
            result = await self._complete_codex(invocation, runtime, session)
        except asyncio.CancelledError:
            result = CommandResult(
                outcome="cancelled",
                event_summary=f"Codex profile {session.profile_name} 认证已取消。",
                title="Codex OAuth",
                text="Codex authentication cancelled.",
                lifecycle_phase="final",
            )
        completed = await publish_command_result(invocation, result)
        await self._publish(runtime.publish_deferred, completed)

    @staticmethod
    def _schedule(runtime: CommandHandlerRuntime, awaitable: Awaitable[Any]) -> None:
        if runtime.schedule_task is not None:
            runtime.schedule_task(awaitable)
        else:
            asyncio.create_task(awaitable)

    @staticmethod
    async def _publish(callback: DeferredPublisher | None, result: CommandResult) -> None:
        if callback is None:
            return
        published = callback(result)
        if inspect.isawaitable(published):
            await published

    @staticmethod
    async def _invoke(callback: Callable[[], Any] | None) -> None:
        if callback is None:
            return
        value = callback()
        if inspect.isawaitable(value):
            await value

    async def _details(self, invocation: CommandInvocation, runtime: CommandHandlerRuntime) -> CommandResult:
        return await approval_details_command_result(
            self._require(runtime.agent, "agent"),
            invocation.context,
            invocation.args,
            approval_id=str(invocation.params.get("approval_id") or "") or None,
        )

    async def _confirm(self, invocation: CommandInvocation, runtime: CommandHandlerRuntime) -> CommandResult:
        return await approve_command_result(
            self._require(runtime.agent, "agent"),
            invocation.context,
            invocation.args,
            approval_id=str(invocation.params.get("approval_id") or "") or None,
        )
    async def _continue(
        self,
        invocation: CommandInvocation,
        runtime: CommandHandlerRuntime,
    ) -> CommandResult:
        return await continue_command_result(
            self._require(runtime.agent, "agent"),
            invocation.context,
        )

    async def _reject(
        self,
        invocation: CommandInvocation,
        runtime: CommandHandlerRuntime,
    ) -> CommandResult:
        if invocation.action == "abandon":
            return await abandon_command_result(
                self._require(runtime.agent, "agent"),
                invocation.context,
            )
        return await reject_command_result(
            self._require(runtime.agent, "agent"),
            invocation.context,
            invocation.args,
            approval_id=str(invocation.params.get("approval_id") or "") or None,
        )

    @staticmethod
    def _sentinel_status(
        _invocation: CommandInvocation,
        runtime: CommandHandlerRuntime,
    ) -> CommandResult:
        return sentinel_status(runtime.sentinel, runtime.pack_loader)
    def _sentinel_alert_context(
        self,
        invocation: CommandInvocation,
    ) -> tuple[str, dict[str, Any]] | None:
        token = str(
            invocation.interaction_id
            or invocation.params.get("alert_token")
            or ""
        ).strip()
        cached = self._sentinel_alerts.get(token)
        if not cached or cached.get("chat_id") != invocation.context.chat_id:
            return None
        return token, cached

    @staticmethod
    def _sentinel_event_refs(event_data: Any) -> dict[str, Any]:
        if not isinstance(event_data, dict):
            return {}
        refs: dict[str, Any] = {}
        for label, keys in {
            "时间": ("timestamp",),
            "检查项": ("check_name", "check_id"),
            "严重度": ("severity_label", "severity"),
            "状态": ("alert_state",),
        }.items():
            for key in keys:
                value = event_data.get(key)
                if value not in (None, ""):
                    refs[label] = value
                    break
        return refs

    @staticmethod
    def _read_environment_profile(max_chars: int = 6000) -> str:
        path = environment_profile_path()
        try:
            text = path.read_text(encoding="utf-8").strip()
        except FileNotFoundError:
            return f"未找到环境档案: {path}"
        except OSError as exc:
            return f"读取环境档案失败: {exc}"
        if not text:
            return f"环境档案为空: {path}"
        if len(text) > max_chars:
            return text[:max_chars] + "\n... (已截断)"
        return text

    def _sentinel_alert_detail(
        self,
        invocation: CommandInvocation,
        _runtime: CommandHandlerRuntime,
    ) -> CommandResult:
        resolved = self._sentinel_alert_context(invocation)
        if resolved is None:
            return CommandResult(
                outcome="sentinel_alert_expired",
                text="告警详情已过期。使用 /sentinel_history 查看告警记录。",
                severity="warning",
            )
        token, cached = resolved
        from chatdome.sentinel.alerter import format_alert_detail

        event_data = cached.get("event")
        detail_text = (
            format_alert_detail(event_data)
            if isinstance(event_data, dict)
            else "暂无详细状态信息。"
        )
        return CommandResult(
            outcome="sentinel_alert_detail_shown",
            event_summary="用户查看了 Sentinel 告警详情。",
            visible_to_agent=True,
            event_refs=self._sentinel_event_refs(event_data),
            text=detail_text,
            facts={"alert_token": token, "event": event_data},
        )

    async def _sentinel_alert_analysis(
        self,
        invocation: CommandInvocation,
        runtime: CommandHandlerRuntime,
    ) -> CommandResult:
        resolved = self._sentinel_alert_context(invocation)
        if resolved is None:
            return CommandResult(
                outcome="sentinel_alert_expired",
                text="告警上下文已过期。使用 /sentinel_history 查看告警记录。",
                severity="warning",
            )
        token, cached = resolved
        event_payload = cached.get("event")
        event_text = (
            event_payload
            if isinstance(event_payload, str)
            else json.dumps(event_payload or {}, ensure_ascii=False, indent=2)
        )
        messages = [
            {
                "role": "system",
                "content": (
                    "你是 ChatDome 的主机安全告警分析助手。"
                    "只基于提供的环境信息和告警信息分析，不要声称已经执行过命令。"
                    "输出中文，面向运维人员，简洁、具体、可执行。"
                ),
            },
            {
                "role": "user",
                "content": (
                    "请分析这条 Sentinel 告警。\n\n"
                    "要求:\n"
                    "- 先给出一句风险判断。\n"
                    "- 点出最值得关注的 IP、用户、端口、时间点和可能原因。\n"
                    "- 给出下一步核实或处置建议，优先使用只读排查命令；需要变更操作时明确提示人工确认。\n"
                    "- 不要复述卡片里的全部原始内容。\n\n"
                    f"环境信息:\n{self._read_environment_profile()}\n\n"
                    f"告警卡片:\n{cached.get('alert_text') or ''}\n\n"
                    f"结构化告警:\n{event_text}"
                ),
            },
        ]
        agent = self._require(runtime.agent, "agent")
        snapshot = await agent.get_active_llm_snapshot()
        try:
            response = await asyncio.wait_for(
                snapshot.client.chat_completion(messages=messages, tools=None),
                timeout=90,
            )
        except TimeoutError:
            return CommandResult(
                outcome="sentinel_alert_analysis_timeout",
                text="告警分析超时，请稍后重试。",
                severity="error",
            )
        try:
            from chatdome.agent.tracker import TokenTracker

            TokenTracker.record_usage(
                chat_id=invocation.context.chat_id,
                model=getattr(snapshot.client, "model", "unknown"),
                action="sentinel_alert_analysis",
                prompt_tokens=response.prompt_tokens,
                completion_tokens=response.completion_tokens,
                total_tokens=response.total_tokens,
            )
        except Exception:
            logger.exception("Failed to record Sentinel alert analysis token usage")
        content = (response.content or "").strip() or "LLM 未返回有效分析。"
        return CommandResult(
            outcome="sentinel_alert_analysis_completed",
            event_summary="用户执行了 Sentinel 告警分析。",
            visible_to_agent=True,
            event_refs=self._sentinel_event_refs(event_payload),
            text=content,
            facts={"alert_token": token, "event": event_payload},
        )

    async def _sentinel_trigger(
        self,
        _invocation: CommandInvocation,
        runtime: CommandHandlerRuntime,
    ) -> CommandResult:
        denied = self._require_admin(runtime)
        if denied:
            return denied
        return await sentinel_trigger(runtime.sentinel)

    @staticmethod
    def _sentinel_history(
        _invocation: CommandInvocation,
        runtime: CommandHandlerRuntime,
    ) -> CommandResult:
        return sentinel_history(runtime.sentinel)

    @staticmethod
    def _sentinel_packs(
        _invocation: CommandInvocation,
        runtime: CommandHandlerRuntime,
    ) -> CommandResult:
        return sentinel_packs(runtime.pack_loader)

    async def _sentinel_mute(
        self,
        invocation: CommandInvocation,
        runtime: CommandHandlerRuntime,
    ) -> CommandResult:
        denied = self._require_admin(runtime)
        if denied:
            return denied
        result = sentinel_mute(
            runtime.sentinel,
            invocation.args,
            chat_id=invocation.context.chat_id,
            source=invocation.context.source,
        )
        await self._reload(
            runtime,
            ("sentinel",),
            f"{invocation.context.source}:/sentinel_mute",
        )
        return result

    async def _sentinel_resume(
        self,
        invocation: CommandInvocation,
        runtime: CommandHandlerRuntime,
    ) -> CommandResult:
        denied = self._require_admin(runtime)
        if denied:
            return denied
        result = sentinel_resume(
            runtime.sentinel,
            chat_id=invocation.context.chat_id,
        )
        await self._reload(
            runtime,
            ("sentinel",),
            f"{invocation.context.source}:/sentinel_resume",
        )
        return result

    @staticmethod
    async def _reload(
        runtime: CommandHandlerRuntime,
        domains: tuple[str, ...],
        reason: str,
    ) -> None:
        if runtime.reload_domains is None:
            return
        result = runtime.reload_domains(domains, reason)
        if inspect.isawaitable(result):
            await result
