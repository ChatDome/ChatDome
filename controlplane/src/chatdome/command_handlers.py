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
from chatdome.runtime_paths import environment_profile_path
from chatdome.slash_commands import (
    CommandDef,
    CommandInvocation,
    CommandResult,
    abandon_command_result,
    approval_details_command_result,
    approve_command_result,
    approve_task_command_result,
    audit_command_result,
    clear_session_command_result,
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
    model_admin_allowed: bool = True


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
        }
        self._sentinel_alerts: dict[str, dict[str, Any]] = {}
        self._sentinel_alert_limit = 200
        self._handlers: dict[str, Callable[[CommandInvocation, CommandHandlerRuntime], Any]] = {
            "/help": self._help,
            "/clear": self._clear,
            "/stop": self._stop,
            "/env": self._env,
            "/audit": self._audit,
            "/token": self._token,
            "/cmd_echo": self._cmd_echo,
            "/engram": self._engram,
            "/model": self._model,
            "/model_list": self._model_list,
            "/model_add": self._model_add,
            "/model_delete": self._model_delete,
            "/model_cancel": self._model_cancel,
            "/codex_login": self._codex_login,
            "/details": self._details,
            "/confirm": self._confirm,
            "/confirm_task": self._confirm_task,
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
            return result
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
    def _require(value: Any, label: str) -> Any:
        if value is None:
            raise RuntimeError(f"{label} is unavailable")
        return value

    @staticmethod
    def _require_model_admin(runtime: CommandHandlerRuntime) -> CommandResult | None:
        if runtime.model_admin_allowed:
            return None
        return CommandResult(
            outcome="unauthorized",
            title="Model management",
            text="当前会话没有 model 管理权限。",
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
        return await stop_task_command_result(runtime.cancel_request)

    @staticmethod
    def _env(_invocation: CommandInvocation, _runtime: CommandHandlerRuntime) -> CommandResult:
        return environment_command_result(environment_profile_path())

    @staticmethod
    def _audit(invocation: CommandInvocation, _runtime: CommandHandlerRuntime) -> CommandResult:
        return audit_command_result(invocation.context, invocation.args)

    @staticmethod
    def _token(invocation: CommandInvocation, _runtime: CommandHandlerRuntime) -> CommandResult:
        return token_usage_command_result(invocation.context)

    async def _cmd_echo(self, invocation: CommandInvocation, runtime: CommandHandlerRuntime) -> CommandResult:
        return command_echo_command_result(self._require(runtime.agent, "agent"), invocation.context)

    async def _engram(self, invocation: CommandInvocation, runtime: CommandHandlerRuntime) -> CommandResult:
        return execute_engram_command(self._require(runtime.agent, "agent"), invocation.args)

    async def _model(self, invocation: CommandInvocation, runtime: CommandHandlerRuntime) -> CommandResult:
        service = self._require(runtime.model_service, "model service")
        if not invocation.args:
            return service.list_profiles()
        denied = self._require_model_admin(runtime)
        if denied:
            return denied
        return await service.switch(invocation.args[0], self._actor(invocation, runtime))

    async def _model_list(self, _invocation: CommandInvocation, runtime: CommandHandlerRuntime) -> CommandResult:
        return self._require(runtime.model_service, "model service").list_profiles()

    async def _model_add(self, invocation: CommandInvocation, runtime: CommandHandlerRuntime) -> CommandResult:
        denied = self._require_model_admin(runtime)
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
        denied = self._require_model_admin(runtime)
        if denied:
            return denied
        service = self._require(runtime.model_service, "model service")
        if invocation.action in {"delete_yes", "delete_no"}:
            return await self.model_workflow.confirm_delete(
                invocation, service, self._actor(invocation, runtime)
            )
        return await self.model_workflow.prepare_delete(invocation, service)

    async def _model_cancel(self, invocation: CommandInvocation, runtime: CommandHandlerRuntime) -> CommandResult:
        denied = self._require_model_admin(runtime)
        if denied:
            return denied
        return self.model_workflow.cancel(
            invocation, self._require(runtime.model_service, "model service")
        )

    async def _codex_login(self, invocation: CommandInvocation, runtime: CommandHandlerRuntime) -> CommandResult:
        denied = self._require_model_admin(runtime)
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
            self._require(runtime.agent, "agent"), invocation.context, invocation.args
        )

    async def _confirm(self, invocation: CommandInvocation, runtime: CommandHandlerRuntime) -> CommandResult:
        return await approve_command_result(
            self._require(runtime.agent, "agent"), invocation.context, invocation.args
        )

    async def _confirm_task(self, invocation: CommandInvocation, runtime: CommandHandlerRuntime) -> CommandResult:
        return await approve_task_command_result(
            self._require(runtime.agent, "agent"), invocation.context, invocation.args
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

    @staticmethod
    async def _sentinel_trigger(
        _invocation: CommandInvocation,
        runtime: CommandHandlerRuntime,
    ) -> CommandResult:
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
