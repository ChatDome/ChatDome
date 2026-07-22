"""
Telegram Bot setup and message routing.

Uses python-telegram-bot v20+ async API.
Routes messages through authentication → AI Agent → reply.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import re
from dataclasses import replace
from pathlib import Path
from typing import Any

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.error import Conflict
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    CallbackQueryHandler,
    filters,
)

from chatdome.agent.core import Agent
from chatdome.agent.result import AgentResult, coerce_agent_result
from chatdome.command_handlers import (
    CommandHandlerRuntime,
    CommandHandlerService,
)
from chatdome.outbound.builders import (
    EnvironmentFactsBuilder,
    OutboundMessageBuilder,
    build_approval_details,
    build_approval_request,
    build_notification_message,
    build_sentinel_alert,
)
from chatdome.outbound.renderers.telegram import TelegramOutboundRenderer, group_controls
from chatdome.platform_adapters import (
    TelegramDeliveryTarget,
    TelegramPlatformAdapter,
)
from chatdome.config import AIConfig, ChatDomeConfig
from chatdome.errors import user_facing_error_message
from chatdome.telegram.auth import Authenticator
from chatdome.telegram.formatting import MessageMarkup, TelegramMessageFormatter
from chatdome.runtime_paths import environment_profile_path
from chatdome.model_commands import ModelCommandService
from chatdome.slash_commands import (
    CommandContext,
    CommandDef,
    CommandInvocation,
    CommandRegistry,
    CommandResult,
    bind_command_catalog,
    format_command_help,
)
from chatdome.llm.codex_oauth_service import CodexOAuthService
from chatdome.llm.profile_admin import (
    LLMProfileAdminService,
    ProfileActor,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Help text
# ---------------------------------------------------------------------------

HELP_TEXT = format_command_help()


# ---------------------------------------------------------------------------
# Bot class
# ---------------------------------------------------------------------------

class TelegramBot:
    """
    Telegram Bot that bridges user messages to the AI Agent.
    """

    def __init__(
        self,
        config: ChatDomeConfig,
        agent: Agent,
        profile_admin: LLMProfileAdminService | None = None,
    ):
        self.config = config
        self.agent = agent
        self.profile_admin = profile_admin
        self._codex_oauth = CodexOAuthService(profile_admin)
        self.auth = Authenticator(config.telegram.allowed_chat_ids)
        self.max_message_length = config.telegram.max_message_length
        self._app: Application | None = None
        self._environment_profile_path = environment_profile_path()
        self._sentinel: Any = None   # SentinelScheduler, injected via set_sentinel()
        self._pack_loader: Any = None
        self._approval_detail_tasks: dict[str, asyncio.Task] = {}
        self._approval_resolution_tasks: dict[int, asyncio.Task] = {}
        self._round_limit_tasks: dict[int, asyncio.Task] = {}
        self._message_tasks: dict[int, asyncio.Task] = {}
        self._command_targets: dict[str, Any] = {}
        # Default policy: plain text output; markdown can be enabled per message.
        self._formatter = TelegramMessageFormatter(enable_markdown=True)
        self._platform_adapter = TelegramPlatformAdapter(self._deliver_telegram_rendered)
        self._command_service = CommandHandlerService(self._command_runtime)
        self._command_registry = self._get_command_registry()

    def _get_command_registry(self) -> CommandRegistry:
        registry = getattr(self, "_command_registry", None)
        if registry is None:
            registry = CommandRegistry()
            bind_command_catalog(
                registry,
                "telegram",
                self._command_service.handle,
            )
            self._command_registry = registry
        return registry

    def set_sentinel(self, scheduler: Any, pack_loader: Any = None) -> None:
        """Inject Sentinel scheduler after construction (avoids circular deps)."""
        self._sentinel = scheduler
        self._pack_loader = pack_loader
        if hasattr(self.agent, "set_sentinel"):
            self.agent.set_sentinel(scheduler)

    async def post_init(self, app: Application) -> None:
        """Called by the Telegram application after initialization, inside the event loop."""
        self.agent.start()
        
        # Send startup notifications
        for chat_id in self.config.telegram.allowed_chat_ids:
            try:
                await self._platform_adapter.deliver(
                    build_notification_message(
                        title="ChatDome online",
                        summary="ChatDome 已上线。",
                        body="🚀 ChatDome 已上线\n安全探针与大模型推理引擎已就绪。",
                        outcome="service_started",
                        facts={"lifecycle": "started"},
                    ),
                    target=TelegramDeliveryTarget(app.bot, chat_id),
                )
            except Exception as e:
                logger.error("Failed to send startup message to %s: %s", chat_id, e)

    async def post_stop(self, app: Application) -> None:
        """Called when the application stops."""
        sentinel = getattr(self, "_sentinel", None)
        if sentinel is not None and hasattr(sentinel, "stop_gracefully"):
            try:
                await sentinel.stop_gracefully()
            except Exception as e:
                logger.error("Failed to stop Sentinel scheduler gracefully: %s", e)

        for chat_id in self.config.telegram.allowed_chat_ids:
            try:
                await self._platform_adapter.deliver(
                    build_notification_message(
                        title="ChatDome offline",
                        summary="ChatDome 已下线。",
                        body="💤 ChatDome 已下线\n主控进程已退出。",
                        outcome="service_stopped",
                        facts={"lifecycle": "stopped"},
                    ),
                    target=TelegramDeliveryTarget(app.bot, chat_id),
                )
            except Exception as e:
                logger.error("Failed to send shutdown message to %s: %s", chat_id, e)

    def build(self) -> Application:
        """Build and configure the Telegram Application."""
        builder = Application.builder().token(self.config.telegram.bot_token)
        proxy_url = str(getattr(self.config.telegram, "proxy_url", "") or "").strip()
        if proxy_url:
            if hasattr(builder, "proxy_url"):
                builder = builder.proxy_url(proxy_url)
            else:
                logger.warning("telegram.proxy_url is configured but this PTB version does not support proxy_url().")
            if hasattr(builder, "get_updates_proxy_url"):
                builder = builder.get_updates_proxy_url(proxy_url)

        self._app = builder.post_init(self.post_init).post_stop(self.post_stop).build()

        for command in self._get_command_registry().commands:
            for exposed_name in (command.name, *command.aliases):
                self._app.add_handler(
                    self._command_handler(
                        exposed_name.removeprefix("/"),
                        command=command,
                    )
                )
        self._app.add_handler(CallbackQueryHandler(self._handle_callback_query))
        self._app.add_handler(
            MessageHandler(filters.TEXT & ~filters.COMMAND, self._handle_message)
        )

        # Error handler
        self._app.add_error_handler(self._handle_error)

        logger.info("Telegram bot built successfully")
        return self._app

    @staticmethod
    def _log_value(value: Any, *, max_len: int = 200) -> str:
        text = " ".join(str(value).replace("\r", " ").replace("\n", " ").replace("\t", " ").split())
        if len(text) > max_len:
            text = text[: max_len - 3] + "..."
        return text.replace("\\", "\\\\").replace('"', '\\"')

    def _log_telegram_command(self, update: Update, command_name: str) -> None:
        chat = getattr(update, "effective_chat", None)
        user = getattr(update, "effective_user", None)
        message = getattr(update, "effective_message", None)
        command_text = getattr(message, "text", None) or f"/{command_name}"
        chat_id = getattr(chat, "id", "-") if chat is not None else "-"
        user_id = getattr(user, "id", "-") if user is not None else "-"
        logger.info(
            '[Telegram command received] chat_id=%s user_id=%s command="%s"',
            chat_id,
            user_id,
            self._log_value(command_text),
        )

    def _log_telegram_callback(self, update: Update, callback_data: str) -> None:
        chat = getattr(update, "effective_chat", None)
        user = getattr(update, "effective_user", None)
        chat_id = getattr(chat, "id", "-") if chat is not None else "-"
        user_id = getattr(user, "id", "-") if user is not None else "-"
        logger.info(
            '[Telegram callback received] chat_id=%s user_id=%s callback_data="%s"',
            chat_id,
            user_id,
            self._log_value(callback_data),
        )

    def _command_context_for_update(
        self,
        update: Update,
        context: ContextTypes.DEFAULT_TYPE | None = None,
    ) -> CommandContext:
        """Build shared command context for Telegram messages and callbacks."""

        chat = getattr(update, "effective_chat", None)
        user = getattr(update, "effective_user", None)
        chat_id = int(getattr(chat, "id", 0) or 0)
        actor_id = str(getattr(user, "id", "") or "")

        def record_event(event: dict[str, Any]) -> None:
            manager = getattr(getattr(self, "agent", None), "session_manager", None)
            if manager is not None:
                manager.record_control_event(chat_id, event)

        command_context = CommandContext(
            source="telegram",
            chat_id=chat_id,
            actor_id=actor_id,
            event_recorder=record_event,
            capabilities=(
                frozenset({"model_admin"})
                if self._is_model_admin(update) else frozenset()
            ),
        )
        target = getattr(update, "effective_message", None)
        if target is not None:
            self._command_targets[command_context.request_id] = target
        return command_context

    def _is_model_admin(self, update: Update | None) -> bool:
        if update is None or update.effective_chat is None:
            return False
        chat = update.effective_chat
        config = getattr(self, "config", None)
        if config is None:
            return False
        telegram_config = config.telegram
        admin_ids = set(
            telegram_config.admin_chat_ids
            or telegram_config.allowed_chat_ids
            or []
        )
        return bool(
            self._check_auth(update)
            and getattr(chat, "type", "") == "private"
            and chat.id in admin_ids
        )

    async def _sync_model_manager(self) -> None:
        manager = self._get_llm_manager()
        reloader = getattr(manager, "reload_profiles", None)
        if callable(reloader):
            value = reloader(self.config.ai_profiles, self.config.active_ai_profile)
            if inspect.isawaitable(value):
                await value

    def _command_runtime(
        self,
        invocation: CommandInvocation,
    ) -> CommandHandlerRuntime:
        target = self._command_targets.pop(invocation.context.request_id, None)

        async def publish_deferred(result: CommandResult) -> None:
            delivery_target = target
            if delivery_target is None and self._app is not None:
                delivery_target = TelegramDeliveryTarget(
                    self._app.bot,
                    invocation.context.chat_id,
                )
            await self._platform_adapter.deliver_result(
                result,
                target=delivery_target,
            )

        def schedule_task(awaitable):
            if self._app is not None:
                return self._app.create_task(awaitable)
            return asyncio.create_task(awaitable)

        return CommandHandlerRuntime(
            agent=self.agent,
            model_service=self._model_command_service(),
            codex_oauth=self._codex_oauth,
            config=self.config,
            sentinel=self._sentinel,
            pack_loader=self._pack_loader,
            profile_actor=ProfileActor(
                source="telegram",
                chat_id=invocation.context.chat_id,
                user_id=(
                    int(invocation.context.actor_id)
                    if str(invocation.context.actor_id).isdigit()
                    else 0
                ),
            ),
            cancel_request=lambda: self._cancel_active_task_for_chat(
                invocation.context.chat_id
            ),
            sync_model=self._sync_model_manager,
            publish_deferred=publish_deferred,
            schedule_task=schedule_task,
            defer_commands=True,
            model_admin_allowed="model_admin" in invocation.context.capabilities,
        )

    def _command_handler(
        self,
        command_name: str,
        *,
        command: CommandDef | None = None,
    ) -> CommandHandler:
        async def wrapped(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
            if not self._check_auth(update):
                self._log_telegram_command(update, command_name)
                return

            message = getattr(update, "effective_message", None)
            raw = self._platform_adapter.receive_message(
                getattr(message, "text", "") or f"/{command_name}"
            ).strip()
            args = tuple(str(item) for item in (getattr(context, "args", None) or ()))
            command_def = command or self._get_command_registry().resolve_name(
                f"/{command_name}"
            )
            if command_def is None:
                raise RuntimeError(f"command is not registered: /{command_name}")
            invocation = self._platform_adapter.receive_command(
                raw=raw,
                raw_name=f"/{command_name}",
                command=command_def,
                args=args,
                context=self._command_context_for_update(update, context),
            )
            await self._platform_adapter.dispatch(
                invocation,
                target=update.message,
            )

        return CommandHandler(command_name, wrapped)

    async def _dispatch_callback_command(
        self,
        target: Any,
        *,
        data: str,
        command_name: str,
        args: tuple[str, ...] = (),
        command_context: CommandContext,
        action: str = "",
        interaction_id: str = "",
        params: dict[str, Any] | None = None,
    ) -> CommandResult:
        """Run a Telegram semantic action through the canonical command service."""

        command = (
            self._get_command_registry().resolve_name(command_name)
            or self._command_service.action_definition(action)
        )
        if command is None:
            raise RuntimeError(f"command is not registered: {command_name}")
        invocation = self._platform_adapter.receive_callback(
            data=data,
            command=command,
            args=args,
            context=command_context,
            action=action,
            interaction_id=interaction_id,
            params=params,
        )
        return await self._platform_adapter.dispatch(
            invocation,
            target=target,
        )

    # ----- Platform task control -----

    def _active_task_for_chat(self, chat_id: int) -> asyncio.Task | None:
        for tasks in (
            self._message_tasks,
            self._approval_resolution_tasks,
            self._round_limit_tasks,
        ):
            task = tasks.get(chat_id)
            if task is None:
                continue
            if task.done():
                tasks.pop(chat_id, None)
                continue
            return task
        return None

    @staticmethod
    def _approval_decision_text(message: Any, action: str) -> str:
        """Keep the approval purpose visible after replacing the action card."""
        source = str(getattr(message, "text", "") or getattr(message, "caption", "") or "")
        purpose = next(
            (line.strip() for line in source.splitlines() if line.strip().startswith("目的：")),
            "目的：信息不可用",
        )
        title = "❌ 已拒绝" if action == "REJECT" else "✅ 已批准"
        return f"{title}\n{purpose}"

    async def _start_approval_resolution(
        self,
        message: Any,
        chat_id: int,
        *,
        data: str,
        command_name: str,
        args: tuple[str, ...],
        command_context: CommandContext,
    ) -> None:
        existing_task = self._approval_resolution_tasks.get(chat_id)
        if existing_task and not existing_task.done():
            return

        coroutine = self._run_approval_resolution(
            message=message,
            chat_id=chat_id,
            data=data,
            command_name=command_name,
            args=args,
            command_context=command_context,
        )
        task = self._app.create_task(coroutine) if self._app is not None else asyncio.create_task(coroutine)
        self._approval_resolution_tasks[chat_id] = task

        def _drop_finished_task(done_task: asyncio.Task) -> None:
            if self._approval_resolution_tasks.get(chat_id) is done_task:
                self._approval_resolution_tasks.pop(chat_id, None)

        task.add_done_callback(_drop_finished_task)

    async def _run_approval_resolution(
        self,
        *,
        message: Any,
        chat_id: int,
        data: str,
        command_name: str,
        args: tuple[str, ...],
        command_context: CommandContext,
    ) -> None:
        try:
            await self._dispatch_callback_command(
                message,
                data=data,
                command_name=command_name,
                args=args,
                command_context=command_context,
            )
        except asyncio.CancelledError:
            logger.info("Approval resolution stopped for chat_id=%s", chat_id)
            raise
        except Exception as e:
            logger.exception("Approval resolution failed for chat_id=%s", chat_id)
            await self._send_long_message(
                message,
                self._format_error_text(
                    e,
                    prefix="命令处理失败",
                    fallback="命令处理失败，请重新发起任务。",
                ),
            )

    async def _cancel_active_task_for_chat(self, chat_id: int) -> bool:
        task = self._active_task_for_chat(chat_id)
        if task is None:
            return False
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        except Exception:
            logger.debug("Task ended while stopping chat_id=%s", chat_id, exc_info=True)
        return True

    # ----- Message handler -----
    # ----- Message handler -----

    async def _handle_message(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        """Handle regular text messages — route to AI Agent."""
        if not self._check_auth(update):
            return
        if await self._handle_llm_admin_message(update, context):
            return

        chat_id = update.effective_chat.id
        user_message = self._platform_adapter.receive_message(
            update.message.text
        )

        logger.info(
            "Message from chat_id=%d: %s",
            chat_id, user_message[:100],
        )

        if self._active_task_for_chat(chat_id) is not None:
            await update.message.reply_text("任务正在运行。\n发送 /stop 中止。")
            return

        thinking_msg = await update.message.reply_text("⏳")
        coroutine = self._run_agent_message(
            message=update.message,
            chat_id=chat_id,
            user_message=user_message,
            thinking_msg=thinking_msg,
        )
        if self._app is not None:
            task = self._app.create_task(coroutine)
        else:
            task = asyncio.create_task(coroutine)

        self._message_tasks[chat_id] = task

        def _drop_finished_task(done_task: asyncio.Task) -> None:
            if self._message_tasks.get(chat_id) is done_task:
                self._message_tasks.pop(chat_id, None)

        task.add_done_callback(_drop_finished_task)

    async def _run_agent_message(
        self,
        message,
        chat_id: int,
        user_message: str,
        thinking_msg,
    ) -> None:
        try:
            response = await self.agent.handle_message(chat_id, user_message)
            try:
                await thinking_msg.delete()
            except Exception:
                pass
            await self._send_agent_result(message, response)
        except asyncio.CancelledError:
            try:
                await thinking_msg.delete()
            except Exception:
                pass
            logger.info("Telegram task stopped for chat_id=%s", chat_id)
            raise
        except Exception as e:
            logger.error("Error handling message: %s", e, exc_info=True)
            error_text = self._format_error_text(
                e,
                prefix="⚠️ 处理消息失败",
                fallback="处理消息时发生未预期错误，请查看日志。",
            )
            try:
                await thinking_msg.edit_text(error_text)
            except Exception:
                await message.reply_text(error_text)

    # ----- Interactive Approval -----

    @staticmethod
    def _rendered_control_markup(rendered):
        keyboard = [
            [InlineKeyboardButton(control.label, callback_data=control.data) for control in row]
            for row in group_controls(rendered.controls)
        ]
        return InlineKeyboardMarkup(keyboard) if keyboard else None

    async def _send_approval_request(self, message, data: dict) -> None:
        outbound = build_approval_request(data)
        await self._platform_adapter.deliver(outbound, target=message)

    @staticmethod
    def _approval_action_markup(data: dict) -> Any:
        payload = dict(data or {})
        payload["ok"] = True
        outbound = build_approval_details(payload)
        rendered = TelegramOutboundRenderer().render(outbound)
        return TelegramBot._rendered_control_markup(rendered)

    async def _send_approval_actions(self, message, data: dict) -> None:
        """Send compact action buttons after the detailed analysis message."""
        await self._reply_text(
            message,
            "请选择操作。",
            markup=MessageMarkup.PLAIN,
            reply_markup=self._approval_action_markup(data),
        )

    @staticmethod
    def _approval_detail_task_key(chat_id: int, approval_id: str | None) -> str:
        approval_key = (approval_id or "").strip() or "legacy"
        return f"{chat_id}:{approval_key}"

    async def _start_approval_detail_analysis(
        self,
        message,
        chat_id: int,
        approval_id: str | None,
        command_context: CommandContext | None = None,
    ) -> None:
        """Start an approval detail review without blocking later chat updates."""
        task_key = self._approval_detail_task_key(chat_id, approval_id)
        existing_task = self._approval_detail_tasks.get(task_key)
        if existing_task and not existing_task.done():
            await self._send_long_message(
                message,
                "命令分析仍在进行中，请稍候。",
            )
            return

        await self._send_long_message(
            message,
            "⏳",
        )

        coroutine = self._run_approval_detail_analysis(
            message=message,
            chat_id=chat_id,
            approval_id=approval_id,
            command_context=command_context,
        )
        if self._app is not None:
            task = self._app.create_task(coroutine)
        else:
            task = asyncio.create_task(coroutine)

        self._approval_detail_tasks[task_key] = task

        def _drop_finished_task(done_task: asyncio.Task) -> None:
            if self._approval_detail_tasks.get(task_key) is done_task:
                self._approval_detail_tasks.pop(task_key, None)

        task.add_done_callback(_drop_finished_task)

    async def _run_approval_detail_analysis(
        self,
        message,
        chat_id: int,
        approval_id: str | None,
        command_context: CommandContext | None = None,
    ) -> None:
        context = command_context or CommandContext(
            source="telegram",
            chat_id=chat_id,
        )
        args = (approval_id,) if approval_id else ()


        try:
            result = await self._dispatch_callback_command(
                message,
                data="approval:details",
                command_name="/details",
                args=args,
                command_context=context,
            )
        except Exception as e:
            logger.exception("Failed to load approval details in background")
            await self._send_long_message(
                message,
                self._format_error_text(
                    e,
                    prefix="命令分析失败",
                    fallback="命令分析失败，请稍后重试。",
                ),
            )
            return

        if result.outcome != "details_shown" or result.outbound is None:
            return

        rendered = self._platform_adapter.render(result.outbound)
        text = "\n".join(rendered.text_parts)
        facts = result.outbound.facts
        self._record_visible_context(
            chat_id,
            event_type="approval_detail",
            user_action="查看待审批命令分析",
            assistant_summary=text,
            refs={
                **dict(result.outbound.refs),
                "safety_status": getattr(facts, "safety_status", ""),
                "risk_level": getattr(facts, "risk_level", ""),
            },
        )

    async def _send_approval_detail_result(
        self,
        message,
        details: dict,
        *,
        chat_id: int,
        full: bool = False,
    ) -> None:
        analysis = details.get("analysis", {}) or {}
        command_hash = str(details.get("command_hash", ""))
        outbound = build_approval_details(details)
        rendered = TelegramOutboundRenderer(full=full).render(outbound)
        text = "\n".join(rendered.text_parts)
        await self._send_long_message(
            message,
            text,
            reply_markup=self._rendered_control_markup(rendered),
        )
        self._record_visible_context(
            chat_id,
            event_type="approval_detail",
            user_action="查看待审批命令分析",
            assistant_summary=text,
            refs={
                "approval_id": details.get("approval_id", ""),
                "run_id": details.get("run_id", ""),
                "command_hash": command_hash[:12],
                "safety_status": analysis.get("safety_status", "UNSAFE"),
                "risk_level": analysis.get("risk_level", "HIGH"),
            },
        )

    @staticmethod
    def _format_approval_detail_text(details: dict) -> str:
        outbound = build_approval_details(details)
        rendered = TelegramOutboundRenderer().render(outbound)
        return "\n".join(rendered.text_parts)

    async def _send_round_limit_prompt(self, message, data: dict[str, Any] | None = None) -> None:
        """Ask user whether to continue after reaching one execution window."""
        payload = dict(data or {})
        payload.setdefault("window", self.agent.config.max_rounds_per_turn)
        outbound = OutboundMessageBuilder().from_agent_result(
            AgentResult.round_limit(payload)
        )
        await self._platform_adapter.deliver(outbound, target=message)

    async def _dispatch_round_limit_command(
        self,
        message: Any,
        chat_id: int,
        action: str,
        command_context: CommandContext | None = None,
    ) -> CommandResult:
        """Resolve one round-limit button through the shared command pipeline."""

        normalized_action = str(action or "").strip().upper()
        if normalized_action not in {"CONTINUE", "ABANDON"}:
            raise ValueError("unsupported round-limit action")
        command_name = "/continue" if normalized_action == "CONTINUE" else "/reject"
        semantic_action = "" if normalized_action == "CONTINUE" else "abandon"

        return await self._dispatch_callback_command(
            message,
            data=normalized_action,
            command_name=command_name,
            command_context=command_context
            or CommandContext(source="telegram", chat_id=chat_id),
            action=semantic_action,
        )

    async def _start_round_limit_resolution(
        self,
        message: Any,
        chat_id: int,
        action: str,
        command_context: CommandContext | None = None,
    ) -> None:
        """Continue a round-limited task in the background after a callback click."""
        normalized_action = (action or "").strip().upper()
        if normalized_action != "CONTINUE":
            await self._dispatch_round_limit_command(
                message,
                chat_id,
                normalized_action,
                command_context,
            )
            return

        existing_task = self._round_limit_tasks.get(chat_id)
        if existing_task and not existing_task.done():
            await self._send_long_message(
                message,
                "任务已在执行中，请稍候。",
            )
            return

        status_msg = await message.reply_text("继续执行中…")
        coroutine = self._run_round_limit_resolution(
            message=message,
            status_message=status_msg,
            chat_id=chat_id,
            action=normalized_action,
            command_context=command_context,
        )
        if self._app is not None:
            task = self._app.create_task(coroutine)
        else:
            task = asyncio.create_task(coroutine)

        self._round_limit_tasks[chat_id] = task

        def _drop_finished_task(done_task: asyncio.Task) -> None:
            if self._round_limit_tasks.get(chat_id) is done_task:
                self._round_limit_tasks.pop(chat_id, None)

        task.add_done_callback(_drop_finished_task)

    async def _run_round_limit_resolution(
        self,
        message: Any,
        status_message: Any,
        chat_id: int,
        action: str,
        command_context: CommandContext | None = None,
    ) -> None:
        """Run round-limit continuation without tying it to callback query timeout."""
        try:
            await self._dispatch_round_limit_command(
                message,
                chat_id,
                action,
                command_context,
            )
        except asyncio.CancelledError:
            logger.warning("Round-limit continuation task cancelled for chat_id=%s", chat_id)
            raise
        except Exception as e:
            logger.exception("Round-limit continuation failed for chat_id=%s", chat_id)
            await self._send_long_message(
                message,
                self._format_error_text(
                    e,
                    prefix="继续执行失败",
                    fallback="继续执行失败，请稍后重试。",
                ),
            )
            return
        finally:
            try:
                await status_message.delete()
            except Exception:
                pass


    def _get_llm_manager(self):
        return getattr(self.agent, "llm_manager", None)

    def _model_command_service(self) -> ModelCommandService:
        return ModelCommandService(
            self._get_llm_manager(),
            self.profile_admin,
            runtime_sync=self._sync_model_manager,
        )

    def _format_llm_profile_list(self) -> str:
        result = self._model_command_service().list_profiles()
        outbound = OutboundMessageBuilder().from_command_result(None, result)
        return "\n".join(TelegramOutboundRenderer().render(outbound).text_parts)

    @staticmethod
    def _default_codex_profile(profile_name: str) -> AIConfig:
        return CodexOAuthService.default_profile(profile_name)

    def _resolve_codex_login_profile(
        self,
        requested_profile: str = "",
    ) -> tuple[str, AIConfig, bool]:
        manager = self._get_llm_manager()
        active_profile = (
            manager.get_active_profile_name() if manager is not None else ""
        )
        return self._codex_oauth.resolve_profile(
            self.config,
            requested_profile,
            active_profile=active_profile,
        )

    async def _handle_llm_admin_message(
        self,
        update: Update,
        context: ContextTypes.DEFAULT_TYPE,
    ) -> bool:
        command_context = self._command_context_for_update(update, context)
        pending = self._command_service.model_workflow.pending_input(command_context)
        if pending is None:
            self._command_targets.pop(command_context.request_id, None)
            return False

        nonce, action = pending
        text = str(update.message.text or "").strip()
        params: dict[str, Any]
        if action == "input_api_key":
            if text != "-":
                try:
                    await update.message.delete()
                except Exception:
                    await update.message.reply_text(
                        "删除 API Key 消息后，使用本地终端完成配置。"
                    )
                    return True
            params = {"secret": text}
        else:
            params = {"input": text}

        await self._dispatch_callback_command(
            update.message,
            data=f"llm_admin:{action}:{nonce}",
            command_name="/model_add",
            command_context=command_context,
            action=action,
            interaction_id=nonce,
            params=params,
        )
        return True

    async def _handle_llm_admin_callback(
        self,
        update: Update,
        context: ContextTypes.DEFAULT_TYPE,
        callback_data: str,
    ) -> None:
        query = update.callback_query
        if query is None or query.message is None:
            return
        parts = callback_data.split(":", 2)
        if len(parts) != 3:
            await query.message.reply_text("Model 操作已失效，请重新开始。")
            return
        _, action, nonce = parts
        command_name = (
            "/model_delete"
            if action in {"delete_yes", "delete_no"}
            else "/model_add"
        )
        await self._clear_callback_message_markup(
            query,
            "model command callback message",
        )
        await self._dispatch_callback_command(
            query.message,
            data=callback_data,
            command_name=command_name,
            command_context=self._command_context_for_update(update, context),
            action=action,
            interaction_id=nonce,
            params={
                "command": command_name,
                "action": action,
                "interaction_id": nonce,
            },
        )

    async def _dispatch_sentinel_alert_action(
        self,
        update: Update,
        context: ContextTypes.DEFAULT_TYPE | None,
        query: Any,
        action: str,
        alert_token: str,
    ) -> None:
        """Adapt Telegram callback UI around one shared semantic action."""

        thinking_message = None
        if action == "sentinel_alert_analysis":
            await self._set_callback_message_markup(
                query,
                self._sentinel_alert_reply_markup(
                    alert_token,
                    include_analysis=False,
                ),
                "sentinel alert analysis",
            )
            thinking_message = await query.message.reply_text("⏳")
        try:
            result = await self._dispatch_callback_command(
                query.message,
                data=f"{action}:{alert_token}",
                command_name=f"/{action}",
                command_context=self._command_context_for_update(update, context),
                action=action,
                interaction_id=alert_token,
                params={"action": action, "alert_token": alert_token},
            )
            if result.outcome == "sentinel_alert_expired":
                await self._clear_callback_message_markup(
                    query,
                    "expired sentinel alert action",
                )
        finally:
            if thinking_message is not None:
                try:
                    await thinking_message.delete()
                except Exception:
                    logger.debug("Failed to delete Sentinel analysis progress message")
    async def _clear_callback_message_markup(self, query, context_label: str = "callback message") -> None:
        await self._set_callback_message_markup(query, None, context_label)

    async def _set_callback_message_markup(
        self,
        query,
        reply_markup: InlineKeyboardMarkup | None,
        context_label: str = "callback message",
    ) -> None:
        try:
            await query.edit_message_reply_markup(reply_markup=reply_markup)
        except Exception:
            logger.exception("Failed to edit %s markup", context_label)

    async def _handle_callback_query(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle inline keyboard button clicks."""
        query = update.callback_query
        if query is None:
            return

        try:
            await query.answer()
        except Exception:
            logger.exception("Failed to answer callback query")

        try:
            if not self._check_auth(update):
                return

            chat = update.effective_chat
            if chat is None or query.message is None:
                return

            chat_id = chat.id
            callback_data = query.data or ""
            self._log_telegram_callback(update, callback_data)

            if callback_data.startswith("llm_admin:"):
                await self._handle_llm_admin_callback(update, context, callback_data)
                return

            if callback_data.startswith(
                ("sentinel_alert_analysis:", "sentinel_alert_detail:")
            ):
                action, alert_token = callback_data.split(":", 1)
                await self._dispatch_sentinel_alert_action(
                    update,
                    context,
                    query,
                    action,
                    alert_token.strip(),
                )
                return

            approval_action = ""
            approval_id = ""
            if callback_data.startswith("approval:"):
                parts = callback_data.split(":", 2)
                if len(parts) == 3:
                    approval_action = parts[1].strip()
                    approval_id = parts[2].strip()

            if callback_data in {"continue_round_task", "abandon_round_task"}:
                action = "CONTINUE" if callback_data == "continue_round_task" else "ABANDON"
                try:
                    await query.edit_message_reply_markup(reply_markup=None)
                except Exception:
                    logger.exception("Failed to edit round-limit callback message markup")

                await self._start_round_limit_resolution(
                    query.message,
                    chat_id,
                    action,
                    self._command_context_for_update(update),
                )
                return

            if callback_data == "show_cmd_details" or approval_action == "details":
                await self._clear_callback_message_markup(query, "approval detail callback message")
                await self._start_approval_detail_analysis(
                    query.message,
                    chat_id,
                    approval_id or None,
                    self._command_context_for_update(update),
                )
                return
            if approval_action == "approve_task":
                action = "APPROVE_TASK"
            elif approval_action == "approve":
                action = "APPROVE"
            elif approval_action == "reject":
                action = "REJECT"
            elif callback_data == "approve_task_cmd":
                action = "APPROVE_TASK"
            elif callback_data == "approve_cmd":
                action = "APPROVE"
            elif callback_data == "reject_cmd":
                action = "REJECT"
            else:
                await self._send_long_message(query.message, "Unknown action button. Please retry.")
                return
            command_name = {
                "APPROVE_TASK": "/confirm_task",
                "APPROVE": "/confirm",
                "REJECT": "/reject",
            }[action]

            await query.edit_message_text(
                text=self._approval_decision_text(query.message, action),
                reply_markup=None,
            )
            await self._start_approval_resolution(
                query.message,
                chat_id,
                data=callback_data,
                command_name=command_name,
                args=(approval_id,) if approval_id else (),
                command_context=self._command_context_for_update(update),
            )
            return
        except asyncio.TimeoutError:
            await self._send_long_message(
                query.message,
                "按钮操作超时，请重试。",
            )
        except Exception as e:
            logger.exception("Callback query handling failed")
            await query.message.reply_text(
                self._format_error_text(
                    e,
                    prefix="按钮操作处理失败",
                    fallback="按钮操作处理失败，请稍后重试。",
                )
            )


    # ----- Utilities -----

    async def _deliver_telegram_rendered(self, message, rendered) -> None:
        text = "\n".join(
            part for part in rendered.text_parts if str(part or "").strip()
        )
        if not text:
            return
        reply_markup = self._rendered_control_markup(rendered)
        if isinstance(message, TelegramDeliveryTarget):
            if len(text) > self.max_message_length:
                text = text[: self.max_message_length - 20] + "\n... (已截断)"
            await self._send_bot_text(
                message.bot,
                message.chat_id,
                text,
                reply_markup=reply_markup,
            )
            return
        await self._send_long_message(
            message,
            text,
            markup=MessageMarkup.PLAIN,
            reply_markup=reply_markup,
        )


    async def _send_command_result(
        self,
        message,
        result: CommandResult,
    ) -> None:
        if result is None:
            return
        outbound = result.outbound or OutboundMessageBuilder().from_command_result(
            None,
            result,
        )
        await self._platform_adapter.deliver(outbound, target=message)

    async def _send_agent_result(self, message, result: AgentResult | str | None) -> None:
        """Render a structured Agent result into Telegram messages."""
        agent_result = coerce_agent_result(result)
        outbound = OutboundMessageBuilder().from_agent_result(agent_result)
        await self._platform_adapter.deliver(outbound, target=message)

    @staticmethod
    def _format_error_text(exc: BaseException, *, prefix: str, fallback: str) -> str:
        """Format a user-visible error without leaking provider internals."""
        detail = user_facing_error_message(exc, fallback=fallback)
        if not prefix:
            return detail
        return f"{prefix}: {detail}"

    async def _reply_text(
        self,
        message,
        text: str,
        *,
        markup: MessageMarkup = MessageMarkup.PLAIN,
        reply_markup=None,
    ) -> None:
        """Send a single reply through formatter policy."""
        rendered = self._formatter.render(text, markup=markup)
        kwargs: dict[str, Any] = {}
        if rendered.parse_mode:
            kwargs["parse_mode"] = rendered.parse_mode
        if reply_markup is not None:
            kwargs["reply_markup"] = reply_markup
        await message.reply_text(rendered.text, **kwargs)

    async def _send_text(
        self,
        update: Update,
        text: str,
        *,
        markup: MessageMarkup = MessageMarkup.TELEGRAM_MARKDOWN,
    ) -> None:
        """Compatibility helper for command handlers that reply to an update."""
        await self._send_long_message(update.message, text, markup=markup)

    async def _send_bot_text(
        self,
        bot,
        chat_id: int,
        text: str,
        *,
        markup: MessageMarkup = MessageMarkup.PLAIN,
        reply_markup=None,
    ) -> None:
        """Send bot-initiated chat message through formatter policy."""
        rendered = self._formatter.render(text, markup=markup)
        kwargs: dict[str, Any] = {}
        if rendered.parse_mode:
            kwargs["parse_mode"] = rendered.parse_mode
        if reply_markup is not None:
            kwargs["reply_markup"] = reply_markup
        await bot.send_message(chat_id=chat_id, text=rendered.text, **kwargs)


    @staticmethod
    def _compact_visible_value(value: Any, max_chars: int = 500) -> str:
        text = " ".join(str(value or "").split()).strip()
        if len(text) <= max_chars:
            return text
        return text[: max_chars - 1].rstrip() + "…"

    @staticmethod
    def _alert_event_reference_fields(event_data: Any) -> dict[str, Any]:
        if not isinstance(event_data, dict):
            return {}

        refs: dict[str, Any] = {}
        key_map = {
            "check_id": "check_id",
            "severity": "severity",
            "severity_label": "severity_label",
            "timestamp": "timestamp",
            "fingerprint": "fingerprint",
            "alert_state": "alert_state",
        }
        for source_key, label in key_map.items():
            value = event_data.get(source_key)
            if value not in (None, ""):
                refs[label] = value

        raw_output = str(event_data.get("raw_output") or "")
        if raw_output.strip():
            refs["raw_output摘要"] = TelegramBot._compact_visible_value(raw_output, 700)
            ips = sorted(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw_output)))
            if ips:
                refs["IP"] = ", ".join(ips[:8])
            ports = sorted(set(re.findall(r"(?::|\bport[ =])([0-9]{1,5})\b", raw_output, flags=re.IGNORECASE)))
            if ports:
                refs["端口"] = ", ".join(ports[:8])

        context = event_data.get("context") if isinstance(event_data.get("context"), dict) else {}
        for label, keys in {
            "用户": ("user", "username", "login_user"),
            "进程": ("process", "process_name", "pid"),
            "命令": ("command", "commands"),
        }.items():
            for key in keys:
                value = event_data.get(key) if key in event_data else context.get(key)
                if value not in (None, "", []):
                    refs[label] = TelegramBot._compact_visible_value(value, 500)
                    break
        return refs

    def _record_visible_context(
        self,
        chat_id: int,
        *,
        event_type: str,
        user_action: str,
        assistant_summary: str,
        refs: dict[str, Any] | None = None,
    ) -> None:
        manager = getattr(getattr(self, "agent", None), "session_manager", None)
        if manager is None:
            return
        try:
            session = manager.get_or_create(chat_id)
            added = session.add_visible_context(
                event_type=event_type,
                user_action=user_action,
                assistant_summary=assistant_summary,
                refs=refs,
            )
            if added:
                manager.save_session(session)
        except Exception:
            logger.exception("Failed to record Telegram visible context")

    @staticmethod
    def _sentinel_alert_reply_markup(alert_token: str, *, include_analysis: bool = True) -> InlineKeyboardMarkup:
        row = [
            InlineKeyboardButton(
                "📋 查看详情",
                callback_data=f"sentinel_alert_detail:{alert_token}",
            )
        ]
        if include_analysis:
            row.append(
                InlineKeyboardButton(
                    "🤖 告警分析",
                    callback_data=f"sentinel_alert_analysis:{alert_token}",
                )
            )
        return InlineKeyboardMarkup([row])


    def _check_auth(self, update: Update) -> bool:
        """Check if the message sender is authorized."""
        if update.effective_chat is None:
            return False
        return self.auth.is_authorized(update.effective_chat.id)

    async def _send_long_message(
        self,
        message,
        text: str,
        *,
        markup: MessageMarkup = MessageMarkup.PLAIN,
        reply_markup=None,
    ) -> None:
        """
        Send a message, automatically splitting if it exceeds Telegram's
        4096 character limit.
        """
        rendered = self._formatter.render(text, markup=markup)
        text = rendered.text
        parse_mode = rendered.parse_mode

        async def _send_chunk(chunk_text: str, chunk_reply_markup=None) -> None:
            kwargs: dict[str, Any] = {}
            if parse_mode:
                kwargs["parse_mode"] = parse_mode
            if chunk_reply_markup is not None:
                kwargs["reply_markup"] = chunk_reply_markup
            await message.reply_text(chunk_text, **kwargs)

        max_len = min(self.max_message_length, 4096)

        if len(text) <= max_len:
            await _send_chunk(text, reply_markup)
            return

        # Split into chunks
        chunks = []
        while text:
            if len(text) <= max_len:
                chunks.append(text)
                break

            # Try to split at a newline
            split_pos = text.rfind("\n", 0, max_len)
            if split_pos == -1 or split_pos < max_len // 2:
                split_pos = max_len

            chunks.append(text[:split_pos])
            text = text[split_pos:].lstrip("\n")

        for i, chunk in enumerate(chunks, 1):
            if len(chunks) > 1:
                chunk = f"📄 ({i}/{len(chunks)})\n{chunk}"
            await _send_chunk(chunk, reply_markup if i == len(chunks) else None)

    def _build_environment_summary(self) -> str:
        facts = EnvironmentFactsBuilder().from_profile(
            self._environment_profile_path,
        )
        result = CommandResult(facts=facts)
        outbound = OutboundMessageBuilder().from_command_result(None, result)
        return "\n".join(TelegramOutboundRenderer().render(outbound).text_parts)

    async def send_alert(self, chat_id: int, text: str, alert_event: Any | None = None) -> None:
        """Send an alert message to a specific chat. Used by Sentinel Alerter."""
        if self._app is None:
            logger.warning("Cannot send alert: app not initialized")
            return
        try:
            original_text = text
            alert_data: dict[str, Any] = {}
            interaction_id = ""
            if alert_event is not None:
                interaction_id = self._command_service.remember_sentinel_alert(
                    chat_id=chat_id,
                    alert_text=original_text,
                    alert_event=alert_event,
                )
                raw_alert = (
                    alert_event.to_dict()
                    if hasattr(alert_event, "to_dict")
                    else alert_event
                )
                if isinstance(raw_alert, dict):
                    alert_data = dict(raw_alert)

            outbound = build_sentinel_alert(
                original_text,
                alert_data,
                interaction_id=interaction_id,
            )
            await self._platform_adapter.deliver(
                outbound,
                target=TelegramDeliveryTarget(self._app.bot, chat_id),
            )
            if alert_event is not None:
                self._record_visible_context(
                    chat_id,
                    event_type="sentinel_alert_push",
                    user_action="收到 Sentinel 告警推送",
                    assistant_summary=original_text,
                    refs=self._alert_event_reference_fields(
                        alert_event.to_dict() if hasattr(alert_event, "to_dict") else alert_event
                    ),
                )
        except Exception:
            logger.exception("Failed to send alert to chat %s", chat_id)

    # ----- Error handler -----

    async def _handle_error(
        self,
        update: object,
        context: ContextTypes.DEFAULT_TYPE,
    ) -> None:
        """Global error handler."""
        if isinstance(context.error, Conflict):
            logger.error(
                "Telegram polling conflict: another process is using this Bot Token via getUpdates. "
                "Stop duplicate chatdome-server instances or any other bot process using the same token."
            )
            return
        logger.error("Telegram error: %s", context.error, exc_info=context.error)
