"""
Telegram Bot setup and message routing.

Uses python-telegram-bot v20+ async API.
Routes messages through authentication → AI Agent → reply.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
import uuid
from pathlib import Path
from types import SimpleNamespace
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
from chatdome.outbound.builders import (
    EnvironmentFactsBuilder,
    OutboundMessageBuilder,
    build_approval_details,
    build_approval_request,
    build_notification_message,
    build_sentinel_alert,
)
from chatdome.outbound.models import ActionKind, OutboundAction
from chatdome.outbound.renderers.telegram import TelegramOutboundRenderer, group_controls
from chatdome.platform_adapters import (
    TelegramDeliveryTarget,
    TelegramPlatformAdapter,
)
from chatdome.config import AIConfig, ChatDomeConfig, validate_profile_name
from chatdome.errors import (
    LLMProfileNotFound,
    LLMProfileNotReady,
    user_facing_error_message,
)
from chatdome.telegram.auth import Authenticator
from chatdome.telegram.formatting import MessageMarkup, TelegramMessageFormatter
from chatdome.runtime_paths import environment_profile_path
from chatdome.model_commands import ModelCommandService
from chatdome.slash_commands import (
    CommandContext,
    CommandDef,
    CommandInvocation,
    CommandResult,
    abandon_command_result,
    approval_details_command_result,
    approve_command_result,
    approve_task_command_result,
    audit_command_result,
    clear_session_command_result,
    command_catalog,
    command_echo_command_result,
    command_help_result,
    continue_command_result,
    environment_command_result,
    execute_engram_command,
    format_command_help,
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
from chatdome.llm.codex_oauth_service import CodexOAuthService
from chatdome.llm.profile_admin import (
    CreateOpenAIProfileRequest,
    LLMProfileAdminService,
    ProfileActor,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Help text
# ---------------------------------------------------------------------------

HELP_TEXT = format_command_help("telegram")


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
        self._alert_analysis_cache: dict[str, dict[str, Any]] = {}
        self._alert_analysis_cache_max = 200
        self._approval_detail_tasks: dict[str, asyncio.Task] = {}
        self._round_limit_tasks: dict[int, asyncio.Task] = {}
        self._message_tasks: dict[int, asyncio.Task] = {}
        self._llm_admin_sessions: dict[tuple[int, int], dict[str, Any]] = {}
        self._llm_admin_confirmations: dict[str, dict[str, Any]] = {}
        # Default policy: plain text output; markdown can be enabled per message.
        self._formatter = TelegramMessageFormatter(enable_markdown=True)
        self._platform_adapter = TelegramPlatformAdapter(self._deliver_telegram_rendered)

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

        callbacks = {
            "/help": self._handle_help,
            "/clear": self._handle_clear,
            "/stop": self._handle_stop,
            "/details": self._handle_details,
            "/continue": self._handle_continue,
            "/confirm": self._handle_confirm,
            "/confirm_task": self._handle_confirm_task,
            "/reject": self._handle_reject,
            "/cmd_echo": self._handle_cmd_echo,
            "/env": self._handle_env,
            "/token": self._handle_token,
            "/audit": self._handle_audit,
            "/sentinel_status": self._handle_sentinel_status,
            "/sentinel_trigger": self._handle_sentinel_trigger,
            "/sentinel_history": self._handle_sentinel_history,
            "/sentinel_packs": self._handle_sentinel_packs,
            "/sentinel_mute": self._handle_sentinel_mute,
            "/sentinel_resume": self._handle_sentinel_resume,
            "/engram": self._handle_engram,
            "/model": self._handle_llm,
            "/model_list": self._handle_llm_list,
            "/model_add": self._handle_llm_add,
            "/model_delete": self._handle_llm_delete,
            "/model_cancel": self._handle_llm_cancel,
            "/codex_login": self._handle_codex_login,
        }
        for command in command_catalog("telegram"):
            callback = callbacks[command.name]
            for exposed_name in (command.name, *command.aliases):
                self._app.add_handler(
                    self._command_handler(
                        exposed_name.removeprefix("/"),
                        callback,
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

    def _command_context_for_update(self, update: Update) -> CommandContext:
        """Build shared command context for Telegram messages and callbacks."""

        chat = getattr(update, "effective_chat", None)
        user = getattr(update, "effective_user", None)
        chat_id = int(getattr(chat, "id", 0) or 0)
        actor_id = str(getattr(user, "id", "") or "")

        def record_event(event: dict[str, Any]) -> None:
            manager = getattr(getattr(self, "agent", None), "session_manager", None)
            if manager is not None:
                manager.record_control_event(chat_id, event)

        return CommandContext(
            source="telegram",
            chat_id=chat_id,
            actor_id=actor_id,
            event_recorder=record_event,
        )

    def _command_handler(
        self,
        command_name: str,
        callback: Any,
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
            command_context = self._command_context_for_update(update)

            command_def = command or CommandDef(
                name=f"/{command_name}",
                description="",
                category="telegram",
            )
            invocation = self._platform_adapter.receive_command(
                raw=raw,
                raw_name=f"/{command_name}",
                command=command_def,
                args=args,
                context=command_context,
            )

            async def invoke(_invocation: CommandInvocation) -> Any:
                return await callback(update, context)

            await self._platform_adapter.dispatch(
                invocation,
                handler=invoke,
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
        handler: Any,
    ) -> CommandResult:
        """Run a Telegram button action through the shared command pipeline."""

        command = CommandDef(
            name=command_name,
            description="",
            category="interaction",
        )
        invocation = self._platform_adapter.receive_callback(
            data=data,
            command=command,
            args=args,
            context=command_context,
        )
        return await self._platform_adapter.dispatch(
            invocation,
            handler=handler,
            target=target,
        )

    # ----- Command handlers -----

    async def _handle_help(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> CommandResult:
        """Handle /help and /start commands."""
        del update, context
        return command_help_result("telegram")

    async def _handle_clear(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> CommandResult:
        """Handle /clear command — reset conversation context."""
        del context
        if not self._check_auth(update):
            return CommandResult(outcome="unauthorized")

        command_context = CommandContext(source="telegram", chat_id=update.effective_chat.id)
        return clear_session_command_result(self.agent, command_context)

    def _active_task_for_chat(self, chat_id: int) -> asyncio.Task | None:
        for tasks in (self._message_tasks, self._round_limit_tasks):
            task = tasks.get(chat_id)
            if task is None:
                continue
            if task.done():
                tasks.pop(chat_id, None)
                continue
            return task
        return None

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

    async def _handle_stop(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> CommandResult:
        """Handle /stop command."""
        del context
        if not self._check_auth(update):
            return CommandResult(outcome="unauthorized")

        chat_id = update.effective_chat.id
        return await stop_task_command_result(
            lambda: self._cancel_active_task_for_chat(chat_id)
        )

    async def _handle_cmd_echo(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> CommandResult:
        """Handle /cmd-echo command — toggle command echo mode."""
        del context
        if not self._check_auth(update):
            return CommandResult(outcome="unauthorized")

        command_context = CommandContext(source="telegram", chat_id=update.effective_chat.id)
        return command_echo_command_result(self.agent, command_context)

    async def _handle_token(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> CommandResult:
        """Handle /token command — query local token usage statistics."""
        del context
        if not self._check_auth(update):
            return CommandResult(outcome="unauthorized")

        command_context = CommandContext(source="telegram", chat_id=update.effective_chat.id)
        return token_usage_command_result(command_context)

    async def _handle_env(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> CommandResult:
        """Handle /env command — show runtime environment profile summary."""
        del update, context
        return environment_command_result(
            self._environment_profile_path,
        )

    async def _handle_audit(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> CommandResult:
        """Handle /audit command - show recent command audit events."""
        if not self._check_auth(update):
            return CommandResult(outcome="unauthorized")

        command_context = CommandContext(source="telegram", chat_id=update.effective_chat.id)
        return audit_command_result(
            command_context,
            getattr(context, "args", None) or (),
        )

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

        async def handler(invocation: CommandInvocation) -> CommandResult:
            return await approval_details_command_result(
                self.agent,
                invocation.context,
                invocation.args,
            )

        try:
            result = await self._dispatch_callback_command(
                message,
                data="approval:details",
                command_name="/details",
                args=args,
                command_context=context,
                handler=handler,
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
        if normalized_action == "CONTINUE":
            command_name = "/continue"

            async def handler(invocation: CommandInvocation) -> CommandResult:
                return await continue_command_result(self.agent, invocation.context)

        elif normalized_action == "ABANDON":
            command_name = "/reject"

            async def handler(invocation: CommandInvocation) -> CommandResult:
                return await abandon_command_result(self.agent, invocation.context)

        else:
            raise ValueError("unsupported round-limit action")

        return await self._dispatch_callback_command(
            message,
            data=normalized_action,
            command_name=command_name,
            command_context=command_context
            or CommandContext(source="telegram", chat_id=chat_id),
            handler=handler,
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

    async def _handle_engram(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> CommandResult:
        """Handle /engram command."""
        if not self._check_auth(update):
            return CommandResult(outcome="unauthorized")
        return execute_engram_command(self.agent, context.args or ())

    def _get_llm_manager(self):
        return getattr(self.agent, "llm_manager", None)

    def _model_command_service(self) -> ModelCommandService:
        return ModelCommandService(
            self._get_llm_manager(),
            self.profile_admin,
        )

    def _format_llm_profile_list(self) -> str:
        result = self._model_command_service().list_profiles()
        outbound = OutboundMessageBuilder().from_command_result(None, result)
        return "\n".join(TelegramOutboundRenderer().render(outbound).text_parts)

    @staticmethod
    def _format_llm_status(status: str) -> str:
        labels = {
            "ready": "ready，可切换",
            "missing_key": "missing_key，config.yaml 中未配置 api_key",
            "token_file_present": "token_file_present，已找到 Codex token 文件",
            "not_authenticated": "not_authenticated，需要 /codex_login",
            "invalid_key_ref": "invalid_key_ref，已废弃 env: 写法，请直接写入 config.yaml",
            "unsupported": "unsupported，不支持的 api_mode",
        }
        return labels.get(status, status)

    async def _handle_llm_list(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> CommandResult:
        """Handle /model_list command."""
        del update, context
        return self._model_command_service().list_profiles()

    async def _handle_llm_add(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> CommandResult:
        if not await self._require_llm_admin(update):
            return CommandResult(outcome="unauthorized")
        if self.profile_admin is None:
            return CommandResult(
                outcome="unavailable",
                text="Model management is unavailable.",
                severity="error",
            )
        key = self._llm_admin_key(update)
        current = self._active_llm_admin_session(key)
        if current is not None:
            return CommandResult(
                outcome="interaction_in_progress",
                text="Complete the current model setup or run /model_cancel.",
            )
        nonce = uuid.uuid4().hex[:12]
        self._llm_admin_sessions[key] = {
            "step": "select_type",
            "nonce": nonce,
            "created_at": time.time(),
        }
        return CommandResult(
            outcome="model_add_input_requested",
            title="Add model profile",
            text="Select model type.",
            event_refs={"interaction_id": nonce},
            facts={
                "operation": "model_add",
                "stage": "select_type",
                "options": ("openai", "codex"),
            },
            actions=(
                OutboundAction(
                    ActionKind.SELECT,
                    "OpenAI-compatible",
                    f"llm_admin:type_openai:{nonce}",
                    params={"interaction_id": nonce, "model_type": "openai"},
                ),
                OutboundAction(
                    ActionKind.SELECT,
                    "Codex OAuth",
                    f"llm_admin:type_codex:{nonce}",
                    params={"interaction_id": nonce, "model_type": "codex"},
                ),
                OutboundAction(
                    ActionKind.CANCEL,
                    "取消",
                    f"llm_admin:cancel:{nonce}",
                    params={"interaction_id": nonce},
                ),
            ),
        )

    async def _handle_llm_cancel(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> CommandResult:
        del context
        if not await self._require_llm_admin(update):
            return CommandResult(outcome="unauthorized")
        key = self._llm_admin_key(update)
        removed_any = self._llm_admin_sessions.pop(key, None) is not None
        for nonce, item in list(self._llm_admin_confirmations.items()):
            if item.get("key") == key:
                self._llm_admin_confirmations.pop(nonce, None)
                removed_any = True
        return self._model_command_service().cancel(removed_any)

    async def _handle_llm_delete(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> CommandResult:
        if not await self._require_llm_admin(update):
            return CommandResult(outcome="unauthorized")
        if self.profile_admin is None:
            return CommandResult(
                outcome="unavailable",
                text="Model management is unavailable.",
                severity="error",
            )
        args = getattr(context, "args", []) or []
        if len(args) != 1:
            return CommandResult(
                outcome="invalid_arguments",
                text="Usage: /model_delete <profile>",
                severity="error",
            )
        try:
            summary = await self._model_command_service().inspect_delete(
                str(args[0]).strip()
            )
        except Exception as exc:
            return CommandResult(
                outcome="failed",
                title="Model delete failed",
                text=user_facing_error_message(
                    exc, fallback="Model profile could not be deleted."
                ),
                severity="error",
            )
        nonce = uuid.uuid4().hex[:12]
        key = self._llm_admin_key(update)
        self._llm_admin_confirmations[nonce] = {
            "kind": "delete",
            "profile_name": summary.name,
            "key": key,
            "expires_at": time.time() + 60,
        }
        return CommandResult(
            outcome="model_delete_confirmation_requested",
            title="Delete model profile",
            text=f"Delete model profile '{summary.name}'?",
            event_refs={"interaction_id": nonce, "profile": summary.name},
            facts={"operation": "model_delete", "profile": summary.name},
            actions=(
                OutboundAction(
                    ActionKind.CONFIRM,
                    "确认删除",
                    f"llm_admin:delete_yes:{nonce}",
                    destructive=True,
                    params={"interaction_id": nonce, "profile": summary.name},
                ),
                OutboundAction(
                    ActionKind.CANCEL,
                    "取消",
                    f"llm_admin:delete_no:{nonce}",
                    params={"interaction_id": nonce, "profile": summary.name},
                ),
            ),
        )

    async def _handle_llm_admin_message(
        self,
        update: Update,
        context: ContextTypes.DEFAULT_TYPE,
    ) -> bool:
        del context
        key = self._llm_admin_key(update)
        session = self._llm_admin_sessions.get(key)
        if session is None:
            return False
        if self._active_llm_admin_session(key) is None:
            await update.message.reply_text("model 配置已超时，请重新运行 /model_add。")
            return True
        if not await self._require_llm_admin(update):
            return True

        text = str(update.message.text or "").strip()
        step = session.get("step")
        if step == "name":
            try:
                name = validate_profile_name(text)
                summary = await self.profile_admin.get_profile_summary(name)
            except Exception as exc:
                await update.message.reply_text(
                    self._format_error_text(
                        exc,
                        prefix="Profile 名称无效",
                        fallback="请输入有效的 profile 名称。",
                    )
                )
                return True
            session["name"] = name
            session["existing"] = summary
            if summary is not None:
                session["step"] = "confirm_overwrite"
                session["expected_fingerprint"] = summary.fingerprint
                keyboard = [[
                    InlineKeyboardButton(
                        "继续覆盖",
                        callback_data=f"llm_admin:overwrite_yes:{session['nonce']}",
                    ),
                    InlineKeyboardButton(
                        "取消",
                        callback_data=f"llm_admin:overwrite_no:{session['nonce']}",
                    ),
                ]]
                await self._reply_text(
                    update.message,
                    (
                        f"已存在 {summary.name}: {summary.provider}/{summary.api_mode}, "
                        f"model={summary.model}, address={summary.base_url}"
                    ),
                    reply_markup=InlineKeyboardMarkup(keyboard),
                )
                return True
            await self._advance_llm_admin_after_name(update.message, session)
            return True

        if step == "model":
            existing = session.get("existing")
            session["model"] = (
                existing.model if text == "-" and existing is not None else text
            )
            session["step"] = "base_url"
            default = existing.base_url if existing is not None else "https://api.openai.com/v1"
            await update.message.reply_text(
                f"输入 Base URL。发送 - 使用当前值: {default}"
            )
            return True

        if step == "base_url":
            existing = session.get("existing")
            session["base_url"] = (
                existing.base_url if text == "-" and existing is not None else text
            )
            session["step"] = "api_key"
            if existing is not None and existing.api_mode == "openai_api":
                await update.message.reply_text("输入 API Key，或发送 - 保留现有 Key。")
            else:
                await update.message.reply_text("输入 API Key。敏感环境请使用本地菜单。")
            return True

        if step == "api_key":
            existing = session.get("existing")
            if text == "-" and existing is not None and existing.api_mode == "openai_api":
                api_key = ""
            else:
                try:
                    await update.message.delete()
                except Exception:
                    self._llm_admin_sessions.pop(key, None)
                    await update.message.reply_text(
                        "无法删除 API Key 消息。请删除该消息并使用本地菜单。"
                    )
                    return True
                api_key = text
            session["api_key"] = api_key
            session["step"] = "confirm_save"
            action = "更新" if existing is not None else "新增"
            keyboard = [[
                InlineKeyboardButton(
                    f"确认{action}",
                    callback_data=f"llm_admin:save_yes:{session['nonce']}",
                ),
                InlineKeyboardButton(
                    "取消",
                    callback_data=f"llm_admin:save_no:{session['nonce']}",
                ),
            ]]
            await self._reply_text(
                update.message,
                (
                    f"{action} {session['name']}？\n"
                    f"模型: {session['model']}\n"
                    f"地址: {session['base_url']}\n"
                    f"API Key: {'unchanged' if not api_key else 'configured'}"
                ),
                reply_markup=InlineKeyboardMarkup(keyboard),
            )
            return True

        await update.message.reply_text("使用按钮继续，或发送 /model_cancel。")
        return True

    async def _advance_llm_admin_after_name(self, message, session: dict[str, Any]) -> None:
        if session.get("type") == "openai":
            session["step"] = "model"
            existing = session.get("existing")
            default = existing.model if existing is not None else "gpt-4o"
            await message.reply_text(f"输入模型名称。发送 - 使用当前值: {default}")
            return
        session["step"] = "codex_confirm"
        keyboard = [[
            InlineKeyboardButton(
                "开始 Codex 授权",
                callback_data=f"llm_admin:codex_start:{session['nonce']}",
            ),
            InlineKeyboardButton(
                "取消",
                callback_data=f"llm_admin:cancel:{session['nonce']}",
            ),
        ]]
        await self._reply_text(
            message,
            f"为 profile '{session['name']}' 启动 Codex OAuth？",
            reply_markup=InlineKeyboardMarkup(keyboard),
        )

    async def _handle_llm(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> CommandResult:
        """List profiles or persistently switch the active model."""
        args = getattr(context, "args", []) or []
        service = self._model_command_service()
        if not args:
            return service.list_profiles()
        if not await self._require_llm_admin(update):
            return CommandResult(outcome="unauthorized")

        try:
            return await service.switch(
                str(args[0]).strip(),
                self._profile_actor(update),
            )
        except Exception as exc:
            logger.warning("Model profile switch failed: %s", exc)
            return CommandResult(
                outcome="failed",
                title="Model switch failed",
                text=user_facing_error_message(
                    exc,
                    fallback="model 切换失败，请检查配置后重试。",
                ),
                severity="error",
            )

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

    async def _handle_codex_login(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> CommandResult:
        """Start the shared Codex OAuth device flow."""
        if not await self._require_llm_admin(update):
            return CommandResult(outcome="unauthorized")

        requested_profile = (getattr(context, "args", []) or [""])[0]
        manager = self._get_llm_manager()
        active_profile = (
            manager.get_active_profile_name() if manager is not None else ""
        )
        try:
            force_codex = bool(getattr(context, "chatdome_force_codex", False))
            forced_profile = (
                self._default_codex_profile(requested_profile)
                if force_codex
                else None
            )
            session = await self._codex_oauth.begin(
                self.config,
                self._profile_actor(update),
                requested_profile=requested_profile,
                active_profile=active_profile,
                forced_profile=forced_profile,
                overwrite_existing=(
                    bool(getattr(context, "chatdome_codex_overwrite", False))
                    if force_codex
                    else None
                ),
                expected_profile_fingerprint=getattr(
                    context,
                    "chatdome_expected_fingerprint",
                    None,
                ),
            )
        except Exception as exc:
            return CommandResult(
                outcome="failed",
                title="Codex OAuth failed",
                text=user_facing_error_message(
                    exc,
                    fallback="无法启动 Codex 认证，请检查 model profile 配置。",
                ),
                severity="error",
            )

        async def complete_authorization() -> None:
            try:
                await self._codex_oauth.complete(session)
                result = CommandResult(
                    outcome="codex_authenticated",
                    event_summary=(
                        f"用户完成了 Codex profile {session.profile_name} 认证。"
                    ),
                    title="Codex OAuth",
                    text=f"Codex profile 已可使用: {session.profile_name}",
                )
            except asyncio.CancelledError:
                return
            except Exception as exc:
                logger.error(
                    "Codex device login polling background task failed: %s",
                    exc,
                )
                result = CommandResult(
                    outcome="failed",
                    title="Codex OAuth failed",
                    text=user_facing_error_message(
                        exc,
                        fallback="Codex 认证失败，请重新运行 /codex_login。",
                    ),
                    severity="error",
                )
            await self._send_command_result(update.message, result)

        if self._app is not None:
            self._app.create_task(complete_authorization())
        else:
            asyncio.create_task(complete_authorization())

        return CommandResult(
            outcome="codex_authorization_pending",
            event_summary=(
                f"用户为 Codex profile {session.profile_name} 启动了认证。"
            ),
            title="Codex OAuth",
            facts=session.authorization,
        )

    async def _handle_llm_admin_callback(
        self,
        update: Update,
        context: ContextTypes.DEFAULT_TYPE,
        callback_data: str,
    ) -> None:
        query = update.callback_query
        if query is None or query.message is None:
            return
        if not await self._require_llm_admin(update):
            return
        parts = callback_data.split(":", 2)
        if len(parts) != 3:
            await query.message.reply_text("Model 操作已失效，请重新开始。")
            return
        _, action, nonce = parts
        key = self._llm_admin_key(update)

        if action in {"delete_yes", "delete_no"}:
            item = self._llm_admin_confirmations.pop(nonce, None)
            if (
                item is None
                or item.get("key") != key
                or float(item.get("expires_at", 0)) < time.time()
            ):
                await query.message.reply_text("删除确认已失效，请重新运行 /model_delete。")
                return
            await query.edit_message_reply_markup(reply_markup=None)
            if action == "delete_no":
                await query.message.reply_text("已取消删除。")
                return
            try:
                result = await self._model_command_service().delete(
                    item["profile_name"],
                    self._profile_actor(update),
                )
            except Exception as exc:
                await query.message.reply_text(
                    self._format_error_text(
                        exc,
                        prefix="删除 model 失败",
                        fallback="删除 model 失败，请重试。",
                    )
                )
                return
            await self._send_command_result(query.message, result)
            return

        session = self._active_llm_admin_session(key)
        if session is None or session.get("nonce") != nonce:
            await query.message.reply_text("model 配置已失效，请重新运行 /model_add。")
            return

        if action == "type_openai":
            session["type"] = "openai"
            session["step"] = "name"
            await query.edit_message_reply_markup(reply_markup=None)
            await query.message.reply_text("输入 profile 名称。")
            return
        if action == "type_codex":
            session["type"] = "codex"
            session["step"] = "name"
            await query.edit_message_reply_markup(reply_markup=None)
            await query.message.reply_text("输入 profile 名称。")
            return
        if action in {"cancel", "overwrite_no", "save_no"}:
            self._llm_admin_sessions.pop(key, None)
            await query.edit_message_reply_markup(reply_markup=None)
            await query.message.reply_text("已取消 model 配置。")
            return
        if action == "overwrite_yes":
            session["overwrite"] = True
            await query.edit_message_reply_markup(reply_markup=None)
            await self._advance_llm_admin_after_name(query.message, session)
            return
        if action == "save_yes":
            if session.get("step") != "confirm_save":
                await query.message.reply_text("model 配置状态无效，请重新开始。")
                return
            saved = dict(session)
            self._llm_admin_sessions.pop(key, None)
            await query.edit_message_reply_markup(reply_markup=None)
            try:
                result = await self._model_command_service().create_openai(
                    CreateOpenAIProfileRequest(
                        name=saved["name"],
                        model=saved["model"],
                        base_url=saved["base_url"],
                        api_key=saved.get("api_key", ""),
                        overwrite_existing=bool(saved.get("existing")),
                        expected_profile_fingerprint=saved.get("expected_fingerprint"),
                    ),
                    self._profile_actor(update),
                )
            except Exception as exc:
                await query.message.reply_text(
                    self._format_error_text(
                        exc,
                        prefix="保存 model 失败",
                        fallback="保存 model 失败，请重新开始。",
                    )
                )
                return
            await self._send_command_result(query.message, result)
            return
        if action == "codex_start":
            saved = dict(session)
            self._llm_admin_sessions.pop(key, None)
            await query.edit_message_reply_markup(reply_markup=None)
            proxy_update = SimpleNamespace(
                effective_chat=update.effective_chat,
                effective_user=update.effective_user,
                message=query.message,
            )
            proxy_context = SimpleNamespace(
                args=[saved["name"]],
                bot=context.bot,
                chatdome_force_codex=True,
                chatdome_codex_overwrite=saved.get("existing") is not None,
                chatdome_expected_fingerprint=saved.get("expected_fingerprint"),
            )
            result = await self._handle_codex_login(proxy_update, proxy_context)
            await self._send_command_result(query.message, result)
            return

        await query.message.reply_text("Model 操作已失效，请重新开始。")

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

            if callback_data.startswith("sentinel_alert_analysis:"):
                alert_token = callback_data.split(":", 1)[1].strip()
                await self._handle_sentinel_alert_analysis(query, chat_id, alert_token)
                return

            if callback_data.startswith("sentinel_alert_detail:"):
                alert_token = callback_data.split(":", 1)[1].strip()
                await self._handle_sentinel_alert_detail(query, chat_id, alert_token)
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

            await self._clear_callback_message_markup(query, "approval decision callback message")

            if action == "APPROVE_TASK":
                business_handler = approve_task_command_result
                command_name = "/confirm"
            elif action == "APPROVE":
                business_handler = approve_command_result
                command_name = "/confirm"
            else:
                business_handler = reject_command_result
                command_name = "/reject"

            async def handler(invocation: CommandInvocation) -> CommandResult:
                return await business_handler(
                    self.agent,
                    invocation.context,
                    invocation.args,
                )

            thinking_msg = await query.message.reply_text("⏳")
            try:
                await asyncio.wait_for(
                    self._dispatch_callback_command(
                        query.message,
                        data=callback_data,
                        command_name=command_name,
                        args=(approval_id,) if approval_id else (),
                        command_context=self._command_context_for_update(update),
                        handler=handler,
                    ),
                    timeout=90,
                )
            finally:
                try:
                    await thinking_msg.delete()
                except Exception:
                    pass
        except asyncio.TimeoutError:
            await self._send_long_message(
                query.message,
                "操作处理超时，当前任务状态已保留。请稍后重试，或发送 /confirm 继续处理待确认命令。",
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

    async def _handle_details(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> CommandResult:
        """Handle /details for the current pending approval."""
        if not self._check_auth(update):
            return CommandResult(outcome="unauthorized")

        command_context = CommandContext(source="telegram", chat_id=update.effective_chat.id)
        return await approval_details_command_result(
            self.agent,
            command_context,
            getattr(context, "args", None) or (),
        )

    async def _handle_continue(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> CommandResult:
        """Handle /continue for a round-limit pause."""
        if not self._check_auth(update):
            return CommandResult(outcome="unauthorized")
        command_context = CommandContext(source="telegram", chat_id=update.effective_chat.id)
        return await continue_command_result(self.agent, command_context)

    async def _handle_confirm(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> CommandResult:
        """Handle /confirm command for high-risk executions."""
        if not self._check_auth(update):
            return CommandResult(outcome="unauthorized")

        command_context = CommandContext(source="telegram", chat_id=update.effective_chat.id)
        return await approve_command_result(
            self.agent,
            command_context,
            getattr(context, "args", None) or (),
        )

    async def _handle_confirm_task(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> CommandResult:
        """Handle /confirm_task for the current task."""
        if not self._check_auth(update):
            return CommandResult(outcome="unauthorized")

        command_context = CommandContext(
            source="telegram",
            chat_id=update.effective_chat.id,
        )
        return await approve_task_command_result(
            self.agent,
            command_context,
            getattr(context, "args", None) or (),
        )

    async def _handle_reject(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> CommandResult:
        """Handle /reject command for pending high-risk execution."""
        if not self._check_auth(update):
            return CommandResult(outcome="unauthorized")

        command_context = CommandContext(source="telegram", chat_id=update.effective_chat.id)
        return await reject_command_result(
            self.agent,
            command_context,
            getattr(context, "args", None) or (),
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

    def _cache_alert_analysis_context(
        self,
        *,
        chat_id: int,
        alert_text: str,
        alert_event: Any | None,
    ) -> str:
        token = uuid.uuid4().hex[:16]
        event_payload: Any = None
        if alert_event is not None:
            if hasattr(alert_event, "to_dict"):
                try:
                    event_payload = alert_event.to_dict()
                except Exception:
                    logger.exception("Failed to serialize alert event for analysis")
                    event_payload = str(alert_event)
            elif isinstance(alert_event, dict):
                event_payload = alert_event
            else:
                event_payload = str(alert_event)

        self._alert_analysis_cache[token] = {
            "chat_id": chat_id,
            "alert_text": alert_text,
            "event": event_payload,
            "created_at": time.time(),
        }

        while len(self._alert_analysis_cache) > self._alert_analysis_cache_max:
            oldest_token = min(
                self._alert_analysis_cache,
                key=lambda key: float(self._alert_analysis_cache[key].get("created_at", 0.0)),
            )
            self._alert_analysis_cache.pop(oldest_token, None)

        return token

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

    def _read_environment_profile_for_llm(self, max_chars: int = 6000) -> str:
        path = self._environment_profile_path
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

    async def _handle_sentinel_alert_analysis(self, query, chat_id: int, alert_token: str) -> None:
        cached = self._alert_analysis_cache.get(alert_token)
        if not cached or cached.get("chat_id") != chat_id:
            await self._clear_callback_message_markup(query, "expired sentinel alert analysis")
            await self._send_long_message(
                query.message,
                "这条告警上下文已过期，请查看 /sentinel_history 或等待下一次告警。",
            )
            return

        await self._set_callback_message_markup(
            query,
            self._sentinel_alert_reply_markup(alert_token, include_analysis=False),
            "sentinel alert analysis",
        )
        thinking_msg = await query.message.reply_text("⏳")
        try:
            env_text = self._read_environment_profile_for_llm()
            alert_text = str(cached.get("alert_text") or "")
            event_payload = cached.get("event")
            if isinstance(event_payload, str):
                event_text = event_payload
            else:
                event_text = json.dumps(event_payload or {}, ensure_ascii=False, indent=2)

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
                        "- 给出下一步核实/处置建议，优先使用只读排查命令；如果需要变更操作，请明确提示需要人工确认。\n"
                        "- 不要复述卡片里的全部原始内容。\n\n"
                        f"环境信息:\n{env_text}\n\n"
                        f"告警卡片:\n{alert_text}\n\n"
                        f"结构化告警:\n{event_text}"
                    ),
                },
            ]
            snapshot = await self.agent.get_active_llm_snapshot()
            response = await asyncio.wait_for(
                snapshot.client.chat_completion(messages=messages, tools=None),
                timeout=90,
            )

            try:
                from chatdome.agent.tracker import TokenTracker
                TokenTracker.record_usage(
                    chat_id=chat_id,
                    model=getattr(snapshot.client, "model", "unknown"),
                    action="sentinel_alert_analysis",
                    prompt_tokens=response.prompt_tokens,
                    completion_tokens=response.completion_tokens,
                    total_tokens=response.total_tokens,
                )
            except Exception:
                logger.exception("Failed to record Sentinel alert analysis token usage")

            content = (response.content or "").strip() or "LLM 未返回有效分析。"
        except TimeoutError:
            logger.exception("Sentinel alert analysis timed out")
            content = "告警分析超时，请稍后重试。"
        except Exception as exc:
            logger.exception("Sentinel alert analysis failed")
            content = self._format_error_text(
                exc,
                prefix="告警分析失败",
                fallback="告警分析失败，请稍后重试。",
            )
        finally:
            try:
                await thinking_msg.delete()
            except Exception:
                pass

        await self._send_long_message(query.message, content)
        self._record_visible_context(
            chat_id,
            event_type="sentinel_alert_analysis",
            user_action="点击告警分析",
            assistant_summary=content,
            refs=self._alert_event_reference_fields(cached.get("event")),
        )

    async def _handle_sentinel_alert_detail(self, query, chat_id: int, alert_token: str) -> None:
        cached = self._alert_analysis_cache.get(alert_token)
        if not cached or cached.get("chat_id") != chat_id:
            await self._clear_callback_message_markup(query, "expired sentinel alert detail")
            await self._send_long_message(
                query.message,
                "告警详情已过期。使用 /sentinel_history 查看告警记录。",
            )
            return

        from chatdome.sentinel.alerter import format_alert_detail

        event_data = cached.get("event")
        detail_text = (
            format_alert_detail(event_data)
            if isinstance(event_data, dict)
            else "暂无详细状态信息。"
        )
        await self._send_long_message(query.message, detail_text)
        self._record_visible_context(
            chat_id,
            event_type="sentinel_alert_detail",
            user_action="查看告警详情",
            assistant_summary=detail_text,
            refs=self._alert_event_reference_fields(event_data),
        )

    @staticmethod
    def _llm_admin_key(update: Update) -> tuple[int, int]:
        chat_id = update.effective_chat.id if update.effective_chat else 0
        user_id = update.effective_user.id if update.effective_user else 0
        return int(chat_id), int(user_id)

    def _active_llm_admin_session(
        self,
        key: tuple[int, int],
    ) -> dict[str, Any] | None:
        session = self._llm_admin_sessions.get(key)
        if session is None:
            return None
        if time.time() - float(session.get("created_at", 0)) > 300:
            self._llm_admin_sessions.pop(key, None)
            return None
        return session

    @staticmethod
    def _profile_actor(update: Update) -> ProfileActor:
        return ProfileActor(
            source="telegram",
            chat_id=update.effective_chat.id if update.effective_chat else 0,
            user_id=update.effective_user.id if update.effective_user else 0,
        )

    async def _require_llm_admin(self, update: Update) -> bool:
        chat = update.effective_chat
        if chat is None or not self._check_auth(update):
            return False
        admin_ids = set(
            self.config.telegram.admin_chat_ids
            or self.config.telegram.allowed_chat_ids
            or []
        )
        if getattr(chat, "type", "") == "private" and chat.id in admin_ids:
            return True
        message = update.effective_message
        if message is not None:
            await message.reply_text(
                "当前会话没有 model 管理权限。请配置 telegram.admin_chat_ids 或 telegram.allowed_chat_ids。"
            )
        return False

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

    # ----- Sentinel command handlers -----

    async def _handle_sentinel_mute(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> CommandResult:
        if not self._check_auth(update):
            return CommandResult(outcome="unauthorized")
        return sentinel_mute(
            self._sentinel,
            context.args or (),
            chat_id=update.effective_chat.id,
            source="telegram",
        )

    async def _handle_sentinel_resume(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> CommandResult:
        del context
        if not self._check_auth(update):
            return CommandResult(outcome="unauthorized")
        return sentinel_resume(
            self._sentinel,
            chat_id=update.effective_chat.id,
        )

    async def _handle_sentinel_status(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> CommandResult:
        del context
        if not self._check_auth(update):
            return CommandResult(outcome="unauthorized")
        return sentinel_status(self._sentinel, self._pack_loader)

    async def _handle_sentinel_trigger(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> CommandResult:
        del context
        if not self._check_auth(update):
            return CommandResult(outcome="unauthorized")
        status_msg = await update.message.reply_text("⏳")
        try:
            result = await sentinel_trigger(self._sentinel)
        finally:
            try:
                await status_msg.delete()
            except Exception:
                pass
        return result

    async def _handle_sentinel_history(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> CommandResult:
        del context
        if not self._check_auth(update):
            return CommandResult(outcome="unauthorized")
        result = sentinel_history(self._sentinel)
        return result

    async def _handle_sentinel_packs(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> CommandResult:
        del context
        if not self._check_auth(update):
            return CommandResult(outcome="unauthorized")
        result = sentinel_packs(self._pack_loader)
        return result

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
                interaction_id = self._cache_alert_analysis_context(
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
