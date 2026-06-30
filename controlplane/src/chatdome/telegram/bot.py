"""
Telegram Bot setup and message routing.

Uses python-telegram-bot v20+ async API.
Routes messages through authentication → AI Agent → reply.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from dataclasses import replace
from datetime import datetime
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
from chatdome.config import AIConfig, ChatDomeConfig, validate_profile_name
from chatdome.errors import (
    LLMProfileNotFound,
    LLMProfileNotReady,
    user_facing_error_message,
)
from chatdome.sentinel.alert_controls import (
    format_alert_push_status,
    parse_alert_mute_until,
)
from chatdome.telegram.auth import Authenticator
from chatdome.telegram.formatting import MessageMarkup, TelegramMessageFormatter
from chatdome.runtime_paths import environment_profile_path
from chatdome.llm.profile_admin import (
    CreateCodexProfileRequest,
    CreateOpenAIProfileRequest,
    LLMProfileAdminService,
    ProfileActor,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Help text
# ---------------------------------------------------------------------------

HELP_TEXT = """\
🛡️ *ChatDome — AI 主机安全助手*

直接用自然语言和我对话，我会自动执行安全审计命令并分析结果。

*示例问题：*
• 有没有人在爆破我的SSH？
• 检查一下磁盘使用情况
• 最近有没有异常的登录记录？
• 系统负载怎么样？有没有可疑进程？
• 检查一下防火墙规则
• 我的服务器有哪些端口在监听？

*命令：*
/help \\- 显示帮助
/clear \\- 清除对话上下文
/env \\- 查看当前运行环境摘要（来自 environment\\_profile\\.md）
/token \\- 查看当前账号的 Token 资源流水与花费汇总
/cmd\\_echo \\- 开关命令回显模式（显示底层执行的具体步骤）
/audit \\[N\\] \\- 查看当前会话最近 N 条命令审计事件
/engram \\- 查看长期记忆印迹
/engram delete <id> \\- 删除指定长期记忆
/sentinel\\_status \\- 哨兵模式告警状态总览
/sentinel\\_trigger \\- 手动触发全量巡检
/sentinel\\_history \\- 查看告警历史
/sentinel\\_packs \\- 查看已加载的命令包
/sentinel\\_mute \\[时长\\] \\- 暂停 Sentinel 告警推送
/sentinel\\_resume \\- 恢复 Sentinel 告警推送
/llm \\[profile\\] \\- 查看或切换当前 LLM profile
/llm\\_list \\- 查看所有 LLM profiles
/llm\\_add \\- 新增 OpenAI-compatible 或 Codex LLM
/llm\\_delete <profile> \\- 删除 LLM profile
/llm\\_cancel \\- 取消正在进行的 LLM 新增流程
/codex\\_login \\- 触发 OpenAI Codex OAuth 设备码认证流程

_直接发送你的问题即可，无需命令前缀。_
"""


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
        self._llm_admin_sessions: dict[tuple[int, int], dict[str, Any]] = {}
        self._llm_admin_confirmations: dict[str, dict[str, Any]] = {}
        # Default policy: plain text output; markdown can be enabled per message.
        self._formatter = TelegramMessageFormatter(enable_markdown=True)

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
                await self._send_bot_text(
                    bot=app.bot,
                    chat_id=chat_id,
                    text="🚀 *ChatDome 已上线*\n安全探针与大模型推理引擎已就绪，随时听候指令！", 
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
                await self._send_bot_text(
                    bot=app.bot,
                    chat_id=chat_id,
                    text="💤 *ChatDome 已下线*\n主控进程已退出，暂停安全接管服务。", 
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

        # Register handlers
        self._app.add_handler(self._command_handler("help", self._handle_help))
        self._app.add_handler(self._command_handler("start", self._handle_help))
        self._app.add_handler(self._command_handler("clear", self._handle_clear))
        self._app.add_handler(self._command_handler("confirm", self._handle_confirm))
        self._app.add_handler(self._command_handler("reject", self._handle_reject))
        self._app.add_handler(self._command_handler("cmd_echo", self._handle_cmd_echo))
        self._app.add_handler(self._command_handler("env", self._handle_env))
        self._app.add_handler(self._command_handler("token", self._handle_token))
        self._app.add_handler(self._command_handler("audit", self._handle_audit))
        self._app.add_handler(self._command_handler("sentinel_status", self._handle_sentinel_status))
        self._app.add_handler(self._command_handler("sentinel_trigger", self._handle_sentinel_trigger))
        self._app.add_handler(self._command_handler("sentinel_history", self._handle_sentinel_history))
        self._app.add_handler(self._command_handler("sentinel_packs", self._handle_sentinel_packs))
        self._app.add_handler(self._command_handler("sentinel_mute", self._handle_sentinel_mute))
        self._app.add_handler(self._command_handler("sentinel_resume", self._handle_sentinel_resume))
        self._app.add_handler(self._command_handler("engram", self._handle_engram))
        self._app.add_handler(self._command_handler("llm", self._handle_llm))
        self._app.add_handler(self._command_handler("llm_list", self._handle_llm_list))
        self._app.add_handler(self._command_handler("llm_add", self._handle_llm_add))
        self._app.add_handler(self._command_handler("llm_delete", self._handle_llm_delete))
        self._app.add_handler(self._command_handler("llm_cancel", self._handle_llm_cancel))
        self._app.add_handler(self._command_handler("codex_login", self._handle_codex_login))
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
        chat = update.effective_chat
        user = update.effective_user
        message = update.effective_message
        command_text = getattr(message, "text", None) or f"/{command_name}"
        chat_id = getattr(chat, "id", "-") if chat is not None else "-"
        user_id = getattr(user, "id", "-") if user is not None else "-"
        logger.info(
            '[Telegram command received] chat_id=%s user_id=%s command="%s"',
            chat_id,
            user_id,
            self._log_value(command_text),
        )

    def _command_handler(self, command_name: str, callback: Any) -> CommandHandler:
        async def wrapped(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
            self._log_telegram_command(update, command_name)
            await callback(update, context)

        return CommandHandler(command_name, wrapped)

    # ----- Command handlers -----

    async def _handle_help(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        """Handle /help and /start commands."""
        if not self._check_auth(update):
            return

        await self._send_long_message(update.message, HELP_TEXT)

    async def _handle_clear(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        """Handle /clear command — reset conversation context."""
        if not self._check_auth(update):
            return

        chat_id = update.effective_chat.id
        cleared = self.agent.clear_session(chat_id)

        if cleared:
            await update.message.reply_text("✅ 对话上下文已清除，可以开始新的对话。")
        else:
            await update.message.reply_text("ℹ️ 当前没有活跃的对话。")

    async def _handle_cmd_echo(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        """Handle /cmd-echo command — toggle command echo mode."""
        if not self._check_auth(update):
            return

        chat_id = update.effective_chat.id
        session = self.agent.session_manager.get_or_create(chat_id)
        session.command_echo = not session.command_echo
        
        if session.command_echo:
            msg = "🔍 命令回显 已开启 🟢"
        else:
            msg = "🔍 命令回显 已关闭 🔴"
            
        await self._send_long_message(update.message, msg)

    async def _handle_token(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        """Handle /token command — query local token usage statistics."""
        if not self._check_auth(update):
            return

        chat_id = update.effective_chat.id
        from chatdome.agent.tracker import TokenTracker
        stats = TokenTracker.get_user_stats(chat_id)
        
        msg = (
            "📊 *Token 资源消耗统计*\n\n"
            f"👤 用户 ID: `{chat_id}`\n"
            f"⬆️ 上行总花费 (Prompt): {stats['prompt_tokens']:,.0f} Tokens\n"
            f"⬇️ 下行总花费 (Completion): {stats['completion_tokens']:,.0f} Tokens\n"
            f"🔢 累计调用账单: {stats['total_tokens']:,.0f} Tokens"
        )
        await self._send_long_message(update.message, msg)

    async def _handle_env(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        """Handle /env command — show runtime environment profile summary."""
        if not self._check_auth(update):
            return

        summary = self._build_environment_summary()
        await self._send_long_message(update.message, summary)

    async def _handle_audit(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        """Handle /audit command - show recent command audit events for current chat."""
        if not self._check_auth(update):
            return

        chat_id = update.effective_chat.id
        limit = 10
        if context.args:
            try:
                parsed = int(context.args[0])
                if parsed > 0:
                    limit = min(parsed, 30)
            except (TypeError, ValueError):
                pass

        from chatdome.agent.audit import CommandAuditTracker

        events = CommandAuditTracker.get_recent_events(chat_id=chat_id, limit=limit)
        if not events:
            await update.message.reply_text("No command audit events yet.")
            return

        lines = [f"Command audit events (latest {len(events)}):"]
        for event in events:
            ts = str(event.get("timestamp_iso", "unknown"))
            event_type = str(event.get("event_type", "unknown"))
            risk = str(event.get("risk_level", "-"))
            command = str(event.get("command", "")).replace("\n", " ").strip()
            if len(command) > 100:
                command = command[:100] + "..."
            line = f"- {ts} | {event_type} | risk={risk}"
            if command:
                line += f"\n  {command}"
            lines.append(line)

        await self._send_long_message(update.message, "\n".join(lines))

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
        user_message = update.message.text

        logger.info(
            "Message from chat_id=%d: %s",
            chat_id, user_message[:100],
        )

        # Send "thinking" indicator
        thinking_msg = await update.message.reply_text("🤔 正在思考...")

        try:
            # Process through agent
            response = await self.agent.handle_message(chat_id, user_message)

            # Delete the thinking message
            try:
                await thinking_msg.delete()
            except Exception:
                pass  # Not critical if we can't delete it

            await self._send_agent_result(update.message, response)

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
                await update.message.reply_text(error_text)

    # ----- Interactive Approval -----

    async def _send_approval_request(self, message, data: dict) -> None:
        approval_id = str((data or {}).get("approval_id") or "").strip()
        risk_level = str((data or {}).get("risk_level") or "unknown").strip()
        command_hash = str((data or {}).get("command_hash") or "").strip()
        hash_line = f"\n命令指纹: {command_hash[:12]}" if command_hash else ""
        approval_line = f"审批编号: {approval_id}\n" if approval_id else ""
        analysis = (data or {}).get("analysis")
        analysis = analysis if isinstance(analysis, dict) else {}
        purpose = self._compact_approval_text((data or {}).get("reason"), "未提供")
        impact = self._compact_approval_text(
            (data or {}).get("impact_analysis") or analysis.get("impact_analysis"),
            "点击“详细命令”查看完整影响分析。",
        )
        text = (
            "⚠️ 待审批\n"
            f"{approval_line}"
            f"风险等级: {risk_level}{hash_line}\n"
            f"操作目的: {purpose}\n"
            f"影响说明: {impact}"
        )
        if approval_id:
            approve_data = f"approval:approve:{approval_id}"
            approve_task_data = f"approval:approve_task:{approval_id}"
            reject_data = f"approval:reject:{approval_id}"
            detail_data = f"approval:details:{approval_id}"
        else:
            approve_data = "approve_cmd"
            approve_task_data = "approve_task_cmd"
            reject_data = "reject_cmd"
            detail_data = "show_cmd_details"
        keyboard = [
            [
                InlineKeyboardButton("✅ 允许", callback_data=approve_data),
                InlineKeyboardButton("✅ 本次任务允许", callback_data=approve_task_data),
            ],
            [
                InlineKeyboardButton("❌ 拒绝", callback_data=reject_data),
                InlineKeyboardButton("🔎 详细命令", callback_data=detail_data),
            ],
        ]
        await self._reply_text(
            message,
            text,
            markup=MessageMarkup.PLAIN,
            reply_markup=InlineKeyboardMarkup(keyboard),
        )
        return

    @staticmethod
    def _compact_approval_text(value: Any, fallback: str, max_chars: int = 120) -> str:
        """Keep approval-card context short and single-line for mobile display."""
        text = " ".join(str(value or "").split()).strip()
        if not text:
            text = fallback
        if len(text) <= max_chars:
            return text
        return text[: max_chars - 1].rstrip() + "…"

    async def _send_approval_actions(self, message, data: dict) -> None:
        """Send compact action buttons after the detailed analysis message."""
        approval_id = str((data or {}).get("approval_id") or "").strip()
        if approval_id:
            approve_data = f"approval:approve:{approval_id}"
            approve_task_data = f"approval:approve_task:{approval_id}"
            reject_data = f"approval:reject:{approval_id}"
        else:
            approve_data = "approve_cmd"
            approve_task_data = "approve_task_cmd"
            reject_data = "reject_cmd"

        keyboard = [
            [
                InlineKeyboardButton("✅ 允许", callback_data=approve_data),
                InlineKeyboardButton("✅ 本次任务允许", callback_data=approve_task_data),
            ],
            [InlineKeyboardButton("❌ 拒绝", callback_data=reject_data)],
        ]
        await self._reply_text(
            message,
            "分析完成。",
            markup=MessageMarkup.PLAIN,
            reply_markup=InlineKeyboardMarkup(keyboard),
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
    ) -> None:
        """Start an approval detail review without blocking later chat updates."""
        task_key = self._approval_detail_task_key(chat_id, approval_id)
        existing_task = self._approval_detail_tasks.get(task_key)
        if existing_task and not existing_task.done():
            await self._send_long_message(
                message,
                "详细命令分析仍在进行中，请稍候。",
            )
            return

        await self._send_long_message(
            message,
            "正在分析命令详情…",
        )

        coroutine = self._run_approval_detail_analysis(
            message=message,
            chat_id=chat_id,
            approval_id=approval_id,
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
    ) -> None:
        try:
            details = await self.agent.get_pending_approval_details(
                chat_id,
                approval_id=approval_id,
                include_llm=True,
            )
        except Exception as e:
            logger.exception("Failed to load approval details in background")
            await self._send_long_message(
                message,
                self._format_error_text(
                    e,
                    prefix="详细命令分析失败",
                    fallback="详细命令分析失败，请稍后重试。",
                ),
            )
            return

        if not details.get("ok"):
            await self._send_long_message(
                message,
                str(details.get("message", "No pending approval.")),
            )
            return

        await self._send_approval_detail_result(message, details)

    async def _send_approval_detail_result(self, message, details: dict) -> None:
        analysis = details.get("analysis", {}) or {}
        command_hash = str(details.get("command_hash", ""))
        text = (
            "Approval details\n\n"
            f"Approval ID: {details.get('approval_id', '')}\n"
            f"Run ID: {details.get('run_id', '')}\n"
            f"Command: {details.get('command', '')}\n"
            f"Command hash: {command_hash[:12]}\n"
            f"Intent: {details.get('reason', '')}\n"
            f"Safety status: {analysis.get('safety_status', 'UNSAFE')}\n"
            f"Risk level: {analysis.get('risk_level', 'HIGH')}\n"
            f"Mutation detected: {bool(analysis.get('mutation_detected', False))}\n"
            f"Deletion detected: {bool(analysis.get('deletion_detected', False))}\n"
            f"Reviewer mode: {analysis.get('reviewer_mode', 'static_only')}\n\n"
            f"Impact analysis:\n{analysis.get('impact_analysis', '')}"
        )
        await self._send_long_message(message, text)
        await self._send_approval_actions(message, details)

    async def _send_round_limit_prompt(self, message, data: dict[str, Any] | None = None) -> None:
        """Ask user whether to continue after reaching one execution window."""
        payload = data or {}
        rounds = int(payload.get("rounds", 0))
        window = int(payload.get("window", self.agent.config.max_rounds_per_turn))
        text = (
            f"\u5f53\u524d\u4efb\u52a1\u5df2\u6267\u884c {rounds} \u8f6e\uff0c\u5c1a\u672a\u5b8c\u6210\u3002\n"
            f"\u662f\u5426\u7ee7\u7eed\u6267\u884c\uff08\u518d\u8fd0\u884c {window} \u8f6e\uff09\uff1f"
        )
        keyboard = [[
            InlineKeyboardButton("\u25b6\ufe0f \u7ee7\u7eed\u6267\u884c", callback_data="continue_round_task"),
            InlineKeyboardButton("\ud83d\uded1 \u653e\u5f03\u4efb\u52a1", callback_data="abandon_round_task"),
        ]]
        await self._reply_text(
            message,
            text,
            markup=MessageMarkup.PLAIN,
            reply_markup=InlineKeyboardMarkup(keyboard),
        )
        return

    async def _start_round_limit_resolution(self, message, chat_id: int, action: str) -> None:
        """Continue a round-limited task in the background after a callback click."""
        normalized_action = (action or "").strip().upper()
        if normalized_action != "CONTINUE":
            final_response = await self.agent.resolve_round_limit(chat_id, normalized_action)
            await self._send_long_message(message, final_response)
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
        message,
        status_message,
        chat_id: int,
        action: str,
    ) -> None:
        """Run round-limit continuation without tying it to callback query timeout."""
        try:
            final_response = await self.agent.resolve_round_limit(chat_id, action)
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

        await self._send_agent_result(message, final_response)

    async def _handle_engram(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle /engram command."""
        if not self._check_auth(update):
            return
            
        args = context.args or []
        store = getattr(self.agent.tool_dispatcher, "engram_store", None)
        
        if not store:
            await self._send_text(update, "❌ EngramStore 未初始化。")
            return
            
        if len(args) == 2 and args[0].lower() == "delete":
            engram_id = args[1]
            if store.remove(engram_id):
                await self._send_text(update, f"✅ 已删除 Engram: {engram_id}")
            else:
                await self._send_text(update, f"❌ 未找到有效记录: {engram_id}")
            return
            
        active = store.list(include_superseded=False)
        if not active:
            await self._send_text(update, "📭 当前没有任何有效的 Engram 记录。")
            return
            
        lines = ["🧠 *ChatDome 主机记忆印迹 (Engrams)*", ""]
        import datetime
        for e in active:
            dt = datetime.datetime.fromtimestamp(e.created_at).strftime('%Y-%m-%d %H:%M')
            lines.append(f"• `[{e.category}]` {e.fact}")
            lines.append(f"  _ID: `{e.id}` | {dt}_")
            
        lines.append("")
        lines.append("🗑️ _删除记录: `/engram delete <id>`_")
        
        await self._send_text(update, "\n".join(lines))

    def _get_llm_manager(self):
        return getattr(self.agent, "llm_manager", None)

    def _format_llm_profile_list(self) -> str:
        manager = self._get_llm_manager()
        if manager is None:
            return "LLMManager 未启用。"

        profiles = manager.list_profiles()
        if not profiles:
            return "No LLM is configured. Please configure an LLM before use."
        active = next((item for item in profiles if item.active), None)
        active_name = active.name if active else manager.get_active_profile_name()

        lines = [
            "LLM Profiles",
            "",
            f"当前: {active_name}",
            "切换命令: /llm <profile_name>",
            "",
            "可复制的切换命令:",
        ]
        for item in profiles:
            suffix = "  (current)" if item.active else ""
            lines.append(f"  /llm {item.name}{suffix}")

        lines.extend(["", "详细信息:"])
        for item in profiles:
            marker = "[当前]" if item.active else "[可选]"
            lines.extend([
                "",
                f"{marker} {item.name}",
                f"  状态: {self._format_llm_status(item.status)}",
                f"  类型: {item.provider}/{item.api_mode}",
                f"  模型: {item.model}",
            ])
            if item.base_url:
                lines.append(f"  地址: {item.base_url}")
            if item.key_ref:
                lines.append(f"  Key: {item.key_ref}")
        return "\n".join(lines)

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
    ) -> None:
        """Handle /llm_list command."""
        if not self._check_auth(update):
            return
        await self._send_long_message(update.message, self._format_llm_profile_list())

    async def _handle_llm_add(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        if not await self._require_llm_admin(update):
            return
        if self.profile_admin is None:
            await update.message.reply_text("LLM 管理服务未启用。")
            return
        key = self._llm_admin_key(update)
        current = self._active_llm_admin_session(key)
        if current is not None:
            await update.message.reply_text("请先完成当前 LLM 配置，或发送 /llm_cancel。")
            return
        nonce = uuid.uuid4().hex[:12]
        self._llm_admin_sessions[key] = {
            "step": "select_type",
            "nonce": nonce,
            "created_at": time.time(),
        }
        keyboard = [[
            InlineKeyboardButton(
                "OpenAI-compatible",
                callback_data=f"llm_admin:type_openai:{nonce}",
            ),
            InlineKeyboardButton(
                "Codex OAuth",
                callback_data=f"llm_admin:type_codex:{nonce}",
            ),
        ], [
            InlineKeyboardButton("取消", callback_data=f"llm_admin:cancel:{nonce}"),
        ]]
        await self._reply_text(
            update.message,
            "选择 LLM 类型。",
            reply_markup=InlineKeyboardMarkup(keyboard),
        )

    async def _handle_llm_cancel(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        del context
        if not await self._require_llm_admin(update):
            return
        key = self._llm_admin_key(update)
        removed_any = self._llm_admin_sessions.pop(key, None) is not None
        for nonce, item in list(self._llm_admin_confirmations.items()):
            if item.get("key") == key:
                self._llm_admin_confirmations.pop(nonce, None)
                removed_any = True
        if removed_any:
            await update.message.reply_text("已取消 LLM 操作。")
        else:
            await update.message.reply_text("当前没有待取消的 LLM 操作。")

    async def _handle_llm_delete(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        if not await self._require_llm_admin(update):
            return
        if self.profile_admin is None:
            await update.message.reply_text("LLM 管理服务未启用。")
            return
        args = getattr(context, "args", []) or []
        if len(args) != 1:
            await update.message.reply_text("用法: /llm_delete <profile>")
            return
        try:
            summary = await self.profile_admin.get_profile_summary(str(args[0]).strip())
        except Exception as exc:
            await update.message.reply_text(
                self._format_error_text(
                    exc,
                    prefix="无法删除 LLM",
                    fallback="无法读取 LLM profile。",
                )
            )
            return
        if summary is None:
            await update.message.reply_text(f"未找到 LLM profile: {args[0]}")
            return
        if summary.active:
            await update.message.reply_text("请先切换 LLM，再删除该 profile。")
            return
        nonce = uuid.uuid4().hex[:12]
        key = self._llm_admin_key(update)
        self._llm_admin_confirmations[nonce] = {
            "kind": "delete",
            "profile_name": summary.name,
            "key": key,
            "expires_at": time.time() + 60,
        }
        keyboard = [[
            InlineKeyboardButton("确认删除", callback_data=f"llm_admin:delete_yes:{nonce}"),
            InlineKeyboardButton("取消", callback_data=f"llm_admin:delete_no:{nonce}"),
        ]]
        await self._reply_text(
            update.message,
            f"删除 LLM profile '{summary.name}'？",
            reply_markup=InlineKeyboardMarkup(keyboard),
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
            await update.message.reply_text("LLM 配置已超时，请重新运行 /llm_add。")
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

        await update.message.reply_text("使用按钮继续，或发送 /llm_cancel。")
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
    ) -> None:
        """List profiles or persistently switch the active LLM."""
        if not self._check_auth(update):
            return

        args = getattr(context, "args", []) or []
        if not args:
            await self._send_long_message(update.message, self._format_llm_profile_list())
            return
        if not await self._require_llm_admin(update):
            return
        if self.profile_admin is None:
            await update.message.reply_text("LLM 管理服务未启用。")
            return

        profile_name = str(args[0]).strip()
        old_profile = self.config.active_ai_profile
        try:
            result = await self.profile_admin.set_active_profile(
                profile_name,
                self._profile_actor(update),
            )
        except Exception as exc:
            logger.warning("LLM profile switch failed: %s", exc)
            await update.message.reply_text(
                self._format_error_text(
                    exc,
                    prefix="LLM 切换失败",
                    fallback="LLM 切换失败，请检查配置后重试。",
                )
            )
            return

        profile = self.config.ai_profiles[result.profile_name]
        await update.message.reply_text(
            "已切换 LLM: "
            f"{result.profile_name} ({profile.provider}/{profile.api_mode}, model={profile.model})"
        )
        logger.info(
            "LLM profile switched by Telegram: %s -> %s",
            old_profile,
            result.profile_name,
        )

    @staticmethod
    def _default_codex_profile(profile_name: str) -> AIConfig:
        from chatdome.llm.codex_auth import default_token_file_config_for_profile

        return AIConfig(
            provider="codex",
            api_mode="codex_responses",
            model="gpt-5.5",
            temperature=0.1,
            max_tokens=2000,
            codex_client_id="",
            codex_token_file=default_token_file_config_for_profile(profile_name),
            codex_base_url="https://chatgpt.com/backend-api/codex",
        )

    @staticmethod
    def _login_profile_with_token_file(profile_name: str, profile: AIConfig) -> tuple[AIConfig, bool]:
        if str(profile.codex_token_file or "").strip():
            return profile, False
        from chatdome.llm.codex_auth import default_token_file_config_for_profile

        return (
            replace(
                profile,
                codex_token_file=default_token_file_config_for_profile(profile_name),
            ),
            True,
        )

    def _resolve_codex_login_profile(self, requested_profile: str = "") -> tuple[str, Any, bool]:
        profiles = self.config.ai_profiles
        requested = str(requested_profile or "").strip()

        if requested:
            profile = profiles.get(requested)
            if profile is None:
                try:
                    validate_profile_name(requested)
                except ValueError as exc:
                    raise LLMProfileNotFound(f"未知 LLM profile: {requested}") from exc
                return requested, self._default_codex_profile(requested), True
            if profile.api_mode != "codex_responses":
                raise LLMProfileNotReady(f"profile {requested} 不是 Codex OAuth profile。")
            login_profile, persist_profile = self._login_profile_with_token_file(requested, profile)
            return requested, login_profile, persist_profile

        manager = self._get_llm_manager()
        active_name = manager.get_active_profile_name() if manager else self.config.active_ai_profile
        active_profile = profiles.get(active_name)
        if active_profile and active_profile.api_mode == "codex_responses":
            login_profile, persist_profile = self._login_profile_with_token_file(active_name, active_profile)
            return active_name, login_profile, persist_profile

        codex_profiles = [
            (name, profile)
            for name, profile in profiles.items()
            if profile.api_mode == "codex_responses"
        ]
        if len(codex_profiles) == 1:
            name, profile = codex_profiles[0]
            login_profile, persist_profile = self._login_profile_with_token_file(name, profile)
            return name, login_profile, persist_profile

        if not codex_profiles:
            return "codex", self._default_codex_profile("codex"), True

        names = ", ".join(name for name, _ in codex_profiles) or "(none)"
        raise LLMProfileNotReady(
            "当前 active profile 不是 Codex。请使用 /codex_login <profile_name> 指定 Codex profile。"
            f"可用 Codex profiles: {names}"
        )

    async def _handle_codex_login(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        """Handle /codex_login command — trigger OAuth Device Code flow."""
        if not self._check_auth(update):
            return
        if not await self._require_llm_admin(update):
            return
        if self.profile_admin is None:
            await update.message.reply_text("LLM 管理服务未启用。")
            return

        chat_id = update.effective_chat.id
        persist_overwrite = False
        persist_expected_fingerprint = None
        from chatdome.llm.codex_auth import CodexOAuth

        try:
            requested_profile = (getattr(context, "args", []) or [""])[0]
            if getattr(context, "chatdome_force_codex", False):
                profile_name = validate_profile_name(requested_profile)
                profile = self._default_codex_profile(profile_name)
                persist_profile = True
            else:
                profile_name, profile, persist_profile = self._resolve_codex_login_profile(
                    requested_profile
                )
            if persist_profile:
                initial_summary = await self.profile_admin.get_profile_summary(profile_name)
                if getattr(context, "chatdome_force_codex", False):
                    persist_overwrite = bool(
                        getattr(context, "chatdome_codex_overwrite", False)
                    )
                    persist_expected_fingerprint = getattr(
                        context, "chatdome_expected_fingerprint", None
                    )
                else:
                    persist_overwrite = initial_summary is not None
                    persist_expected_fingerprint = (
                        initial_summary.fingerprint if initial_summary is not None else None
                    )
        except Exception as e:
            await update.message.reply_text(
                self._format_error_text(
                    e,
                    prefix="❌ 无法启动 Codex 认证",
                    fallback="无法启动 Codex 认证，请检查 LLM profile 配置。",
                )
            )
            return
        
        oauth = CodexOAuth(
            client_id=profile.codex_client_id or None,
            token_file=profile.codex_token_file or None,
        )
        
        try:
            status_msg = await update.message.reply_text("正在向 OpenAI 申请设备验证码，请稍候...")
            device_info = await oauth.request_device_code()
            await status_msg.delete()
        except Exception as e:
            logger.error("Failed to request Codex device code: %s", e)
            await update.message.reply_text(
                self._format_error_text(
                    e,
                    prefix="❌ 申请验证码失败",
                    fallback="申请 Codex 设备验证码失败，请稍后重试。",
                )
            )
            return

        device_code = device_info["device_code"]
        user_code = device_info["user_code"]
        verification_uri = device_info.get("verification_uri", "https://auth.openai.com/codex/device")
        interval = device_info.get("interval", 5)
        expires_in = device_info.get("expires_in", 300)

        msg_text = (
            "🔐 *OpenAI Codex 认证授权*\n\n"
            f"Profile: `{profile_name}`\n\n"
            f"请在浏览器中打开链接进行授权：\n"
            f"{verification_uri}\n\n"
            f"输入以下临时验证码：\n"
            f"`{user_code}`\n\n"
            f"⏳ 该验证码将在 5 分钟内有效。绑定成功后，ChatDome 将自动保存授权凭证。"
        )
        
        await self._send_long_message(update.message, msg_text, markup=MessageMarkup.TELEGRAM_MARKDOWN)

        # Start background polling task
        async def do_poll_and_exchange():
            try:
                code, code_verifier = await oauth.poll_device_token(
                    device_code=device_code,
                    user_code=user_code,
                    interval=interval,
                    timeout=expires_in
                )
                await oauth.exchange_token(code, code_verifier)
                if persist_profile:
                    result = await self.profile_admin.create_codex(
                        CreateCodexProfileRequest(
                            name=profile_name,
                            model=profile.model,
                            client_id=profile.codex_client_id,
                            token_file=profile.codex_token_file,
                            base_url=profile.codex_base_url,
                            temperature=profile.temperature,
                            max_tokens=profile.max_tokens,
                            overwrite_existing=persist_overwrite,
                            expected_profile_fingerprint=persist_expected_fingerprint,
                        ),
                        self._profile_actor(update),
                    )
                    logger.info(
                        "Codex profile persisted in process: %s action=%s",
                        result.profile_name,
                        result.action,
                    )

                await self._send_bot_text(
                    bot=context.bot,
                    chat_id=chat_id,
                    text=(
                        "✅ *Codex 认证成功！*\n"
                        f"Profile `{profile_name}` 已可使用。"
                    ),
                    markup=MessageMarkup.TELEGRAM_MARKDOWN
                )
            except asyncio.CancelledError:
                pass
            except Exception as e:
                logger.error("Codex device login polling background task failed: %s", e)
                await self._send_bot_text(
                    bot=context.bot,
                    chat_id=chat_id,
                    text=self._format_error_text(
                        e,
                        prefix="❌ Codex 认证失败",
                        fallback="Codex 认证失败，请重新运行 /codex_login。",
                    ),
                    markup=MessageMarkup.PLAIN,
                )

        if self._app is not None:
            self._app.create_task(do_poll_and_exchange())
        else:
            asyncio.create_task(do_poll_and_exchange())

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
            await query.message.reply_text("LLM 操作已失效，请重新开始。")
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
                await query.message.reply_text("删除确认已失效，请重新运行 /llm_delete。")
                return
            await query.edit_message_reply_markup(reply_markup=None)
            if action == "delete_no":
                await query.message.reply_text("已取消删除。")
                return
            try:
                result = await self.profile_admin.delete_profile(
                    item["profile_name"],
                    self._profile_actor(update),
                )
            except Exception as exc:
                await query.message.reply_text(
                    self._format_error_text(
                        exc,
                        prefix="删除 LLM 失败",
                        fallback="删除 LLM 失败，请重试。",
                    )
                )
                return
            await query.message.reply_text(f"已删除 LLM profile: {result.profile_name}")
            return

        session = self._active_llm_admin_session(key)
        if session is None or session.get("nonce") != nonce:
            await query.message.reply_text("LLM 配置已失效，请重新运行 /llm_add。")
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
            await query.message.reply_text("已取消 LLM 配置。")
            return
        if action == "overwrite_yes":
            session["overwrite"] = True
            await query.edit_message_reply_markup(reply_markup=None)
            await self._advance_llm_admin_after_name(query.message, session)
            return
        if action == "save_yes":
            if session.get("step") != "confirm_save":
                await query.message.reply_text("LLM 配置状态无效，请重新开始。")
                return
            saved = dict(session)
            self._llm_admin_sessions.pop(key, None)
            await query.edit_message_reply_markup(reply_markup=None)
            try:
                result = await self.profile_admin.create_openai(
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
                        prefix="保存 LLM 失败",
                        fallback="保存 LLM 失败，请重新开始。",
                    )
                )
                return
            verb = "已更新" if result.action == "updated" else "已新增"
            await query.message.reply_text(f"{verb} LLM profile: {result.profile_name}")
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
            await self._handle_codex_login(proxy_update, proxy_context)
            return

        await query.message.reply_text("LLM 操作已失效，请重新开始。")

    async def _clear_callback_message_markup(self, query, context_label: str = "callback message") -> None:
        try:
            await query.edit_message_reply_markup(reply_markup=None)
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

                await self._start_round_limit_resolution(query.message, chat_id, action)
                return

            if callback_data == "show_cmd_details" or approval_action == "details":
                await self._clear_callback_message_markup(query, "approval detail callback message")
                await self._start_approval_detail_analysis(
                    query.message,
                    chat_id,
                    approval_id or None,
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

            thinking_msg = await query.message.reply_text("Processing...")
            try:
                _, final_response = await asyncio.wait_for(
                    self.agent.resume_session(chat_id, action, approval_id=approval_id or None),
                    timeout=90,
                )
            finally:
                try:
                    await thinking_msg.delete()
                except Exception:
                    pass

            await self._send_agent_result(query.message, final_response)
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

    async def _handle_confirm(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle /confirm command for high-risk executions."""
        if not self._check_auth(update):
            return
            
        chat_id = update.effective_chat.id
        approval_id = context.args[0].strip() if context.args else None
        thinking_msg = await update.message.reply_text("🤔 强制批准执行中...")
        try:
            _, final_response = await self.agent.resume_session(chat_id, "APPROVE", approval_id=approval_id)
            try:
                await thinking_msg.delete()
            except Exception:
                pass

            await self._send_agent_result(update.message, final_response)
        except Exception as e:
            logger.exception("Confirm command failed")
            await update.message.reply_text(
                self._format_error_text(
                    e,
                    prefix="⚠️ 恢复会话失败",
                    fallback="恢复会话失败，请稍后重试。",
                )
            )

    async def _handle_reject(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle /reject command for pending high-risk execution."""
        if not self._check_auth(update):
            return

        chat_id = update.effective_chat.id
        approval_id = context.args[0].strip() if context.args else None
        thinking_msg = await update.message.reply_text("🤹 正在拒绝待执行命令...")
        try:
            _, final_response = await self.agent.resume_session(chat_id, "REJECT", approval_id=approval_id)
            try:
                await thinking_msg.delete()
            except Exception:
                pass

            await self._send_agent_result(update.message, final_response)
        except Exception as e:
            logger.exception("Reject command failed")
            await update.message.reply_text(
                self._format_error_text(
                    e,
                    prefix="⚠️ 恢复会话失败",
                    fallback="恢复会话失败，请稍后重试。",
                )
            )

    # ----- Utilities -----

    async def _send_agent_result(self, message, result: AgentResult | str | None) -> None:
        """Render a structured Agent result into Telegram messages."""
        agent_result = coerce_agent_result(result)
        if agent_result.kind == "pending_approval":
            await self._send_approval_request(message, agent_result.payload)
            return
        if agent_result.kind == "round_limit":
            await self._send_round_limit_prompt(message, agent_result.payload)
            return
        await self._send_long_message(message, agent_result.content)

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
            await self._send_long_message(
                query.message,
                "这条告警上下文已过期，请查看 /sentinel_history 或等待下一次告警。",
            )
            return

        thinking_msg = await query.message.reply_text("正在生成告警分析...")
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

    async def _handle_sentinel_alert_detail(self, query, chat_id: int, alert_token: str) -> None:
        cached = self._alert_analysis_cache.get(alert_token)
        if not cached or cached.get("chat_id") != chat_id:
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
        admin_ids = set(self.config.telegram.admin_chat_ids or [])
        if getattr(chat, "type", "") == "private" and chat.id in admin_ids:
            return True
        message = update.effective_message
        if message is not None:
            await message.reply_text(
                "当前会话没有 LLM 管理权限。请在 config.yaml 的 "
                "telegram.admin_chat_ids 中配置管理员 Chat ID。"
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
    ) -> None:
        """
        Send a message, automatically splitting if it exceeds Telegram's
        4096 character limit.
        """
        rendered = self._formatter.render(text, markup=markup)
        text = rendered.text
        parse_mode = rendered.parse_mode

        async def _send_chunk(chunk_text: str) -> None:
            kwargs: dict[str, Any] = {}
            if parse_mode:
                kwargs["parse_mode"] = parse_mode
            await message.reply_text(chunk_text, **kwargs)

        max_len = min(self.max_message_length, 4096)

        if len(text) <= max_len:
            await _send_chunk(text)
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
            await _send_chunk(chunk)

    @staticmethod
    def _truncate_csv_items(raw: str, max_items: int = 14) -> str:
        """Truncate a comma-separated list for Telegram readability."""
        items = [x.strip() for x in raw.split(",") if x.strip()]
        if not items or items == ["none"]:
            return "none"

        if len(items) <= max_items:
            return ", ".join(items)
        return f"{', '.join(items[:max_items])} ... (+{len(items) - max_items} more)"

    def _build_environment_summary(self) -> str:
        """Build a short environment summary from environment_profile.md."""
        path = self._environment_profile_path
        if not path.exists():
            return (
                "ℹ️ 未找到环境档案。\n"
                "请重启 ChatDome 生成运行环境画像。"
            )

        try:
            text = path.read_text(encoding="utf-8")
        except OSError as e:
            return self._format_error_text(
                e,
                prefix="⚠️ 读取环境档案失败",
                fallback="读取环境档案失败，请检查文件权限。",
            )

        fields: dict[str, str] = {}
        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("- ") or ": " not in line:
                continue
            key, value = line[2:].split(": ", 1)
            fields[key.strip()] = value.strip()

        available = self._truncate_csv_items(fields.get("Available", "none"))
        missing = self._truncate_csv_items(fields.get("Missing", "none"))

        return (
            "🧭 当前运行环境摘要\n\n"
            f"采集时间(UTC): {fields.get('UTC', 'unknown')}\n\n"
            "主机信息:\n"
            f"- OS family: {fields.get('OS family', 'unknown')}\n"
            f"- OS release: {fields.get('OS release', 'unknown')}\n"
            f"- OS version: {fields.get('OS version', 'unknown')}\n"
            f"- Machine: {fields.get('Machine', 'unknown')}\n"
            f"- Python: {fields.get('Python', 'unknown')}\n"
            f"- Shell: {fields.get('Shell', 'unknown')}\n"
            f"- Linux distro: {fields.get('Linux distro', 'N/A')}\n"
            f"- WSL: {fields.get('WSL', 'unknown')}\n\n"
            "命令探测(节选):\n"
            f"- Available: {available}\n"
            f"- Missing: {missing}"
        )

    # ----- Sentinel command handlers -----

    async def _handle_sentinel_mute(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        """Handle /sentinel_mute — pause Sentinel alert pushes."""
        if not self._check_auth(update):
            return
        if self._sentinel is None:
            await update.message.reply_text("ℹ️ 哨兵模式未启用。")
            return

        raw_args = " ".join(context.args or []).strip()
        until = parse_alert_mute_until(raw_args)
        chat_id = update.effective_chat.id
        status = self._sentinel.mute_alert_push(
            until=until,
            reason=f"telegram_command:/sentinel_mute {raw_args}".strip(),
            chat_id=chat_id,
        )
        await update.message.reply_text(
            format_alert_push_status(status, prefix="✅ 已暂停 Sentinel 告警推送。")
        )

    async def _handle_sentinel_resume(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        """Handle /sentinel_resume — resume Sentinel alert pushes."""
        if not self._check_auth(update):
            return
        if self._sentinel is None:
            await update.message.reply_text("ℹ️ 哨兵模式未启用。")
            return

        chat_id = update.effective_chat.id
        status = self._sentinel.resume_alert_push(chat_id=chat_id)
        await update.message.reply_text(
            format_alert_push_status(status, prefix="✅ 已恢复 Sentinel 告警推送。")
        )

    async def _handle_sentinel_status(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        """Handle /sentinel_status — show alert statistics overview."""
        if not self._check_auth(update):
            return
        if self._sentinel is None:
            await update.message.reply_text("ℹ️ 哨兵模式未启用。")
            return
        from chatdome.sentinel.alerter import format_status_message
        status = "运行中" if self._sentinel.is_running else "未运行"
        check_count = len(self._sentinel.checks)
        alert_target_count = len(self._sentinel.alert_chat_ids)
        loaded_commands = self._pack_loader.command_count if self._pack_loader is not None else 0
        learning = "是" if self._sentinel.suppressor.is_learning else "否"
        push_status = self._sentinel.alert_push_status()
        if push_status.get("muted"):
            muted_until = push_status.get("muted_until")
            if isinstance(muted_until, datetime):
                push_line = f"已静默至 {muted_until.strftime('%Y-%m-%d %H:%M %Z').strip()}"
            else:
                push_line = "已静默至手动恢复"
        else:
            push_line = "开启"

        runtime_lines = [
            "🧭 调度器状态",
            f"  - 运行状态: {status}",
            f"  - 检查项数量: {check_count}",
            f"  - 已加载命令: {loaded_commands}",
            f"  - 告警推送目标: {alert_target_count} 个",
            f"  - 告警推送状态: {push_line}",
            f"  - 基线学习中: {learning}",
        ]
        if alert_target_count == 0:
            runtime_lines.append("  - ⚠️ 未配置推送目标，告警只会记录，不会发到手机")
        text = format_status_message(self._sentinel.history)
        await update.message.reply_text("\n".join(runtime_lines) + "\n\n" + text)

    async def _handle_sentinel_trigger(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        """Handle /sentinel_trigger — manually trigger all checks."""
        if not self._check_auth(update):
            return
        if self._sentinel is None:
            await update.message.reply_text("ℹ️ 哨兵模式未启用。")
            return
        await update.message.reply_text("⏳ 正在执行全量巡检...")
        try:
            result = await self._sentinel.trigger_all()
            if len(result) > self.max_message_length:
                result = result[:self.max_message_length - 20] + "\n... (已截断)"
            await update.message.reply_text(f"🛡️ 巡检完成:\n\n{result}")
        except Exception as e:
            logger.exception("Sentinel trigger failed")
            await update.message.reply_text(
                self._format_error_text(
                    e,
                    prefix="❌ 巡检出错",
                    fallback="巡检执行失败，请稍后重试。",
                )
            )

    async def _handle_sentinel_history(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        """Handle /sentinel_history — show alert history."""
        if not self._check_auth(update):
            return
        if self._sentinel is None:
            await update.message.reply_text("ℹ️ 哨兵模式未启用。")
            return
        from chatdome.sentinel.alerter import format_history_message
        text = format_history_message(self._sentinel.history)
        await self._send_long_message(update.message, text)

    async def _handle_sentinel_packs(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        """Handle /sentinel_packs — list loaded command packs."""
        if not self._check_auth(update):
            return
        if self._pack_loader is None:
            await update.message.reply_text("ℹ️ PackLoader 未初始化。")
            return
        checks = self._pack_loader.list_checks()
        if not checks:
            await update.message.reply_text("ℹ️ 无可用命令包。")
            return
        from collections import defaultdict
        packs: dict[str, list[str]] = defaultdict(list)
        for cmd in self._pack_loader._commands.values():
            packs[cmd.pack].append(f"  - {cmd.id}: {cmd.name}")
        lines = [f"📦 已加载 {len(checks)} 条命令 ({len(packs)} 个包):", ""]
        for pack_name, cmds in sorted(packs.items()):
            lines.append(f"**{pack_name}** ({len(cmds)} 条):")
            lines.extend(sorted(cmds))
            lines.append("")
        text = "\n".join(lines)
        if len(text) > self.max_message_length:
            text = text[:self.max_message_length - 20] + "\n... (已截断)"
        await update.message.reply_text(text)

    async def send_alert(self, chat_id: int, text: str, alert_event: Any | None = None) -> None:
        """Send an alert message to a specific chat. Used by Sentinel Alerter."""
        if self._app is None:
            logger.warning("Cannot send alert: app not initialized")
            return
        try:
            original_text = text
            reply_markup = None
            if alert_event is not None:
                token = self._cache_alert_analysis_context(
                    chat_id=chat_id,
                    alert_text=original_text,
                    alert_event=alert_event,
                )
                reply_markup = InlineKeyboardMarkup(
                    [[
                        InlineKeyboardButton(
                            "📋 查看详情",
                            callback_data=f"sentinel_alert_detail:{token}",
                        ),
                        InlineKeyboardButton(
                            "🤖 告警分析",
                            callback_data=f"sentinel_alert_analysis:{token}",
                        ),
                    ]]
                )

            if len(text) > self.max_message_length:
                text = text[:self.max_message_length - 20] + "\n... (已截断)"
            await self._send_bot_text(self._app.bot, chat_id, text, reply_markup=reply_markup)
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
