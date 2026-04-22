"""
Telegram Bot setup and message routing.

Uses python-telegram-bot v20+ async API.
Routes messages through authentication → AI Agent → reply.
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    CallbackQueryHandler,
    filters,
)

from chatdome.agent.core import Agent
from chatdome.config import ChatDomeConfig
from chatdome.telegram.auth import Authenticator
from chatdome.telegram.formatting import MessageMarkup, TelegramMessageFormatter

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
/sentinel\\_status \\- 哨兵模式告警状态总览
/sentinel\\_trigger \\- 手动触发全量巡检
/sentinel\\_history \\- 查看告警历史
/sentinel\\_packs \\- 查看已加载的命令包

_直接发送你的问题即可，无需命令前缀。_
"""


# ---------------------------------------------------------------------------
# Bot class
# ---------------------------------------------------------------------------

class TelegramBot:
    """
    Telegram Bot that bridges user messages to the AI Agent.
    """

    def __init__(self, config: ChatDomeConfig, agent: Agent):
        self.config = config
        self.agent = agent
        self.auth = Authenticator(config.telegram.allowed_chat_ids)
        self.max_message_length = config.telegram.max_message_length
        self._app: Application | None = None
        self._environment_profile_path = Path("chat_data/environment_profile.md")
        self._sentinel: Any = None   # SentinelScheduler, injected via set_sentinel()
        self._pack_loader: Any = None
        # Default policy: plain text output; markdown can be enabled per message.
        self._formatter = TelegramMessageFormatter(enable_markdown=True)

    def set_sentinel(self, scheduler: Any, pack_loader: Any = None) -> None:
        """Inject Sentinel scheduler after construction (avoids circular deps)."""
        self._sentinel = scheduler
        self._pack_loader = pack_loader

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
        self._app = (
            Application.builder()
            .token(self.config.telegram.bot_token)
            .post_init(self.post_init)
            .post_stop(self.post_stop)
            .build()
        )

        # Register handlers
        self._app.add_handler(CommandHandler("help", self._handle_help))
        self._app.add_handler(CommandHandler("start", self._handle_help))
        self._app.add_handler(CommandHandler("clear", self._handle_clear))
        self._app.add_handler(CommandHandler("confirm", self._handle_confirm))
        self._app.add_handler(CommandHandler("reject", self._handle_reject))
        self._app.add_handler(CommandHandler("cmd_echo", self._handle_cmd_echo))
        self._app.add_handler(CommandHandler("env", self._handle_env))
        self._app.add_handler(CommandHandler("token", self._handle_token))
        self._app.add_handler(CommandHandler("audit", self._handle_audit))
        self._app.add_handler(CommandHandler("sentinel_status", self._handle_sentinel_status))
        self._app.add_handler(CommandHandler("sentinel_trigger", self._handle_sentinel_trigger))
        self._app.add_handler(CommandHandler("sentinel_history", self._handle_sentinel_history))
        self._app.add_handler(CommandHandler("sentinel_packs", self._handle_sentinel_packs))
        self._app.add_handler(CallbackQueryHandler(self._handle_callback_query))
        self._app.add_handler(
            MessageHandler(filters.TEXT & ~filters.COMMAND, self._handle_message)
        )

        # Error handler
        self._app.add_error_handler(self._handle_error)

        logger.info("Telegram bot built successfully")
        return self._app

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
            msg = "🔍 *Command Echo (命令回显模式) 已开启* 🟢\n\n在接下来的回话底部，将会附带实际执行底层步骤的命令代码，供您审计和学习。"
        else:
            msg = "🔍 *Command Echo (命令回显模式) 已关闭* 🔴\n\n对话展示将恢复为干净清爽的安全专家总结模式。"
            
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

            if response.startswith("__PENDING_APPROVAL__:"):
                data = json.loads(response.split(":", 1)[1])
                await self._send_approval_request(update.message, data)
                return
            if response.startswith("__ROUND_LIMIT_CONFIRM__:"):
                data = json.loads(response.split(":", 1)[1])
                await self._send_round_limit_prompt(update.message, data)
                return

            # Send response (handle long messages)
            await self._send_long_message(update.message, response)

        except Exception as e:
            logger.error("Error handling message: %s", e, exc_info=True)
            try:
                await thinking_msg.edit_text(f"⚠️ 处理消息时发生错误: {e}")
            except Exception:
                await update.message.reply_text(f"⚠️ 处理消息时发生错误: {e}")

    # ----- Interactive Approval -----

    async def _send_approval_request(self, message, _data: dict) -> None:
        text = (
            "⚠️ 检测到需要审批的系统操作。\n"
            "默认不展示命令细节。\n"
            "你可以直接允许/拒绝，或先查看详细命令及影响分析。"
        )
        keyboard = [
            [
                InlineKeyboardButton("✅ 允许", callback_data="approve_cmd"),
                InlineKeyboardButton("✅ 本次任务允许", callback_data="approve_task_cmd"),
            ],
            [
                InlineKeyboardButton("❌ 拒绝", callback_data="reject_cmd"),
                InlineKeyboardButton("🔎 详细命令", callback_data="show_cmd_details"),
            ],
        ]
        await self._reply_text(
            message,
            text,
            markup=MessageMarkup.PLAIN,
            reply_markup=InlineKeyboardMarkup(keyboard),
        )
        return

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

            if callback_data in {"continue_round_task", "abandon_round_task"}:
                action = "CONTINUE" if callback_data == "continue_round_task" else "ABANDON"
                try:
                    await query.edit_message_reply_markup(reply_markup=None)
                except Exception:
                    logger.exception("Failed to edit round-limit callback message markup")

                thinking_msg = await query.message.reply_text("Processing...")
                try:
                    final_response = await asyncio.wait_for(
                        self.agent.resolve_round_limit(chat_id, action),
                        timeout=120,
                    )
                finally:
                    try:
                        await thinking_msg.delete()
                    except Exception:
                        pass

                if final_response.startswith("__ROUND_LIMIT_CONFIRM__:"):
                    data = json.loads(final_response.split(":", 1)[1])
                    await self._send_round_limit_prompt(query.message, data)
                elif final_response.startswith("__PENDING_APPROVAL__:"):
                    data = json.loads(final_response.split(":", 1)[1])
                    await self._send_approval_request(query.message, data)
                else:
                    await self._send_long_message(query.message, final_response)
                return

            if callback_data == "show_cmd_details":
                await self._send_long_message(query.message, "正在分析命令影响，请稍候...")
                try:
                    details = await asyncio.wait_for(
                        self.agent.get_pending_approval_details(chat_id),
                        timeout=25,
                    )
                except TimeoutError:
                    await self._send_long_message(
                        query.message,
                        "Approval detail request timed out. Command is still pending. Please click allow/reject again or send /confirm.",
                    )
                    return
                except Exception as e:
                    await self._send_long_message(query.message, f"Failed to load approval details: {e}")
                    return

                if not details.get("ok"):
                    await self._send_long_message(query.message, str(details.get("message", "No pending approval.")))
                    return

                analysis = details.get("analysis", {}) or {}
                text = (
                    "Approval details\n\n"
                    f"Command: {details.get('command', '')}\n"
                    f"Intent: {details.get('reason', '')}\n"
                    f"Safety status: {analysis.get('safety_status', 'UNSAFE')}\n"
                    f"Risk level: {analysis.get('risk_level', 'HIGH')}\n"
                    f"Mutation detected: {bool(analysis.get('mutation_detected', False))}\n"
                    f"Deletion detected: {bool(analysis.get('deletion_detected', False))}\n"
                    f"Reviewer mode: {analysis.get('reviewer_mode', 'static_only')}\n\n"
                    f"Impact analysis:\n{analysis.get('impact_analysis', '')}"
                )
                await self._send_long_message(query.message, text)
                await self._send_approval_request(query.message, {})
                return

            if callback_data == "approve_task_cmd":
                action = "APPROVE_TASK"
            elif callback_data == "approve_cmd":
                action = "APPROVE"
            elif callback_data == "reject_cmd":
                action = "REJECT"
            else:
                await self._send_long_message(query.message, "Unknown action button. Please retry.")
                return

            # Remove buttons from the message for terminal decision actions.
            try:
                await query.edit_message_reply_markup(reply_markup=None)
            except Exception:
                logger.exception("Failed to edit callback message markup")

            thinking_msg = await query.message.reply_text("Processing...")
            try:
                raw_result, final_response = await asyncio.wait_for(
                    self.agent.resume_session(chat_id, action),
                    timeout=90,
                )
            finally:
                try:
                    await thinking_msg.delete()
                except Exception:
                    pass

            if action in {"APPROVE", "APPROVE_TASK"} and raw_result:
                await self._send_long_message(query.message, f"Execution result:\n```text\n{raw_result}\n```")

            if final_response.startswith("__PENDING_APPROVAL__:"):
                data = json.loads(final_response.split(":", 1)[1])
                await self._send_approval_request(query.message, data)
            elif final_response.startswith("__ROUND_LIMIT_CONFIRM__:"):
                data = json.loads(final_response.split(":", 1)[1])
                await self._send_round_limit_prompt(query.message, data)
            else:
                await self._send_long_message(query.message, final_response)
        except TimeoutError:
            await self._send_long_message(
                query.message,
                "Approval action timed out. Command is still pending. Please retry or send /confirm.",
            )
        except Exception as e:
            logger.exception("Callback query handling failed")
            await query.message.reply_text(f"Resume session failed: {e}")

    async def _handle_confirm(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle /confirm command for high-risk executions."""
        if not self._check_auth(update):
            return
            
        chat_id = update.effective_chat.id
        thinking_msg = await update.message.reply_text("🤔 强制批准执行中...")
        try:
            raw_result, final_response = await self.agent.resume_session(chat_id, "APPROVE")
            try:
                await thinking_msg.delete()
            except Exception:
                pass
                
            if raw_result:
                await self._send_long_message(update.message, f"⚙️ *真实沙箱执行结果*:\n```text\n{raw_result}\n```")
                
            if final_response.startswith("__PENDING_APPROVAL__:"):
                data = json.loads(final_response.split(":", 1)[1])
                await self._send_approval_request(update.message, data)
            elif final_response.startswith("__ROUND_LIMIT_CONFIRM__:"):
                data = json.loads(final_response.split(":", 1)[1])
                await self._send_round_limit_prompt(update.message, data)
            else:
                await self._send_long_message(update.message, final_response)
        except Exception as e:
            await update.message.reply_text(f"⚠️ 恢复会话异常: {e}")

    async def _handle_reject(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle /reject command for pending high-risk execution."""
        if not self._check_auth(update):
            return

        chat_id = update.effective_chat.id
        thinking_msg = await update.message.reply_text("🤹 正在拒绝待执行命令...")
        try:
            _, final_response = await self.agent.resume_session(chat_id, "REJECT")
            try:
                await thinking_msg.delete()
            except Exception:
                pass

            if final_response.startswith("__PENDING_APPROVAL__:"):
                data = json.loads(final_response.split(":", 1)[1])
                await self._send_approval_request(update.message, data)
            elif final_response.startswith("__ROUND_LIMIT_CONFIRM__:"):
                data = json.loads(final_response.split(":", 1)[1])
                await self._send_round_limit_prompt(update.message, data)
            else:
                await self._send_long_message(update.message, final_response)
        except Exception as e:
            await update.message.reply_text(f"⚠️ 恢复会话异常: {e}")

    # ----- Utilities -----

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

    async def _send_bot_text(
        self,
        bot,
        chat_id: int,
        text: str,
        *,
        markup: MessageMarkup = MessageMarkup.PLAIN,
    ) -> None:
        """Send bot-initiated chat message through formatter policy."""
        rendered = self._formatter.render(text, markup=markup)
        kwargs: dict[str, Any] = {}
        if rendered.parse_mode:
            kwargs["parse_mode"] = rendered.parse_mode
        await bot.send_message(chat_id=chat_id, text=rendered.text, **kwargs)

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
                "请先重启 ChatDome，让启动流程自动生成 chat_data/environment_profile.md。"
            )

        try:
            text = path.read_text(encoding="utf-8")
        except OSError as e:
            return f"⚠️ 读取环境档案失败: {e}"

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
            f"档案文件: {path.resolve()}\n"
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

    async def _handle_sentinel_status(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        """Handle /sentinel_status — show alert statistics overview."""
        if not self._check_auth(update):
            return
        if self._sentinel is None:
            await update.message.reply_text("ℹ️ 哨兵模式未启用。请在 config.yaml 中设置 sentinel.enabled: true")
            return
        from chatdome.sentinel.alerter import format_status_message
        status = "运行中" if self._sentinel.is_running else "未运行"
        check_count = len(self._sentinel.checks)
        loaded_commands = self._pack_loader.command_count if self._pack_loader is not None else 0
        learning = "是" if self._sentinel.suppressor.is_learning else "否"

        runtime_lines = [
            "🧭 调度器状态",
            f"  - 运行状态: {status}",
            f"  - 检查项数量: {check_count}",
            f"  - 已加载命令: {loaded_commands}",
            f"  - 基线学习中: {learning}",
        ]
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
            await update.message.reply_text(f"❌ 巡检出错: {e}")

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

    async def send_alert(self, chat_id: int, text: str) -> None:
        """Send an alert message to a specific chat. Used by Sentinel Alerter."""
        if self._app is None:
            logger.warning("Cannot send alert: app not initialized")
            return
        try:
            if len(text) > self.max_message_length:
                text = text[:self.max_message_length - 20] + "\n... (已截断)"
            await self._send_bot_text(self._app.bot, chat_id, text)
        except Exception:
            logger.exception("Failed to send alert to chat %s", chat_id)

    # ----- Error handler -----

    async def _handle_error(
        self,
        update: object,
        context: ContextTypes.DEFAULT_TYPE,
    ) -> None:
        """Global error handler."""
        logger.error("Telegram error: %s", context.error, exc_info=context.error)
