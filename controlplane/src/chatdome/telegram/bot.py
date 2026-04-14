"""
Telegram Bot setup and message routing.

Uses python-telegram-bot v20+ async API.
Routes messages through authentication → AI Agent → reply.
"""

from __future__ import annotations

import json
import logging

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
/token \\- 查看当前账号的 Token 资源流水与花费汇总
/cmd\\_echo \\- 开关命令回显模式（显示底层执行的具体步骤）

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

    async def post_init(self, app: Application) -> None:
        """Called by the Telegram application after initialization, inside the event loop."""
        self.agent.start()
        
        # Send startup notifications
        for chat_id in self.config.telegram.allowed_chat_ids:
            try:
                await app.bot.send_message(
                    chat_id=chat_id, 
                    text="🚀 *ChatDome 已上线*\n安全探针与大模型推理引擎已就绪，随时听候指令！", 
                    parse_mode="Markdown"
                )
            except Exception as e:
                logger.error("Failed to send startup message to %s: %s", chat_id, e)

    async def post_stop(self, app: Application) -> None:
        """Called when the application stops."""
        for chat_id in self.config.telegram.allowed_chat_ids:
            try:
                await app.bot.send_message(
                    chat_id=chat_id, 
                    text="💤 *ChatDome 已下线*\n主控进程已退出，暂停安全接管服务。", 
                    parse_mode="Markdown"
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
        self._app.add_handler(CommandHandler("cmd_echo", self._handle_cmd_echo))
        self._app.add_handler(CommandHandler("token", self._handle_token))
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

        await update.message.reply_text(
            HELP_TEXT,
            parse_mode="MarkdownV2",
        )

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
            
        await update.message.reply_text(msg, parse_mode="Markdown")

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
        await update.message.reply_text(msg, parse_mode="Markdown")

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

            # Send response (handle long messages)
            await self._send_long_message(update.message, response)

        except Exception as e:
            logger.error("Error handling message: %s", e, exc_info=True)
            try:
                await thinking_msg.edit_text(f"⚠️ 处理消息时发生错误: {e}")
            except Exception:
                await update.message.reply_text(f"⚠️ 处理消息时发生错误: {e}")

    # ----- Interactive Approval -----

    async def _send_approval_request(self, message, data: dict) -> None:
        command = data.get("command", "")
        safety = data.get("safety_status", "UNSAFE")
        impact = data.get("impact_analysis", "")
        reason = data.get("reason", "未提供原因说明")
        
        text = (
            f"⚠️ *AI 尝试执行动态命令*\n"
            f"`{command}`\n\n"
            f"📋 *执行评估*\n"
            f"• *意图*: {reason}\n"
            f"• *影响*: {impact}\n\n"
        )
        
        reply_markup = None
        if safety == "SAFE":
            text += "🟢 *风险定级*: 已评估为安全操作，等待您的最终确认。"
            keyboard = [
                [
                    InlineKeyboardButton("✅ 批准并执行", callback_data="approve_cmd"),
                    InlineKeyboardButton("❌ 拒绝", callback_data="reject_cmd"),
                ]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
        else:
            text += (
                "🔴 *风险定级*: 高危操作！等待确认。\n"
                "为防止误触，请点击下方拒绝。若您明确后果并执意执行，请回复指令： `/confirm`"
            )
            keyboard = [
                [InlineKeyboardButton("❌ 拒绝", callback_data="reject_cmd")]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            
        await message.reply_text(text, parse_mode="Markdown", reply_markup=reply_markup)

    async def _handle_callback_query(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle inline keyboard button clicks."""
        query = update.callback_query
        await query.answer()
        
        if not self._check_auth(update):
            return
            
        chat_id = update.effective_chat.id
        action = "APPROVE" if query.data == "approve_cmd" else "REJECT"
        
        # Remove buttons from the message
        await query.edit_message_reply_markup(reply_markup=None)
        
        thinking_msg = await query.message.reply_text("🤔 处理中...")
        try:
            raw_result, final_response = await self.agent.resume_session(chat_id, action)
            try:
                await thinking_msg.delete()
            except Exception:
                pass
                
            if action == "APPROVE" and raw_result:
                await self._send_long_message(query.message, f"⚙️ *真实沙箱执行结果*:\n```text\n{raw_result}\n```")
                
            if final_response.startswith("__PENDING_APPROVAL__:"):
                data = json.loads(final_response.split(":", 1)[1])
                await self._send_approval_request(query.message, data)
            else:
                await self._send_long_message(query.message, final_response)
        except Exception as e:
            await query.message.reply_text(f"⚠️ 恢复会话异常: {e}")

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
            else:
                await self._send_long_message(update.message, final_response)
        except Exception as e:
            await update.message.reply_text(f"⚠️ 恢复会话异常: {e}")

    # ----- Utilities -----

    def _check_auth(self, update: Update) -> bool:
        """Check if the message sender is authorized."""
        if update.effective_chat is None:
            return False
        return self.auth.is_authorized(update.effective_chat.id)

    async def _send_long_message(self, message, text: str) -> None:
        """
        Send a message, automatically splitting if it exceeds Telegram's
        4096 character limit.
        """
        max_len = min(self.max_message_length, 4096)

        if len(text) <= max_len:
            await message.reply_text(text)
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
            await message.reply_text(chunk)

    async def _handle_error(
        self,
        update: object,
        context: ContextTypes.DEFAULT_TYPE,
    ) -> None:
        """Global error handler."""
        logger.error("Telegram error: %s", context.error, exc_info=context.error)
