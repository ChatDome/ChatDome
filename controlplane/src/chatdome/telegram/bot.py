"""
Telegram Bot setup and message routing.

Uses python-telegram-bot v20+ async API.
Routes messages through authentication → AI Agent → reply.
"""

from __future__ import annotations

import logging

from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
    MessageHandler,
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

    def build(self) -> Application:
        """Build and configure the Telegram Application."""
        self._app = (
            Application.builder()
            .token(self.config.telegram.bot_token)
            .post_init(self.post_init)
            .build()
        )

        # Register handlers
        self._app.add_handler(CommandHandler("help", self._handle_help))
        self._app.add_handler(CommandHandler("start", self._handle_help))
        self._app.add_handler(CommandHandler("clear", self._handle_clear))
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

            # Send response (handle long messages)
            await self._send_long_message(update, response)

        except Exception as e:
            logger.error("Error handling message: %s", e, exc_info=True)
            try:
                await thinking_msg.edit_text(f"⚠️ 处理消息时发生错误: {e}")
            except Exception:
                await update.message.reply_text(f"⚠️ 处理消息时发生错误: {e}")

    # ----- Utilities -----

    def _check_auth(self, update: Update) -> bool:
        """Check if the message sender is authorized."""
        if update.effective_chat is None:
            return False
        return self.auth.is_authorized(update.effective_chat.id)

    async def _send_long_message(self, update: Update, text: str) -> None:
        """
        Send a message, automatically splitting if it exceeds Telegram's
        4096 character limit.
        """
        max_len = min(self.max_message_length, 4096)

        if len(text) <= max_len:
            await update.message.reply_text(text)
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
            await update.message.reply_text(chunk)

    async def _handle_error(
        self,
        update: object,
        context: ContextTypes.DEFAULT_TYPE,
    ) -> None:
        """Global error handler."""
        logger.error("Telegram error: %s", context.error, exc_info=context.error)
