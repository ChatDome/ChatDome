"""
ChatDome entry point.

Loads configuration, initializes all components, and starts the
Telegram bot polling loop.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from chatdome.config import load_config
from chatdome.agent.core import Agent
from chatdome.executor.sandbox import CommandSandbox
from chatdome.llm.client import LLMClient
from chatdome.telegram.bot import TelegramBot


def setup_logging() -> None:
    """Configure structured logging."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[logging.StreamHandler(sys.stdout)],
    )
    # Reduce noise from third-party libraries
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("openai").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("telegram").setLevel(logging.WARNING)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="chatdome",
        description="ChatDome — AI-powered host security assistant via Telegram",
    )
    parser.add_argument(
        "--config", "-c",
        default=None,
        help="Path to config.yaml (default: ./config.yaml)",
    )
    return parser.parse_args()


def main() -> None:
    """Main entry point."""
    setup_logging()
    logger = logging.getLogger("chatdome")

    args = parse_args()

    # ── Load configuration ──
    try:
        config = load_config(args.config)
    except (FileNotFoundError, ValueError) as e:
        logger.error("Configuration error: %s", e)
        sys.exit(1)

    logger.info("=" * 60)
    logger.info("  ChatDome v0.1.0 — AI Host Security Assistant")
    logger.info("=" * 60)
    logger.info("  Model:    %s", config.ai.model)
    logger.info("  Base URL: %s", config.ai.base_url)
    logger.info("  Allowed chats: %s", config.telegram.allowed_chat_ids or "(all)")
    logger.info("  Generated commands: %s", config.agent.allow_generated_commands)
    logger.info("=" * 60)

    # ── Initialize components ──

    # LLM Client
    llm = LLMClient(
        api_key=config.ai.api_key,
        base_url=config.ai.base_url,
        model=config.ai.model,
        temperature=config.ai.temperature,
        max_tokens=config.ai.max_tokens,
    )

    # Command Sandbox
    sandbox = CommandSandbox(
        default_timeout=config.agent.command_timeout,
        max_output_chars=config.agent.max_output_chars,
        allow_generated_commands=config.agent.allow_generated_commands,
    )

    # AI Agent
    agent = Agent(
        llm=llm,
        sandbox=sandbox,
        config=config.agent,
    )

    # Telegram Bot
    bot = TelegramBot(config=config, agent=agent)
    app = bot.build()

    # ── Run ──
    logger.info("Starting Telegram bot polling...")
    try:
        app.run_polling(drop_pending_updates=True)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        # Cleanup is handled by python-telegram-bot's run_polling
        logger.info("ChatDome stopped.")


if __name__ == "__main__":
    main()
