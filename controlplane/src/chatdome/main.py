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
from pathlib import Path

from chatdome.config import load_config
from chatdome.agent.core import Agent
from chatdome.executor.sandbox import CommandSandbox
from chatdome.llm.client import LLMClient
from chatdome.runtime_environment import collect_and_persist_runtime_environment
from chatdome.sentinel.pack_loader import PackLoader
from chatdome.sentinel.user_context import UserContextLedger
from chatdome.telegram.bot import TelegramBot
from chatdome.logger import setup_logging


# setup_logging was removed and replaced by chatdome.logger.setup_logging()


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
    logger.info("  ChatDome v0.2.0 — AI Host Security Assistant")
    logger.info("=" * 60)
    logger.info("  Model:    %s", config.ai.model)
    logger.info("  Base URL: %s", config.ai.base_url)
    logger.info("  Allowed chats: %s", config.telegram.allowed_chat_ids or "(all)")
    logger.info("  Generated commands: %s", config.agent.allow_generated_commands)
    logger.info(
        "  Session policy: memory_timeout=%ss, pending_timeout=%ss, persisted_ttl=%ss",
        config.agent.session_timeout,
        config.agent.pending_approval_timeout,
        config.agent.persisted_session_ttl,
    )
    if config.agent.allow_unrestricted_commands:
        logger.warning("  ⚠️  UNRESTRICTED commands: ENABLED — ALL validation bypassed!")
    logger.info("=" * 60)

    # ── Initialize components ──

    # Pack Loader (replaces old registry.py)
    pack_loader = PackLoader(
        builtin_dir=Path(__file__).parent / "packs",
    )
    sentinel_cfg = getattr(config, "sentinel", None)
    enabled_packs = getattr(sentinel_cfg, "builtin_packs", None) if sentinel_cfg else None
    pack_loader.load(enabled_packs=enabled_packs)
    logger.info("  Pack Loader: %d commands loaded", pack_loader.command_count)

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
        allow_unrestricted_commands=config.agent.allow_unrestricted_commands,
        pack_loader=pack_loader,
    )

    # Runtime environment profile (OS/shell/command availability)
    env_report_path = Path("chat_data/environment_profile.md")
    env_snapshot, runtime_environment_context = collect_and_persist_runtime_environment(
        env_report_path,
    )
    logger.info(
        "  Environment: %s %s | shell=%s | report=%s",
        env_snapshot.os_family,
        env_snapshot.os_release,
        env_snapshot.shell,
        env_report_path.resolve(),
    )

    # User Context Ledger
    user_context_ledger = UserContextLedger()
    valid_check_ids = [str(c.get("check_id")) for c in config.sentinel.checks if c.get("check_id")]
    
    # AI Agent
    agent = Agent(
        llm=llm,
        sandbox=sandbox,
        config=config.agent,
        runtime_environment_context=runtime_environment_context,
        pack_loader=pack_loader,
        user_context_ledger=user_context_ledger,
        valid_check_ids=valid_check_ids,
    )

    # Telegram Bot
    bot = TelegramBot(config=config, agent=agent)

    # Sentinel Scheduler (optional)
    sentinel_scheduler = None
    if config.sentinel.enabled:
        from chatdome.sentinel.scheduler import SentinelScheduler

        # Determine alert targets: sentinel.alert_chat_ids or fallback to telegram.allowed_chat_ids
        alert_targets = config.sentinel.alert_chat_ids or config.telegram.allowed_chat_ids

        sentinel_scheduler = SentinelScheduler(
            config=config.sentinel,
            pack_loader=pack_loader,
            sandbox=sandbox,
            send_alert_fn=bot.send_alert,
            alert_chat_ids=alert_targets,
            user_context_ledger=user_context_ledger,
        )

        bot.set_sentinel(sentinel_scheduler, pack_loader)
        logger.info("  Sentinel: ENABLED (%d checks, push≥%d, cooldown=%ds)",
                     len(config.sentinel.checks), config.sentinel.push_min_severity,
                     config.sentinel.default_cooldown)
    else:
        bot.set_sentinel(None, pack_loader)
        logger.info("  Sentinel: disabled")

    app = bot.build()

    # Start Sentinel after bot is built (needs event loop from run_polling)
    if sentinel_scheduler is not None:
        original_post_init = bot.post_init

        async def _post_init_with_sentinel(app_instance):
            await original_post_init(app_instance)
            sentinel_scheduler.start()

        app.post_init = _post_init_with_sentinel

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
