"""
ChatDome entry point.

Loads configuration, initializes all components, and starts the
Telegram bot polling loop.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import os
import sys
from pathlib import Path

from chatdome import __version__
from chatdome.config import load_config
from chatdome.agent.core import Agent
from chatdome.agent.prompts import build_system_prompt, build_tools
from chatdome.executor.sandbox import CommandSandbox
from chatdome.llm.manager import LLMManager
from chatdome.reload_control import ReloadControl
from chatdome.runtime_environment import collect_and_persist_runtime_environment
from chatdome.sentinel.pack_loader import PackLoader
from chatdome.sentinel.user_context import UserContextLedger
from chatdome.agent.engram import EngramStore
from chatdome.telegram.bot import TelegramBot
from chatdome.logger import setup_logging


PID_PATH = Path("chat_data") / "chatdome.pid"


def _write_pid_file(path: Path = PID_PATH) -> None:
    """Write the current process id for local service tooling."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"{os.getpid()}\n", encoding="utf-8")


def _remove_pid_file(path: Path = PID_PATH) -> None:
    """Remove the pid file if it still belongs to this process."""
    try:
        current = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return
    except OSError:
        logging.getLogger("chatdome").warning("Failed to read pid file: %s", path)
        return

    if current and current != str(os.getpid()):
        return
    try:
        path.unlink()
    except OSError:
        logging.getLogger("chatdome").warning("Failed to remove pid file: %s", path)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="chatdome-server",
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
    logger.info("  ChatDome v%s — AI Host Security Assistant", __version__)
    logger.info("=" * 60)
    active_profile = config.ai_profiles[config.active_ai_profile]
    logger.info("  AI profile: %s", config.active_ai_profile)
    logger.info("  AI:       %s / %s", active_profile.provider, active_profile.api_mode)
    logger.info("  Model:    %s", active_profile.model)
    logger.info("  Profiles: %d configured", len(config.ai_profiles))
    logger.info("  Allowed chats: %s", config.telegram.allowed_chat_ids or "(all)")
    logger.info("  Generated commands: %s", config.agent.allow_generated_commands)
    logger.info(
        "  Command output archive: %s",
        "enabled" if config.agent.persist_command_outputs else "disabled",
    )
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

    # LLM Manager
    try:
        llm_manager = LLMManager(config.ai_profiles, config.active_ai_profile)
    except (RuntimeError, ValueError) as e:
        logger.error("LLM manager error: %s", e)
        sys.exit(1)

    # Command Sandbox
    sandbox = CommandSandbox(
        default_timeout=config.agent.command_timeout,
        max_output_chars=config.agent.max_output_chars,
        allow_generated_commands=config.agent.allow_generated_commands,
        allow_unrestricted_commands=config.agent.allow_unrestricted_commands,
        persist_command_outputs=config.agent.persist_command_outputs,
        command_output_retention_days=config.agent.command_output_retention_days,
        command_output_max_chars=config.agent.command_output_max_chars,
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
    
    # Engram Store
    engram_store = EngramStore()

    # AI Agent
    agent = Agent(
        llm=None,
        llm_manager=llm_manager,
        sandbox=sandbox,
        config=config.agent,
        runtime_environment_context=runtime_environment_context,
        pack_loader=pack_loader,
        user_context_ledger=user_context_ledger,
        valid_check_ids=valid_check_ids,
        engram_store=engram_store,
    )

    # Telegram Bot
    bot = TelegramBot(config=config, agent=agent)

    sentinel_scheduler = None

    def _create_sentinel_scheduler(sentinel_config):
        from chatdome.sentinel.scheduler import SentinelScheduler

        # Determine alert targets: sentinel.alert_chat_ids or fallback to telegram.allowed_chat_ids
        alert_targets = sentinel_config.alert_chat_ids or config.telegram.allowed_chat_ids
        if alert_targets:
            logger.info("  Sentinel alert targets: %s", alert_targets)
        else:
            logger.warning(
                "  Sentinel is enabled but no alert chat targets are configured. "
                "Set chatdome.sentinel.alert_chat_ids or "
                "chatdome.telegram.allowed_chat_ids in config.yaml to receive Telegram pushes."
            )

        return SentinelScheduler(
            config=sentinel_config,
            pack_loader=pack_loader,
            sandbox=sandbox,
            send_alert_fn=bot.send_alert,
            alert_chat_ids=alert_targets,
            user_context_ledger=user_context_ledger,
        )

    # Sentinel Scheduler (optional)
    if config.sentinel.enabled:
        sentinel_scheduler = _create_sentinel_scheduler(config.sentinel)

        bot.set_sentinel(sentinel_scheduler, pack_loader)
        logger.info(
            "  Sentinel: ENABLED (%d checks, push>=%d, state-machine mode)",
            len(config.sentinel.checks),
            config.sentinel.push_min_severity,
        )
    else:
        bot.set_sentinel(None, pack_loader)
        logger.info("  Sentinel: disabled")

    app = bot.build()
    reload_control = ReloadControl()
    reload_task: asyncio.Task | None = None

    def _agent_system_prompt() -> str:
        return build_system_prompt(
            allow_unrestricted_commands=config.agent.allow_unrestricted_commands,
            runtime_environment_context=runtime_environment_context,
            pack_loader=pack_loader,
        )

    def _refresh_agent_runtime() -> None:
        nonlocal valid_check_ids
        valid_check_ids = [
            str(c.get("check_id")) for c in config.sentinel.checks if c.get("check_id")
        ]
        agent.config = config.agent
        agent.tools = build_tools(
            allow_unrestricted_commands=config.agent.allow_unrestricted_commands,
            pack_loader=pack_loader,
            valid_check_ids=valid_check_ids,
        )
        agent.session_manager.session_timeout = config.agent.session_timeout
        agent.session_manager.pending_approval_timeout = config.agent.pending_approval_timeout
        agent.session_manager.persisted_session_ttl = config.agent.persisted_session_ttl
        agent.session_manager.max_history_tokens = config.agent.max_history_tokens
        agent.session_manager.system_prompt = _agent_system_prompt()

        sessions = getattr(agent.session_manager, "_sessions", {})
        for session in list(sessions.values()):
            try:
                session.add_system_message(
                    agent.session_manager._build_memory_prompt(session.chat_id)
                )
                agent.session_manager.save_session(session)
            except Exception:
                logger.exception("Failed to refresh active session prompt")

        sandbox.default_timeout = config.agent.command_timeout
        sandbox.max_output_chars = config.agent.max_output_chars
        sandbox.allow_generated_commands = config.agent.allow_generated_commands
        sandbox.allow_unrestricted_commands = config.agent.allow_unrestricted_commands
        sandbox.persist_command_outputs = config.agent.persist_command_outputs
        sandbox.command_output_retention_days = max(
            1,
            int(config.agent.command_output_retention_days),
        )
        sandbox.command_output_max_chars = max(1, int(config.agent.command_output_max_chars))

    async def _reload_sentinel_runtime() -> None:
        nonlocal sentinel_scheduler
        old_scheduler = sentinel_scheduler
        if old_scheduler is not None and hasattr(old_scheduler, "stop_gracefully"):
            await old_scheduler.stop_gracefully()

        pack_loader.load(enabled_packs=config.sentinel.builtin_packs)
        if config.sentinel.enabled:
            sentinel_scheduler = _create_sentinel_scheduler(config.sentinel)
            bot.set_sentinel(sentinel_scheduler, pack_loader)
            sentinel_scheduler.start()
            logger.info(
                "Sentinel hot-reloaded: enabled (%d checks, push>=%d)",
                len(config.sentinel.checks),
                config.sentinel.push_min_severity,
            )
        else:
            sentinel_scheduler = None
            bot.set_sentinel(None, pack_loader)
            logger.info("Sentinel hot-reloaded: disabled")

    async def _apply_reload_request(domains: list[str], config_path: str = "") -> list[str]:
        requested = set(domains)
        if "all" in requested:
            requested = {"llm", "sentinel", "agent"}

        new_config = load_config(config_path or args.config)
        applied: list[str] = []

        if "llm" in requested:
            await llm_manager.reload_profiles(
                new_config.ai_profiles,
                new_config.active_ai_profile,
            )
            config.active_ai_profile = new_config.active_ai_profile
            config.ai_profiles = new_config.ai_profiles
            applied.append("llm")

        sentinel_changed = "sentinel" in requested
        if sentinel_changed:
            config.sentinel = new_config.sentinel
            await _reload_sentinel_runtime()
            applied.append("sentinel")

        if "agent" in requested:
            config.agent = new_config.agent
            _refresh_agent_runtime()
            applied.append("agent")
        elif sentinel_changed:
            # Sentinel changes can alter available packs/check ids exposed to the agent.
            _refresh_agent_runtime()

        return applied

    async def _reload_watch_loop() -> None:
        logger.info("Runtime reload watcher started (%s)", reload_control.request_path)
        while True:
            await asyncio.sleep(2)
            try:
                request = reload_control.load_request()
            except Exception as exc:
                logger.warning("Failed to load reload request: %s", exc)
                continue
            if request is None:
                continue

            logger.info(
                "Applying runtime reload request %s domains=%s source=%s",
                request.request_id,
                request.domains,
                request.source,
            )
            try:
                applied = await _apply_reload_request(request.domains, request.config_path)
                reload_control.mark_status(
                    request.request_id,
                    ok=True,
                    message="reload applied",
                    applied_domains=applied,
                )
                logger.info("Runtime reload applied: %s", applied)
            except Exception as exc:
                logger.exception("Runtime reload failed")
                reload_control.mark_status(
                    request.request_id,
                    ok=False,
                    message=str(exc),
                    applied_domains=[],
                )
            finally:
                reload_control.clear_request(request.request_id)

    original_post_init = bot.post_init

    async def _post_init_with_runtime(app_instance):
        nonlocal reload_task
        await original_post_init(app_instance)
        if sentinel_scheduler is not None:
            sentinel_scheduler.start()
        reload_task = app_instance.create_task(_reload_watch_loop())

    app.post_init = _post_init_with_runtime

    original_post_stop = bot.post_stop

    async def _post_stop_with_runtime(app_instance):
        nonlocal reload_task
        if reload_task is not None:
            reload_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await reload_task
            reload_task = None
        await original_post_stop(app_instance)

    app.post_stop = _post_stop_with_runtime

    # ── Run ──
    logger.info("Starting Telegram bot polling...")
    try:
        _write_pid_file()
        app.run_polling(drop_pending_updates=True)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        _remove_pid_file()
        # Cleanup is handled by python-telegram-bot's run_polling
        logger.info("ChatDome stopped.")


if __name__ == "__main__":
    main()
