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
import signal
import sys
from pathlib import Path

from chatdome import __version__
from chatdome.config import load_config
from chatdome.config_writer import default_config_template_path
from chatdome.agent.core import Agent
from chatdome.agent.audit import CommandAuditTracker
from chatdome.agent.prompts import build_system_prompt, build_tools
from chatdome.executor.sandbox import CommandSandbox
from chatdome.llm.manager import LLMManager
from chatdome.llm.profile_admin import (
    LLMProfileAdminService,
    ProfileActor,
    ProfileConfigStore,
)
from chatdome.reload_control import ReloadControl
from chatdome.runtime_environment import collect_and_persist_runtime_environment
from chatdome.sentinel.pack_loader import PackLoader
from chatdome.sentinel.user_context import UserContextLedger
from chatdome.agent.engram import EngramStore
from chatdome.telegram.bot import TelegramBot
from chatdome.logger import setup_logging
from chatdome.runtime_paths import environment_profile_path, llm_profile_lock_path, run_path
from chatdome.runtime import (
    RuntimeCapabilities,
    discard_platform_delivery,
    write_runtime_status,
)


PID_PATH = run_path("chatdome.pid")
LOCK_PATH = run_path("chatdome.lock")
READY_PATH = run_path("ready.json")


async def build_telegram_application(bot: TelegramBot):
    """Build python-telegram-bot objects on the active service event loop."""
    return bot.build()


class _InstanceLock:
    """Best-effort process lock to prevent duplicate core service instances."""

    def __init__(self, path: Path = LOCK_PATH) -> None:
        self.path = path
        self._fh = None

    def acquire(self) -> bool:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self.path.open("a+", encoding="utf-8")

        if os.name == "posix":
            import fcntl

            try:
                fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                self._fh.close()
                self._fh = None
                return False
        elif os.name == "nt":
            import msvcrt

            try:
                self._fh.seek(0)
                self._fh.write(" ")
                self._fh.flush()
                self._fh.seek(0)
                msvcrt.locking(self._fh.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError:
                self._fh.close()
                self._fh = None
                return False

        self._fh.seek(0)
        self._fh.truncate()
        self._fh.write(f"{os.getpid()}\n")
        self._fh.flush()
        return True

    def release(self) -> None:
        if self._fh is None:
            return
        try:
            if os.name == "posix":
                import fcntl

                fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
            elif os.name == "nt":
                import msvcrt

                self._fh.seek(0)
                with contextlib.suppress(OSError):
                    msvcrt.locking(self._fh.fileno(), msvcrt.LK_UNLCK, 1)
        finally:
            self._fh.close()
            self._fh = None


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
    instance_lock = _InstanceLock()

    if not instance_lock.acquire():
        logger.error(
            "Another ChatDome service is running. "
            "Run systemctl status chatdome and stop duplicate chatdome-server processes."
        )
        sys.exit(1)

    # ── Load configuration ──
    try:
        config = load_config(args.config)
    except (FileNotFoundError, ValueError) as e:
        logger.error("Configuration error: %s", e)
        sys.exit(1)
    runtime_config_path = args.config or os.environ.get("CHATDOME_CONFIG", "config.yaml")

    logger.info("=" * 60)
    logger.info("  ChatDome v%s — AI Host Security Assistant", __version__)
    logger.info("=" * 60)
    if config.llm_configured:
        active_profile = config.ai_profiles[config.active_ai_profile]
        logger.info("  AI profile: %s", config.active_ai_profile)
        logger.info("  AI:       %s / %s", active_profile.provider, active_profile.api_mode)
        logger.info("  Model:    %s", active_profile.model)
        logger.info("  Profiles: %d configured", len(config.ai_profiles))
    else:
        logger.info("  LLM:      not_configured")
    logger.info(
        "  Telegram: %s",
        "configured" if config.telegram_configured else "not_configured",
    )
    logger.info(
        "  Allowed users: %s",
        sorted(set(config.telegram.allowed_ids) | set(config.telegram.admin_ids)) or "(none)",
    )
    logger.info("  Command approval mode: %s", config.agent.command_approval_mode)
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
    logger.info("=" * 60)

    # ── Initialize components ──

    # Pack Loader (replaces old registry.py)
    pack_loader = PackLoader(
        builtin_dir=Path(__file__).parent / "packs",
    )
    pack_loader.load()
    logger.info("  Pack Loader: %d commands loaded", pack_loader.command_count)

    # LLM Manager
    llm_manager = None
    if config.llm_configured:
        try:
            llm_manager = LLMManager(config.ai_profiles, config.active_ai_profile)
        except (RuntimeError, ValueError) as e:
            logger.error("LLM component unavailable: %s", e)

    # Command Sandbox
    sandbox = CommandSandbox(
        default_timeout=config.agent.command_timeout,
        max_output_chars=config.agent.max_output_chars,
        persist_command_outputs=config.agent.persist_command_outputs,
        command_output_retention_days=config.agent.command_output_retention_days,
        command_output_max_chars=config.agent.command_output_max_chars,
        pack_loader=pack_loader,
    )

    # Runtime environment profile (OS/shell/command availability)
    env_report_path = environment_profile_path()
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
    # Engram Store
    engram_store = EngramStore()

    def _create_agent(manager: LLMManager) -> Agent:
        return Agent(
            llm=None,
            llm_manager=manager,
            sandbox=sandbox,
            config=config.agent,
            runtime_environment_context=runtime_environment_context,
            user_context_ledger=user_context_ledger,
            engram_store=engram_store,
        )

    agent = _create_agent(llm_manager) if llm_manager is not None else None
    bot = None
    sentinel_scheduler = None

    async def _apply_llm_profile_config(new_config, action: str) -> None:
        nonlocal llm_manager, agent, capabilities
        if action in {"switched", "updated"}:
            candidate_manager = LLMManager(
                new_config.ai_profiles,
                new_config.active_ai_profile,
            )
            await candidate_manager.validate_profile_ready(new_config.active_ai_profile)
        if new_config.llm_configured:
            if llm_manager is None:
                llm_manager = LLMManager(
                    new_config.ai_profiles,
                    new_config.active_ai_profile,
                )
                agent = _create_agent(llm_manager)
                if sentinel_scheduler is not None:
                    agent.set_sentinel(sentinel_scheduler)
                agent.start()
            else:
                await llm_manager.reload_profiles(
                    new_config.ai_profiles,
                    new_config.active_ai_profile,
                )
        elif agent is not None:
            await agent.stop()
            agent = None
            llm_manager = None
        config.active_ai_profile = new_config.active_ai_profile
        config.ai_profiles = new_config.ai_profiles
        if bot is not None:
            bot.agent = agent
            bot.llm_manager = llm_manager
        capabilities = capabilities.with_state(
            "llm",
            "ready" if new_config.llm_configured else "not_configured",
        )
        write_runtime_status(READY_PATH, capabilities)

    def _record_profile_audit(event_type: str, actor: ProfileActor, fields: dict) -> None:
        CommandAuditTracker.record_event(
            event_type,
            chat_id=actor.chat_id,
            source=actor.source,
            user_id=actor.user_id,
            **fields,
        )

    profile_admin = LLMProfileAdminService(
        ProfileConfigStore(
            runtime_config_path,
            llm_profile_lock_path(),
            template_path=default_config_template_path(),
        ),
        runtime_apply=_apply_llm_profile_config,
        audit_recorder=_record_profile_audit,
    )

    # Telegram Bot
    if config.telegram_configured:
        bot = TelegramBot(
            config=config,
            agent=agent,
            profile_admin=profile_admin,
            llm_manager=llm_manager,
        )

    def _create_sentinel_scheduler(sentinel_config):
        from chatdome.sentinel.scheduler import SentinelScheduler

        alert_targets = config.telegram_alert_user_ids
        if alert_targets:
            logger.info("  Sentinel alert targets: %s", alert_targets)
        else:
            logger.warning(
                "  Sentinel is enabled but no Telegram alert users are configured. "
                "Set Telegram allowed_ids or Sentinel alert_targets to receive pushes."
            )

        return SentinelScheduler(
            config=sentinel_config,
            pack_loader=pack_loader,
            sandbox=sandbox,
            send_alert_fn=(bot.send_alert if bot is not None else discard_platform_delivery),
            alert_chat_ids=alert_targets,
            user_context_ledger=user_context_ledger,
        )

    # Sentinel Scheduler (optional)
    if config.sentinel.enabled:
        sentinel_scheduler = _create_sentinel_scheduler(config.sentinel)

        if bot is not None:
            bot.set_sentinel(sentinel_scheduler, pack_loader)
        if agent is not None:
            agent.set_sentinel(sentinel_scheduler)
        logger.info(
            "  Sentinel: ENABLED (%d checks, push>=%d, state-machine mode)",
            len(sentinel_scheduler.checks),
            config.sentinel.push_min_severity,
        )
    else:
        if bot is not None:
            bot.set_sentinel(None, pack_loader)
        logger.info("  Sentinel: disabled")

    capabilities = RuntimeCapabilities.from_config(config)
    if config.llm_configured and llm_manager is None:
        capabilities = capabilities.with_state(
            "llm", "degraded", "模型组件初始化失败，请检查服务日志。"
        )
    app = None
    reload_control = ReloadControl()
    reload_task: asyncio.Task | None = None

    def _agent_system_prompt() -> str:
        return build_system_prompt(
            runtime_environment_context=runtime_environment_context,
        )

    def _refresh_agent_runtime() -> None:
        sandbox.default_timeout = config.agent.command_timeout
        sandbox.max_output_chars = config.agent.max_output_chars
        sandbox.persist_command_outputs = config.agent.persist_command_outputs
        sandbox.command_output_retention_days = max(
            1,
            int(config.agent.command_output_retention_days),
        )
        sandbox.command_output_max_chars = max(1, int(config.agent.command_output_max_chars))
        if agent is None:
            return

        agent.config = config.agent
        agent.tools = build_tools()
        agent.session_manager.session_timeout = config.agent.session_timeout
        agent.session_manager.pending_approval_timeout = config.agent.pending_approval_timeout
        agent.session_manager.persisted_session_ttl = config.agent.persisted_session_ttl
        agent.session_manager.max_history_tokens = config.agent.max_history_tokens
        agent.session_manager.system_prompt = _agent_system_prompt()
        agent.tool_dispatcher.command_approval_mode = config.agent.command_approval_mode

        sessions = getattr(agent.session_manager, "_sessions", {})
        for session in list(sessions.values()):
            try:
                session.add_system_message(
                    agent.session_manager._build_memory_prompt(session.chat_id)
                )
                agent.session_manager.save_session(session)
            except Exception:
                logger.exception("Failed to refresh active session prompt")

    async def _reload_sentinel_runtime() -> None:
        nonlocal sentinel_scheduler, capabilities
        old_scheduler = sentinel_scheduler
        if old_scheduler is not None and hasattr(old_scheduler, "stop_gracefully"):
            await old_scheduler.stop_gracefully()

        pack_loader.load()
        if config.sentinel.enabled:
            sentinel_scheduler = _create_sentinel_scheduler(config.sentinel)
            if bot is not None:
                bot.set_sentinel(sentinel_scheduler, pack_loader)
            if agent is not None:
                agent.set_sentinel(sentinel_scheduler)
            sentinel_scheduler.start()
            logger.info(
                "Sentinel hot-reloaded: enabled (%d checks, push>=%d)",
                len(sentinel_scheduler.checks),
                config.sentinel.push_min_severity,
            )
        else:
            sentinel_scheduler = None
            if bot is not None:
                bot.set_sentinel(None, pack_loader)
            if agent is not None:
                agent.set_sentinel(None)
            logger.info("Sentinel hot-reloaded: disabled")
        capabilities = capabilities.with_state(
            "sentinel",
            "ready" if config.sentinel.enabled else "disabled",
        )
        write_runtime_status(READY_PATH, capabilities)

    async def _apply_reload_request(domains: list[str], config_path: str = "") -> list[str]:
        requested = set(domains)
        if "all" in requested:
            requested = {"llm", "sentinel", "agent"}

        new_config = load_config(config_path or runtime_config_path)
        applied: list[str] = []

        if "llm" in requested:
            await _apply_llm_profile_config(new_config, "reload")
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

    async def _run_service() -> None:
        nonlocal reload_task, capabilities, app
        stop_event = asyncio.Event()
        loop = asyncio.get_running_loop()
        for stop_signal in (signal.SIGINT, signal.SIGTERM):
            with contextlib.suppress(NotImplementedError, RuntimeError, ValueError):
                loop.add_signal_handler(stop_signal, stop_event.set)

        telegram_initialized = False
        telegram_started = False
        polling_started = False
        if agent is not None:
            agent.start()
        if sentinel_scheduler is not None:
            sentinel_scheduler.start()
        reload_task = asyncio.create_task(_reload_watch_loop())

        if bot is not None:
            logger.info("Starting Telegram bot polling...")
            try:
                app = await build_telegram_application(bot)
                await app.initialize()
                telegram_initialized = True
                if app.updater is None:
                    raise RuntimeError("Telegram updater is unavailable")
                await app.updater.start_polling(drop_pending_updates=True)
                polling_started = True
                await app.start()
                telegram_started = True
                await bot.post_init(app)
            except Exception as exc:
                capabilities = capabilities.with_state(
                    "telegram", "degraded", str(exc)
                )
                logger.exception("Telegram component degraded")
        else:
            logger.info("Telegram component: %s", capabilities.telegram.state)

        write_runtime_status(READY_PATH, capabilities)
        logger.info("ChatDome core service ready")
        try:
            await stop_event.wait()
        finally:
            if bot is not None and telegram_initialized:
                with contextlib.suppress(Exception):
                    await bot.post_stop(app)
            if polling_started and app is not None and app.updater is not None:
                with contextlib.suppress(Exception):
                    await app.updater.stop()
            if telegram_started and app is not None:
                with contextlib.suppress(Exception):
                    await app.stop()
            if telegram_initialized and app is not None:
                with contextlib.suppress(Exception):
                    await app.shutdown()
            if reload_task is not None:
                reload_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await reload_task
                reload_task = None
            if sentinel_scheduler is not None:
                with contextlib.suppress(Exception):
                    await sentinel_scheduler.stop_gracefully()
            if agent is not None:
                with contextlib.suppress(Exception):
                    await agent.stop()

    # ── Run ──
    try:
        _write_pid_file()
        asyncio.run(_run_service())
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        READY_PATH.unlink(missing_ok=True)
        _remove_pid_file()
        instance_lock.release()
        logger.info("ChatDome stopped.")


if __name__ == "__main__":
    main()
