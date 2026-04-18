"""
Sentinel Scheduler — async pipeline orchestrator.

Runs check definitions on their configured intervals using
a single ``asyncio.Task``.  Implements cold-start protection
and coordinates evaluator → suppressor → alerter flow.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Coroutine

from chatdome.config import SentinelConfig
from chatdome.executor.sandbox import CommandSandbox
from chatdome.sentinel.alerter import AlertEvent, AlertHistory, format_alert_message
from chatdome.sentinel.checks import CheckDefinition, load_checks, severity_label
from chatdome.sentinel.evaluator import evaluate
from chatdome.sentinel.pack_loader import PackLoader
from chatdome.sentinel.suppressor import Suppressor
from chatdome.sentinel.user_context import UserContextLedger

logger = logging.getLogger(__name__)


class SentinelScheduler:
    """
    Orchestrates the Sentinel SOC pipeline.

    Pipeline per check:
      1. Execute command (via PackLoader + sandbox)
      2. Evaluate rule (Evaluator)
      3. Suppress / rate-limit (Suppressor)
      4. Format + push alert (Alerter)
      5. Record to history
    """

    def __init__(
        self,
        config: SentinelConfig,
        pack_loader: PackLoader,
        sandbox: CommandSandbox,
        send_alert_fn: Callable[[int, str], Coroutine[Any, Any, None]],
        alert_chat_ids: list[int] | None = None,
        user_context_ledger: UserContextLedger | None = None,
    ) -> None:
        self._config = config
        self._pack_loader = pack_loader
        self._sandbox = sandbox
        self._send_alert = send_alert_fn
        self._alert_chat_ids = alert_chat_ids or []
        self._ledger = user_context_ledger or UserContextLedger()

        # Load check definitions
        self._checks = load_checks(config.checks)

        # Initialize sub-components
        self._suppressor = Suppressor(
            push_min_severity=config.push_min_severity,
            default_cooldown=config.default_cooldown,
            global_rate_limit=config.global_rate_limit,
            global_rate_window=config.global_rate_window,
            learning_rounds=config.learning_rounds,
        )

        # Register per-check cooldown overrides
        for check in self._checks:
            if check.cooldown is not None:
                check_key = check.check_id or check.name
                self._suppressor.set_cooldown(check_key, check.cooldown)

        self._history = AlertHistory(
            alerts_path=Path("chat_data/sentinel_alerts.jsonl"),
        )

        # Runtime state
        self._task: asyncio.Task | None = None
        self._running = False
        self._round_count = 0

    # -- Public API --------------------------------------------------------

    @property
    def history(self) -> AlertHistory:
        return self._history

    @property
    def suppressor(self) -> Suppressor:
        return self._suppressor

    @property
    def checks(self) -> list[CheckDefinition]:
        return self._checks

    @property
    def is_running(self) -> bool:
        return self._running

    def start(self) -> None:
        """Start the scheduler background task."""
        if self._task is not None and not self._task.done():
            logger.warning("Sentinel scheduler already running")
            return

        if not self._checks:
            logger.warning("No Sentinel checks configured, not starting scheduler")
            return

        self._running = True
        self._task = asyncio.ensure_future(self._run_loop())
        logger.info(
            "🛡️ Sentinel scheduler started (%d checks, learning=%s)",
            len(self._checks),
            self._suppressor.is_learning,
        )

    def stop(self) -> None:
        """Stop the scheduler."""
        self._running = False
        if self._task is not None:
            self._task.cancel()
            self._task = None
        logger.info("Sentinel scheduler stopped")

    async def trigger_all(self) -> str:
        """Manually trigger all checks immediately. Returns summary text."""
        results: list[str] = []
        for check in self._checks:
            try:
                result = await self._run_single_check(check)
                results.append(result)
            except Exception as e:
                results.append(f"❌ {check.name}: {e}")
        return "\n".join(results) if results else "无检查项配置"

    # -- Main Loop ---------------------------------------------------------

    async def _run_loop(self) -> None:
        """Main scheduling loop."""
        # Track next execution time for each check
        check_timers: dict[str, float] = {}
        for check in self._checks:
            key = check.check_id or check.name
            check_timers[key] = 0  # Run immediately on first cycle

        tick_interval = 10  # Check every 10 seconds

        # Log cold-start status
        if self._suppressor.is_learning:
            logger.info("🛡️ Sentinel 正在学习基线 (前 %d 轮静默)...", self._config.learning_rounds)
            for chat_id in self._alert_chat_ids:
                try:
                    await self._send_alert(chat_id, "🛡️ Sentinel 正在学习基线，暂不推送告警...")
                except Exception:
                    logger.exception("Failed to send cold-start notification")

        try:
            while self._running:
                now = time.monotonic()
                checks_executed = 0

                for check in self._checks:
                    key = check.check_id or check.name
                    next_run = check_timers.get(key, 0)

                    if now >= next_run:
                        try:
                            await self._run_single_check(check)
                            checks_executed += 1
                        except Exception:
                            logger.exception("Check failed: %s", check.name)

                        check_timers[key] = now + check.interval

                # Mark round complete if all checks were executed
                if checks_executed > 0 and checks_executed >= len(self._checks):
                    self._round_count += 1
                    self._suppressor.complete_round()

                await asyncio.sleep(tick_interval)

        except asyncio.CancelledError:
            logger.info("Sentinel scheduler task cancelled")
        except Exception:
            logger.exception("Sentinel scheduler crashed")

    # -- Single Check Execution --------------------------------------------

    async def _run_single_check(self, check: CheckDefinition) -> str:
        """Execute a single check through the full pipeline."""
        check_key = check.check_id or check.name

        # Step 1: Execute command
        if check.check_id is None:
            # AI mode — skip for Phase 1
            return f"⏭️ {check.name}: AI 模式 (Phase 2)"

        result = await self._sandbox.execute_security_check(
            check_id=check.check_id,
            args=check.args or None,
        )

        if result.timed_out:
            logger.warning("Check %s timed out", check.name)
            return f"⏱️ {check.name}: 超时"

        if result.return_code is not None and result.return_code != 0 and not result.stdout:
            logger.warning("Check %s failed: %s", check.name, result.stderr)
            return f"❌ {check.name}: 执行失败"

        output = result.stdout or ""

        # Step 2: Evaluate rule
        if check.rule is None:
            # No rule → informational only
            return f"ℹ️ {check.name}: 已执行 (无规则)"

        eval_result = evaluate(check.rule, output)

        if not eval_result.triggered:
            return f"✅ {check.name}: 正常 ({eval_result.description})"

        # Step 2.5: Verify User Context Ledger
        override_reason = self._ledger.is_exempt(check_key, output)
        if override_reason:
            # Re-route the alert into the exact suppression format used for natural suppression
            suppression = SuppressionResult(suppressed=True, reason=f"user_override: {override_reason}")
            # Ensure it skips the standard suppressor cooldown loop
        else:
            # Step 3: Alert triggered → check suppression
            suppression = self._suppressor.should_push(
                check_id=check_key,
                severity=check.severity,
                cooldown_override=check.cooldown,
            )

        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        label = severity_label(check.severity)

        # Step 4: Record to history
        event = AlertEvent(
            timestamp=now_str,
            check_name=check.name,
            check_id=check_key,
            severity=check.severity,
            severity_label=label,
            rule=eval_result.description,
            current_value=eval_result.current_value,
            raw_output=output[:2000],  # Truncate for storage
            pushed=not suppression.suppressed,
            suppressed=suppression.suppressed,
            suppression_reason=suppression.reason,
        )
        self._history.record(event)

        # Step 5: Push if not suppressed
        if not suppression.suppressed:
            message = format_alert_message(event)
            for chat_id in self._alert_chat_ids:
                try:
                    await self._send_alert(chat_id, message)
                except Exception:
                    logger.exception("Failed to push alert to chat %s", chat_id)

            return f"🚨 {check.name}: 已推送告警 (severity={check.severity})"
        else:
            logger.debug(
                "Alert suppressed for %s: %s",
                check.name, suppression.reason,
            )
            return f"🔇 {check.name}: 告警已抑制 ({suppression.reason})"
