"""
Sentinel Scheduler — async pipeline orchestrator.

Runs check definitions on their configured intervals using
a single ``asyncio.Task``.  Implements cold-start protection
and coordinates evaluator → suppressor → alerter flow.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Coroutine

from chatdome.config import SentinelConfig
from chatdome.executor.sandbox import CommandSandbox
from chatdome.sentinel.alerter import AlertEvent, AlertHistory, format_alert_message
from chatdome.sentinel.checks import CheckDefinition, load_checks, severity_label
from chatdome.sentinel.evaluator import EvalResult, evaluate
from chatdome.sentinel.pack_loader import PackLoader
from chatdome.sentinel.suppressor import SuppressionResult, Suppressor
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
        # Differential mode baselines: check_key -> normalized output lines
        self._diff_baselines: dict[str, set[str]] = {}
        self._baseline_notes: list[str] = []
        self._baseline_report_sent = False

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
                            result_text = await self._run_single_check(check)
                            checks_executed += 1
                            if (
                                self._round_count == 0
                                and result_text.startswith("ℹ️ ")
                                and "已建立差异基线" in result_text
                            ):
                                note = f"- {result_text[3:]}"
                                if note not in self._baseline_notes:
                                    self._baseline_notes.append(note)
                        except Exception:
                            logger.exception("Check failed: %s", check.name)

                        check_timers[key] = now + check.interval

                # Mark round complete if all checks were executed
                if checks_executed > 0 and checks_executed >= len(self._checks):
                    self._round_count += 1
                    self._suppressor.complete_round()
                    if self._round_count == 1:
                        await self._send_baseline_summary_if_needed()

                await asyncio.sleep(tick_interval)

        except asyncio.CancelledError:
            logger.info("Sentinel scheduler task cancelled")
        except Exception:
            logger.exception("Sentinel scheduler crashed")

    # -- Single Check Execution --------------------------------------------

    @staticmethod
    def _canonicalize_diff_line(check_key: str, line: str) -> str:
        """
        Canonicalize a differential line to suppress noisy fields.

        - ssh_bruteforce: keep only source IP (drop changing count prefix)
        - open_ports: keep local listen endpoint (drop queue/process noise)
        """
        text = line.strip()
        if not text:
            return ""

        if check_key == "ssh_bruteforce":
            # Example: "123 1.2.3.4" -> "1.2.3.4"
            m = re.match(r"^\s*\d+\s+(\S+)\s*$", text)
            if m:
                return m.group(1)
            parts = text.split()
            return parts[-1] if parts else ""

        if check_key == "open_ports":
            # Extract first host:port-like endpoint (e.g. 0.0.0.0:22 / [::]:443).
            for token in text.split():
                if token.endswith(":*"):
                    continue
                if re.search(r":\d+$", token):
                    return token
            return text

        return text

    def _normalize_lines(self, check_key: str, output: str) -> set[str]:
        """Normalize output into a unique canonical line set for differential mode."""
        normalized: set[str] = set()
        for raw in (output or "").splitlines():
            line = self._canonicalize_diff_line(check_key, raw)
            if line:
                normalized.add(line)
        return normalized

    def _diff_baseline(
        self,
        check_key: str,
        output: str,
    ) -> tuple[set[str], set[str], bool, int]:
        """
        Compare output against baseline and update baseline.

        Returns:
            added_lines, removed_lines, baseline_initialized, current_size
        """
        current_lines = self._normalize_lines(check_key, output)
        previous_lines = self._diff_baselines.get(check_key)

        if previous_lines is None:
            self._diff_baselines[check_key] = current_lines
            return set(), set(), True, len(current_lines)

        added_lines = current_lines - previous_lines
        removed_lines = previous_lines - current_lines
        self._diff_baselines[check_key] = current_lines

        logger.debug(
            "Differential check %s delta: +%d -%d",
            check_key,
            len(added_lines),
            len(removed_lines),
        )
        return added_lines, removed_lines, False, len(current_lines)

    @staticmethod
    def _build_diff_payload(
        added_lines: set[str],
        removed_lines: set[str],
        max_items: int = 80,
    ) -> str:
        """Format differential delta payload for alerts."""
        added = sorted(added_lines)
        removed = sorted(removed_lines)
        lines = [f"变化摘要: 新增 {len(added)}，减少 {len(removed)}"]

        if added:
            lines.append("")
            lines.append("新增项:")
            for item in added[:max_items]:
                lines.append(f"+ {item}")
            if len(added) > max_items:
                lines.append(f"... (+{len(added) - max_items} more)")

        if removed:
            lines.append("")
            lines.append("减少项:")
            for item in removed[:max_items]:
                lines.append(f"- {item}")
            if len(removed) > max_items:
                lines.append(f"... (+{len(removed) - max_items} more)")

        return "\n".join(lines)

    @staticmethod
    def _build_rule_summary(check: CheckDefinition, eval_description: str) -> str:
        """Generate a user-facing rule summary that is easy to understand."""
        if check.rule is None:
            return "无规则"

        if check.mode == "differential" and check.rule.type in {"line_count", "added_count"}:
            return f"匹配行数 {check.rule.operator} {check.rule.threshold:g}（仅基线变化时告警）"

        if check.rule.type == "line_count":
            return f"匹配行数 {check.rule.operator} {check.rule.threshold:g}"

        return eval_description

    @staticmethod
    def _build_rule_summary_runtime(check: CheckDefinition, eval_description: str) -> str:
        """Build runtime-facing rule summaries with explicit differential semantics."""
        if check.rule is None:
            return "no rule"

        if check.mode == "differential" and check.rule.type == "added_count":
            return f"added items {check.rule.operator} {check.rule.threshold:g} (differential mode)"

        if check.mode == "differential" and check.rule.type == "line_count":
            return f"line count {check.rule.operator} {check.rule.threshold:g} (alert on baseline delta)"

        if check.rule.type == "line_count":
            return f"line count {check.rule.operator} {check.rule.threshold:g}"

        return eval_description

    async def _send_baseline_summary_if_needed(self) -> None:
        """Send one startup baseline summary after the first full round."""
        if self._baseline_report_sent or not self._baseline_notes:
            return

        lines = [
            "🛡️ Sentinel 基线采集完成",
            "",
            "已建立以下差异基线：",
        ]
        lines.extend(self._baseline_notes[:20])
        if len(self._baseline_notes) > 20:
            lines.append(f"... (+{len(self._baseline_notes) - 20} more)")
        lines.extend(
            [
                "",
                "后续将仅在与基线相比出现变化时告警，告警只展示变化项。",
            ]
        )
        summary = "\n".join(lines)

        for chat_id in self._alert_chat_ids:
            try:
                await self._send_alert(chat_id, summary)
            except Exception:
                logger.exception("Failed to send baseline summary to chat %s", chat_id)

        self._baseline_report_sent = True

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

        stderr_text = (result.stderr or "").strip()
        if result.return_code is None and stderr_text:
            logger.warning("Check %s failed before completion: %s", check.name, stderr_text)
            return f"❌ {check.name}: 执行失败"

        if result.return_code is not None and result.return_code != 0:
            logger.warning("Check %s failed (code=%s): %s", check.name, result.return_code, stderr_text)
            return f"❌ {check.name}: 执行失败"

        output = result.stdout or ""
        alert_output = output
        added_lines: set[str] = set()
        removed_lines: set[str] = set()
        if check.mode == "differential":
            added_lines, removed_lines, baseline_initialized, baseline_size = self._diff_baseline(
                check_key=check_key,
                output=output,
            )
            if baseline_initialized:
                logger.info(
                    "Differential baseline initialized for %s (%d entries)",
                    check.name,
                    baseline_size,
                )
                return f"ℹ️ {check.name}: 已建立差异基线 ({baseline_size} 条)"

        # Step 2: Evaluate rule
        if check.rule is None:
            # No rule → informational only
            return f"ℹ️ {check.name}: 已执行 (无规则)"

        # Differential strategy:
        # - ssh_bruteforce: alert only when NEW source IPs appear.
        # - added_count rules: evaluate against added delta lines.
        # - others: evaluate against the full snapshot output.
        if check.mode == "differential" and check_key == "ssh_bruteforce":
            added_ip_count = len(added_lines)
            eval_result = EvalResult(
                triggered=added_ip_count > 0,
                current_value=added_ip_count,
                description="new ssh source ip count > 0",
            )
            rule_summary = "new ssh source ip > 0 (added-only differential alert)"
        elif check.mode == "differential" and check.rule.type == "added_count":
            added_output = "\n".join(sorted(added_lines))
            eval_result = evaluate(check.rule, added_output)
            rule_summary = self._build_rule_summary_runtime(check, eval_result.description)
        else:
            eval_result = evaluate(check.rule, output)
            rule_summary = self._build_rule_summary_runtime(check, eval_result.description)

        if not eval_result.triggered:
            return f"✅ {check.name}: 正常 (当前值={eval_result.current_value}, 规则={rule_summary})"

        if check.mode == "differential" and check_key == "ssh_bruteforce":
            if not added_lines:
                return (
                    f"✅ {check.name}: anomaly persists but no new ssh source ip "
                    f"(value={eval_result.current_value}, rule={rule_summary})"
                )
            # SSH differential policy: alert on newly seen source IPs only.
            removed_lines = set()

        if check.mode == "differential" and check_key != "ssh_bruteforce":
            if not added_lines and not removed_lines:
                return f"✅ {check.name}: 异常持续但无变化 (当前值={eval_result.current_value}, 规则={rule_summary})"
            alert_output = self._build_diff_payload(added_lines, removed_lines)

        # Step 2.5: Verify User Context Ledger
        ledger_payload = alert_output or output
        override_reason = self._ledger.is_exempt(check_key, ledger_payload)
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
            mode=check.mode,
            severity=check.severity,
            severity_label=label,
            rule=rule_summary,
            current_value=eval_result.current_value,
            raw_output=(alert_output or output)[:2000],  # Truncate for storage
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
