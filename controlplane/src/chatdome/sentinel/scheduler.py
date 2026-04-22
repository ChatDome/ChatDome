"""
Sentinel Scheduler: async pipeline orchestrator.

Runs configured checks on intervals and routes results through:
execute -> evaluate -> suppress/state-machine -> history/push.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import time
from datetime import datetime
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
    """Orchestrates the Sentinel SOC pipeline."""

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

        self._checks = load_checks(config.checks)
        self._suppressor = Suppressor(
            global_rate_limit=config.global_rate_limit,
            global_rate_window=config.global_rate_window,
            learning_rounds=config.learning_rounds,
        )
        self._history = AlertHistory(
            alerts_path=Path("chat_data/sentinel_alerts.jsonl"),
            retention_days=config.alert_retention_days,
        )

        self._task: asyncio.Task | None = None
        self._running = False
        self._round_count = 0

        # Differential baselines: check_key -> normalized line set
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
        if self._task is not None and not self._task.done():
            logger.warning("Sentinel scheduler already running")
            return
        if not self._checks:
            logger.warning("No Sentinel checks configured, not starting scheduler")
            return

        self._running = True
        self._task = asyncio.ensure_future(self._run_loop())
        logger.info(
            "Sentinel scheduler started (%d checks, learning=%s)",
            len(self._checks),
            self._suppressor.is_learning,
        )

    def stop(self) -> None:
        self._running = False
        if self._task is not None:
            self._task.cancel()
            self._task = None
        logger.info("Sentinel scheduler stopped")

    async def trigger_all(self) -> str:
        results: list[str] = []
        for check in self._checks:
            try:
                results.append(await self._run_single_check(check))
            except Exception as exc:
                results.append(f"❌ {check.name}: {exc}")
        return "\n".join(results) if results else "No checks configured"

    # -- Loop --------------------------------------------------------------

    async def _run_loop(self) -> None:
        check_timers: dict[str, float] = {}
        for check in self._checks:
            check_timers[check.check_id or check.name] = 0.0
        checks_seen_in_round: set[str] = set()

        tick_interval = 10

        if self._suppressor.is_learning:
            logger.info("Sentinel cold-start learning (%d rounds)", self._config.learning_rounds)
            for chat_id in self._alert_chat_ids:
                try:
                    await self._send_alert(chat_id, "Sentinel is learning baseline. Alerts are muted temporarily.")
                except Exception:
                    logger.exception("Failed to send cold-start notification")

        try:
            while self._running:
                now = time.monotonic()

                for check in self._checks:
                    key = check.check_id or check.name
                    if now < check_timers.get(key, 0.0):
                        continue

                    try:
                        result_text = await self._run_single_check(check)
                        if self._round_count == 0 and result_text.startswith("BASELINE_INIT:"):
                            note = f"- {result_text[len('BASELINE_INIT: '):]}"
                            if note not in self._baseline_notes:
                                self._baseline_notes.append(note)
                    except Exception:
                        logger.exception("Check failed: %s", check.name)

                    check_timers[key] = now + check.interval
                    # Count this check as seen even when execution fails, to avoid
                    # getting stuck in cold-start forever due to one bad check.
                    checks_seen_in_round.add(key)

                if len(checks_seen_in_round) >= len(self._checks):
                    self._round_count += 1
                    self._suppressor.complete_round()
                    if self._round_count == 1:
                        await self._send_baseline_summary_if_needed()
                    checks_seen_in_round.clear()

                await asyncio.sleep(tick_interval)

        except asyncio.CancelledError:
            logger.info("Sentinel scheduler task cancelled")
        except Exception:
            logger.exception("Sentinel scheduler crashed")

    # -- Differential helpers ---------------------------------------------

    @staticmethod
    def _canonicalize_diff_line(check_key: str, line: str) -> str:
        text = line.strip()
        if not text:
            return ""

        if check_key == "ssh_bruteforce":
            m = re.match(r"^\s*\d+\s+(\S+)\s*$", text)
            if m:
                return m.group(1)
            parts = text.split()
            return parts[-1] if parts else ""

        if check_key == "open_ports":
            endpoint = ""
            for token in text.split():
                if token.endswith(":*"):
                    continue
                if re.search(r":\d+$", token):
                    endpoint = token
                    break
            if not endpoint:
                return ""

            owners = SentinelScheduler._extract_port_owners(text)
            if not owners:
                return f"{endpoint} (unknown:unknown)"
            return f"{endpoint} ({','.join(owners)})"

        return text

    @staticmethod
    def _extract_port_owners(line: str) -> list[str]:
        owners: set[tuple[str, str]] = set()

        for name, pid in re.findall(r'"([^"]+)"\s*,pid=(\d+)', line):
            n = (name or "").strip()
            p = (pid or "").strip()
            if n and p:
                owners.add((n, p))

        for pid, name in re.findall(r"\b(\d+)/([^\s/]+)\b", line):
            n = (name or "").strip()
            p = (pid or "").strip()
            if n and p and n != "-" and p != "-":
                owners.add((n, p))

        return [f"{name}:{pid}" for name, pid in sorted(owners)]

    def _normalize_lines(self, check_key: str, output: str) -> set[str]:
        normalized: set[str] = set()
        for raw in (output or "").splitlines():
            line = self._canonicalize_diff_line(check_key, raw)
            if line:
                normalized.add(line)
        return normalized

    def _diff_baseline(self, check_key: str, output: str) -> tuple[set[str], set[str], bool, int]:
        current_lines = self._normalize_lines(check_key, output)
        previous_lines = self._diff_baselines.get(check_key)

        if previous_lines is None:
            self._diff_baselines[check_key] = current_lines
            return set(), set(), True, len(current_lines)

        added_lines = current_lines - previous_lines
        removed_lines = previous_lines - current_lines
        self._diff_baselines[check_key] = current_lines
        return added_lines, removed_lines, False, len(current_lines)

    @staticmethod
    def _build_diff_payload(added_lines: set[str], removed_lines: set[str], max_items: int = 80) -> str:
        added = sorted(added_lines)
        removed = sorted(removed_lines)
        lines = [f"delta: +{len(added)} / -{len(removed)}"]

        if added:
            lines.append("")
            lines.append("added:")
            for item in added[:max_items]:
                lines.append(f"+ {item}")
            if len(added) > max_items:
                lines.append(f"... (+{len(added) - max_items} more)")

        if removed:
            lines.append("")
            lines.append("removed:")
            for item in removed[:max_items]:
                lines.append(f"- {item}")
            if len(removed) > max_items:
                lines.append(f"... (+{len(removed) - max_items} more)")

        return "\n".join(lines)

    @staticmethod
    def _build_rule_summary_runtime(check: CheckDefinition, eval_description: str) -> str:
        if check.rule is None:
            return "no rule"
        if check.mode == "differential" and check.rule.type == "added_count":
            return f"added items {check.rule.operator} {check.rule.threshold:g} (differential mode)"
        if check.mode == "differential" and check.rule.type == "line_count":
            return f"line count {check.rule.operator} {check.rule.threshold:g} (alert on baseline delta)"
        if check.rule.type == "line_count":
            return f"line count {check.rule.operator} {check.rule.threshold:g}"
        return eval_description

    # -- Fingerprints ------------------------------------------------------

    @staticmethod
    def _safe_ip(value: str) -> str:
        try:
            return str(ipaddress.ip_address(value.strip()))
        except ValueError:
            return ""

    @staticmethod
    def _extract_first_ip(text: str) -> str:
        for token in re.findall(r"[0-9a-fA-F:.]+", text):
            ip_value = SentinelScheduler._safe_ip(token)
            if ip_value:
                return ip_value
        return ""

    @staticmethod
    def _extract_user(text: str) -> str:
        m = re.search(r"\bfor\s+([a-zA-Z0-9_.-]+)\b", text)
        return m.group(1) if m else "unknown"

    @staticmethod
    def _extract_ssh_port(text: str) -> str:
        m = re.search(r"\bport\s+(\d+)\b", text)
        return m.group(1) if m else "22"

    def _build_fingerprints(self, *, check_key: str, alert_output: str, now: datetime) -> set[str]:
        lines = [x.strip() for x in (alert_output or "").splitlines() if x.strip()]
        fps: set[str] = set()

        if check_key == "ssh_bruteforce":
            for line in lines:
                ip_value = self._extract_first_ip(line)
                if ip_value:
                    fps.add(f"{ip_value}|22|unknown|failed")
            return fps

        if check_key == "ssh_failed_burst":
            bucket = now.strftime("%Y-%m-%dT%H:%M")
            for line in lines:
                ip_value = self._extract_first_ip(line)
                if ip_value:
                    fps.add(f"{ip_value}|{bucket}")
            return fps

        if check_key == "ssh_success_login":
            for line in lines:
                ip_value = self._extract_first_ip(line)
                if not ip_value:
                    continue
                user = self._extract_user(line)
                port = self._extract_ssh_port(line)
                fps.add(f"{ip_value}|{user}|{port}")
            return fps

        if check_key == "open_ports":
            for line in lines:
                cleaned = line[1:].strip() if line[:1] in {"+", "-"} else line
                endpoint_match = re.search(r"([0-9a-fA-F*.:]+):(\d+)", cleaned)
                if not endpoint_match:
                    continue
                listen_ip = endpoint_match.group(1)
                port = endpoint_match.group(2)
                owner_match = re.search(r"\(([^:(),]+):(\d+)\)", cleaned)
                if owner_match:
                    process_name = owner_match.group(1).strip()
                    pid = owner_match.group(2).strip()
                else:
                    process_name = "unknown"
                    pid = "unknown"
                fps.add(f"{listen_ip}|{port}|{pid}|{process_name}")
            return fps

        if check_key == "disk_usage":
            for line in lines:
                if "%" not in line:
                    continue
                parts = line.split()
                if parts:
                    fps.add(parts[-1])
            return fps

        for line in lines:
            fps.add(line)
        return fps

    # -- Alert recording ---------------------------------------------------

    async def _record_and_maybe_push(self, event: AlertEvent) -> bool:
        self._history.record(event)
        if event.suppressed:
            return False

        message = format_alert_message(event)
        for chat_id in self._alert_chat_ids:
            try:
                await self._send_alert(chat_id, message)
            except Exception:
                logger.exception("Failed to push alert to chat %s", chat_id)
        return True

    async def _send_baseline_summary_if_needed(self) -> None:
        if self._baseline_report_sent or not self._baseline_notes:
            return

        lines = [
            "Sentinel baseline collection completed",
            "",
            "Differential baselines initialized:",
        ]
        lines.extend(self._baseline_notes[:20])
        if len(self._baseline_notes) > 20:
            lines.append(f"... (+{len(self._baseline_notes) - 20} more)")
        lines.extend(["", "Future differential alerts are sent only when baseline deltas appear."])
        summary = "\n".join(lines)

        for chat_id in self._alert_chat_ids:
            try:
                await self._send_alert(chat_id, summary)
            except Exception:
                logger.exception("Failed to send baseline summary to chat %s", chat_id)

        self._baseline_report_sent = True

    # -- Single check ------------------------------------------------------

    async def _run_single_check(self, check: CheckDefinition) -> str:
        check_key = check.check_id or check.name

        if check.check_id is None:
            return f"⏭️ {check.name}: AI mode (Phase 2)"

        result = await self._sandbox.execute_security_check(
            check_id=check.check_id,
            args=check.args or None,
        )

        if result.timed_out:
            logger.warning("Check %s timed out", check.name)
            return f"⏱️ {check.name}: timed out"

        stderr_text = (result.stderr or "").strip()
        if result.return_code is None and stderr_text:
            logger.warning("Check %s failed before completion: %s", check.name, stderr_text)
            return f"❌ {check.name}: execution failed"

        if result.return_code is not None and result.return_code != 0:
            logger.warning("Check %s failed (code=%s): %s", check.name, result.return_code, stderr_text)
            return f"❌ {check.name}: execution failed"

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
                logger.info("Differential baseline initialized for %s (%d entries)", check.name, baseline_size)
                return f"BASELINE_INIT: {check.name}: differential baseline initialized ({baseline_size} entries)"

        if check.rule is None:
            return f"ℹ️ {check.name}: executed (no rule)"

        if check.mode == "differential" and check_key in {"ssh_bruteforce", "ssh_success_login"}:
            added_count = len(added_lines)
            eval_result = EvalResult(
                triggered=added_count > 0,
                current_value=added_count,
                description=(
                    "new ssh source ip count > 0"
                    if check_key == "ssh_bruteforce"
                    else "new ssh successful login entry count > 0"
                ),
            )
            rule_summary = (
                "new ssh source ip > 0 (added-only differential alert)"
                if check_key == "ssh_bruteforce"
                else "new ssh successful login entry > 0 (added-only differential alert)"
            )
        elif check.mode == "differential" and check.rule.type == "added_count":
            added_output = "\n".join(sorted(added_lines))
            eval_result = evaluate(check.rule, added_output)
            rule_summary = self._build_rule_summary_runtime(check, eval_result.description)
        else:
            eval_result = evaluate(check.rule, output)
            rule_summary = self._build_rule_summary_runtime(check, eval_result.description)

        now_dt = datetime.now().astimezone()
        now_str = now_dt.strftime("%Y-%m-%d %H:%M:%S")
        label = severity_label(check.severity)

        if not eval_result.triggered:
            quiet_transition = self._suppressor.observe_quiet(
                check_id=check_key,
                severity=check.severity,
            )
            if quiet_transition.state_changed:
                event = AlertEvent(
                    timestamp=now_str,
                    check_name=check.name,
                    check_id=check_key,
                    mode=check.mode,
                    severity=check.severity,
                    severity_label=label,
                    rule=f"state transition: {quiet_transition.previous_state} -> {quiet_transition.state}",
                    current_value=eval_result.current_value,
                    raw_output="state-only transition (no new anomaly event)",
                    pushed=not quiet_transition.suppressed,
                    suppressed=quiet_transition.suppressed,
                    suppression_reason=quiet_transition.reason,
                    alert_state=quiet_transition.state,
                    previous_state=quiet_transition.previous_state,
                    fingerprint="",
                )
                pushed = await self._record_and_maybe_push(event)
                if pushed:
                    return f"🚨 {check.name}: state changed to {quiet_transition.state}, pushed"
                return f"📪 {check.name}: state changed to {quiet_transition.state} ({quiet_transition.reason})"

            return f"✅ {check.name}: normal (value={eval_result.current_value}, rule={rule_summary})"

        if check.mode == "differential" and check_key in {"ssh_bruteforce", "ssh_success_login"}:
            if not added_lines:
                return (
                    f"✅ {check.name}: anomaly persists but no new ssh delta entry "
                    f"(value={eval_result.current_value}, rule={rule_summary})"
                )
            removed_lines = set()
            alert_output = "\n".join(sorted(added_lines))

        if check.mode == "differential" and check_key not in {"ssh_bruteforce", "ssh_success_login"}:
            if not added_lines and not removed_lines:
                return f"✅ {check.name}: anomaly persists but no differential change (value={eval_result.current_value}, rule={rule_summary})"
            alert_output = self._build_diff_payload(added_lines, removed_lines)

        ledger_payload = alert_output or output
        override_reason = self._ledger.is_exempt(check_key, ledger_payload)
        if override_reason:
            suppression = SuppressionResult(
                suppressed=True,
                reason=f"user_override: {override_reason}",
                state="",
                previous_state="",
                state_changed=False,
            )
        else:
            fingerprints = self._build_fingerprints(
                check_key=check_key,
                alert_output=(alert_output or output),
                now=now_dt,
            )
            suppression = self._suppressor.process_event(
                check_id=check_key,
                severity=check.severity,
                fingerprints=fingerprints,
            )

        event = AlertEvent(
            timestamp=now_str,
            check_name=check.name,
            check_id=check_key,
            mode=check.mode,
            severity=check.severity,
            severity_label=label,
            rule=rule_summary,
            current_value=eval_result.current_value,
            raw_output=(alert_output or output)[:2000],
            pushed=not suppression.suppressed,
            suppressed=suppression.suppressed,
            suppression_reason=suppression.reason,
            alert_state=suppression.state,
            previous_state=suppression.previous_state,
            fingerprint="|".join(suppression.fingerprints[:10]),
        )
        pushed = await self._record_and_maybe_push(event)

        if pushed:
            return f"🚨 {check.name}: pushed (state={suppression.state or 'N/A'}, severity={check.severity})"

        logger.debug("Alert suppressed for %s: %s", check.name, suppression.reason)
        return f"📪 {check.name}: suppressed (state={suppression.state or 'N/A'}, reason={suppression.reason})"
