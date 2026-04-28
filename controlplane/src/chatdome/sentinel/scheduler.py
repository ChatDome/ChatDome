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
from dataclasses import dataclass, field
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

SSH_SUCCESS_CHECK_IDS = {"ssh_success_login", "ssh_success_login_offhours"}
SSH_ADDED_ONLY_CHECK_IDS = {"ssh_bruteforce"} | SSH_SUCCESS_CHECK_IDS
SSH_SESSION_COMMANDS_PATROL_CHECK_ID = "ssh_session_commands_patrol"


@dataclass
class SSHSessionRecord:
    """Runtime state for one SSH audit session."""

    user: str = "unknown"
    ip: str = "unknown"
    port: str = "22"
    sshd_pid: str = ""
    audit_session_id: str = ""
    login_line: str = ""
    first_seen_monotonic: float = field(default_factory=time.monotonic)
    last_seen_monotonic: float = field(default_factory=time.monotonic)


class SentinelScheduler:
    """Orchestrates the Sentinel SOC pipeline."""

    def __init__(
        self,
        config: SentinelConfig,
        pack_loader: PackLoader,
        sandbox: CommandSandbox,
        send_alert_fn: Callable[..., Coroutine[Any, Any, None]],
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

        self._auditd_checked = False
        self._auditd_available: bool | None = None
        self._auditd_has_execve_rule = False
        self._auditd_status_output = ""
        self._auditd_notice_sent = False

        self._ssh_session_tracker: dict[str, SSHSessionRecord] = {}
        self._ssh_session_command_baselines: dict[str, set[str]] = {}

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

    def _pack_command_available(self, check_id: str) -> bool:
        if self._pack_loader is None or not hasattr(self._pack_loader, "get_command"):
            return False
        try:
            return self._pack_loader.get_command(check_id) is not None
        except Exception:
            logger.exception("Failed to inspect pack command: %s", check_id)
            return False

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
        await self._ensure_auditd_status()
        await self._maybe_send_auditd_setup_notice()

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

    # -- auditd / SSH session tracking -------------------------------------

    async def _ensure_auditd_status(self, force: bool = False) -> None:
        if self._auditd_checked and not force:
            return

        self._auditd_checked = True
        self._auditd_available = None
        self._auditd_has_execve_rule = False
        self._auditd_status_output = ""

        if not self._pack_command_available("auditd_status"):
            logger.info("auditd_status command not available; SSH session command tracking disabled")
            return

        result = await self._sandbox.execute_security_check("auditd_status", args={})
        if result.timed_out or result.return_code not in (0, None):
            self._auditd_status_output = (result.stderr or result.stdout or "").strip()
            self._auditd_available = False
            return

        output = (result.stdout or "").strip()
        self._auditd_status_output = output
        lowered = output.lower()
        self._auditd_available = "=== auditd installed ===\nyes" in lowered or "\nyes\n" in lowered
        self._auditd_has_execve_rule = "execve" in lowered and "no execve rules found" not in lowered

    async def _maybe_send_auditd_setup_notice(self) -> None:
        if self._auditd_notice_sent or not self._alert_chat_ids:
            return
        if self._auditd_available and self._auditd_has_execve_rule:
            return
        if self._auditd_available is None and not self._auditd_status_output:
            return

        if self._auditd_available is False:
            reason = "auditd 未安装或不可用"
        elif not self._auditd_has_execve_rule:
            reason = "auditd 已安装，但缺少 execve 审计规则"
        else:
            reason = "auditd 状态未知"

        status_excerpt = "\n".join(self._auditd_status_output.splitlines()[:12]).strip()
        lines = [
            "ℹ️ SSH 会话命令追踪尚未完全启用",
            "",
            f"原因: {reason}",
            "",
            "启用后，Sentinel 可以把 SSH 登录后的 execve 命令按 audit session ID 归属到具体会话。",
            "推荐规则:",
            "- auditctl -a always,exit -F arch=b64 -S execve -k chatdome_cmd",
            "- auditctl -a always,exit -F arch=b32 -S execve -k chatdome_cmd",
        ]
        if status_excerpt:
            lines.extend(["", "当前检测结果:", status_excerpt])

        message = "\n".join(lines)
        for chat_id in self._alert_chat_ids:
            try:
                await self._send_alert(chat_id, message)
            except Exception:
                logger.exception("Failed to send auditd setup notice to chat %s", chat_id)

        self._auditd_notice_sent = True

    @staticmethod
    def _extract_sshd_pid(text: str) -> str:
        for pattern in (r"\bsshd_pid=(\d+)\b", r"\bsshd\[(\d+)\]"):
            match = re.search(pattern, text)
            if match:
                return match.group(1)
        return ""

    @staticmethod
    def _extract_audit_session_id(text: str) -> str:
        match = re.search(r"\bses=(\d+)\b", text)
        return match.group(1) if match else ""

    @staticmethod
    def _parse_ssh_success_details(text: str) -> dict[str, str]:
        parts = text.split()
        ip_value, ip_index = SentinelScheduler._extract_first_ip_with_index(text)
        method = ""

        for i, token in enumerate(parts):
            if token == "Accepted" and (i + 1) < len(parts):
                method = parts[i + 1]
                break

        if not method and ip_index >= 0 and (ip_index + 2) < len(parts):
            candidate = parts[ip_index + 2].strip().strip(",;()[]{}<>")
            if candidate and not candidate.startswith("sshd_pid="):
                method = candidate

        return {
            "time": " ".join(parts[:3]) if len(parts) >= 3 else "",
            "method": method or "unknown",
            "user": SentinelScheduler._extract_user(text),
            "ip": ip_value,
            "port": SentinelScheduler._extract_ssh_port(text),
            "sshd_pid": SentinelScheduler._extract_sshd_pid(text),
        }

    @staticmethod
    def _session_key(*, audit_session_id: str = "", sshd_pid: str = "") -> str:
        if audit_session_id:
            return f"ses={audit_session_id}"
        if sshd_pid:
            return f"pid={sshd_pid}"
        return ""

    def _remember_ssh_session(self, details: dict[str, str], audit_session_id: str = "") -> SSHSessionRecord | None:
        key = self._session_key(
            audit_session_id=audit_session_id,
            sshd_pid=details.get("sshd_pid", ""),
        )
        if not key:
            return None

        now = time.monotonic()
        record = self._ssh_session_tracker.get(key)
        if record is None:
            record = SSHSessionRecord(
                user=details.get("user") or "unknown",
                ip=details.get("ip") or "unknown",
                port=details.get("port") or "22",
                sshd_pid=details.get("sshd_pid") or "",
                audit_session_id=audit_session_id,
                login_line=details.get("login_line") or "",
                first_seen_monotonic=now,
                last_seen_monotonic=now,
            )
            self._ssh_session_tracker[key] = record
            return record

        record.user = details.get("user") or record.user
        record.ip = details.get("ip") or record.ip
        record.port = details.get("port") or record.port
        record.sshd_pid = details.get("sshd_pid") or record.sshd_pid
        record.audit_session_id = audit_session_id or record.audit_session_id
        record.login_line = details.get("login_line") or record.login_line
        record.last_seen_monotonic = now
        return record

    async def _resolve_audit_session_id(self, sshd_pid: str) -> str:
        if not sshd_pid:
            return ""
        await self._ensure_auditd_status()
        if self._auditd_available is False:
            return ""
        if not self._pack_command_available("ssh_audit_session_for_pid"):
            return ""

        result = await self._sandbox.execute_security_check(
            "ssh_audit_session_for_pid",
            args={"sshd_pid": sshd_pid},
        )
        if result.timed_out or result.return_code not in (0, None):
            return ""
        return self._extract_audit_session_id(result.stdout or "")

    @staticmethod
    def _normalize_command_lines(output: str) -> list[str]:
        commands: list[str] = []
        seen: set[str] = set()
        ignored = {
            "AUDITD_NOT_AVAILABLE",
            "ausearch failed",
            "No matching audit events",
        }
        for raw in (output or "").splitlines():
            line = raw.strip()
            if not line or line in ignored:
                continue
            if line.startswith("type=") or line.startswith("----"):
                continue
            if line not in seen:
                seen.add(line)
                commands.append(line)
        return commands

    async def _fetch_session_commands(self, session_id: str, limit: int = 50) -> tuple[list[str], str]:
        if not session_id:
            return [], "no_audit_session"
        await self._ensure_auditd_status()
        if self._auditd_available is False:
            return [], "auditd_unavailable"
        if self._auditd_available and not self._auditd_has_execve_rule:
            return [], "execve_rule_missing"
        if not self._pack_command_available("ssh_session_commands"):
            return [], "command_unavailable"

        result = await self._sandbox.execute_security_check(
            "ssh_session_commands",
            args={"session_id": session_id, "limit": limit},
        )
        if result.timed_out or result.return_code not in (0, None):
            return [], "query_failed"

        output = result.stdout or ""
        if "AUDITD_NOT_AVAILABLE" in output:
            return [], "auditd_unavailable"
        commands = self._normalize_command_lines(output)
        return commands, "ok" if commands else "no_commands"

    async def _build_ssh_success_context(self, alert_output: str) -> dict[str, Any]:
        sessions: list[dict[str, Any]] = []
        for raw_line in (alert_output or "").splitlines():
            line = raw_line.strip()
            if not line:
                continue

            details = self._parse_ssh_success_details(line)
            details["login_line"] = line
            sshd_pid = details.get("sshd_pid", "")
            if not sshd_pid:
                sessions.append({**details, "tracking_status": "no_pid", "commands": []})
                continue

            audit_session_id = await self._resolve_audit_session_id(sshd_pid)
            if not audit_session_id:
                status = "auditd_unavailable" if self._auditd_available is False else "no_audit_session"
                sessions.append({**details, "audit_session_id": "", "tracking_status": status, "commands": []})
                self._remember_ssh_session(details)
                continue

            commands, status = await self._fetch_session_commands(audit_session_id, limit=50)
            session_info = {
                **details,
                "audit_session_id": audit_session_id,
                "tracking_status": status,
                "commands": commands,
            }
            sessions.append(session_info)

            self._remember_ssh_session(details, audit_session_id=audit_session_id)
            session_key = self._session_key(audit_session_id=audit_session_id, sshd_pid=sshd_pid)
            if session_key and commands:
                self._ssh_session_command_baselines[session_key] = set(commands)

        if not sessions:
            return {}
        return {
            "ssh_sessions": sessions,
            "auditd": {
                "available": self._auditd_available,
                "has_execve_rule": self._auditd_has_execve_rule,
            },
        }

    def _purge_old_tracked_sessions(self, tracking_window_hours: int) -> None:
        cutoff = time.monotonic() - max(1, tracking_window_hours) * 3600
        stale_keys = [
            key
            for key, record in self._ssh_session_tracker.items()
            if record.first_seen_monotonic < cutoff
        ]
        for key in stale_keys:
            self._ssh_session_tracker.pop(key, None)
            self._ssh_session_command_baselines.pop(key, None)

    @staticmethod
    def _parse_active_session_line(line: str) -> dict[str, str] | None:
        if "sshd:" not in line or "@" not in line:
            return None
        pid_match = re.match(r"\s*(\d+)\s+", line)
        if not pid_match:
            return None
        identity_match = re.search(r"sshd:\s*([^\s@]+)@(\S+)", line)
        return {
            "sshd_pid": pid_match.group(1),
            "user": identity_match.group(1) if identity_match else "unknown",
            "tty": identity_match.group(2) if identity_match else "",
            "ip": "unknown",
            "port": "22",
            "login_line": line.strip(),
        }

    async def _discover_active_ssh_sessions(self, tracking_window_hours: int) -> list[SSHSessionRecord]:
        self._purge_old_tracked_sessions(tracking_window_hours)
        records: dict[str, SSHSessionRecord] = dict(self._ssh_session_tracker)

        if self._pack_command_available("ssh_active_sessions"):
            result = await self._sandbox.execute_security_check("ssh_active_sessions", args={"limit": 50})
            if not result.timed_out and result.return_code in (0, None):
                output_lines = (result.stdout or "").splitlines()
                tty_sources: dict[str, str] = {}
                for raw_line in output_lines:
                    match = re.search(r"\btty=(\S+)\s+from=(\S+)", raw_line)
                    if match:
                        tty_sources[match.group(1)] = match.group(2)

                for raw_line in output_lines:
                    details = self._parse_active_session_line(raw_line)
                    if not details:
                        continue
                    tty = details.get("tty", "")
                    if tty and tty in tty_sources:
                        details["ip"] = tty_sources[tty]
                    audit_session_id = await self._resolve_audit_session_id(details["sshd_pid"])
                    record = self._remember_ssh_session(details, audit_session_id=audit_session_id)
                    if record is not None:
                        records[self._session_key(
                            audit_session_id=record.audit_session_id,
                            sshd_pid=record.sshd_pid,
                        )] = record

        return list(records.values())

    async def _run_ssh_session_commands_patrol(self, check: CheckDefinition) -> str:
        tracking_window_hours = int((check.args or {}).get("tracking_window_hours", 1) or 1)
        limit = int((check.args or {}).get("limit", 50) or 50)
        await self._ensure_auditd_status()

        if self._auditd_available is False:
            return f"ℹ️ {check.name}: auditd unavailable, SSH session command tracking disabled"
        if self._auditd_available and not self._auditd_has_execve_rule:
            return f"ℹ️ {check.name}: auditd execve rule missing"

        sessions = await self._discover_active_ssh_sessions(tracking_window_hours)
        updates: list[dict[str, Any]] = []
        initialized = 0

        for record in sessions:
            if not record.audit_session_id and record.sshd_pid:
                record.audit_session_id = await self._resolve_audit_session_id(record.sshd_pid)
            if not record.audit_session_id:
                continue

            commands, status = await self._fetch_session_commands(record.audit_session_id, limit=limit)
            if status not in {"ok", "no_commands"}:
                continue

            session_key = self._session_key(
                audit_session_id=record.audit_session_id,
                sshd_pid=record.sshd_pid,
            )
            current = set(commands)
            previous = self._ssh_session_command_baselines.get(session_key)
            if previous is None:
                self._ssh_session_command_baselines[session_key] = current
                initialized += 1
                continue

            added = current - previous
            self._ssh_session_command_baselines[session_key] = current
            if not added:
                continue

            updates.append(
                {
                    "user": record.user,
                    "ip": record.ip,
                    "port": record.port,
                    "sshd_pid": record.sshd_pid,
                    "audit_session_id": record.audit_session_id,
                    "added_commands": sorted(added),
                }
            )

        if not updates:
            quiet_transition = self._suppressor.observe_quiet(
                check_id=SSH_SESSION_COMMANDS_PATROL_CHECK_ID,
                severity=check.severity,
            )
            if quiet_transition.state_changed:
                now_str = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")
                event = AlertEvent(
                    timestamp=now_str,
                    check_name=check.name,
                    check_id=SSH_SESSION_COMMANDS_PATROL_CHECK_ID,
                    mode=check.mode,
                    severity=check.severity,
                    severity_label=severity_label(check.severity),
                    rule=f"state transition: {quiet_transition.previous_state} -> {quiet_transition.state}",
                    current_value=0,
                    raw_output="state-only transition (no new SSH session commands)",
                    pushed=not quiet_transition.suppressed,
                    suppressed=quiet_transition.suppressed,
                    action_reason=quiet_transition.reason,
                    alert_state=quiet_transition.state,
                    previous_state=quiet_transition.previous_state,
                    fingerprint="",
                )
                pushed = await self._record_and_maybe_push(event)
                return f"🚨 {check.name}: state changed to {quiet_transition.state}, pushed" if pushed else (
                    f"📢 {check.name}: state changed to {quiet_transition.state} ({quiet_transition.reason})"
                )
            if initialized:
                return f"BASELINE_INIT: {check.name}: SSH session command baseline initialized ({initialized} sessions)"
            return f"✅ {check.name}: no new SSH session commands"

        added_count = sum(len(update["added_commands"]) for update in updates)
        fingerprints = {
            f"ses={update['audit_session_id']}|{command}"
            for update in updates
            for command in update["added_commands"]
        }
        suppression = self._suppressor.process_event(
            check_id=SSH_SESSION_COMMANDS_PATROL_CHECK_ID,
            severity=check.severity,
            fingerprints=fingerprints,
            notify_on_repeat=True,
            event_weight=added_count,
        )

        raw_lines: list[str] = []
        for update in updates:
            raw_lines.append(
                "session "
                f"user={update['user']} ip={update['ip']} port={update['port']} "
                f"sshd_pid={update['sshd_pid']} ses={update['audit_session_id']}"
            )
            raw_lines.extend(f"+ {command}" for command in update["added_commands"])

        now_str = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")
        event = AlertEvent(
            timestamp=now_str,
            check_name=check.name,
            check_id=SSH_SESSION_COMMANDS_PATROL_CHECK_ID,
            mode=check.mode,
            severity=check.severity,
            severity_label=severity_label(check.severity),
            rule="added SSH session command count > 0 (differential mode)",
            current_value=added_count,
            raw_output="\n".join(raw_lines)[:2000],
            pushed=not suppression.suppressed,
            suppressed=suppression.suppressed,
            action_reason=suppression.reason,
            alert_state=suppression.state,
            previous_state=suppression.previous_state,
            fingerprint="|".join(suppression.fingerprints[:10]),
            context={"ssh_command_updates": updates},
        )
        pushed = await self._record_and_maybe_push(event)
        if pushed:
            return f"🚨 {check.name}: pushed (new_commands={added_count}, state={suppression.state or 'N/A'})"
        return f"📢 {check.name}: suppressed (state={suppression.state or 'N/A'}, reason={suppression.reason})"

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

        if check_key in SSH_SUCCESS_CHECK_IDS:
            return SentinelScheduler._canonicalize_ssh_success_line(text)

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
    def _canonicalize_ssh_success_line(text: str) -> str:
        lowered = text.lower()
        if lowered.startswith("no ssh ") or "log access denied" in lowered:
            return ""

        if not text.split():
            return ""

        details = SentinelScheduler._parse_ssh_success_details(text)
        if not details.get("ip"):
            return text

        fields = [
            details.get("time", ""),
            details.get("method", ""),
            details.get("user", ""),
            details.get("ip", ""),
            details.get("port", ""),
        ]
        if details.get("sshd_pid"):
            fields.append(f"sshd_pid={details['sshd_pid']}")
        normalized = " ".join(field for field in fields if field)
        return normalized or text

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
            return str(ipaddress.ip_address(value.strip().strip("[](),;")))
        except ValueError:
            return ""

    @staticmethod
    def _extract_first_ip(text: str) -> str:
        ip_value, _ = SentinelScheduler._extract_first_ip_with_index(text)
        return ip_value

    @staticmethod
    def _extract_first_ip_with_index(text: str) -> tuple[str, int]:
        parts = text.split()
        for index, token in enumerate(parts):
            ip_value = SentinelScheduler._safe_ip(token)
            if ip_value:
                return ip_value, index

        for token in re.findall(r"[0-9a-fA-F:.]+", text):
            ip_value = SentinelScheduler._safe_ip(token)
            if ip_value:
                return ip_value, -1
        return "", -1

    @staticmethod
    def _extract_user(text: str) -> str:
        m = re.search(r"\bfor\s+([a-zA-Z0-9_.-]+)\b", text)
        if m:
            return m.group(1)

        _, ip_index = SentinelScheduler._extract_first_ip_with_index(text)
        parts = text.split()
        if ip_index > 0 and ip_index < len(parts):
            candidate = parts[ip_index - 1].strip()
            if candidate and candidate not in {"from", "port"} and not SentinelScheduler._safe_ip(candidate):
                return candidate
        return "unknown"

    @staticmethod
    def _extract_ssh_port(text: str) -> str:
        m = re.search(r"\bport\s+(\d+)\b", text)
        if m:
            return m.group(1)

        _, ip_index = SentinelScheduler._extract_first_ip_with_index(text)
        parts = text.split()
        if ip_index >= 0 and (ip_index + 1) < len(parts):
            candidate = parts[ip_index + 1].strip()
            if candidate.isdigit():
                return candidate
        return "22"

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

        if check_key in SSH_SUCCESS_CHECK_IDS:
            for line in lines:
                details = self._parse_ssh_success_details(line)
                ip_value = details.get("ip", "")
                if not ip_value:
                    continue
                user = details.get("user", "unknown")
                port = details.get("port", "22")
                sshd_pid = details.get("sshd_pid") or "unknown"
                fps.add(f"{ip_value}|{user}|{port}|{sshd_pid}")
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
                await self._send_alert(chat_id, message, event)
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

    @staticmethod
    def _format_failure_detail(stderr_text: str, max_chars: int = 240) -> str:
        text = " ".join((stderr_text or "").split())
        if not text:
            return ""
        if len(text) > max_chars:
            text = text[: max_chars - 3] + "..."
        return f" ({text})"

    # -- Single check ------------------------------------------------------

    async def _run_single_check(self, check: CheckDefinition) -> str:
        check_key = check.check_id or check.name

        if check_key == SSH_SESSION_COMMANDS_PATROL_CHECK_ID:
            return await self._run_ssh_session_commands_patrol(check)

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
            return f"❌ {check.name}: execution failed{self._format_failure_detail(stderr_text)}"

        if result.return_code is not None and result.return_code != 0:
            logger.warning("Check %s failed (code=%s): %s", check.name, result.return_code, stderr_text)
            return f"❌ {check.name}: execution failed{self._format_failure_detail(stderr_text)}"

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

        if check.mode == "differential" and check_key in SSH_ADDED_ONLY_CHECK_IDS:
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
                    action_reason=quiet_transition.reason,
                    alert_state=quiet_transition.state,
                    previous_state=quiet_transition.previous_state,
                    fingerprint="",
                )
                pushed = await self._record_and_maybe_push(event)
                if pushed:
                    return f"🚨 {check.name}: state changed to {quiet_transition.state}, pushed"
                return f"📪 {check.name}: state changed to {quiet_transition.state} ({quiet_transition.reason})"

            return f"✅ {check.name}: normal (value={eval_result.current_value}, rule={rule_summary})"

        if check.mode == "differential" and check_key in SSH_ADDED_ONLY_CHECK_IDS:
            if not added_lines:
                return (
                    f"✅ {check.name}: anomaly persists but no new ssh delta entry "
                    f"(value={eval_result.current_value}, rule={rule_summary})"
                )
            removed_lines = set()
            alert_output = "\n".join(sorted(added_lines))

        if check.mode == "differential" and check_key not in SSH_ADDED_ONLY_CHECK_IDS:
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
                notify_on_repeat=check_key in SSH_SUCCESS_CHECK_IDS and bool(added_lines),
                event_weight=len(added_lines) if check_key in SSH_ADDED_ONLY_CHECK_IDS else 1,
            )

        event_context: dict[str, Any] = {}
        if check_key in SSH_SUCCESS_CHECK_IDS and not suppression.suppressed:
            event_context = await self._build_ssh_success_context(alert_output or output)

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
            action_reason=suppression.reason,
            alert_state=suppression.state,
            previous_state=suppression.previous_state,
            fingerprint="|".join(suppression.fingerprints[:10]),
            context=event_context,
        )
        pushed = await self._record_and_maybe_push(event)

        if pushed:
            return f"🚨 {check.name}: pushed (state={suppression.state or 'N/A'}, severity={check.severity})"

        logger.debug("Alert suppressed for %s: %s", check.name, suppression.reason)
        return f"📪 {check.name}: suppressed (state={suppression.state or 'N/A'}, reason={suppression.reason})"
