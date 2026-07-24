"""
Tool dispatch — routes LLM tool_calls to the appropriate executor.

Handles:
  - read_chatdome_manual → curated internal operating manual
  - run_security_check → CommandSandbox.execute_security_check
  - run_shell_command  → CommandSandbox.execute_shell_command
  - whois_lookup       → HTTP call to ip-api.com
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
from collections.abc import Iterable
from datetime import datetime
from typing import Any

import httpx

from chatdome.agent.audit import CommandAuditTracker
from chatdome.agent.manual import read_manual_section
from chatdome.executor.command_parser import ShellCommandSegment, split_shell_commands
from chatdome.executor.sandbox import CommandSandbox, CommandResult
from chatdome.llm.client import LLMClient
from chatdome.sentinel.alert_controls import format_alert_push_status, parse_alert_mute_until

_COMMAND_DETAIL_BATCH_SIZE = 4
_COMMAND_DETAIL_MAX_CONCURRENCY = 2
_COMMAND_DETAIL_TIMEOUT_SECONDS = 30.0
_COMMAND_DETAIL_MAX_TOKENS_PER_SEGMENT = 12
_COMMAND_DETAIL_MAX_TARGETS_PER_SEGMENT = 6
_COMMAND_DETAIL_MAX_WARNINGS_PER_SEGMENT = 3
_COMMAND_DETAIL_MAX_TOKEN_CHARS = 240
_COMMAND_DETAIL_MAX_LABEL_CHARS = 40
_COMMAND_DETAIL_MAX_MEANING_CHARS = 120
_COMMAND_DETAIL_MAX_SUMMARY_CHARS = 160
_COMMAND_DETAIL_MAX_WARNING_CHARS = 160

logger = logging.getLogger(__name__)


class _InvalidCommandDetailResponse(ValueError):
    """The reviewer returned JSON that cannot provide command details."""


_COMMAND_DETAIL_CANCELLED_TASKS: set[asyncio.Task[Any]] = set()


def _release_cancelled_command_detail_task(task: asyncio.Task[Any]) -> None:
    _COMMAND_DETAIL_CANCELLED_TASKS.discard(task)
    if task.cancelled():
        return
    try:
        task.exception()
    except asyncio.CancelledError:
        pass


def _cancel_command_detail_tasks(
    tasks: Iterable[asyncio.Task[Any]],
) -> None:
    for task in tuple(tasks):
        if task.done():
            _release_cancelled_command_detail_task(task)
            continue
        task.cancel()
        _COMMAND_DETAIL_CANCELLED_TASKS.add(task)
        task.add_done_callback(_release_cancelled_command_detail_task)


_LONG_TERM_CONTEXT_SIGNALS = (
    "通常",
    "一般",
    "经常",
    "常用",
    "日常",
    "固定",
    "长期",
    "常驻",
    "默认",
    "总是",
    "每次",
    "习惯",
    "偏好",
)
_TRANSIENT_CONTEXT_SIGNALS = (
    "刚才",
    "刚刚",
    "临时",
    "今天",
    "本次",
    "这次",
    "这条",
    "刚发生",
    "手动重启",
    "重启",
    "停止",
    "启动",
    "部署",
    "升级",
    "测试",
    "排查",
    "维护",
)
_IDENTITY_CONTEXT_SIGNALS = (
    "我的",
    "本人",
    "自己",
    "我们",
    "可信",
    "白名单",
    "允许",
    "合法",
    "正常来源",
    "正常操作",
)
_BEHAVIOR_CONTEXT_SIGNALS = (
    "通过",
    "使用",
    "登录",
    "连接",
    "访问",
    "发布",
    "巡检",
    "备份",
    "同步",
    "拉取",
    "推送",
)
_TOPOLOGY_CONTEXT_SIGNALS = (
    "ip",
    "网段",
    "端口",
    "节点",
    "跳板",
    "堡垒",
    "vpn",
    "内网",
    "公网",
    "网关",
    "负载均衡",
    "反代",
    "域名",
    "地址",
    "服务",
    "机器",
    "服务器",
    "容器",
)
_ENVIRONMENT_CONTEXT_SIGNALS = (
    "路径",
    "目录",
    "配置",
    "软件",
    "组件",
    "版本",
    "进程",
    "服务",
    "数据库",
    "中间件",
)
_CONSTRAINT_CONTEXT_SIGNALS = (
    "不要",
    "不能",
    "禁止",
    "避免",
    "只允许",
    "必须",
    "不得",
)
_PREFERENCE_CONTEXT_SIGNALS = (
    "优先",
    "偏好",
    "习惯",
    "希望",
    "默认",
    "尽量",
    "回复",
    "格式",
)
_TOPOLOGY_CONTEXT_CHECKS = {
    "ssh_success_login",
    "ssh_bruteforce",
    "active_connections",
    "open_ports",
}



class PendingApprovalError(Exception):
    """Raised when a tool call requires user confirmation before execution."""
    def __init__(
        self,
        command: str,
        safety_status: str,
        impact_analysis: str,
        tool_call_id: str,
        reason: str = "",
        risk_level: str = "HIGH",
        mutation_detected: bool = False,
        deletion_detected: bool = False,
        command_breakdown: dict[str, Any] | None = None,
    ):
        self.command = command
        self.safety_status = safety_status
        self.impact_analysis = impact_analysis
        self.tool_call_id = tool_call_id
        self.reason = reason
        self.risk_level = risk_level
        self.mutation_detected = mutation_detected
        self.deletion_detected = deletion_detected
        self.command_breakdown = command_breakdown or {}
        super().__init__(f"Command requires approval: {command}")


class ToolDispatcher:
    """
    Routes tool calls from the LLM to the appropriate handler
    and formats results as strings for the conversation.
    """

    def __init__(
        self,
        sandbox: CommandSandbox,
        llm: Any = None,
        user_context_ledger: Any = None,
        engram_store: Any = None,
        sentinel: Any = None,
        session_manager: Any = None,
    ):
        self.sandbox = sandbox
        self.llm = llm
        self.user_context_ledger = user_context_ledger
        self.engram_store = engram_store
        self.sentinel = sentinel
        self.session_manager = session_manager
        self._http_client: httpx.AsyncClient | None = None

    def set_sentinel(self, sentinel: Any) -> None:
        """Inject the Sentinel scheduler after runtime wiring."""
        self.sentinel = sentinel

    def set_session_manager(self, session_manager: Any) -> None:
        """Inject the session manager after Agent construction."""
        self.session_manager = session_manager

    async def _get_http_client(self) -> httpx.AsyncClient:
        """Lazy-init the HTTP client."""
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(timeout=10.0)
        return self._http_client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._http_client and not self._http_client.is_closed:
            await self._http_client.aclose()

    async def dispatch(
        self,
        tool_name: str,
        arguments_json: str,
        tool_call_id: str = "",
        chat_id: int = 0,
        llm: Any = None,
    ) -> str:
        """
        Dispatch a tool call and return the formatted result string.
        Raises PendingApprovalError if the command needs human confirmation.

        Args:
            tool_name: The function name from the LLM tool_call.
            arguments_json: The raw JSON arguments string.
            tool_call_id: The ID of this tool call.
            chat_id: The ID of the chat context.

        Returns:
            Formatted result string to feed back to the LLM.
        """
        try:
            args = LLMClient.parse_json_object(arguments_json) if arguments_json else {}
        except Exception as e:
            logger.warning(
                "Tool argument parse failed for %s (tool_call_id=%s): %s | raw=%r",
                tool_name,
                tool_call_id,
                e,
                (arguments_json or "")[:200],
            )
            return f"参数解析失败: {e}"

        try:
            if tool_name == "read_chatdome_manual":
                return self._handle_read_chatdome_manual(args)
            elif tool_name == "search_session_history":
                return self._handle_search_session_history(args, chat_id)
            elif tool_name == "run_security_check":
                return await self._handle_security_check(args, tool_call_id, chat_id)
            elif tool_name == "run_shell_command":
                return await self._handle_shell_command(args, tool_call_id, chat_id, llm=llm)
            elif tool_name == "get_command_audit_events":
                return self._handle_command_audit_events(args, chat_id)
            elif tool_name == "whois_lookup":
                return await self._handle_whois_lookup(args)
            elif tool_name == "add_user_context":
                return await self._handle_add_user_context(args)
            elif tool_name == "set_sentinel_alert_push_policy":
                return self._handle_sentinel_alert_push_policy(args, chat_id)
            elif tool_name == "save_engram":
                return self._handle_save_engram(args)
            elif tool_name == "recall_engrams":
                return self._handle_recall_engrams(args)
            else:
                return f"未知工具: {tool_name}"
        except PendingApprovalError:
            raise
        except Exception as e:
            logger.error("Tool execution failed: %s — %s", tool_name, e)
            return f"工具执行异常: {e}"

    # ----- Handlers -----

    def _handle_read_chatdome_manual(self, args: dict[str, Any]) -> str:
        """Return one curated operating manual section."""
        return read_manual_section(str(args.get("section_id", "")))

    def _handle_search_session_history(self, args: dict[str, Any], chat_id: int = 0) -> str:
        """Return relevant snippets from the current chat session."""
        if not chat_id:
            return json.dumps(
                {"ok": False, "error": "missing_chat_id", "matches": []},
                ensure_ascii=False,
            )
        if not self.session_manager:
            return json.dumps(
                {"ok": False, "error": "session_manager_unavailable", "matches": []},
                ensure_ascii=False,
            )

        query = str(args.get("query") or "").strip()
        try:
            limit = int(args.get("limit", 5))
        except (TypeError, ValueError):
            limit = 5
        limit = min(max(limit, 1), 10)

        matches = self.session_manager.search_history(
            chat_id,
            query,
            limit=limit,
            max_chars_per_item=900,
        )
        payload = {
            "ok": True,
            "query": query,
            "source": f"sessions/{chat_id}.json",
            "matches": matches,
            "priority_note": "Historical session snippets are reference context. Current user input, current alerts, and current tool results take priority.",
        }
        return json.dumps(payload, ensure_ascii=False, indent=2)

    @staticmethod
    def _parse_until_iso(value: Any) -> datetime | None:
        text = str(value or "").strip()
        if not text:
            return None
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed.astimezone() if parsed.tzinfo is not None else parsed.astimezone()

    def _resolve_alert_push_until(self, args: dict[str, Any]) -> tuple[datetime | None, str]:
        until_iso = str(args.get("until_iso") or "").strip()
        if until_iso:
            parsed = self._parse_until_iso(until_iso)
            if parsed is None:
                return None, f"无法解析 until_iso: {until_iso}"
            return parsed, ""

        duration = str(args.get("duration") or "").strip()
        if not duration:
            return None, ""

        if duration.lower() in {"manual", "until_resume", "forever", "indefinite"}:
            return None, ""

        parsed = parse_alert_mute_until(duration)
        if parsed is None:
            return None, f"无法解析 duration: {duration}"
        return parsed, ""

    def _handle_sentinel_alert_push_policy(self, args: dict[str, Any], chat_id: int = 0) -> str:
        """Control Sentinel Telegram alert push policy through an explicit tool call."""
        if not self.sentinel:
            return "Sentinel 未启用，无法调整告警推送策略。"

        action = str(args.get("action") or "").strip().lower()
        if action not in {"mute", "resume", "status"}:
            return "缺少或不支持的 action。请使用 mute、resume 或 status。"

        if action == "status":
            return format_alert_push_status(self.sentinel.alert_push_status())

        if action == "resume":
            status = self.sentinel.resume_alert_push(chat_id=chat_id or None)
            return format_alert_push_status(status, prefix="已恢复 Sentinel 告警推送。")

        until, error = self._resolve_alert_push_until(args)
        if error:
            return error

        reason = str(args.get("reason") or "agent_tool_request").strip()
        status = self.sentinel.mute_alert_push(
            until=until,
            reason=f"agent_tool:{reason[:160]}",
            chat_id=chat_id or None,
        )
        return format_alert_push_status(status, prefix="已暂停 Sentinel 告警推送。")

    def _handle_save_engram(self, args: dict[str, Any]) -> str:
        if not self.engram_store:
            return "❌ EngramStore 未初始化，保存失败。"
        category = str(args.get("category", "")).strip()
        fact = str(args.get("fact", "")).strip()
        source_context = str(args.get("source_context", "")).strip()
        supersedes_id = args.get("supersedes_id")

        if not category or not fact:
            return "参数错误: category 和 fact 是必填字段。"

        if supersedes_id:
            try:
                engram = self.engram_store.supersede(supersedes_id, category, fact, source_context)
                return f"🧠 已更新 Engram 记录 (覆盖了 {supersedes_id})：[{category}] {fact} (记录 ID: {engram.id})"
            except ValueError as e:
                return f"❌ 更新失败：{e}"

        existing = self._find_existing_engram(category, fact)
        if existing:
            return f"🧠 Engram 已存在：[{category}] {fact} (记录 ID: {existing.id})"

        conflicts = self.engram_store.find_conflicts(category, fact)
        if conflicts:
            c = conflicts[0]
            import datetime
            time_str = datetime.datetime.fromtimestamp(c.created_at).strftime('%Y-%m-%d %H:%M:%S')
            return (
                f"⚠️ 发现与已有 Engram 冲突：\n"
                f"在 {time_str} 你曾记录：\"{c.fact}\" (记录 ID: {c.id})\n"
                f"你现在想保存的 \"{fact}\" 与此矛盾。\n"
                f"请立即向用户指出矛盾并确认：是否要更新为新的事实？\n"
                f"如果用户确认更新，请带上 supersedes_id=\"{c.id}\" 再次调用 save_engram 进行覆盖。"
            )

        engram = self.engram_store.add(category, fact, source_context)
        return f"🧠 已录入 Engram：[{category}] {fact} (记录 ID: {engram.id})"

    def _find_existing_engram(self, category: str, fact: str) -> Any | None:
        if not self.engram_store:
            return None
        normalized = " ".join(str(fact or "").split())
        for engram in self.engram_store.list(category=category):
            if " ".join(str(engram.fact or "").split()) == normalized:
                return engram
        return None

    def _handle_recall_engrams(self, args: dict[str, Any]) -> str:
        if not self.engram_store:
            return "❌ EngramStore 未初始化。"
        category = args.get("category")
        engrams = self.engram_store.list(category=category)
        if not engrams:
            return "未找到相关的 Engram 记忆记录。"
            
        lines = [f"共找到 {len(engrams)} 条有效记录："]
        for e in engrams:
            lines.append(f"[{e.id}] [{e.category}] {e.fact}")
        return "\n".join(lines)

    async def _handle_security_check(
        self,
        args: dict[str, Any],
        tool_call_id: str = "",
        chat_id: int = 0,
    ) -> str:
        """Execute a pre-defined security check."""
        check_id = args.get("check_id", "")
        check_args = args.get("args")

        result = await self.sandbox.execute_security_check(
            check_id,
            check_args,
            chat_id=chat_id,
            tool_call_id=tool_call_id,
        )
        return self._format_command_result(result)

    def _handle_command_audit_events(self, args: dict[str, Any], chat_id: int = 0) -> str:
        """Return recent ChatDome command audit events without running host commands."""
        try:
            limit = int(args.get("limit", 5))
        except (TypeError, ValueError):
            limit = 5
        limit = min(max(limit, 1), 30)

        scope = str(args.get("scope", "executed") or "executed").strip().lower()
        if scope not in {"executed", "all"}:
            scope = "executed"

        raw_events = CommandAuditTracker.get_recent_events(
            chat_id=chat_id if chat_id else None,
            limit=max(100, limit * 20),
        )
        executed_event_types = {"command_executed", "security_check_executed"}

        events: list[dict[str, Any]] = []
        for event in raw_events:
            command = str(event.get("command", "") or "").strip()
            if not command:
                continue
            if scope == "executed" and str(event.get("event_type", "")) not in executed_event_types:
                continue
            events.append(event)
            if len(events) >= limit:
                break

        if not events:
            if scope == "executed":
                return "No executed ChatDome command audit events were found for this chat."
            return "No ChatDome command audit events with command text were found for this chat."

        title_scope = "executed commands" if scope == "executed" else "command audit events"
        lines = [
            f"ChatDome internal audit: latest {len(events)} {title_scope} (newest first).",
            "Source note: these are ChatDome tool executions, not SSH user session commands.",
        ]
        for idx, event in enumerate(events, start=1):
            timestamp = str(event.get("timestamp_iso", "unknown"))
            event_type = str(event.get("event_type", "unknown"))
            command = " ".join(str(event.get("command", "")).split())
            if len(command) > 300:
                command = command[:297].rstrip() + "..."

            details: list[str] = []
            check_id = str(event.get("check_id", "") or "").strip()
            if check_id:
                details.append(f"check_id={check_id}")
            execution_mode = str(event.get("execution_mode", "") or "").strip()
            if execution_mode:
                details.append(f"mode={execution_mode}")
            if "return_code" in event:
                details.append(f"return_code={event.get('return_code')}")
            if "duration_ms" in event:
                details.append(f"duration_ms={event.get('duration_ms')}")

            suffix = f" ({', '.join(details)})" if details else ""
            lines.append(f"{idx}. {timestamp} | {event_type}{suffix}\n   {command}")

        return "\n".join(lines)

    async def _handle_shell_command(
        self,
        args: dict[str, Any],
        tool_call_id: str,
        chat_id: int = 0,
        llm: Any = None,
    ) -> str:
        """Evaluate and suspend an AI-generated shell command for user approval."""
        command = args.get("command", "")
        reason = args.get("reason", "无说明")
        
        if not command:
            return "缺少 command 参数"

        # New approval flow:
        # - Do static-only precheck first (no LLM call here)
        # - Show minimal approval prompt
        # - Run full LLM analysis only when user asks for details
        analysis = await self.analyze_command_for_approval(
            command=command,
            reason=reason,
            chat_id=chat_id,
            tool_call_id=tool_call_id,
            include_llm=False,
            llm=llm,
        )
        static_is_safe = bool(analysis.get("static_is_safe", False))
        static_critical = bool(analysis.get("static_critical", False))
        mutation_detected = bool(analysis.get("mutation_detected", False))
        deletion_detected = bool(analysis.get("deletion_detected", False))
        safety_status = str(analysis.get("safety_status", "UNSAFE"))
        risk_level = str(analysis.get("risk_level", "HIGH"))
        impact_summary = self._build_initial_impact_summary(analysis)

        CommandAuditTracker.record_event(
            "command_reviewed",
            chat_id=chat_id,
            tool_call_id=tool_call_id,
            command=command,
            reason=reason,
            safety_status=safety_status,
            risk_level=risk_level,
            mutation_detected=mutation_detected,
            deletion_detected=deletion_detected,
            reviewer_mode="deferred",
            static_is_safe=static_is_safe,
            static_reason=analysis.get("static_reason", ""),
            static_write_detected=bool(analysis.get("static_write_detected", False)),
            static_critical=static_critical,
            unrestricted_mode=self.sandbox.allow_unrestricted_commands,
        )

        if self.sandbox.allow_unrestricted_commands:
            can_auto_execute = (
                static_is_safe
                and not static_critical
                and not mutation_detected
                and not deletion_detected
            )
            if can_auto_execute:
                result = await self.sandbox.execute_shell_command(
                    command,
                    reason,
                    chat_id=chat_id,
                    tool_call_id=tool_call_id,
                )
                return self._format_command_result(result)
            pending_mode = "unrestricted_guardrail"
        else:
            pending_mode = "restricted_default"

        CommandAuditTracker.record_event(
            "command_pending_approval",
            chat_id=chat_id,
            tool_call_id=tool_call_id,
            command=command,
            reason=reason,
            safety_status=safety_status,
            risk_level=risk_level,
            mutation_detected=mutation_detected,
            deletion_detected=deletion_detected,
            mode=pending_mode,
        )
        raise PendingApprovalError(
            command=command,
            safety_status=safety_status,
            impact_analysis=impact_summary,
            tool_call_id=tool_call_id,
            reason=reason,
            risk_level=risk_level,
            mutation_detected=mutation_detected,
            deletion_detected=deletion_detected,
        )

    async def get_command_approval_details(
        self,
        command: str,
        reason: str,
        chat_id: int = 0,
        tool_call_id: str = "",
        include_llm: bool = True,
        llm: Any = None,
    ) -> dict[str, Any]:
        """Return full approval details, including optional LLM analysis."""
        analysis = await self.analyze_command_for_approval(
            command=command,
            reason=reason,
            chat_id=chat_id,
            tool_call_id=tool_call_id,
            include_llm=include_llm,
            llm=llm,
        )
        CommandAuditTracker.record_event(
            "command_detail_requested",
            chat_id=chat_id,
            tool_call_id=tool_call_id,
            command=command,
            reason=reason,
            safety_status=analysis.get("safety_status"),
            risk_level=analysis.get("risk_level"),
            mutation_detected=analysis.get("mutation_detected"),
            deletion_detected=analysis.get("deletion_detected"),
            reviewer_mode=analysis.get("reviewer_mode"),
        )
        return analysis

    async def analyze_command_for_approval(
        self,
        command: str,
        reason: str,
        chat_id: int = 0,
        tool_call_id: str = "",
        include_llm: bool = False,
        llm: Any = None,
    ) -> dict[str, Any]:
        """Return static gate data or LLM details bounded by the static gate."""
        if include_llm:
            return await self._analyze_command_details_with_llm(
                command=command,
                chat_id=chat_id,
                llm=llm,
            )
        return self._analyze_command_static_gate(command)

    def _analyze_command_static_gate(self, command: str) -> dict[str, Any]:
        from chatdome.executor.validator import (
            has_write_intent,
            is_critical_command,
            validate_command,
        )

        static_check = validate_command(command, check_allowlist=False)
        static_critical = is_critical_command(command)
        static_write = has_write_intent(command)
        static_delete = self._has_delete_intent(command)

        if static_critical:
            safety_status = "CRITICAL"
            risk_level = "CRITICAL"
        elif static_write or not static_check.is_safe:
            safety_status = "UNSAFE"
            risk_level = "HIGH"
        else:
            safety_status = "SAFE"
            risk_level = "LOW"

        return {
            "safety_status": safety_status,
            "risk_level": risk_level,
            "mutation_detected": static_write,
            "deletion_detected": static_delete,
            "impact_analysis": self._build_initial_impact_summary({}),
            "reviewer_mode": "static_gate",
            "reviewer_status": safety_status,
            "reviewer_risk_level": risk_level,
            "static_is_safe": static_check.is_safe,
            "static_reason": static_check.reason,
            "static_write_detected": static_write,
            "static_critical": static_critical,
        }

    async def _analyze_command_details_with_llm(
        self,
        command: str,
        chat_id: int = 0,
        llm: Any = None,
    ) -> dict[str, Any]:
        reviewer_llm = llm if llm is not None else self.llm
        static_gate = self._analyze_command_static_gate(command)
        if reviewer_llm is None:
            details = self._llm_detail_fallback(
                "命令分析不可用。请直接检查原始命令。",
                command,
                error_code="llm_unavailable",
            )
            return self._apply_static_detail_floor(details, static_gate)

        segments = split_shell_commands(command)
        if not segments:
            details = self._llm_detail_fallback(
                "命令分析不可用。请直接检查原始命令。",
                command,
                error_code="empty_command",
            )
            return self._apply_static_detail_floor(details, static_gate)

        batch_specs = [
            (offset, segments[offset : offset + _COMMAND_DETAIL_BATCH_SIZE])
            for offset in range(0, len(segments), _COMMAND_DETAIL_BATCH_SIZE)
        ]
        semaphore = asyncio.Semaphore(_COMMAND_DETAIL_MAX_CONCURRENCY)

        async def analyze_batch(
            offset: int,
            batch_segments: tuple[ShellCommandSegment, ...],
        ) -> tuple[int, dict[str, Any] | None, bool, str]:
            async with semaphore:
                try:
                    payload = await self._request_command_detail_batch(
                        reviewer_llm,
                        batch_segments,
                        chat_id=chat_id,
                        previous_separator=(
                            segments[offset - 1].separator if offset else ""
                        ),
                        compact=False,
                    )
                    return (
                        offset,
                        self._normalize_llm_command_details(payload, batch_segments),
                        False,
                        "",
                    )
                except _InvalidCommandDetailResponse:
                    logger.warning(
                        "Command detail response invalid; retrying compact format: "
                        "start=%d count=%d",
                        offset + 1,
                        len(batch_segments),
                    )
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    logger.warning(
                        "Command detail batch failed: start=%d count=%d error=%s",
                        offset + 1,
                        len(batch_segments),
                        type(exc).__name__,
                    )
                    return offset, None, False, "provider_error"

                try:
                    payload = await self._request_command_detail_batch(
                        reviewer_llm,
                        batch_segments,
                        chat_id=chat_id,
                        previous_separator=(
                            segments[offset - 1].separator if offset else ""
                        ),
                        compact=True,
                    )
                    return (
                        offset,
                        self._normalize_llm_command_details(payload, batch_segments),
                        True,
                        "compact_retry",
                    )
                except _InvalidCommandDetailResponse:
                    logger.warning(
                        "Compact command detail response invalid: start=%d count=%d",
                        offset + 1,
                        len(batch_segments),
                    )
                    return offset, None, False, "invalid_response"
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    logger.warning(
                        "Compact command detail batch failed: "
                        "start=%d count=%d error=%s",
                        offset + 1,
                        len(batch_segments),
                        type(exc).__name__,
                    )
                    return offset, None, False, "provider_error"

        tasks = {
            asyncio.create_task(analyze_batch(offset, batch_segments)): (
                offset,
                len(batch_segments),
            )
            for offset, batch_segments in batch_specs
        }
        try:
            done, pending = await asyncio.wait(
                tuple(tasks),
                timeout=_COMMAND_DETAIL_TIMEOUT_SECONDS,
            )
        except asyncio.CancelledError:
            _cancel_command_detail_tasks(tasks)
            raise

        _cancel_command_detail_tasks(pending)

        batch_results: dict[int, tuple[dict[str, Any], bool]] = {}
        batch_errors: dict[int, str] = {
            tasks[task][0]: "timeout"
            for task in pending
        }
        for task in done:
            try:
                offset, analysis, compact, error_code = task.result()
            except asyncio.CancelledError:
                offset = tasks[task][0]
                batch_errors[offset] = "timeout"
                continue
            if analysis is None:
                batch_errors[offset] = error_code or "provider_error"
                continue
            batch_results[offset] = (analysis, compact)
            if error_code:
                batch_errors[offset] = error_code

        if pending:
            logger.warning(
                "Command detail analysis timed out after %.1fs: completed=%d total=%d",
                _COMMAND_DETAIL_TIMEOUT_SECONDS,
                len(done),
                len(tasks),
            )

        details = self._merge_command_detail_batches(
            command=command,
            segments=segments,
            batch_specs=batch_specs,
            batch_results=batch_results,
            batch_errors=batch_errors,
        )
        return self._apply_static_detail_floor(details, static_gate)

    async def _request_command_detail_batch(
        self,
        reviewer_llm: Any,
        segments: tuple[ShellCommandSegment, ...],
        *,
        chat_id: int,
        previous_separator: str,
        compact: bool,
    ) -> dict[str, Any]:
        from chatdome.agent.prompts import (
            COMMAND_DETAIL_COMPACT_SYSTEM_PROMPT,
            COMMAND_DETAIL_SYSTEM_PROMPT,
        )

        command_parts: list[str] = []
        for position, segment in enumerate(segments):
            command_parts.append(segment.command)
            if position < len(segments) - 1 and segment.separator:
                command_parts.append(segment.separator)
        command_payload = json.dumps(
            {
                "command": " ".join(command_parts),
                "commands": [
                    {
                        "index": position + 1,
                        "command": segment.command,
                        "separator": segment.separator,
                        "operator_before": (
                            previous_separator
                            if position == 0
                            else segments[position - 1].separator
                        ),
                        "operator_after": segment.separator,
                    }
                    for position, segment in enumerate(segments)
                ],
                "shell": "bash",
            },
            ensure_ascii=False,
        )
        messages = [
            {
                "role": "system",
                "content": (
                    COMMAND_DETAIL_COMPACT_SYSTEM_PROMPT
                    if compact
                    else COMMAND_DETAIL_SYSTEM_PROMPT
                ),
            },
            {
                "role": "user",
                "content": (
                    "只分析以下 JSON 中的 command 和 commands 字段。\n"
                    + command_payload
                ),
            },
        ]
        kwargs: dict[str, Any] = {
            "messages": messages,
            "response_format": {"type": "json_object"},
        }
        try:
            params = inspect.signature(reviewer_llm.chat_completion).parameters
        except (TypeError, ValueError):
            params = {}
        if "temperature" in params:
            kwargs["temperature"] = 0.0
        if "max_tokens" in params:
            requested_tokens = (
                250 + 120 * len(segments)
                if compact
                else 420 + 220 * len(segments)
            )
            configured_tokens = int(
                getattr(reviewer_llm, "max_tokens", requested_tokens)
                or requested_tokens
            )
            kwargs["max_tokens"] = min(requested_tokens, max(1, configured_tokens))

        response = await reviewer_llm.chat_completion(**kwargs)
        if chat_id > 0:
            try:
                from chatdome.agent.tracker import TokenTracker

                TokenTracker.record_usage(
                    chat_id=chat_id,
                    model=getattr(reviewer_llm, "model", "unknown"),
                    action=(
                        "command_detail_compact_retry"
                        if compact
                        else "command_detail"
                    ),
                    prompt_tokens=getattr(response, "prompt_tokens", 0),
                    completion_tokens=getattr(response, "completion_tokens", 0),
                    total_tokens=getattr(response, "total_tokens", 0),
                )
            except Exception:
                logger.debug(
                    "Failed to record command detail token usage",
                    exc_info=True,
                )

        try:
            parsed = LLMClient.parse_json_object(response.content or "")
            self._validate_command_detail_payload(parsed, len(segments))
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            raise _InvalidCommandDetailResponse(
                "invalid command detail response"
            ) from exc
        return parsed

    @staticmethod
    def _validate_command_detail_payload(
        payload: dict[str, Any],
        command_count: int,
    ) -> None:
        required_fields = {
            "safety_status",
            "risk_level",
            "mutation_detected",
            "deletion_detected",
            "impact_analysis",
            "command_breakdown",
        }
        if command_count < 1 or not isinstance(payload, dict):
            raise _InvalidCommandDetailResponse("invalid detail payload")
        if required_fields - payload.keys():
            raise _InvalidCommandDetailResponse("missing detail fields")

        safety_status = str(payload.get("safety_status", "")).strip().upper()
        if safety_status not in {"SAFE", "UNSAFE", "CRITICAL"}:
            raise _InvalidCommandDetailResponse("invalid safety status")
        risk_level = str(payload.get("risk_level", "")).strip().upper()
        if risk_level not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            raise _InvalidCommandDetailResponse("invalid risk level")

        mutation_detected = payload.get("mutation_detected")
        deletion_detected = payload.get("deletion_detected")
        if not isinstance(mutation_detected, bool):
            raise _InvalidCommandDetailResponse("invalid mutation flag")
        if not isinstance(deletion_detected, bool):
            raise _InvalidCommandDetailResponse("invalid deletion flag")
        if mutation_detected and safety_status == "SAFE":
            raise _InvalidCommandDetailResponse("inconsistent mutation status")
        if deletion_detected and not mutation_detected:
            raise _InvalidCommandDetailResponse("inconsistent deletion status")
        if deletion_detected and risk_level in {"LOW", "MEDIUM"}:
            raise _InvalidCommandDetailResponse("inconsistent deletion risk")
        if not str(payload.get("impact_analysis") or "").strip():
            raise _InvalidCommandDetailResponse("missing impact analysis")

        breakdown = payload.get("command_breakdown")
        if not isinstance(breakdown, dict):
            raise _InvalidCommandDetailResponse("missing command breakdown")

        raw_commands = breakdown.get("commands")
        if command_count == 1 and not isinstance(raw_commands, list):
            if not str(breakdown.get("base_cmd") or "").strip():
                raise _InvalidCommandDetailResponse("missing base command")
            if not str(breakdown.get("summary") or "").strip():
                raise _InvalidCommandDetailResponse("missing command summary")
            return
        if not isinstance(raw_commands, list):
            raise _InvalidCommandDetailResponse("missing command groups")
        if len(raw_commands) != command_count:
            raise _InvalidCommandDetailResponse("incomplete command groups")
        if not str(breakdown.get("summary") or "").strip():
            raise _InvalidCommandDetailResponse("missing breakdown summary")

        for position, item in enumerate(raw_commands, start=1):
            if not isinstance(item, dict):
                raise _InvalidCommandDetailResponse("invalid command group")
            try:
                index = int(item["index"])
            except (KeyError, TypeError, ValueError) as exc:
                raise _InvalidCommandDetailResponse("invalid command index") from exc
            if index != position:
                raise _InvalidCommandDetailResponse("out-of-order command groups")
            if not str(item.get("base_cmd") or "").strip():
                raise _InvalidCommandDetailResponse("missing base command")
            if not str(item.get("summary") or "").strip():
                raise _InvalidCommandDetailResponse("missing command summary")

    @classmethod
    def _merge_command_detail_batches(
        cls,
        *,
        command: str,
        segments: tuple[ShellCommandSegment, ...],
        batch_specs: list[tuple[int, tuple[ShellCommandSegment, ...]]],
        batch_results: dict[int, tuple[dict[str, Any], bool]],
        batch_errors: dict[int, str],
    ) -> dict[str, Any]:
        commands = []
        for index, segment in enumerate(segments, start=1):
            child = cls._minimal_command_breakdown("命令解析不可用")
            child.update(
                {
                    "index": index,
                    "command": segment.command,
                    "separator": segment.separator,
                }
            )
            commands.append(child)

        analyzed_command_count = 0
        analyses: list[dict[str, Any]] = []
        compact_used = False
        for offset, batch_segments in batch_specs:
            stored = batch_results.get(offset)
            if stored is None:
                continue
            analysis, compact = stored
            analyses.append(analysis)
            compact_used = compact_used or compact
            batch_commands = (
                analysis.get("command_breakdown", {}).get("commands", [])
            )
            for position, child in enumerate(batch_commands):
                if position >= len(batch_segments):
                    break
                normalized = dict(child)
                normalized.update(
                    {
                        "index": offset + position + 1,
                        "command": batch_segments[position].command,
                        "separator": batch_segments[position].separator,
                    }
                )
                commands[offset + position] = normalized
            analyzed_command_count += len(batch_segments)

        errors = [
            batch_errors[offset]
            for offset, _ in batch_specs
            if batch_errors.get(offset)
        ]
        errors = list(dict.fromkeys(errors))
        if not analyses:
            error_code = "timeout" if "timeout" in errors else (
                errors[0] if errors else "provider_error"
            )
            message = (
                "命令分析超时。请直接检查原始命令。"
                if error_code == "timeout"
                else "命令分析不可用。请直接检查原始命令。"
            )
            return cls._llm_detail_fallback(
                message,
                command,
                error_code=error_code,
            )

        safety_order = {"SAFE": 0, "UNSAFE": 1, "CRITICAL": 2}
        risk_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        safety_status = max(
            (str(item.get("safety_status", "UNSAFE")) for item in analyses),
            key=lambda value: safety_order.get(value, 1),
        )
        risk_level = max(
            (str(item.get("risk_level", "HIGH")) for item in analyses),
            key=lambda value: risk_order.get(value, 2),
        )
        mutation_detected = any(
            bool(item.get("mutation_detected", False))
            for item in analyses
        )
        deletion_detected = any(
            bool(item.get("deletion_detected", False))
            for item in analyses
        )

        detail_status = (
            "complete"
            if analyzed_command_count == len(segments)
            and not compact_used
            and not errors
            else "partial"
        )
        if detail_status == "partial":
            if safety_order.get(safety_status, 1) < safety_order["UNSAFE"]:
                safety_status = "UNSAFE"
            if risk_order.get(risk_level, 2) < risk_order["HIGH"]:
                risk_level = "HIGH"
            mutation_detected = True
        if compact_used and "compact_retry" not in errors:
            errors.append("compact_retry")

        impacts = list(
            dict.fromkeys(
                " ".join(str(item.get("impact_analysis") or "").split())
                for item in analyses
                if str(item.get("impact_analysis") or "").strip()
            )
        )
        impact_analysis = cls._limit_command_detail_text(
            "；".join(impacts) or "请直接检查原始命令。",
            400,
        )
        summaries = [
            str(item.get("command_breakdown", {}).get("summary") or "").strip()
            for item in analyses
        ]
        summary = cls._limit_command_detail_text(
            "；".join(item for item in summaries if item),
            400,
        )
        tokens = [item for child in commands for item in child["tokens"]]
        targets = [item for child in commands for item in child["targets"]]
        warnings = [item for child in commands for item in child["warnings"]]

        return {
            "safety_status": safety_status,
            "risk_level": risk_level,
            "mutation_detected": mutation_detected,
            "deletion_detected": deletion_detected,
            "impact_analysis": impact_analysis,
            "command_breakdown": {
                "summary": summary,
                "commands": commands,
                "tokens": tokens,
                "targets": targets,
                "warnings": warnings,
                "irreversible": any(
                    bool(child.get("irreversible", False))
                    for child in commands
                ),
            },
            "detail_status": detail_status,
            "reviewer_mode": (
                "llm" if detail_status == "complete" else "llm_partial"
            ),
            "reviewer_status": safety_status,
            "reviewer_risk_level": risk_level,
            "analyzed_command_count": analyzed_command_count,
            "command_count": len(segments),
            "detail_errors": errors,
        }

    @staticmethod
    def _limit_command_detail_text(value: Any, max_chars: int) -> str:
        text = " ".join(str(value or "").split())
        if len(text) <= max_chars:
            return text
        return text[: max_chars - 1].rstrip() + "…"

    @staticmethod
    def _apply_static_detail_floor(
        details: dict[str, Any],
        static_gate: dict[str, Any],
    ) -> dict[str, Any]:
        safety_order = {"SAFE": 0, "UNSAFE": 1, "CRITICAL": 2}
        risk_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        bounded = dict(details)
        safety_status = max(
            (
                str(bounded.get("safety_status", "UNSAFE")).strip().upper(),
                str(static_gate.get("safety_status", "UNSAFE")).strip().upper(),
            ),
            key=lambda value: safety_order.get(value, 1),
        )
        risk_level = max(
            (
                str(bounded.get("risk_level", "HIGH")).strip().upper(),
                str(static_gate.get("risk_level", "HIGH")).strip().upper(),
            ),
            key=lambda value: risk_order.get(value, 2),
        )
        mutation_detected = bool(
            bounded.get("mutation_detected", False)
        ) or bool(static_gate.get("mutation_detected", False))
        deletion_detected = bool(
            bounded.get("deletion_detected", False)
        ) or bool(static_gate.get("deletion_detected", False))
        if deletion_detected:
            mutation_detected = True
            if safety_order.get(safety_status, 1) < safety_order["UNSAFE"]:
                safety_status = "UNSAFE"
            if risk_order.get(risk_level, 2) < risk_order["HIGH"]:
                risk_level = "HIGH"

        bounded.update(
            {
                "safety_status": safety_status,
                "risk_level": risk_level,
                "mutation_detected": mutation_detected,
                "deletion_detected": deletion_detected,
                "reviewer_status": safety_status,
                "reviewer_risk_level": risk_level,
            }
        )
        return bounded

    @classmethod
    def _normalize_llm_command_details(
        cls,
        payload: dict[str, Any],
        segments: tuple[ShellCommandSegment, ...],
    ) -> dict[str, Any]:
        safety_status = str(payload.get("safety_status", "UNSAFE")).strip().upper()
        if safety_status not in {"SAFE", "UNSAFE", "CRITICAL"}:
            safety_status = "UNSAFE"

        risk_level = str(payload.get("risk_level", "HIGH")).strip().upper()
        if risk_level not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            risk_level = "HIGH"

        impact_analysis = cls._limit_command_detail_text(
            payload.get("impact_analysis") or "LLM 未返回影响说明。",
            _COMMAND_DETAIL_MAX_SUMMARY_CHARS,
        )
        breakdown = cls._normalize_llm_command_breakdown_groups(
            payload.get("command_breakdown"), segments
        )

        return {
            "safety_status": safety_status,
            "risk_level": risk_level,
            "mutation_detected": bool(payload.get("mutation_detected", False)),
            "deletion_detected": bool(payload.get("deletion_detected", False)),
            "impact_analysis": impact_analysis,
            "command_breakdown": breakdown,
            "reviewer_mode": "llm",
            "reviewer_status": safety_status,
            "reviewer_risk_level": risk_level,
        }

    @classmethod
    def _normalize_llm_command_breakdown(cls, raw: Any, command: str) -> dict[str, Any]:
        if not isinstance(raw, dict):
            return cls._minimal_command_breakdown("命令解析不可用")

        command_text = str(command or "")
        allowed_roles = {
            "command",
            "subcommand",
            "option",
            "argument",
            "target_file",
            "target_directory",
            "target_path",
            "target_service",
            "process",
            "url",
            "env",
            "operator",
            "unknown",
        }
        allowed_target_types = {"file", "directory", "path", "service", "process", "url", "package", "user", "other"}
        allowed_operations = {"read", "write", "delete", "modify", "execute", "network", "unknown"}

        raw_tokens = raw.get("tokens", [])
        if not isinstance(raw_tokens, list):
            raw_tokens = []
        tokens: list[dict[str, str]] = []
        for item in raw_tokens[:_COMMAND_DETAIL_MAX_TOKENS_PER_SEGMENT]:
            if not isinstance(item, dict):
                continue
            raw_token = str(item.get("token") or "").strip()
            if not raw_token or raw_token not in command_text:
                continue
            token = raw_token[:_COMMAND_DETAIL_MAX_TOKEN_CHARS]
            role = str(item.get("role") or "unknown").strip()
            if role not in allowed_roles:
                role = "unknown"
            label = cls._limit_command_detail_text(
                item.get("label") or role,
                _COMMAND_DETAIL_MAX_LABEL_CHARS,
            )
            meaning = cls._limit_command_detail_text(
                item.get("meaning") or label or "命令组成部分",
                _COMMAND_DETAIL_MAX_MEANING_CHARS,
            )
            tokens.append(
                {
                    "token": token,
                    "role": role,
                    "label": label,
                    "meaning": meaning,
                }
            )

        raw_targets = raw.get("targets", [])
        if not isinstance(raw_targets, list):
            raw_targets = []
        targets: list[dict[str, str]] = []
        for item in raw_targets[:_COMMAND_DETAIL_MAX_TARGETS_PER_SEGMENT]:
            if isinstance(item, str):
                item = {"value": item}
            if not isinstance(item, dict):
                continue
            raw_value = str(item.get("value") or "").strip()
            if not raw_value or raw_value not in command_text:
                continue
            value = raw_value[:_COMMAND_DETAIL_MAX_TOKEN_CHARS]
            target_type = str(item.get("type") or "other").strip()
            if target_type not in allowed_target_types:
                target_type = "other"
            operation = str(item.get("operation") or "unknown").strip()
            if operation not in allowed_operations:
                operation = "unknown"
            targets.append(
                {"value": value, "type": target_type, "operation": operation}
            )

        raw_warnings = raw.get("warnings", [])
        if not isinstance(raw_warnings, list):
            raw_warnings = []
        warnings = [
            cls._limit_command_detail_text(
                item,
                _COMMAND_DETAIL_MAX_WARNING_CHARS,
            )
            for item in raw_warnings[:_COMMAND_DETAIL_MAX_WARNINGS_PER_SEGMENT]
            if cls._limit_command_detail_text(item, _COMMAND_DETAIL_MAX_WARNING_CHARS)
        ]
        confidence = str(raw.get("confidence") or "medium").strip().lower()
        if confidence not in {"low", "medium", "high"}:
            confidence = "medium"

        return {
            "base_cmd": cls._limit_command_detail_text(
                raw.get("base_cmd"),
                _COMMAND_DETAIL_MAX_TOKEN_CHARS,
            ),
            "summary": cls._limit_command_detail_text(
                raw.get("summary"),
                _COMMAND_DETAIL_MAX_SUMMARY_CHARS,
            ),
            "tokens": tokens,
            "targets": targets,
            "warnings": warnings,
            "irreversible": bool(raw.get("irreversible", False)),
            "confidence": confidence,
        }

    @classmethod
    def _normalize_llm_command_breakdown_groups(
        cls,
        raw: Any,
        segments: tuple[ShellCommandSegment, ...],
    ) -> dict[str, Any]:
        payload = raw if isinstance(raw, dict) else {}
        raw_commands = payload.get("commands")
        commands_by_index: dict[int, dict[str, Any]] = {}

        if isinstance(raw_commands, list):
            for position, item in enumerate(raw_commands, start=1):
                if not isinstance(item, dict):
                    continue
                try:
                    index = int(item.get("index", position))
                except (TypeError, ValueError):
                    continue
                if 1 <= index <= len(segments) and index not in commands_by_index:
                    commands_by_index[index] = item
        elif len(segments) == 1 and payload:
            # Accept cached or mocked responses that use the legacy flat schema.
            commands_by_index[1] = payload

        commands: list[dict[str, Any]] = []
        for index, segment in enumerate(segments, start=1):
            item = commands_by_index.get(index)
            if item is None:
                normalized = cls._minimal_command_breakdown("命令解析不可用")
            else:
                normalized = cls._normalize_llm_command_breakdown(item, segment.command)
            normalized.update(
                {
                    "index": index,
                    "command": segment.command,
                    "separator": segment.separator,
                }
            )
            commands.append(normalized)

        tokens = [item for child in commands for item in child["tokens"]]
        targets = [item for child in commands for item in child["targets"]]
        warnings = [item for child in commands for item in child["warnings"]]
        summary = cls._limit_command_detail_text(
            payload.get("summary"),
            _COMMAND_DETAIL_MAX_SUMMARY_CHARS,
        )
        if not summary and len(commands) == 1:
            summary = commands[0]["summary"]

        return {
            "summary": summary,
            "commands": commands,
            "tokens": tokens,
            "targets": targets,
            "warnings": warnings,
            "irreversible": any(child["irreversible"] for child in commands),
        }

    @staticmethod
    def _minimal_command_breakdown(summary: str) -> dict[str, Any]:
        return {
            "base_cmd": "",
            "summary": summary,
            "tokens": [],
            "targets": [],
            "warnings": [],
            "irreversible": False,
            "confidence": "low",
        }

    @classmethod
    def _llm_detail_fallback(
        cls,
        message: str,
        command: str = "",
        *,
        error_code: str = "unavailable",
    ) -> dict[str, Any]:
        segments = split_shell_commands(command)
        return {
            "safety_status": "UNSAFE",
            "risk_level": "HIGH",
            "mutation_detected": True,
            "deletion_detected": False,
            "impact_analysis": cls._limit_command_detail_text(message, 400),
            "command_breakdown": cls._normalize_llm_command_breakdown_groups(
                {},
                segments,
            ),
            "detail_status": "failed",
            "reviewer_mode": "llm_error",
            "reviewer_status": "UNSAFE",
            "reviewer_risk_level": "HIGH",
            "analyzed_command_count": 0,
            "command_count": len(segments),
            "detail_errors": [error_code],
        }

    @staticmethod
    def _has_delete_intent(command: str) -> bool:
        """Lightweight lexical detector for delete/destructive intent."""
        text = f" {str(command or '').lower()} "
        tokens = (" rm ", " rmdir ", " del ", " unlink ", " shred ", " wipe ")
        return any(tok in text for tok in tokens)

    @staticmethod
    def _build_initial_impact_summary(analysis: dict[str, Any]) -> str:
        """Return the neutral first-card summary used before details are opened."""
        return "待确认操作。查看详情后决定是否执行。"

    async def _handle_whois_lookup(self, args: dict[str, Any]) -> str:
        """Look up IP geolocation via ipwho.is (HTTPS)."""
        ip = args.get("ip", "")
        if not ip:
            return "缺少 IP 地址参数"

        try:
            client = await self._get_http_client()
            response = await client.get(f"https://ipwho.is/{ip}")
            data = response.json()

            if not data.get("success", False):
                return f"IP 查询失败: {data.get('message', '未知错误')}"

            connection = data.get("connection", {})
            asn = connection.get("asn", "")
            org = connection.get("org", "未知")
            as_display = f"AS{asn} {org}" if asn else org

            lines = [
                f"IP: {data.get('ip', ip)}",
                f"国家: {data.get('country', '未知')}",
                f"地区: {data.get('region', '未知')}",
                f"城市: {data.get('city', '未知')}",
                f"ISP: {connection.get('isp', '未知')}",
                f"组织: {org}",
                f"AS: {as_display}",
            ]
            return "\n".join(lines)

        except httpx.TimeoutException:
            return f"IP 查询超时: {ip}"
        except Exception as e:
            logger.error("Whois lookup failed for %s: %s", ip, e)
            return f"IP 查询异常: {e}"

    async def _handle_add_user_context(self, args: dict[str, Any]) -> str:
        """Handle adding user context overrides to prevent Sentinel false alarms."""
        if not self.user_context_ledger:
            return "内部错误: 暂不支持用户上下文功能，UserContextLedger 未初始化。"

        check_id = str(args.get("check_id", "")).strip()
        pattern = str(args.get("pattern", "")).strip()
        summary = str(args.get("summary", "")).strip()

        if not check_id or not summary:
            return "参数错误: check_id 和 summary 是必填字段。"

        try:
            self.user_context_ledger.add_context(check_id, pattern, summary)
            lines = [
                f"成功: 已将用户上下文 (check_id={check_id}, pattern='{pattern}') 写入 ledger，后续匹配时将自动静默。",
                f"摘要: {summary}",
            ]
            engram_args = self._build_engram_from_user_context(check_id, pattern, summary)
            if engram_args:
                lines.append("Engram 同步: " + self._handle_save_engram(engram_args))
            return "\n".join(lines)
        except Exception as e:
            return f"写入用户上下文失败: {e}"

    def _build_engram_from_user_context(
        self,
        check_id: str,
        pattern: str,
        summary: str,
    ) -> dict[str, str] | None:
        if not self.engram_store:
            return None
        normalized_summary = " ".join(summary.split()).strip()
        if not self._is_durable_user_context(check_id, pattern, normalized_summary):
            return None

        category = self._classify_user_context_engram(check_id, pattern, normalized_summary)
        fact = self._normalize_user_context_fact(pattern, normalized_summary)
        return {
            "category": category,
            "fact": fact,
            "source_context": (
                "用户通过 Sentinel 告警确认: "
                f"check_id={check_id}, pattern={pattern or 'all'}, summary={normalized_summary}"
            ),
        }

    def _is_durable_user_context(self, check_id: str, pattern: str, summary: str) -> bool:
        text = f"{check_id} {pattern} {summary}".lower()
        if not text.strip():
            return False

        has_long_term_signal = self._contains_any(text, _LONG_TERM_CONTEXT_SIGNALS)
        has_transient_signal = self._contains_any(text, _TRANSIENT_CONTEXT_SIGNALS)
        if has_transient_signal and not has_long_term_signal:
            return False

        has_identity_signal = self._contains_any(text, _IDENTITY_CONTEXT_SIGNALS)
        has_behavior_signal = self._contains_any(text, _BEHAVIOR_CONTEXT_SIGNALS)
        has_topology_signal = self._contains_any(text, _TOPOLOGY_CONTEXT_SIGNALS)
        has_environment_signal = self._contains_any(text, _ENVIRONMENT_CONTEXT_SIGNALS)
        has_declarative_signal = any(token in summary for token in ("是", "属于", "用于", "对应", "负责", "作为"))

        return (
            has_long_term_signal
            or (has_declarative_signal and (has_identity_signal or has_behavior_signal or has_topology_signal or has_environment_signal))
            or (has_identity_signal and (has_behavior_signal or has_topology_signal))
        )

    def _classify_user_context_engram(self, check_id: str, pattern: str, summary: str) -> str:
        text = f"{check_id} {pattern} {summary}".lower()
        if self._contains_any(text, _CONSTRAINT_CONTEXT_SIGNALS):
            return "constraint"
        if self._contains_any(text, _PREFERENCE_CONTEXT_SIGNALS):
            return "preference"
        if self._contains_any(text, _BEHAVIOR_CONTEXT_SIGNALS):
            return "behavior"
        if check_id in _TOPOLOGY_CONTEXT_CHECKS or self._contains_any(text, _TOPOLOGY_CONTEXT_SIGNALS):
            return "topology"
        if self._contains_any(text, _ENVIRONMENT_CONTEXT_SIGNALS):
            return "environment"
        return "behavior"

    def _normalize_user_context_fact(self, pattern: str, summary: str) -> str:
        fact = summary
        if fact.startswith("用户确认"):
            fact = fact.replace("用户确认", "", 1).strip()
        fact = fact.replace("是其", "是用户的", 1)
        fact = fact.replace("属于本人操作", "属于用户本人操作", 1)
        if pattern and pattern not in fact:
            fact = f"{pattern}: {fact}"
        return fact

    @staticmethod
    def _contains_any(text: str, keywords: tuple[str, ...]) -> bool:
        return any(keyword.lower() in text for keyword in keywords)

    # ----- Formatting -----

    @staticmethod
    def _format_command_result(result: CommandResult) -> str:
        """Format a CommandResult into a string for the LLM."""
        parts = []

        if result.command:
            parts.append(f"[命令] {result.command}")

        if result.timed_out:
            parts.append("[状态] 执行超时")
        elif result.return_code is not None:
            parts.append(f"[状态] 退出码: {result.return_code}")

        if result.stdout:
            parts.append(f"[输出]\n{result.stdout}")
        elif result.stderr:
            parts.append(f"[错误]\n{result.stderr}")
        else:
            parts.append("[输出] (无输出)")

        if result.truncated:
            parts.append("[注意] 输出已截断")

        return "\n".join(parts)
