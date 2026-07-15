"""Telegram rendering for unified outbound messages."""

from __future__ import annotations

from collections import defaultdict
from typing import DefaultDict, List

from chatdome.outbound.models import (
    ActionKind,
    ApprovalDetailsFacts,
    ApprovalRequestFacts,
    CodexAuthorizationFacts,
    EnvironmentFacts,
    ModelProfilesFacts,
    OutboundAction,
    OutboundMessage,
    OutboundMessageKind,
    RenderedControl,
    RenderedMessage,
)
from chatdome.outbound.renderers.common import compact_approval_purpose, compact_impact


_ACTION_LABELS = {
    ActionKind.APPROVE: "✅ 允许",
    ActionKind.APPROVE_TASK: "✅ 本次任务允许",
    ActionKind.REJECT: "❌ 拒绝",
    ActionKind.SHOW_DETAILS: "🔎 命令分析",
    ActionKind.CONTINUE: "▶️ 继续执行",
    ActionKind.STOP: "🛑 放弃任务",
}

_CALLBACK_ACTIONS = {
    ActionKind.APPROVE: "approve",
    ActionKind.APPROVE_TASK: "approve_task",
    ActionKind.REJECT: "reject",
    ActionKind.SHOW_DETAILS: "details",
}


class TelegramOutboundRenderer:
    def __init__(self, *, full: bool = False):
        self.full = full

    @staticmethod
    def _control(action: OutboundAction, row: int) -> RenderedControl:
        callback_action = _CALLBACK_ACTIONS.get(action.kind, action.kind.value)
        token = str(action.token or "").strip()
        data = f"approval:{callback_action}:{token}" if token else callback_action
        return RenderedControl(
            kind=action.kind,
            label=_ACTION_LABELS.get(action.kind, action.label),
            data=data,
            row=row,
            destructive=action.destructive,
        )

    def _approval_controls(self, message: OutboundMessage) -> tuple[RenderedControl, ...]:
        rows = {
            ActionKind.APPROVE: 0,
            ActionKind.APPROVE_TASK: 0,
            ActionKind.REJECT: 1,
            ActionKind.SHOW_DETAILS: 1,
        }
        return tuple(self._control(action, rows.get(action.kind, 0)) for action in message.actions)

    def _render_request(self, message: OutboundMessage) -> RenderedMessage:
        facts = message.facts
        if not isinstance(facts, ApprovalRequestFacts):
            raise TypeError("approval request facts are required")
        purpose = compact_approval_purpose(
            facts.reason,
            fallback="信息不可用，请先查看命令分析。",
        )
        lines = ["⚠️ 待审批", f"目的：{purpose}"]
        if any(action.kind == ActionKind.APPROVE for action in message.actions):
            lines.extend(["是否允许本次操作？", "点击“命令分析”查看详情。"])
        elif any(action.kind == ActionKind.SHOW_DETAILS for action in message.actions):
            lines.append("请先查看命令分析，再决定是否允许。")
        else:
            lines.append("审批信息不完整，无法处理。")
        return RenderedMessage(
            text_parts=("\n".join(lines),),
            controls=self._approval_controls(message),
        )

    @staticmethod
    def _breakdown_lines(facts: ApprovalDetailsFacts) -> List[str]:
        lines: List[str] = []
        for index, item in enumerate(facts.command_breakdown):
            has_more = index < len(facts.command_breakdown) - 1 or bool(facts.warnings)
            prefix = "├" if has_more else "└"
            lines.append(f"{prefix} {item.token} → {item.meaning}")
        lines.extend(f"⚠ {warning}" for warning in facts.warnings)
        return lines

    def _render_details(self, message: OutboundMessage) -> RenderedMessage:
        facts = message.facts
        if not isinstance(facts, ApprovalDetailsFacts):
            raise TypeError("approval details facts are required")
        if not facts.ok:
            return RenderedMessage(text_parts=(f"ℹ️ {facts.error_message or '没有待审批操作。'}",))

        flags = []
        if facts.mutation_detected:
            flags.append("修改系统")
        if facts.deletion_detected:
            flags.append("删除文件")
        impact = compact_impact(facts.impact_analysis, full=self.full)
        lines = [
            "🔎 命令审批详情",
            "",
            "🛡 安全评估",
            f"风险等级: {facts.risk_level or 'unknown'} | 安全状态: {facts.safety_status or 'unknown'}",
        ]
        if flags:
            lines.append(f"标记: {' · '.join(flags)}")
        lines.extend(["", "📋 命令", facts.command or "(empty)"])
        breakdown = self._breakdown_lines(facts)
        if breakdown:
            lines.extend(["", "命令解析:", *breakdown])
        lines.extend(["", "💥 影响说明", impact])
        return RenderedMessage(
            text_parts=("\n".join(lines),),
            controls=self._approval_controls(message),
        )
    @staticmethod
    def _short_commands(items: tuple[str, ...], limit: int = 14) -> str:
        if not items:
            return "none"
        visible = ", ".join(items[:limit])
        if len(items) > limit:
            visible += f" ... (+{len(items) - limit} more)"
        return visible

    def _render_environment(self, facts: EnvironmentFacts) -> RenderedMessage:
        if not facts.available:
            return RenderedMessage(
                text_parts=(
                    f"?? {facts.error_message}\n??? ChatDome ?????????",
                )
            )
        lines = [
            "?? ????????",
            "",
            f"????(UTC): {facts.collected_at_utc}",
            "",
            "????:",
            f"- OS family: {facts.os_family}",
            f"- OS release: {facts.os_release}",
            f"- OS version: {facts.os_version}",
            f"- Machine: {facts.machine}",
            f"- Python: {facts.python_version}",
            f"- Shell: {facts.shell}",
            f"- Linux distro: {facts.linux_distro}",
            f"- WSL: {facts.is_wsl}",
            "",
            "????(??):",
            f"- Available: {self._short_commands(facts.available_commands)}",
            f"- Missing: {self._short_commands(facts.missing_commands)}",
        ]
        return RenderedMessage(text_parts=("\n".join(lines),))

    @staticmethod
    def _render_model_profiles(facts: ModelProfilesFacts) -> RenderedMessage:
        if not facts.profiles:
            return RenderedMessage(
                text_parts=("No model is configured. Run /model_add.",)
            )
        lines = [
            "Model profiles",
            "",
            f"Active: {facts.active_profile}",
            "Switch: /model <profile>",
            "",
            "Profiles:",
        ]
        for profile in facts.profiles:
            suffix = "  (current)" if profile.active else ""
            lines.append(f"  /model {profile.name}{suffix}")
        lines.extend(["", "Details:"])
        for profile in facts.profiles:
            marker = "active" if profile.active else "available"
            lines.extend(
                [
                    f"[{marker}] {profile.name}",
                    f"  Status: {profile.status}",
                    f"  Type: {profile.provider}/{profile.api_mode}",
                    f"  Model: {profile.model}",
                ]
            )
            if profile.base_url:
                lines.append(f"  Base URL: {profile.base_url}")
            if profile.key_ref:
                lines.append(f"  Key: {profile.key_ref}")
            lines.append("")
        return RenderedMessage(text_parts=("\n".join(lines).rstrip(),))

    @staticmethod
    def _render_codex_authorization(
        facts: CodexAuthorizationFacts,
    ) -> RenderedMessage:
        minutes = max(1, facts.expires_in // 60)
        text = "\n".join(
            [
                "?? OpenAI Codex ??",
                "",
                f"Profile: {facts.profile_name}",
                f"????: {facts.verification_uri}",
                f"?????: {facts.user_code}",
                f"???: {minutes} ??",
                "?????????????",
            ]
        )
        return RenderedMessage(text_parts=(text,))


    def render(self, message: OutboundMessage) -> RenderedMessage:
        if isinstance(message.facts, EnvironmentFacts):
            return self._render_environment(message.facts)
        if isinstance(message.facts, ModelProfilesFacts):
            return self._render_model_profiles(message.facts)
        if isinstance(message.facts, CodexAuthorizationFacts):
            return self._render_codex_authorization(message.facts)
        if message.kind == OutboundMessageKind.APPROVAL_REQUEST:
            return self._render_request(message)
        if message.kind == OutboundMessageKind.APPROVAL_DETAILS:
            return self._render_details(message)
        return RenderedMessage(text_parts=((message.body or message.summary),))


def group_controls(controls: tuple[RenderedControl, ...]) -> List[List[RenderedControl]]:
    """Keep renderer-selected rows while preserving control order."""
    grouped: DefaultDict[int, List[RenderedControl]] = defaultdict(list)
    for control in controls:
        grouped[control.row].append(control)
    return [grouped[row] for row in sorted(grouped)]
