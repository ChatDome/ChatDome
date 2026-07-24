"""Telegram rendering for unified outbound messages."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from typing import DefaultDict, List

from chatdome.outbound.models import (
    ActionKind,
    ApprovalDetailsFacts,
    ApprovalRequestFacts,
    CodexAuthorizationFacts,
    CommandEchoFacts,
    CommandHelpFacts,
    EnvironmentFacts,
    ModelProfilesFacts,
    OutboundAction,
    OutboundMessage,
    OutboundMessageKind,
    RenderedControl,
    RenderedMessage,
    SessionControlFacts,
    TokenUsageFacts,
)
from chatdome.outbound.renderers.common import compact_approval_purpose, compact_impact


_ACTION_LABELS = {
    ActionKind.APPROVE: "✅ 允许",
    ActionKind.APPROVE_TASK: "✅ 本次任务允许",
    ActionKind.REJECT: "❌ 拒绝",
    ActionKind.ANALYZE: "🤖 告警分析",
    ActionKind.SHOW_DETAILS: "🔎 命令分析",
    ActionKind.CONTINUE: "▶️ 继续执行",
    ActionKind.STOP: "🛑 放弃任务",
    ActionKind.SELECT: "Select",
    ActionKind.CONFIRM: "Confirm",
    ActionKind.CANCEL: "Cancel",
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
    def _grouped_breakdown_lines(facts: ApprovalDetailsFacts) -> List[str]:
        show_headings = len(facts.command_groups) > 1
        lines: List[str] = []
        for position, group in enumerate(facts.command_groups):
            if position and show_headings:
                lines.append("")
            if show_headings:
                separator = f" {group.separator}" if group.separator else ""
                lines.append(f"[{group.index}] {group.command}{separator}")
            for index, item in enumerate(group.items):
                has_more = index < len(group.items) - 1 or bool(group.warnings)
                prefix = "├" if has_more else "└"
                lines.append(f"{prefix} {item.token} → {item.meaning}")
            if not group.items and group.summary:
                prefix = "├" if group.warnings else "└"
                lines.append(f"{prefix} {group.summary}")
            lines.extend(f"⚠ {warning}" for warning in group.warnings)
        return lines

    @staticmethod
    def _breakdown_lines(facts: ApprovalDetailsFacts) -> List[str]:
        if facts.command_groups:
            return TelegramOutboundRenderer._grouped_breakdown_lines(facts)
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

        purpose = compact_approval_purpose(facts.reason, fallback="")
        if facts.detail_status == "failed":
            lines = ["⚠️ 命令分析不可用"]
            if purpose:
                lines.extend(["", f"目的：{purpose}"])
            lines.extend(
                [
                    "请核对原始命令后决定是否允许。",
                    "",
                    "📋 命令",
                    facts.command or "(empty)",
                ]
            )
            return RenderedMessage(
                text_parts=("\n".join(lines),),
                controls=self._approval_controls(message),
            )

        flags = []
        if facts.mutation_detected:
            flags.append("修改系统")
        if facts.deletion_detected:
            flags.append("删除文件")
        full = self.full or bool(message.presentation.get("full"))
        impact = compact_impact(facts.impact_analysis, full=full)
        if facts.detail_status == "partial":
            if facts.command_count:
                notice = (
                    f"已分析 {facts.analyzed_command_count}/{facts.command_count} 个子命令，"
                    "请核对未分析部分。"
                )
            else:
                notice = "部分子命令未完成分析，请核对原始命令。"
            lines = ["⚠️ 命令分析部分可用", notice, ""]
        else:
            lines = ["🔎 命令审批详情", ""]
        lines.extend(
            [
                f"目的：{purpose or '信息不可用'}",
                "",
                "🛡 安全评估",
                f"风险等级: {facts.risk_level or 'unknown'} | 安全状态: {facts.safety_status or 'unknown'}",
            ]
        )
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
                    f"ℹ️ {facts.error_message}\n运行 chatdome doctor 检查环境。",
                )
            )
        lines = [
            "🖥 ChatDome 运行环境",
            "",
            f"采集时间（UTC）：{facts.collected_at_utc}",
            "",
            "主机信息：",
            f"- OS family: {facts.os_family}",
            f"- OS release: {facts.os_release}",
            f"- OS version: {facts.os_version}",
            f"- Machine: {facts.machine}",
            f"- Python: {facts.python_version}",
            f"- Shell: {facts.shell}",
            f"- Linux distro: {facts.linux_distro}",
            f"- WSL: {facts.is_wsl}",
            "",
            "命令可用性（摘要）：",
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
                "🔐 OpenAI Codex 授权",
                "",
                f"Profile: {facts.profile_name}",
                f"授权地址：{facts.verification_uri}",
                f"设备验证码：{facts.user_code}",
                f"有效期：{minutes} 分钟",
                "请在浏览器中完成授权。",
            ]
        )
        return RenderedMessage(text_parts=(text,))

    @staticmethod
    def _render_help(facts: CommandHelpFacts) -> RenderedMessage:
        lines = ["可用命令："]
        for command in facts.commands:
            aliases = f"（{', '.join(command.aliases)}）" if command.aliases else ""
            lines.append(f"{command.usage}{aliases}  {command.description}")
        return RenderedMessage(text_parts=("\n".join(lines),))

    @staticmethod
    def _render_session_control(
        facts: SessionControlFacts,
    ) -> RenderedMessage:
        if facts.operation == "clear_session":
            text = "✅ 对话已重置。" if facts.changed else "ℹ️ 当前没有活跃的对话。"
        else:
            text = "⏹️ 任务已停止。" if facts.changed else "ℹ️ 当前没有运行中的任务。"
        return RenderedMessage(text_parts=(text,))

    @staticmethod
    def _render_token_usage(facts: TokenUsageFacts) -> RenderedMessage:
        return RenderedMessage(
            text_parts=(
                "\n".join(
                    [
                        "📊 Token 资源消耗统计",
                        "",
                        f"用户 ID: {facts.chat_id}",
                        f"Prompt: {facts.prompt_tokens:,} Tokens",
                        f"Completion: {facts.completion_tokens:,} Tokens",
                        f"Total: {facts.total_tokens:,} Tokens",
                    ]
                ),
            )
        )

    @staticmethod
    def _render_command_echo(facts: CommandEchoFacts) -> RenderedMessage:
        state = "已开启" if facts.enabled else "已关闭"
        return RenderedMessage(text_parts=(f"🔍 命令回显{state}。",))

    @staticmethod
    def _render_task_paused(message: OutboundMessage) -> RenderedMessage:
        facts = message.facts if isinstance(message.facts, Mapping) else {}
        rounds = int(facts.get("rounds") or 0)
        window = int(facts.get("window") or 0)
        lines = [f"当前任务已执行 {rounds} 轮，尚未完成。"]
        if window:
            lines.append(f"是否继续执行，再运行 {window} 轮？")
        else:
            lines.append("是否继续执行？")
        controls = []
        for action in message.actions:
            if action.kind == ActionKind.CONTINUE:
                data = "continue_round_task"
            elif action.kind == ActionKind.STOP:
                data = "abandon_round_task"
            else:
                continue
            controls.append(
                RenderedControl(
                    kind=action.kind,
                    label=_ACTION_LABELS[action.kind],
                    data=data,
                    row=0,
                    destructive=action.destructive,
                )
            )
        return RenderedMessage(
            text_parts=("\n".join(lines),),
            controls=tuple(controls),
        )


    @staticmethod
    def _render_operation(message: OutboundMessage) -> RenderedMessage:
        controls = tuple(
            RenderedControl(
                kind=action.kind,
                label=action.label,
                data=str(action.token or action.kind.value),
                row=(
                    0
                    if action.kind in {
                        ActionKind.SELECT,
                        ActionKind.SHOW_DETAILS,
                        ActionKind.ANALYZE,
                    }
                    else 1
                ),
                destructive=action.destructive,
            )
            for action in message.actions
        )
        return RenderedMessage(
            text_parts=((message.body or message.summary),),
            controls=controls,
        )

    def render(self, message: OutboundMessage) -> RenderedMessage:
        if isinstance(message.facts, CommandHelpFacts):
            return self._render_help(message.facts)
        if isinstance(message.facts, SessionControlFacts):
            return self._render_session_control(message.facts)
        if isinstance(message.facts, TokenUsageFacts):
            return self._render_token_usage(message.facts)
        if isinstance(message.facts, CommandEchoFacts):
            return self._render_command_echo(message.facts)
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
        if message.kind == OutboundMessageKind.TASK_PAUSED:
            return self._render_task_paused(message)
        if message.actions:
            return self._render_operation(message)
        return RenderedMessage(text_parts=((message.body or message.summary),))


def group_controls(controls: tuple[RenderedControl, ...]) -> List[List[RenderedControl]]:
    """Keep renderer-selected rows while preserving control order."""
    grouped: DefaultDict[int, List[RenderedControl]] = defaultdict(list)
    for control in controls:
        grouped[control.row].append(control)
    return [grouped[row] for row in sorted(grouped)]
