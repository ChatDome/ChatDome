"""Plain-text fallback rendering for platforms without interactive controls."""

from __future__ import annotations

from chatdome.outbound.models import (
    ActionKind,
    ApprovalDetailsFacts,
    ApprovalRequestFacts,
    OutboundMessage,
    OutboundMessageKind,
    RenderedMessage,
)
from chatdome.outbound.renderers.common import compact_approval_purpose, compact_impact


class PlainTextOutboundRenderer:
    def render(self, message: OutboundMessage) -> RenderedMessage:
        if message.kind == OutboundMessageKind.APPROVAL_REQUEST:
            facts = message.facts
            if not isinstance(facts, ApprovalRequestFacts):
                raise TypeError("approval request facts are required")
            purpose = compact_approval_purpose(
                facts.reason,
                fallback="信息不可用，请先查看命令分析。",
            )
            lines = ["待审批", f"目的：{purpose}"]
            action_kinds = {action.kind for action in message.actions}
            if ActionKind.APPROVE in action_kinds:
                lines.append("回复 /confirm 允许，或 /reject 拒绝。")
            elif ActionKind.REJECT in action_kinds:
                lines.append("回复 /reject 拒绝。")
            if facts.details_available:
                lines.append("发送 /details 查看命令分析。")
            return RenderedMessage(text_parts=("\n".join(lines),))
        if message.kind == OutboundMessageKind.APPROVAL_DETAILS:
            facts = message.facts
            if not isinstance(facts, ApprovalDetailsFacts):
                raise TypeError("approval details facts are required")
            if not facts.ok:
                return RenderedMessage(
                    text_parts=(f"ℹ️ {facts.error_message or '没有待审批操作。'}",)
                )

            purpose = compact_approval_purpose(facts.reason, fallback="")
            if facts.detail_status == "failed":
                lines = ["⚠️ 命令分析不可用"]
                if purpose:
                    lines.append(f"目的：{purpose}")
                lines.extend(
                    ["请核对原始命令后决定是否允许。", f"命令：{facts.command or '(empty)'}"]
                )
            else:
                if facts.detail_status == "partial":
                    lines = ["⚠️ 命令分析部分可用"]
                    if facts.command_count:
                        lines.append(
                            f"已分析 {facts.analyzed_command_count}/{facts.command_count} 个子命令，"
                            "请核对未分析部分。"
                        )
                    else:
                        lines.append("部分子命令未完成分析，请核对原始命令。")
                else:
                    lines = ["🔎 命令审批详情"]
                lines.extend(
                    [
                        f"目的：{purpose or '信息不可用'}",
                        f"风险等级：{facts.risk_level or 'unknown'} | 安全状态：{facts.safety_status or 'unknown'}",
                        f"命令：{facts.command or '(empty)'}",
                        f"影响：{compact_impact(facts.impact_analysis, full=False)}",
                    ]
                )
            action_kinds = {action.kind for action in message.actions}
            if ActionKind.APPROVE in action_kinds:
                lines.append("回复 /confirm 允许，或 /reject 拒绝。")
            return RenderedMessage(text_parts=("\n".join(lines),))
        return RenderedMessage(text_parts=((message.body or message.summary),))
