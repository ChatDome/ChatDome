"""Plain-text fallback rendering for platforms without interactive controls."""

from __future__ import annotations

from chatdome.outbound.models import (
    ActionKind,
    ApprovalRequestFacts,
    OutboundMessage,
    OutboundMessageKind,
    RenderedMessage,
)
from chatdome.outbound.renderers.common import compact_approval_purpose


class PlainTextOutboundRenderer:
    def render(self, message: OutboundMessage) -> RenderedMessage:
        if message.kind == OutboundMessageKind.APPROVAL_REQUEST:
            facts = message.facts
            if not isinstance(facts, ApprovalRequestFacts):
                raise TypeError("approval request facts are required")
            approval_id = str(message.refs.get("approval_id", "")).strip()
            purpose = compact_approval_purpose(
                facts.reason,
                fallback="信息不可用，请先查看命令分析。",
            )
            lines = [f"待审批 {approval_id}".rstrip(), f"目的：{purpose}"]
            action_kinds = {action.kind for action in message.actions}
            if approval_id and ActionKind.APPROVE in action_kinds:
                lines.append(f"回复 /confirm {approval_id} 允许，或 /reject {approval_id} 拒绝。")
            elif approval_id and ActionKind.REJECT in action_kinds:
                lines.append(f"回复 /reject {approval_id} 拒绝。")
            if approval_id and facts.details_available:
                lines.append(f"发送 /details {approval_id} 查看命令分析。")
            return RenderedMessage(text_parts=("\n".join(lines),))
        return RenderedMessage(text_parts=((message.body or message.summary),))
