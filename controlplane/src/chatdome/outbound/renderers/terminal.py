"""Terminal rendering for unified outbound messages."""

from __future__ import annotations

from typing import Any, List

from chatdome.outbound.models import (
    ActionKind,
    ApprovalDetailsFacts,
    ApprovalRequestFacts,
    OutboundMessage,
    OutboundMessageKind,
    RenderedMessage,
)
from chatdome.outbound.renderers.common import (
    compact_approval_purpose,
    compact_impact,
    reason_adds_context,
)


class TerminalOutboundRenderer:
    def __init__(self, *, ascii_mode: bool = False, full: bool = False):
        self.ascii_mode = ascii_mode
        self.full = full

    def _status(self, emoji: str, fallback: str, text: str) -> str:
        return f"{fallback if self.ascii_mode else emoji} {text}"

    @staticmethod
    def _indent(value: Any, max_chars: int = 3000) -> str:
        text = str(value or "").strip()
        if len(text) > max_chars:
            text = text[: max_chars - 20].rstrip() + "\n... (truncated)"
        return "\n".join(f"  {line}" for line in text.splitlines()) if text else "  (empty)"

    def _action_prompt(self, message: OutboundMessage, *, include_details: bool) -> str:
        kinds = {action.kind for action in message.actions}
        if ActionKind.APPROVE in kinds:
            return "Allow operation? [y/n]  d=details" if include_details else "Allow operation? [y/n]"
        if ActionKind.SHOW_DETAILS in kinds:
            return "Review command analysis before approval.  n=reject  d=details"
        return "Approval unavailable."

    def _render_request(self, message: OutboundMessage) -> RenderedMessage:
        facts = message.facts
        if not isinstance(facts, ApprovalRequestFacts):
            raise TypeError("approval request facts are required")
        purpose = compact_approval_purpose(
            facts.reason,
            fallback="Unavailable; review details before approval.",
        )
        text = "\n".join(
            [
                self._status("⚠️", "[!]", "Approval required"),
                f"Purpose: {purpose}",
                self._action_prompt(message, include_details=facts.details_available),
            ]
        )
        return RenderedMessage(text_parts=(text,))

    def _breakdown_lines(self, facts: ApprovalDetailsFacts) -> List[str]:
        if not facts.command_breakdown:
            return []
        arrow = "->" if self.ascii_mode else "→"
        warning_prefix = "[!]" if self.ascii_mode else "⚠"
        token_width = min(max(len(item.token) for item in facts.command_breakdown), 28)
        lines = ["命令解析:"]
        for item in facts.command_breakdown:
            padded = item.token if len(item.token) > token_width else item.token.ljust(token_width)
            lines.append(f"  {padded} {arrow} {item.meaning}")
        lines.extend(f"  {warning_prefix} {warning}" for warning in facts.warnings)
        return lines

    def _render_details(self, message: OutboundMessage) -> RenderedMessage:
        facts = message.facts
        if not isinstance(facts, ApprovalDetailsFacts):
            raise TypeError("approval details facts are required")
        if not facts.ok:
            text = self._status("ℹ️", "[i]", facts.error_message or "No pending approval.")
            return RenderedMessage(text_parts=(text,))

        risk = facts.risk_level or "unknown"
        safety = facts.safety_status or "unknown"
        impact = compact_impact(
            facts.impact_analysis,
            full=self.full,
            suffix="... Run /details full for full analysis.",
        )
        flags = []
        if facts.mutation_detected:
            flags.append("modifies system")
        if facts.deletion_detected:
            flags.append("deletes files")

        lines = [self._status("🔎", "[details]", "Approval details")]
        lines.append(f"Risk: {risk}    Safety: {safety}")
        if flags:
            lines.append(f"Flags: {', '.join(flags)}")
        if self.full and reason_adds_context(facts.reason, facts.impact_analysis):
            lines.extend(["", "Reason:", self._indent(facts.reason, max_chars=1600)])
        lines.extend(["", "Command:", "```bash", facts.command or "(empty)", "```"])
        breakdown = self._breakdown_lines(facts)
        if breakdown:
            lines.extend(["", *breakdown])
        lines.extend(["", "Impact:", self._indent(impact, max_chars=4000), ""])
        lines.append(self._action_prompt(message, include_details=False))
        return RenderedMessage(text_parts=("\n".join(lines),))

    def render(self, message: OutboundMessage) -> RenderedMessage:
        if message.kind == OutboundMessageKind.APPROVAL_REQUEST:
            return self._render_request(message)
        if message.kind == OutboundMessageKind.APPROVAL_DETAILS:
            return self._render_details(message)
        if message.kind == OutboundMessageKind.TASK_PAUSED:
            return RenderedMessage(text_parts=(f"{message.summary}\nContinue? [y/n]",))
        return RenderedMessage(text_parts=((message.body or message.summary),))
