"""Terminal rendering for unified outbound messages."""

from __future__ import annotations

from typing import Any, List

from chatdome.outbound.models import (
    ActionKind,
    ApprovalDetailsFacts,
    ApprovalRequestFacts,
    CodexAuthorizationFacts,
    CommandEchoFacts,
    CommandHelpFacts,
    EnvironmentFacts,
    ModelProfilesFacts,
    OutboundMessage,
    OutboundMessageKind,
    RenderedMessage,
    SessionControlFacts,
    TokenUsageFacts,
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
            prompts = ["Allow operation? [y/n]"]
            if ActionKind.APPROVE_TASK in kinds:
                prompts.append("t=allow for task")
            if include_details:
                prompts.append("d=details")
            return "  ".join(prompts)
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

    def _grouped_breakdown_lines(self, facts: ApprovalDetailsFacts) -> List[str]:
        arrow = "->" if self.ascii_mode else "→"
        warning_prefix = "[!]" if self.ascii_mode else "⚠"
        show_headings = len(facts.command_groups) > 1
        lines = ["命令解析:"]
        for position, group in enumerate(facts.command_groups):
            if position and show_headings:
                lines.append("")
            indent = "    " if show_headings else "  "
            if show_headings:
                separator = f" {group.separator}" if group.separator else ""
                lines.append(f"  [{group.index}] {group.command}{separator}")
            if group.items:
                token_width = min(max(len(item.token) for item in group.items), 28)
                for item in group.items:
                    padded = (
                        item.token
                        if len(item.token) > token_width
                        else item.token.ljust(token_width)
                    )
                    lines.append(f"{indent}{padded} {arrow} {item.meaning}")
            elif group.summary:
                lines.append(f"{indent}{group.summary}")
            lines.extend(f"{indent}{warning_prefix} {warning}" for warning in group.warnings)
        return lines

    def _breakdown_lines(self, facts: ApprovalDetailsFacts) -> List[str]:
        if facts.command_groups:
            return self._grouped_breakdown_lines(facts)
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

        if facts.detail_status == "failed":
            purpose = compact_approval_purpose(facts.reason, fallback="")
            lines = [self._status("⚠️", "[!]", "Command analysis unavailable")]
            if purpose:
                lines.append(f"Purpose: {purpose}")
            lines.extend(
                [
                    "Review the original command before allowing it.",
                    "",
                    "Command:",
                    "```bash",
                    facts.command or "(empty)",
                    "```",
                    "",
                    self._action_prompt(message, include_details=False),
                ]
            )
            return RenderedMessage(text_parts=("\n".join(lines),))

        risk = facts.risk_level or "unknown"
        safety = facts.safety_status or "unknown"
        full = self.full or bool(message.presentation.get("full"))
        impact = compact_impact(
            facts.impact_analysis,
            full=full,
            suffix="... Run /details full for full analysis.",
        )
        flags = []
        if facts.mutation_detected:
            flags.append("modifies system")
        if facts.deletion_detected:
            flags.append("deletes files")

        if facts.detail_status == "partial":
            lines = [
                self._status("⚠️", "[!]", "Command analysis partially available")
            ]
            if facts.command_count:
                lines.append(
                    f"Analyzed {facts.analyzed_command_count}/{facts.command_count} "
                    "subcommands. Review unanalyzed portions."
                )
            else:
                lines.append(
                    "Some subcommands were not analyzed. Review the original command."
                )
        else:
            lines = [self._status("🔎", "[details]", "Approval details")]
        lines.append(f"Risk: {risk}    Safety: {safety}")
        if flags:
            lines.append(f"Flags: {', '.join(flags)}")
        if full and reason_adds_context(facts.reason, facts.impact_analysis):
            lines.extend(["", "Reason:", self._indent(facts.reason, max_chars=1600)])
        lines.extend(["", "Command:", "```bash", facts.command or "(empty)", "```"])
        breakdown = self._breakdown_lines(facts)
        if breakdown:
            lines.extend(["", *breakdown])
        lines.extend(["", "Impact:", self._indent(impact, max_chars=4000), ""])
        lines.append(self._action_prompt(message, include_details=False))
        return RenderedMessage(text_parts=("\n".join(lines),))
    @staticmethod

    def _command_list(items: tuple[str, ...]) -> str:
        return ", ".join(items) if items else "none"

    def _render_environment(self, facts: EnvironmentFacts) -> RenderedMessage:
        if not facts.available:
            text = self._status("ℹ️", "[i]", facts.error_message)
            return RenderedMessage(text_parts=(f"{text}\nRun: chatdome doctor",))
        lines = [
            "ChatDome Runtime Environment Profile",
            "",
            f"Collected at (UTC): {facts.collected_at_utc}",
            "",
            "Host summary:",
            f"- OS family: {facts.os_family}",
            f"- OS release: {facts.os_release}",
            f"- OS version: {facts.os_version}",
            f"- Machine: {facts.machine}",
            f"- Python: {facts.python_version}",
            f"- Shell: {facts.shell}",
            f"- Linux distro: {facts.linux_distro}",
            f"- WSL: {facts.is_wsl}",
            "",
            "Command availability:",
            f"- Available: {self._command_list(facts.available_commands)}",
            f"- Missing: {self._command_list(facts.missing_commands)}",
            "",
            f"Profile: {facts.profile_path}",
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
                "Codex OAuth",
                f"Profile: {facts.profile_name}",
                f"Open: {facts.verification_uri}",
                f"Code: {facts.user_code}",
                f"Expires in: {minutes} minutes",
                "Waiting for authorization...",
            ]
        )
        return RenderedMessage(text_parts=(text,))

    @staticmethod
    def _render_help(facts: CommandHelpFacts) -> RenderedMessage:
        lines = ["Commands:"]
        for command in facts.commands:
            aliases = f" ({', '.join(command.aliases)})" if command.aliases else ""
            lines.append(f"  {command.usage}{aliases}  {command.description}")
        return RenderedMessage(text_parts=("\n".join(lines),))

    def _render_session_control(
        self,
        facts: SessionControlFacts,
    ) -> RenderedMessage:
        if facts.operation == "clear_session":
            text = (
                self._status("✅", "[ok]", "Session cleared.")
                if facts.changed
                else self._status("ℹ️", "[i]", "No active session.")
            )
        else:
            text = (
                self._status("⏹️", "[stop]", "Task stopped.")
                if facts.changed
                else self._status("ℹ️", "[i]", "No running task.")
            )
        return RenderedMessage(text_parts=(text,))

    @staticmethod
    def _render_token_usage(facts: TokenUsageFacts) -> RenderedMessage:
        return RenderedMessage(
            text_parts=(
                "\n".join(
                    [
                        "Token usage",
                        f"Prompt: {facts.prompt_tokens:,}",
                        f"Completion: {facts.completion_tokens:,}",
                        f"Total: {facts.total_tokens:,}",
                    ]
                ),
            )
        )

    def _render_command_echo(self, facts: CommandEchoFacts) -> RenderedMessage:
        state = "enabled" if facts.enabled else "disabled"
        return RenderedMessage(
            text_parts=(self._status("🔍", "[cmd]", f"Command echo {state}."),)
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
            return RenderedMessage(text_parts=(f"{message.summary}\nContinue? [y/n]",))
        return RenderedMessage(text_parts=((message.body or message.summary),))
