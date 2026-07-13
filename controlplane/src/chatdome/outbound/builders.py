"""Builders that convert Agent results and approval data into outbound messages."""

from __future__ import annotations

from types import MappingProxyType
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple

from chatdome.agent.result import coerce_agent_result
from chatdome.outbound.models import (
    ActionKind,
    ApprovalDetailsFacts,
    ApprovalRequestFacts,
    CommandBreakdownItem,
    OutboundAction,
    OutboundMessage,
    OutboundMessageKind,
)
from chatdome.outbound.policy import apply_outbound_policy, normalize_text


def _optional_bool(value: Any) -> Optional[bool]:
    if value is None or value == "":
        return None
    if isinstance(value, str):
        return value.strip().casefold() in {"1", "true", "yes", "y", "on"}
    return bool(value)


def _refs(data: Mapping[str, Any]) -> Mapping[str, str]:
    values = {
        key: normalize_text(data.get(key, ""))
        for key in ("approval_id", "run_id", "command_hash")
        if normalize_text(data.get(key, ""))
    }
    return MappingProxyType(values)


def _approval_actions(
    approval_id: str,
    *,
    include_details: bool,
) -> Tuple[OutboundAction, ...]:
    actions = [
        OutboundAction(ActionKind.APPROVE, "Allow", approval_id),
        OutboundAction(ActionKind.APPROVE_TASK, "Allow for task", approval_id),
        OutboundAction(ActionKind.REJECT, "Reject", approval_id, destructive=True),
    ]
    if include_details:
        actions.append(OutboundAction(ActionKind.SHOW_DETAILS, "Command analysis", approval_id))
    return tuple(actions)


def build_approval_request(payload: Optional[Mapping[str, Any]]) -> OutboundMessage:
    data = dict(payload or {})
    approval_id = normalize_text(data.get("approval_id", ""))
    details_available = _optional_bool(data.get("requires_detail_expansion", True))
    facts = ApprovalRequestFacts(
        command=str(data.get("command") or "").strip(),
        reason=normalize_text(data.get("reason", "")),
        impact_analysis=str(data.get("impact_analysis") or "").strip(),
        risk_level=normalize_text(data.get("risk_level", "")),
        safety_status=normalize_text(data.get("safety_status", "")),
        mutation_detected=_optional_bool(data.get("mutation_detected")),
        deletion_detected=_optional_bool(data.get("deletion_detected")),
        details_available=True if details_available is None else details_available,
    )
    message = OutboundMessage(
        kind=OutboundMessageKind.APPROVAL_REQUEST,
        title="Approval required",
        summary=facts.reason,
        severity="warning",
        refs=_refs(data),
        facts=facts,
        actions=_approval_actions(approval_id, include_details=facts.details_available),
    )
    return apply_outbound_policy(message)


def _breakdown_items(value: Any) -> Tuple[CommandBreakdownItem, ...]:
    if not isinstance(value, Iterable) or isinstance(value, (str, bytes, Mapping)):
        return ()
    items = []
    for raw in value:
        if not isinstance(raw, Mapping):
            continue
        token = str(raw.get("token") or "").strip()
        label = str(raw.get("label") or raw.get("role") or "").strip()
        meaning = str(raw.get("meaning") or label or "命令组成部分").strip()
        if label and label not in meaning:
            meaning = f"{label}（{meaning}）"
        items.append(CommandBreakdownItem(token=token, label=label, meaning=meaning))
    return tuple(items)


def _warnings(value: Any) -> Tuple[str, ...]:
    if not isinstance(value, Iterable) or isinstance(value, (str, bytes, Mapping)):
        return ()
    return tuple(text for item in value if (text := str(item or "").strip()))


def build_approval_details(details: Optional[Mapping[str, Any]]) -> OutboundMessage:
    data = dict(details or {})
    ok = bool(data.get("ok"))
    analysis = data.get("analysis") if isinstance(data.get("analysis"), Mapping) else {}
    breakdown = analysis.get("command_breakdown") if isinstance(analysis.get("command_breakdown"), Mapping) else {}
    facts = ApprovalDetailsFacts(
        ok=ok,
        command=str(data.get("command") or "").strip(),
        reason=str(data.get("reason") or "").strip(),
        impact_analysis=str(analysis.get("impact_analysis") or data.get("impact_analysis") or "").strip(),
        risk_level=normalize_text(analysis.get("risk_level") or data.get("risk_level") or ""),
        safety_status=normalize_text(analysis.get("safety_status") or data.get("safety_status") or ""),
        mutation_detected=_optional_bool(analysis.get("mutation_detected", data.get("mutation_detected"))),
        deletion_detected=_optional_bool(analysis.get("deletion_detected", data.get("deletion_detected"))),
        command_breakdown=_breakdown_items(breakdown.get("tokens")),
        warnings=_warnings(breakdown.get("warnings")),
        error_message=str(data.get("message") or "No pending approval.").strip() if not ok else "",
    )
    approval_id = normalize_text(data.get("approval_id", ""))
    actions = _approval_actions(approval_id, include_details=False) if ok and approval_id else ()
    return OutboundMessage(
        kind=OutboundMessageKind.APPROVAL_DETAILS,
        title="Approval details",
        summary=facts.reason or facts.impact_analysis,
        severity="warning" if ok else "info",
        refs=_refs(data),
        facts=facts,
        actions=actions,
    )


class OutboundMessageBuilder:
    """Convert the stable AgentResult contract into outbound semantics."""

    def from_agent_result(self, value: Any) -> OutboundMessage:
        result = coerce_agent_result(value)
        if result.kind == "pending_approval":
            return build_approval_request(result.payload)
        if result.kind == "round_limit":
            payload: Dict[str, Any] = dict(result.payload or {})
            token = normalize_text(payload.get("run_id", "")) or None
            actions = (
                OutboundAction(ActionKind.CONTINUE, "Continue", token),
                OutboundAction(ActionKind.STOP, "Stop", token, destructive=True),
            )
            rounds = int(payload.get("rounds") or 0)
            return OutboundMessage(
                kind=OutboundMessageKind.TASK_PAUSED,
                title="Task paused",
                summary=f"Task paused after {rounds} rounds.",
                severity="info",
                refs=_refs(payload),
                facts=MappingProxyType(payload),
                actions=actions,
            )
        return OutboundMessage(
            kind=OutboundMessageKind.TEXT,
            title="",
            summary=result.content,
            body=result.content,
        )
