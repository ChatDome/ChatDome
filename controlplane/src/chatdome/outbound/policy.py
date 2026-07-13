"""Validation and safe degradation for unified outbound messages."""

from __future__ import annotations

import logging
from dataclasses import replace
from typing import List

from chatdome.outbound.models import (
    ActionKind,
    ApprovalRequestFacts,
    OutboundMessage,
    OutboundMessageKind,
)


logger = logging.getLogger(__name__)

_EMPTY_APPROVAL_REASONS = frozenset({"无说明", "not provided", "unknown"})
_APPROVAL_ACTIONS = frozenset({ActionKind.APPROVE, ActionKind.APPROVE_TASK})


class OutboundContractError(ValueError):
    """Raised when an outbound message violates its semantic contract."""


def normalize_text(value: object) -> str:
    return " ".join(str(value or "").split()).strip()


def has_meaningful_approval_reason(value: object) -> bool:
    reason = normalize_text(value)
    return bool(reason) and reason.casefold() not in _EMPTY_APPROVAL_REASONS


def outbound_contract_errors(message: OutboundMessage) -> List[str]:
    errors: List[str] = []
    if message.kind != OutboundMessageKind.APPROVAL_REQUEST:
        return errors
    if not isinstance(message.facts, ApprovalRequestFacts):
        return ["approval request facts are missing"]

    approval_id = normalize_text(message.refs.get("approval_id", ""))
    if not approval_id:
        errors.append("approval_id is required")
    if not has_meaningful_approval_reason(message.facts.reason):
        errors.append("approval reason is required")

    for action in message.actions:
        if action.kind in _APPROVAL_ACTIONS and action.token != approval_id:
            errors.append(f"{action.kind.value} action is not bound to approval_id")
    return errors


def validate_outbound_message(message: OutboundMessage) -> None:
    errors = outbound_contract_errors(message)
    if errors:
        raise OutboundContractError("; ".join(errors))


def apply_outbound_policy(message: OutboundMessage) -> OutboundMessage:
    """Remove unsafe controls while preserving a useful blocked message."""
    errors = outbound_contract_errors(message)
    if not errors:
        return message

    approval_id = normalize_text(message.refs.get("approval_id", ""))
    actions = message.actions
    if not approval_id:
        actions = ()
    else:
        actions = tuple(action for action in actions if action.kind not in _APPROVAL_ACTIONS)
    logger.error("Outbound approval contract rejected controls: %s", "; ".join(errors))
    return replace(message, severity="error", actions=actions)
