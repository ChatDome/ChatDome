"""Typed semantic contracts for messages sent to user-facing platforms."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Optional, Tuple


class OutboundMessageKind(str, Enum):
    """Business message types shared by all outbound platforms."""

    TEXT = "text"
    APPROVAL_REQUEST = "approval_request"
    APPROVAL_DETAILS = "approval_details"
    TASK_PAUSED = "task_paused"
    OPERATION_RESULT = "operation_result"
    ERROR = "error"
    NOTIFICATION = "notification"


class ActionKind(str, Enum):
    """Platform-independent operations offered by an outbound message."""

    APPROVE = "approve"
    APPROVE_TASK = "approve_task"
    REJECT = "reject"
    SHOW_DETAILS = "show_details"
    CONTINUE = "continue"
    STOP = "stop"
    RETRY = "retry"


@dataclass(frozen=True)
class OutboundAction:
    kind: ActionKind
    label: str
    token: Optional[str] = None
    destructive: bool = False


@dataclass(frozen=True)
class CommandBreakdownItem:
    token: str
    label: str
    meaning: str


@dataclass(frozen=True)
class ApprovalRequestFacts:
    command: str
    reason: str
    impact_analysis: str
    risk_level: str
    safety_status: str = ""
    mutation_detected: Optional[bool] = None
    deletion_detected: Optional[bool] = None
    details_available: bool = True


@dataclass(frozen=True)
class ApprovalDetailsFacts:
    ok: bool
    command: str = ""
    reason: str = ""
    impact_analysis: str = ""
    risk_level: str = ""
    safety_status: str = ""
    mutation_detected: Optional[bool] = None
    deletion_detected: Optional[bool] = None
    command_breakdown: Tuple[CommandBreakdownItem, ...] = ()
    warnings: Tuple[str, ...] = ()
    error_message: str = ""


@dataclass(frozen=True)
class OutboundMessage:
    kind: OutboundMessageKind
    title: str
    summary: str
    body: str = ""
    severity: str = "info"
    refs: Mapping[str, str] = field(default_factory=dict)
    facts: Any = field(default_factory=dict)
    actions: Tuple[OutboundAction, ...] = ()


@dataclass(frozen=True)
class RenderedControl:
    """A platform-ready control produced from one semantic action."""

    kind: ActionKind
    label: str
    data: str
    row: int = 0
    destructive: bool = False


@dataclass(frozen=True)
class RenderedMessage:
    """Platform-ready text and controls; adapters only perform delivery."""

    text_parts: Tuple[str, ...]
    controls: Tuple[RenderedControl, ...] = ()
    parse_mode: Optional[str] = None
