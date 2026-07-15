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
    ENVIRONMENT = "environment"


class ActionKind(str, Enum):
    """Platform-independent operations offered by an outbound message."""

    APPROVE = "approve"
    APPROVE_TASK = "approve_task"
    REJECT = "reject"
    SHOW_DETAILS = "show_details"
    CONTINUE = "continue"
    STOP = "stop"


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
class EnvironmentFacts:
    """Runtime environment values shared by every platform renderer."""

    available: bool
    profile_path: str
    collected_at_utc: str = "unknown"
    os_family: str = "unknown"
    os_release: str = "unknown"
    os_version: str = "unknown"
    machine: str = "unknown"
    python_version: str = "unknown"
    shell: str = "unknown"
    linux_distro: str = "N/A"
    is_wsl: str = "unknown"
    available_commands: Tuple[str, ...] = ()
    missing_commands: Tuple[str, ...] = ()
    error_message: str = ""


@dataclass(frozen=True)
class ModelProfileFacts:
    """One model profile without credentials."""

    name: str
    provider: str
    api_mode: str
    model: str
    base_url: str = ""
    status: str = ""
    key_ref: str = ""
    active: bool = False


@dataclass(frozen=True)
class ModelProfilesFacts:
    """Model profile inventory returned by the shared command service."""

    active_profile: str
    profiles: Tuple[ModelProfileFacts, ...] = ()


@dataclass(frozen=True)
class CodexAuthorizationFacts:
    """Public device-authorization values safe to send to a user."""

    profile_name: str
    verification_uri: str
    user_code: str
    expires_in: int


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
