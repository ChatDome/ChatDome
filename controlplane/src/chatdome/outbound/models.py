"""Typed semantic contracts for messages sent to user-facing platforms."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
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
    ANALYZE = "analyze"
    CONTINUE = "continue"
    STOP = "stop"

    SELECT = "select"
    CONFIRM = "confirm"
    CANCEL = "cancel"


@dataclass(frozen=True)
class OutboundAction:
    """One platform-independent action attached to an outbound message."""
    kind: ActionKind
    label: str
    token: Optional[str] = None
    destructive: bool = False
    params: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "params",
            MappingProxyType(
                {str(key): str(value) for key, value in self.params.items()}
            ),
        )


@dataclass(frozen=True)
class CommandBreakdownItem:
    token: str
    label: str
    meaning: str


@dataclass(frozen=True)
class CommandBreakdownGroup:
    index: int
    command: str
    separator: str = ""
    summary: str = ""
    items: Tuple[CommandBreakdownItem, ...] = ()
    warnings: Tuple[str, ...] = ()


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
    detail_status: str = "complete"
    reviewer_mode: str = ""
    analyzed_command_count: int = 0
    command_count: int = 0
    detail_errors: Tuple[str, ...] = ()
    command: str = ""
    reason: str = ""
    impact_analysis: str = ""
    risk_level: str = ""
    safety_status: str = ""
    mutation_detected: Optional[bool] = None
    deletion_detected: Optional[bool] = None
    command_breakdown: Tuple[CommandBreakdownItem, ...] = ()
    command_groups: Tuple[CommandBreakdownGroup, ...] = ()
    warnings: Tuple[str, ...] = ()
    error_message: str = ""


@dataclass(frozen=True)
class CommandHelpItemFacts:
    """One command entry exposed by the shared command catalog."""

    name: str
    usage: str
    aliases: Tuple[str, ...]
    description: str


@dataclass(frozen=True)
class CommandHelpFacts:
    """Commands available to the current platform."""

    commands: Tuple[CommandHelpItemFacts, ...]


@dataclass(frozen=True)
class SessionControlFacts:
    """Result of clearing a session or stopping a task."""

    operation: str
    changed: bool


@dataclass(frozen=True)
class TokenUsageFacts:
    """Token counters for one Agent session."""

    chat_id: int
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int


@dataclass(frozen=True)
class CommandEchoFacts:
    """Current command echo state."""

    enabled: bool


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
    status: str = ""
    outcome: str = ""
    refs: Mapping[str, str] = field(default_factory=dict)
    presentation: Mapping[str, Any] = field(default_factory=dict)
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
