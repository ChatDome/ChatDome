"""Unified outbound message contracts and platform renderers."""

from chatdome.outbound.builders import (
    OutboundMessageBuilder,
    build_approval_details,
    build_approval_request,
)
from chatdome.outbound.models import (
    ActionKind,
    ApprovalDetailsFacts,
    ApprovalRequestFacts,
    OutboundAction,
    OutboundMessage,
    OutboundMessageKind,
    RenderedControl,
    RenderedMessage,
)

__all__ = [
    "ActionKind",
    "ApprovalDetailsFacts",
    "ApprovalRequestFacts",
    "OutboundAction",
    "OutboundMessage",
    "OutboundMessageBuilder",
    "OutboundMessageKind",
    "RenderedControl",
    "RenderedMessage",
    "build_approval_details",
    "build_approval_request",
]
