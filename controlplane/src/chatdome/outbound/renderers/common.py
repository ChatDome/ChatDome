"""Shared presentation helpers for outbound renderers."""

from __future__ import annotations

from chatdome.outbound.policy import has_meaningful_approval_reason, normalize_text


def compact_approval_purpose(value: object, *, fallback: str, max_chars: int = 120) -> str:
    reason = normalize_text(value)
    if not has_meaningful_approval_reason(reason):
        reason = normalize_text(fallback)
    limit = max(2, int(max_chars))
    if len(reason) <= limit:
        return reason
    return reason[: limit - 1].rstrip() + "…"


def compact_impact(value: object, *, full: bool, max_chars: int = 220, suffix: str = "") -> str:
    text = normalize_text(value) or "review required"
    if full or len(text) <= max_chars:
        return text
    ending = suffix or "..."
    available = max(1, max_chars - len(ending))
    return text[:available].rstrip() + ending


def reason_adds_context(reason: str, impact: str) -> bool:
    normalized_reason = normalize_text(reason).casefold()
    normalized_impact = normalize_text(impact).casefold()
    if not has_meaningful_approval_reason(normalized_reason):
        return False
    if not normalized_impact:
        return True
    return normalized_reason not in normalized_impact and normalized_impact not in normalized_reason
