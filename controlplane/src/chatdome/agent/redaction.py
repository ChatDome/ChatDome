"""Shared redaction helpers for persisted conversation context."""

from __future__ import annotations

import re

_REDACTED = "[REDACTED]"
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)
_SENSITIVE_KEY_VALUE_RE = re.compile(
    r"(?i)([\"']?\b(?:telegram[_-]?bot[_-]?token|bot[_-]?token|api[_-]?key|openai[_-]?api[_-]?key|password|passwd|secret|access[_-]?token|refresh[_-]?token|client[_-]?secret|private[_-]?key|codex[_-]?token)\b[\"']?\s*[:=]\s*[\"']?)([^\"'\s,;}]+)([\"']?)"
)
_AUTH_BEARER_RE = re.compile(r"(?i)\b(authorization\s*[:=]\s*bearer\s+)([A-Za-z0-9._~+/=-]{10,})")
_TELEGRAM_BOT_TOKEN_RE = re.compile(r"\b\d{6,}:[A-Za-z0-9_-]{20,}\b")
_OPENAI_STYLE_KEY_RE = re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b")


def redact_sensitive_text(text: str) -> str:
    """Redact common credential shapes before text is persisted."""
    redacted = str(text or "")
    redacted = _PRIVATE_KEY_RE.sub(_REDACTED, redacted)
    redacted = _SENSITIVE_KEY_VALUE_RE.sub(
        lambda match: f"{match.group(1)}{_REDACTED}{match.group(3)}",
        redacted,
    )
    redacted = _AUTH_BEARER_RE.sub(lambda match: f"{match.group(1)}{_REDACTED}", redacted)
    redacted = _TELEGRAM_BOT_TOKEN_RE.sub(_REDACTED, redacted)
    redacted = _OPENAI_STYLE_KEY_RE.sub(_REDACTED, redacted)
    return redacted


def redact_field_value(key: str, value: object) -> str:
    """Use a field name to redact values whose shape alone is not recognizable."""
    composite = redact_sensitive_text(f"{key}={value}")
    return composite.partition("=")[2]
