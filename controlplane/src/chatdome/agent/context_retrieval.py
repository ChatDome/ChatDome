"""Deterministic policy for retrieving compressed conversation evidence."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


_HISTORY_REFERENCE_RE = re.compile(
    r"(?:刚才|之前|以前|历史|上次|上一次|先前|那些|继续上次|继续之前)",
    re.IGNORECASE,
)
_EVIDENCE_RE = re.compile(
    r"(?:原文|原始|精确|具体数值|证据|依据|完整结果|详细结果)",
    re.IGNORECASE,
)
_REFERENCE_ONLY_RE = re.compile(r"(?:这个|那个|这些|那些|刚才的|之前的)", re.IGNORECASE)
_QUERY_NOISE_RE = re.compile(
    r"(?:请|帮我|继续|查看|查找|查询|刚才|之前|以前|历史|上次|上一次|先前|那些|这个|那个|这些|的|任务|内容|结果)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class RetrievalDecision:
    should_retrieve: bool
    reason: str = ""
    query: str = ""


class ContextRetrievalPolicy:
    """Trigger retrieval only for explicit historical or evidence-dependent input."""

    def evaluate(self, user_text: str, session: Any) -> RetrievalDecision:
        text = " ".join(str(user_text or "").split()).strip()
        if not text:
            return RetrievalDecision(False)
        if _HISTORY_REFERENCE_RE.search(text):
            return RetrievalDecision(True, "explicit_history_reference", self._query(text))
        summary = getattr(session, "working_summary", None)
        if summary is not None and summary.all_source_event_ids() and _EVIDENCE_RE.search(text):
            return RetrievalDecision(True, "summary_evidence_requested", self._query(text))
        if _REFERENCE_ONLY_RE.search(text) and not self._recent_context_resolves_reference(session):
            return RetrievalDecision(True, "unresolved_reference", self._query(text))
        return RetrievalDecision(False)

    @staticmethod
    def _query(text: str) -> str:
        cleaned = " ".join(_QUERY_NOISE_RE.sub(" ", text).split()).strip()
        return cleaned or text

    @staticmethod
    def _recent_context_resolves_reference(session: Any) -> bool:
        messages = [
            message
            for message in getattr(session, "messages", [])[-4:]
            if isinstance(message, dict) and message.get("role") != "system"
        ]
        substantive = [
            str(message.get("content") or "").strip()
            for message in messages
            if len(str(message.get("content") or "").strip()) >= 12
        ]
        return len(substantive) >= 2
