"""Tool-free classification for user input received during command approval."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Literal

from chatdome.llm.client import LLMClient

logger = logging.getLogger(__name__)

ApprovalInputClassification = Literal[
    "approve",
    "reject",
    "approval_question",
    "new_task",
    "tool_required",
    "unknown",
]
_ALLOWED_CLASSIFICATIONS = frozenset(
    {
        "approve",
        "reject",
        "approval_question",
        "new_task",
        "tool_required",
        "unknown",
    }
)
_TOOL_TEXT_MARKERS = (
    "<tool_call",
    "</tool_call>",
    "<function=",
    "</function>",
    "<parameter=",
    "</parameter>",
)


@dataclass(frozen=True)
class ApprovalInputDecision:
    """Validated classification returned by the approval input model call."""

    classification: ApprovalInputClassification
    answer: str = ""
    prompt_tokens: int = field(default=0, repr=False, compare=False)
    completion_tokens: int = field(default=0, repr=False, compare=False)
    total_tokens: int = field(default=0, repr=False, compare=False)


def _unknown_decision() -> ApprovalInputDecision:
    return ApprovalInputDecision(classification="unknown")


def _looks_like_tool_call_text(content: str) -> bool:
    text = str(content or "").strip().lower()
    return any(marker in text for marker in _TOOL_TEXT_MARKERS)


async def classify_approval_input(
    llm,
    *,
    command: str,
    reason: str,
    risk_level: str,
    user_message: str,
) -> ApprovalInputDecision:
    """Classify one approval-period message with exactly one tool-free LLM call."""
    system_prompt = (
        "你是命令审批输入分类器。只判断给定的当前审批和用户输入，不能执行工具，"
        "不能输出工具调用或额外文本。必须输出一个 JSON 对象："
        '{"classification":"approve|reject|approval_question|new_task|tool_required|unknown",'
        '"answer":""}。'
        "approval_question 必须直接回答用户关于当前命令的风险、作用或替代方案；"
        "其他分类的 answer 必须为空字符串。"
    )
    payload = json.dumps(
        {
            "pending_command": str(command or ""),
            "reason": str(reason or ""),
            "risk_level": str(risk_level or ""),
            "user_message": str(user_message or ""),
        },
        ensure_ascii=False,
    )
    try:
        response = await llm.chat_completion(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": payload},
            ],
            tools=None,
            response_format={"type": "json_object"},
        )
        if response.tool_calls:
            return _unknown_decision()
        content = str(response.content or "").strip()
        if not content or _looks_like_tool_call_text(content):
            return _unknown_decision()
        parsed = LLMClient.parse_json_object(content)
    except Exception as exc:
        logger.warning("Approval input classification failed: %s", exc)
        return _unknown_decision()

    classification = str(parsed.get("classification") or "").strip().lower()
    if classification not in _ALLOWED_CLASSIFICATIONS:
        return _unknown_decision()
    answer_value = parsed.get("answer", "")
    answer = answer_value.strip() if isinstance(answer_value, str) else ""
    if _looks_like_tool_call_text(answer):
        return _unknown_decision()
    if classification == "approval_question" and not answer:
        return _unknown_decision()

    return ApprovalInputDecision(
        classification=classification,
        answer=answer if classification == "approval_question" else "",
        prompt_tokens=int(getattr(response, "prompt_tokens", 0) or 0),
        completion_tokens=int(getattr(response, "completion_tokens", 0) or 0),
        total_tokens=int(getattr(response, "total_tokens", 0) or 0),
    )
