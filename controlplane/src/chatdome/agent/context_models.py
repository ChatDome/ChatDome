"""Structured state shared by context budgeting, compression, and commands."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable


def local_timestamp() -> str:
    """Return a readable local timestamp with an explicit UTC offset."""

    return datetime.now().astimezone().isoformat(sep=" ", timespec="seconds")


def _nonempty_text(value: Any, field_name: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{field_name} must not be empty")
    return text


def _event_ids(values: Any) -> list[str]:
    if not isinstance(values, (list, tuple)):
        return []
    result: list[str] = []
    for value in values:
        if not isinstance(value, str):
            continue
        event_id = value.strip()
        if event_id and event_id not in result:
            result.append(event_id)
    return result


@dataclass
class SummaryItem:
    text: str
    source_event_ids: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, payload: Any) -> "SummaryItem":
        if not isinstance(payload, dict):
            raise ValueError("summary item must be an object")
        return cls(
            text=_nonempty_text(payload.get("text"), "text"),
            source_event_ids=_event_ids(payload.get("source_event_ids")),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "text": self.text,
            "source_event_ids": list(self.source_event_ids),
        }


_SUMMARY_LIST_FIELDS = (
    "completed",
    "key_results",
    "files",
    "commands",
    "pending",
    "user_constraints",
)


@dataclass
class WorkingSummary:
    current_goal: str
    current_state: str
    completed: list[SummaryItem] = field(default_factory=list)
    key_results: list[SummaryItem] = field(default_factory=list)
    files: list[SummaryItem] = field(default_factory=list)
    commands: list[SummaryItem] = field(default_factory=list)
    pending: list[SummaryItem] = field(default_factory=list)
    user_constraints: list[SummaryItem] = field(default_factory=list)
    source_event_ids: list[str] = field(default_factory=list)
    updated_at: str = ""
    token_count: int = 0
    version: int = 1

    @classmethod
    def from_dict(cls, payload: Any) -> "WorkingSummary":
        if not isinstance(payload, dict):
            raise ValueError("working_summary must be an object")
        values: dict[str, Any] = {}
        for field_name in _SUMMARY_LIST_FIELDS:
            raw_items = payload.get(field_name, [])
            if not isinstance(raw_items, list):
                raise ValueError(f"{field_name} must be a list")
            values[field_name] = [SummaryItem.from_dict(item) for item in raw_items]
        raw_token_count = payload.get("token_count", 0)
        token_count = (
            raw_token_count
            if isinstance(raw_token_count, int) and not isinstance(raw_token_count, bool)
            else 0
        )
        return cls(
            current_goal=_nonempty_text(payload.get("current_goal"), "current_goal"),
            current_state=_nonempty_text(payload.get("current_state"), "current_state"),
            source_event_ids=_event_ids(payload.get("source_event_ids")),
            updated_at=str(payload.get("updated_at") or "").strip(),
            token_count=max(0, token_count),
            version=1,
            **values,
        )

    def all_source_event_ids(self) -> list[str]:
        result = list(self.source_event_ids)
        for field_name in _SUMMARY_LIST_FIELDS:
            for item in getattr(self, field_name):
                for event_id in item.source_event_ids:
                    if event_id not in result:
                        result.append(event_id)
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": 1,
            "current_goal": self.current_goal,
            "current_state": self.current_state,
            **{
                field_name: [item.to_dict() for item in getattr(self, field_name)]
                for field_name in _SUMMARY_LIST_FIELDS
            },
            "source_event_ids": self.all_source_event_ids(),
            "updated_at": self.updated_at,
            "token_count": self.token_count,
        }

    def to_prompt_block(self) -> str:
        lines = [
            "[Working Summary - 当前任务工作摘要]",
            f"当前目标：{self.current_goal}",
            f"当前状态：{self.current_state}",
        ]
        labels = {
            "completed": "已完成",
            "key_results": "关键结果",
            "files": "相关文件",
            "commands": "相关命令",
            "pending": "待办",
            "user_constraints": "用户约束",
        }
        for field_name in _SUMMARY_LIST_FIELDS:
            items: Iterable[SummaryItem] = getattr(self, field_name)
            for item in items:
                refs = f" [{', '.join(item.source_event_ids)}]" if item.source_event_ids else ""
                lines.append(f"- {labels[field_name]}：{item.text}{refs}")
        if self.all_source_event_ids():
            lines.append(f"来源事件：{', '.join(self.all_source_event_ids())}")
        return "\n".join(lines)


@dataclass
class LastCompaction:
    compaction_id: str
    completed_at: str
    tokens_before: int
    tokens_after: int
    reduction_percent: int
    working_summary_tokens: int
    preserved_tail_tokens: int

    @classmethod
    def from_dict(cls, payload: Any) -> "LastCompaction | None":
        if not isinstance(payload, dict):
            return None
        compaction_id = str(payload.get("compaction_id") or "").strip()
        if not compaction_id:
            return None
        return cls(
            compaction_id=compaction_id,
            completed_at=str(payload.get("completed_at") or "").strip(),
            tokens_before=max(0, int(payload.get("tokens_before") or 0)),
            tokens_after=max(0, int(payload.get("tokens_after") or 0)),
            reduction_percent=max(0, int(payload.get("reduction_percent") or 0)),
            working_summary_tokens=max(0, int(payload.get("working_summary_tokens") or 0)),
            preserved_tail_tokens=max(0, int(payload.get("preserved_tail_tokens") or 0)),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "compaction_id": self.compaction_id,
            "completed_at": self.completed_at,
            "tokens_before": self.tokens_before,
            "tokens_after": self.tokens_after,
            "reduction_percent": self.reduction_percent,
            "working_summary_tokens": self.working_summary_tokens,
            "preserved_tail_tokens": self.preserved_tail_tokens,
        }


@dataclass
class ContextState:
    last_compaction: LastCompaction | None = None
    last_compaction_status: str = ""

    @classmethod
    def from_dict(cls, payload: Any) -> "ContextState":
        if not isinstance(payload, dict):
            return cls()
        return cls(
            last_compaction=LastCompaction.from_dict(payload.get("last_compaction")),
            last_compaction_status=str(payload.get("last_compaction_status") or "").strip(),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "last_compaction": (
                self.last_compaction.to_dict() if self.last_compaction is not None else None
            ),
            "last_compaction_status": self.last_compaction_status,
        }
