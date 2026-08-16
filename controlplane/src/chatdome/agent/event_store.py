"""Append-only, searchable conversation event archive."""

from __future__ import annotations

import json
import os
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Mapping

from chatdome.agent.redaction import redact_field_value, redact_sensitive_text


def _local_timestamp() -> str:
    return datetime.now().astimezone().isoformat(sep=" ", timespec="seconds")


def _event_id() -> str:
    now = datetime.now().astimezone()
    return f"EV-{now:%Y%m%d-%H%M%S}-{uuid.uuid4().hex[:6].upper()}"


@dataclass(frozen=True)
class ChatEvent:
    event_id: str
    timestamp: str
    chat_id: int | str
    type: str
    payload: dict[str, Any]
    turn_id: int | None = None
    source: str = "chatdome"
    redaction_applied: bool = False
    schema_version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "chat_id": self.chat_id,
            "turn_id": self.turn_id,
            "source": self.source,
            "type": self.type,
            "payload": self.payload,
            "redaction": {"applied": self.redaction_applied},
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ChatEvent":
        payload = value.get("payload")
        redaction = value.get("redaction")
        if not isinstance(payload, dict):
            raise ValueError("event payload must be an object")
        if not isinstance(redaction, dict):
            redaction = {}
        return cls(
            schema_version=int(value.get("schema_version", 1)),
            event_id=str(value["event_id"]),
            timestamp=str(value["timestamp"]),
            chat_id=value["chat_id"],
            turn_id=int(value["turn_id"]) if value.get("turn_id") is not None else None,
            source=str(value.get("source", "chatdome")),
            type=str(value["type"]),
            payload=payload,
            redaction_applied=bool(redaction.get("applied", False)),
        )


@dataclass(frozen=True)
class EventSearchResult:
    matches: list[ChatEvent] = field(default_factory=list)
    scanned_events: int = 0
    clear_boundary_event_id: str | None = None


@dataclass(frozen=True)
class EventCleanupResult:
    scanned_files: int = 0
    removed_events: int = 0
    kept_events: int = 0
    skipped: bool = False
    errors: tuple[str, ...] = ()


class EventStore:
    """Persist recent conversation events without coupling them to Session state."""

    SEARCHABLE_TYPES = frozenset(
        {
            "message.user",
            "message.assistant",
            "tool.call",
            "tool.result",
            "approval.requested",
            "approval.approved",
            "approval.rejected",
        }
    )

    def __init__(self, data_root: Path, *, retention_days: int = 30) -> None:
        if retention_days < 0:
            raise ValueError("retention_days must be zero or greater")
        self.data_root = Path(data_root)
        self.events_dir = self.data_root / "events"
        self.retention_days = retention_days
        self._lock = threading.RLock()

    def path_for(self, chat_id: int | str) -> Path:
        return self.events_dir / f"{chat_id}.jsonl"

    def append(
        self,
        chat_id: int | str,
        event_type: str,
        payload: Mapping[str, Any],
        *,
        turn_id: int | None = None,
        source: str = "chatdome",
    ) -> ChatEvent:
        safe_payload, redaction_applied = self._sanitize_payload(dict(payload))
        event = ChatEvent(
            event_id=_event_id(),
            timestamp=_local_timestamp(),
            chat_id=chat_id,
            turn_id=turn_id,
            source=str(source or "chatdome"),
            type=str(event_type),
            payload=safe_payload,
            redaction_applied=redaction_applied,
        )
        path = self.path_for(chat_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(event.to_dict(), ensure_ascii=False, separators=(",", ":")) + "\n"
        with self._lock, path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())
        return event

    def read_events(self, chat_id: int | str) -> list[ChatEvent]:
        path = self.path_for(chat_id)
        if not path.exists():
            return []
        events: list[ChatEvent] = []
        with self._lock, path.open("r", encoding="utf-8") as handle:
            for line in handle:
                try:
                    raw = json.loads(line)
                    if isinstance(raw, dict):
                        events.append(ChatEvent.from_dict(raw))
                except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                    continue
        return events

    def latest_clear_event_id(self, chat_id: int | str) -> str | None:
        for event in reversed(self.read_events(chat_id)):
            if event.type == "session.cleared":
                return event.event_id
        return None

    def search(
        self,
        chat_id: int | str,
        query: str,
        *,
        limit: int = 5,
        include_cleared: bool = False,
    ) -> EventSearchResult:
        limit = max(0, int(limit))
        events = self.read_events(chat_id)
        boundary_index = -1
        boundary_id = None
        for index in range(len(events) - 1, -1, -1):
            if events[index].type == "session.cleared":
                boundary_index = index
                boundary_id = events[index].event_id
                break
        eligible = events if include_cleared else events[boundary_index + 1 :]
        searchable = [event for event in eligible if event.type in self.SEARCHABLE_TYPES]
        terms = [part.casefold() for part in str(query or "").split() if part]
        matches: list[ChatEvent] = []
        if terms and limit:
            for event in reversed(searchable):
                haystack = json.dumps(event.payload, ensure_ascii=False, sort_keys=True).casefold()
                if all(term in haystack for term in terms):
                    matches.append(event)
        return EventSearchResult(
            matches=matches[:limit],
            scanned_events=len(searchable),
            clear_boundary_event_id=boundary_id,
        )

    def cleanup(self, *, now: datetime | None = None) -> EventCleanupResult:
        if self.retention_days == 0:
            return EventCleanupResult(skipped=True)
        if not self.events_dir.exists():
            return EventCleanupResult()
        current = now or datetime.now().astimezone()
        if current.tzinfo is None:
            current = current.astimezone()
        cutoff = current - timedelta(days=self.retention_days)
        scanned_files = removed = kept = 0
        errors: list[str] = []
        for path in sorted(self.events_dir.glob("*.jsonl")):
            scanned_files += 1
            try:
                file_removed, file_kept = self._cleanup_file(path, cutoff)
                removed += file_removed
                kept += file_kept
            except OSError as exc:
                errors.append(f"{path.name}: {exc}")
        return EventCleanupResult(
            scanned_files=scanned_files,
            removed_events=removed,
            kept_events=kept,
            errors=tuple(errors),
        )

    def _cleanup_file(self, path: Path, cutoff: datetime) -> tuple[int, int]:
        original_lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
        retained: list[str] = []
        removed = 0
        for line in original_lines:
            try:
                raw = json.loads(line)
                timestamp = datetime.fromisoformat(str(raw["timestamp"]))
                if timestamp.tzinfo is None:
                    timestamp = timestamp.astimezone()
                if timestamp < cutoff:
                    removed += 1
                    continue
            except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                pass
            retained.append(line if line.endswith("\n") else line + "\n")
        if not removed:
            return 0, len(retained)
        temp_path = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        try:
            with self._lock, temp_path.open("w", encoding="utf-8", newline="\n") as handle:
                handle.writelines(retained)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_path, path)
        finally:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass
        return removed, len(retained)

    @classmethod
    def _sanitize_payload(cls, payload: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        sanitized, changed = cls._sanitize_value(payload)
        return sanitized, changed

    @classmethod
    def _sanitize_value(cls, value: Any, *, field_name: str | None = None) -> tuple[Any, bool]:
        if isinstance(value, dict):
            result: dict[str, Any] = {}
            changed = False
            for key, item in value.items():
                safe_item, item_changed = cls._sanitize_value(item, field_name=str(key))
                result[str(key)] = safe_item
                changed = changed or item_changed
            return result, changed
        if isinstance(value, list):
            result_list: list[Any] = []
            changed = False
            for item in value:
                safe_item, item_changed = cls._sanitize_value(item)
                result_list.append(safe_item)
                changed = changed or item_changed
            return result_list, changed
        if isinstance(value, tuple):
            safe_list, changed = cls._sanitize_value(list(value))
            return safe_list, changed
        if isinstance(value, str):
            safe_value = (
                redact_field_value(field_name, value)
                if field_name is not None
                else redact_sensitive_text(value)
            )
            return safe_value, safe_value != value
        if field_name is not None:
            safe_text = redact_field_value(field_name, value)
            if safe_text != str(value):
                return safe_text, True
        return value, False
