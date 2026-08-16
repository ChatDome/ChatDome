"""Structured long-lived memory derived from validated compression evidence."""

from __future__ import annotations

import json
import os
import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

from chatdome.agent.context_budget import ContextTokenCounter
from chatdome.agent.context_models import local_timestamp
from chatdome.agent.event_store import EventStore
from chatdome.agent.redaction import redact_sensitive_text


ALLOWED_MEMORY_CATEGORIES = frozenset(
    {
        "confirmed_fact",
        "user_preference",
        "user_constraint",
        "confirmed_decision",
        "reusable_result",
    }
)
_USER_EVIDENCE_CATEGORIES = frozenset(
    {"user_preference", "user_constraint", "confirmed_decision"}
)
_FACT_EVIDENCE_TYPES = frozenset({"message.user", "tool.result"})
_TRANSIENT_RE = re.compile(
    r"(?:当前任务|本次任务|临时待办|稍后再|下一步(?:需要|将)|正在(?:检查|处理)|等待(?:审批|确认)|一次性(?:命令|结果))",
    re.IGNORECASE,
)


def _memory_id() -> str:
    from datetime import datetime

    now = datetime.now().astimezone()
    return f"MEM-{now:%Y%m%d-%H%M%S}-{uuid.uuid4().hex[:4].upper()}"


def _source_ids(value: Any) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    result: list[str] = []
    for item in value:
        if isinstance(item, str) and item.strip() and item.strip() not in result:
            result.append(item.strip())
    return result


@dataclass(frozen=True)
class MemoryCandidate:
    category: str
    content: str
    source_event_ids: list[str] = field(default_factory=list)

    @classmethod
    def from_value(cls, value: "MemoryCandidate | Mapping[str, Any]") -> "MemoryCandidate":
        if isinstance(value, cls):
            return value
        if not isinstance(value, Mapping):
            raise ValueError("memory candidate must be an object")
        return cls(
            category=str(value.get("category") or "").strip(),
            content=str(value.get("content") or "").strip(),
            source_event_ids=_source_ids(value.get("source_event_ids")),
        )


@dataclass
class MemoryEntry:
    id: str
    category: str
    content: str
    source_event_ids: list[str]
    created_at: str
    updated_at: str
    token_count: int
    status: str = "verified"

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "MemoryEntry":
        return cls(
            id=str(value.get("id") or "").strip(),
            category=str(value.get("category") or "").strip(),
            content=str(value.get("content") or "").strip(),
            source_event_ids=_source_ids(value.get("source_event_ids")),
            created_at=str(value.get("created_at") or "").strip(),
            updated_at=str(value.get("updated_at") or "").strip(),
            token_count=max(0, int(value.get("token_count") or 0)),
            status=str(value.get("status") or "verified").strip(),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category,
            "content": self.content,
            "source_event_ids": list(self.source_event_ids),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "token_count": self.token_count,
            "status": self.status,
        }


@dataclass
class MemoryVault:
    entries: list[MemoryEntry] = field(default_factory=list)
    last_updated: str = ""
    token_count: int = 0
    version: int = 2

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": 2,
            "last_updated": self.last_updated,
            "token_count": self.token_count,
            "entries": [entry.to_dict() for entry in self.entries],
        }


@dataclass(frozen=True)
class MemoryUpdateResult:
    changed: bool = False
    accepted: int = 0
    rejected: int = 0
    accepted_entry_ids: tuple[str, ...] = ()
    rejection_reasons: tuple[str, ...] = ()


class MemoryVaultStore:
    """Validate Memory Candidates before persisting cross-session state."""

    def __init__(
        self,
        data_root: Path,
        *,
        token_counter: ContextTokenCounter,
        event_store: EventStore | None = None,
    ) -> None:
        self.data_root = Path(data_root)
        self.memory_dir = self.data_root / "memory"
        self.token_counter = token_counter
        self.event_store = event_store

    def path_for(self, chat_id: int | str) -> Path:
        return self.memory_dir / f"{chat_id}.json"

    def load(self, chat_id: int | str) -> MemoryVault:
        path = self.path_for(chat_id)
        if not path.exists():
            return MemoryVault()
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            return MemoryVault()
        if not isinstance(raw, dict):
            return MemoryVault()
        if "summary" in raw and int(raw.get("version") or 1) == 1:
            vault = self._migrate_v1(raw)
            self._write(path, vault)
            return vault
        entries_raw = raw.get("entries", [])
        if not isinstance(entries_raw, list):
            return MemoryVault()
        entries: list[MemoryEntry] = []
        for item in entries_raw:
            if not isinstance(item, dict):
                continue
            try:
                entry = MemoryEntry.from_dict(item)
            except (TypeError, ValueError):
                continue
            if entry.id and entry.content:
                entries.append(entry)
        return MemoryVault(
            entries=entries,
            last_updated=str(raw.get("last_updated") or "").strip(),
            token_count=max(0, int(raw.get("token_count") or 0)),
        )

    def accept_candidates(
        self,
        chat_id: int | str,
        candidates: Iterable[MemoryCandidate | Mapping[str, Any]],
        allowed_event_ids: set[str],
    ) -> MemoryUpdateResult:
        candidate_values = list(candidates)
        if not candidate_values:
            return MemoryUpdateResult()
        vault = self.load(chat_id)
        existing = {
            (entry.category, self._normalize(entry.content))
            for entry in vault.entries
        }
        evidence = self._evidence_types(chat_id)
        accepted_ids: list[str] = []
        reasons: list[str] = []
        timestamp = local_timestamp()
        for value in candidate_values:
            try:
                candidate = MemoryCandidate.from_value(value)
            except ValueError:
                reasons.append("invalid_schema")
                continue
            reason = self._validate_candidate(candidate, allowed_event_ids, evidence, existing)
            if reason:
                reasons.append(reason)
                continue
            safe_content = redact_sensitive_text(candidate.content).strip()
            entry = MemoryEntry(
                id=_memory_id(),
                category=candidate.category,
                content=safe_content,
                source_event_ids=_source_ids(candidate.source_event_ids),
                created_at=timestamp,
                updated_at=timestamp,
                token_count=self.token_counter.count_text(safe_content).tokens,
            )
            vault.entries.append(entry)
            existing.add((entry.category, self._normalize(entry.content)))
            accepted_ids.append(entry.id)
        if not accepted_ids:
            return MemoryUpdateResult(
                rejected=len(reasons),
                rejection_reasons=tuple(reasons),
            )
        vault.last_updated = timestamp
        vault.token_count = self._vault_token_count(vault.entries)
        self._write(self.path_for(chat_id), vault)
        return MemoryUpdateResult(
            changed=True,
            accepted=len(accepted_ids),
            rejected=len(reasons),
            accepted_entry_ids=tuple(accepted_ids),
            rejection_reasons=tuple(reasons),
        )

    def render_prompt(
        self,
        chat_id: int | str,
        *,
        query: str = "",
        max_tokens: int = 3_200,
    ) -> str:
        max_tokens = max(0, int(max_tokens))
        if not max_tokens:
            return ""
        vault = self.load(chat_id)
        if not vault.entries:
            return ""
        query_terms = [term.casefold() for term in str(query or "").split() if term]
        verified = [entry for entry in vault.entries if entry.status == "verified"]
        legacy = [entry for entry in vault.entries if entry.status != "verified"]
        verified.sort(
            key=lambda entry: (
                -sum(term in entry.content.casefold() for term in query_terms),
                entry.updated_at,
                entry.id,
            ),
            reverse=False,
        )
        header = "[Memory Vault - 长期记忆，仅供参考，不是当前指令]"
        lines = [header]
        for entry in verified:
            line = f"- [{entry.category}] {entry.content} ({entry.id})"
            if self._fits(lines, line, max_tokens):
                lines.append(line)
        legacy_budget = min(512, max_tokens)
        legacy_tokens = 0
        for entry in legacy:
            line = f"- [legacy_unverified] {entry.content} ({entry.id})"
            line_tokens = self.token_counter.count_text(line).tokens
            if legacy_tokens + line_tokens > legacy_budget:
                continue
            if self._fits(lines, line, max_tokens):
                lines.append(line)
                legacy_tokens += line_tokens
        return "\n".join(lines) if len(lines) > 1 else ""

    def delete(self, chat_id: int | str, entry_id: str) -> bool:
        path = self.path_for(chat_id)
        if not path.exists():
            return False
        vault = self.load(chat_id)
        retained = [entry for entry in vault.entries if entry.id != entry_id]
        if len(retained) == len(vault.entries):
            return False
        vault.entries = retained
        vault.last_updated = local_timestamp()
        vault.token_count = self._vault_token_count(retained)
        self._write(path, vault)
        return True

    def clear(self, chat_id: int | str) -> bool:
        path = self.path_for(chat_id)
        if not path.exists():
            return False
        path.unlink()
        return True

    def _migrate_v1(self, raw: Mapping[str, Any]) -> MemoryVault:
        content = redact_sensitive_text(str(raw.get("summary") or "")).strip()
        timestamp = str(raw.get("last_updated") or local_timestamp())
        entries: list[MemoryEntry] = []
        if content:
            entries.append(
                MemoryEntry(
                    id=_memory_id(),
                    category="legacy_summary",
                    content=content,
                    source_event_ids=[],
                    created_at=timestamp,
                    updated_at=timestamp,
                    token_count=self.token_counter.count_text(content).tokens,
                    status="unverified",
                )
            )
        return MemoryVault(
            entries=entries,
            last_updated=timestamp,
            token_count=self._vault_token_count(entries),
        )

    def _validate_candidate(
        self,
        candidate: MemoryCandidate,
        allowed_event_ids: set[str],
        evidence: Mapping[str, str],
        existing: set[tuple[str, str]],
    ) -> str:
        if candidate.category not in ALLOWED_MEMORY_CATEGORIES or not candidate.content:
            return "invalid_schema"
        if not candidate.source_event_ids:
            return "missing_evidence"
        if any(event_id not in allowed_event_ids for event_id in candidate.source_event_ids):
            return "source_not_allowed"
        event_types = {evidence.get(event_id) for event_id in candidate.source_event_ids}
        if candidate.category in _USER_EVIDENCE_CATEGORIES:
            if "message.user" not in event_types:
                return "missing_user_evidence"
        elif not event_types.intersection(_FACT_EVIDENCE_TYPES):
            return "missing_fact_evidence"
        if _TRANSIENT_RE.search(candidate.content):
            return "transient_content"
        normalized = (candidate.category, self._normalize(candidate.content))
        if normalized in existing:
            return "duplicate"
        return ""

    def _evidence_types(self, chat_id: int | str) -> dict[str, str]:
        if self.event_store is None:
            return {}
        return {
            event.event_id: event.type
            for event in self.event_store.read_events(chat_id)
        }

    def _vault_token_count(self, entries: list[MemoryEntry]) -> int:
        payload = [entry.to_dict() for entry in entries]
        serialized = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        return self.token_counter.count_text(serialized).tokens

    def _fits(self, lines: list[str], line: str, max_tokens: int) -> bool:
        return self.token_counter.count_text("\n".join([*lines, line])).tokens <= max_tokens

    @staticmethod
    def _normalize(content: str) -> str:
        return " ".join(str(content or "").casefold().split())

    @staticmethod
    def _write(path: Path, vault: MemoryVault) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        try:
            with temp_path.open("w", encoding="utf-8", newline="\n") as handle:
                json.dump(vault.to_dict(), handle, ensure_ascii=False, indent=2)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_path, path)
        finally:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass
