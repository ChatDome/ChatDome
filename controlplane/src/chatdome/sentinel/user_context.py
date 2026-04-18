"""
Sentinel User Context Ledger — explicit user-approved baseline exceptions.

Allows the AI Agent to register exceptions (e.g. intentional port closures)
which the Sentinel Scheduler natively reads to suppress false alarms silently.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class UserContextRecord:
    """A single user-approved baseline override."""

    id: str
    check_id: str
    pattern: str
    summary: str
    created_at: float

    def to_dict(self) -> dict[str, str | float]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, str | float]) -> UserContextRecord:
        return cls(
            id=str(data.get("id", "")),
            check_id=str(data.get("check_id", "")),
            pattern=str(data.get("pattern", "")),
            summary=str(data.get("summary", "")),
            created_at=float(data.get("created_at", 0.0)),
        )


class UserContextLedger:
    """
    Manages the `user_context.json` flat file database.

    Provides high-speed `O(N)` exception checks for the Sentinel Scheduler.
    """

    def __init__(self, storage_path: Path | str = "chat_data/user_context.json") -> None:
        self.storage_path = Path(storage_path)
        self.records: list[UserContextRecord] = []
        self._load_from_disk()

    def _load_from_disk(self) -> None:
        """Load records from JSON file."""
        if not self.storage_path.exists():
            return

        try:
            raw_data = json.loads(self.storage_path.read_text(encoding="utf-8"))
            if isinstance(raw_data, list):
                self.records = [UserContextRecord.from_dict(item) for item in raw_data]
                logger.info("Loaded %d user context overrides from %s", len(self.records), self.storage_path)
        except Exception as e:
            logger.error("Failed to load user context from %s: %s", self.storage_path, e)

    def _save_to_disk(self) -> None:
        """Persist records to JSON file."""
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            data_to_write = [r.to_dict() for r in self.records]
            self.storage_path.write_text(json.dumps(data_to_write, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception as e:
            logger.error("Failed to save user context to %s: %s", self.storage_path, e)

    def add_context(self, check_id: str, pattern: str, summary: str) -> None:
        """
        Add a new user context override rule.
        
        Args:
            check_id: Target check definition ID (e.g. 'open_ports').
            pattern: Optional substring to match in the command stdout. Cases-insensitive.
            summary: Natural language intent context from user.
        """
        record = UserContextRecord(
            id=f"ctx-{int(time.time() * 1000)}",
            check_id=check_id,
            pattern=pattern,
            summary=summary,
            created_at=time.time()
        )
        self.records.append(record)
        self._save_to_disk()
        logger.info("Added user context override [%s] for check_id=%s, pattern=%s", record.id, check_id, pattern)

    def is_exempt(self, check_id: str, raw_output: str) -> str | None:
        """
        Check if a triggered alert output matches any user context override.

        Args:
            check_id: Target check definition ID triggered.
            raw_output: Command raw stdout context.

        Returns:
            The summary/reason of the matched override, or None if no match.
        """
        if not self.records:
            return None

        # Optimization: pre-calculate lower case to avoid repeated overhead per record evaluation
        raw_output_lower = raw_output.lower()

        for record in self.records:
            if record.check_id != check_id:
                continue

            if not record.pattern:
                return record.summary

            if record.pattern.lower() in raw_output_lower:
                return record.summary

        return None
