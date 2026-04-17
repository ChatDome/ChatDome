"""
Command audit tracker with tamper-evident hash chain.

Stores append-only JSONL records under chat_data/audit, one file per UTC day.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


AUDIT_DIR = Path("chat_data") / "audit"
AUDIT_FILE_PREFIX = "audit-"
AUDIT_FILE_SUFFIX = ".jsonl"
GENESIS_HASH = "0" * 64
DEFAULT_RETENTION_DAYS = 30


class CommandAuditTracker:
    """
    Append-only command audit tracker.

    Each record carries:
    - prev_hash: previous record hash in the same file
    - event_hash: hash of current record payload (excluding event_hash itself)
    """

    _lock = threading.Lock()
    _last_cleanup_ts: float = 0.0
    _cleanup_interval_seconds: int = 3600

    @classmethod
    def record_event(
        cls,
        event_type: str,
        chat_id: int = 0,
        **fields: Any,
    ) -> None:
        """Append one audit event."""
        now = datetime.now(timezone.utc)
        payload: dict[str, Any] = {
            "timestamp": int(now.timestamp()),
            "timestamp_iso": now.isoformat().replace("+00:00", "Z"),
            "event_type": str(event_type),
            "chat_id": int(chat_id),
        }
        payload.update(cls._sanitize(fields))

        try:
            cls._append_record(payload, now)
            cls._maybe_cleanup(now)
        except Exception as e:
            logger.error("Failed to write command audit event: %s", e)

    @classmethod
    def get_recent_events(cls, chat_id: int | None = None, limit: int = 20) -> list[dict[str, Any]]:
        """Read recent audit events, newest first."""
        if limit <= 0:
            return []

        if not AUDIT_DIR.exists():
            return []

        events: list[dict[str, Any]] = []
        paths = sorted(
            AUDIT_DIR.glob(f"{AUDIT_FILE_PREFIX}*{AUDIT_FILE_SUFFIX}"),
            reverse=True,
        )

        for path in paths:
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except OSError:
                continue

            for line in reversed(lines):
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if chat_id is not None and int(record.get("chat_id", -1)) != int(chat_id):
                    continue

                events.append(record)
                if len(events) >= limit:
                    return events

        return events

    @classmethod
    def verify_file(cls, path: Path) -> tuple[bool, str]:
        """Verify one audit file hash chain."""
        expected_prev = GENESIS_HASH
        line_no = 0

        try:
            with path.open("r", encoding="utf-8") as f:
                for raw in f:
                    line_no += 1
                    line = raw.strip()
                    if not line:
                        continue

                    record = json.loads(line)
                    prev_hash = str(record.get("prev_hash", ""))
                    if prev_hash != expected_prev:
                        return False, f"line {line_no}: prev_hash mismatch"

                    recorded_hash = str(record.get("event_hash", ""))
                    computed_hash = cls._compute_event_hash(record)
                    if recorded_hash != computed_hash:
                        return False, f"line {line_no}: event_hash mismatch"

                    expected_prev = recorded_hash
        except FileNotFoundError:
            return False, f"file not found: {path}"
        except json.JSONDecodeError as e:
            return False, f"invalid json at line {line_no}: {e}"
        except OSError as e:
            return False, f"io error: {e}"

        return True, "ok"

    @classmethod
    def cleanup_old_files(
        cls,
        retention_days: int = DEFAULT_RETENTION_DAYS,
        now: datetime | None = None,
    ) -> int:
        """Delete audit files older than retention window. Returns delete count."""
        if retention_days <= 0:
            retention_days = DEFAULT_RETENTION_DAYS

        now = now or datetime.now(timezone.utc)
        oldest_keep_date = now.date() - timedelta(days=retention_days - 1)
        deleted = 0

        if not AUDIT_DIR.exists():
            return 0

        for path in AUDIT_DIR.glob(f"{AUDIT_FILE_PREFIX}*{AUDIT_FILE_SUFFIX}"):
            file_date = cls._extract_file_date(path.name)
            if file_date is None:
                continue
            if file_date < oldest_keep_date:
                try:
                    path.unlink()
                    deleted += 1
                except OSError as e:
                    logger.warning("Failed to delete old audit file %s: %s", path, e)

        return deleted

    @staticmethod
    def sha256_text(text: str) -> str:
        """Stable SHA-256 digest for text payloads."""
        return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()

    @classmethod
    def _append_record(cls, payload: dict[str, Any], now: datetime) -> None:
        AUDIT_DIR.mkdir(parents=True, exist_ok=True)
        file_path = AUDIT_DIR / f"{AUDIT_FILE_PREFIX}{now.strftime('%Y-%m-%d')}{AUDIT_FILE_SUFFIX}"

        with cls._lock:
            prev_hash = cls._load_last_hash(file_path)
            payload["prev_hash"] = prev_hash
            payload["event_hash"] = cls._compute_event_hash(payload)

            with file_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")

    @classmethod
    def _load_last_hash(cls, file_path: Path) -> str:
        if not file_path.exists():
            return GENESIS_HASH

        last_hash = GENESIS_HASH
        try:
            with file_path.open("r", encoding="utf-8") as f:
                for raw in f:
                    line = raw.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    candidate = str(record.get("event_hash", ""))
                    if len(candidate) == 64:
                        last_hash = candidate
        except OSError as e:
            logger.warning("Failed reading existing audit file %s: %s", file_path, e)

        return last_hash

    @classmethod
    def _compute_event_hash(cls, record: dict[str, Any]) -> str:
        canonical = cls._canonical_json(record)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @staticmethod
    def _canonical_json(record: dict[str, Any]) -> str:
        payload = dict(record)
        payload.pop("event_hash", None)
        return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    @classmethod
    def _maybe_cleanup(cls, now: datetime) -> None:
        now_ts = time.time()
        if (now_ts - cls._last_cleanup_ts) < cls._cleanup_interval_seconds:
            return

        with cls._lock:
            # Double-check after lock to avoid duplicate cleanup under concurrency.
            now_ts = time.time()
            if (now_ts - cls._last_cleanup_ts) < cls._cleanup_interval_seconds:
                return
            deleted = cls.cleanup_old_files(retention_days=DEFAULT_RETENTION_DAYS, now=now)
            cls._last_cleanup_ts = now_ts
            if deleted:
                logger.info("Command audit cleanup removed %d old file(s)", deleted)

    @staticmethod
    def _extract_file_date(filename: str):
        if not (filename.startswith(AUDIT_FILE_PREFIX) and filename.endswith(AUDIT_FILE_SUFFIX)):
            return None

        date_str = filename[len(AUDIT_FILE_PREFIX): -len(AUDIT_FILE_SUFFIX)]
        try:
            return datetime.strptime(date_str, "%Y-%m-%d").date()
        except ValueError:
            return None

    @classmethod
    def _sanitize(cls, value: Any) -> Any:
        if value is None:
            return None
        if isinstance(value, (str, int, float, bool)):
            return value
        if isinstance(value, dict):
            return {str(k): cls._sanitize(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [cls._sanitize(v) for v in value]
        return str(value)
