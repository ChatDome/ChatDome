"""Process-safe lease for the single interactive ChatDome turn."""

from __future__ import annotations

import contextlib
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any, TextIO

from chatdome.runtime_paths import run_path


DEFAULT_LOCK_PATH = run_path("global-turn.lock")


class GlobalTurnLease:
    """Exclusive turn ownership retained across approval states."""

    def __init__(
        self,
        lock_path: Path,
        file_handle: TextIO,
        owner: dict[str, Any],
    ) -> None:
        self.lock_path = lock_path
        self.metadata_path = lock_path.with_suffix(lock_path.suffix + ".json")
        self._file_handle = file_handle
        self._owner = owner
        self._released = False
        self._write_owner()

    @property
    def owner_id(self) -> str:
        return str(self._owner["owner_id"])

    def update(self, turn_id: int | None, state: str) -> None:
        if self._released:
            return
        self._owner["turn_id"] = turn_id
        self._owner["state"] = str(state or "running")
        self._owner["updated_at"] = time.time()
        self._write_owner()

    def release(self) -> None:
        if self._released:
            return
        self._released = True
        try:
            current = self._read_metadata()
            if current.get("owner_id") == self.owner_id:
                with contextlib.suppress(OSError):
                    self.metadata_path.unlink()
            _unlock(self._file_handle)
        finally:
            self._file_handle.close()

    def __del__(self) -> None:
        with contextlib.suppress(Exception):
            self.release()

    def _write_owner(self) -> None:
        self.metadata_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.metadata_path.with_name(
            f".{self.metadata_path.name}.{self.owner_id}.tmp"
        )
        temporary.write_text(
            json.dumps(self._owner, ensure_ascii=False, sort_keys=True),
            encoding="utf-8",
        )
        temporary.replace(self.metadata_path)

    def _read_metadata(self) -> dict[str, Any]:
        try:
            data = json.loads(self.metadata_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, json.JSONDecodeError):
            return {}
        return data if isinstance(data, dict) else {}


class GlobalTurnCoordinator:
    """Acquire one non-blocking OS lock shared by Telegram and CLI processes."""

    def __init__(self, lock_path: Path | None = None) -> None:
        self.lock_path = Path(lock_path or DEFAULT_LOCK_PATH)
        self.metadata_path = self.lock_path.with_suffix(self.lock_path.suffix + ".json")

    def try_acquire(
        self,
        source: str,
        chat_id: int,
        user_id: int | None,
    ) -> GlobalTurnLease | None:
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        file_handle = self.lock_path.open("a+", encoding="utf-8")
        if not _try_lock(file_handle):
            file_handle.close()
            return None
        now = time.time()
        try:
            return GlobalTurnLease(
                self.lock_path,
                file_handle,
                {
                    "owner_id": uuid.uuid4().hex,
                    "pid": os.getpid(),
                    "source": str(source or "unknown"),
                    "chat_id": int(chat_id),
                    "user_id": user_id,
                    "turn_id": None,
                    "state": "starting",
                    "acquired_at": now,
                    "updated_at": now,
                },
            )
        except Exception:
            _unlock(file_handle)
            file_handle.close()
            raise

    def read_owner(self) -> dict[str, Any]:
        try:
            data = json.loads(self.metadata_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, json.JSONDecodeError):
            return {}
        return data if isinstance(data, dict) else {}


def _try_lock(file_handle: TextIO) -> bool:
    if os.name == "posix":
        import fcntl

        try:
            fcntl.flock(file_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        return True
    if os.name == "nt":
        import msvcrt

        try:
            file_handle.seek(0)
            if not file_handle.read(1):
                file_handle.seek(0)
                file_handle.write(" ")
                file_handle.flush()
            file_handle.seek(0)
            msvcrt.locking(file_handle.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            return False
    return True


def _unlock(file_handle: TextIO) -> None:
    if os.name == "posix":
        import fcntl

        with contextlib.suppress(OSError):
            fcntl.flock(file_handle.fileno(), fcntl.LOCK_UN)
    elif os.name == "nt":
        import msvcrt

        file_handle.seek(0)
        with contextlib.suppress(OSError):
            msvcrt.locking(file_handle.fileno(), msvcrt.LK_UNLCK, 1)
