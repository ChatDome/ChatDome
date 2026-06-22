"""File-based runtime reload request protocol.

The local management menu writes reload requests under the configured runtime
data directory and the running ChatDome process polls the same files.  This keeps the control path
simple: no extra daemon, socket, or database is required.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from chatdome.runtime_paths import data_dir


SUPPORTED_RELOAD_DOMAINS = {"llm", "sentinel", "agent", "all"}


@dataclass(frozen=True)
class ReloadRequest:
    """One reload request created by menu/CLI tooling."""

    request_id: str
    domains: list[str]
    requested_at: float
    source: str = "manual"
    config_path: str = ""


@dataclass(frozen=True)
class ReloadStatus:
    """Last known reload result."""

    request_id: str
    ok: bool
    message: str
    applied_domains: list[str] = field(default_factory=list)
    completed_at: float = field(default_factory=time.time)


class ReloadControl:
    """Read and write reload request/status files."""

    def __init__(
        self,
        base_dir: str | Path | None = None,
        request_file: str = "reload_request.json",
        status_file: str = "reload_status.json",
    ) -> None:
        self.base_dir = Path(base_dir) if base_dir is not None else data_dir()
        self.request_path = self.base_dir / request_file
        self.status_path = self.base_dir / status_file

    def request_reload(
        self,
        domains: list[str] | tuple[str, ...] | str,
        *,
        source: str = "manual",
        config_path: str = "",
    ) -> ReloadRequest:
        """Create a reload request and persist it atomically."""
        normalized = self.normalize_domains(domains)
        request = ReloadRequest(
            request_id=f"reload-{int(time.time())}-{uuid.uuid4().hex[:8]}",
            domains=normalized,
            requested_at=time.time(),
            source=str(source or "manual"),
            config_path=str(config_path or ""),
        )
        self._write_json(self.request_path, self._request_to_dict(request))
        return request

    def load_request(self) -> ReloadRequest | None:
        """Load the current pending request, if any."""
        data = self._read_json(self.request_path)
        if not data:
            return None
        request_id = str(data.get("request_id") or "").strip()
        if not request_id:
            return None
        domains = self.normalize_domains(data.get("domains") or [])
        return ReloadRequest(
            request_id=request_id,
            domains=domains,
            requested_at=float(data.get("requested_at") or 0.0),
            source=str(data.get("source") or "manual"),
            config_path=str(data.get("config_path") or ""),
        )

    def clear_request(self, request_id: str | None = None) -> bool:
        """Remove the pending request if it matches the optional id."""
        request = self.load_request()
        if request is None:
            return False
        if request_id and request.request_id != request_id:
            return False
        try:
            self.request_path.unlink()
            return True
        except FileNotFoundError:
            return False

    def mark_status(
        self,
        request_id: str,
        *,
        ok: bool,
        message: str,
        applied_domains: list[str] | tuple[str, ...] | str = (),
    ) -> ReloadStatus:
        """Persist the result of a reload attempt."""
        status = ReloadStatus(
            request_id=str(request_id),
            ok=bool(ok),
            message=str(message),
            applied_domains=self.normalize_domains(applied_domains) if applied_domains else [],
            completed_at=time.time(),
        )
        self._write_json(self.status_path, self._status_to_dict(status))
        return status

    def load_status(self) -> ReloadStatus | None:
        """Load the last reload status, if present."""
        data = self._read_json(self.status_path)
        if not data:
            return None
        request_id = str(data.get("request_id") or "").strip()
        if not request_id:
            return None
        return ReloadStatus(
            request_id=request_id,
            ok=bool(data.get("ok")),
            message=str(data.get("message") or ""),
            applied_domains=self.normalize_domains(data.get("applied_domains") or []),
            completed_at=float(data.get("completed_at") or 0.0),
        )

    @staticmethod
    def normalize_domains(domains: list[str] | tuple[str, ...] | str) -> list[str]:
        """Validate and normalize reload domains."""
        if isinstance(domains, str):
            raw_items = [item.strip() for item in domains.split(",")]
        else:
            raw_items = [str(item).strip() for item in domains]

        normalized: list[str] = []
        for item in raw_items:
            if not item:
                continue
            item = item.lower()
            if item not in SUPPORTED_RELOAD_DOMAINS:
                raise ValueError(
                    f"Unsupported reload domain: {item}. "
                    f"Supported: {', '.join(sorted(SUPPORTED_RELOAD_DOMAINS))}"
                )
            if item == "all":
                return ["all"]
            if item not in normalized:
                normalized.append(item)

        if not normalized:
            raise ValueError("At least one reload domain is required.")
        return normalized

    @staticmethod
    def _request_to_dict(request: ReloadRequest) -> dict[str, Any]:
        return {
            "version": 1,
            "request_id": request.request_id,
            "domains": request.domains,
            "requested_at": request.requested_at,
            "source": request.source,
            "config_path": request.config_path,
        }

    @staticmethod
    def _status_to_dict(status: ReloadStatus) -> dict[str, Any]:
        return {
            "version": 1,
            "request_id": status.request_id,
            "ok": status.ok,
            "message": status.message,
            "applied_domains": status.applied_domains,
            "completed_at": status.completed_at,
        }

    @staticmethod
    def _read_json(path: Path) -> dict[str, Any] | None:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON in {path}: {exc}") from exc
        if not isinstance(data, dict):
            raise ValueError(f"Invalid reload payload in {path}: expected object")
        return data

    @staticmethod
    def _write_json(path: Path, payload: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = path.with_name(f"{path.name}.tmp")
        tmp_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        tmp_path.replace(path)
