"""Transactional LLM profile configuration management."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import tempfile
from contextlib import AbstractContextManager
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable

import yaml

from chatdome.config import (
    ChatDomeConfig,
    parse_config_document,
    validate_llm_config,
    validate_profile_name,
)
from chatdome.errors import (
    LLMProfileChanged,
    LLMProfileConflict,
    LLMProfileDeleteForbidden,
    LLMProfileNotFound,
    LLMProfileNotReady,
)


RuntimeApply = Callable[[ChatDomeConfig, str], Awaitable[None]]
AuditRecorder = Callable[[str, "ProfileActor", dict[str, Any]], None]


@dataclass(frozen=True)
class ProfileActor:
    source: str
    chat_id: int = 0
    user_id: int = 0


@dataclass(frozen=True)
class CreateOpenAIProfileRequest:
    name: str
    model: str
    base_url: str
    api_key: str
    temperature: float = 0.1
    max_tokens: int = 2000
    overwrite_existing: bool = False
    expected_profile_fingerprint: str | None = None


@dataclass(frozen=True)
class CreateCodexProfileRequest:
    name: str
    model: str
    client_id: str
    token_file: str
    base_url: str
    temperature: float = 0.1
    max_tokens: int = 2000
    overwrite_existing: bool = False
    expected_profile_fingerprint: str | None = None


@dataclass(frozen=True)
class ProfileSummary:
    name: str
    provider: str
    api_mode: str
    model: str
    base_url: str
    fingerprint: str
    active: bool
    has_api_key: bool


@dataclass(frozen=True)
class ProfileMutationResult:
    action: str
    profile_name: str
    active_profile: str
    profile_count: int


@dataclass
class _StoredMutation:
    result: ProfileMutationResult
    config: ChatDomeConfig
    previous_document: dict[str, Any]
    previous_config: ChatDomeConfig | None
    written_fingerprint: str


class _ConfigFileLock(AbstractContextManager):
    def __init__(self, path: Path) -> None:
        self.path = path
        self._handle = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = self.path.open("a+b")
        if self._handle.tell() == 0:
            self._handle.write(b"0")
            self._handle.flush()
        self._handle.seek(0)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(self._handle.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(self._handle.fileno(), fcntl.LOCK_EX)
        return self

    def __exit__(self, exc_type, exc, tb):
        if self._handle is not None:
            self._handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(self._handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)
            self._handle.close()
        return False


class ProfileConfigStore:
    """Serialize all LLM profile mutations through one atomic YAML writer."""

    def __init__(self, config_path: str | Path, lock_path: str | Path) -> None:
        self.config_path = Path(config_path).expanduser()
        self.lock_path = Path(lock_path).expanduser()

    @staticmethod
    def value_fingerprint(value: Any) -> str:
        payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def get_profile_summary(self, profile_name: str) -> ProfileSummary | None:
        name = validate_profile_name(profile_name)
        with _ConfigFileLock(self.lock_path):
            document = self._read_document()
            root = self._chatdome_root(document)
            profiles = self._profile_items(root)
            raw = profiles.get(name)
            if not isinstance(raw, dict):
                return None
            return self._summary(name, raw, str(root.get("active_ai_profile") or ""))

    def mutate(
        self,
        operation: Callable[[dict[str, Any]], ProfileMutationResult],
    ) -> _StoredMutation:
        with _ConfigFileLock(self.lock_path):
            previous_document = self._read_document()
            document = deepcopy(previous_document)
            previous_config = self._parse_optional(previous_document)
            result = operation(document)
            config = parse_config_document(document)
            validate_llm_config(config)
            self._write_document(document)
            return _StoredMutation(
                result=result,
                config=config,
                previous_document=previous_document,
                previous_config=previous_config,
                written_fingerprint=self.value_fingerprint(document),
            )

    def restore(self, mutation: _StoredMutation) -> bool:
        with _ConfigFileLock(self.lock_path):
            current = self._read_document()
            if self.value_fingerprint(current) != mutation.written_fingerprint:
                return False
            self._write_document(mutation.previous_document)
            return True

    def _read_document(self) -> dict[str, Any]:
        if not self.config_path.is_file():
            raise LLMProfileNotReady(
                f"Configuration file not found: {self.config_path}",
                user_message="未找到 ChatDome 配置文件。",
            )
        raw = yaml.safe_load(self.config_path.read_text(encoding="utf-8")) or {}
        if not isinstance(raw, dict):
            raise LLMProfileNotReady(
                "Configuration document must be a mapping.",
                user_message="ChatDome 配置文件格式无效。",
            )
        return raw

    def _write_document(self, document: dict[str, Any]) -> None:
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(
            prefix=f".{self.config_path.name}.",
            suffix=".tmp",
            dir=str(self.config_path.parent),
        )
        temp_path = Path(temp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                yaml.safe_dump(
                    document,
                    handle,
                    allow_unicode=True,
                    sort_keys=False,
                )
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temp_path, 0o600)
            os.replace(temp_path, self.config_path)
            try:
                directory_fd = os.open(str(self.config_path.parent), os.O_RDONLY)
            except OSError:
                directory_fd = -1
            if directory_fd >= 0:
                try:
                    os.fsync(directory_fd)
                except OSError:
                    pass
                finally:
                    os.close(directory_fd)
        finally:
            if temp_path.exists():
                temp_path.unlink()

    @staticmethod
    def _chatdome_root(document: dict[str, Any]) -> dict[str, Any]:
        root = document.setdefault("chatdome", {})
        if not isinstance(root, dict):
            raise LLMProfileNotReady(
                "chatdome root must be a mapping.",
                user_message="ChatDome 配置文件格式无效。",
            )
        return root

    @staticmethod
    def _profile_items(root: dict[str, Any]) -> dict[str, Any]:
        profiles = root.setdefault("ai_profiles", {})
        if not isinstance(profiles, dict):
            raise LLMProfileNotReady(
                "chatdome.ai_profiles must be a mapping.",
                user_message="LLM profile 配置格式无效。",
            )
        return profiles

    @classmethod
    def _summary(cls, name: str, raw: dict[str, Any], active: str) -> ProfileSummary:
        api_mode = str(raw.get("api_mode") or "openai_api")
        base_url = (
            str(raw.get("codex_base_url") or "")
            if api_mode == "codex_responses"
            else str(raw.get("base_url") or "")
        )
        return ProfileSummary(
            name=name,
            provider=str(raw.get("provider") or "openai"),
            api_mode=api_mode,
            model=str(raw.get("model") or ""),
            base_url=base_url,
            fingerprint=cls.value_fingerprint(raw),
            active=name == active,
            has_api_key=bool(str(raw.get("api_key") or "").strip()),
        )

    @staticmethod
    def _parse_optional(document: dict[str, Any]) -> ChatDomeConfig | None:
        try:
            return parse_config_document(document)
        except ValueError:
            return None


class LLMProfileAdminService:
    def __init__(
        self,
        store: ProfileConfigStore,
        *,
        runtime_apply: RuntimeApply | None = None,
        audit_recorder: AuditRecorder | None = None,
    ) -> None:
        self.store = store
        self.runtime_apply = runtime_apply
        self.audit_recorder = audit_recorder

    async def get_profile_summary(self, profile_name: str) -> ProfileSummary | None:
        return await asyncio.to_thread(self.store.get_profile_summary, profile_name)

    async def create_openai(
        self,
        request: CreateOpenAIProfileRequest,
        actor: ProfileActor,
    ) -> ProfileMutationResult:
        name = validate_profile_name(request.name)

        def operation(document: dict[str, Any]) -> ProfileMutationResult:
            root = self.store._chatdome_root(document)
            profiles = self.store._profile_items(root)
            existing = profiles.get(name)
            self._validate_overwrite(
                name,
                existing,
                request.overwrite_existing,
                request.expected_profile_fingerprint,
            )
            api_key = str(request.api_key or "").strip()
            if not api_key and isinstance(existing, dict):
                if str(existing.get("api_mode") or "openai_api") == "openai_api":
                    api_key = str(existing.get("api_key") or "").strip()
            if not api_key:
                raise LLMProfileNotReady(
                    "api_key is required",
                    user_message="请输入 API Key。",
                )
            action = "updated" if isinstance(existing, dict) else "created"
            profiles[name] = {
                "provider": "openai",
                "api_mode": "openai_api",
                "base_url": str(request.base_url or "https://api.openai.com/v1").strip(),
                "model": str(request.model or "gpt-4o").strip(),
                "temperature": float(request.temperature),
                "max_tokens": int(request.max_tokens),
                "api_key": api_key,
            }
            if not str(root.get("active_ai_profile") or "").strip():
                root["active_ai_profile"] = name
            return self._result(action, name, root, profiles)

        failure_action = "update" if request.overwrite_existing else "create"
        return await self._run_mutation(operation, actor, failure_action)

    async def create_codex(
        self,
        request: CreateCodexProfileRequest,
        actor: ProfileActor,
    ) -> ProfileMutationResult:
        name = validate_profile_name(request.name)
        token_file = str(request.token_file or "").strip()
        if not token_file or not Path(token_file).expanduser().is_file():
            raise LLMProfileNotReady(
                "codex token file is missing",
                user_message="Codex Token 文件不存在，请重新认证。",
            )

        def operation(document: dict[str, Any]) -> ProfileMutationResult:
            root = self.store._chatdome_root(document)
            profiles = self.store._profile_items(root)
            existing = profiles.get(name)
            self._validate_overwrite(
                name,
                existing,
                request.overwrite_existing,
                request.expected_profile_fingerprint,
            )
            action = "updated" if isinstance(existing, dict) else "created"
            profiles[name] = {
                "provider": "codex",
                "api_mode": "codex_responses",
                "model": str(request.model or "gpt-5.5").strip(),
                "temperature": float(request.temperature),
                "max_tokens": int(request.max_tokens),
                "codex_client_id": str(request.client_id or "").strip(),
                "codex_token_file": token_file,
                "codex_base_url": str(
                    request.base_url or "https://chatgpt.com/backend-api/codex"
                ).strip(),
            }
            if not str(root.get("active_ai_profile") or "").strip():
                root["active_ai_profile"] = name
            return self._result(action, name, root, profiles)

        failure_action = "update" if request.overwrite_existing else "create"
        return await self._run_mutation(operation, actor, failure_action)

    async def delete_profile(
        self,
        profile_name: str,
        actor: ProfileActor,
    ) -> ProfileMutationResult:
        name = validate_profile_name(profile_name)

        def operation(document: dict[str, Any]) -> ProfileMutationResult:
            root = self.store._chatdome_root(document)
            profiles = self.store._profile_items(root)
            if name not in profiles:
                raise LLMProfileNotFound(f"Unknown LLM profile: {name}")
            if str(root.get("active_ai_profile") or "") == name:
                raise LLMProfileDeleteForbidden(
                    f"Cannot delete active LLM profile: {name}",
                    user_message="请先切换 LLM，再删除该 profile。",
                )
            if len(profiles) <= 1:
                raise LLMProfileDeleteForbidden(
                    "Cannot delete the last LLM profile.",
                    user_message="至少保留一个 LLM profile。",
                )
            del profiles[name]
            return self._result("deleted", name, root, profiles)

        return await self._run_mutation(operation, actor, "delete")

    async def set_active_profile(
        self,
        profile_name: str,
        actor: ProfileActor,
    ) -> ProfileMutationResult:
        name = validate_profile_name(profile_name)

        def operation(document: dict[str, Any]) -> ProfileMutationResult:
            root = self.store._chatdome_root(document)
            profiles = self.store._profile_items(root)
            if name not in profiles:
                raise LLMProfileNotFound(f"Unknown LLM profile: {name}")
            profile = profiles[name]
            if not isinstance(profile, dict):
                raise LLMProfileNotReady(f"Invalid LLM profile: {name}")
            api_mode = str(profile.get("api_mode") or "openai_api")
            if api_mode == "openai_api" and not str(profile.get("api_key") or "").strip():
                raise LLMProfileNotReady(
                    f"LLM profile {name!r} is missing api_key.",
                    user_message="该 LLM profile 未配置 API Key。",
                )
            if api_mode == "codex_responses":
                token_file = str(profile.get("codex_token_file") or "").strip()
                if not token_file or not Path(token_file).expanduser().is_file():
                    raise LLMProfileNotReady(
                        f"LLM profile {name!r} is missing Codex token.",
                        user_message="该 Codex profile 尚未完成认证。",
                    )
            root["active_ai_profile"] = name
            return self._result("switched", name, root, profiles)

        return await self._run_mutation(operation, actor, "switch")

    async def _run_mutation(
        self,
        operation: Callable[[dict[str, Any]], ProfileMutationResult],
        actor: ProfileActor,
        failure_action: str,
    ) -> ProfileMutationResult:
        mutation: _StoredMutation | None = None
        try:
            mutation = await asyncio.to_thread(self.store.mutate, operation)
            if self.runtime_apply is not None:
                await self.runtime_apply(mutation.config, mutation.result.action)
            self._audit(f"llm_profile_{mutation.result.action}", actor, mutation.result)
            return mutation.result
        except Exception as exc:
            rollback_error_type = ""
            if mutation is not None and self.runtime_apply is not None:
                try:
                    restored = await asyncio.to_thread(self.store.restore, mutation)
                    if restored and mutation.previous_config is not None:
                        await self.runtime_apply(mutation.previous_config, "rollback")
                except Exception as rollback_exc:
                    rollback_error_type = type(rollback_exc).__name__
            action = failure_action
            if mutation is not None:
                action = {
                    "created": "create",
                    "updated": "update",
                    "deleted": "delete",
                    "switched": "switch",
                }.get(mutation.result.action, failure_action)
            self._audit(
                f"llm_profile_{action}_failed",
                actor,
                None,
                error_type=type(exc).__name__,
                rollback_error_type=rollback_error_type,
            )
            raise

    def _audit(
        self,
        event_type: str,
        actor: ProfileActor,
        result: ProfileMutationResult | None,
        **fields: Any,
    ) -> None:
        if self.audit_recorder is None:
            return
        payload = dict(fields)
        if result is not None:
            payload.update(
                profile_name=result.profile_name,
                active_profile=result.active_profile,
                profile_count=result.profile_count,
            )
        self.audit_recorder(event_type, actor, payload)

    @classmethod
    def _validate_overwrite(
        cls,
        name: str,
        existing: Any,
        overwrite_existing: bool,
        expected_fingerprint: str | None,
    ) -> None:
        if not isinstance(existing, dict):
            return
        if not overwrite_existing:
            raise LLMProfileConflict(
                f"Profile already exists: {name}",
                user_message=f"LLM profile 已存在: {name}",
            )
        actual = ProfileConfigStore.value_fingerprint(existing)
        if not expected_fingerprint or actual != expected_fingerprint:
            raise LLMProfileChanged(
                f"LLM profile changed before overwrite: {name}",
                user_message="LLM profile 已发生变化，请重新开始操作。",
            )

    @staticmethod
    def _result(
        action: str,
        name: str,
        root: dict[str, Any],
        profiles: dict[str, Any],
    ) -> ProfileMutationResult:
        return ProfileMutationResult(
            action=action,
            profile_name=name,
            active_profile=str(root.get("active_ai_profile") or ""),
            profile_count=len(profiles),
        )
