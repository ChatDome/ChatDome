"""Platform-neutral model command interaction workflow."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, replace
from typing import Any, Mapping

from chatdome.config import AIConfig, validate_profile_name
from chatdome.llm.profile_admin import CreateOpenAIProfileRequest, ProfileActor
from chatdome.model_commands import ModelCommandService
from chatdome.outbound.models import ActionKind, OutboundAction
from chatdome.slash_commands import CommandInvocation, CommandResult


@dataclass(frozen=True)
class CodexWorkflowRequest:
    """Validated request to start the shared Codex OAuth lifecycle."""

    profile_name: str
    forced_profile: AIConfig | None = None
    overwrite_existing: bool | None = None
    expected_profile_fingerprint: str | None = None


@dataclass(frozen=True)
class ModelWorkflowResult:
    """One model workflow result with an optional Codex operation."""

    result: CommandResult
    codex_request: CodexWorkflowRequest | None = None


class ModelCommandWorkflow:
    """Own model input, overwrite, save, and delete state for every platform."""

    def __init__(self, *, session_ttl: int = 300, confirmation_ttl: int = 60) -> None:
        self.session_ttl = session_ttl
        self.confirmation_ttl = confirmation_ttl
        self._sessions: dict[tuple[str, int, str], dict[str, Any]] = {}
        self._confirmations: dict[str, dict[str, Any]] = {}

    @property
    def sessions(self) -> Mapping[tuple[str, int, str], dict[str, Any]]:
        return self._sessions

    @property
    def confirmations(self) -> Mapping[str, dict[str, Any]]:
        return self._confirmations

    def pending_input(self, context: Any) -> tuple[str, str] | None:
        session = self._active_session(self._key_from_context(context))
        if session is None:
            return None
        step = str(session.get("step") or "")
        if step not in {"name", "model", "base_url", "api_key"}:
            return None
        return str(session["nonce"]), f"input_{step}"

    async def handle_add(
        self,
        invocation: CommandInvocation,
        service: ModelCommandService,
        actor: ProfileActor,
    ) -> ModelWorkflowResult:
        action = str(invocation.action or "").strip()
        if action in {"submit_openai", "submit_codex"}:
            return await self._submit_complete(invocation, service)
        if not action:
            return ModelWorkflowResult(self._start(invocation))

        key = self._key(invocation)
        session = self._active_session(key)
        nonce = str(invocation.interaction_id or "")
        refs = {"interaction_id": nonce}
        if session is None or str(session.get("nonce")) != nonce:
            return ModelWorkflowResult(self._expired(refs))

        if action in {"type_openai", "type_codex"}:
            session["type"] = action.removeprefix("type_")
            session["step"] = "name"
            return ModelWorkflowResult(
                self._input_result(session, "name", "输入 profile 名称。")
            )
        if action.startswith("input_"):
            return await self._accept_input(invocation, session, service)
        if action in {"cancel", "overwrite_no", "save_no"}:
            self._sessions.pop(key, None)
            return ModelWorkflowResult(service.cancel(True))
        if action == "overwrite_yes":
            if session.get("step") != "confirm_overwrite":
                return ModelWorkflowResult(self._invalid_state(refs))
            session["overwrite"] = True
            return ModelWorkflowResult(self._after_name(session))
        if action == "save_yes":
            if session.get("step") != "confirm_save":
                return ModelWorkflowResult(self._invalid_state(refs))
            saved = dict(session)
            self._sessions.pop(key, None)
            result = await service.create_openai(
                CreateOpenAIProfileRequest(
                    name=saved["name"],
                    model=saved["model"],
                    base_url=saved["base_url"],
                    api_key=str(saved.get("api_key") or ""),
                    temperature=float(saved.get("temperature", 0.1)),
                    max_tokens=int(saved.get("max_tokens", 2000)),
                    overwrite_existing=bool(saved.get("existing")),
                    expected_profile_fingerprint=saved.get("expected_fingerprint"),
                ),
                actor,
            )
            return ModelWorkflowResult(replace(result, event_refs=refs))
        if action == "codex_start":
            if session.get("step") != "codex_confirm":
                return ModelWorkflowResult(self._invalid_state(refs))
            saved = dict(session)
            self._sessions.pop(key, None)
            request = CodexWorkflowRequest(
                profile_name=str(saved["name"]),
                forced_profile=AIConfig(
                    provider="codex",
                    api_mode="codex_responses",
                    model=str(saved.get("model") or "gpt-5.5"),
                    temperature=float(saved.get("temperature", 0.1)),
                    max_tokens=int(saved.get("max_tokens", 2000)),
                    codex_client_id="",
                    codex_token_file="",
                    codex_base_url="https://chatgpt.com/backend-api/codex",
                ),
                overwrite_existing=saved.get("existing") is not None,
                expected_profile_fingerprint=saved.get("expected_fingerprint"),
            )
            return ModelWorkflowResult(
                CommandResult(outcome="codex_authorization_started", event_refs=refs),
                request,
            )
        return ModelWorkflowResult(
            CommandResult(
                outcome="invalid_interaction",
                text="Model 操作已失效，请重新开始。",
                severity="error",
                event_refs=refs,
            )
        )

    async def prepare_delete(
        self,
        invocation: CommandInvocation,
        service: ModelCommandService,
    ) -> CommandResult:
        if len(invocation.args) != 1:
            return CommandResult(
                outcome="invalid_arguments",
                text="Usage: /model_delete <profile>",
                severity="error",
            )
        summary = await service.inspect_delete(str(invocation.args[0]).strip())
        nonce = uuid.uuid4().hex[:12]
        self._confirmations[nonce] = {
            "key": self._key(invocation),
            "profile_name": summary.name,
            "expires_at": time.time() + self.confirmation_ttl,
        }
        refs = {"interaction_id": nonce, "profile": summary.name}
        return CommandResult(
            outcome="model_delete_confirmation_requested",
            title="Delete model profile",
            text=f"Delete model profile '{summary.name}'?",
            event_refs=refs,
            facts={"operation": "model_delete", "profile": summary.name},
            actions=self._actions(
                invocation.command.name,
                nonce,
                (
                    (ActionKind.CONFIRM, "确认删除", "delete_yes", True),
                    (ActionKind.CANCEL, "取消", "delete_no", False),
                ),
            ),
        )

    async def confirm_delete(
        self,
        invocation: CommandInvocation,
        service: ModelCommandService,
        actor: ProfileActor,
    ) -> CommandResult:
        nonce = str(invocation.interaction_id or "")
        refs = {"interaction_id": nonce}
        item = self._confirmations.pop(nonce, None)
        if (
            item is None
            or item.get("key") != self._key(invocation)
            or float(item.get("expires_at", 0)) < time.time()
        ):
            return CommandResult(
                outcome="interaction_expired",
                text="删除确认已失效，请重新运行 /model_delete。",
                severity="error",
                event_refs=refs,
            )
        if invocation.action == "delete_no":
            return replace(service.cancel(True), event_refs=refs)
        if invocation.action != "delete_yes":
            return self._invalid_state(refs)
        result = await service.delete(str(item["profile_name"]), actor)
        return replace(result, event_refs=refs)

    def cancel(self, invocation: CommandInvocation, service: ModelCommandService) -> CommandResult:
        key = self._key(invocation)
        removed = self._sessions.pop(key, None) is not None
        for nonce, item in list(self._confirmations.items()):
            if item.get("key") == key:
                self._confirmations.pop(nonce, None)
                removed = True
        return service.cancel(removed)

    def _start(self, invocation: CommandInvocation) -> CommandResult:
        key = self._key(invocation)
        if self._active_session(key) is not None:
            return CommandResult(
                outcome="interaction_in_progress",
                text="Complete the current model setup or run /model_cancel.",
            )
        nonce = uuid.uuid4().hex[:12]
        self._sessions[key] = {
            "step": "select_type",
            "nonce": nonce,
            "created_at": time.time(),
        }
        return CommandResult(
            outcome="model_add_input_requested",
            title="Add model profile",
            text="Select model type.",
            event_refs={"interaction_id": nonce},
            facts={"operation": "model_add", "stage": "select_type"},
            actions=self._actions(
                invocation.command.name,
                nonce,
                (
                    (ActionKind.SELECT, "OpenAI-compatible", "type_openai", False),
                    (ActionKind.SELECT, "Codex OAuth", "type_codex", False),
                    (ActionKind.CANCEL, "取消", "cancel", False),
                ),
            ),
        )

    async def _submit_complete(
        self,
        invocation: CommandInvocation,
        service: ModelCommandService,
    ) -> ModelWorkflowResult:
        params = dict(invocation.params)
        model_type = invocation.action.removeprefix("submit_")
        if model_type not in {"openai", "codex"}:
            return ModelWorkflowResult(
                CommandResult(
                    outcome="invalid_arguments",
                    text="Model type must be openai or codex.",
                    severity="error",
                )
            )
        name = validate_profile_name(str(params.get("name") or ""))
        summary = (
            await service.profile_admin.get_profile_summary(name)
            if service.profile_admin is not None
            else None
        )
        nonce = str(invocation.interaction_id or uuid.uuid4().hex[:12])
        session = {
            "step": "confirm_overwrite" if summary is not None else "ready",
            "nonce": nonce,
            "created_at": time.time(),
            "type": model_type,
            "name": name,
            "existing": summary,
            "expected_fingerprint": getattr(summary, "fingerprint", None),
            "model": str(params.get("model") or ("gpt-5.5" if model_type == "codex" else "")),
            "base_url": str(params.get("base_url") or "https://api.openai.com/v1"),
            "api_key": str(params.get("api_key") or ""),
            "temperature": float(params.get("temperature", 0.1)),
            "max_tokens": int(params.get("max_tokens", 2000)),
        }
        self._sessions[self._key(invocation)] = session
        if summary is not None:
            return ModelWorkflowResult(self._overwrite_result(invocation.command.name, session))
        if model_type == "codex":
            return ModelWorkflowResult(self._after_name(session))
        return ModelWorkflowResult(self._save_result(invocation.command.name, session))

    async def _accept_input(
        self,
        invocation: CommandInvocation,
        session: dict[str, Any],
        service: ModelCommandService,
    ) -> ModelWorkflowResult:
        step = str(session.get("step") or "")
        refs = {"interaction_id": str(session["nonce"])}
        if invocation.action != f"input_{step}":
            return ModelWorkflowResult(self._invalid_state(refs))
        text = str(invocation.params.get("input") or "").strip()
        if step == "api_key" and "secret" in invocation.params:
            text = str(invocation.params.get("secret") or "")
        if step == "name":
            name = validate_profile_name(text)
            summary = (
                await service.profile_admin.get_profile_summary(name)
                if service.profile_admin is not None
                else None
            )
            session["name"] = name
            session["existing"] = summary
            if summary is not None:
                session["step"] = "confirm_overwrite"
                session["expected_fingerprint"] = summary.fingerprint
                return ModelWorkflowResult(self._overwrite_result(invocation.command.name, session))
            return ModelWorkflowResult(self._after_name(session))
        if step == "model":
            existing = session.get("existing")
            session["model"] = existing.model if text == "-" and existing else text
            session["step"] = "base_url"
            default = existing.base_url if existing else "https://api.openai.com/v1"
            return ModelWorkflowResult(
                self._input_result(session, "base_url", f"输入 Base URL。发送 - 使用当前值: {default}")
            )
        if step == "base_url":
            existing = session.get("existing")
            session["base_url"] = existing.base_url if text == "-" and existing else text
            session["step"] = "api_key"
            prompt = (
                "输入 API Key，或发送 - 保留现有 Key。"
                if existing is not None and existing.api_mode == "openai_api"
                else "输入 API Key。敏感环境请使用本地菜单。"
            )
            return ModelWorkflowResult(self._input_result(session, "api_key", prompt))
        if step == "api_key":
            existing = session.get("existing")
            session["api_key"] = "" if text == "-" and existing else text
            return ModelWorkflowResult(self._save_result(invocation.command.name, session))
        return ModelWorkflowResult(self._invalid_state(refs))

    def _after_name(self, session: dict[str, Any]) -> CommandResult:
        if session.get("type") == "openai":
            session["step"] = "model"
            existing = session.get("existing")
            default = existing.model if existing is not None else "gpt-4o"
            return self._input_result(
                session, "model", f"输入模型名称。发送 - 使用当前值: {default}"
            )
        session["step"] = "codex_confirm"
        nonce = str(session["nonce"])
        return CommandResult(
            outcome="codex_authorization_confirmation_requested",
            title="Codex OAuth",
            text=f"为 profile '{session['name']}' 启动 Codex OAuth？",
            event_refs={"interaction_id": nonce},
            facts={"operation": "model_add", "stage": "codex_confirmation", "profile": session["name"]},
            actions=self._actions(
                "/model_add",
                nonce,
                (
                    (ActionKind.CONFIRM, "开始 Codex 授权", "codex_start", False),
                    (ActionKind.CANCEL, "取消", "cancel", False),
                ),
            ),
        )

    def _overwrite_result(self, command: str, session: dict[str, Any]) -> CommandResult:
        summary = session["existing"]
        nonce = str(session["nonce"])
        return CommandResult(
            outcome="model_overwrite_confirmation_requested",
            title="Overwrite model profile",
            text=(
                f"已存在 {summary.name}: {summary.provider}/{summary.api_mode}, "
                f"model={summary.model}, address={summary.base_url}"
            ),
            event_refs={"interaction_id": nonce},
            facts={"operation": "model_add", "stage": "confirm_overwrite", "profile": summary.name},
            actions=self._actions(
                command,
                nonce,
                (
                    (ActionKind.CONFIRM, "继续覆盖", "overwrite_yes", False),
                    (ActionKind.CANCEL, "取消", "overwrite_no", False),
                ),
            ),
        )

    def _save_result(self, command: str, session: dict[str, Any]) -> CommandResult:
        session["step"] = "confirm_save"
        nonce = str(session["nonce"])
        api_key = str(session.get("api_key") or "")
        existing = session.get("existing")
        action = "更新" if existing is not None else "新增"
        return CommandResult(
            outcome="model_save_confirmation_requested",
            title="Save model profile",
            text=(
                f"{action} {session['name']}？\n模型: {session['model']}\n"
                f"地址: {session['base_url']}\nAPI Key: "
                f"{'unchanged' if not api_key else 'configured'}"
            ),
            event_refs={"interaction_id": nonce},
            facts={
                "operation": "model_add",
                "stage": "confirm_save",
                "profile": session["name"],
                "api_key_status": "unchanged" if not api_key else "configured",
            },
            actions=self._actions(
                command,
                nonce,
                (
                    (ActionKind.CONFIRM, f"确认{action}", "save_yes", False),
                    (ActionKind.CANCEL, "取消", "save_no", False),
                ),
            ),
        )

    @staticmethod
    def _input_result(session: dict[str, Any], stage: str, text: str) -> CommandResult:
        return CommandResult(
            outcome="model_add_input_requested",
            title="Add model profile",
            text=text,
            event_refs={"interaction_id": str(session["nonce"])},
            facts={"operation": "model_add", "stage": stage},
        )

    @staticmethod
    def _expired(refs: Mapping[str, Any]) -> CommandResult:
        return CommandResult(
            outcome="interaction_expired",
            text="model 配置已失效，请重新运行 /model_add。",
            severity="error",
            event_refs=refs,
        )

    @staticmethod
    def _invalid_state(refs: Mapping[str, Any]) -> CommandResult:
        return CommandResult(
            outcome="invalid_interaction_state",
            text="model 配置状态无效，请重新开始。",
            severity="error",
            event_refs=refs,
        )

    @staticmethod
    def _actions(
        command: str,
        nonce: str,
        specs: tuple[tuple[ActionKind, str, str, bool], ...],
    ) -> tuple[OutboundAction, ...]:
        return tuple(
            OutboundAction(
                kind,
                label,
                f"llm_admin:{action}:{nonce}",
                destructive=destructive,
                params={
                    "command": command,
                    "action": action,
                    "interaction_id": nonce,
                },
            )
            for kind, label, action, destructive in specs
        )

    @staticmethod
    def _key(invocation: CommandInvocation) -> tuple[str, int, str]:
        return ModelCommandWorkflow._key_from_context(invocation.context)

    @staticmethod
    def _key_from_context(context: Any) -> tuple[str, int, str]:
        return str(context.source), int(context.chat_id), str(context.actor_id)

    def _active_session(
        self,
        key: tuple[str, int, str],
    ) -> dict[str, Any] | None:
        session = self._sessions.get(key)
        if session is None:
            return None
        if time.time() - float(session.get("created_at", 0)) > self.session_ttl:
            self._sessions.pop(key, None)
            return None
        return session
