"""Shared exception types and user-facing error formatting."""

from __future__ import annotations


class ChatDomeError(RuntimeError):
    """Base class for errors that can be rendered safely to users."""

    code = "chatdome.error"
    user_message = "操作失败，请稍后重试。"
    retryable = False
    expose_detail = False

    def __init__(
        self,
        message: str = "",
        *,
        user_message: str | None = None,
        code: str | None = None,
        retryable: bool | None = None,
        expose_detail: bool | None = None,
    ) -> None:
        detail = str(message or "").strip()
        super().__init__(detail or user_message or self.user_message)
        self.detail = detail
        if user_message is not None:
            self.user_message = user_message
        if code is not None:
            self.code = code
        if retryable is not None:
            self.retryable = retryable
        if expose_detail is not None:
            self.expose_detail = expose_detail

    def to_user_message(self, *, include_code: bool = False) -> str:
        """Return a concise, safe message suitable for Telegram."""
        message = str(self.user_message or "").strip() or "操作失败，请稍后重试。"
        if self.expose_detail and self.detail and self.detail != message:
            message = f"{message}\n详情: {self.detail}"
        if include_code and self.code:
            message = f"{message}\n错误代码: {self.code}"
        return message


class ConfigError(ChatDomeError):
    code = "config.error"
    user_message = "配置无效，请检查 ChatDome 配置文件。"


class AgentError(ChatDomeError):
    code = "agent.error"
    user_message = "Agent 处理失败，请稍后重试。"


class AgentUnavailableError(AgentError):
    code = "agent.unavailable"
    user_message = "Agent 当前不可用，请稍后重试。"


class AgentStateError(AgentError):
    code = "agent.state_error"
    user_message = "当前会话状态无法继续，请发送 /clear 后重试。"


class ApprovalError(AgentError):
    code = "agent.approval_error"
    user_message = "命令审批流程无法继续，请重新发起任务。"


class LLMError(ChatDomeError):
    code = "llm.error"
    user_message = "LLM 当前不可用，请稍后重试。"


class LLMProfileError(LLMError):
    code = "llm.profile_error"
    user_message = "LLM profile 配置或状态异常。"
    expose_detail = True


class LLMProfileNotFound(LLMProfileError):
    code = "llm.profile_not_found"
    user_message = "未找到指定的 LLM profile。"


class LLMProfileNotReady(LLMProfileError):
    code = "llm.profile_not_ready"
    user_message = "LLM profile 尚未就绪。"


class LLMAuthenticationError(LLMError):
    code = "llm.authentication_error"
    user_message = "LLM 认证失败，请检查 API Key 或重新登录。"


class LLMRateLimitError(LLMError):
    code = "llm.rate_limited"
    user_message = "LLM 请求过于频繁，请稍后重试。"
    retryable = True


class LLMTimeoutError(LLMError, TimeoutError):
    code = "llm.timeout"
    user_message = "LLM 请求超时，请稍后重试。"
    retryable = True


class LLMProviderError(LLMError):
    code = "llm.provider_error"
    user_message = "LLM 服务返回异常，请稍后重试。"
    retryable = True


class LLMResponseFormatError(LLMError):
    code = "llm.response_format_error"
    user_message = "LLM 返回格式异常，请重新发起请求。"


class CodexAuthError(LLMAuthenticationError):
    code = "llm.codex_auth_error"
    user_message = "Codex 认证流程失败，请稍后重试。"


class CodexAuthTimeoutError(CodexAuthError, TimeoutError):
    code = "llm.codex_auth_timeout"
    user_message = "Codex 认证等待超时，请重新运行 /codex_login。"
    retryable = True


class SandboxError(ChatDomeError):
    code = "sandbox.error"
    user_message = "命令沙箱执行异常，请查看日志。"


class SandboxValidationError(SandboxError):
    code = "sandbox.validation_error"
    user_message = "命令未通过沙箱校验，已拒绝执行。"


class SandboxExecutionError(SandboxError):
    code = "sandbox.execution_error"
    user_message = "命令沙箱执行失败，请查看日志。"


class SandboxTimeoutError(SandboxError, TimeoutError):
    code = "sandbox.timeout"
    user_message = "命令执行超时，已终止。"
    retryable = True


def user_facing_error_message(
    exc: BaseException,
    *,
    fallback: str = "操作失败，请稍后重试。",
    include_code: bool = False,
) -> str:
    """Return a safe message for user-visible channels."""
    if isinstance(exc, ChatDomeError):
        return exc.to_user_message(include_code=include_code)
    if isinstance(exc, TimeoutError):
        return "操作超时，请稍后重试。"
    return fallback


__all__ = [
    "AgentError",
    "AgentStateError",
    "AgentUnavailableError",
    "ApprovalError",
    "ChatDomeError",
    "CodexAuthError",
    "CodexAuthTimeoutError",
    "ConfigError",
    "LLMAuthenticationError",
    "LLMError",
    "LLMProfileError",
    "LLMProfileNotFound",
    "LLMProfileNotReady",
    "LLMProviderError",
    "LLMRateLimitError",
    "LLMResponseFormatError",
    "LLMTimeoutError",
    "SandboxError",
    "SandboxExecutionError",
    "SandboxTimeoutError",
    "SandboxValidationError",
    "user_facing_error_message",
]
