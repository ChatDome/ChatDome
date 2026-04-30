"""LLM provider adapters."""

from __future__ import annotations

from typing import Any

from chatdome.llm.client import LLMClient, LLMResponse, ToolCall
from chatdome.llm.codex_cli import CodexCLIClient


def create_llm_client(ai_config: Any) -> Any:
    """Create the configured LLM provider adapter."""
    api_mode = getattr(ai_config, "api_mode", "openai_api")
    if api_mode == "codex_cli":
        return CodexCLIClient(
            command=getattr(ai_config, "codex_command", "codex"),
            model=getattr(ai_config, "model", "gpt-5.4"),
            profile=getattr(ai_config, "codex_profile", ""),
            cwd=getattr(ai_config, "codex_cwd", ""),
            timeout=getattr(ai_config, "codex_timeout", 300),
            sandbox=getattr(ai_config, "codex_sandbox", "read-only"),
            approval_policy=getattr(ai_config, "codex_approval_policy", "never"),
            ephemeral=getattr(ai_config, "codex_ephemeral", True),
            validate_auth=getattr(ai_config, "codex_validate_auth", True),
        )

    return LLMClient(
        api_key=getattr(ai_config, "api_key", ""),
        base_url=getattr(ai_config, "base_url", "https://api.openai.com/v1"),
        model=getattr(ai_config, "model", "gpt-4o"),
        temperature=getattr(ai_config, "temperature", 0.1),
        max_tokens=getattr(ai_config, "max_tokens", 2000),
    )


__all__ = [
    "CodexCLIClient",
    "LLMClient",
    "LLMResponse",
    "ToolCall",
    "create_llm_client",
]
