"""LLM provider adapters."""

from __future__ import annotations

from typing import Any

from chatdome.llm.client import LLMClient, LLMResponse, ToolCall
from chatdome.llm.codex_responses import CodexResponsesClient


def create_llm_client(ai_config: Any) -> Any:
    """Create the configured LLM provider adapter."""
    api_mode = getattr(ai_config, "api_mode", "openai_api")
    if api_mode == "codex_responses":
        return CodexResponsesClient(
            base_url=getattr(ai_config, "codex_base_url", "https://chatgpt.com/backend-api/codex"),
            model=getattr(ai_config, "model", "gpt-5.5"),
            temperature=getattr(ai_config, "temperature", 0.1),
            max_tokens=getattr(ai_config, "max_tokens", 2000),
            codex_client_id=getattr(ai_config, "codex_client_id", None) or None,
            codex_token_file=getattr(ai_config, "codex_token_file", None) or None,
        )

    return LLMClient(
        api_key=getattr(ai_config, "api_key", ""),
        base_url=getattr(ai_config, "base_url", "https://api.openai.com/v1"),
        model=getattr(ai_config, "model", "gpt-4o"),
        temperature=getattr(ai_config, "temperature", 0.1),
        max_tokens=getattr(ai_config, "max_tokens", 2000),
    )


__all__ = [
    "CodexResponsesClient",
    "LLMClient",
    "LLMResponse",
    "ToolCall",
    "create_llm_client",
]
