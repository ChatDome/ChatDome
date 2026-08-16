"""Token accounting for complete LLM request payloads."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from typing import Any, Callable, Literal, Optional, Protocol


TokenCountMethod = Literal["model_tokenizer", "family_tokenizer", "heuristic"]


class TextEncoder(Protocol):
    def encode(self, text: str) -> list[int]:
        """Encode text into token identifiers."""


@dataclass(frozen=True)
class TokenCountResult:
    tokens: int
    method: TokenCountMethod


@dataclass(frozen=True)
class ContextBudgetSnapshot:
    current_tokens: int
    limit_tokens: int
    target_tokens: int
    usage_percent: int
    method: TokenCountMethod

    @property
    def requires_compaction(self) -> bool:
        return self.current_tokens >= self.limit_tokens


EncoderLoader = Callable[[str], tuple[Optional[TextEncoder], TokenCountMethod]]


def _load_encoder(model: str) -> tuple[TextEncoder | None, TokenCountMethod]:
    try:
        import tiktoken  # type: ignore[import-not-found]
    except ImportError:
        return None, "heuristic"

    try:
        return tiktoken.encoding_for_model(model), "model_tokenizer"
    except KeyError:
        model_name = str(model or "").lower()
        if any(marker in model_name for marker in ("gpt", "codex", "o1", "o3", "o4")):
            try:
                return tiktoken.get_encoding("o200k_base"), "family_tokenizer"
            except KeyError:
                pass
    return None, "heuristic"


class ContextTokenCounter:
    """Count the serialized request that will be sent to the LLM provider."""

    def __init__(
        self,
        model: str = "",
        *,
        encoder: TextEncoder | None = None,
        encoder_loader: EncoderLoader = _load_encoder,
    ) -> None:
        self.model = str(model or "")
        if encoder is not None:
            self._encoder = encoder
            self.method: TokenCountMethod = "model_tokenizer"
        else:
            self._encoder, self.method = encoder_loader(self.model)

    @staticmethod
    def _serialize(value: Any) -> str:
        return json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )

    @staticmethod
    def _heuristic_tokens(text: str) -> int:
        ascii_chars = sum(1 for char in text if ord(char) < 128)
        non_ascii_chars = len(text) - ascii_chars
        estimate = math.ceil(ascii_chars / 3) + math.ceil(non_ascii_chars * 1.5)
        return max(1, estimate)

    def count_text(self, text: str) -> TokenCountResult:
        value = str(text or "")
        if self._encoder is not None:
            return TokenCountResult(tokens=len(self._encoder.encode(value)), method=self.method)
        return TokenCountResult(tokens=self._heuristic_tokens(value), method="heuristic")

    def count_messages(self, messages: list[dict[str, Any]]) -> TokenCountResult:
        return self.count_text(self._serialize({"messages": list(messages or [])}))

    def count_request(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
    ) -> TokenCountResult:
        payload = {
            "messages": list(messages or []),
            "tools": list(tools or []),
        }
        return self.count_text(self._serialize(payload))


class ContextBudgetService:
    def __init__(
        self,
        counter: ContextTokenCounter,
        *,
        limit_tokens: int = 32_000,
        target_ratio: float = 0.70,
    ) -> None:
        self.counter = counter
        self.limit_tokens = max(1, int(limit_tokens))
        self.target_tokens = max(1, int(self.limit_tokens * float(target_ratio)))

    def snapshot(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
    ) -> ContextBudgetSnapshot:
        counted = self.counter.count_request(messages, tools)
        return ContextBudgetSnapshot(
            current_tokens=counted.tokens,
            limit_tokens=self.limit_tokens,
            target_tokens=self.target_tokens,
            usage_percent=round(counted.tokens / self.limit_tokens * 100),
            method=counted.method,
        )
