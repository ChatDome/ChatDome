"""
OpenAI-compatible LLM API client with async support.

Supports any provider that implements the OpenAI chat completion
API format (OpenAI, Azure, local models via LiteLLM, etc.).
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

import openai

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Response types
# ---------------------------------------------------------------------------

@dataclass
class ToolCall:
    """A parsed tool call from the LLM response."""
    id: str
    name: str
    arguments: str  # raw JSON string


@dataclass
class LLMResponse:
    """Normalized LLM response."""
    content: str | None = None
    tool_calls: list[ToolCall] = field(default_factory=list)
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class LLMClient:
    """
    Async OpenAI-compatible LLM client.

    Wraps the openai.AsyncOpenAI SDK with retry logic and
    normalized response handling.
    """

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.openai.com/v1",
        model: str = "gpt-4o",
        temperature: float = 0.1,
        max_tokens: int = 2000,
        max_retries: int = 3,
    ):
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.max_retries = max_retries

        self._client = openai.AsyncOpenAI(
            api_key=api_key,
            base_url=base_url,
        )

        logger.info(
            "LLM client initialized: model=%s, base_url=%s",
            model, base_url,
        )

    async def chat_completion(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        response_format: dict[str, str] | None = None,
    ) -> LLMResponse:
        """
        Send a chat completion request to the LLM.

        Args:
            messages: OpenAI-format message history.
            tools: Optional tool/function definitions.
            response_format: Optional dict for JSON output format.

        Returns:
            Normalized LLMResponse.

        Raises:
            Exception: After all retries are exhausted.
        """
        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"
        if response_format:
            kwargs["response_format"] = response_format

        last_error: Exception | None = None
        for attempt in range(1, self.max_retries + 1):
            try:
                response = await self._client.chat.completions.create(**kwargs)
                return self._parse_response(response)

            except openai.RateLimitError as e:
                last_error = e
                wait_time = 2 ** attempt
                logger.warning(
                    "Rate limited (attempt %d/%d), retrying in %ds: %s",
                    attempt, self.max_retries, wait_time, e,
                )
                await asyncio.sleep(wait_time)

            except openai.APITimeoutError as e:
                last_error = e
                wait_time = 2 ** attempt
                logger.warning(
                    "API timeout (attempt %d/%d), retrying in %ds: %s",
                    attempt, self.max_retries, wait_time, e,
                )
                await asyncio.sleep(wait_time)

            except openai.AuthenticationError as e:
                logger.error("Authentication failed: %s", e)
                raise

            except openai.APIError as e:
                last_error = e
                logger.error(
                    "API error (attempt %d/%d): %s",
                    attempt, self.max_retries, e,
                )
                if attempt < self.max_retries:
                    await asyncio.sleep(2 ** attempt)

        raise RuntimeError(
            f"LLM API call failed after {self.max_retries} attempts: {last_error}"
        )

    async def evaluate_command_safety(
        self, command: str, system_prompt: str, chat_id: int = 0
    ) -> dict[str, Any]:
        """
        Use the LLM to evaluate the safety and impact of a shell command.
        Forces JSON output format.
        """
        review_command = self._format_command_for_review(command)
        messages = [
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": (
                    "请分析以下命令（其中 \\n / \\r / \\t 为转义后的可视符号，不是实际换行执行）：\n"
                    f"{review_command}"
                ),
            },
        ]
        
        # Force low temperature to ensure deterministic safety output
        original_temp = self.temperature
        self.temperature = 0.0
        
        try:
            # Note: json_object format is supported by OpenAI and many compatible providers.
            response = await self.chat_completion(
                messages=messages,
                response_format={"type": "json_object"}
            )
            content = response.content or "{}"
            result = self._parse_json_object(content)
            
            if chat_id > 0:
                from chatdome.agent.tracker import TokenTracker
                TokenTracker.record_usage(
                    chat_id=chat_id,
                    model=self.model,
                    action="ai_reviewer",
                    prompt_tokens=response.prompt_tokens,
                    completion_tokens=response.completion_tokens,
                    total_tokens=response.total_tokens
                )
            
            # Normalize and ensure required fields exist
            safety_status = str(result.get("safety_status", "UNSAFE")).strip().upper()
            if safety_status not in {"SAFE", "UNSAFE", "CRITICAL"}:
                safety_status = "UNSAFE"

            risk_level = str(result.get("risk_level", "HIGH")).strip().upper()
            if risk_level not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
                risk_level = "HIGH"

            mutation_detected = bool(result.get("mutation_detected", safety_status != "SAFE"))
            deletion_detected = bool(result.get("deletion_detected", False))
            impact_analysis = str(result.get("impact_analysis", "无法解析安全分析结果")).strip()

            # Safety consistency correction (fail-safe)
            if mutation_detected and safety_status == "SAFE":
                safety_status = "UNSAFE"
            if deletion_detected and risk_level in {"LOW", "MEDIUM"}:
                risk_level = "HIGH"

            return {
                "safety_status": safety_status,
                "risk_level": risk_level,
                "mutation_detected": mutation_detected,
                "deletion_detected": deletion_detected,
                "impact_analysis": impact_analysis,
            }
        except Exception as e:
            logger.error("Error evaluating command safety: %s", e)
            return {
                "safety_status": "UNSAFE",
                "risk_level": "HIGH",
                "mutation_detected": True,
                "deletion_detected": False,
                "impact_analysis": f"安全审查机制执行失败，拒绝放行 ({str(e)})",
            }
        finally:
            self.temperature = original_temp

    @staticmethod
    def _format_command_for_review(command: str) -> str:
        """
        Normalize command text before sending to the reviewer model.

        Rendering control characters as visible escapes reduces the chance
        that the model echoes raw controls into JSON string values.
        """
        text = str(command or "")
        text = text.replace("\\", "\\\\")
        text = text.replace("\r", "\\r")
        text = text.replace("\n", "\\n")
        text = text.replace("\t", "\\t")
        return text

    @staticmethod
    def _extract_json_object(raw_text: str) -> str:
        """
        Extract a JSON object candidate from model output.

        Some OpenAI-compatible providers may wrap JSON in markdown fences
        or add extra text before/after the object.
        """
        text = (raw_text or "").strip()
        if not text:
            return "{}"

        if text.startswith("```"):
            lines = text.splitlines()
            if len(lines) >= 3 and lines[-1].strip() == "```":
                text = "\n".join(lines[1:-1]).strip()

        start = text.find("{")
        if start == -1:
            return text

        # Extract the first balanced object to avoid trailing chatter.
        depth = 0
        in_string = False
        escaped = False
        for idx in range(start, len(text)):
            ch = text[idx]
            if in_string:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == "\"":
                    in_string = False
                continue

            if ch == "\"":
                in_string = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return text[start:idx + 1]

        return text[start:]

    @staticmethod
    def _sanitize_json_candidate(candidate: str) -> str:
        """
        Repair common JSON issues from non-conformant providers.

        - remove BOM/NUL
        - escape raw control chars inside JSON strings
        - remove trailing commas before } or ]
        """
        text = (candidate or "").replace("\ufeff", "").replace("\x00", "")
        if not text:
            return "{}"

        out: list[str] = []
        in_string = False
        escaped = False
        for ch in text:
            if in_string:
                if escaped:
                    out.append(ch)
                    escaped = False
                    continue

                if ch == "\\":
                    out.append(ch)
                    escaped = True
                    continue

                if ch == "\"":
                    out.append(ch)
                    in_string = False
                    continue

                code = ord(ch)
                if code < 0x20:
                    if ch == "\n":
                        out.append("\\n")
                    elif ch == "\r":
                        out.append("\\r")
                    elif ch == "\t":
                        out.append("\\t")
                    elif ch == "\b":
                        out.append("\\b")
                    elif ch == "\f":
                        out.append("\\f")
                    else:
                        out.append(f"\\u{code:04x}")
                    continue

                out.append(ch)
                continue

            out.append(ch)
            if ch == "\"":
                in_string = True

        repaired = "".join(out)
        repaired = re.sub(r",\s*([}\]])", r"\1", repaired)
        return repaired.strip()

    @staticmethod
    def _parse_json_object(raw_text: str) -> dict[str, Any]:
        """
        Parse a JSON object with strict-first and relaxed fallback.

        Fallback with strict=False tolerates unescaped control characters
        returned by some models/providers.
        """
        candidate = LLMClient._extract_json_object(raw_text)
        repaired = LLMClient._sanitize_json_candidate(candidate)
        parse_error: Exception | None = None

        for attempt_text in (candidate, repaired):
            for strict in (True, False):
                try:
                    parsed = json.loads(attempt_text, strict=strict)
                    if isinstance(parsed, dict):
                        if attempt_text is repaired:
                            logger.debug("Command safety JSON parsed after repair normalization.")
                        elif not strict:
                            logger.debug(
                                "Command safety JSON parsed with relaxed mode due to invalid control characters."
                            )
                        return parsed
                    raise ValueError("Reviewer response is not a JSON object")
                except (json.JSONDecodeError, ValueError) as e:
                    parse_error = e
                    if strict:
                        logger.debug(
                            "Strict JSON parse failed for command safety response; retrying relaxed mode: %s",
                            e,
                        )
                        continue
                    # Continue with repaired candidate after relaxed parse fails.
                    continue

        if parse_error:
            raise parse_error
        raise ValueError("Failed to parse command safety response")

    @staticmethod
    def parse_json_object(raw_text: str) -> dict[str, Any]:
        """Public wrapper for robust JSON-object parsing."""
        return LLMClient._parse_json_object(raw_text)

    def _parse_response(self, response: Any) -> LLMResponse:
        """Parse the raw OpenAI response into our normalized format."""
        choice = response.choices[0]
        message = choice.message

        # Parse tool calls
        tool_calls = []
        if message.tool_calls:
            for tc in message.tool_calls:
                tool_calls.append(
                    ToolCall(
                        id=tc.id,
                        name=tc.function.name,
                        arguments=tc.function.arguments,
                    )
                )

        # Parse usage
        usage = response.usage
        return LLMResponse(
            content=message.content,
            tool_calls=tool_calls,
            prompt_tokens=usage.prompt_tokens if usage else 0,
            completion_tokens=usage.completion_tokens if usage else 0,
            total_tokens=usage.total_tokens if usage else 0,
        )
