"""
OpenAI Responses API client for Codex backend.

Adapts standard chat completion requests to the OpenAI Responses API format,
injects OAuth authentication, and maps responses back to ChatDome models.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import openai
from chatdome.errors import (
    LLMAuthenticationError,
    LLMProviderError,
    LLMRateLimitError,
    LLMTimeoutError,
)
from chatdome.llm.client import LLMClient, LLMResponse, ToolCall
from chatdome.llm.codex_auth import CodexOAuth

logger = logging.getLogger(__name__)


class CodexResponsesClient(LLMClient):
    """
    LLM client that communicates with OpenAI Codex backend via the Responses API.
    
    Manages OAuth authentication internally using CodexOAuth.
    """

    def __init__(
        self,
        base_url: str = "https://chatgpt.com/backend-api/codex",
        model: str = "gpt-5.5",
        temperature: float = 0.1,
        max_tokens: int = 2000,
        max_retries: int = 3,
        codex_client_id: str | None = None,
        codex_token_file: str | None = None,
    ) -> None:
        # Base constructor parameters. api_key is empty because we manage it via OAuth.
        super().__init__(
            api_key="",
            base_url=base_url,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            max_retries=max_retries,
        )
        self.oauth = CodexOAuth(client_id=codex_client_id, token_file=codex_token_file)
        self.base_url = base_url

    def _convert_messages_to_input(self, messages: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
        """Convert OpenAI messages format to Responses API instructions + input items."""
        instructions = ""
        input_items = []
        
        for msg in messages:
            role = msg.get("role")
            content = msg.get("content")
            
            if role == "system":
                # System prompt is mapped to instructions
                instructions = content or ""
            elif role == "user":
                input_items.append({
                    "type": "message",
                    "role": "user",
                    "content": content or ""
                })
            elif role == "assistant":
                if msg.get("tool_calls"):
                    # Process tool calls output by the assistant
                    for tc in msg["tool_calls"]:
                        fn = tc.get("function", {})
                        args = fn.get("arguments", "{}")
                        call_id = tc.get("call_id") or tc.get("id")
                        if not call_id:
                            logger.warning("Skipping Codex function_call without call_id/id in history.")
                            continue
                        input_item = {
                            "type": "function_call",
                            "call_id": call_id,
                            "name": fn.get("name"),
                            "arguments": args
                        }
                        response_item_id = tc.get("id")
                        if isinstance(response_item_id, str) and response_item_id.startswith("fc"):
                            input_item["id"] = response_item_id
                        input_items.append(input_item)
                elif content:
                    input_items.append({
                        "type": "message",
                        "role": "assistant",
                        "content": content
                    })
            elif role == "tool":
                call_id = msg.get("tool_call_id")
                if not call_id:
                    logger.warning("Skipping Codex tool output without tool_call_id in history.")
                    continue
                input_items.append({
                    "type": "function_call_output",
                    "call_id": call_id,
                    "output": content or ""
                })
                
        return instructions, input_items

    def _convert_tools(self, tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Convert Chat Completions tools to Responses API format."""
        converted = []
        for tool in tools:
            if tool.get("type") == "function":
                fn = tool["function"]
                converted.append({
                    "type": "function",
                    "name": fn["name"],
                    "description": fn.get("description", ""),
                    "parameters": fn.get("parameters", {}),
                })
        return converted

    def _parse_responses_output(self, response: Any) -> LLMResponse:
        """Parse Responses API output item and usage metrics into LLMResponse."""
        content = None
        tool_calls: list[ToolCall] = []
        
        # Iterate over output items in the response
        output_list = self._event_value(response, "output", []) or []
        for item in output_list:
            item_type = self._event_value(item, "type", None)
            
            if item_type == "message":
                # Extract text segments from message contents
                content_parts = self._event_value(item, "content", []) or []
                for part in content_parts:
                    part_type = self._event_value(part, "type", None)
                    if part_type == "output_text":
                        text_val = self._event_value(part, "text", "")
                        content = (content or "") + text_val
                        
            elif item_type == "function_call":
                # Parse tool calls
                response_item_id = self._event_value(item, "id", None)
                call_id = self._event_value(item, "call_id", None) or response_item_id
                name = self._event_value(item, "name", None)
                arguments = self._event_value(item, "arguments", "{}")
                if not call_id or not name:
                    logger.warning(
                        "Skipping malformed Codex function_call item: id=%s call_id=%s name=%s",
                        response_item_id,
                        call_id,
                        name,
                    )
                    continue
                
                # Make sure arguments is a string (as expected by ChatDome)
                if not isinstance(arguments, str):
                    import json
                    arguments = json.dumps(arguments, ensure_ascii=False)
                    
                tool_calls.append(ToolCall(
                    id=call_id,
                    name=name,
                    arguments=arguments,
                    response_id=response_item_id,
                ))
                
        # Parse usage statistics
        usage = self._event_value(response, "usage", None)
        prompt_tokens = self._event_value(usage, "input_tokens", 0) if usage else 0
        completion_tokens = self._event_value(usage, "output_tokens", 0) if usage else 0
        total_tokens = self._event_value(usage, "total_tokens", 0) if usage else 0
        
        return LLMResponse(
            content=content,
            tool_calls=tool_calls,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens
        )

    @staticmethod
    def _event_value(event: Any, key: str, default: Any = None) -> Any:
        """Read a field from either SDK event objects or dict-like test doubles."""
        if isinstance(event, dict):
            return event.get(key, default)
        return getattr(event, key, default)

    @staticmethod
    def _has_response_payload(response: LLMResponse) -> bool:
        """Return True when the parsed response has model-visible output."""
        return bool(response.content or response.tool_calls)

    @staticmethod
    def _item_type(item: Any) -> str:
        """Return an output item type without logging the item's content."""
        if isinstance(item, dict):
            return str(item.get("type") or "<missing>")
        return str(getattr(item, "type", None) or "<missing>")

    def _log_stream_summary(
        self,
        *,
        event_counts: dict[str, int],
        delta_chars: int,
        done_text_chars: int,
        done_output_items: list[Any],
        completed_output_len: int | None,
        final_source: str,
        empty: bool,
    ) -> None:
        """
        Log Codex stream shape without sensitive payload content.

        DEBUG keeps normal logs quiet. If parsing produced no visible output,
        WARNING exposes enough metadata to diagnose backend event-shape changes.
        """
        item_type_counts: dict[str, int] = {}
        for item in done_output_items:
            item_type = self._item_type(item)
            item_type_counts[item_type] = item_type_counts.get(item_type, 0) + 1

        log_fn = logger.warning if empty else logger.debug
        log_fn(
            "Codex stream summary: event_counts=%s delta_chars=%d done_text_chars=%d "
            "done_output_items=%d done_output_item_types=%s completed_output_len=%s final_source=%s empty=%s",
            event_counts,
            delta_chars,
            done_text_chars,
            len(done_output_items),
            item_type_counts,
            completed_output_len,
            final_source,
            empty,
        )

    async def _parse_streaming_response(self, stream: Any) -> LLMResponse:
        """
        Consume a Responses streaming result and map it to LLMResponse.

        Codex backend requires streaming, but the final `response.completed`
        event contains the same full response shape parsed by
        `_parse_responses_output`, so that path remains the source of truth.
        """
        if not hasattr(stream, "__aiter__"):
            return self._parse_responses_output(stream)

        completed_response: Any | None = None
        text_parts: list[str] = []
        done_text_parts: list[str] = []
        done_output_items: list[Any] = []
        event_counts: dict[str, int] = {}
        delta_chars = 0
        done_text_chars = 0

        async for event in stream:
            event_type = self._event_value(event, "type", "")
            event_counts[event_type or "<missing>"] = event_counts.get(event_type or "<missing>", 0) + 1
            if event_type == "response.completed":
                completed_response = self._event_value(event, "response")
            elif event_type == "response.output_text.delta":
                delta = self._event_value(event, "delta", "")
                if delta:
                    delta_text = str(delta)
                    delta_chars += len(delta_text)
                    text_parts.append(delta_text)
            elif event_type == "response.output_text.done":
                text = self._event_value(event, "text", "")
                if text:
                    done_text = str(text)
                    done_text_chars += len(done_text)
                    done_text_parts.append(done_text)
            elif event_type == "response.output_item.done":
                item = self._event_value(event, "item") or self._event_value(event, "output_item")
                if item is not None:
                    done_output_items.append(item)
            elif event_type in {"response.failed", "error"}:
                error = self._event_value(event, "error", None)
                raise LLMProviderError(
                    f"Codex streaming response failed: {error or event}",
                    user_message="Codex 响应流返回异常，请稍后重试。",
                    retryable=True,
                )

        streamed_text = "".join(text_parts) if text_parts else "".join(done_text_parts)
        streamed_response = (
            self._parse_responses_output({"output": done_output_items})
            if done_output_items
            else LLMResponse()
        )
        if streamed_text and not streamed_response.content:
            streamed_response.content = streamed_text

        completed_output = (
            self._event_value(completed_response, "output", None)
            if completed_response is not None
            else None
        )
        completed_output_len = len(completed_output) if isinstance(completed_output, list) else None

        if completed_response is not None:
            completed_parsed = self._parse_responses_output(completed_response)
            if self._has_response_payload(completed_parsed):
                self._log_stream_summary(
                    event_counts=event_counts,
                    delta_chars=delta_chars,
                    done_text_chars=done_text_chars,
                    done_output_items=done_output_items,
                    completed_output_len=completed_output_len,
                    final_source="completed",
                    empty=False,
                )
                return completed_parsed

            # Codex can complete with an empty output array while the stream
            # already delivered text/output_item events. In that case, keep the
            # streamed payload and only borrow token usage from the final event.
            if self._has_response_payload(streamed_response):
                streamed_response.prompt_tokens = completed_parsed.prompt_tokens
                streamed_response.completion_tokens = completed_parsed.completion_tokens
                streamed_response.total_tokens = completed_parsed.total_tokens
                self._log_stream_summary(
                    event_counts=event_counts,
                    delta_chars=delta_chars,
                    done_text_chars=done_text_chars,
                    done_output_items=done_output_items,
                    completed_output_len=completed_output_len,
                    final_source="streamed_fallback",
                    empty=False,
                )
                return streamed_response

            self._log_stream_summary(
                event_counts=event_counts,
                delta_chars=delta_chars,
                done_text_chars=done_text_chars,
                done_output_items=done_output_items,
                completed_output_len=completed_output_len,
                final_source="completed_empty",
                empty=True,
            )
            return completed_parsed

        # Fallback for minimal streams that only carry text deltas.
        self._log_stream_summary(
            event_counts=event_counts,
            delta_chars=delta_chars,
            done_text_chars=done_text_chars,
            done_output_items=done_output_items,
            completed_output_len=completed_output_len,
            final_source="streamed_without_completed",
            empty=not self._has_response_payload(streamed_response),
        )
        return streamed_response

    async def chat_completion(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        response_format: dict[str, str] | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        """
        Send a chat completion request mapped onto the Responses API.
        """
        # 1. Acquire valid OAuth Token
        access_token = await self.oauth.ensure_valid_token()
        
        # 2. Re-bind key on self._client or local OpenAI client
        client = openai.AsyncOpenAI(
            api_key=access_token,
            base_url=self.base_url,
        )
        
        # 3. Format input payloads
        instructions, input_items = self._convert_messages_to_input(messages)
        converted_tools = self._convert_tools(tools) if tools else []
        
        # Responses API doesn't support response_format parameter in some versions/backends.
        # Add constraint directly in instructions if json_object is requested.
        if response_format and response_format.get("type") == "json_object":
            instructions = (instructions or "") + (
                "\n\nIMPORTANT: Your response must be a single, valid JSON object matching the requested output format. "
                "Do not wrap it in markdown code block fences (like ```json). "
                "Output only the JSON object."
            )
            
        kwargs: dict[str, Any] = {
            "model": self.model,
            "instructions": instructions,
            "input": input_items,
            "stream": True,
        }
        
        if converted_tools:
            kwargs["tools"] = converted_tools
            kwargs["tool_choice"] = "auto"
            
        # Codex backend supports a narrower Responses payload than the public
        # OpenAI Responses API. Do not send temperature/max_output_tokens here:
        # the backend rejects unsupported request parameters with HTTP 400.
        
        # Disable storing the response on OpenAI servers by default
        kwargs["store"] = False

        # 4. Request with Retry loop
        last_error: Exception | None = None
        for attempt in range(1, self.max_retries + 1):
            try:
                # Codex backend requires streaming Responses requests.
                response_stream = await client.responses.create(**kwargs)
                return await self._parse_streaming_response(response_stream)
                
            except openai.RateLimitError as e:
                last_error = e
                wait_time = 2 ** attempt
                logger.warning(
                    "Codex API Rate limited (attempt %d/%d), retrying in %ds: %s",
                    attempt, self.max_retries, wait_time, e,
                )
                await asyncio.sleep(wait_time)
                
            except openai.APITimeoutError as e:
                last_error = e
                wait_time = 2 ** attempt
                logger.warning(
                    "Codex API timeout (attempt %d/%d), retrying in %ds: %s",
                    attempt, self.max_retries, wait_time, e,
                )
                await asyncio.sleep(wait_time)
                
            except openai.AuthenticationError as e:
                logger.error("Codex API authentication failed: %s", e)
                raise LLMAuthenticationError(
                    str(e),
                    user_message="Codex 认证失败，请重新运行 /codex_login。",
                ) from e
                
            except openai.APIError as e:
                last_error = e
                logger.error(
                    "Codex API error (attempt %d/%d): %s",
                    attempt, self.max_retries, e,
                )
                if attempt < self.max_retries:
                    await asyncio.sleep(2 ** attempt)
                    
        message = f"Codex Responses API call failed after {self.max_retries} attempts: {last_error}"
        if isinstance(last_error, openai.RateLimitError):
            raise LLMRateLimitError(message) from last_error
        if isinstance(last_error, openai.APITimeoutError):
            raise LLMTimeoutError(message) from last_error
        raise LLMProviderError(message) from last_error
