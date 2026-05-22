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
                        input_items.append({
                            "type": "function_call",
                            "id": tc.get("id"),
                            "name": fn.get("name"),
                            "arguments": args
                        })
                elif content:
                    input_items.append({
                        "type": "message",
                        "role": "assistant",
                        "content": content
                    })
            elif role == "tool":
                input_items.append({
                    "type": "function_call_output",
                    "call_id": msg.get("tool_call_id"),
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
        output_list = getattr(response, "output", []) or []
        for item in output_list:
            item_type = getattr(item, "type", None)
            
            if item_type == "message":
                # Extract text segments from message contents
                content_parts = getattr(item, "content", []) or []
                for part in content_parts:
                    part_type = getattr(part, "type", None)
                    if part_type == "output_text":
                        text_val = getattr(part, "text", "")
                        content = (content or "") + text_val
                        
            elif item_type == "function_call":
                # Parse tool calls
                call_id = getattr(item, "id", None)
                name = getattr(item, "name", None)
                arguments = getattr(item, "arguments", "{}")
                
                # Make sure arguments is a string (as expected by ChatDome)
                if not isinstance(arguments, str):
                    import json
                    arguments = json.dumps(arguments, ensure_ascii=False)
                    
                tool_calls.append(ToolCall(
                    id=call_id,
                    name=name,
                    arguments=arguments
                ))
                
        # Parse usage statistics
        usage = getattr(response, "usage", None)
        prompt_tokens = getattr(usage, "input_tokens", 0) if usage else 0
        completion_tokens = getattr(usage, "output_tokens", 0) if usage else 0
        total_tokens = getattr(usage, "total_tokens", 0) if usage else 0
        
        return LLMResponse(
            content=content,
            tool_calls=tool_calls,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens
        )

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
        }
        
        if converted_tools:
            kwargs["tools"] = converted_tools
            kwargs["tool_choice"] = "auto"
            
        # Map temperature and max_tokens (in Responses API, it is max_output_tokens)
        temp_val = self.temperature if temperature is None else temperature
        kwargs["temperature"] = temp_val
        
        max_tok = self.max_tokens if max_tokens is None else max_tokens
        kwargs["max_output_tokens"] = max_tok
        
        # Disable storing the response on OpenAI servers by default
        kwargs["store"] = False

        # 4. Request with Retry loop
        last_error: Exception | None = None
        for attempt in range(1, self.max_retries + 1):
            try:
                # SDK Call to responses.create
                response = await client.responses.create(**kwargs)
                return self._parse_responses_output(response)
                
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
                raise
                
            except openai.APIError as e:
                last_error = e
                logger.error(
                    "Codex API error (attempt %d/%d): %s",
                    attempt, self.max_retries, e,
                )
                if attempt < self.max_retries:
                    await asyncio.sleep(2 ** attempt)
                    
        raise RuntimeError(
            f"Codex Responses API call failed after {self.max_retries} attempts: {last_error}"
        )
