import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from chatdome.llm.client import ToolCall
from chatdome.llm.codex_responses import CodexResponsesClient


class CodexResponsesClientTests(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.token_file = Path(self.tmp_dir.name) / "auth.json"
        
        # Pre-seed a valid token to avoid real OAuth file checking issues in unit tests
        self.token_data = {
            "access_token": "mock_access_token",
            "refresh_token": "mock_refresh_token",
            "expires_at": 9999999999,
            "client_id": "test_client",
        }
        self.token_file.write_text(json.dumps(self.token_data), encoding="utf-8")
        
        self.client = CodexResponsesClient(
            base_url="http://mock-api",
            model="gpt-5.5",
            codex_client_id="test_client",
            codex_token_file=str(self.token_file),
        )

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_convert_messages_to_input(self):
        messages = [
            {"role": "system", "content": "system prompt"},
            {"role": "user", "content": "user request"},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_1",
                        "function": {"name": "run_cmd", "arguments": '{"cmd": "ls"}'},
                    }
                ],
            },
            {"role": "tool", "tool_call_id": "call_1", "content": "file1.txt"},
            {"role": "assistant", "content": "done"},
        ]

        instructions, input_items = self.client._convert_messages_to_input(messages)

        self.assertEqual(instructions, "system prompt")
        self.assertEqual(len(input_items), 4)
        
        self.assertEqual(input_items[0], {"type": "message", "role": "user", "content": "user request"})
        
        self.assertEqual(input_items[1], {
            "type": "function_call",
            "id": "call_1",
            "name": "run_cmd",
            "arguments": '{"cmd": "ls"}',
        })
        
        self.assertEqual(input_items[2], {
            "type": "function_call_output",
            "call_id": "call_1",
            "output": "file1.txt",
        })
        
        self.assertEqual(input_items[3], {"type": "message", "role": "assistant", "content": "done"})

    def test_convert_tools(self):
        tools = [
            {
                "type": "function",
                "function": {
                    "name": "my_tool",
                    "description": "desc",
                    "parameters": {"type": "object"},
                },
            }
        ]
        
        converted = self.client._convert_tools(tools)
        
        self.assertEqual(len(converted), 1)
        self.assertEqual(converted[0], {
            "type": "function",
            "name": "my_tool",
            "description": "desc",
            "parameters": {"type": "object"},
        })

    def test_parse_responses_output(self):
        # Build mock response object using SimpleNamespace
        part_text = SimpleNamespace(type="output_text", text="Hello back")
        msg_item = SimpleNamespace(type="message", content=[part_text])
        call_item = SimpleNamespace(type="function_call", id="call_99", name="some_tool", arguments={"param": 1})
        
        mock_response = SimpleNamespace(
            output=[msg_item, call_item],
            usage=SimpleNamespace(input_tokens=10, output_tokens=20, total_tokens=30),
        )

        res = self.client._parse_responses_output(mock_response)

        self.assertEqual(res.content, "Hello back")
        self.assertEqual(len(res.tool_calls), 1)
        self.assertEqual(res.tool_calls[0].id, "call_99")
        self.assertEqual(res.tool_calls[0].name, "some_tool")
        self.assertEqual(res.tool_calls[0].arguments, '{"param": 1}')
        self.assertEqual(res.prompt_tokens, 10)
        self.assertEqual(res.completion_tokens, 20)
        self.assertEqual(res.total_tokens, 30)

    def test_chat_completion_success(self):
        asyncio.run(self._run_chat_completion_success())

    async def _run_chat_completion_success(self):
        part_text = SimpleNamespace(type="output_text", text="AI response text")
        msg_item = SimpleNamespace(type="message", content=[part_text])
        mock_resp = SimpleNamespace(
            output=[msg_item],
            usage=SimpleNamespace(input_tokens=10, output_tokens=15, total_tokens=25),
        )
        
        mock_client = MagicMock()
        mock_client.responses.create = AsyncMock(return_value=mock_resp)

        with patch("openai.AsyncOpenAI", return_value=mock_client):
            messages = [{"role": "user", "content": "hi"}]
            res = await self.client.chat_completion(messages)

        self.assertEqual(res.content, "AI response text")
        self.assertEqual(res.prompt_tokens, 10)
        self.assertEqual(res.completion_tokens, 15)
        
        # Verify call arguments
        mock_client.responses.create.assert_called_once()
        kwargs = mock_client.responses.create.call_args[1]
        self.assertEqual(kwargs["model"], "gpt-5.5")
        self.assertEqual(kwargs["store"], False)
        self.assertEqual(kwargs["stream"], True)
        self.assertEqual(kwargs["input"], [{"type": "message", "role": "user", "content": "hi"}])
        self.assertNotIn("max_output_tokens", kwargs)
        self.assertNotIn("temperature", kwargs)

    def test_chat_completion_stream_completed_event(self):
        asyncio.run(self._run_chat_completion_stream_completed_event())

    async def _run_chat_completion_stream_completed_event(self):
        part_text = SimpleNamespace(type="output_text", text="streamed response")
        msg_item = SimpleNamespace(type="message", content=[part_text])
        mock_resp = SimpleNamespace(
            output=[msg_item],
            usage=SimpleNamespace(input_tokens=3, output_tokens=4, total_tokens=7),
        )

        async def mock_stream():
            yield SimpleNamespace(type="response.output_text.delta", delta="ignored when completed exists")
            yield SimpleNamespace(type="response.completed", response=mock_resp)

        mock_client = MagicMock()
        mock_client.responses.create = AsyncMock(return_value=mock_stream())

        with patch("openai.AsyncOpenAI", return_value=mock_client):
            messages = [{"role": "user", "content": "hi"}]
            res = await self.client.chat_completion(messages)

        self.assertEqual(res.content, "streamed response")
        self.assertEqual(res.prompt_tokens, 3)
        self.assertEqual(res.completion_tokens, 4)
        self.assertEqual(res.total_tokens, 7)

    def test_evaluate_command_safety(self):
        asyncio.run(self._run_evaluate_command_safety())

    async def _run_evaluate_command_safety(self):
        # We mock chat_completion to return a safety review JSON
        mock_response = MagicMock()
        mock_response.content = """
        {
            "safety_status": "SAFE",
            "risk_level": "LOW",
            "mutation_detected": false,
            "deletion_detected": false,
            "impact_analysis": "Safe review"
        }
        """
        mock_response.prompt_tokens = 5
        mock_response.completion_tokens = 5
        mock_response.total_tokens = 10

        with patch.object(self.client, "chat_completion", new_callable=AsyncMock) as mock_chat:
            mock_chat.return_value = mock_response
            
            result = await self.client.evaluate_command_safety("echo 1", "System instructions")
            
            self.assertEqual(result["safety_status"], "SAFE")
            self.assertEqual(result["risk_level"], "LOW")
            self.assertFalse(result["mutation_detected"])
            self.assertFalse(result["deletion_detected"])
            self.assertEqual(result["impact_analysis"], "Safe review")
            
            # Verify chat_completion was called with JSON prompt instruction
            mock_chat.assert_called_once()
            args, kwargs = mock_chat.call_args
            self.assertEqual(kwargs["response_format"], {"type": "json_object"})
            self.assertEqual(kwargs["temperature"], 0.0)


if __name__ == "__main__":
    unittest.main()
