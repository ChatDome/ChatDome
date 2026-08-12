import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from chatdome.agent.core import Agent
from chatdome.agent.prompts import build_system_prompt, build_tools
from chatdome.agent.session import AgentSession
from chatdome.agent.tools import PendingApprovalError, ToolDispatcher
from chatdome.llm.client import LLMResponse, ToolCall


class FakeLLM:
    model = "fake-model"

    def __init__(self, response: LLMResponse):
        self.response = response
        self.calls = []

    async def chat_completion(self, messages, tools=None, response_format=None):
        self.calls.append(
            {
                "messages": messages,
                "tools": tools,
                "response_format": response_format,
            }
        )
        return self.response


class SequenceLLM:
    model = "fake-model"

    def __init__(self, *responses: LLMResponse):
        self.responses = list(responses)
        self.calls = []

    async def chat_completion(self, messages, tools=None, response_format=None):
        self.calls.append(
            {
                "messages": messages,
                "tools": tools,
                "response_format": response_format,
            }
        )
        if self.responses:
            return self.responses.pop(0)
        return LLMResponse(content="done")


class DiagnosticSequenceLLM:
    model = "diagnostic-model"
    max_tokens = 2000

    def __init__(self, *responses: LLMResponse):
        self.responses = list(responses)

    async def chat_completion(
        self,
        messages,
        tools=None,
        response_format=None,
        temperature=None,
        max_tokens=None,
    ):
        del messages, tools, response_format, temperature, max_tokens
        return self.responses.pop(0)


class SlowCommandDetailLLM:
    model = "fake-model"

    def __init__(self):
        self.calls = 0
        self.cancelled = False

    async def chat_completion(self, messages, tools=None, response_format=None):
        del messages, tools, response_format
        self.calls += 1
        try:
            await asyncio.sleep(10)
        except asyncio.CancelledError:
            self.cancelled = True
            raise

class CancellationResistantDetailLLM:
    model = "fake-model"

    def __init__(self):
        self.started = asyncio.Event()
        self.cancelled = asyncio.Event()

    async def chat_completion(self, messages, tools=None, response_format=None):
        del messages, tools, response_format
        self.started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled.set()
            await asyncio.sleep(0.2)
            raise



def _command_detail_response(
    commands,
    *,
    safety_status="SAFE",
    risk_level="LOW",
    mutation_detected=False,
    deletion_detected=False,
    compact=False,
):
    groups = []
    for index, command in enumerate(commands, start=1):
        base_cmd = command.split()[0]
        group = {
            "index": index,
            "base_cmd": base_cmd,
            "summary": f"分析 {command}",
            "targets": [],
            "warnings": [],
            "irreversible": False,
            "confidence": "high",
        }
        if not compact:
            group["tokens"] = [
                {
                    "token": base_cmd,
                    "role": "command",
                    "label": "命令",
                    "meaning": "执行当前命令",
                }
            ]
        groups.append(group)
    return LLMResponse(
        content=json.dumps(
            {
                "safety_status": safety_status,
                "risk_level": risk_level,
                "mutation_detected": mutation_detected,
                "deletion_detected": deletion_detected,
                "impact_analysis": "分析当前批次命令。",
                "command_breakdown": {
                    "summary": "分析当前批次",
                    "commands": groups,
                },
            },
            ensure_ascii=False,
        )
    )


class RepeatingToolLLM:
    model = "fake-model"

    def __init__(self, tools_per_round: int):
        self.tools_per_round = tools_per_round
        self.calls = 0

    async def chat_completion(self, messages, tools=None, response_format=None):
        self.calls += 1
        tool_calls = [
            ToolCall(
                id=f"call-{self.calls}-{index}",
                name="fake_tool",
                arguments=json.dumps({"round": self.calls, "index": index}),
            )
            for index in range(self.tools_per_round)
        ]
        return LLMResponse(content=None, tool_calls=tool_calls)


class RepeatingSameToolLLM:
    model = "fake-model"

    def __init__(self):
        self.calls = 0

    async def chat_completion(self, messages, tools=None, response_format=None):
        self.calls += 1
        return LLMResponse(
            content=None,
            tool_calls=[
                ToolCall(
                    id=f"same-call-{self.calls}",
                    name="run_security_check",
                    arguments='{"check_id": "recent_cron_jobs", "args": {"limit": 5}}',
                )
            ],
        )


class FakeSessionManager:
    def __init__(self, session: AgentSession):
        self.session = session
        self.saved = 0
        self.lock = None

    def get_or_create(self, chat_id: int) -> AgentSession:
        self.session.chat_id = chat_id
        return self.session

    def save_session(self, session: AgentSession) -> None:
        self.saved += 1
        self.session = session

    def get_turn_lock(self, _chat_id: int):
        if self.lock is None:
            self.lock = asyncio.Lock()
        return self.lock


class FakeSandbox:
    def __init__(self):
        self.commands = []

    async def execute_shell_command(self, command, reason, chat_id=0, tool_call_id=""):
        self.commands.append(
            {
                "command": command,
                "reason": reason,
                "chat_id": chat_id,
                "tool_call_id": tool_call_id,
            }
        )
        return SimpleNamespace(
            stdout="ok",
            stderr="",
            return_code=0,
            timed_out=False,
            truncated=False,
            command=command,
        )


class FakeToolDispatcher:
    def __init__(self):
        self.sandbox = FakeSandbox()

    def _format_command_result(self, result) -> str:
        return result.stdout


class CountingToolDispatcher:
    def __init__(self):
        self.calls = []

    async def dispatch(self, tool_name, arguments_json, tool_call_id="", chat_id=0):
        self.calls.append(
            {
                "tool_name": tool_name,
                "arguments_json": arguments_json,
                "tool_call_id": tool_call_id,
                "chat_id": chat_id,
            }
        )
        return "ok"


class PendingAfterSecondToolDispatcher:
    def __init__(self):
        self.calls = []

    async def dispatch(self, tool_name, arguments_json, tool_call_id="", chat_id=0):
        self.calls.append(
            {
                "tool_name": tool_name,
                "arguments_json": arguments_json,
                "tool_call_id": tool_call_id,
                "chat_id": chat_id,
            }
        )
        if tool_call_id == "call-2":
            raise PendingApprovalError(
                command="systemctl restart nginx",
                safety_status="NEEDS_APPROVAL",
                impact_analysis="May restart a service.",
                tool_call_id=tool_call_id,
                reason="Need to restart nginx after config check.",
                risk_level="HIGH",
            )
        return f"result for {tool_call_id}"


class ApprovalRequiredShellDispatcher:
    def __init__(self):
        self.calls = []
        self.sandbox = FakeSandbox()

    def _format_command_result(self, result) -> str:
        return result.stdout

    async def dispatch(self, tool_name, arguments_json, tool_call_id="", chat_id=0):
        self.calls.append(
            {
                "tool_name": tool_name,
                "arguments_json": arguments_json,
                "tool_call_id": tool_call_id,
                "chat_id": chat_id,
            }
        )
        args = json.loads(arguments_json or "{}")
        command = args.get("command", "")
        reason = args.get("reason", "")
        raise PendingApprovalError(
            command=command,
            safety_status="NEEDS_APPROVAL",
            impact_analysis="May restart a service.",
            tool_call_id=tool_call_id,
            reason=reason,
            risk_level="HIGH",
        )


class FakeApprovalDetailDispatcher:
    def __init__(self, session=None, clear_pending: bool = False):
        self.session = session
        self.clear_pending = clear_pending
        self.calls = []

    async def get_command_approval_details(
        self,
        command,
        reason,
        chat_id=0,
        tool_call_id="",
        include_llm=True,
    ):
        self.calls.append(
            {
                "command": command,
                "reason": reason,
                "chat_id": chat_id,
                "tool_call_id": tool_call_id,
                "include_llm": include_llm,
            }
        )
        if self.clear_pending and self.session is not None:
            self.session.clear_pending_state()
        return {
            "safety_status": "SAFE",
            "risk_level": "LOW",
            "mutation_detected": False,
            "deletion_detected": False,
            "impact_analysis": "AI detail",
            "reviewer_mode": "llm" if include_llm else "static_only",
        }


def _agent_with_llm(llm: FakeLLM) -> Agent:
    agent = object.__new__(Agent)
    agent.llm = llm
    agent.config = SimpleNamespace(model="fake-model")
    agent._persist_session = lambda session: None
    return agent


def _resume_agent(session: AgentSession) -> Agent:
    agent = object.__new__(Agent)
    agent.llm = FakeLLM(LLMResponse(content="done"))
    agent.config = SimpleNamespace(model="fake-model")
    agent.session_manager = FakeSessionManager(session)
    agent.tool_dispatcher = FakeToolDispatcher()

    async def fake_run_loop(chat_id, run_session):
        return "done"

    agent._run_loop = fake_run_loop
    return agent


def _details_agent(session: AgentSession, dispatcher) -> Agent:
    agent = object.__new__(Agent)
    agent.llm = FakeLLM(LLMResponse(content="done"))
    agent.config = SimpleNamespace(model="fake-model")
    agent.session_manager = FakeSessionManager(session)
    agent.tool_dispatcher = dispatcher
    agent._persist_session = lambda saved_session: agent.session_manager.save_session(saved_session)
    return agent


def _pending_agent(session: AgentSession, llm) -> Agent:
    agent = object.__new__(Agent)
    agent.llm = llm
    agent.llm_manager = None
    agent.config = SimpleNamespace(
        model="fake-model",
        max_history_tokens=16000,
        max_rounds_per_turn=10,
    )
    agent.tools = []
    agent.session_manager = FakeSessionManager(session)
    agent.tool_dispatcher = FakeToolDispatcher()
    return agent


def _loop_agent(llm, dispatcher, max_rounds_per_turn: int = 10) -> Agent:
    agent = object.__new__(Agent)
    agent.llm = llm
    agent.config = SimpleNamespace(model="fake-model", max_rounds_per_turn=max_rounds_per_turn)
    agent.tools = []
    agent.tool_dispatcher = dispatcher
    agent._persist_session = lambda session: None
    return agent


def _pending_session() -> AgentSession:
    session = AgentSession(chat_id=123)
    session.pending_approval = True
    session.pending_approval_id = "AP-20260423-000001"
    session.pending_run_id = "RUN-123-000001"
    session.pending_tool_call_id = "call-1"
    session.pending_command = "fail2ban-client status sshd"
    session.pending_command_hash = Agent._command_hash(session.pending_command)
    session.pending_reason = "查询 sshd jail 中当前被封禁的 IP 数量及列表"
    session.pending_risk_level = "LOW"
    session.messages = [
        {"role": "system", "content": "system prompt"},
        {"role": "user", "content": "帮我看看 fail2ban 封禁状态"},
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": "call-1",
                    "type": "function",
                    "function": {
                        "name": "run_shell_command",
                        "arguments": '{"command": "fail2ban-client status sshd"}',
                    },
                }
            ],
        },
    ]
    return session


class PendingApprovalFollowupTests(unittest.TestCase):
    def test_execute_without_approval_runs_risky_command(self):
        sandbox = FakeSandbox()
        dispatcher = ToolDispatcher(
            sandbox,
            command_approval_mode="execute_without_approval",
        )

        result = asyncio.run(
            dispatcher.dispatch(
                "run_shell_command",
                '{"command":"rm /tmp/example","reason":"cleanup"}',
                "call-direct",
                7,
            )
        )

        self.assertEqual(sandbox.commands[0]["command"], "rm /tmp/example")
        self.assertIn("ok", result)

    def test_risky_mode_runs_only_fully_recognized_read_commands(self):
        sandbox = FakeSandbox()
        dispatcher = ToolDispatcher(
            sandbox,
            command_approval_mode="require_approval_for_risky_commands",
        )

        asyncio.run(
            dispatcher.dispatch(
                "run_shell_command",
                '{"command":"df -h; ss -tlnH","reason":"inspect"}',
                "call-safe",
                7,
            )
        )

        self.assertEqual(sandbox.commands[0]["command"], "df -h; ss -tlnH")

    def test_risky_mode_requires_approval_for_unknown_command(self):
        sandbox = FakeSandbox()
        dispatcher = ToolDispatcher(
            sandbox,
            command_approval_mode="require_approval_for_risky_commands",
        )

        with self.assertRaises(PendingApprovalError):
            asyncio.run(
                dispatcher.dispatch(
                    "run_shell_command",
                    '{"command":"custom-inspector --all","reason":"inspect"}',
                    "call-unknown",
                    7,
                )
            )

        self.assertEqual(sandbox.commands, [])

    def test_all_commands_mode_requires_approval_without_risk_analysis(self):
        sandbox = FakeSandbox()
        dispatcher = ToolDispatcher(
            sandbox,
            command_approval_mode="require_approval_for_all_commands",
        )

        with patch.object(
            dispatcher,
            "_analyze_command_static_gate",
            side_effect=AssertionError("risk analysis must not run"),
        ):
            with self.assertRaises(PendingApprovalError):
                asyncio.run(
                    dispatcher.dispatch(
                        "run_shell_command",
                        '{"command":"df -h","reason":"inspect"}',
                        "call-all",
                        7,
                    )
                )

        self.assertEqual(sandbox.commands, [])

    def test_initial_impact_summary_is_neutral_before_details(self):
        summary = ToolDispatcher._build_initial_impact_summary(
            {
                "static_is_safe": False,
                "mutation_detected": True,
                "deletion_detected": True,
                "static_critical": True,
            }
        )

        self.assertIn("查看详情", summary)
        self.assertNotIn("删除", summary)
        self.assertNotIn("高危", summary)

    def test_llm_details_respect_static_guardrail_risk_floor(self):
        dispatcher = ToolDispatcher(FakeSandbox())
        llm = FakeLLM(
            LLMResponse(
                content=json.dumps(
                    {
                        "safety_status": "SAFE",
                        "risk_level": "LOW",
                        "mutation_detected": False,
                        "deletion_detected": False,
                        "impact_analysis": "LLM 认为该命令风险较低。",
                        "command_breakdown": {
                            "base_cmd": "rm",
                            "summary": "删除指定文件",
                            "tokens": [
                                {
                                    "token": "rm",
                                    "role": "command",
                                    "label": "命令",
                                    "meaning": "删除文件或目录",
                                },
                                {
                                    "token": "/",
                                    "role": "target_file",
                                    "label": "目标文件",
                                    "meaning": "命令作用的文件路径",
                                },
                            ],
                            "targets": [
                                {
                                    "value": "/",
                                    "type": "file",
                                    "operation": "delete",
                                }
                            ],
                            "warnings": [],
                            "irreversible": False,
                            "confidence": "high",
                        },
                    },
                    ensure_ascii=False,
                )
            )
        )

        analysis = asyncio.run(
            dispatcher.analyze_command_for_approval(
                "rm -rf /",
                "用户上下文不应进入详情解析",
                chat_id=0,
                include_llm=True,
                llm=llm,
            )
        )

        self.assertEqual(analysis["reviewer_mode"], "llm")
        self.assertEqual(analysis["detail_status"], "complete")
        self.assertEqual(analysis["safety_status"], "CRITICAL")
        self.assertEqual(analysis["risk_level"], "CRITICAL")
        self.assertTrue(analysis["mutation_detected"])
        self.assertTrue(analysis["deletion_detected"])
        self.assertNotIn("static_signals", analysis)
        self.assertEqual(analysis["command_breakdown"]["tokens"][1]["label"], "目标文件")
        self.assertEqual(llm.calls[0]["response_format"], {"type": "json_object"})
        encoded_messages = json.dumps(llm.calls[0]["messages"], ensure_ascii=False)
        self.assertIn("rm -rf /", encoded_messages)
        self.assertNotIn("用户上下文不应进入详情解析", encoded_messages)

    def test_llm_details_group_tokens_by_locally_split_subcommand(self):
        dispatcher = ToolDispatcher(FakeSandbox())
        llm = FakeLLM(
            LLMResponse(
                content=json.dumps(
                    {
                        "safety_status": "UNSAFE",
                        "risk_level": "HIGH",
                        "mutation_detected": True,
                        "deletion_detected": False,
                        "impact_analysis": "切换目录后重启 ChatDome 服务。",
                        "command_breakdown": {
                            "summary": "切换目录并重启服务",
                            "commands": [
                                {
                                    "index": 1,
                                    "command": "LLM 回显不会被信任",
                                    "separator": "||",
                                    "base_cmd": "cd",
                                    "summary": "切换工作目录",
                                    "tokens": [
                                        {"token": "cd", "role": "command", "label": "命令", "meaning": "切换目录"},
                                        {"token": "/srv", "role": "target_directory", "label": "目标目录", "meaning": "工作目录"},
                                        {"token": "systemctl", "role": "command", "label": "命令", "meaning": "跨组内容"},
                                    ],
                                    "targets": [],
                                    "warnings": [],
                                    "irreversible": False,
                                    "confidence": "high",
                                },
                                {
                                    "index": 2,
                                    "command": "错误的第二段回显",
                                    "separator": ";",
                                    "base_cmd": "systemctl",
                                    "summary": "重启服务",
                                    "tokens": [
                                        {"token": "systemctl", "role": "command", "label": "命令", "meaning": "控制服务"},
                                        {"token": "restart", "role": "subcommand", "label": "子命令", "meaning": "重启服务"},
                                        {"token": "chatdome", "role": "target_service", "label": "目标服务", "meaning": "ChatDome 服务"},
                                        {"token": "/srv", "role": "target_directory", "label": "目标目录", "meaning": "跨组内容"},
                                    ],
                                    "targets": [],
                                    "warnings": ["服务会短暂中断"],
                                    "irreversible": False,
                                    "confidence": "high",
                                },
                            ],
                        },
                    },
                    ensure_ascii=False,
                )
            )
        )

        analysis = asyncio.run(
            dispatcher.analyze_command_for_approval(
                "cd /srv; systemctl restart chatdome",
                "重启服务",
                include_llm=True,
                llm=llm,
            )
        )

        commands = analysis["command_breakdown"]["commands"]
        self.assertEqual([item["command"] for item in commands], ["cd /srv", "systemctl restart chatdome"])
        self.assertEqual([item["separator"] for item in commands], [";", ""])
        self.assertEqual([item["token"] for item in commands[0]["tokens"]], ["cd", "/srv"])
        self.assertEqual(
            [item["token"] for item in commands[1]["tokens"]],
            ["systemctl", "restart", "chatdome"],
        )
        self.assertEqual(len(llm.calls), 1)
        user_content = llm.calls[0]["messages"][1]["content"]
        command_payload = json.loads(user_content.split("\n", 1)[1])
        self.assertEqual([item["command"] for item in command_payload["commands"]], ["cd /srv", "systemctl restart chatdome"])
        self.assertEqual(command_payload["commands"][0]["separator"], ";")

    def test_command_details_are_batched_and_merged_in_original_order(self):
        dispatcher = ToolDispatcher(FakeSandbox())
        llm = SequenceLLM(
            _command_detail_response(["echo a", "echo b"]),
            _command_detail_response(["echo c", "echo d"]),
            _command_detail_response(["echo e"]),
        )

        with (
            patch("chatdome.agent.tools._COMMAND_DETAIL_BATCH_SIZE", 2),
            patch("chatdome.agent.tools._COMMAND_DETAIL_MAX_CONCURRENCY", 1),
        ):
            analysis = asyncio.run(
                dispatcher.analyze_command_for_approval(
                    "echo a && echo b && echo c || echo d; echo e",
                    "分析批处理",
                    include_llm=True,
                    llm=llm,
                )
            )

        commands = analysis["command_breakdown"]["commands"]
        self.assertEqual(len(llm.calls), 3)
        self.assertEqual(analysis["detail_status"], "complete")
        self.assertEqual(analysis["analyzed_command_count"], 5)
        self.assertEqual(analysis["command_count"], 5)
        self.assertEqual(
            [item["command"] for item in commands],
            ["echo a", "echo b", "echo c", "echo d", "echo e"],
        )
        self.assertEqual(
            [item["separator"] for item in commands],
            ["&&", "&&", "||", ";", ""],
        )
        self.assertEqual([item["index"] for item in commands], [1, 2, 3, 4, 5])
        batch_payloads = [
            json.loads(call["messages"][1]["content"].split("\n", 1)[1])
            for call in llm.calls
        ]
        self.assertEqual(
            [payload["command"] for payload in batch_payloads],
            [
                "echo a && echo b",
                "echo c || echo d",
                "echo e",
            ],
        )
        self.assertEqual(
            batch_payloads[1]["commands"][0]["operator_before"],
            "&&",
        )
        self.assertEqual(
            batch_payloads[2]["commands"][0]["operator_before"],
            ";",
        )
        self.assertNotIn("batch_start_index", batch_payloads[0])

    def test_invalid_detail_json_retries_once_with_compact_schema(self):
        dispatcher = ToolDispatcher(FakeSandbox())
        llm = SequenceLLM(
            LLMResponse(content='{"safety_status":"SAFE"'),
            _command_detail_response(["echo ok"], compact=True),
        )

        analysis = asyncio.run(
            dispatcher.analyze_command_for_approval(
                "echo ok",
                "测试紧凑重试",
                include_llm=True,
                llm=llm,
            )
        )

        self.assertEqual(len(llm.calls), 2)
        self.assertEqual(analysis["detail_status"], "partial")
        self.assertEqual(analysis["reviewer_mode"], "llm_partial")
        self.assertEqual(analysis["detail_errors"], ["compact_retry"])
        self.assertEqual(analysis["analyzed_command_count"], 1)
        self.assertEqual(
            analysis["command_breakdown"]["commands"][0]["tokens"],
            [],
        )
        self.assertIn(
            "Linux shell 命令风险解析器",
            llm.calls[1]["messages"][0]["content"],
        )

    def test_two_invalid_detail_responses_are_marked_failed(self):
        dispatcher = ToolDispatcher(FakeSandbox())
        llm = SequenceLLM(
            LLMResponse(content="{"),
            LLMResponse(content="{"),
        )

        analysis = asyncio.run(
            dispatcher.analyze_command_for_approval(
                "echo ok",
                "测试分析失败",
                include_llm=True,
                llm=llm,
            )
        )

        self.assertEqual(len(llm.calls), 2)
        self.assertEqual(analysis["detail_status"], "failed")
        self.assertEqual(analysis["reviewer_mode"], "llm_error")
        self.assertEqual(analysis["detail_errors"], ["invalid_response"])
        self.assertEqual(analysis["analyzed_command_count"], 0)
        self.assertEqual(analysis["command_count"], 1)

    def test_invalid_json_logs_safe_command_detail_diagnostics(self):
        command = "echo PRIVATE_COMMAND_MARKER"
        raw_response = '{"private":"PRIVATE_RESPONSE_MARKER"'
        llm = DiagnosticSequenceLLM(
            LLMResponse(
                content=raw_response,
                completion_tokens=640,
                finish_reason="length",
            ),
            LLMResponse(
                content=raw_response,
                completion_tokens=370,
                finish_reason="length",
            ),
        )

        with self.assertLogs("chatdome.agent.tools", level="WARNING") as captured:
            asyncio.run(
                ToolDispatcher(FakeSandbox()).analyze_command_for_approval(
                    command,
                    "测试诊断日志",
                    include_llm=True,
                    llm=llm,
                )
            )

        output = "\n".join(captured.output)
        self.assertEqual(len(captured.records), 2)
        self.assertIn("mode=standard", output)
        self.assertIn("mode=compact", output)
        self.assertIn("reason=json_parse_error", output)
        self.assertIn("model=diagnostic-model", output)
        self.assertIn("requested_max_tokens=640", output)
        self.assertIn("requested_max_tokens=370", output)
        self.assertIn(f"response_chars={len(raw_response)}", output)
        self.assertIn("completion_tokens=640", output)
        self.assertIn("finish_reason=length", output)
        self.assertIn("json_line=1", output)
        self.assertNotIn("PRIVATE_RESPONSE_MARKER", output)
        self.assertNotIn("PRIVATE_COMMAND_MARKER", output)

    def test_missing_fields_log_stable_validation_reason(self):
        raw_response = '{"safety_status":"SAFE"}'
        llm = DiagnosticSequenceLLM(
            LLMResponse(content=raw_response),
            LLMResponse(content=raw_response),
        )

        with self.assertLogs("chatdome.agent.tools", level="WARNING") as captured:
            asyncio.run(
                ToolDispatcher(FakeSandbox()).analyze_command_for_approval(
                    "echo ok",
                    "测试字段诊断",
                    include_llm=True,
                    llm=llm,
                )
            )

        output = "\n".join(captured.output)
        self.assertIn("reason=missing_detail_fields", output)
        self.assertIn("missing_count=5", output)

    def test_incomplete_groups_log_expected_and_actual_counts(self):
        response = _command_detail_response(["echo a"])
        llm = DiagnosticSequenceLLM(response, response)

        with self.assertLogs("chatdome.agent.tools", level="WARNING") as captured:
            asyncio.run(
                ToolDispatcher(FakeSandbox()).analyze_command_for_approval(
                    "echo a && echo b",
                    "测试分组诊断",
                    include_llm=True,
                    llm=llm,
                )
            )

        output = "\n".join(captured.output)
        self.assertIn("reason=incomplete_command_groups", output)
        self.assertIn("expected=2", output)
        self.assertIn("actual=1", output)

    def test_empty_command_groups_retry_then_fail_instead_of_showing_details(self):
        invalid_response = LLMResponse(
            content=json.dumps(
                {
                    "safety_status": "SAFE",
                    "risk_level": "LOW",
                    "mutation_detected": False,
                    "deletion_detected": False,
                    "impact_analysis": "无影响。",
                    "command_breakdown": {
                        "summary": "空结构",
                        "commands": [{}, {}],
                    },
                },
                ensure_ascii=False,
            )
        )
        dispatcher = ToolDispatcher(FakeSandbox())
        llm = SequenceLLM(invalid_response, invalid_response)

        analysis = asyncio.run(
            dispatcher.analyze_command_for_approval(
                "echo a && echo b",
                "测试空结构",
                include_llm=True,
                llm=llm,
            )
        )

        self.assertEqual(len(llm.calls), 2)
        self.assertEqual(analysis["detail_status"], "failed")
        self.assertEqual(analysis["detail_errors"], ["invalid_response"])

    def test_inconsistent_deletion_flags_retry_then_fail(self):
        invalid_response = _command_detail_response(
            ["rm /tmp/a"],
            safety_status="SAFE",
            risk_level="LOW",
            mutation_detected=False,
            deletion_detected=True,
        )
        dispatcher = ToolDispatcher(FakeSandbox())
        llm = SequenceLLM(invalid_response, invalid_response)

        analysis = asyncio.run(
            dispatcher.analyze_command_for_approval(
                "rm /tmp/a",
                "测试风险一致性",
                include_llm=True,
                llm=llm,
            )
        )

        self.assertEqual(len(llm.calls), 2)
        self.assertEqual(analysis["detail_status"], "failed")
        self.assertEqual(analysis["detail_errors"], ["invalid_response"])

    def test_failed_batch_preserves_completed_batches_as_partial(self):
        dispatcher = ToolDispatcher(FakeSandbox())
        llm = SequenceLLM(
            _command_detail_response(["echo a", "echo b"]),
            LLMResponse(content="{"),
            LLMResponse(content="{"),
        )

        with (
            patch("chatdome.agent.tools._COMMAND_DETAIL_BATCH_SIZE", 2),
            patch("chatdome.agent.tools._COMMAND_DETAIL_MAX_CONCURRENCY", 1),
        ):
            analysis = asyncio.run(
                dispatcher.analyze_command_for_approval(
                    "echo a && echo b && echo c",
                    "测试部分结果",
                    include_llm=True,
                    llm=llm,
                )
            )

        commands = analysis["command_breakdown"]["commands"]
        self.assertEqual(analysis["detail_status"], "partial")
        self.assertEqual(analysis["analyzed_command_count"], 2)
        self.assertEqual(analysis["command_count"], 3)
        self.assertEqual(analysis["detail_errors"], ["invalid_response"])
        self.assertEqual(commands[2]["summary"], "命令解析不可用")
        self.assertEqual(analysis["safety_status"], "UNSAFE")
        self.assertEqual(analysis["risk_level"], "HIGH")
        self.assertTrue(analysis["mutation_detected"])

    def test_command_detail_hard_timeout_cancels_pending_batches(self):
        dispatcher = ToolDispatcher(FakeSandbox())
        llm = SlowCommandDetailLLM()

        with patch(
            "chatdome.agent.tools._COMMAND_DETAIL_TIMEOUT_SECONDS",
            0.01,
        ):
            analysis = asyncio.run(
                dispatcher.analyze_command_for_approval(
                    "echo ok",
                    "测试分析超时",
                    include_llm=True,
                    llm=llm,
                )
            )

        self.assertTrue(llm.cancelled)
        self.assertEqual(analysis["detail_status"], "failed")
        self.assertEqual(analysis["detail_errors"], ["timeout"])
        self.assertIn("分析超时", analysis["impact_analysis"])

    def test_hard_timeout_does_not_wait_for_delayed_cancellation(self):
        async def run_case():
            dispatcher = ToolDispatcher(FakeSandbox())
            llm = CancellationResistantDetailLLM()
            loop = asyncio.get_running_loop()
            started_at = loop.time()
            analysis = await dispatcher.analyze_command_for_approval(
                "echo ok",
                "测试硬超时",
                include_llm=True,
                llm=llm,
            )
            elapsed = loop.time() - started_at

            await asyncio.wait_for(llm.cancelled.wait(), timeout=0.1)
            self.assertLess(elapsed, 0.1)
            self.assertEqual(analysis["detail_status"], "failed")
            self.assertEqual(analysis["detail_errors"], ["timeout"])
            await asyncio.sleep(0.25)

        with patch(
            "chatdome.agent.tools._COMMAND_DETAIL_TIMEOUT_SECONDS",
            0.01,
        ):
            asyncio.run(run_case())

    def test_external_cancellation_does_not_wait_for_detail_provider(self):
        async def run_case():
            dispatcher = ToolDispatcher(FakeSandbox())
            llm = CancellationResistantDetailLLM()
            detail_task = asyncio.create_task(
                dispatcher.analyze_command_for_approval(
                    "echo ok",
                    "测试中止分析",
                    include_llm=True,
                    llm=llm,
                )
            )
            await asyncio.wait_for(llm.started.wait(), timeout=0.1)

            started_at = asyncio.get_running_loop().time()
            detail_task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await detail_task
            elapsed = asyncio.get_running_loop().time() - started_at

            await asyncio.wait_for(llm.cancelled.wait(), timeout=0.1)
            self.assertLess(elapsed, 0.1)
            await asyncio.sleep(0.25)

        asyncio.run(run_case())

    def test_command_detail_normalization_limits_each_segment(self):
        raw = {
            "base_cmd": "echo",
            "summary": "摘要" * 200,
            "tokens": [
                {
                    "token": "echo",
                    "role": "command",
                    "label": "标签" * 100,
                    "meaning": "解释" * 200,
                }
                for _ in range(20)
            ],
            "targets": [
                {
                    "value": "/tmp/a",
                    "type": "file",
                    "operation": "read",
                }
                for _ in range(10)
            ],
            "warnings": [f"风险 {index}" for index in range(8)],
        }

        normalized = ToolDispatcher._normalize_llm_command_breakdown(
            raw,
            "echo /tmp/a",
        )

        self.assertEqual(len(normalized["tokens"]), 12)
        self.assertEqual(len(normalized["targets"]), 6)
        self.assertEqual(len(normalized["warnings"]), 3)
        self.assertLessEqual(len(normalized["tokens"][0]["label"]), 40)
        self.assertLessEqual(len(normalized["tokens"][0]["meaning"]), 120)
        self.assertLessEqual(len(normalized["summary"]), 160)

    def test_pending_session_snapshot_preserves_approval_binding(self):
        session = _pending_session()

        restored = AgentSession.from_snapshot(session.to_snapshot())

        self.assertEqual(restored.pending_approval_id, session.pending_approval_id)
        self.assertEqual(restored.pending_run_id, session.pending_run_id)
        self.assertEqual(restored.pending_command_hash, session.pending_command_hash)
        self.assertEqual(restored.pending_risk_level, "LOW")

    def test_missing_legacy_tool_output_is_repaired(self):
        session = AgentSession(chat_id=123)
        session.messages = [
            {"role": "system", "content": "system prompt"},
            {"role": "user", "content": "check web"},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "fc_legacy",
                        "call_id": "call_legacy",
                        "type": "function",
                        "function": {"name": "run_shell_command", "arguments": "{}"},
                    }
                ],
            },
        ]

        repaired = session.repair_missing_tool_outputs()

        self.assertEqual(repaired, 1)
        self.assertEqual(session.messages[-1]["role"], "tool")
        self.assertEqual(session.messages[-1]["tool_call_id"], "call_legacy")
        self.assertIn("Legacy tool output was missing", session.messages[-1]["content"])
        self.assertIn("Do not retry or continue it", session.messages[-1]["content"])

    def test_pending_tool_output_is_not_repaired_until_decision(self):
        session = _pending_session()

        repaired = session.repair_missing_tool_outputs()

        self.assertEqual(repaired, 0)
        self.assertFalse(any(msg.get("role") == "tool" for msg in session.messages))

    def test_detail_request_can_upgrade_static_cache_to_llm_review(self):
        session = _pending_session()
        session.pending_analysis = {
            "safety_status": "SAFE",
            "risk_level": "LOW",
            "mutation_detected": False,
            "deletion_detected": False,
            "impact_analysis": "Static detail",
            "reviewer_mode": "static_only",
        }
        dispatcher = FakeApprovalDetailDispatcher()
        agent = _details_agent(session, dispatcher)

        details = asyncio.run(
            agent.get_pending_approval_details(
                123,
                approval_id=session.pending_approval_id,
                include_llm=True,
            )
        )

        self.assertTrue(details["ok"])
        self.assertEqual(details["analysis"]["reviewer_mode"], "llm")
        self.assertEqual([call["include_llm"] for call in dispatcher.calls], [True])

    def test_detail_request_does_not_cache_result_after_approval_changes(self):
        session = _pending_session()
        dispatcher = FakeApprovalDetailDispatcher(session=session, clear_pending=True)
        agent = _details_agent(session, dispatcher)

        details = asyncio.run(
            agent.get_pending_approval_details(
                123,
                approval_id=session.pending_approval_id,
                include_llm=True,
            )
        )

        self.assertFalse(details["ok"])
        self.assertIsNone(session.pending_analysis)

    def test_visible_context_during_compression_is_not_sent_to_react_loop(self):
        class InjectingLLM:
            model = "fake-model"

            def __init__(self, session):
                self.session = session
                self.calls = []

            async def chat_completion(self, messages, tools=None, response_format=None):
                self.calls.append(
                    {
                        "messages": list(messages),
                        "tools": tools,
                        "response_format": response_format,
                    }
                )
                if len(self.calls) == 1:
                    self.session.add_visible_context(
                        event_type="sentinel_alert_push",
                        user_action="收到 Sentinel 告警推送",
                        assistant_summary="SSH 成功登录告警。",
                        refs={"check_id": "ssh_success_login", "IP": "114.246.239.99"},
                    )
                    await asyncio.sleep(0)
                    return SimpleNamespace(content="压缩摘要：旧上下文。")
                return LLMResponse(content="final answer", prompt_tokens=1, completion_tokens=1, total_tokens=2)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            memory_path = root / "memory" / "123.json"
            compression_path = root / "compression" / "123.log"
            session = AgentSession(chat_id=123)
            session.messages = [
                {"role": "system", "content": "system"},
                {"role": "user", "content": "旧问题"},
                {"role": "assistant", "content": "旧回答"},
                {"role": "user", "content": "继续分析"},
                {"role": "assistant", "content": "继续分析结果"},
            ]
            llm = InjectingLLM(session)
            agent = object.__new__(Agent)
            agent.llm = llm
            agent.config = SimpleNamespace(model="fake-model", max_history_tokens=1, max_rounds_per_turn=10)
            agent.tools = []
            agent.session_manager = FakeSessionManager(session)
            agent.tool_dispatcher = CountingToolDispatcher()
            agent._persist_session = lambda saved_session: agent.session_manager.save_session(saved_session)

            async def fake_snapshot():
                return SimpleNamespace(client=llm)

            agent.get_active_llm_snapshot = fake_snapshot

            with patch("chatdome.agent.session.memory_file_path", return_value=memory_path), patch(
                "chatdome.agent.session.compression_log_path",
                return_value=compression_path,
            ), patch("chatdome.agent.tracker.TokenTracker.record_usage"):
                response = asyncio.run(agent.handle_message(123, "分析当前状态"))

        self.assertEqual(response.kind, "reply")
        self.assertEqual(response.content, "final answer")
        self.assertEqual(len(llm.calls), 2)
        react_messages = llm.calls[1]["messages"]
        encoded_react_messages = json.dumps(react_messages, ensure_ascii=False)
        self.assertNotIn("sentinel_alert_push", encoded_react_messages)
        self.assertNotIn("114.246.239.99", encoded_react_messages)
        self.assertFalse(session.agent_running)
        self.assertEqual(session.deferred_visible_context_count(), 0)
        final_index = next(i for i, msg in enumerate(session.messages) if msg.get("content") == "final answer")
        visible_index = next(
            i
            for i, msg in enumerate(session.messages)
            if "[Telegram 用户可见事件]" in str(msg.get("content", ""))
        )
        self.assertLess(final_index, visible_index)

    def test_round_limit_reports_llm_rounds_not_tool_results(self):
        session = AgentSession(chat_id=123)
        session.add_user_message("run a multi-step investigation")
        llm = RepeatingToolLLM(tools_per_round=2)
        dispatcher = CountingToolDispatcher()
        agent = _loop_agent(llm, dispatcher, max_rounds_per_turn=10)

        with patch("chatdome.agent.tracker.TokenTracker.record_usage"):
            response = asyncio.run(agent._run_loop(123, session))

        self.assertEqual(response.kind, "round_limit")
        self.assertEqual(response.payload["rounds"], 10)
        self.assertEqual(session.pending_round_count, 10)
        self.assertEqual(session.round_count, 10)
        self.assertEqual(llm.calls, 10)
        self.assertEqual(len(dispatcher.calls), 20)

    def test_repeated_identical_tool_call_is_suppressed_and_stopped(self):
        session = AgentSession(chat_id=123)
        session.add_user_message("show the latest 5 executed commands")
        llm = RepeatingSameToolLLM()
        dispatcher = CountingToolDispatcher()
        agent = _loop_agent(llm, dispatcher, max_rounds_per_turn=10)

        with patch("chatdome.agent.tracker.TokenTracker.record_usage"):
            response = asyncio.run(agent._run_loop(123, session))

        self.assertEqual(response.kind, "reply")
        self.assertIn("重复工具调用", response.content)
        self.assertEqual(llm.calls, 3)
        self.assertEqual(len(dispatcher.calls), 1)
        tool_results = [msg for msg in session.messages if msg.get("role") == "tool"]
        self.assertEqual(len(tool_results), 3)
        self.assertIn("Duplicate tool call suppressed", tool_results[-1]["content"])

    def test_pending_approval_defers_remaining_tool_calls_with_outputs(self):
        session = AgentSession(chat_id=123)
        session.add_user_message("diagnose and repair web service")
        llm = FakeLLM(
            LLMResponse(
                content=None,
                tool_calls=[
                    ToolCall(
                        id="call-1",
                        name="run_shell_command",
                        arguments='{"command": "ss -tlnp"}',
                    ),
                    ToolCall(
                        id="call-2",
                        name="run_shell_command",
                        arguments='{"command": "systemctl restart nginx"}',
                    ),
                    ToolCall(
                        id="call-3",
                        name="run_shell_command",
                        arguments='{"command": "journalctl -u nginx -n 50"}',
                    ),
                ],
            )
        )
        dispatcher = PendingAfterSecondToolDispatcher()
        agent = _loop_agent(llm, dispatcher)

        with patch("chatdome.agent.audit.CommandAuditTracker.record_event"), patch(
            "chatdome.agent.tracker.TokenTracker.record_usage"
        ):
            response = asyncio.run(agent._run_loop(123, session))

        self.assertEqual(response.kind, "pending_approval")
        self.assertIsNone(session.pending_run_id)
        self.assertNotIn("run_id", response.payload)
        self.assertEqual(response.payload["safety_status"], "NEEDS_APPROVAL")
        self.assertFalse(response.payload["mutation_detected"])
        self.assertFalse(response.payload["deletion_detected"])
        self.assertEqual(
            [call["tool_call_id"] for call in dispatcher.calls],
            ["call-1", "call-2"],
        )
        tool_results = {
            msg["tool_call_id"]: msg["content"]
            for msg in session.messages
            if msg.get("role") == "tool"
        }
        self.assertEqual(tool_results["call-1"], "result for call-1")
        self.assertIn("not executed", tool_results["call-3"])
        self.assertNotIn("call-2", tool_results)

        resume_agent = _resume_agent(session)
        with patch("chatdome.agent.audit.CommandAuditTracker.record_event"):
            raw_result, final_response = asyncio.run(
                resume_agent.resume_session(
                    123,
                    "APPROVE",
                    approval_id=session.pending_approval_id,
                )
            )

        self.assertEqual(raw_result, "ok")
        self.assertEqual(final_response.kind, "reply")
        tool_result_ids = [
            msg["tool_call_id"]
            for msg in session.messages
            if msg.get("role") == "tool"
        ]
        self.assertCountEqual(tool_result_ids, ["call-1", "call-2", "call-3"])

    def test_deferred_tool_call_can_be_requested_after_approval(self):
        session = AgentSession(chat_id=123)
        session.add_user_message("restart ssh on a custom port and update fail2ban")
        restart_sshd = json.dumps(
            {
                "command": "systemctl restart sshd",
                "reason": "Apply SSH port change.",
            }
        )
        restart_fail2ban = json.dumps(
            {
                "command": "systemctl restart fail2ban",
                "reason": "Apply fail2ban SSH port change.",
            }
        )
        llm = SequenceLLM(
            LLMResponse(
                content=None,
                tool_calls=[
                    ToolCall(
                        id="restart-sshd",
                        name="run_shell_command",
                        arguments=restart_sshd,
                    ),
                    ToolCall(
                        id="restart-fail2ban-deferred",
                        name="run_shell_command",
                        arguments=restart_fail2ban,
                    ),
                ],
            ),
            LLMResponse(
                content=None,
                tool_calls=[
                    ToolCall(
                        id="restart-fail2ban",
                        name="run_shell_command",
                        arguments=restart_fail2ban,
                    ),
                ],
            ),
        )
        dispatcher = ApprovalRequiredShellDispatcher()
        agent = object.__new__(Agent)
        agent.llm = llm
        agent.config = SimpleNamespace(model="fake-model", max_rounds_per_turn=10)
        agent.tools = []
        agent.session_manager = FakeSessionManager(session)
        agent.tool_dispatcher = dispatcher
        agent._persist_session = lambda saved_session: agent.session_manager.save_session(saved_session)

        with patch("chatdome.agent.audit.CommandAuditTracker.record_event"), patch(
            "chatdome.agent.tracker.TokenTracker.record_usage"
        ):
            first_response = asyncio.run(agent._run_loop(123, session))

        self.assertEqual(first_response.kind, "pending_approval")
        self.assertEqual(session.pending_command, "systemctl restart sshd")
        self.assertEqual(
            [call["tool_call_id"] for call in dispatcher.calls],
            ["restart-sshd"],
        )

        with patch("chatdome.agent.audit.CommandAuditTracker.record_event"), patch(
            "chatdome.agent.tracker.TokenTracker.record_usage"
        ):
            raw_result, final_response = asyncio.run(
                agent.resume_session(
                    123,
                    "APPROVE",
                    approval_id=session.pending_approval_id,
                )
            )

        self.assertEqual(raw_result, "ok")
        self.assertEqual(final_response.kind, "pending_approval")
        self.assertEqual(session.pending_command, "systemctl restart fail2ban")
        self.assertEqual(
            [call["tool_call_id"] for call in dispatcher.calls],
            ["restart-sshd", "restart-fail2ban"],
        )
        tool_result_text = "\n".join(
            msg.get("content", "")
            for msg in session.messages
            if msg.get("role") == "tool"
        )
        self.assertNotIn("Duplicate tool call suppressed", tool_result_text)

    def test_command_audit_tool_returns_recent_executed_commands(self):
        from chatdome.agent.audit import CommandAuditTracker

        with tempfile.TemporaryDirectory() as tmp:
            with patch("chatdome.agent.audit.AUDIT_DIR", Path(tmp)):
                CommandAuditTracker.record_event(
                    "security_check_executed",
                    chat_id=123,
                    command="last -n 5",
                    reason="security_check:recent_logins",
                    check_id="recent_logins",
                    execution_mode="pack",
                    return_code=0,
                    duration_ms=12,
                )
                CommandAuditTracker.record_event(
                    "command_reviewed",
                    chat_id=123,
                    command="history | tail -5",
                    reason="not actually executed",
                )
                CommandAuditTracker.record_event(
                    "security_check_executed",
                    chat_id=456,
                    command="whoami",
                    reason="other chat",
                )
                CommandAuditTracker.record_event(
                    "security_check_executed",
                    chat_id=123,
                    audit_source="sentinel",
                    command="uptime",
                    reason="security_check:sentinel_uptime",
                )

                dispatcher = ToolDispatcher(SimpleNamespace())
                result = asyncio.run(
                    dispatcher.dispatch(
                        "get_command_audit_events",
                        '{"limit": 5}',
                        tool_call_id="audit-call",
                        chat_id=123,
                    )
                )

        self.assertIn("ChatDome internal audit", result)
        self.assertIn("not SSH user session commands", result)
        self.assertIn("last -n 5", result)
        self.assertNotIn("history | tail -5", result)
        self.assertNotIn("whoami", result)
        self.assertNotIn("uptime", result)

    def test_manual_index_and_tools_separate_chatdome_and_ssh_sources(self):
        prompt = build_system_prompt()
        tools = build_tools()
        manual_tool = next(
            tool
            for tool in tools
            if tool["function"]["name"] == "read_chatdome_manual"
        )
        audit_tool = next(
            tool
            for tool in tools
            if tool["function"]["name"] == "get_command_audit_events"
        )
        manual_section_ids = (
            manual_tool["function"]["parameters"]["properties"]["section_id"]["enum"]
        )
        description = audit_tool["function"]["description"]

        self.assertIn("read_chatdome_manual(section_id)", prompt)
        self.assertIn("command_audit", prompt)
        self.assertIn("ssh_session_commands", prompt)
        self.assertIn("host_exec_audit", prompt)
        self.assertIn("command_audit", manual_section_ids)
        self.assertIn("ssh_session_commands", manual_section_ids)
        self.assertIn("Do not use for generic host/user/SSH command history", description)
        self.assertIn("auditd_status", description)
        self.assertIn("ssh_session_commands", description)

    def test_read_chatdome_manual_returns_curated_section(self):
        dispatcher = ToolDispatcher(SimpleNamespace())
        result = asyncio.run(
            dispatcher.dispatch(
                "read_chatdome_manual",
                '{"section_id": "ssh_session_commands"}',
                tool_call_id="manual-call",
                chat_id=123,
            )
        )

        self.assertIn("ChatDome manual section: ssh_session_commands", result)
        self.assertIn("auditd_status", result)
        self.assertIn("ssh_session_commands", result)
        self.assertIn("last -i -F -n", result)

    def test_summary_skips_old_persisted_tool_like_followups(self):
        session = _pending_session()
        session.pending_followups = [
            {"role": "user", "content": "我想知道目前有多少IP已经被封禁了"},
            {
                "role": "assistant",
                "content": (
                    "<tool_call>\n"
                    "<function=run_shell_command>\n"
                    "<parameter=command>fail2ban-client status sshd</parameter>\n"
                    "</function>\n"
                    "</tool_call>"
                ),
            },
        ]

        summary = Agent._summarize_pending_followups(session)

        self.assertIn("用户: 我想知道目前有多少IP已经被封禁了", summary)
        self.assertNotIn("<tool_call>", summary)
        self.assertNotIn("<function=run_shell_command>", summary)

    def test_new_query_while_pending_uses_one_classifier_call_and_defers_message(self):
        llm = FakeLLM(
            LLMResponse(content='{"classification":"new_task","answer":""}')
        )
        session = _pending_session()
        agent = _pending_agent(session, llm)

        result = asyncio.run(
            agent.handle_message(123, "我想知道目前有多少IP已经被封禁了")
        )

        self.assertEqual(
            result.content,
            "当前命令等待处理。发送 /confirm 执行，或发送 /reject 取消。",
        )
        self.assertEqual(len(llm.calls), 1)
        self.assertIsNone(llm.calls[0]["tools"])
        self.assertEqual(llm.calls[0]["response_format"], {"type": "json_object"})
        self.assertEqual(session.deferred_user_message, "我想知道目前有多少IP已经被封禁了")
        self.assertEqual(session.active_turn.state, "waiting_approval_decision")
        self.assertEqual(session.pending_followups, [])

    def test_approval_question_uses_classifier_answer_without_second_llm_call(self):
        llm = FakeLLM(
            LLMResponse(
                content=(
                    '{"classification":"approval_question",'
                    '"answer":"该命令只查询 fail2ban 状态，不修改配置。"}'
                )
            )
        )
        session = _pending_session()
        agent = _pending_agent(session, llm)

        with patch("chatdome.agent.tracker.TokenTracker.record_usage"):
            result = asyncio.run(agent.handle_message(123, "这条命令有什么风险？"))

        self.assertEqual(result.content, "该命令只查询 fail2ban 状态，不修改配置。")
        self.assertEqual(len(llm.calls), 1)
        self.assertEqual(
            session.pending_followups,
            [
                {"role": "user", "content": "这条命令有什么风险？"},
                {
                    "role": "assistant",
                    "content": "该命令只查询 fail2ban 状态，不修改配置。",
                },
            ],
        )
        self.assertEqual(session.active_turn.state, "waiting_approval")

    def test_waiting_decision_repeats_prompt_without_reclassifying_or_replacing(self):
        llm = FakeLLM(
            LLMResponse(content='{"classification":"tool_required","answer":""}')
        )
        session = _pending_session()
        agent = _pending_agent(session, llm)

        first = asyncio.run(agent.handle_message(123, "检查磁盘"))
        second = asyncio.run(agent.handle_message(123, "改成检查内存"))

        self.assertEqual(first.content, second.content)
        self.assertEqual(len(llm.calls), 1)
        self.assertEqual(session.deferred_user_message, "检查磁盘")

    def test_natural_approval_is_classified_then_resumes_same_turn(self):
        llm = SequenceLLM(
            LLMResponse(content='{"classification":"approve","answer":""}'),
            LLMResponse(content="done"),
        )
        session = _pending_session()
        agent = _pending_agent(session, llm)

        with patch("chatdome.agent.audit.CommandAuditTracker.record_event"), patch(
            "chatdome.agent.tracker.TokenTracker.record_usage"
        ):
            result = asyncio.run(agent.handle_message(123, "同意执行"))

        self.assertEqual(result.content, "done")
        self.assertEqual(len(llm.calls), 2)
        self.assertEqual(len(agent.tool_dispatcher.sandbox.commands), 1)
        self.assertIsNone(session.active_turn)

    def test_tool_like_classifier_response_becomes_unknown_and_defers_input(self):
        llm = FakeLLM(
            LLMResponse(
                content=(
                    "<tool_call>\n"
                    "<function=run_shell_command>\n"
                    "<parameter=command>\n"
                    "fail2ban-client status sshd\n"
                    "</parameter>\n"
                    "</function>\n"
                    "</tool_call>"
                ),
                tool_calls=[
                    ToolCall(
                        id="call-2",
                        name="run_shell_command",
                        arguments='{"command": "fail2ban-client status sshd"}',
                    )
                ],
            )
        )
        session = _pending_session()
        agent = _pending_agent(session, llm)

        with patch("chatdome.agent.tracker.TokenTracker.record_usage"):
            result = asyncio.run(agent.handle_message(123, "这个命令安全吗？"))

        self.assertEqual(
            result.content,
            "当前命令等待处理。发送 /confirm 执行，或发送 /reject 取消。",
        )
        self.assertEqual(len(llm.calls), 1)
        self.assertEqual(session.pending_followups, [])
        self.assertEqual(session.deferred_user_message, "这个命令安全吗？")

    def test_abort_pending_task_clears_approval_without_resuming(self):
        session = _pending_session()
        session.task_auto_approve = True
        session.pending_analysis = {"reviewer_mode": "llm"}
        session.pending_followups = [{"role": "user", "content": "question"}]
        agent = _resume_agent(session)

        with patch(
            "chatdome.agent.audit.CommandAuditTracker.record_event"
        ) as record_event:
            aborted = asyncio.run(agent.abort_pending_task(123))
            repeated_abort = asyncio.run(
                agent.abort_pending_task(123, approval_id="AP-20260423-000001")
            )

        self.assertTrue(aborted)
        self.assertFalse(repeated_abort)
        self.assertFalse(session.pending_approval)
        self.assertFalse(session.task_auto_approve)
        self.assertIsNone(session.pending_approval_id)
        self.assertIsNone(session.pending_command)
        self.assertEqual(session.pending_followups, [])
        self.assertEqual(agent.tool_dispatcher.sandbox.commands, [])
        self.assertEqual(agent.llm.calls, [])
        self.assertGreater(agent.session_manager.saved, 0)

        tool_results = [
            message
            for message in session.messages
            if message.get("role") == "tool"
        ]
        self.assertEqual(len(tool_results), 1)
        self.assertEqual(tool_results[0]["tool_call_id"], "call-1")
        self.assertIn("/stop", tool_results[0]["content"])

        record_event.assert_called_once()
        audit_call = record_event.call_args
        self.assertEqual(audit_call.args[0], "command_task_aborted")
        self.assertEqual(audit_call.kwargs["approval_id"], "AP-20260423-000001")
        self.assertEqual(audit_call.kwargs["approval_action"], "ABORT")

        raw_result, final_response = asyncio.run(
            agent.resume_session(
                123,
                "APPROVE",
                approval_id="AP-20260423-000001",
            )
        )
        self.assertEqual(raw_result, "")
        self.assertEqual(final_response.payload["approval_status"], "unavailable")
        self.assertEqual(agent.tool_dispatcher.sandbox.commands, [])

    def test_reject_cancels_turn_without_second_react_call(self):
        session = _pending_session()
        agent = _resume_agent(session)

        with patch("chatdome.agent.audit.CommandAuditTracker.record_event"):
            _, result = asyncio.run(agent.resume_session(123, "REJECT"))

        self.assertEqual(result.content, "已拒绝当前命令，任务已取消。")
        self.assertEqual(agent.llm.calls, [])
        self.assertIsNone(session.active_turn)
        self.assertEqual(session.messages[-2]["role"], "tool")
        self.assertEqual(session.messages[-1]["role"], "assistant")

    def test_removed_task_scope_approval_alias_cancels_without_execution(self):
        session = _pending_session()
        agent = _resume_agent(session)

        with patch("chatdome.agent.audit.CommandAuditTracker.record_event"):
            _, result = asyncio.run(agent.resume_session(123, "APPROVE_TASK"))

        self.assertEqual(result.content, "已拒绝当前命令，任务已取消。")
        self.assertEqual(agent.tool_dispatcher.sandbox.commands, [])
        self.assertFalse(session.task_auto_approve)
        self.assertIsNone(session.active_turn)

    def test_reject_releases_deferred_message_after_cancellation(self):
        session = _pending_session()
        session.defer_user_message("inspect disk", user_id=456)
        agent = _resume_agent(session)

        with patch("chatdome.agent.audit.CommandAuditTracker.record_event"):
            _, result = asyncio.run(agent.resume_session(123, "REJECT"))

        self.assertEqual(result.payload["deferred_user_message"], "inspect disk")
        self.assertEqual(result.payload["deferred_user_id"], 456)
        self.assertEqual(session.deferred_user_message, "inspect disk")
        self.assertEqual(session.deferred_user_id, 456)

    def test_approve_releases_deferred_message_only_after_completed(self):
        session = _pending_session()
        session.defer_user_message("inspect disk", user_id=456)
        llm = SequenceLLM(LLMResponse(content="done"))
        agent = _pending_agent(session, llm)

        with patch("chatdome.agent.audit.CommandAuditTracker.record_event"), patch(
            "chatdome.agent.tracker.TokenTracker.record_usage"
        ):
            _, result = asyncio.run(
                agent.resume_session(
                    123,
                    "APPROVE",
                    approval_id=session.pending_approval_id,
                )
            )

        self.assertEqual(result.content, "done")
        self.assertEqual(result.payload["deferred_user_message"], "inspect disk")
        self.assertEqual(result.payload["deferred_user_id"], 456)
        self.assertEqual(session.deferred_user_message, "inspect disk")
        self.assertEqual(session.deferred_user_id, 456)

    def test_approve_retains_deferred_message_when_another_approval_is_created(self):
        session = AgentSession(chat_id=123)
        session.add_user_message("restart services")
        session.defer_user_message("inspect disk", user_id=456)
        llm = SequenceLLM(
            LLMResponse(
                tool_calls=[
                    ToolCall(
                        id="call-2",
                        name="run_shell_command",
                        arguments='{"command":"systemctl restart nginx"}',
                    )
                ]
            )
        )
        dispatcher = ApprovalRequiredShellDispatcher()
        agent = object.__new__(Agent)
        agent.llm = llm
        agent.llm_manager = None
        agent.config = SimpleNamespace(max_rounds_per_turn=10, max_history_tokens=16000)
        agent.tools = []
        agent.session_manager = FakeSessionManager(session)
        agent.tool_dispatcher = dispatcher
        session.begin_turn("restart services")
        session.transition_turn("waiting_approval")
        session.pending_approval = True
        session.pending_approval_id = "AP-1"
        session.pending_tool_call_id = "call-1"
        session.pending_command = "systemctl restart sshd"
        session.pending_command_hash = Agent._command_hash(session.pending_command)
        session.pending_reason = "重启 SSH 服务"

        with patch("chatdome.agent.audit.CommandAuditTracker.record_event"), patch(
            "chatdome.agent.tracker.TokenTracker.record_usage"
        ):
            _, result = asyncio.run(
                agent.resume_session(123, "APPROVE", approval_id="AP-1")
            )

        self.assertEqual(result.kind, "pending_approval")
        self.assertEqual(session.deferred_user_message, "inspect disk")
        self.assertNotIn("deferred_user_message", result.payload)

    def test_missing_reason_requires_details_before_natural_or_typed_approval(self):
        session = _pending_session()
        session.pending_reason = "无说明"
        context = session.begin_turn("inspect", user_id=123)
        session.transition_turn("waiting_approval")
        agent = _resume_agent(session)

        _, result = asyncio.run(
            agent.resume_session(
                123,
                "APPROVE",
                approval_id=session.pending_approval_id,
            )
        )

        self.assertEqual(result.payload["approval_status"], "review_required")
        self.assertIn("/details", result.content)
        self.assertTrue(session.pending_approval)
        self.assertEqual(session.active_turn.turn_id, context.turn_id)
        self.assertEqual(agent.tool_dispatcher.sandbox.commands, [])

    def test_stale_classifier_result_cannot_mutate_rejected_approval(self):
        class GatedClassifierLLM:
            model = "fake-model"

            def __init__(self):
                self.started = asyncio.Event()
                self.release = asyncio.Event()

            async def chat_completion(self, messages, tools=None, response_format=None):
                del messages, tools, response_format
                self.started.set()
                await self.release.wait()
                return LLMResponse(
                    content=json.dumps(
                        {
                            "classification": "unknown",
                            "answer": "",
                        }
                    )
                )

        async def scenario():
            session = _pending_session()
            session.begin_turn("inspect", user_id=123)
            session.transition_turn("waiting_approval")
            llm = GatedClassifierLLM()
            agent = _pending_agent(session, llm)

            classify_task = asyncio.create_task(
                agent.handle_message(123, "换个方法", user_id=456)
            )
            await llm.started.wait()
            _, rejected = await agent.resume_session(
                123,
                "REJECT",
                approval_id=session.pending_approval_id,
            )
            llm.release.set()
            classified = await classify_task
            return session, agent, rejected, classified

        with patch("chatdome.agent.audit.CommandAuditTracker.record_event"), patch(
            "chatdome.agent.tracker.TokenTracker.record_usage"
        ):
            session, agent, rejected, classified = asyncio.run(scenario())

        self.assertEqual(rejected.content, "已拒绝当前命令，任务已取消。")
        self.assertEqual(classified.content, "审批状态已变化，请查看最新消息。")
        self.assertIsNone(session.active_turn)
        self.assertIsNone(session.deferred_user_message)
        self.assertEqual(agent.tool_dispatcher.sandbox.commands, [])

    def test_hash_mismatch_fails_turn_without_execution_or_llm_call(self):
        session = _pending_session()
        session.pending_command_hash = Agent._command_hash("echo original")
        llm = FakeLLM(LLMResponse(content="must not run"))
        agent = _pending_agent(session, llm)

        with patch("chatdome.agent.audit.CommandAuditTracker.record_event"):
            _, result = asyncio.run(
                agent.resume_session(
                    123,
                    "APPROVE",
                    approval_id=session.pending_approval_id,
                )
            )

        self.assertEqual(result.content, "命令校验失败，任务已终止。")
        self.assertEqual(agent.tool_dispatcher.sandbox.commands, [])
        self.assertEqual(llm.calls, [])
        self.assertIsNone(session.active_turn)

    def test_hidden_approval_id_mismatch_keeps_current_pending_state(self):
        session = _pending_session()
        context = session.begin_turn("inspect")
        session.transition_turn("waiting_approval")
        original = (
            session.pending_command,
            session.pending_command_hash,
            session.active_turn.turn_id,
            session.active_turn.state,
        )
        agent = _resume_agent(session)

        _, result = asyncio.run(
            agent.resume_session(123, "APPROVE", approval_id="AP-OTHER")
        )

        self.assertIn("审批编号不匹配", result.content)
        self.assertEqual(
            (
                session.pending_command,
                session.pending_command_hash,
                context.turn_id,
                session.active_turn.state,
            ),
            original,
        )
        self.assertEqual(agent.tool_dispatcher.sandbox.commands, [])

    def test_abort_pending_task_rejects_mismatched_approval_id(self):
        session = _pending_session()
        agent = _resume_agent(session)

        with patch(
            "chatdome.agent.audit.CommandAuditTracker.record_event"
        ) as record_event:
            aborted = asyncio.run(
                agent.abort_pending_task(123, approval_id="AP-OTHER")
            )

        self.assertFalse(aborted)
        self.assertTrue(session.pending_approval)
        self.assertEqual(agent.session_manager.saved, 0)
        record_event.assert_not_called()

    def test_abort_pending_task_does_not_race_approval_processing(self):
        session = _pending_session()
        session.approval_processing = True
        agent = _resume_agent(session)

        with patch(
            "chatdome.agent.audit.CommandAuditTracker.record_event"
        ) as record_event:
            aborted = asyncio.run(agent.abort_pending_task(123))

        self.assertFalse(aborted)
        self.assertTrue(session.pending_approval)
        self.assertEqual(agent.session_manager.saved, 0)
        record_event.assert_not_called()

    def test_resume_rejects_mismatched_approval_id_without_execution(self):
        session = _pending_session()
        agent = _resume_agent(session)

        with patch("chatdome.agent.audit.CommandAuditTracker.record_event"):
            raw_result, final_response = asyncio.run(
                agent.resume_session(
                    123,
                    "APPROVE",
                    approval_id="AP-OTHER",
                )
            )

        self.assertEqual(raw_result, "")
        self.assertEqual(final_response.kind, "reply")
        self.assertIn("审批编号不匹配", final_response.content)
        self.assertTrue(session.pending_approval)
        self.assertEqual(agent.tool_dispatcher.sandbox.commands, [])

    def test_resume_rejects_command_hash_mismatch_without_execution(self):
        session = _pending_session()
        session.pending_command_hash = Agent._command_hash("echo original command")
        agent = _resume_agent(session)

        with patch("chatdome.agent.audit.CommandAuditTracker.record_event"):
            raw_result, final_response = asyncio.run(
                agent.resume_session(
                    123,
                    "APPROVE",
                    approval_id=session.pending_approval_id,
                )
        )

        self.assertIn("命令校验失败", raw_result)
        self.assertEqual(final_response.content, "命令校验失败，任务已终止。")
        self.assertFalse(session.pending_approval)
        self.assertEqual(agent.tool_dispatcher.sandbox.commands, [])
        self.assertEqual(agent.llm.calls, [])
        self.assertIsNone(session.active_turn)
        self.assertEqual(session.messages[-2]["role"], "tool")
        self.assertIn("哈希与审批单不一致", session.messages[-2]["content"])
        self.assertEqual(session.messages[-1]["role"], "assistant")

    def test_resume_executes_when_approval_id_and_hash_match(self):
        session = _pending_session()
        agent = _resume_agent(session)

        with patch("chatdome.agent.audit.CommandAuditTracker.record_event"):
            raw_result, final_response = asyncio.run(
                agent.resume_session(
                    123,
                    "APPROVE",
                    approval_id=session.pending_approval_id,
                )
            )

        self.assertEqual(raw_result, "ok")
        self.assertEqual(final_response.content, "done")
        self.assertFalse(session.pending_approval)
        self.assertEqual(len(agent.tool_dispatcher.sandbox.commands), 1)
        self.assertEqual(
            agent.tool_dispatcher.sandbox.commands[0]["command"],
            "fail2ban-client status sshd",
        )


if __name__ == "__main__":
    unittest.main()
