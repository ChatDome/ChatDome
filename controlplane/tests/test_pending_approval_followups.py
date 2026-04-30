import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from chatdome.agent.core import Agent
from chatdome.agent.session import AgentSession
from chatdome.agent.tools import ToolDispatcher
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


class FakeSessionManager:
    def __init__(self, session: AgentSession):
        self.session = session
        self.saved = 0

    def get_or_create(self, chat_id: int) -> AgentSession:
        self.session.chat_id = chat_id
        return self.session

    def save_session(self, session: AgentSession) -> None:
        self.saved += 1
        self.session = session


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
        )


class FakeToolDispatcher:
    def __init__(self):
        self.sandbox = FakeSandbox()

    def _format_command_result(self, result) -> str:
        return result.stdout


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
    def test_initial_impact_summary_describes_static_precheck(self):
        summary = ToolDispatcher._build_initial_impact_summary(
            {
                "static_is_safe": False,
                "mutation_detected": True,
                "deletion_detected": False,
                "static_critical": False,
            }
        )

        self.assertIn("状态变更", summary)
        self.assertNotIn("Static precheck", summary)

    def test_pending_session_snapshot_preserves_approval_binding(self):
        session = _pending_session()

        restored = AgentSession.from_snapshot(session.to_snapshot())

        self.assertEqual(restored.pending_approval_id, session.pending_approval_id)
        self.assertEqual(restored.pending_run_id, session.pending_run_id)
        self.assertEqual(restored.pending_command_hash, session.pending_command_hash)
        self.assertEqual(restored.pending_risk_level, "LOW")

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

    def test_new_query_while_pending_does_not_call_llm_or_store_followup(self):
        llm = FakeLLM(LLMResponse(content="should not be used"))
        agent = _agent_with_llm(llm)
        session = _pending_session()

        response = asyncio.run(
            agent._handle_pending_followup(
                123,
                session,
                "我想知道目前有多少IP已经被封禁了",
            )
        )

        self.assertEqual(llm.calls, [])
        self.assertIn("可以继续问不需要执行命令的问题", response)
        self.assertIn("fail2ban-client status sshd", response)
        self.assertEqual(session.pending_followups, [])

    def test_tool_like_pending_followup_response_is_not_persisted(self):
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
        agent = _agent_with_llm(llm)
        session = _pending_session()

        with patch("chatdome.agent.tracker.TokenTracker.record_usage"):
            response = asyncio.run(
                agent._handle_pending_followup(
                    123,
                    session,
                    "这个命令安全吗？",
                )
            )

        self.assertIn("可以继续问不需要执行命令的问题", response)
        self.assertNotIn("<tool_call>", response)
        self.assertEqual(len(llm.calls), 1)
        self.assertFalse(any("tool_calls" in message for message in llm.calls[0]["messages"]))
        persisted_text = "\n".join(item["content"] for item in session.pending_followups)
        self.assertNotIn("<tool_call>", persisted_text)
        self.assertNotIn("<function=run_shell_command>", persisted_text)

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
        self.assertIn("审批编号不匹配", final_response)
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
        self.assertEqual(final_response, "done")
        self.assertFalse(session.pending_approval)
        self.assertEqual(agent.tool_dispatcher.sandbox.commands, [])
        self.assertEqual(session.messages[-1]["role"], "tool")
        self.assertIn("哈希与审批单不一致", session.messages[-1]["content"])

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
        self.assertEqual(final_response, "done")
        self.assertFalse(session.pending_approval)
        self.assertEqual(len(agent.tool_dispatcher.sandbox.commands), 1)
        self.assertEqual(
            agent.tool_dispatcher.sandbox.commands[0]["command"],
            "fail2ban-client status sshd",
        )


if __name__ == "__main__":
    unittest.main()
