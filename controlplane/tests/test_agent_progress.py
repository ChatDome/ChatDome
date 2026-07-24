import asyncio
from types import SimpleNamespace

from chatdome.agent.core import Agent
from chatdome.agent.session import AgentSession
from chatdome.llm.client import LLMResponse, ToolCall


class SequenceLLM:
    model = "test-model"

    def __init__(self):
        self.responses = [
            LLMResponse(
                tool_calls=[
                    ToolCall(
                        id="call-1",
                        name="read_file",
                        arguments='{"path": "/tmp/example"}',
                    )
                ]
            ),
            LLMResponse(content="处理完成"),
        ]

    async def chat_completion(self, messages, tools=None):
        del messages, tools
        return self.responses.pop(0)


class SessionManager:
    def __init__(self, session):
        self.session = session

    def get_or_create(self, chat_id):
        self.session.chat_id = chat_id
        return self.session

    def save_session(self, session):
        self.session = session


class Dispatcher:
    async def dispatch(self, name, arguments, tool_call_id, chat_id):
        del name, arguments, tool_call_id, chat_id
        return "读取完成"


def test_agent_reports_real_processing_and_execution_stages():
    session = AgentSession(
        chat_id=1,
        messages=[{"role": "system", "content": "system"}],
    )
    llm = SequenceLLM()
    agent = object.__new__(Agent)
    agent.llm = llm
    agent.llm_manager = None
    agent.config = SimpleNamespace(
        max_history_tokens=16000,
        max_rounds_per_turn=10,
    )
    agent.tools = []
    agent.session_manager = SessionManager(session)
    agent.tool_dispatcher = Dispatcher()
    stages = []

    result = asyncio.run(
        agent.handle_message(
            1,
            "读取文件",
            progress_callback=stages.append,
        )
    )

    assert result.content == "处理完成"
    assert stages == ["processing", "executing", "processing"]
