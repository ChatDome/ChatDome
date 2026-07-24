import asyncio
import json
import logging
from pathlib import Path

from chatdome.agent.session import AgentSession, record_persisted_control_event
from chatdome.slash_commands import (
    CommandContext,
    CommandDef,
    CommandRegistry,
    CommandResult,
    approval_details_command_result,
    bind_command_catalog,
    command_help_result,
    command_catalog,
    toggle_command_echo,
    stop_task_command_result,
)


def test_registry_uses_shared_context_logging_and_event_recording(caplog) -> None:
    events = []

    async def stop_handler(invocation):
        assert invocation.context.source == "cli"
        return CommandResult(
            outcome="task_stopped",
            event_summary="用户中止了任务。",
            visible_to_agent=True,
        )

    registry = CommandRegistry(
        [
            CommandDef(
                "/stop",
                "Stop task",
                "control",
                handler=stop_handler,
            )
        ],
        context_factory=lambda: CommandContext(
            source="cli",
            chat_id=-1,
            actor_id="local",
            event_recorder=events.append,
        ),
    )

    with caplog.at_level(logging.INFO, logger="chatdome.slash_commands"):
        result = asyncio.run(registry.execute("/stop sk-abcdefghijklmnop"))

    assert result.outcome == "task_stopped"
    assert events == [
        {
            "event_id": events[0]["event_id"],
            "event_type": "control_command",
            "request_id": events[0]["request_id"],
            "phase": "final",
            "source": "cli",
            "actor_id": "local",
            "command": "/stop",
            "action": "",
            "interaction_id": "",
            "argument_count": 1,
            "outcome": "task_stopped",
            "display_text": "用户中止了任务。",
            "visible_to_agent": True,
            "refs": {},
        }
    ]
    assert "Control command received" in caplog.text
    assert "Control command lifecycle" in caplog.text
    assert "sk-abcdefghijklmnop" not in caplog.text
    assert "sk-abcdefghijklmnop" not in json.dumps(events, ensure_ascii=False)


def test_registry_records_failed_command_before_reraising() -> None:
    events = []

    async def failing_handler(_invocation):
        raise RuntimeError("failure")

    registry = CommandRegistry(
        [CommandDef("/fail", "Fail", "test", handler=failing_handler)],
        context_factory=lambda: CommandContext(
            source="telegram",
            chat_id=123,
            actor_id="456",
            event_recorder=events.append,
        ),
    )

    try:
        asyncio.run(registry.execute("/fail"))
    except RuntimeError as exc:
        assert str(exc) == "failure"
    else:
        raise AssertionError("command failure was not reraised")

    assert len(events) == 1
    assert events[0]["outcome"] == "failed"
    assert events[0]["command"] == "/fail"


def test_control_event_uses_existing_session_snapshot(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("CHATDOME_DATA_DIR", str(tmp_path))
    event = {
        "event_id": "evt-1",
        "event_type": "control_command",
        "source": "cli",
        "actor_id": "local",
        "command": "/stop",
        "outcome": "task_stopped",
        "display_text": "用户通过 CLI 中止了当前任务，后续步骤未执行。",
        "visible_to_agent": True,
        "refs": {
            "api_key": "sk-abcdefghijklmnop",
            "password": "plain-secret",
        },
    }

    assert record_persisted_control_event(-1, event)

    snapshot_path = Path(tmp_path) / "sessions" / "-1.json"
    payload = json.loads(snapshot_path.read_text(encoding="utf-8"))
    session = AgentSession.from_snapshot(payload["session"])

    assert session.events[-1]["command"] == "/stop"
    assert session.events[-1]["refs"]["api_key"] == "[REDACTED]"
    assert session.events[-1]["refs"]["password"] == "[REDACTED]"
    visible_messages = "\n".join(
        str(message.get("content") or "") for message in session.messages
    )
    assert "[CLI 用户可见事件]" in visible_messages
    assert "后续步骤未执行" in visible_messages


def test_session_clear_removes_prior_control_events() -> None:
    session = AgentSession(chat_id=123)
    session.add_system_message("system")
    session.add_control_event(
        {
            "event_type": "control_command",
            "command": "/help",
            "outcome": "completed",
        }
    )

    session.clear()

    assert session.events == []
    assert session.messages == [{"role": "system", "content": "system"}]


def test_toggle_command_echo_uses_session_manager_and_persists() -> None:
    class SessionManager:
        def __init__(self) -> None:
            self.session = AgentSession(chat_id=123)
            self.saved = []

        def get_or_create(self, chat_id):
            assert chat_id == 123
            return self.session

        def save_session(self, session):
            self.saved.append(session)

    class Agent:
        def __init__(self) -> None:
            self.session_manager = SessionManager()

    agent = Agent()

    assert toggle_command_echo(agent, 123) is True
    assert agent.session_manager.saved == [agent.session_manager.session]
    assert toggle_command_echo(agent, 123) is False
    assert agent.session_manager.saved == [
        agent.session_manager.session,
        agent.session_manager.session,
    ]


def test_cli_and_telegram_share_one_command_catalog() -> None:
    cli_commands = command_catalog("cli")
    telegram_commands = command_catalog("telegram")
    cli_names = {command.name for command in cli_commands}
    telegram_names = {command.name for command in telegram_commands}

    assert "/retry" not in cli_names
    assert cli_names == telegram_names
    assert "/exit" not in cli_names
    assert "/retry" not in telegram_names

    cli_aliases = {
        alias
        for command in cli_commands
        for alias in command.aliases
    }
    assert "/start" in cli_aliases
    assert "/llm_add" in cli_aliases
    assert "/quit" not in cli_aliases

    cli_help = command_help_result("cli")
    telegram_help = command_help_result("telegram")
    assert cli_help.text == telegram_help.text
    assert cli_help.facts == telegram_help.facts
    assert all(item.name != "/exit" for item in cli_help.facts.commands)


def test_platform_catalogs_bind_to_one_shared_handler() -> None:
    calls = []

    async def shared_handler(invocation):
        calls.append(invocation.command.name)
        return CommandResult(outcome="help_shown")

    registries = []
    for platform in ("cli", "telegram"):
        registry = CommandRegistry()
        bind_command_catalog(registry, platform, shared_handler)
        registries.append(registry)
        assert all(command.handler is shared_handler for command in registry.commands)

    for registry in registries:
        result = asyncio.run(registry.execute("/help"))
        assert result.outcome == "help_shown"
    assert calls == ["/help", "/help"]


def test_stop_result_combines_live_cancellation_and_pending_abort() -> None:
    calls = []

    async def cancel_live_task():
        calls.append("live")
        return True

    async def abort_pending_task():
        calls.append("pending")
        return True

    result = asyncio.run(
        stop_task_command_result(cancel_live_task, abort_pending_task)
    )

    assert calls == ["live", "pending"]
    assert result.outcome == "task_stopped"
    assert result.facts.changed


def test_stop_result_keeps_legacy_single_callback_contract() -> None:
    result = asyncio.run(stop_task_command_result(lambda: True))

    assert result.outcome == "task_stopped"
    assert result.facts.changed


def test_approval_details_command_preserves_degraded_outcome() -> None:
    class DetailAgent:
        def __init__(self, detail_status):
            self.detail_status = detail_status

        async def get_pending_approval_details(
            self,
            chat_id,
            approval_id=None,
            include_llm=True,
        ):
            del chat_id, approval_id, include_llm
            return {
                "ok": True,
                "approval_id": "AP-1",
                "command": "echo ok",
                "reason": "检查命令",
                "analysis": {
                    "detail_status": self.detail_status,
                    "reviewer_mode": (
                        "llm_partial"
                        if self.detail_status == "partial"
                        else "llm_error"
                    ),
                    "command_count": 1,
                    "analyzed_command_count": (
                        1 if self.detail_status == "partial" else 0
                    ),
                    "impact_analysis": "请核对原始命令。",
                    "command_breakdown": {"commands": []},
                },
            }

    context = CommandContext(source="telegram", chat_id=123)
    expected = {
        "partial": ("details_partial", "approval_details_partial"),
        "failed": ("details_unavailable", "approval_details_unavailable"),
    }
    for detail_status, (outcome, state) in expected.items():
        result = asyncio.run(
            approval_details_command_result(
                DetailAgent(detail_status),
                context,
                ("AP-1",),
            )
        )

        assert result.outcome == outcome
        assert result.state == state
        assert result.outbound.outcome == outcome
