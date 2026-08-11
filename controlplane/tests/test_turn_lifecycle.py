from __future__ import annotations

import pytest

from chatdome.agent import session as session_module
from chatdome.agent.session import AgentSession, SessionManager


def test_session_allocates_monotonic_numeric_turn_ids():
    session = AgentSession(chat_id=7)

    first = session.begin_turn("first", user_id=70)
    session.finish_turn("completed")
    second = session.begin_turn("second", user_id=70)

    assert first.turn_id == 1
    assert second.turn_id == 2
    assert session.next_turn_id == 3


def test_session_rejects_second_active_turn_without_allocating_id():
    session = AgentSession(chat_id=7)
    session.begin_turn("first", user_id=70)

    with pytest.raises(RuntimeError, match="active turn already exists"):
        session.begin_turn("second", user_id=70)

    assert session.next_turn_id == 2


def test_snapshot_restores_active_turn_and_deferred_message():
    session = AgentSession(chat_id=7)
    context = session.begin_turn("inspect nginx", user_id=70)
    session.transition_turn("waiting_approval_decision")
    session.defer_user_message("inspect disk")

    restored = AgentSession.from_snapshot(session.to_snapshot())

    assert restored.active_turn is not None
    assert restored.active_turn.turn_id == context.turn_id
    assert restored.active_turn.state == "waiting_approval_decision"
    assert restored.deferred_user_message == "inspect disk"


def test_session_manager_restart_preserves_turn_counter(tmp_path, monkeypatch):
    monkeypatch.setattr(session_module, "data_dir", lambda: tmp_path)
    first_manager = SessionManager(system_prompt="system")
    first_session = first_manager.get_or_create(7)
    first_session.begin_turn("first", user_id=70)
    first_session.finish_turn("completed")
    first_manager.save_session(first_session)

    restored_manager = SessionManager(system_prompt="system")
    restored_session = restored_manager.get_or_create(7)
    second = restored_session.begin_turn("second", user_id=70)

    assert second.turn_id == 2


def test_clear_discards_activity_but_keeps_monotonic_counter():
    session = AgentSession(chat_id=7)
    session.begin_turn("first", user_id=70)
    session.defer_user_message("second")

    session.clear()
    next_context = session.begin_turn("third", user_id=70)

    assert next_context.turn_id == 2
    assert session.deferred_user_message is None
