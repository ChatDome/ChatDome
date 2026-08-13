import asyncio
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from chatdome.agent.global_turn import GlobalTurnCoordinator
from chatdome.agent.core import Agent
from chatdome.agent.session import AgentSession


class GlobalTurnCoordinatorTests(unittest.TestCase):
    def test_independent_coordinators_contend_and_release(self):
        with TemporaryDirectory() as temp_dir:
            lock_path = Path(temp_dir) / "turn.lock"
            first = GlobalTurnCoordinator(lock_path)
            second = GlobalTurnCoordinator(lock_path)

            lease = first.try_acquire("telegram", 123, 456)

            self.assertIsNotNone(lease)
            self.assertIsNone(second.try_acquire("cli", -1, None))
            lease.update(turn_id=7, state="waiting_approval")
            owner = second.read_owner()
            self.assertEqual(owner["source"], "telegram")
            self.assertEqual(owner["chat_id"], 123)
            self.assertEqual(owner["user_id"], 456)
            self.assertEqual(owner["turn_id"], 7)
            self.assertEqual(owner["state"], "waiting_approval")
            self.assertNotIn("message", json.dumps(owner))

            lease.release()

            replacement = second.try_acquire("cli", -1, None)
            self.assertIsNotNone(replacement)
            replacement.release()

    def test_release_is_idempotent(self):
        with TemporaryDirectory() as temp_dir:
            coordinator = GlobalTurnCoordinator(Path(temp_dir) / "turn.lock")
            lease = coordinator.try_acquire("cli", -1, None)
            self.assertIsNotNone(lease)

            lease.release()
            lease.release()

            self.assertEqual(coordinator.read_owner(), {})

    def test_agent_keeps_lease_until_turn_is_terminal(self):
        with TemporaryDirectory() as temp_dir:
            lock_path = Path(temp_dir) / "turn.lock"
            first = object.__new__(Agent)
            first.global_turn_coordinator = GlobalTurnCoordinator(lock_path)
            first._global_turn_lease = None
            first._global_turn_chat_id = None
            first._global_turn_release_pending_chat_id = None
            first.session_manager = SimpleNamespace(save_session=lambda session: None)
            second = object.__new__(Agent)
            second.global_turn_coordinator = GlobalTurnCoordinator(lock_path)
            second._global_turn_lease = None
            second._global_turn_chat_id = None
            second._global_turn_release_pending_chat_id = None
            first_session = AgentSession(chat_id=1)
            first_session.begin_turn("restart nginx", user_id=10)
            first_session.transition_turn("waiting_approval")
            second_session = AgentSession(chat_id=2)

            self.assertTrue(
                first._claim_global_turn(first_session, source="telegram", user_id=10)
            )
            first._update_global_turn_lease(first_session)
            self.assertFalse(
                second._claim_global_turn(second_session, source="cli", user_id=None)
            )

            first._finish_turn(first_session, "cancelled")
            first._persist_session(first_session)

            self.assertTrue(
                second._claim_global_turn(second_session, source="cli", user_id=None)
            )
            second._release_global_turn_lease()

    def test_busy_message_does_not_load_or_create_session(self):
        with TemporaryDirectory() as temp_dir:
            lock_path = Path(temp_dir) / "turn.lock"
            owner = GlobalTurnCoordinator(lock_path).try_acquire("telegram", 1, 10)
            manager = SimpleNamespace(
                get_or_create=lambda _chat_id: self.fail("session was mutated"),
            )
            agent = object.__new__(Agent)
            agent.global_turn_coordinator = GlobalTurnCoordinator(lock_path)
            agent._global_turn_lease = None
            agent._global_turn_chat_id = None
            agent._global_turn_release_pending_chat_id = None
            agent.session_manager = manager
            try:
                result = asyncio.run(
                    agent.handle_message(2, "second", user_id=20, source="cli")
                )
            finally:
                owner.release()

            self.assertIn("已有任务正在执行", result.content)


if __name__ == "__main__":
    unittest.main()
