import unittest
from unittest.mock import patch

from chatdome.sentinel.suppressor import Suppressor


class SuppressorStateMachineTests(unittest.TestCase):
    def _call_at(self, timestamp: float, func, *args, **kwargs):
        with patch("chatdome.sentinel.suppressor.time.monotonic", return_value=timestamp):
            return func(*args, **kwargs)

    def test_first_event_enters_new(self):
        suppressor = Suppressor(global_rate_limit=100, global_rate_window=300, learning_rounds=0)

        result = self._call_at(
            10.0,
            suppressor.process_event,
            "ssh_bruteforce",
            8,
            {"1.1.1.1|22|unknown|failed"},
        )

        self.assertFalse(result.suppressed)
        self.assertTrue(result.state_changed)
        self.assertEqual(result.state, "NEW")
        self.assertEqual(result.previous_state, "")

    def test_escalates_to_l1_within_window(self):
        suppressor = Suppressor(global_rate_limit=100, global_rate_window=300, learning_rounds=0)

        # 5 events in 10 minutes should trigger L1.
        for ts in [0, 30, 60, 90]:
            self._call_at(ts, suppressor.process_event, "ssh_bruteforce", 8, {"1.1.1.1|22|unknown|failed"})

        l1 = self._call_at(
            120,
            suppressor.process_event,
            "ssh_bruteforce",
            8,
            {"1.1.1.1|22|unknown|failed"},
        )

        self.assertEqual(l1.state, "ESCALATED_L1")
        self.assertTrue(l1.state_changed)
        self.assertFalse(l1.suppressed)

    def test_weighted_batch_event_can_escalate_to_l1_immediately(self):
        suppressor = Suppressor(global_rate_limit=100, global_rate_window=300, learning_rounds=0)

        l1 = self._call_at(
            10.0,
            suppressor.process_event,
            "ssh_success_login",
            9,
            {"203.0.113.10|root|22"},
            event_weight=5,
        )

        self.assertEqual(l1.state, "ESCALATED_L1")
        self.assertTrue(l1.state_changed)
        self.assertFalse(l1.suppressed)
        self.assertEqual(l1.event_count, 5)

    def test_weighted_repeat_contributes_to_escalation_window(self):
        suppressor = Suppressor(global_rate_limit=100, global_rate_window=300, learning_rounds=0)

        self._call_at(
            10.0,
            suppressor.process_event,
            "ssh_success_login",
            9,
            {"203.0.113.10|root|22"},
        )
        l1 = self._call_at(
            70.0,
            suppressor.process_event,
            "ssh_success_login",
            9,
            {"203.0.113.10|root|22"},
            notify_on_repeat=True,
            event_weight=4,
        )

        self.assertEqual(l1.previous_state, "NEW")
        self.assertEqual(l1.state, "ESCALATED_L1")
        self.assertTrue(l1.state_changed)
        self.assertFalse(l1.suppressed)
        self.assertEqual(l1.event_count, 5)

    def test_recovered_candidate_rebounds_to_l1_on_new_event(self):
        suppressor = Suppressor(global_rate_limit=100, global_rate_window=300, learning_rounds=0)

        for ts in [0, 30, 60, 90, 120]:
            self._call_at(ts, suppressor.process_event, "ssh_bruteforce", 8, {"1.1.1.1|22|unknown|failed"})

        recovered_candidate = self._call_at(
            120 + 20 * 60 + 1,
            suppressor.observe_quiet,
            "ssh_bruteforce",
            8,
        )
        self.assertEqual(recovered_candidate.state, "RECOVERED_CANDIDATE")
        self.assertTrue(recovered_candidate.state_changed)

        rebound = self._call_at(
            120 + 20 * 60 + 2,
            suppressor.process_event,
            "ssh_bruteforce",
            8,
            {"2.2.2.2|22|unknown|failed"},
        )
        self.assertEqual(rebound.previous_state, "RECOVERED_CANDIDATE")
        self.assertEqual(rebound.state, "ESCALATED_L1")
        self.assertTrue(rebound.state_changed)
        self.assertFalse(rebound.suppressed)

    def test_recovered_candidate_goes_to_recovered_after_observe_window(self):
        suppressor = Suppressor(global_rate_limit=100, global_rate_window=300, learning_rounds=0)

        for ts in [0, 30, 60, 90, 120]:
            self._call_at(ts, suppressor.process_event, "ssh_bruteforce", 8, {"1.1.1.1|22|unknown|failed"})

        self._call_at(120 + 20 * 60 + 1, suppressor.observe_quiet, "ssh_bruteforce", 8)
        recovered = self._call_at(
            120 + 20 * 60 + 1 + 15 * 60 + 1,
            suppressor.observe_quiet,
            "ssh_bruteforce",
            8,
        )

        self.assertEqual(recovered.previous_state, "RECOVERED_CANDIDATE")
        self.assertEqual(recovered.state, "RECOVERED")
        self.assertTrue(recovered.state_changed)

    def test_notify_on_repeat_pushes_without_state_change(self):
        suppressor = Suppressor(global_rate_limit=100, global_rate_window=300, learning_rounds=0)

        first = self._call_at(
            10.0,
            suppressor.process_event,
            "ssh_success_login",
            9,
            {"203.0.113.10|root|22"},
        )
        repeat = self._call_at(
            70.0,
            suppressor.process_event,
            "ssh_success_login",
            9,
            {"203.0.113.10|root|22"},
            notify_on_repeat=True,
        )

        self.assertFalse(first.suppressed)
        self.assertEqual(first.state, "NEW")
        self.assertFalse(repeat.suppressed)
        self.assertEqual(repeat.reason, "repeat_event")
        self.assertEqual(repeat.state, "NEW")
        self.assertFalse(repeat.state_changed)

    def test_notify_on_repeat_still_respects_global_rate_limit(self):
        suppressor = Suppressor(global_rate_limit=1, global_rate_window=300, learning_rounds=0)

        self._call_at(
            10.0,
            suppressor.process_event,
            "ssh_success_login",
            9,
            {"203.0.113.10|root|22"},
        )
        repeat = self._call_at(
            70.0,
            suppressor.process_event,
            "ssh_success_login",
            9,
            {"203.0.113.10|root|22"},
            notify_on_repeat=True,
        )

        self.assertTrue(repeat.suppressed)
        self.assertIn("rate_limit", repeat.reason)


if __name__ == "__main__":
    unittest.main()
