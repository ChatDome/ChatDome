"""
Sentinel suppressor: state-machine based alerting.

Core behavior:
  - Cold start guard (learning rounds)
  - Per-check threat envelope state transitions
  - Fingerprint-aware escalation windows (L1/L2/L3)
  - Quiet/observe degradation (RECOVERED_CANDIDATE -> RECOVERED)
  - Global push rate-limit guard
"""

from __future__ import annotations

import logging
import time
from collections import deque
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class SuppressionResult:
    """Decision result for one state-machine evaluation."""

    suppressed: bool
    reason: str = ""
    state: str = ""
    previous_state: str = ""
    state_changed: bool = False
    event_count: int = 0
    unique_fingerprint_count: int = 0
    fingerprints: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class EscalationLevel:
    """Escalation threshold within a rolling time window."""

    state: str
    window_seconds: int
    event_threshold: int
    unique_fingerprint_threshold: int


@dataclass
class ThreatEvent:
    """Single triggered alert event within one check type."""

    timestamp: float
    fingerprints: frozenset[str] = field(default_factory=frozenset)
    event_count: int = 1


@dataclass
class ThreatEnvelope:
    """Runtime state bucket for one check type."""

    state: str = ""
    state_since: float = 0.0
    last_event_at: float = 0.0
    recovered_candidate_at: float = 0.0
    events: deque[ThreatEvent] = field(default_factory=deque)


class Suppressor:
    """
    Alert suppression engine driven by per-check state machine transitions.

    During debug/testing stage, every state transition is eligible for push,
    then guarded by global rate limiting.
    """

    def __init__(
        self,
        global_rate_limit: int = 10,
        global_rate_window: int = 300,
        learning_rounds: int = 1,
    ) -> None:
        self._global_rate_limit = global_rate_limit
        self._global_rate_window = global_rate_window
        self._learning_rounds = learning_rounds

        # Fixed baseline (documented, non-optional).
        self._levels: tuple[EscalationLevel, ...] = (
            EscalationLevel("ESCALATED_L1", window_seconds=10 * 60, event_threshold=5, unique_fingerprint_threshold=3),
            EscalationLevel("ESCALATED_L2", window_seconds=20 * 60, event_threshold=12, unique_fingerprint_threshold=6),
            EscalationLevel("ESCALATED_L3", window_seconds=30 * 60, event_threshold=25, unique_fingerprint_threshold=10),
        )
        self._quiet_window_seconds = 20 * 60
        self._observe_window_seconds = 15 * 60
        self._max_window_seconds = max(level.window_seconds for level in self._levels)

        # Global rate limiter: sliding window of push timestamps
        self._push_timestamps: deque[float] = deque()
        # Per-check threat envelopes
        self._envelopes: dict[str, ThreatEnvelope] = {}

        # Cold-start: how many full rounds have completed
        self._completed_rounds = 0
        self._learning_mode = learning_rounds > 0

    # -- Cold Start --------------------------------------------------------

    def complete_round(self) -> None:
        """Mark one full check round as completed."""
        self._completed_rounds += 1
        if self._learning_mode and self._completed_rounds >= self._learning_rounds:
            self._learning_mode = False
            logger.info(
                "Sentinel cold-start learning complete (%d rounds)",
                self._completed_rounds,
            )

    @property
    def is_learning(self) -> bool:
        return self._learning_mode

    # -- Main API ----------------------------------------------------------

    def process_event(
        self,
        check_id: str,
        severity: int,
        fingerprints: set[str] | None = None,
        notify_on_repeat: bool = False,
        event_weight: int = 1,
    ) -> SuppressionResult:
        """Process one triggered event and evaluate event-driven transitions."""
        del severity  # kept in signature for compatibility/future policy hooks
        now = time.monotonic()

        if self._learning_mode:
            return SuppressionResult(
                suppressed=True,
                reason=f"cold_start (round {self._completed_rounds + 1}/{self._learning_rounds})",
            )

        envelope = self._envelopes.setdefault(check_id, ThreatEnvelope())
        event_fingerprints = {x.strip() for x in (fingerprints or set()) if x and x.strip()}
        event_count = max(1, int(event_weight or 1))
        self._append_event(envelope, now, event_fingerprints, event_count)
        envelope.last_event_at = now

        previous_state = envelope.state
        next_state = self._next_state_on_event(envelope, now)
        state_changed = next_state != previous_state
        if state_changed:
            envelope.state = next_state
            envelope.state_since = now
            if next_state != "RECOVERED_CANDIDATE":
                envelope.recovered_candidate_at = 0.0

        event_count, unique_fingerprint_count = self._window_metrics(envelope, window_seconds=self._max_window_seconds, now=now)
        if not state_changed:
            if notify_on_repeat:
                return self._allow_or_rate_limit(
                    state=envelope.state,
                    previous_state=previous_state,
                    reason="repeat_event",
                    event_count=event_count,
                    unique_fingerprint_count=unique_fingerprint_count,
                    fingerprints=sorted(event_fingerprints),
                    now=now,
                    state_changed=False,
                )
            return SuppressionResult(
                suppressed=True,
                reason="no_state_change",
                state=envelope.state,
                previous_state=previous_state,
                state_changed=False,
                event_count=event_count,
                unique_fingerprint_count=unique_fingerprint_count,
                fingerprints=sorted(event_fingerprints),
            )

        return self._allow_or_rate_limit(
            state=envelope.state,
            previous_state=previous_state,
            reason=f"state_transition ({previous_state or 'NONE'} -> {envelope.state})",
            event_count=event_count,
            unique_fingerprint_count=unique_fingerprint_count,
            fingerprints=sorted(event_fingerprints),
            now=now,
        )

    def observe_quiet(self, check_id: str, severity: int) -> SuppressionResult:
        """Evaluate time-driven transitions without a new event."""
        del severity  # kept for future policy hooks
        now = time.monotonic()
        if self._learning_mode:
            return SuppressionResult(
                suppressed=True,
                reason=f"cold_start (round {self._completed_rounds + 1}/{self._learning_rounds})",
            )

        envelope = self._envelopes.get(check_id)
        if envelope is None or not envelope.state:
            return SuppressionResult(suppressed=True, reason="no_active_envelope")

        self._prune_events(envelope, now)
        previous_state = envelope.state
        next_state = previous_state

        if previous_state in {"NEW", "ESCALATED_L1", "ESCALATED_L2", "ESCALATED_L3"}:
            if envelope.last_event_at > 0 and (now - envelope.last_event_at) >= self._quiet_window_seconds:
                next_state = "RECOVERED_CANDIDATE"
                envelope.recovered_candidate_at = now
        elif previous_state == "RECOVERED_CANDIDATE":
            if envelope.recovered_candidate_at > 0 and (now - envelope.recovered_candidate_at) >= self._observe_window_seconds:
                next_state = "RECOVERED"

        if next_state == previous_state:
            return SuppressionResult(
                suppressed=True,
                reason="no_state_change",
                state=previous_state,
                previous_state=previous_state,
                state_changed=False,
            )

        envelope.state = next_state
        envelope.state_since = now
        if next_state == "RECOVERED":
            envelope.events.clear()
            envelope.recovered_candidate_at = 0.0

        event_count, unique_fingerprint_count = self._window_metrics(envelope, window_seconds=self._max_window_seconds, now=now)
        return self._allow_or_rate_limit(
            state=envelope.state,
            previous_state=previous_state,
            reason=f"state_transition ({previous_state} -> {envelope.state})",
            event_count=event_count,
            unique_fingerprint_count=unique_fingerprint_count,
            fingerprints=[],
            now=now,
        )

    # -- Internals ---------------------------------------------------------

    @staticmethod
    def _state_rank(state: str) -> int:
        order = {"NEW": 1, "ESCALATED_L1": 2, "ESCALATED_L2": 3, "ESCALATED_L3": 4}
        return order.get(state, 0)

    def _next_state_on_event(self, envelope: ThreatEnvelope, now: float) -> str:
        """Compute state transition caused by a newly triggered event."""
        state = envelope.state
        if not state or state == "RECOVERED":
            return self._target_escalation_state(envelope, now) or "NEW"

        if state == "RECOVERED_CANDIDATE":
            return "ESCALATED_L1"

        target = self._target_escalation_state(envelope, now)
        if not target:
            return state if state else "NEW"

        # Escalation-only while incident is active.
        return target if self._state_rank(target) > self._state_rank(state) else state

    def _target_escalation_state(self, envelope: ThreatEnvelope, now: float) -> str:
        for level in reversed(self._levels):
            event_count, unique_fingerprint_count = self._window_metrics(
                envelope=envelope,
                window_seconds=level.window_seconds,
                now=now,
            )
            if event_count >= level.event_threshold or unique_fingerprint_count >= level.unique_fingerprint_threshold:
                return level.state
        return ""

    def _window_metrics(self, envelope: ThreatEnvelope, window_seconds: int, now: float) -> tuple[int, int]:
        cutoff = now - window_seconds
        event_count = 0
        fingerprints: set[str] = set()
        for event in envelope.events:
            if event.timestamp < cutoff:
                continue
            event_count += event.event_count
            fingerprints.update(event.fingerprints)
        return event_count, len(fingerprints)

    def _append_event(self, envelope: ThreatEnvelope, now: float, fingerprints: set[str], event_count: int) -> None:
        envelope.events.append(ThreatEvent(
            timestamp=now,
            fingerprints=frozenset(fingerprints),
            event_count=event_count,
        ))
        self._prune_events(envelope, now)

    def _prune_events(self, envelope: ThreatEnvelope, now: float) -> None:
        # Keep enough history for max escalation window + observation period.
        keep_seconds = self._max_window_seconds + self._observe_window_seconds
        cutoff = now - keep_seconds
        while envelope.events and envelope.events[0].timestamp < cutoff:
            envelope.events.popleft()

    def _allow_or_rate_limit(
        self,
        *,
        state: str,
        previous_state: str,
        reason: str,
        event_count: int,
        unique_fingerprint_count: int,
        fingerprints: list[str],
        now: float,
        state_changed: bool = True,
    ) -> SuppressionResult:
        cutoff = now - self._global_rate_window
        while self._push_timestamps and self._push_timestamps[0] < cutoff:
            self._push_timestamps.popleft()

        if len(self._push_timestamps) >= self._global_rate_limit:
            return SuppressionResult(
                suppressed=True,
                reason=f"rate_limit ({self._global_rate_limit}/{self._global_rate_window}s)",
                state=state,
                previous_state=previous_state,
                state_changed=state_changed,
                event_count=event_count,
                unique_fingerprint_count=unique_fingerprint_count,
                fingerprints=fingerprints,
            )

        self._push_timestamps.append(now)
        return SuppressionResult(
            suppressed=False,
            reason=reason,
            state=state,
            previous_state=previous_state,
            state_changed=state_changed,
            event_count=event_count,
            unique_fingerprint_count=unique_fingerprint_count,
            fingerprints=fingerprints,
        )

    def reset(self) -> None:
        """Reset all suppression state (e.g., on config reload)."""
        self._envelopes.clear()
        self._push_timestamps.clear()
        self._completed_rounds = 0
        self._learning_mode = self._learning_rounds > 0
