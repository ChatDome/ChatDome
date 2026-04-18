"""
Sentinel Suppressor — alert anti-flooding with multi-layer protection.

Phase 1 layers:
  - Layer 0: Cold Start Guard (learning period)
  - Layer 1: Push Threshold (severity-based)
  - Layer 2: Cooldown (per-check deduplication)
  - Layer 3: Global Rate Limiter
"""

from __future__ import annotations

import logging
import time
from collections import deque
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class SuppressionResult:
    """Result of suppression check."""

    suppressed: bool
    reason: str = ""


class Suppressor:
    """
    Alert suppression engine.

    Decides whether an alert should be pushed to Telegram or silently recorded.
    """

    def __init__(
        self,
        push_min_severity: int = 7,
        default_cooldown: int = 300,
        global_rate_limit: int = 10,
        global_rate_window: int = 300,
        learning_rounds: int = 1,
    ) -> None:
        self._push_min_severity = push_min_severity
        self._default_cooldown = default_cooldown
        self._global_rate_limit = global_rate_limit
        self._global_rate_window = global_rate_window
        self._learning_rounds = learning_rounds

        # Cooldown state: check_id → last alert timestamp
        self._cooldowns: dict[str, float] = {}
        # Per-check cooldown overrides
        self._cooldown_overrides: dict[str, int] = {}

        # Global rate limiter: sliding window of push timestamps
        self._push_timestamps: deque[float] = deque()

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

    # -- Cooldown Override -------------------------------------------------

    def set_cooldown(self, check_id: str, cooldown: int) -> None:
        """Set a per-check cooldown override."""
        self._cooldown_overrides[check_id] = cooldown

    # -- Main Check --------------------------------------------------------

    def should_push(self, check_id: str, severity: int, cooldown_override: int | None = None) -> SuppressionResult:
        """
        Decide whether an alert should be pushed to Telegram.

        Returns a SuppressionResult with suppressed=True if the alert
        should NOT be pushed (it will still be recorded in history).
        """
        now = time.monotonic()

        # Layer 0: Cold Start Guard
        if self._learning_mode:
            return SuppressionResult(
                suppressed=True,
                reason=f"cold_start (round {self._completed_rounds + 1}/{self._learning_rounds})",
            )

        # Layer 1: Push Threshold
        if severity < self._push_min_severity:
            return SuppressionResult(
                suppressed=True,
                reason=f"below_threshold (severity={severity} < {self._push_min_severity})",
            )

        # Layer 2: Cooldown
        cooldown = cooldown_override or self._cooldown_overrides.get(check_id, self._default_cooldown)
        last_alert = self._cooldowns.get(check_id)
        if last_alert is not None:
            elapsed = now - last_alert
            if elapsed < cooldown:
                remaining = int(cooldown - elapsed)
                return SuppressionResult(
                    suppressed=True,
                    reason=f"cooldown ({remaining}s remaining)",
                )

        # Layer 3: Global Rate Limiter
        # Remove expired timestamps from the window
        cutoff = now - self._global_rate_window
        while self._push_timestamps and self._push_timestamps[0] < cutoff:
            self._push_timestamps.popleft()

        if len(self._push_timestamps) >= self._global_rate_limit:
            return SuppressionResult(
                suppressed=True,
                reason=f"rate_limit ({self._global_rate_limit}/{self._global_rate_window}s)",
            )

        # All layers passed → allow push
        self._cooldowns[check_id] = now
        self._push_timestamps.append(now)
        return SuppressionResult(suppressed=False)

    def reset(self) -> None:
        """Reset all suppression state (e.g., on config reload)."""
        self._cooldowns.clear()
        self._push_timestamps.clear()
        self._completed_rounds = 0
        self._learning_mode = self._learning_rounds > 0
