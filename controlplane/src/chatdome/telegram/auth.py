"""Telegram private-user authentication."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


class Authenticator:
    """User ID allowlist and administrator policy."""

    def __init__(self, allowed_ids: list[int], admin_ids: list[int]):
        self._admins = set(admin_ids)
        self._allowed = set(allowed_ids) | self._admins
        logger.info(
            "Authenticator initialized with %d allowed users and %d administrators",
            len(self._allowed),
            len(self._admins),
        )

    def is_authorized(self, user_id: int) -> bool:
        """Return whether a Telegram user may access ChatDome."""
        authorized = user_id in self._allowed
        if not authorized:
            logger.warning(
                "Unauthorized Telegram access attempt from user_id=%d", user_id,
            )
        return authorized

    def is_admin(self, user_id: int) -> bool:
        """Return whether a Telegram user may perform administrative actions."""
        return user_id in self._admins

    @property
    def allowed_count(self) -> int:
        """Number of allowed chat IDs."""
        return len(self._allowed)
