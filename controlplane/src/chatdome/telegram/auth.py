"""
Telegram Chat ID authentication.

Only messages from whitelisted Chat IDs are processed.
All others are silently dropped with a log warning.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


class Authenticator:
    """Chat ID-based authentication for Telegram messages."""

    def __init__(self, allowed_chat_ids: list[int]):
        self._allowed = set(allowed_chat_ids)
        logger.info(
            "Authenticator initialized with %d allowed chat IDs", len(self._allowed),
        )

    def is_authorized(self, chat_id: int) -> bool:
        """
        Check if a chat ID is authorized.

        Returns True if the chat ID is in the allowlist,
        or if the allowlist is empty (allow all — for testing).
        """
        if not self._allowed:
            # Empty allowlist = allow all (useful for initial setup)
            logger.warning(
                "Allowlist is empty — allowing all chat IDs. "
                "Configure allowed_chat_ids for production use."
            )
            return True

        authorized = chat_id in self._allowed
        if not authorized:
            logger.warning(
                "Unauthorized access attempt from chat_id=%d", chat_id,
            )
        return authorized

    @property
    def allowed_count(self) -> int:
        """Number of allowed chat IDs."""
        return len(self._allowed)
