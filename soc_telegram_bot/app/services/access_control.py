"""Telegram user access control."""
from __future__ import annotations

import logging

from telegram import Update

logger = logging.getLogger(__name__)


class AccessControl:
    def __init__(self, allowed_ids: set[int]) -> None:
        self._allowed: set[int] = allowed_ids

    def is_allowed(self, user_id: int) -> bool:
        return user_id in self._allowed

    def check(self, update: Update) -> bool:
        if update.effective_user is None:
            return False
        uid = update.effective_user.id
        if uid not in self._allowed:
            logger.warning(
                "Denied access attempt from user_id=%d username=%s",
                uid,
                update.effective_user.username,
            )
            return False
        return True

    def add_user(self, user_id: int) -> None:
        self._allowed.add(user_id)
        logger.info("Access granted to user_id=%d", user_id)

    def remove_user(self, user_id: int) -> None:
        self._allowed.discard(user_id)
        logger.info("Access revoked from user_id=%d", user_id)

    def list_users(self) -> set[int]:
        return set(self._allowed)
