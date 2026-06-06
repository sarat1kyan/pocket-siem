"""Tests for access control."""
from unittest.mock import MagicMock

from app.services.access_control import AccessControl


def _update(user_id: int, username: str = "testuser") -> MagicMock:
    update = MagicMock()
    update.effective_user.id = user_id
    update.effective_user.username = username
    return update


def test_allowed_user_passes():
    ac = AccessControl({12345, 67890})
    assert ac.is_allowed(12345) is True
    assert ac.check(_update(12345)) is True


def test_denied_user_blocked():
    ac = AccessControl({12345})
    assert ac.is_allowed(99999) is False
    assert ac.check(_update(99999)) is False


def test_empty_allowlist_blocks_everyone():
    ac = AccessControl(set())
    assert ac.check(_update(12345)) is False


def test_add_user():
    ac = AccessControl({12345})
    ac.add_user(99999)
    assert ac.is_allowed(99999) is True


def test_remove_user():
    ac = AccessControl({12345, 67890})
    ac.remove_user(12345)
    assert ac.is_allowed(12345) is False
    assert ac.is_allowed(67890) is True


def test_list_users():
    ac = AccessControl({1, 2, 3})
    assert ac.list_users() == {1, 2, 3}


def test_no_effective_user():
    ac = AccessControl({12345})
    update = MagicMock()
    update.effective_user = None
    assert ac.check(update) is False
