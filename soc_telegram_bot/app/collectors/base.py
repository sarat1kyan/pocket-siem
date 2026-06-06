"""Abstract base class for all security data collectors."""
from __future__ import annotations

import abc
import logging
from datetime import UTC, datetime

from app.models import SecurityEvent

logger = logging.getLogger(__name__)


class BaseCollector(abc.ABC):
    """Polls a security data source and returns normalized SecurityEvent objects."""

    name: str = "base"

    def __init__(self) -> None:
        self._last_poll: datetime | None = None

    @abc.abstractmethod
    async def fetch_events(self, since: datetime | None = None) -> list[SecurityEvent]:
        """Return new events since *since* (or all recent events if None)."""
        ...

    @abc.abstractmethod
    async def health_check(self) -> bool:
        """Return True if the upstream API is reachable."""
        ...

    async def poll(self) -> list[SecurityEvent]:
        since = self._last_poll
        logger.debug("%s: polling since %s", self.name, since)
        events = await self.fetch_events(since=since)
        self._last_poll = datetime.now(UTC)
        logger.info("%s: fetched %d events", self.name, len(events))
        return events
