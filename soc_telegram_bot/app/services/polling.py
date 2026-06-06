"""Background polling service — orchestrates collectors, dedup, and notifications."""
from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Coroutine
from datetime import UTC, datetime

from app.collectors.base import BaseCollector
from app.config import Settings
from app.models import SecurityEvent
from app.services.dedupe import filter_new_events, mark_event_notified, mark_event_stored
from app.severity import Severity

logger = logging.getLogger(__name__)

# Callable that accepts a SecurityEvent and sends a Telegram notification
NotifyFn = Callable[[SecurityEvent], Coroutine]


class PollingService:
    def __init__(
        self,
        settings: Settings,
        collectors: list[BaseCollector],
        notify_fn: NotifyFn,
        session_factory,
    ) -> None:
        self._settings = settings
        self._collectors = collectors
        self._notify_fn = notify_fn
        self._session_factory = session_factory
        self._paused = False
        self._running = False
        self._task: asyncio.Task | None = None
        self._threshold = Severity.from_str(settings.min_severity)
        # Simple rate-limit state
        self._sent_this_minute = 0
        self._minute_start = datetime.now(UTC)

    @property
    def paused(self) -> bool:
        return self._paused

    def pause(self) -> None:
        self._paused = True
        logger.info("Polling paused")

    def resume(self) -> None:
        self._paused = False
        logger.info("Polling resumed")

    def set_threshold(self, severity_str: str) -> bool:
        try:
            self._threshold = Severity.from_str(severity_str)
            self._settings.__dict__["min_severity"] = severity_str.lower()
            logger.info("Severity threshold updated to %s", self._threshold.label())
            return True
        except Exception:
            return False

    def start(self) -> None:
        if not self._running:
            self._running = True
            self._task = asyncio.create_task(self._loop(), name="polling_loop")
            logger.info("Polling loop started (interval=%ds)", self._settings.poll_interval_seconds)

    def stop(self) -> None:
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
        logger.info("Polling loop stopped")

    async def _loop(self) -> None:
        while self._running:
            try:
                await self._tick()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.exception("Unhandled error in polling loop: %s", exc)
            await asyncio.sleep(self._settings.poll_interval_seconds)

    async def _tick(self) -> None:
        if self._paused:
            logger.debug("Polling paused — skipping tick")
            return
        for collector in self._collectors:
            try:
                events = await collector.poll()
                await self._process_events(events)
            except Exception as exc:
                logger.error("Collector %s error during tick: %s", collector.name, exc)

    def _rate_ok(self) -> bool:
        now = datetime.now(UTC)
        elapsed = (now - self._minute_start).total_seconds()
        if elapsed >= 60:
            self._minute_start = now
            self._sent_this_minute = 0
        return self._sent_this_minute < self._settings.max_alerts_per_minute

    async def _process_events(self, events: list[SecurityEvent]) -> None:
        if not events:
            return
        # Filter by severity threshold before touching DB
        qualifying = [
            e for e in events
            if Severity.from_str(e.severity).meets_threshold(self._threshold)
        ]
        if not qualifying:
            return

        async with self._session_factory() as session:
            try:
                new_events = await filter_new_events(session, qualifying)
                for event in new_events:
                    orm = await mark_event_stored(session, event)
                    await session.commit()
                    if not self._rate_ok():
                        logger.warning(
                            "Rate limit reached (%d/min) — dropping event %s",
                            self._settings.max_alerts_per_minute,
                            event.alert_id,
                        )
                        continue
                    try:
                        await self._notify_fn(event)
                        self._sent_this_minute += 1
                        await mark_event_notified(session, orm.id)
                        await session.commit()
                    except Exception as exc:
                        logger.error("Failed to notify event %s: %s", event.alert_id, exc)
            except Exception as exc:
                logger.error("DB error during event processing: %s", exc)
                await session.rollback()
