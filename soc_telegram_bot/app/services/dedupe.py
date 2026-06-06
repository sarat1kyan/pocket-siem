"""Deduplication service — prevents the same alert from being sent twice."""
from __future__ import annotations

import logging
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import SecurityEvent, SecurityEventORM

logger = logging.getLogger(__name__)


async def filter_new_events(
    session: AsyncSession, events: list[SecurityEvent]
) -> list[SecurityEvent]:
    """Return only events not already stored in the database."""
    if not events:
        return []
    hashes = [e.dedup_hash for e in events]
    result = await session.execute(
        select(SecurityEventORM.dedup_hash).where(
            SecurityEventORM.dedup_hash.in_(hashes)
        )
    )
    known = {row[0] for row in result.fetchall()}
    new = [e for e in events if e.dedup_hash not in known]
    logger.debug("Dedup: %d total, %d known, %d new", len(events), len(known), len(new))
    return new


async def mark_event_stored(session: AsyncSession, event: SecurityEvent) -> SecurityEventORM:
    """Persist a new event to the database (not yet notified)."""
    orm = event.to_orm()
    session.add(orm)
    await session.flush()
    return orm


async def mark_event_notified(session: AsyncSession, orm_id: int) -> None:
    """Mark an already-stored event as notified."""
    result = await session.execute(
        select(SecurityEventORM).where(SecurityEventORM.id == orm_id)
    )
    row = result.scalar_one_or_none()
    if row:
        row.notified = True
        row.notified_at = datetime.now(UTC)
