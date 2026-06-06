"""Tests for the deduplication service using an in-memory SQLite DB."""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.models import Base, SecurityEvent, SecurityEventORM
from app.services.dedupe import filter_new_events, mark_event_notified, mark_event_stored


@pytest.fixture
async def db_session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", connect_args={"check_same_thread": False})
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with factory() as session:
        yield session
    await engine.dispose()


def _event(alert_id: str, vendor: str = "Trellix") -> SecurityEvent:
    return SecurityEvent(
        vendor=vendor,
        source="test",
        alert_id=alert_id,
        severity="high",
        title=f"Test alert {alert_id}",
    )


@pytest.mark.asyncio
async def test_filter_new_events_all_new(db_session):
    events = [_event("a-1"), _event("a-2"), _event("a-3")]
    result = await filter_new_events(db_session, events)
    assert len(result) == 3


@pytest.mark.asyncio
async def test_filter_new_events_deduplicates(db_session):
    e = _event("dup-1")
    await mark_event_stored(db_session, e)
    await db_session.commit()

    result = await filter_new_events(db_session, [e, _event("new-1")])
    assert len(result) == 1
    assert result[0].alert_id == "new-1"


@pytest.mark.asyncio
async def test_mark_event_stored_persists(db_session):
    e = _event("store-1")
    orm = await mark_event_stored(db_session, e)
    await db_session.commit()
    assert orm.id is not None
    assert orm.notified is False


@pytest.mark.asyncio
async def test_mark_event_notified(db_session):
    e = _event("notify-1")
    orm = await mark_event_stored(db_session, e)
    await db_session.commit()

    await mark_event_notified(db_session, orm.id)
    await db_session.commit()

    from sqlalchemy import select
    result = await db_session.execute(
        select(SecurityEventORM).where(SecurityEventORM.id == orm.id)
    )
    row = result.scalar_one()
    assert row.notified is True
    assert row.notified_at is not None


@pytest.mark.asyncio
async def test_vendor_scoped_dedup(db_session):
    # Same alert_id, different vendors = different hashes = both new
    e_trellix = _event("same-id", vendor="Trellix")
    e_paloalto = _event("same-id", vendor="PaloAlto")
    result = await filter_new_events(db_session, [e_trellix, e_paloalto])
    assert len(result) == 2


@pytest.mark.asyncio
async def test_empty_input(db_session):
    result = await filter_new_events(db_session, [])
    assert result == []
