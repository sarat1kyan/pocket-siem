"""Async database setup — SQLite by default, PostgreSQL via DATABASE_URL."""
from __future__ import annotations

import logging
import os
from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.models import Base

logger = logging.getLogger(__name__)

_engine = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def _ensure_data_dir(url: str) -> None:
    """Create the local data directory for SQLite databases if needed."""
    if url.startswith("sqlite"):
        # Extract path from sqlite+aiosqlite:///./data/soc_bot.db
        path = url.split("///", 1)[-1]
        dir_path = os.path.dirname(path)
        if dir_path and dir_path not in (".", ""):
            os.makedirs(dir_path, exist_ok=True)


def get_engine(database_url: str):
    global _engine
    if _engine is None:
        _ensure_data_dir(database_url)
        connect_args = {}
        if "sqlite" in database_url:
            connect_args["check_same_thread"] = False
        _engine = create_async_engine(
            database_url,
            echo=False,
            connect_args=connect_args,
            pool_pre_ping=True,
        )
        logger.info("Database engine created: %s", database_url.split("@")[-1])
    return _engine


def get_session_factory(database_url: str) -> async_sessionmaker[AsyncSession]:
    global _session_factory
    if _session_factory is None:
        engine = get_engine(database_url)
        _session_factory = async_sessionmaker(
            engine, expire_on_commit=False, class_=AsyncSession
        )
    return _session_factory


async def init_db(database_url: str) -> None:
    engine = get_engine(database_url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database schema initialised")


async def get_session(database_url: str) -> AsyncGenerator[AsyncSession, None]:
    factory = get_session_factory(database_url)
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
