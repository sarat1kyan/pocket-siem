"""FastAPI admin / health endpoints.

All /admin/* routes require Authorization: Bearer <ADMIN_API_KEY>.
/health and /ready are public.
"""
from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from sqlalchemy import desc, func, select

from app.config import Settings, get_settings
from app.models import SecurityEventORM

logger = logging.getLogger(__name__)
router = APIRouter()
bearer = HTTPBearer(auto_error=True)


def require_admin(
    credentials: HTTPAuthorizationCredentials = Security(bearer),
    settings: Settings = Depends(get_settings),
) -> None:
    if credentials.credentials != settings.admin_api_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid admin API key",
        )


# ── Public endpoints ──────────────────────────────────────────────────────────

@router.get("/health", tags=["public"])
async def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "timestamp": datetime.now(UTC).isoformat(),
    }


@router.get("/ready", tags=["public"])
async def ready() -> dict[str, Any]:
    return {"ready": True}


# ── Admin endpoints ───────────────────────────────────────────────────────────

@router.get("/admin/status", tags=["admin"], dependencies=[Depends(require_admin)])
async def admin_status(
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    return {
        "mock_mode": settings.mock_mode,
        "environment": settings.environment,
        "trellix_enabled": settings.enable_trellix,
        "paloalto_enabled": settings.enable_paloalto,
        "min_severity": settings.min_severity,
        "poll_interval_seconds": settings.poll_interval_seconds,
    }


class EventOut(BaseModel):
    id: int
    vendor: str
    source: str
    alert_id: str
    severity: str
    title: str
    notified: bool
    received_at: datetime
    detection_time: datetime | None

    model_config = {"from_attributes": True}


@router.get(
    "/admin/events",
    response_model=list[EventOut],
    tags=["admin"],
    dependencies=[Depends(require_admin)],
)
async def admin_events(
    vendor: str | None = Query(None),
    severity: str | None = Query(None),
    limit: int = Query(50, le=500),
    offset: int = Query(0),
) -> list[EventOut]:
    from app.config import get_settings
    from app.db import get_session_factory

    settings = get_settings()
    factory = get_session_factory(settings.database_url)
    async with factory() as session:
        stmt = (
            select(SecurityEventORM)
            .order_by(desc(SecurityEventORM.received_at))
            .limit(limit)
            .offset(offset)
        )
        if vendor:
            stmt = stmt.where(SecurityEventORM.vendor == vendor)
        if severity:
            stmt = stmt.where(SecurityEventORM.severity == severity.lower())
        result = await session.execute(stmt)
        rows = result.scalars().all()
    return [EventOut.model_validate(r) for r in rows]


@router.get(
    "/admin/stats",
    tags=["admin"],
    dependencies=[Depends(require_admin)],
)
async def admin_stats() -> dict[str, Any]:
    from app.config import get_settings
    from app.db import get_session_factory

    settings = get_settings()
    factory = get_session_factory(settings.database_url)
    async with factory() as session:
        total = (await session.execute(func.count(SecurityEventORM.id))).scalar() or 0
        notified = (
            await session.execute(
                func.count(SecurityEventORM.id).filter(SecurityEventORM.notified == True)  # noqa: E712
            )
        ).scalar() or 0
        by_severity_rows = (
            await session.execute(
                select(SecurityEventORM.severity, func.count(SecurityEventORM.id)).group_by(
                    SecurityEventORM.severity
                )
            )
        ).fetchall()
        by_vendor_rows = (
            await session.execute(
                select(SecurityEventORM.vendor, func.count(SecurityEventORM.id)).group_by(
                    SecurityEventORM.vendor
                )
            )
        ).fetchall()
    return {
        "total_events": total,
        "notified_events": notified,
        "by_severity": {r[0]: r[1] for r in by_severity_rows},
        "by_vendor": {r[0]: r[1] for r in by_vendor_rows},
    }


@router.post(
    "/admin/pause",
    tags=["admin"],
    dependencies=[Depends(require_admin)],
)
async def admin_pause() -> dict[str, str]:
    from app.main import get_polling_service

    svc = get_polling_service()
    if svc:
        svc.pause()
    return {"status": "paused"}


@router.post(
    "/admin/resume",
    tags=["admin"],
    dependencies=[Depends(require_admin)],
)
async def admin_resume() -> dict[str, str]:
    from app.main import get_polling_service

    svc = get_polling_service()
    if svc:
        svc.resume()
    return {"status": "resumed"}


@router.post(
    "/admin/set_severity",
    tags=["admin"],
    dependencies=[Depends(require_admin)],
)
async def admin_set_severity(severity: str = Query(...)) -> dict[str, str]:
    from app.main import get_polling_service

    valid = {"low", "medium", "high", "critical"}
    if severity.lower() not in valid:
        raise HTTPException(400, f"severity must be one of {valid}")
    svc = get_polling_service()
    if svc:
        svc.set_threshold(severity)
    return {"severity": severity.lower()}
