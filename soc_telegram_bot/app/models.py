"""SQLAlchemy ORM models and Pydantic schemas."""
from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, computed_field
from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# ── SQLAlchemy base ────────────────────────────────────────────────────────────

class Base(DeclarativeBase):
    pass


class SecurityEventORM(Base):
    __tablename__ = "security_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    vendor: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(128), nullable=False)
    alert_id: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    dedup_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    severity: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    raw_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    notified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    notified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    detection_time: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class BotStateORM(Base):
    __tablename__ = "bot_state"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
    )


# ── Pydantic schemas ───────────────────────────────────────────────────────────

class SecurityEvent(BaseModel):
    """Normalized security event from any vendor."""

    vendor: str
    source: str
    alert_id: str
    severity: str
    title: str
    detection_time: datetime | None = None

    # Trellix-specific optional fields
    host: str | None = None
    username: str | None = None
    process_name: str | None = None
    command_line: str | None = None
    tactic: str | None = None
    technique: str | None = None
    status: str | None = None

    # Palo Alto-specific optional fields
    threat_name: str | None = None
    threat_type: str | None = None
    source_ip: str | None = None
    source_user: str | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    application: str | None = None
    action: str | None = None
    rule: str | None = None
    url_or_domain: str | None = None

    raw_json: dict[str, Any] | None = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def dedup_hash(self) -> str:
        key = f"{self.vendor}:{self.alert_id}"
        return hashlib.sha256(key.encode()).hexdigest()

    def to_orm(self) -> SecurityEventORM:
        raw = json.dumps(self.raw_json, default=str) if self.raw_json else None
        return SecurityEventORM(
            vendor=self.vendor,
            source=self.source,
            alert_id=self.alert_id,
            dedup_hash=self.dedup_hash,
            severity=self.severity,
            title=self.title,
            raw_json=raw,
            detection_time=self.detection_time,
        )
