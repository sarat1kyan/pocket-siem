"""Utility helpers for normalizing raw API data into SecurityEvent objects."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any


def parse_datetime(value: Any) -> datetime | None:
    """Best-effort datetime parser for ISO-8601, epoch, and common log formats."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value
    if isinstance(value, (int, float)):
        # Epoch seconds
        return datetime.fromtimestamp(value, tz=UTC)
    s = str(value).strip()
    if not s:
        return None
    # Try ISO-8601 variants
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y/%m/%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
    ):
        try:
            dt = datetime.strptime(s, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            return dt
        except ValueError:
            continue
    return None


def safe_str(value: Any, max_len: int = 512) -> str | None:
    if value is None:
        return None
    s = str(value).strip()
    return s[:max_len] if s else None


def map_panos_severity(value: Any) -> str:
    """Map PAN-OS severity strings/numbers to normalized labels."""
    mapping = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "informational": "informational",
        "info": "informational",
        "5": "critical",
        "4": "high",
        "3": "medium",
        "2": "low",
        "1": "informational",
    }
    return mapping.get(str(value).lower().strip(), "unknown")


def truncate(value: str | None, length: int = 200) -> str | None:
    if not value:
        return value
    return value[:length] + "…" if len(value) > length else value
