"""Tests for the normalizer module."""
from datetime import UTC, datetime

from app.normalizer import map_panos_severity, parse_datetime, safe_str, truncate


def test_parse_datetime_iso_z():
    dt = parse_datetime("2024-01-15T14:30:00Z")
    assert dt is not None
    assert dt.year == 2024
    assert dt.tzinfo == UTC


def test_parse_datetime_epoch():
    dt = parse_datetime(1705329000)
    assert dt is not None
    assert dt.tzinfo == UTC


def test_parse_datetime_none():
    assert parse_datetime(None) is None
    assert parse_datetime("") is None


def test_parse_datetime_passthrough():
    now = datetime.now(UTC)
    assert parse_datetime(now) == now


def test_safe_str_truncates():
    long_str = "x" * 600
    result = safe_str(long_str, max_len=512)
    assert len(result) == 512


def test_safe_str_none():
    assert safe_str(None) is None


def test_safe_str_empty():
    assert safe_str("") is None


def test_map_panos_severity():
    assert map_panos_severity("critical") == "critical"
    assert map_panos_severity("HIGH") == "high"
    assert map_panos_severity("5") == "critical"
    assert map_panos_severity("3") == "medium"
    assert map_panos_severity("unknown_value") == "unknown"


def test_truncate():
    long_str = "a" * 250
    result = truncate(long_str, 200)
    assert result.endswith("…")
    assert len(result) == 201  # 200 + ellipsis char


def test_truncate_short():
    short = "hello"
    assert truncate(short, 200) == "hello"


def test_truncate_none():
    assert truncate(None) is None
