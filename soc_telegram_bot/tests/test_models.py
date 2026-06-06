"""Tests for SecurityEvent model and dedup hash."""
from datetime import UTC, datetime

from app.models import SecurityEvent


def _make_event(**kwargs) -> SecurityEvent:
    defaults = dict(
        vendor="Trellix",
        source="Trellix EDR",
        alert_id="alert-001",
        severity="high",
        title="Suspicious process",
    )
    defaults.update(kwargs)
    return SecurityEvent(**defaults)


def test_dedup_hash_deterministic():
    e1 = _make_event(alert_id="abc-123")
    e2 = _make_event(alert_id="abc-123")
    assert e1.dedup_hash == e2.dedup_hash


def test_dedup_hash_vendor_scoped():
    e1 = _make_event(vendor="Trellix", alert_id="same-id")
    e2 = _make_event(vendor="PaloAlto", alert_id="same-id")
    assert e1.dedup_hash != e2.dedup_hash


def test_to_orm_fields():
    dt = datetime(2024, 6, 1, 12, 0, 0, tzinfo=UTC)
    event = _make_event(
        detection_time=dt,
        host="SERVER01",
        raw_json={"key": "value"},
    )
    orm = event.to_orm()
    assert orm.vendor == "Trellix"
    assert orm.alert_id == "alert-001"
    assert orm.severity == "high"
    assert orm.detection_time == dt
    assert '"key": "value"' in (orm.raw_json or "")


def test_optional_fields_default_none():
    event = _make_event()
    assert event.host is None
    assert event.username is None
    assert event.source_ip is None


def test_paloalto_event():
    event = SecurityEvent(
        vendor="PaloAlto",
        source="PAN-OS threat",
        alert_id="pa-001",
        severity="critical",
        title="CVE-2021-44228 Log4j RCE",
        threat_name="CVE-2021-44228",
        threat_type="vulnerability",
        source_ip="10.0.0.1",
        destination_ip="203.0.113.1",
        destination_port=443,
        action="block",
        rule="block-vuln",
    )
    assert event.vendor == "PaloAlto"
    assert event.destination_port == 443
    assert event.dedup_hash  # non-empty hash
