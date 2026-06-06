"""Tests for Telegram message formatters."""
from datetime import UTC, datetime

from app.models import SecurityEvent
from app.notifier.formatters import format_event, format_paloalto, format_trellix


def _trellix_event(**kwargs) -> SecurityEvent:
    defaults = dict(
        vendor="Trellix",
        source="Trellix EDR",
        alert_id="t-001",
        severity="high",
        title="Suspicious powershell",
        host="WORKSTATION-ABCD",
        username="jdoe",
        process_name="powershell.exe",
        command_line="powershell.exe -EncodedCommand abc123",
        tactic="Execution",
        technique="T1059.001",
        status="New",
        detection_time=datetime(2024, 6, 1, 12, 0, 0, tzinfo=UTC),
    )
    defaults.update(kwargs)
    return SecurityEvent(**defaults)


def _paloalto_event(**kwargs) -> SecurityEvent:
    defaults = dict(
        vendor="PaloAlto",
        source="PAN-OS threat",
        alert_id="pa-001",
        severity="critical",
        title="CVE-2021-44228 RCE",
        threat_name="CVE-2021-44228",
        threat_type="vulnerability",
        source_ip="10.0.0.1",
        destination_ip="203.0.113.1",
        destination_port=443,
        application="ssl",
        action="block",
        rule="block-vuln",
        detection_time=datetime(2024, 6, 1, 12, 0, 0, tzinfo=UTC),
    )
    defaults.update(kwargs)
    return SecurityEvent(**defaults)


def test_trellix_format_contains_key_fields():
    text = format_trellix(_trellix_event())
    assert "Trellix EDR Alert" in text
    assert "HIGH" in text
    assert "WORKSTATION-ABCD" in text
    assert "jdoe" in text
    assert "powershell.exe" in text
    assert "T1059.001" in text
    assert "2024-06-01" in text


def test_paloalto_format_contains_key_fields():
    text = format_paloalto(_paloalto_event())
    assert "Palo Alto Threat Alert" in text
    assert "CRITICAL" in text
    assert "CVE-2021-44228" in text
    assert "10.0.0.1" in text
    assert "203.0.113.1:443" in text
    assert "block" in text
    assert "block-vuln" in text


def test_format_event_dispatches_trellix():
    text = format_event(_trellix_event())
    assert "Trellix" in text


def test_format_event_dispatches_paloalto():
    text = format_event(_paloalto_event())
    assert "Palo Alto" in text


def test_format_event_generic_fallback():
    event = SecurityEvent(
        vendor="Generic",
        source="generic",
        alert_id="g-001",
        severity="medium",
        title="Generic alert",
    )
    text = format_event(event)
    assert "Security Alert" in text
    assert "MEDIUM" in text


def test_missing_optional_fields_no_error():
    # Should not raise even with all optional fields None
    event = _trellix_event(
        host=None, username=None, process_name=None, command_line=None,
        tactic=None, technique=None, status=None, detection_time=None,
    )
    text = format_trellix(event)
    assert "Trellix EDR Alert" in text
