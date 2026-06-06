"""Tests for collector mock mode — exercises the full mock event pipeline."""
from unittest.mock import MagicMock

import pytest

from app.collectors.paloalto import PaloAltoCollector
from app.collectors.trellix import TrellixCollector
from app.severity import Severity


def _mock_settings(**overrides):
    m = MagicMock()
    m.mock_mode = True
    m.trellix_base_url = "https://fake.trellix.example.com"
    m.trellix_client_id = None
    m.trellix_client_secret = None
    m.trellix_api_key = None
    m.trellix_verify_ssl = True
    m.paloalto_hostname = "firewall.example.com"
    m.paloalto_api_key = "fake-key"
    m.paloalto_vsys = "vsys1"
    m.paloalto_verify_ssl = True
    m.paloalto_log_count = 50
    for k, v in overrides.items():
        setattr(m, k, v)
    return m


@pytest.mark.asyncio
async def test_trellix_mock_returns_events():
    collector = TrellixCollector(_mock_settings())
    events = await collector.fetch_events()
    assert len(events) >= 1
    for e in events:
        assert e.vendor == "Trellix"
        assert e.severity in ("high", "critical", "medium")
        assert e.alert_id.startswith("mock-trellix-")
        assert e.host is not None
        assert e.process_name is not None
        assert e.detection_time is not None


@pytest.mark.asyncio
async def test_paloalto_mock_returns_events():
    collector = PaloAltoCollector(_mock_settings())
    events = await collector.fetch_events()
    assert len(events) >= 1
    for e in events:
        assert e.vendor == "PaloAlto"
        assert e.severity in ("high", "critical")
        assert e.alert_id.startswith("mock-pa-")
        assert e.source_ip is not None
        assert e.destination_ip is not None
        assert e.detection_time is not None


@pytest.mark.asyncio
async def test_trellix_mock_health_check():
    collector = TrellixCollector(_mock_settings())
    assert await collector.health_check() is True


@pytest.mark.asyncio
async def test_paloalto_mock_health_check():
    collector = PaloAltoCollector(_mock_settings())
    assert await collector.health_check() is True


@pytest.mark.asyncio
async def test_trellix_mock_events_are_unique():
    collector = TrellixCollector(_mock_settings())
    # Call several times to ensure IDs vary
    all_ids = set()
    for _ in range(5):
        events = await collector.fetch_events()
        for e in events:
            all_ids.add(e.alert_id)
    assert len(all_ids) > 1  # Not all identical


@pytest.mark.asyncio
async def test_trellix_severity_meets_high_threshold():
    collector = TrellixCollector(_mock_settings())
    events = await collector.fetch_events()
    threshold = Severity.HIGH
    qualifying = [e for e in events if Severity.from_str(e.severity).meets_threshold(threshold)]
    # Mock always generates high/critical events so all should qualify
    assert len(qualifying) > 0
