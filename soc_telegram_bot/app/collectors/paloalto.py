"""Palo Alto Networks PAN-OS XML API collector.

The PAN-OS XML API is queried via HTTPS at:
  https://<hostname>/api/?type=log&log-type=threat&...

Authentication: X-PAN-KEY header or key= query param.
API key is generated once via:
  GET /api/?type=keygen&user=<user>&password=<pass>

This module uses the pre-generated API key stored in PALOALTO_API_KEY.
Set MOCK_MODE=true to bypass real API calls and generate synthetic events.
"""
from __future__ import annotations

import logging
import random
import uuid
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from typing import Any

import httpx
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from app.collectors.base import BaseCollector
from app.config import Settings
from app.models import SecurityEvent
from app.normalizer import map_panos_severity, parse_datetime, safe_str, truncate

logger = logging.getLogger(__name__)

MOCK_THREAT_NAMES = [
    "Eicar-Test-Virus", "CVE-2021-44228 Log4j RCE",
    "Emotet Dropper", "Cobalt Strike Beacon C2",
    "Mimikatz Credential Dump", "RDP Brute Force",
    "DNS Tunneling", "SQL Injection Attempt",
    "Exploit Kit Landing Page", "Ransomware Beacon",
]
MOCK_APPS = ["web-browsing", "ssl", "dns", "smtp", "ftp", "ssh", "rdp", "http2"]
MOCK_ACTIONS = ["alert", "block", "drop", "reset-both"]
MOCK_TYPES = ["vulnerability", "wildfire-virus", "spyware", "url", "file"]


class PaloAltoCollector(BaseCollector):
    name = "paloalto"

    def __init__(self, settings: Settings) -> None:
        super().__init__()
        self._settings = settings
        self._client: httpx.AsyncClient | None = None

    def _build_client(self) -> httpx.AsyncClient:
        if not self._settings.paloalto_hostname:
            raise ValueError("PALOALTO_HOSTNAME is not configured")
        base = f"https://{self._settings.paloalto_hostname}"
        return httpx.AsyncClient(
            base_url=base,
            verify=self._settings.paloalto_verify_ssl,
            timeout=30.0,
            headers={"X-PAN-KEY": self._settings.paloalto_api_key or ""},
        )

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = self._build_client()
        return self._client

    def _build_query(self, since: datetime | None) -> str:
        """Build XPath filter for log query."""
        if since:
            ts = since.strftime("%Y/%m/%d %H:%M:%S")
            return f"(receive_time geq '{ts}')"
        return "(severity geq high)"

    @retry(
        retry=retry_if_exception_type((httpx.TransportError, httpx.TimeoutException)),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        stop=stop_after_attempt(4),
        reraise=True,
    )
    async def _query_logs(
        self, log_type: str, since: datetime | None
    ) -> list[dict[str, Any]]:
        client = await self._get_client()
        query = self._build_query(since)
        params = {
            "type": "log",
            "log-type": log_type,
            "nlogs": str(self._settings.paloalto_log_count),
            "query": query,
            "key": self._settings.paloalto_api_key or "",
        }
        resp = await client.get("/api/", params=params)
        resp.raise_for_status()
        return self._parse_xml_logs(resp.text, log_type)

    def _parse_xml_logs(self, xml_text: str, log_type: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        try:
            root = ET.fromstring(xml_text)
            status = root.get("status", "")
            if status != "success":
                msg = root.findtext(".//msg") or "unknown error"
                logger.warning("PAN-OS API returned status=%s: %s", status, msg)
                return []
            entries = root.findall(".//entry")
            for entry in entries:
                record: dict[str, Any] = {"_log_type": log_type}
                for child in entry:
                    record[child.tag] = child.text
                results.append(record)
        except ET.ParseError as exc:
            logger.error("XML parse error from PAN-OS: %s", exc)
        return results

    async def fetch_events(self, since: datetime | None = None) -> list[SecurityEvent]:
        if self._settings.mock_mode:
            return self._generate_mock_events()
        if not self._settings.paloalto_hostname:
            logger.warning("Palo Alto polling skipped — PALOALTO_HOSTNAME not set")
            return []
        events: list[SecurityEvent] = []
        for log_type in ("threat", "wildfire"):
            try:
                records = await self._query_logs(log_type, since)
                events.extend(self._normalize(r) for r in records)
            except httpx.HTTPStatusError as exc:
                logger.error(
                    "PAN-OS %s log HTTP error %s", log_type, exc.response.status_code
                )
            except Exception as exc:
                logger.error("PAN-OS %s fetch error: %s", log_type, exc)
        return events

    async def health_check(self) -> bool:
        if self._settings.mock_mode:
            return True
        if not self._settings.paloalto_hostname:
            return False
        try:
            client = await self._get_client()
            params = {
                "type": "op",
                "cmd": "<show><system><info></info></system></show>",
                "key": self._settings.paloalto_api_key or "",
            }
            resp = await client.get("/api/", params=params)
            return resp.status_code == 200
        except Exception as exc:
            logger.warning("PAN-OS health check failed: %s", exc)
            return False

    def _normalize(self, raw: dict[str, Any]) -> SecurityEvent:
        log_type = raw.get("_log_type", "threat")
        log_id = str(
            raw.get("seqno") or raw.get("logid") or raw.get("serial") or uuid.uuid4()
        )
        alert_id = f"pa-{log_type}-{log_id}"
        severity = map_panos_severity(raw.get("severity", raw.get("threat_category", "unknown")))
        threat_name = safe_str(raw.get("threatid", raw.get("threat", raw.get("app"))))
        threat_type = safe_str(raw.get("type", log_type))
        src_ip = safe_str(raw.get("src", raw.get("srcip")))
        dst_ip = safe_str(raw.get("dst", raw.get("dstip")))
        try:
            dst_port = int(raw.get("dport") or raw.get("dstport") or 0) or None
        except (ValueError, TypeError):
            dst_port = None
        source_user = safe_str(raw.get("srcuser", raw.get("src_user")))
        application = safe_str(raw.get("app", raw.get("application")))
        action = safe_str(raw.get("action", raw.get("action_flags")))
        rule = safe_str(raw.get("rule", raw.get("rulename")))
        url_or_domain = truncate(safe_str(raw.get("misc", raw.get("url", raw.get("domain")))))
        detection_time = parse_datetime(raw.get("receive_time", raw.get("time_received")))
        title = f"{threat_name or 'Threat'} — {threat_type or log_type}"
        return SecurityEvent(
            vendor="PaloAlto",
            source=f"PAN-OS {log_type}",
            alert_id=alert_id,
            severity=severity,
            title=title,
            threat_name=threat_name,
            threat_type=threat_type,
            source_ip=src_ip,
            source_user=source_user,
            destination_ip=dst_ip,
            destination_port=dst_port,
            application=application,
            action=action,
            rule=rule,
            url_or_domain=url_or_domain,
            detection_time=detection_time,
            raw_json=raw,
        )

    def _generate_mock_events(self) -> list[SecurityEvent]:
        count = random.randint(1, 2)
        events: list[SecurityEvent] = []
        for _ in range(count):
            uid = uuid.uuid4().hex[:8]
            severity = random.choice(["high", "critical", "high"])
            threat = random.choice(MOCK_THREAT_NAMES)
            threat_type = random.choice(MOCK_TYPES)
            action = random.choice(MOCK_ACTIONS)
            src = f"10.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
            dst = f"203.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
            app = random.choice(MOCK_APPS)
            events.append(
                SecurityEvent(
                    vendor="PaloAlto",
                    source="PAN-OS threat (mock)",
                    alert_id=f"mock-pa-{uid}",
                    severity=severity,
                    title=f"[MOCK] {threat}",
                    threat_name=threat,
                    threat_type=threat_type,
                    source_ip=src,
                    destination_ip=dst,
                    destination_port=random.choice([80, 443, 8080, 4444, 22]),
                    application=app,
                    action=action,
                    rule=f"Internet-{threat_type}-block",
                    url_or_domain=f"malicious-{uid}.example.com",
                    detection_time=datetime.now(UTC),
                    raw_json={"mock": True, "alert_id": uid},
                )
            )
        return events
