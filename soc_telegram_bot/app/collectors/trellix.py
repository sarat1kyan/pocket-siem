"""Trellix EDR collector.

Auth flow (choose one, checked in order):
  1. OAuth2 client-credentials: TRELLIX_CLIENT_ID + TRELLIX_CLIENT_SECRET
  2. API key header:             TRELLIX_API_KEY

Trellix uses McAfee/Trellix ePolicy Orchestrator (ePO) SaaS API or the
Trellix EDR Cloud API v1 depending on your tenant.  The implementation
targets the Trellix EDR Cloud Alert API:
  GET /edr/v2/alerts  (with query params: since, severity, limit, offset)

Set MOCK_MODE=true to bypass real API calls and generate synthetic events.
"""
from __future__ import annotations

import logging
import random
import string
import uuid
from datetime import UTC, datetime, timedelta
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
from app.normalizer import parse_datetime, safe_str, truncate

logger = logging.getLogger(__name__)

_OAUTH_URL = "https://iam.mcafee-cloud.com/iam/v1.1/token"

MOCK_TACTICS = ["Execution", "Persistence", "Privilege Escalation", "Defense Evasion",
                "Credential Access", "Discovery", "Lateral Movement", "Collection",
                "Exfiltration", "Command and Control", "Impact"]
MOCK_TECHNIQUES = ["T1059.001", "T1055", "T1078", "T1003", "T1021.002",
                   "T1053.005", "T1486", "T1190", "T1566.001", "T1071.001"]
MOCK_PROCESSES = ["powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe",
                  "rundll32.exe", "regsvr32.exe", "certutil.exe", "net.exe", "svchost.exe"]
MOCK_SEVERITIES = ["high", "critical", "high", "critical", "medium"]


class TrellixCollector(BaseCollector):
    name = "trellix"

    def __init__(self, settings: Settings) -> None:
        super().__init__()
        self._settings = settings
        self._token: str | None = None
        self._token_expiry: datetime | None = None
        self._client: httpx.AsyncClient | None = None

    def _build_client(self) -> httpx.AsyncClient:
        headers: dict[str, str] = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if self._settings.trellix_api_key:
            headers["x-api-key"] = self._settings.trellix_api_key
        return httpx.AsyncClient(
            base_url=self._settings.trellix_base_url,
            headers=headers,
            verify=self._settings.trellix_verify_ssl,
            timeout=30.0,
        )

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = self._build_client()
        return self._client

    @retry(
        retry=retry_if_exception_type((httpx.TransportError, httpx.TimeoutException)),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        stop=stop_after_attempt(4),
        reraise=True,
    )
    async def _refresh_token(self) -> None:
        """Obtain OAuth2 bearer token via client-credentials grant."""
        if not (self._settings.trellix_client_id and self._settings.trellix_client_secret):
            return
        async with httpx.AsyncClient(
            verify=self._settings.trellix_verify_ssl, timeout=20.0
        ) as client:
            resp = await client.post(
                _OAUTH_URL,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self._settings.trellix_client_id,
                    "client_secret": self._settings.trellix_client_secret,
                    "scope": "edr.dashboard.read edr.alert.read",
                },
            )
            resp.raise_for_status()
            data = resp.json()
            self._token = data["access_token"]
            expires_in = int(data.get("expires_in", 3600))
            self._token_expiry = datetime.now(UTC) + timedelta(
                seconds=expires_in - 60
            )
            logger.debug("Trellix OAuth2 token refreshed (expires in %ds)", expires_in)

    async def _ensure_token(self) -> None:
        if not self._token or (
            self._token_expiry and datetime.now(UTC) >= self._token_expiry
        ):
            await self._refresh_token()

    @retry(
        retry=retry_if_exception_type((httpx.TransportError, httpx.TimeoutException)),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        stop=stop_after_attempt(4),
        reraise=True,
    )
    async def _get_alerts(self, since: datetime | None) -> list[dict[str, Any]]:
        await self._ensure_token()
        client = await self._get_client()
        params: dict[str, Any] = {"limit": 100, "offset": 0}
        if since:
            params["since"] = since.strftime("%Y-%m-%dT%H:%M:%SZ")
        if self._token:
            client.headers["Authorization"] = f"Bearer {self._token}"
        resp = await client.get("/edr/v2/alerts", params=params)
        resp.raise_for_status()
        data = resp.json()
        # The Trellix API wraps results in {"data": [...]} or returns a list directly
        if isinstance(data, list):
            return data
        return data.get("data", data.get("alerts", data.get("items", [])))

    async def fetch_events(self, since: datetime | None = None) -> list[SecurityEvent]:
        if self._settings.mock_mode:
            return self._generate_mock_events()
        try:
            raw_alerts = await self._get_alerts(since)
            return [self._normalize(a) for a in raw_alerts]
        except httpx.HTTPStatusError as exc:
            logger.error("Trellix HTTP error %s: %s", exc.response.status_code, exc.response.text[:200])
            return []
        except Exception as exc:
            logger.error("Trellix fetch error: %s", exc)
            return []

    async def health_check(self) -> bool:
        if self._settings.mock_mode:
            return True
        try:
            await self._ensure_token()
            client = await self._get_client()
            if self._token:
                client.headers["Authorization"] = f"Bearer {self._token}"
            resp = await client.get("/edr/v2/alerts", params={"limit": 1})
            return resp.status_code < 500
        except Exception as exc:
            logger.warning("Trellix health check failed: %s", exc)
            return False

    def _normalize(self, raw: dict[str, Any]) -> SecurityEvent:
        # Accommodate different Trellix API response shapes
        attrs = raw.get("attributes", raw)
        alert_id = str(
            raw.get("id") or attrs.get("id") or attrs.get("alertId") or uuid.uuid4()
        )
        severity = str(
            attrs.get("severity", attrs.get("threatSeverity", "unknown"))
        ).lower()
        title = str(
            attrs.get("name", attrs.get("title", attrs.get("threatName", "Trellix Alert")))
        )
        host = safe_str(attrs.get("hostname", attrs.get("host", attrs.get("deviceName"))))
        username = safe_str(attrs.get("userName", attrs.get("username", attrs.get("user"))))
        process_name = safe_str(
            attrs.get("processName", attrs.get("process", attrs.get("fileName")))
        )
        command_line = truncate(
            safe_str(attrs.get("commandLine", attrs.get("cmdLine")))
        )
        tactic = safe_str(attrs.get("tactic", attrs.get("mitreTactic")))
        technique = safe_str(attrs.get("technique", attrs.get("mitreAttack", attrs.get("mitreId"))))
        status = safe_str(attrs.get("status", attrs.get("state", attrs.get("alertStatus"))))
        detection_time = parse_datetime(
            attrs.get("detectionDate", attrs.get("createdAt", attrs.get("timestamp")))
        )
        return SecurityEvent(
            vendor="Trellix",
            source="Trellix EDR",
            alert_id=alert_id,
            severity=severity,
            title=title,
            host=host,
            username=username,
            process_name=process_name,
            command_line=command_line,
            tactic=tactic,
            technique=technique,
            status=status,
            detection_time=detection_time,
            raw_json=raw,
        )

    def _generate_mock_events(self) -> list[SecurityEvent]:
        count = random.randint(1, 3)
        events: list[SecurityEvent] = []
        for _ in range(count):
            uid = uuid.uuid4().hex[:8]
            severity = random.choice(MOCK_SEVERITIES)
            process = random.choice(MOCK_PROCESSES)
            tactic = random.choice(MOCK_TACTICS)
            technique = random.choice(MOCK_TECHNIQUES)
            host = f"WORKSTATION-{''.join(random.choices(string.ascii_uppercase, k=4))}"
            username = f"user_{''.join(random.choices(string.ascii_lowercase, k=5))}"
            events.append(
                SecurityEvent(
                    vendor="Trellix",
                    source="Trellix EDR (mock)",
                    alert_id=f"mock-trellix-{uid}",
                    severity=severity,
                    title=f"[MOCK] Suspicious {process} activity — {tactic}",
                    host=host,
                    username=username,
                    process_name=process,
                    command_line=f"{process} -EncodedCommand {uuid.uuid4().hex}",
                    tactic=tactic,
                    technique=technique,
                    status="New",
                    detection_time=datetime.now(UTC),
                    raw_json={"mock": True, "alert_id": uid},
                )
            )
        return events
