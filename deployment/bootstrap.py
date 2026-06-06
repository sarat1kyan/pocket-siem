#!/usr/bin/env python3
"""
Pocket SIEM Bootstrap
Paste this entire script on the server: python3 bootstrap.py
It installs everything without requiring any URL to be typed.
"""
import os, sys, subprocess, textwrap, stat

DEPLOY_DIR = "/opt/pocket-siem"

# ── Credentials from environment ─────────────────────────────────────────────
TG_TOKEN   = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TG_USERS   = os.environ.get("ALLOWED_TELEGRAM_USER_IDS", "")
ADMIN_KEY  = os.environ.get("ADMIN_API_KEY", "")
TR_ID      = os.environ.get("TRELLIX_CLIENT_ID", "")
TR_SECRET  = os.environ.get("TRELLIX_CLIENT_SECRET", "")
TR_URL     = os.environ.get("TRELLIX_BASE_URL", "https://api.manage.trellix.com")
MOCK       = os.environ.get("MOCK_MODE", "false")
INTERVAL   = os.environ.get("POLL_INTERVAL", "60")
SEVERITY   = os.environ.get("MIN_SEVERITY", "high")

for name, val in [("TELEGRAM_BOT_TOKEN", TG_TOKEN),
                  ("ALLOWED_TELEGRAM_USER_IDS", TG_USERS),
                  ("ADMIN_API_KEY", ADMIN_KEY)]:
    if not val:
        print(f"ERROR: {name} env var is required"); sys.exit(1)

# Fix URL if user accidentally set it with angle brackets
TR_URL = TR_URL.strip("<>")

def run(cmd, **kw):
    print(f"  $ {cmd[:80]}")
    return subprocess.run(cmd, shell=True, check=True, **kw)

def section(title):
    print(f"\n{'='*56}\n  {title}\n{'='*56}")

# ── STAGE 1: System packages ──────────────────────────────────────────────────
section("STAGE 1 — System packages")
os.environ["DEBIAN_FRONTEND"] = "noninteractive"
run("apt-get update -qq 2>&1 | tail -2")
run("apt-get install -y -qq python3 python3-pip python3-venv curl git 2>&1 | tail -3")

# Install Docker if missing
if subprocess.run("docker info", shell=True, capture_output=True).returncode != 0:
    section("Installing Docker")
    run("""
    install -m 0755 -d /etc/apt/keyrings && \
    curl -fsSL https://download.docker.com/linux/$(. /etc/os-release && echo $ID)/gpg \
      -o /etc/apt/keyrings/docker.asc && \
    chmod a+r /etc/apt/keyrings/docker.asc && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
      https://download.docker.com/linux/$(. /etc/os-release && echo $ID) \
      $(. /etc/os-release && echo $VERSION_CODENAME) stable" \
      > /etc/apt/sources.list.d/docker.list && \
    apt-get update -qq && \
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin && \
    systemctl enable --now docker
    """)

# ── STAGE 2: Directories ──────────────────────────────────────────────────────
section("STAGE 2 — Directories")
for d in [DEPLOY_DIR,
          f"{DEPLOY_DIR}/app",
          f"{DEPLOY_DIR}/app/notifier",
          f"{DEPLOY_DIR}/app/collectors",
          f"{DEPLOY_DIR}/app/services",
          f"{DEPLOY_DIR}/app/api",
          f"{DEPLOY_DIR}/data"]:
    os.makedirs(d, exist_ok=True)
print("  Directories created")

# ── STAGE 3: Application files ────────────────────────────────────────────────
section("STAGE 3 — Application code")

files = {}

files["app/__init__.py"] = ""
files["app/notifier/__init__.py"] = ""
files["app/collectors/__init__.py"] = ""
files["app/services/__init__.py"] = ""
files["app/api/__init__.py"] = ""

files["app/severity.py"] = textwrap.dedent("""
    from __future__ import annotations
    from enum import IntEnum
    from typing import Optional

    class Severity(IntEnum):
        UNKNOWN=0; INFORMATIONAL=1; LOW=2; MEDIUM=3; HIGH=4; CRITICAL=5

        @classmethod
        def from_str(cls, value):
            if not value: return cls.UNKNOWN
            m = {"informational":cls.INFORMATIONAL,"info":cls.INFORMATIONAL,
                 "low":cls.LOW,"medium":cls.MEDIUM,"med":cls.MEDIUM,
                 "moderate":cls.MEDIUM,"high":cls.HIGH,
                 "critical":cls.CRITICAL,"crit":cls.CRITICAL,"fatal":cls.CRITICAL,
                 "1":cls.INFORMATIONAL,"2":cls.LOW,"3":cls.MEDIUM,"4":cls.HIGH,"5":cls.CRITICAL}
            return m.get(str(value).lower().strip(), cls.UNKNOWN)

        def label(self): return self.name.upper()
        def emoji(self):
            return {Severity.CRITICAL:"🔴",Severity.HIGH:"🟠",Severity.MEDIUM:"🟡",
                    Severity.LOW:"🟢",Severity.INFORMATIONAL:"⚪",Severity.UNKNOWN:"❓"}[self]
        def meets_threshold(self, t): return self >= t
""").lstrip()

files["app/models.py"] = textwrap.dedent("""
    from __future__ import annotations
    import hashlib, json
    from datetime import datetime, timezone
    from typing import Any, Dict, Optional
    from pydantic import BaseModel, computed_field
    from sqlalchemy import Boolean, DateTime, Integer, String, Text
    from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

    class Base(DeclarativeBase): pass

    class SecurityEventORM(Base):
        __tablename__ = "security_events"
        id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
        vendor: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
        source: Mapped[str] = mapped_column(String(128), nullable=False)
        alert_id: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
        dedup_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
        severity: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
        title: Mapped[str] = mapped_column(String(512), nullable=False)
        raw_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
        notified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
        notified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
        received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
            default=lambda: datetime.now(timezone.utc), nullable=False)
        detection_time: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    class SecurityEvent(BaseModel):
        vendor: str; source: str; alert_id: str; severity: str; title: str
        detection_time: Optional[datetime] = None
        host: Optional[str] = None; username: Optional[str] = None
        process_name: Optional[str] = None; command_line: Optional[str] = None
        tactic: Optional[str] = None; technique: Optional[str] = None
        status: Optional[str] = None
        threat_name: Optional[str] = None; threat_type: Optional[str] = None
        source_ip: Optional[str] = None; source_user: Optional[str] = None
        destination_ip: Optional[str] = None; destination_port: Optional[int] = None
        application: Optional[str] = None; action: Optional[str] = None
        rule: Optional[str] = None; url_or_domain: Optional[str] = None
        raw_json: Optional[Dict[str, Any]] = None

        @computed_field
        @property
        def dedup_hash(self) -> str:
            return hashlib.sha256(f"{self.vendor}:{self.alert_id}".encode()).hexdigest()

        def to_orm(self):
            raw = json.dumps(self.raw_json, default=str) if self.raw_json else None
            return SecurityEventORM(vendor=self.vendor, source=self.source,
                alert_id=self.alert_id, dedup_hash=self.dedup_hash,
                severity=self.severity, title=self.title, raw_json=raw,
                detection_time=self.detection_time)
""").lstrip()

files["app/normalizer.py"] = textwrap.dedent("""
    from __future__ import annotations
    from datetime import datetime, UTC
    from typing import Any, Optional

    def parse_datetime(value: Any) -> Optional[datetime]:
        if value is None: return None
        if isinstance(value, datetime):
            return value.replace(tzinfo=UTC) if value.tzinfo is None else value
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value, tz=UTC)
        s = str(value).strip()
        if not s: return None
        for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ","%Y-%m-%dT%H:%M:%SZ",
                    "%Y-%m-%dT%H:%M:%S.%f%z","%Y-%m-%dT%H:%M:%S%z",
                    "%Y/%m/%d %H:%M:%S","%Y-%m-%d %H:%M:%S"):
            try:
                dt = datetime.strptime(s, fmt)
                return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt
            except ValueError: continue
        return None

    def safe_str(value: Any, max_len: int = 512) -> Optional[str]:
        if value is None: return None
        s = str(value).strip()
        return s[:max_len] if s else None

    def map_panos_severity(value: Any) -> str:
        m = {"critical":"critical","high":"high","medium":"medium","low":"low",
             "informational":"informational","5":"critical","4":"high","3":"medium","2":"low","1":"informational"}
        return m.get(str(value).lower().strip(), "unknown")

    def truncate(value, length=200):
        if not value: return value
        return value[:length]+"…" if len(value)>length else value
""").lstrip()

files["app/db.py"] = textwrap.dedent("""
    from __future__ import annotations
    import logging, os
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
    from app.models import Base
    logger = logging.getLogger(__name__)
    _engine = None
    _session_factory = None

    def _ensure_data_dir(url):
        if url.startswith("sqlite"):
            path = url.split("///",1)[-1]
            d = os.path.dirname(path)
            if d and d not in (".",""):
                os.makedirs(d, exist_ok=True)

    def get_engine(database_url):
        global _engine
        if _engine is None:
            _ensure_data_dir(database_url)
            ca = {"check_same_thread":False} if "sqlite" in database_url else {}
            _engine = create_async_engine(database_url, echo=False, connect_args=ca, pool_pre_ping=True)
        return _engine

    def get_session_factory(database_url):
        global _session_factory
        if _session_factory is None:
            _session_factory = async_sessionmaker(get_engine(database_url),
                expire_on_commit=False, class_=AsyncSession)
        return _session_factory

    async def init_db(database_url):
        async with get_engine(database_url).begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("DB schema initialised")
""").lstrip()

files["app/config.py"] = textwrap.dedent(f"""
    from __future__ import annotations
    import re
    from functools import lru_cache
    from typing import List, Optional
    from pydantic import Field, field_validator, model_validator
    from pydantic_settings import BaseSettings, SettingsConfigDict

    class Settings(BaseSettings):
        model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8",
            case_sensitive=False, extra="ignore")
        telegram_bot_token: str = Field(...)
        allowed_telegram_user_ids: List[int] = Field(default_factory=list)
        telegram_chat_id: Optional[int] = Field(None)
        enable_trellix: bool = Field(True)
        trellix_base_url: str = Field("https://api.manage.trellix.com")
        trellix_client_id: Optional[str] = Field(None)
        trellix_client_secret: Optional[str] = Field(None)
        trellix_api_key: Optional[str] = Field(None)
        trellix_verify_ssl: bool = Field(True)
        enable_paloalto: bool = Field(True)
        paloalto_hostname: Optional[str] = Field(None)
        paloalto_api_key: Optional[str] = Field(None)
        paloalto_vsys: str = Field("vsys1")
        paloalto_verify_ssl: bool = Field(True)
        paloalto_log_count: int = Field(50)
        poll_interval_seconds: int = Field(60)
        min_severity: str = Field("high")
        database_url: str = Field("sqlite+aiosqlite:///./data/soc_bot.db")
        admin_api_key: str = Field(...)
        api_host: str = Field("0.0.0.0")
        api_port: int = Field(8080)
        mock_mode: bool = Field(False)
        max_alerts_per_minute: int = Field(20)
        log_level: str = Field("INFO")
        environment: str = Field("production")

        @field_validator("min_severity", mode="before")
        @classmethod
        def norm_sev(cls, v):
            v = str(v).lower().strip()
            assert v in {{"low","medium","high","critical"}}, f"invalid severity: {{v}}"
            return v

        @field_validator("allowed_telegram_user_ids", mode="before")
        @classmethod
        def parse_ids(cls, v):
            if isinstance(v, list): return [int(i) for i in v]
            if isinstance(v, str):
                return [int(p) for p in re.split(r"[,\\s]+", v.strip()) if p]
            return v

        @field_validator("log_level", mode="before")
        @classmethod
        def upper_level(cls, v): return str(v).upper()

        def masked_repr(self):
            return (f"Settings(env={{self.environment}}, mock={{self.mock_mode}}, "
                    f"trellix={{'on' if self.enable_trellix else 'off'}}, "
                    f"paloalto={{'on' if self.enable_paloalto else 'off'}}, "
                    f"sev={{self.min_severity}})")

    @lru_cache(maxsize=1)
    def get_settings(): return Settings()
""").lstrip()

files["app/collectors/base.py"] = textwrap.dedent("""
    from __future__ import annotations
    import abc, logging
    from datetime import datetime, UTC
    from typing import List, Optional
    from app.models import SecurityEvent
    logger = logging.getLogger(__name__)

    class BaseCollector(abc.ABC):
        name: str = "base"
        def __init__(self): self._last_poll = None

        @abc.abstractmethod
        async def fetch_events(self, since=None): ...

        @abc.abstractmethod
        async def health_check(self) -> bool: ...

        async def poll(self):
            since = self._last_poll
            events = await self.fetch_events(since=since)
            self._last_poll = datetime.now(UTC)
            logger.info("%s: fetched %d events", self.name, len(events))
            return events
""").lstrip()

files["app/collectors/trellix.py"] = textwrap.dedent("""
    from __future__ import annotations
    import logging, random, string, uuid
    from datetime import datetime, timedelta, UTC
    from typing import Any, Dict, List, Optional
    import httpx
    from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential
    from app.collectors.base import BaseCollector
    from app.models import SecurityEvent
    from app.normalizer import parse_datetime, safe_str, truncate
    logger = logging.getLogger(__name__)

    _OAUTH_URL = "https://iam.mcafee-cloud.com/iam/v1.1/token"
    MOCK_TACTICS  = ["Execution","Persistence","Privilege Escalation","Lateral Movement","Exfiltration"]
    MOCK_TECHS    = ["T1059.001","T1055","T1078","T1003","T1021.002","T1486"]
    MOCK_PROCS    = ["powershell.exe","cmd.exe","wscript.exe","mshta.exe","rundll32.exe"]
    MOCK_SEVS     = ["high","critical","high","critical","medium"]

    class TrellixCollector(BaseCollector):
        name = "trellix"
        def __init__(self, settings):
            super().__init__()
            self._settings = settings
            self._token = None
            self._token_expiry = None
            self._client = None

        def _build_client(self):
            h = {"Accept":"application/json","Content-Type":"application/json"}
            if self._settings.trellix_api_key: h["x-api-key"] = self._settings.trellix_api_key
            return httpx.AsyncClient(base_url=self._settings.trellix_base_url,
                headers=h, verify=self._settings.trellix_verify_ssl, timeout=30.0)

        async def _get_client(self):
            if self._client is None: self._client = self._build_client()
            return self._client

        @retry(retry=retry_if_exception_type((httpx.TransportError,httpx.TimeoutException)),
               wait=wait_exponential(min=2,max=30), stop=stop_after_attempt(4), reraise=True)
        async def _refresh_token(self):
            if not (self._settings.trellix_client_id and self._settings.trellix_client_secret): return
            async with httpx.AsyncClient(verify=self._settings.trellix_verify_ssl, timeout=20.0) as c:
                r = await c.post(_OAUTH_URL, data={"grant_type":"client_credentials",
                    "client_id":self._settings.trellix_client_id,
                    "client_secret":self._settings.trellix_client_secret,
                    "scope":"edr.dashboard.read edr.alert.read"})
                r.raise_for_status()
                d = r.json()
                self._token = d["access_token"]
                self._token_expiry = datetime.now(UTC) + timedelta(seconds=int(d.get("expires_in",3600))-60)

        async def _ensure_token(self):
            if not self._token or (self._token_expiry and datetime.now(UTC) >= self._token_expiry):
                await self._refresh_token()

        async def fetch_events(self, since=None):
            if self._settings.mock_mode: return self._mock()
            try:
                await self._ensure_token()
                c = await self._get_client()
                p = {"limit":100,"offset":0}
                if since: p["since"] = since.strftime("%Y-%m-%dT%H:%M:%SZ")
                if self._token: c.headers["Authorization"] = f"Bearer {self._token}"
                r = await c.get("/edr/v2/alerts", params=p)
                r.raise_for_status()
                d = r.json()
                raw = d if isinstance(d,list) else d.get("data",d.get("alerts",d.get("items",[])))
                return [self._norm(a) for a in raw]
            except httpx.HTTPStatusError as e:
                logger.error("Trellix HTTP %s: %s", e.response.status_code, e.response.text[:200])
                return []
            except Exception as e:
                logger.error("Trellix error: %s", e)
                return []

        async def health_check(self):
            if self._settings.mock_mode: return True
            try:
                await self._ensure_token()
                c = await self._get_client()
                if self._token: c.headers["Authorization"] = f"Bearer {self._token}"
                r = await c.get("/edr/v2/alerts", params={"limit":1})
                return r.status_code < 500
            except: return False

        def _norm(self, raw):
            a = raw.get("attributes", raw)
            return SecurityEvent(vendor="Trellix", source="Trellix EDR",
                alert_id=str(raw.get("id") or a.get("id") or a.get("alertId") or uuid.uuid4()),
                severity=str(a.get("severity",a.get("threatSeverity","unknown"))).lower(),
                title=str(a.get("name",a.get("title",a.get("threatName","Trellix Alert")))),
                host=safe_str(a.get("hostname",a.get("host",a.get("deviceName")))),
                username=safe_str(a.get("userName",a.get("username",a.get("user")))),
                process_name=safe_str(a.get("processName",a.get("process",a.get("fileName")))),
                command_line=truncate(safe_str(a.get("commandLine",a.get("cmdLine")))),
                tactic=safe_str(a.get("tactic",a.get("mitreTactic"))),
                technique=safe_str(a.get("technique",a.get("mitreAttack",a.get("mitreId")))),
                status=safe_str(a.get("status",a.get("state",a.get("alertStatus")))),
                detection_time=parse_datetime(a.get("detectionDate",a.get("createdAt",a.get("timestamp")))),
                raw_json=raw)

        def _mock(self):
            return [SecurityEvent(
                vendor="Trellix", source="Trellix EDR (mock)",
                alert_id=f"mock-trellix-{uuid.uuid4().hex[:8]}",
                severity=random.choice(MOCK_SEVS),
                title=f"[MOCK] Suspicious {random.choice(MOCK_PROCS)} — {random.choice(MOCK_TACTICS)}",
                host=f"WORKSTATION-{''.join(random.choices(string.ascii_uppercase,k=4))}",
                username=f"user_{''.join(random.choices(string.ascii_lowercase,k=5))}",
                process_name=random.choice(MOCK_PROCS),
                command_line=f"{random.choice(MOCK_PROCS)} -EncodedCommand {uuid.uuid4().hex}",
                tactic=random.choice(MOCK_TACTICS),
                technique=random.choice(MOCK_TECHS),
                status="New",
                detection_time=datetime.now(UTC),
                raw_json={"mock":True})
            for _ in range(random.randint(1,3))]
""").lstrip()

files["app/collectors/paloalto.py"] = textwrap.dedent("""
    from __future__ import annotations
    import logging, random, uuid, xml.etree.ElementTree as ET
    from datetime import datetime, UTC
    from typing import Any, Dict, List, Optional
    import httpx
    from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential
    from app.collectors.base import BaseCollector
    from app.models import SecurityEvent
    from app.normalizer import map_panos_severity, parse_datetime, safe_str, truncate
    logger = logging.getLogger(__name__)

    MOCK_THREATS = ["CVE-2021-44228 Log4j RCE","Cobalt Strike Beacon","Emotet Dropper",
                    "RDP Brute Force","DNS Tunneling","SQL Injection","Ransomware Beacon"]
    MOCK_TYPES = ["vulnerability","wildfire-virus","spyware","url"]
    MOCK_APPS  = ["web-browsing","ssl","dns","smtp","rdp"]

    class PaloAltoCollector(BaseCollector):
        name = "paloalto"
        def __init__(self, settings):
            super().__init__()
            self._settings = settings
            self._client = None

        def _build_client(self):
            if not self._settings.paloalto_hostname:
                raise ValueError("PALOALTO_HOSTNAME not configured")
            return httpx.AsyncClient(
                base_url=f"https://{self._settings.paloalto_hostname}",
                verify=self._settings.paloalto_verify_ssl, timeout=30.0,
                headers={"X-PAN-KEY": self._settings.paloalto_api_key or ""})

        async def _get_client(self):
            if self._client is None: self._client = self._build_client()
            return self._client

        async def fetch_events(self, since=None):
            if self._settings.mock_mode: return self._mock()
            if not self._settings.paloalto_hostname: return []
            events = []
            for lt in ("threat","wildfire"):
                try:
                    c = await self._get_client()
                    q = f"(receive_time geq '{since.strftime('%Y/%m/%d %H:%M:%S')}')" if since else "(severity geq high)"
                    r = await c.get("/api/", params={"type":"log","log-type":lt,
                        "nlogs":str(self._settings.paloalto_log_count),"query":q,
                        "key":self._settings.paloalto_api_key or ""})
                    r.raise_for_status()
                    root = ET.fromstring(r.text)
                    if root.get("status","") == "success":
                        for entry in root.findall(".//entry"):
                            raw = {"_log_type":lt}
                            for child in entry: raw[child.tag] = child.text
                            events.append(self._norm(raw))
                except Exception as e:
                    logger.error("PAN-OS %s error: %s", lt, e)
            return events

        async def health_check(self):
            if self._settings.mock_mode: return True
            if not self._settings.paloalto_hostname: return False
            try:
                c = await self._get_client()
                r = await c.get("/api/", params={"type":"op",
                    "cmd":"<show><system><info></info></system></show>",
                    "key":self._settings.paloalto_api_key or ""})
                return r.status_code == 200
            except: return False

        def _norm(self, raw):
            lt = raw.get("_log_type","threat")
            lid = str(raw.get("seqno") or raw.get("logid") or uuid.uuid4())
            try: dp = int(raw.get("dport") or 0) or None
            except: dp = None
            return SecurityEvent(vendor="PaloAlto", source=f"PAN-OS {lt}",
                alert_id=f"pa-{lt}-{lid}",
                severity=map_panos_severity(raw.get("severity","unknown")),
                title=f"{safe_str(raw.get('threatid',raw.get('threat','Threat')))} — {lt}",
                threat_name=safe_str(raw.get("threatid",raw.get("threat"))),
                threat_type=safe_str(raw.get("type",lt)),
                source_ip=safe_str(raw.get("src",raw.get("srcip"))),
                source_user=safe_str(raw.get("srcuser")),
                destination_ip=safe_str(raw.get("dst",raw.get("dstip"))),
                destination_port=dp,
                application=safe_str(raw.get("app")),
                action=safe_str(raw.get("action")),
                rule=safe_str(raw.get("rule",raw.get("rulename"))),
                url_or_domain=truncate(safe_str(raw.get("misc",raw.get("url",raw.get("domain"))))),
                detection_time=parse_datetime(raw.get("receive_time")),
                raw_json=raw)

        def _mock(self):
            return [SecurityEvent(vendor="PaloAlto", source="PAN-OS (mock)",
                alert_id=f"mock-pa-{uuid.uuid4().hex[:8]}",
                severity=random.choice(["high","critical","high"]),
                title=f"[MOCK] {random.choice(MOCK_THREATS)}",
                threat_name=random.choice(MOCK_THREATS),
                threat_type=random.choice(MOCK_TYPES),
                source_ip=f"10.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
                destination_ip=f"203.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
                destination_port=random.choice([80,443,8080,4444]),
                application=random.choice(MOCK_APPS),
                action=random.choice(["alert","block","drop"]),
                rule=f"block-{random.choice(MOCK_TYPES)}",
                url_or_domain=f"malicious-{uuid.uuid4().hex[:8]}.example.com",
                detection_time=datetime.now(UTC),
                raw_json={"mock":True})
            for _ in range(random.randint(1,2))]
""").lstrip()

files["app/services/dedupe.py"] = textwrap.dedent("""
    from __future__ import annotations
    import logging
    from datetime import datetime, UTC
    from sqlalchemy import select
    from app.models import SecurityEvent, SecurityEventORM
    logger = logging.getLogger(__name__)

    async def filter_new_events(session, events):
        if not events: return []
        hashes = [e.dedup_hash for e in events]
        result = await session.execute(select(SecurityEventORM.dedup_hash)
            .where(SecurityEventORM.dedup_hash.in_(hashes)))
        known = {r[0] for r in result.fetchall()}
        return [e for e in events if e.dedup_hash not in known]

    async def mark_event_stored(session, event):
        orm = event.to_orm()
        session.add(orm)
        await session.flush()
        return orm

    async def mark_event_notified(session, orm_id):
        result = await session.execute(select(SecurityEventORM).where(SecurityEventORM.id == orm_id))
        row = result.scalar_one_or_none()
        if row: row.notified = True; row.notified_at = datetime.now(UTC)
""").lstrip()

files["app/services/access_control.py"] = textwrap.dedent("""
    from __future__ import annotations
    import logging
    logger = logging.getLogger(__name__)

    class AccessControl:
        def __init__(self, allowed_ids): self._allowed = set(allowed_ids)
        def is_allowed(self, uid): return uid in self._allowed
        def check(self, update):
            if update.effective_user is None: return False
            uid = update.effective_user.id
            if uid not in self._allowed:
                logger.warning("Denied uid=%d user=%s", uid, update.effective_user.username)
                return False
            return True
        def add_user(self, uid): self._allowed.add(uid)
        def remove_user(self, uid): self._allowed.discard(uid)
        def list_users(self): return set(self._allowed)
""").lstrip()

files["app/services/polling.py"] = textwrap.dedent("""
    from __future__ import annotations
    import asyncio, logging
    from datetime import datetime, UTC
    from app.services.dedupe import filter_new_events, mark_event_notified, mark_event_stored
    from app.severity import Severity
    logger = logging.getLogger(__name__)

    class PollingService:
        def __init__(self, settings, collectors, notify_fn, session_factory):
            self._settings = settings
            self._collectors = collectors
            self._notify_fn = notify_fn
            self._session_factory = session_factory
            self._paused = False
            self._running = False
            self._task = None
            self._threshold = Severity.from_str(settings.min_severity)
            self._sent = 0
            self._minute_start = datetime.now(UTC)

        @property
        def paused(self): return self._paused
        def pause(self): self._paused = True; logger.info("Polling paused")
        def resume(self): self._paused = False; logger.info("Polling resumed")

        def set_threshold(self, s):
            self._threshold = Severity.from_str(s)
            logger.info("Threshold set to %s", self._threshold.label())
            return True

        def start(self):
            if not self._running:
                self._running = True
                self._task = asyncio.create_task(self._loop())
                logger.info("Polling started (interval=%ds)", self._settings.poll_interval_seconds)

        def stop(self):
            self._running = False
            if self._task and not self._task.done(): self._task.cancel()

        async def _loop(self):
            while self._running:
                try: await self._tick()
                except asyncio.CancelledError: break
                except Exception as e: logger.exception("Polling error: %s", e)
                await asyncio.sleep(self._settings.poll_interval_seconds)

        async def _tick(self):
            if self._paused: return
            for c in self._collectors:
                try:
                    events = await c.poll()
                    await self._process(events)
                except Exception as e:
                    logger.error("Collector %s error: %s", c.name, e)

        def _rate_ok(self):
            now = datetime.now(UTC)
            if (now - self._minute_start).total_seconds() >= 60:
                self._minute_start = now; self._sent = 0
            return self._sent < self._settings.max_alerts_per_minute

        async def _process(self, events):
            if not events: return
            qualifying = [e for e in events
                if Severity.from_str(e.severity).meets_threshold(self._threshold)]
            if not qualifying: return
            async with self._session_factory() as session:
                try:
                    new = await filter_new_events(session, qualifying)
                    for event in new:
                        orm = await mark_event_stored(session, event)
                        await session.commit()
                        if not self._rate_ok():
                            logger.warning("Rate limit reached — dropping %s", event.alert_id)
                            continue
                        try:
                            await self._notify_fn(event)
                            self._sent += 1
                            await mark_event_notified(session, orm.id)
                            await session.commit()
                        except Exception as e:
                            logger.error("Notify failed for %s: %s", event.alert_id, e)
                except Exception as e:
                    logger.error("DB error: %s", e)
                    await session.rollback()
""").lstrip()

files["app/notifier/formatters.py"] = textwrap.dedent("""
    from __future__ import annotations
    from typing import Optional
    from app.models import SecurityEvent
    from app.severity import Severity

    def _f(label, value): return f"• *{label}:* {value}\\n" if value else ""
    def _dt(e): return e.detection_time.strftime("%Y-%m-%d %H:%M:%S UTC") if e.detection_time else "Unknown"

    def format_trellix(e):
        sev = Severity.from_str(e.severity)
        return (f"🚨 *Trellix EDR Alert* {sev.emoji()}\\n• *Severity:* `{sev.label()}`\\n"
            + _f("Host",e.host) + _f("User",e.username) + _f("Detection",e.title)
            + _f("Process",e.process_name) + _f("Command",e.command_line)
            + _f("MITRE", f"{e.tactic} / {e.technique}" if e.tactic or e.technique else None)
            + _f("Status",e.status) + f"• *Time:* `{_dt(e)}`\\n")

    def format_paloalto(e):
        sev = Severity.from_str(e.severity)
        dst = f"{e.destination_ip}:{e.destination_port}" if e.destination_ip and e.destination_port else e.destination_ip
        return (f"🔥 *Palo Alto Threat Alert* {sev.emoji()}\\n• *Severity:* `{sev.label()}`\\n"
            + _f("Threat",e.threat_name or e.title) + _f("Type",e.threat_type)
            + _f("Source",e.source_ip) + _f("Destination",dst) + _f("User",e.source_user)
            + _f("App",e.application) + _f("Action",e.action) + _f("Rule",e.rule)
            + _f("URL/Domain",e.url_or_domain) + f"• *Time:* `{_dt(e)}`\\n")

    def format_event(e):
        if e.vendor.lower().startswith("trellix"): return format_trellix(e)
        if e.vendor.lower().startswith("palo"): return format_paloalto(e)
        sev = Severity.from_str(e.severity)
        return f"⚠️ *Security Alert* {sev.emoji()}\\n• *Vendor:* {e.vendor}\\n• *Severity:* `{sev.label()}`\\n• {e.title}\\n• *Time:* `{_dt(e)}`\\n"
""").lstrip()

files["app/notifier/telegram_bot.py"] = textwrap.dedent("""
    from __future__ import annotations
    import logging
    from typing import Optional
    from sqlalchemy import desc, select
    from telegram import BotCommand, Update
    from telegram.constants import ParseMode
    from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters
    from app.models import SecurityEvent, SecurityEventORM
    from app.notifier.formatters import format_event
    from app.services.access_control import AccessControl
    from app.severity import Severity
    logger = logging.getLogger(__name__)

    def _guard(access):
        def dec(fn):
            async def w(update, context):
                if not access.check(update):
                    await update.effective_message.reply_text("⛔ Access denied. Use /whoami to get your ID.")
                    return
                return await fn(update, context)
            w.__name__ = fn.__name__; return w
        return dec

    class SocBot:
        def __init__(self, settings, access_control, session_factory, polling_service=None):
            self._settings = settings
            self._access = access_control
            self._session_factory = session_factory
            self._polling = polling_service
            self._app = None

        def _g(self, fn): return _guard(self._access)(fn)

        def build_application(self):
            app = Application.builder().token(self._settings.telegram_bot_token).build()
            g = self._g
            for cmd, handler in [
                ("start",g(self._start)),("help",g(self._help)),("status",g(self._status)),
                ("health",g(self._health)),("sources",g(self._sources)),
                ("recent",g(self._recent)),("recent_trellix",g(self._recent_trellix)),
                ("recent_paloalto",g(self._recent_paloalto)),("critical",g(self._critical)),
                ("set_severity",g(self._set_sev)),("pause",g(self._pause)),("resume",g(self._resume)),
                ("whoami",self._whoami)]:
                app.add_handler(CommandHandler(cmd, handler))
            app.add_handler(MessageHandler(filters.COMMAND, g(self._unknown)))
            self._app = app; return app

        async def setup_commands(self):
            if not self._app: return
            await self._app.bot.set_my_commands([
                BotCommand("start","Welcome"),BotCommand("help","Commands"),
                BotCommand("status","Bot status"),BotCommand("health","API health"),
                BotCommand("sources","Data sources"),BotCommand("recent","Last 5 alerts"),
                BotCommand("recent_trellix","Last 5 Trellix"),BotCommand("recent_paloalto","Last 5 PA"),
                BotCommand("critical","Last 5 CRITICAL"),BotCommand("set_severity","Change threshold"),
                BotCommand("pause","Pause alerts"),BotCommand("resume","Resume alerts"),
                BotCommand("whoami","Your Telegram ID")])

        async def send_alert(self, event):
            if not self._app: return
            text = format_event(event)
            targets = [self._settings.telegram_chat_id] if self._settings.telegram_chat_id \
                else list(self._access.list_users())
            for cid in targets:
                try: await self._app.bot.send_message(chat_id=cid, text=text, parse_mode=ParseMode.MARKDOWN)
                except Exception as e: logger.error("Send failed to %d: %s", cid, e)

        async def _start(self, u, c): await u.message.reply_text("👋 *Pocket SIEM Bot* running! Use /help.", parse_mode=ParseMode.MARKDOWN)
        async def _help(self, u, c): await u.message.reply_text("*Commands*\\n/status /health /sources /recent\\n/recent\\\\_trellix /recent\\\\_paloalto /critical\\n/set\\\\_severity /pause /resume /whoami", parse_mode=ParseMode.MARKDOWN)

        async def _status(self, u, c):
            paused = self._polling.paused if self._polling else False
            thr = self._polling._threshold.label() if self._polling else self._settings.min_severity.upper()
            await u.message.reply_text(
                f"*Status*\\n• Mode: {'🟡 MOCK' if self._settings.mock_mode else '🟢 Live'}\\n"
                f"• Polling: {'⏸ Paused' if paused else '▶️ Active'}\\n"
                f"• Severity: `{thr}`\\n• Interval: `{self._settings.poll_interval_seconds}s`\\n"
                f"• Trellix: {'✅' if self._settings.enable_trellix else '❌'}\\n"
                f"• Palo Alto: {'✅' if self._settings.enable_paloalto else '❌'}", parse_mode=ParseMode.MARKDOWN)

        async def _health(self, u, c):
            from app.collectors.trellix import TrellixCollector
            from app.collectors.paloalto import PaloAltoCollector
            lines = ["*Health Check*\\n"]
            if self._settings.enable_trellix:
                ok = await TrellixCollector(self._settings).health_check()
                lines.append(f"• Trellix: {'✅ OK' if ok else '❌ Unreachable'}")
            if self._settings.enable_paloalto:
                ok = await PaloAltoCollector(self._settings).health_check()
                lines.append(f"• Palo Alto: {'✅ OK' if ok else '❌ Unreachable'}")
            await u.message.reply_text("\\n".join(lines), parse_mode=ParseMode.MARKDOWN)

        async def _sources(self, u, c):
            lines = ["*Sources*\\n"]
            if self._settings.enable_trellix: lines.append(f"• Trellix: `{self._settings.trellix_base_url}`")
            if self._settings.enable_paloalto: lines.append(f"• Palo Alto: `{self._settings.paloalto_hostname or 'not set'}`")
            await u.message.reply_text("\\n".join(lines), parse_mode=ParseMode.MARKDOWN)

        async def _recent(self, u, c): await self._show_recent(u)
        async def _recent_trellix(self, u, c): await self._show_recent(u, vendor="Trellix")
        async def _recent_paloalto(self, u, c): await self._show_recent(u, vendor="PaloAlto")
        async def _critical(self, u, c): await self._show_recent(u, severity="critical")

        async def _show_recent(self, u, vendor=None, limit=5, severity=None):
            async with self._session_factory() as session:
                stmt = select(SecurityEventORM).order_by(desc(SecurityEventORM.received_at)).limit(limit)
                if vendor: stmt = stmt.where(SecurityEventORM.vendor == vendor)
                if severity: stmt = stmt.where(SecurityEventORM.severity == severity)
                rows = (await session.execute(stmt)).scalars().all()
            if not rows: await u.message.reply_text("No events found."); return
            for row in rows:
                dt = row.detection_time or row.received_at
                ts = dt.strftime("%Y-%m-%d %H:%M UTC") if dt else "?"
                sev = Severity.from_str(row.severity)
                await u.message.reply_text(f"{sev.emoji()} *{row.vendor}* — `{sev.label()}`\\n• {row.title}\\n• `{ts}`", parse_mode=ParseMode.MARKDOWN)

        async def _set_sev(self, u, c):
            args = c.args
            if not args or args[0].lower() not in {"low","medium","high","critical"}:
                await u.message.reply_text("Usage: /set_severity low|medium|high|critical"); return
            if self._polling: self._polling.set_threshold(args[0].lower())
            await u.message.reply_text(f"✅ Threshold: `{args[0].upper()}`", parse_mode=ParseMode.MARKDOWN)

        async def _pause(self, u, c):
            if self._polling: self._polling.pause()
            await u.message.reply_text("⏸ Paused.")

        async def _resume(self, u, c):
            if self._polling: self._polling.resume()
            await u.message.reply_text("▶️ Resumed.")

        async def _whoami(self, u, c):
            user = u.effective_user
            if not user: await u.message.reply_text("Cannot identify."); return
            await u.message.reply_text(
                f"👤 *Your Identity*\\n• ID: `{user.id}`\\n• @{user.username or 'none'}\\n• {user.full_name}\\n\\nAdd `{user.id}` to ALLOWED\\\\_TELEGRAM\\\\_USER\\\\_IDS.",
                parse_mode=ParseMode.MARKDOWN)

        async def _unknown(self, u, c): await u.message.reply_text("Unknown command. /help")
""").lstrip()

files["app/api/__init__.py"] = ""

files["app/api/routes.py"] = textwrap.dedent("""
    from __future__ import annotations
    import logging
    from datetime import datetime, UTC
    from typing import Any, Optional
    from fastapi import APIRouter, Depends, HTTPException, Query, Security, status
    from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
    from pydantic import BaseModel
    from sqlalchemy import desc, func, select
    from app.config import Settings, get_settings
    from app.models import SecurityEventORM
    logger = logging.getLogger(__name__)
    router = APIRouter()
    bearer = HTTPBearer(auto_error=True)

    def require_admin(creds: HTTPAuthorizationCredentials = Security(bearer),
                      settings: Settings = Depends(get_settings)):
        if creds.credentials != settings.admin_api_key:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Invalid admin key")

    @router.get("/health")
    async def health(): return {"status":"ok","timestamp":datetime.now(UTC).isoformat()}

    @router.get("/ready")
    async def ready(): return {"ready":True}

    @router.get("/admin/status", dependencies=[Depends(require_admin)])
    async def admin_status(s: Settings = Depends(get_settings)):
        return {"mock_mode":s.mock_mode,"environment":s.environment,
                "trellix_enabled":s.enable_trellix,"paloalto_enabled":s.enable_paloalto,
                "min_severity":s.min_severity,"poll_interval":s.poll_interval_seconds}

    class EventOut(BaseModel):
        id:int; vendor:str; source:str; alert_id:str; severity:str
        title:str; notified:bool; received_at:datetime; detection_time:Optional[datetime]
        model_config={"from_attributes":True}

    @router.get("/admin/events", response_model=list[EventOut], dependencies=[Depends(require_admin)])
    async def admin_events(vendor:str|None=Query(None), severity:str|None=Query(None),
                           limit:int=Query(50,le=500), offset:int=Query(0)):
        from app.config import get_settings
        from app.db import get_session_factory
        s = get_settings()
        async with get_session_factory(s.database_url)() as session:
            stmt = select(SecurityEventORM).order_by(desc(SecurityEventORM.received_at)).limit(limit).offset(offset)
            if vendor: stmt=stmt.where(SecurityEventORM.vendor==vendor)
            if severity: stmt=stmt.where(SecurityEventORM.severity==severity.lower())
            rows = (await session.execute(stmt)).scalars().all()
        return [EventOut.model_validate(r) for r in rows]

    @router.get("/admin/stats", dependencies=[Depends(require_admin)])
    async def admin_stats():
        from app.config import get_settings
        from app.db import get_session_factory
        s = get_settings()
        async with get_session_factory(s.database_url)() as session:
            total = (await session.execute(func.count(SecurityEventORM.id))).scalar() or 0
            notified = (await session.execute(func.count(SecurityEventORM.id).filter(SecurityEventORM.notified==True))).scalar() or 0  # noqa
            by_sev = (await session.execute(select(SecurityEventORM.severity,func.count(SecurityEventORM.id)).group_by(SecurityEventORM.severity))).fetchall()
            by_ven = (await session.execute(select(SecurityEventORM.vendor,func.count(SecurityEventORM.id)).group_by(SecurityEventORM.vendor))).fetchall()
        return {"total":total,"notified":notified,"by_severity":{r[0]:r[1] for r in by_sev},"by_vendor":{r[0]:r[1] for r in by_ven}}

    @router.post("/admin/pause", dependencies=[Depends(require_admin)])
    async def admin_pause():
        from app.main import get_polling_service
        svc = get_polling_service()
        if svc: svc.pause()
        return {"status":"paused"}

    @router.post("/admin/resume", dependencies=[Depends(require_admin)])
    async def admin_resume():
        from app.main import get_polling_service
        svc = get_polling_service()
        if svc: svc.resume()
        return {"status":"resumed"}

    @router.post("/admin/set_severity", dependencies=[Depends(require_admin)])
    async def admin_set_severity(severity:str=Query(...)):
        from app.main import get_polling_service
        if severity.lower() not in {"low","medium","high","critical"}:
            raise HTTPException(400,"Invalid severity")
        svc = get_polling_service()
        if svc: svc.set_threshold(severity)
        return {"severity":severity.lower()}
""").lstrip()

files["app/main.py"] = textwrap.dedent("""
    from __future__ import annotations
    import asyncio, logging, logging.config
    from typing import Optional
    import uvicorn
    from fastapi import FastAPI
    from app.api.routes import router
    from app.collectors.paloalto import PaloAltoCollector
    from app.collectors.trellix import TrellixCollector
    from app.config import Settings, get_settings
    from app.db import get_session_factory, init_db
    from app.notifier.telegram_bot import SocBot
    from app.services.access_control import AccessControl
    from app.services.polling import PollingService
    logger = logging.getLogger(__name__)
    _polling_service: Optional[PollingService] = None

    def get_polling_service(): return _polling_service

    def configure_logging(level):
        logging.config.dictConfig({
            "version":1,"disable_existing_loggers":False,
            "formatters":{"json":{"()":"pythonjsonlogger.jsonlogger.JsonFormatter",
                "format":"%(asctime)s %(name)s %(levelname)s %(message)s"},
                "plain":{"format":"%(asctime)s [%(levelname)s] %(name)s: %(message)s"}},
            "handlers":{"console":{"class":"logging.StreamHandler","stream":"ext://sys.stdout","formatter":"json"}},
            "root":{"handlers":["console"],"level":level},
            "loggers":{"httpx":{"level":"WARNING"},"telegram":{"level":"WARNING"},
                       "uvicorn":{"level":"WARNING"}}})

    def _build_app(settings):
        app = FastAPI(title="Pocket SIEM Admin API", version="1.0.0",
            docs_url="/docs" if settings.environment!="production" else None, redoc_url=None,
            openapi_url="/openapi.json" if settings.environment!="production" else None)
        app.include_router(router)
        return app

    async def main():
        global _polling_service
        settings = get_settings()
        configure_logging(settings.log_level)
        logger.info("Starting Pocket SIEM — %s", settings.masked_repr())
        await init_db(settings.database_url)
        session_factory = get_session_factory(settings.database_url)
        access = AccessControl(set(settings.allowed_telegram_user_ids))
        collectors = []
        if settings.enable_trellix: collectors.append(TrellixCollector(settings))
        if settings.enable_paloalto: collectors.append(PaloAltoCollector(settings))
        if not collectors: logger.warning("No collectors enabled")
        soc_bot = SocBot(settings=settings, access_control=access, session_factory=session_factory)
        bot_app = soc_bot.build_application()
        _polling_service = PollingService(settings=settings, collectors=collectors,
            notify_fn=soc_bot.send_alert, session_factory=session_factory)
        soc_bot._polling = _polling_service
        fastapi_app = _build_app(settings)
        await bot_app.initialize()
        await soc_bot.setup_commands()
        await bot_app.start()
        await bot_app.updater.start_polling(drop_pending_updates=True)
        logger.info("Telegram bot started")
        _polling_service.start()
        config = uvicorn.Config(fastapi_app, host=settings.api_host,
            port=settings.api_port, log_level="warning", loop="none")
        server = uvicorn.Server(config)
        logger.info("FastAPI on %s:%d", settings.api_host, settings.api_port)
        try: await server.serve()
        except (KeyboardInterrupt, asyncio.CancelledError): pass
        finally:
            logger.info("Shutting down…")
            _polling_service.stop()
            await bot_app.updater.stop()
            await bot_app.stop()
            await bot_app.shutdown()

    if __name__ == "__main__":
        asyncio.run(main())
""").lstrip()

# Write all files
for rel_path, content in files.items():
    full_path = os.path.join(DEPLOY_DIR, rel_path)
    os.makedirs(os.path.dirname(full_path), exist_ok=True)
    with open(full_path, "w") as f:
        f.write(content)
print(f"  Written {len(files)} application files")

# ── STAGE 4: Requirements ─────────────────────────────────────────────────────
section("STAGE 4 — Python dependencies")
with open(f"{DEPLOY_DIR}/requirements.txt", "w") as f:
    f.write("\n".join([
        "fastapi>=0.111.0",
        "uvicorn[standard]>=0.29.0",
        "python-telegram-bot>=21.0.0",
        "httpx>=0.27.0",
        "pydantic>=2.7.0",
        "pydantic-settings>=2.2.0",
        "sqlalchemy>=2.0.0",
        "aiosqlite>=0.20.0",
        "asyncpg>=0.29.0",
        "tenacity>=8.2.0",
        "python-json-logger>=2.0.7",
        "python-dotenv>=1.0.0",
    ]))

run(f"python3 -m venv {DEPLOY_DIR}/.venv")
run(f"{DEPLOY_DIR}/.venv/bin/pip install --quiet --upgrade pip")
run(f"{DEPLOY_DIR}/.venv/bin/pip install --quiet -r {DEPLOY_DIR}/requirements.txt")
print("  Dependencies installed")

# ── STAGE 5: .env file ────────────────────────────────────────────────────────
section("STAGE 5 — Environment configuration")
env_content = f"""# Pocket SIEM Configuration — chmod 600
TELEGRAM_BOT_TOKEN={TG_TOKEN}
ALLOWED_TELEGRAM_USER_IDS={TG_USERS}
ADMIN_API_KEY={ADMIN_KEY}
ENABLE_TRELLIX=true
TRELLIX_BASE_URL={TR_URL}
TRELLIX_CLIENT_ID={TR_ID}
TRELLIX_CLIENT_SECRET={TR_SECRET}
TRELLIX_VERIFY_SSL=true
ENABLE_PALOALTO=false
PALOALTO_VSYS=vsys1
PALOALTO_VERIFY_SSL=true
PALOALTO_LOG_COUNT=50
POLL_INTERVAL_SECONDS={INTERVAL}
MIN_SEVERITY={SEVERITY}
MAX_ALERTS_PER_MINUTE=20
DATABASE_URL=sqlite+aiosqlite:///./data/soc_bot.db
API_HOST=127.0.0.1
API_PORT=8080
MOCK_MODE={MOCK}
LOG_LEVEL=INFO
ENVIRONMENT=production
"""
env_path = f"{DEPLOY_DIR}/.env"
with open(env_path, "w") as f:
    f.write(env_content)
os.chmod(env_path, stat.S_IRUSR | stat.S_IWUSR)  # 600
print(f"  .env written at {env_path} (permissions 600)")

# ── STAGE 6: Systemd service ──────────────────────────────────────────────────
section("STAGE 6 — Systemd service")
svc = f"""[Unit]
Description=Pocket SIEM Telegram SOC Monitoring Bot
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
User=root
WorkingDirectory={DEPLOY_DIR}
EnvironmentFile={DEPLOY_DIR}/.env
ExecStart={DEPLOY_DIR}/.venv/bin/python -m app.main
Restart=on-failure
RestartSec=10
TimeoutStopSec=30
StandardOutput=journal
StandardError=journal
SyslogIdentifier=pocket-siem
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths={DEPLOY_DIR}/data
ReadWritePaths={DEPLOY_DIR}

[Install]
WantedBy=multi-user.target
"""
with open("/etc/systemd/system/pocket-siem.service", "w") as f:
    f.write(svc)
run("systemctl daemon-reload")
run("systemctl enable pocket-siem.service")
print("  Systemd service installed and enabled")

# ── STAGE 7: Log rotation ─────────────────────────────────────────────────────
section("STAGE 7 — Log rotation")
with open("/etc/logrotate.d/pocket-siem", "w") as f:
    f.write("/var/log/pocket-siem/*.log {\n    daily\n    missingok\n    rotate 14\n"
            "    compress\n    delaycompress\n    notifempty\n    copytruncate\n}\n")
os.makedirs("/var/log/pocket-siem", exist_ok=True)
print("  Logrotate configured")

# ── STAGE 8: Permissions ──────────────────────────────────────────────────────
section("STAGE 8 — Permissions")
run(f"chown -R root:root {DEPLOY_DIR}")
run(f"chmod 700 {DEPLOY_DIR}")
os.chmod(env_path, stat.S_IRUSR | stat.S_IWUSR)
run(f"chmod -R 755 {DEPLOY_DIR}/app")
run(f"chmod 700 {DEPLOY_DIR}/data")
print("  Permissions set")

# ── STAGE 9: Syntax check ─────────────────────────────────────────────────────
section("STAGE 9 — Smoke test")
result = subprocess.run(
    [f"{DEPLOY_DIR}/.venv/bin/python", "-c",
     "import sys; sys.path.insert(0,'.'); "
     "from app.severity import Severity; from app.models import SecurityEvent; "
     "from app.notifier.formatters import format_event; "
     "e=SecurityEvent(vendor='Trellix',source='test',alert_id='t1',severity='high',title='Test'); "
     "assert e.dedup_hash; assert 'Trellix' in format_event(e); print('Smoke test: PASS')"],
    cwd=DEPLOY_DIR, capture_output=True, text=True)
print(" ", result.stdout.strip() or result.stderr.strip())
if result.returncode != 0:
    print("  WARN:", result.stderr[:300])

# ── STAGE 10: Start service ───────────────────────────────────────────────────
section("STAGE 10 — Start service")
subprocess.run("systemctl start pocket-siem.service", shell=True)
import time; time.sleep(6)
status = subprocess.run("systemctl is-active pocket-siem.service",
    shell=True, capture_output=True, text=True).stdout.strip()
print(f"  Service status: {status}")
if status != "active":
    print("  --- Last 30 log lines ---")
    subprocess.run("journalctl -u pocket-siem -n 30 --no-pager", shell=True)

# ── STAGE 11: Health check ────────────────────────────────────────────────────
section("STAGE 11 — Health check")
time.sleep(4)
try:
    import urllib.request
    resp = urllib.request.urlopen("http://127.0.0.1:8080/health", timeout=8)
    body = resp.read().decode()
    print(f"  FastAPI /health: {body.strip()}")
except Exception as e:
    print(f"  FastAPI /health: not yet ready ({e})")

# ── STAGE 12: Telegram test message ──────────────────────────────────────────
section("STAGE 12 — Telegram test message")
try:
    import urllib.request, urllib.parse, json as _json
    host = "api.telegram.org"
    path = f"/bot{TG_TOKEN}/sendMessage"
    import socket as _s; ip = _s.getaddrinfo(host, 443)[0][4][0]
    msg = f"🧪 *Pocket SIEM deployed!*\n\nServer: pipeline-mgmt\nTime: {__import__('datetime').datetime.now(__import__('datetime').timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n\nSend /status to check bot health."
    data = urllib.parse.urlencode({"chat_id": TG_USERS.split(",")[0].strip(),
                                   "text": msg, "parse_mode": "Markdown"}).encode()
    req = urllib.request.Request(f"https://{host}{path}", data=data)
    resp = urllib.request.urlopen(req, timeout=15)
    body = _json.loads(resp.read())
    if body.get("ok"):
        print("  ✅ Test message sent to Telegram successfully!")
    else:
        print(f"  ⚠️  Telegram response: {body}")
except Exception as e:
    print(f"  ⚠️  Telegram test message: {e}")

# ── Final report ──────────────────────────────────────────────────────────────
section("FINAL DEPLOYMENT REPORT")
import socket
print(f"""
  Hostname  : {socket.gethostname()}
  Directory : {DEPLOY_DIR}
  Service   : {'✅ active' if status == 'active' else '❌ ' + status}
  Admin key : {ADMIN_KEY[:8]}**** (first 8 chars shown)
  .env perms: 600 (root only)

  Useful commands:
    systemctl status pocket-siem
    journalctl -u pocket-siem -f
    curl http://127.0.0.1:8080/health

  To enable mock alerts:
    sed -i 's/MOCK_MODE=false/MOCK_MODE=true/' {DEPLOY_DIR}/.env
    systemctl restart pocket-siem

  Full admin key (save this):
    {ADMIN_KEY}
""")
