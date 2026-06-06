#!/usr/bin/env bash
# =============================================================================
# Pocket SIEM — Production Deployment Script
# Deploys Telegram SOC monitoring bot on a Linux server
# Usage: bash deploy.sh  (credentials injected via environment or .deploy-env)
# =============================================================================
set -euo pipefail
IFS=$'\n\t'

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
info()    { echo -e "${CYAN}[INFO]${RESET} $*"; }
ok()      { echo -e "${GREEN}[OK]${RESET}   $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET} $*"; }
err()     { echo -e "${RED}[ERR]${RESET}  $*" >&2; }
section() { echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════════${RESET}"; \
            echo -e "${BOLD}${CYAN}  $*${RESET}"; \
            echo -e "${BOLD}${CYAN}══════════════════════════════════════════════${RESET}"; }
mask()    { local v="$1"; echo "${v:0:4}****"; }

# ── Load credentials ──────────────────────────────────────────────────────────
if [[ -f /root/pocket-siem/.deploy-env ]]; then
  # shellcheck disable=SC1091
  source /root/pocket-siem/.deploy-env
fi

TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
ALLOWED_TELEGRAM_USER_IDS="${ALLOWED_TELEGRAM_USER_IDS:-}"
ADMIN_API_KEY="${ADMIN_API_KEY:-}"
TRELLIX_CLIENT_ID="${TRELLIX_CLIENT_ID:-}"
TRELLIX_CLIENT_SECRET="${TRELLIX_CLIENT_SECRET:-}"
TRELLIX_API_KEY="${TRELLIX_API_KEY:-}"
TRELLIX_BASE_URL="${TRELLIX_BASE_URL:-https://api.manage.trellix.com}"
PALOALTO_HOSTNAME="${PALOALTO_HOSTNAME:-}"
PALOALTO_API_KEY="${PALOALTO_API_KEY:-}"
MOCK_MODE="${MOCK_MODE:-false}"
POLL_INTERVAL="${POLL_INTERVAL:-60}"
MIN_SEVERITY="${MIN_SEVERITY:-high}"

if [[ -z "$TELEGRAM_BOT_TOKEN" ]]; then
  err "TELEGRAM_BOT_TOKEN is required."; exit 1
fi
if [[ -z "$ALLOWED_TELEGRAM_USER_IDS" ]]; then
  err "ALLOWED_TELEGRAM_USER_IDS is required."; exit 1
fi
if [[ -z "$ADMIN_API_KEY" ]]; then
  ADMIN_API_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
  warn "ADMIN_API_KEY not set — generated: $(mask "$ADMIN_API_KEY")"
fi

DEPLOY_DIR="/opt/pocket-siem"
SERVICE_USER="pocket-siem"
SERVICE_NAME="pocket-siem"
TIMESTAMP=$(date -u +"%Y-%m-%d %H:%M:%S UTC")

# ─────────────────────────────────────────────────────────────────────────────
section "STAGE 0 — Environment Assessment"
# ─────────────────────────────────────────────────────────────────────────────

echo ""
info "OS:"
cat /etc/os-release | grep -E "^(PRETTY_NAME|ID|VERSION_ID)=" | sed 's/^/    /'
uname -r | xargs -I{} echo "    Kernel: {}"

echo ""
info "CPU:"
lscpu | grep -E "^(Model name|CPU\(s\)|Thread)" | sed 's/^/    /'

echo ""
info "RAM:"
free -h | sed 's/^/    /'

echo ""
info "Disk (/):"
df -h / | sed 's/^/    /'

echo ""
info "Running services (top 10 by memory):"
ps aux --sort=-%mem | head -11 | awk '{print "    "$1,$2,$3,$4,$11}' || true

echo ""
info "Firewall status:"
if command -v ufw &>/dev/null; then
  ufw status 2>/dev/null | sed 's/^/    /' || echo "    ufw not active"
elif command -v firewall-cmd &>/dev/null; then
  firewall-cmd --state 2>/dev/null | sed 's/^/    /' || echo "    firewalld not running"
elif command -v iptables &>/dev/null; then
  iptables -L INPUT --line-numbers 2>/dev/null | head -10 | sed 's/^/    /' || echo "    iptables not accessible"
else
  echo "    No firewall tool detected"
fi

echo ""
info "Docker:"
if command -v docker &>/dev/null; then
  docker version --format 'Client: {{.Client.Version}}  Server: {{.Server.Version}}' 2>/dev/null \
    | sed 's/^/    /' || echo "    Docker installed but daemon not running"
  docker compose version 2>/dev/null | sed 's/^/    /' || true
else
  warn "Docker not installed — will install"
  INSTALL_DOCKER=true
fi

echo ""
info "Python:"
python3 --version 2>/dev/null | sed 's/^/    /' || echo "    python3 not found"
pip3 --version 2>/dev/null | sed 's/^/    /' || echo "    pip3 not found"

echo ""
info "Git:"
git --version 2>/dev/null | sed 's/^/    /' || echo "    git not found"

ok "Environment assessment complete"

# ─────────────────────────────────────────────────────────────────────────────
section "STAGE 1 — System Dependencies"
# ─────────────────────────────────────────────────────────────────────────────

export DEBIAN_FRONTEND=noninteractive

info "Updating apt cache…"
apt-get update -qq 2>&1 | tail -2

info "Installing base packages…"
apt-get install -y -qq \
  curl wget git python3 python3-pip python3-venv \
  ca-certificates gnupg lsb-release \
  logrotate jq 2>&1 | tail -3
ok "Base packages installed"

# Install Docker if missing
if [[ "${INSTALL_DOCKER:-false}" == "true" ]] || ! command -v docker &>/dev/null; then
  info "Installing Docker Engine…"
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/$(. /etc/os-release && echo "$ID")/gpg \
    -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
    https://download.docker.com/linux/$(. /etc/os-release && echo "$ID") \
    $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -qq
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  systemctl enable docker
  systemctl start docker
  ok "Docker installed and started"
fi

# Verify docker compose
if ! docker compose version &>/dev/null; then
  err "docker compose not available"; exit 1
fi
ok "Docker Compose available"

# ─────────────────────────────────────────────────────────────────────────────
section "STAGE 2 — Project Directory & Service User"
# ─────────────────────────────────────────────────────────────────────────────

info "Creating service user: $SERVICE_USER"
if ! id "$SERVICE_USER" &>/dev/null; then
  useradd -r -s /sbin/nologin -d "$DEPLOY_DIR" "$SERVICE_USER"
  ok "User $SERVICE_USER created"
else
  ok "User $SERVICE_USER already exists"
fi

# Add service user to docker group
usermod -aG docker "$SERVICE_USER" 2>/dev/null || true

info "Creating project structure at $DEPLOY_DIR…"
mkdir -p "$DEPLOY_DIR"/{app/{notifier,collectors,services,api},data,logs}

# ─────────────────────────────────────────────────────────────────────────────
section "STAGE 3 — Application Code"
# ─────────────────────────────────────────────────────────────────────────────

info "Writing application files…"

# ── app/__init__.py ───────────────────────────────────────────────────────────
touch "$DEPLOY_DIR"/app/__init__.py
touch "$DEPLOY_DIR"/app/notifier/__init__.py
touch "$DEPLOY_DIR"/app/collectors/__init__.py
touch "$DEPLOY_DIR"/app/services/__init__.py
touch "$DEPLOY_DIR"/app/api/__init__.py

# ── app/config.py ─────────────────────────────────────────────────────────────
cat > "$DEPLOY_DIR/app/config.py" << 'PYEOF'
"""Central configuration via pydantic-settings."""
from __future__ import annotations
import re
from functools import lru_cache
from typing import List, Optional
from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8",
        case_sensitive=False, extra="ignore",
    )
    telegram_bot_token: str = Field(...)
    allowed_telegram_user_ids: List[int] = Field(default_factory=list)
    telegram_chat_id: Optional[int] = Field(None)
    enable_trellix: bool = Field(True)
    trellix_base_url: str = Field("https://api.manage.trellix.com")
    trellix_client_id: Optional[str] = Field(None)
    trellix_client_secret: Optional[str] = Field(None)
    trellix_api_key: Optional[str] = Field(None)
    trellix_tenant_id: Optional[str] = Field(None)
    trellix_verify_ssl: bool = Field(True)
    enable_paloalto: bool = Field(True)
    paloalto_hostname: Optional[str] = Field(None)
    paloalto_api_key: Optional[str] = Field(None)
    paloalto_vsys: str = Field("vsys1")
    paloalto_verify_ssl: bool = Field(True)
    paloalto_log_count: int = Field(50, ge=1, le=500)
    poll_interval_seconds: int = Field(60, ge=10)
    min_severity: str = Field("high")
    database_url: str = Field("sqlite+aiosqlite:///./data/soc_bot.db")
    admin_api_key: str = Field(...)
    api_host: str = Field("0.0.0.0")
    api_port: int = Field(8080)
    mock_mode: bool = Field(False)
    max_alerts_per_minute: int = Field(20, ge=1)
    log_level: str = Field("INFO")
    environment: str = Field("production")

    @field_validator("min_severity", mode="before")
    @classmethod
    def normalize_severity(cls, v: str) -> str:
        valid = {"low","medium","high","critical"}
        v = str(v).lower().strip()
        if v not in valid: raise ValueError(f"min_severity must be one of {valid}")
        return v

    @field_validator("allowed_telegram_user_ids", mode="before")
    @classmethod
    def parse_user_ids(cls, v):
        if isinstance(v, list): return [int(i) for i in v]
        if isinstance(v, str):
            parts = re.split(r"[,\s]+", v.strip())
            return [int(p) for p in parts if p]
        return v

    @field_validator("log_level", mode="before")
    @classmethod
    def upper_log_level(cls, v: str) -> str: return str(v).upper()

    @model_validator(mode="after")
    def warn_insecure_tls(self) -> "Settings":
        import warnings
        if not self.trellix_verify_ssl:
            warnings.warn("TRELLIX_VERIFY_SSL=false — TLS verification disabled!", stacklevel=2)
        if not self.paloalto_verify_ssl:
            warnings.warn("PALOALTO_VERIFY_SSL=false — TLS verification disabled!", stacklevel=2)
        return self

    def masked_repr(self) -> str:
        def mask(v): return v[:4]+"****" if v and len(v)>4 else "****"
        return (f"Settings(env={self.environment}, mock={self.mock_mode}, "
                f"trellix={'on' if self.enable_trellix else 'off'}, "
                f"paloalto={'on' if self.enable_paloalto else 'off'}, "
                f"min_severity={self.min_severity})")

@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
PYEOF

# ── app/severity.py ───────────────────────────────────────────────────────────
cat > "$DEPLOY_DIR/app/severity.py" << 'PYEOF'
from __future__ import annotations
from enum import IntEnum
from typing import Optional

class Severity(IntEnum):
    UNKNOWN = 0; INFORMATIONAL = 1; LOW = 2; MEDIUM = 3; HIGH = 4; CRITICAL = 5

    @classmethod
    def from_str(cls, value: Optional[str]) -> "Severity":
        if not value: return cls.UNKNOWN
        mapping = {
            "informational": cls.INFORMATIONAL, "info": cls.INFORMATIONAL,
            "low": cls.LOW, "medium": cls.MEDIUM, "med": cls.MEDIUM,
            "moderate": cls.MEDIUM, "high": cls.HIGH,
            "critical": cls.CRITICAL, "crit": cls.CRITICAL, "fatal": cls.CRITICAL,
            "1": cls.INFORMATIONAL, "2": cls.LOW, "3": cls.MEDIUM,
            "4": cls.HIGH, "5": cls.CRITICAL,
        }
        return mapping.get(str(value).lower().strip(), cls.UNKNOWN)

    def label(self) -> str: return self.name.upper()
    def emoji(self) -> str:
        return {Severity.CRITICAL:"🔴",Severity.HIGH:"🟠",Severity.MEDIUM:"🟡",
                Severity.LOW:"🟢",Severity.INFORMATIONAL:"⚪",Severity.UNKNOWN:"❓"}[self]
    def meets_threshold(self, threshold: "Severity") -> bool: return self >= threshold
PYEOF

# ── app/models.py ─────────────────────────────────────────────────────────────
cat > "$DEPLOY_DIR/app/models.py" << 'PYEOF'
from __future__ import annotations
import hashlib, json
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field, computed_field
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

class BotStateORM(Base):
    __tablename__ = "bot_state"
    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc), nullable=False)

class SecurityEvent(BaseModel):
    vendor: str; source: str; alert_id: str; severity: str; title: str
    detection_time: Optional[datetime] = None
    host: Optional[str] = None; username: Optional[str] = None
    process_name: Optional[str] = None; command_line: Optional[str] = None
    tactic: Optional[str] = None; technique: Optional[str] = None; status: Optional[str] = None
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

    def to_orm(self) -> SecurityEventORM:
        raw = json.dumps(self.raw_json, default=str) if self.raw_json else None
        return SecurityEventORM(vendor=self.vendor, source=self.source,
            alert_id=self.alert_id, dedup_hash=self.dedup_hash,
            severity=self.severity, title=self.title, raw_json=raw,
            detection_time=self.detection_time)
PYEOF

# ── app/normalizer.py ─────────────────────────────────────────────────────────
cat > "$DEPLOY_DIR/app/normalizer.py" << 'PYEOF'
from __future__ import annotations
from datetime import datetime, timezone, UTC
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
    mapping = {"critical":"critical","high":"high","medium":"medium","low":"low",
               "informational":"informational","info":"informational",
               "5":"critical","4":"high","3":"medium","2":"low","1":"informational"}
    return mapping.get(str(value).lower().strip(), "unknown")

def truncate(value: Optional[str], length: int = 200) -> Optional[str]:
    if not value: return value
    return value[:length]+"…" if len(value) > length else value
PYEOF

# ── app/db.py ─────────────────────────────────────────────────────────────────
cat > "$DEPLOY_DIR/app/db.py" << 'PYEOF'
from __future__ import annotations
import logging, os
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from app.models import Base
logger = logging.getLogger(__name__)
_engine = None
_session_factory = None

def _ensure_data_dir(url: str) -> None:
    if url.startswith("sqlite"):
        path = url.split("///", 1)[-1]
        dir_path = os.path.dirname(path)
        if dir_path and dir_path not in (".", ""):
            os.makedirs(dir_path, exist_ok=True)

def get_engine(database_url: str):
    global _engine
    if _engine is None:
        _ensure_data_dir(database_url)
        connect_args = {"check_same_thread": False} if "sqlite" in database_url else {}
        _engine = create_async_engine(database_url, echo=False,
            connect_args=connect_args, pool_pre_ping=True)
        logger.info("Database engine created: %s", database_url.split("@")[-1])
    return _engine

def get_session_factory(database_url: str):
    global _session_factory
    if _session_factory is None:
        engine = get_engine(database_url)
        _session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    return _session_factory

async def init_db(database_url: str) -> None:
    engine = get_engine(database_url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database schema initialised")

async def get_session(database_url: str) -> AsyncGenerator[AsyncSession, None]:
    factory = get_session_factory(database_url)
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
PYEOF

# ── app/collectors/base.py ────────────────────────────────────────────────────
cat > "$DEPLOY_DIR/app/collectors/base.py" << 'PYEOF'
from __future__ import annotations
import abc, logging
from datetime import datetime, UTC
from typing import List, Optional
from app.models import SecurityEvent
logger = logging.getLogger(__name__)

class BaseCollector(abc.ABC):
    name: str = "base"
    def __init__(self) -> None: self._last_poll: Optional[datetime] = None

    @abc.abstractmethod
    async def fetch_events(self, since: Optional[datetime] = None) -> List[SecurityEvent]: ...

    @abc.abstractmethod
    async def health_check(self) -> bool: ...

    async def poll(self) -> List[SecurityEvent]:
        since = self._last_poll
        logger.debug("%s: polling since %s", self.name, since)
        events = await self.fetch_events(since=since)
        self._last_poll = datetime.now(UTC)
        logger.info("%s: fetched %d events", self.name, len(events))
        return events
PYEOF

# ── app/collectors/trellix.py ─────────────────────────────────────────────────
cat > "$DEPLOY_DIR/app/collectors/trellix.py" << 'PYEOF'
from __future__ import annotations
import logging, random, string, uuid
from datetime import datetime, timedelta, UTC
from typing import Any, Dict, List, Optional
import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential
from app.collectors.base import BaseCollector
from app.config import Settings
from app.models import SecurityEvent
from app.normalizer import parse_datetime, safe_str, truncate
logger = logging.getLogger(__name__)

_OAUTH_URL = "https://iam.mcafee-cloud.com/iam/v1.1/token"
MOCK_TACTICS = ["Execution","Persistence","Privilege Escalation","Defense Evasion",
                "Credential Access","Lateral Movement","Exfiltration","Command and Control"]
MOCK_TECHNIQUES = ["T1059.001","T1055","T1078","T1003","T1021.002","T1486","T1566.001"]
MOCK_PROCESSES = ["powershell.exe","cmd.exe","wscript.exe","mshta.exe","rundll32.exe"]
MOCK_SEVERITIES = ["high","critical","high","critical","medium"]

class TrellixCollector(BaseCollector):
    name = "trellix"
    def __init__(self, settings: Settings) -> None:
        super().__init__()
        self._settings = settings
        self._token: Optional[str] = None
        self._token_expiry: Optional[datetime] = None
        self._client: Optional[httpx.AsyncClient] = None

    def _build_client(self) -> httpx.AsyncClient:
        headers: Dict[str, str] = {"Accept":"application/json","Content-Type":"application/json"}
        if self._settings.trellix_api_key:
            headers["x-api-key"] = self._settings.trellix_api_key
        return httpx.AsyncClient(base_url=self._settings.trellix_base_url,
            headers=headers, verify=self._settings.trellix_verify_ssl, timeout=30.0)

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None: self._client = self._build_client()
        return self._client

    @retry(retry=retry_if_exception_type((httpx.TransportError,httpx.TimeoutException)),
           wait=wait_exponential(multiplier=1,min=2,max=30), stop=stop_after_attempt(4), reraise=True)
    async def _refresh_token(self) -> None:
        if not (self._settings.trellix_client_id and self._settings.trellix_client_secret): return
        async with httpx.AsyncClient(verify=self._settings.trellix_verify_ssl, timeout=20.0) as client:
            resp = await client.post(_OAUTH_URL, data={
                "grant_type":"client_credentials",
                "client_id":self._settings.trellix_client_id,
                "client_secret":self._settings.trellix_client_secret,
                "scope":"edr.dashboard.read edr.alert.read"})
            resp.raise_for_status()
            data = resp.json()
            self._token = data["access_token"]
            expires_in = int(data.get("expires_in", 3600))
            self._token_expiry = datetime.now(UTC) + timedelta(seconds=expires_in-60)
            logger.debug("Trellix OAuth2 token refreshed")

    async def _ensure_token(self) -> None:
        if not self._token or (self._token_expiry and datetime.now(UTC) >= self._token_expiry):
            await self._refresh_token()

    @retry(retry=retry_if_exception_type((httpx.TransportError,httpx.TimeoutException)),
           wait=wait_exponential(multiplier=1,min=2,max=30), stop=stop_after_attempt(4), reraise=True)
    async def _get_alerts(self, since: Optional[datetime]) -> List[Dict[str, Any]]:
        await self._ensure_token()
        client = await self._get_client()
        params: Dict[str, Any] = {"limit":100,"offset":0}
        if since: params["since"] = since.strftime("%Y-%m-%dT%H:%M:%SZ")
        if self._token: client.headers["Authorization"] = f"Bearer {self._token}"
        resp = await client.get("/edr/v2/alerts", params=params)
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, list): return data
        return data.get("data", data.get("alerts", data.get("items",[])))

    async def fetch_events(self, since: Optional[datetime] = None) -> List[SecurityEvent]:
        if self._settings.mock_mode: return self._generate_mock_events()
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
        if self._settings.mock_mode: return True
        try:
            await self._ensure_token()
            client = await self._get_client()
            if self._token: client.headers["Authorization"] = f"Bearer {self._token}"
            resp = await client.get("/edr/v2/alerts", params={"limit":1})
            return resp.status_code < 500
        except Exception as exc:
            logger.warning("Trellix health check failed: %s", exc)
            return False

    def _normalize(self, raw: Dict[str, Any]) -> SecurityEvent:
        attrs = raw.get("attributes", raw)
        alert_id = str(raw.get("id") or attrs.get("id") or attrs.get("alertId") or uuid.uuid4())
        return SecurityEvent(
            vendor="Trellix", source="Trellix EDR", alert_id=alert_id,
            severity=str(attrs.get("severity", attrs.get("threatSeverity","unknown"))).lower(),
            title=str(attrs.get("name", attrs.get("title", attrs.get("threatName","Trellix Alert")))),
            host=safe_str(attrs.get("hostname", attrs.get("host", attrs.get("deviceName")))),
            username=safe_str(attrs.get("userName", attrs.get("username", attrs.get("user")))),
            process_name=safe_str(attrs.get("processName", attrs.get("process", attrs.get("fileName")))),
            command_line=truncate(safe_str(attrs.get("commandLine", attrs.get("cmdLine")))),
            tactic=safe_str(attrs.get("tactic", attrs.get("mitreTactic"))),
            technique=safe_str(attrs.get("technique", attrs.get("mitreAttack", attrs.get("mitreId")))),
            status=safe_str(attrs.get("status", attrs.get("state", attrs.get("alertStatus")))),
            detection_time=parse_datetime(attrs.get("detectionDate", attrs.get("createdAt", attrs.get("timestamp")))),
            raw_json=raw)

    def _generate_mock_events(self) -> List[SecurityEvent]:
        events = []
        for _ in range(random.randint(1,3)):
            uid = uuid.uuid4().hex[:8]
            events.append(SecurityEvent(
                vendor="Trellix", source="Trellix EDR (mock)",
                alert_id=f"mock-trellix-{uid}",
                severity=random.choice(MOCK_SEVERITIES),
                title=f"[MOCK] Suspicious {random.choice(MOCK_PROCESSES)} — {random.choice(MOCK_TACTICS)}",
                host=f"WORKSTATION-{''.join(random.choices(string.ascii_uppercase,k=4))}",
                username=f"user_{''.join(random.choices(string.ascii_lowercase,k=5))}",
                process_name=random.choice(MOCK_PROCESSES),
                command_line=f"{random.choice(MOCK_PROCESSES)} -EncodedCommand {uuid.uuid4().hex}",
                tactic=random.choice(MOCK_TACTICS),
                technique=random.choice(MOCK_TECHNIQUES),
                status="New",
                detection_time=datetime.now(UTC),
                raw_json={"mock":True,"id":uid}))
        return events
PYEOF

# ── app/collectors/paloalto.py ────────────────────────────────────────────────
cat > "$DEPLOY_DIR/app/collectors/paloalto.py" << 'PYEOF'
from __future__ import annotations
import logging, random, uuid, xml.etree.ElementTree as ET
from datetime import datetime, UTC
from typing import Any, Dict, List, Optional
import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential
from app.collectors.base import BaseCollector
from app.config import Settings
from app.models import SecurityEvent
from app.normalizer import map_panos_severity, parse_datetime, safe_str, truncate
logger = logging.getLogger(__name__)

MOCK_THREATS = ["CVE-2021-44228 Log4j RCE","Emotet Dropper","Cobalt Strike Beacon C2",
                "Mimikatz Credential Dump","RDP Brute Force","DNS Tunneling",
                "SQL Injection Attempt","Ransomware Beacon"]
MOCK_APPS = ["web-browsing","ssl","dns","smtp","ftp","ssh","rdp"]
MOCK_TYPES = ["vulnerability","wildfire-virus","spyware","url"]

class PaloAltoCollector(BaseCollector):
    name = "paloalto"
    def __init__(self, settings: Settings) -> None:
        super().__init__()
        self._settings = settings
        self._client: Optional[httpx.AsyncClient] = None

    def _build_client(self) -> httpx.AsyncClient:
        if not self._settings.paloalto_hostname:
            raise ValueError("PALOALTO_HOSTNAME is not configured")
        return httpx.AsyncClient(
            base_url=f"https://{self._settings.paloalto_hostname}",
            verify=self._settings.paloalto_verify_ssl, timeout=30.0,
            headers={"X-PAN-KEY": self._settings.paloalto_api_key or ""})

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None: self._client = self._build_client()
        return self._client

    def _build_query(self, since: Optional[datetime]) -> str:
        if since: return f"(receive_time geq '{since.strftime('%Y/%m/%d %H:%M:%S')}')"
        return "(severity geq high)"

    @retry(retry=retry_if_exception_type((httpx.TransportError,httpx.TimeoutException)),
           wait=wait_exponential(multiplier=1,min=2,max=30), stop=stop_after_attempt(4), reraise=True)
    async def _query_logs(self, log_type: str, since: Optional[datetime]) -> List[Dict[str,Any]]:
        client = await self._get_client()
        resp = await client.get("/api/", params={"type":"log","log-type":log_type,
            "nlogs":str(self._settings.paloalto_log_count),
            "query":self._build_query(since),
            "key":self._settings.paloalto_api_key or ""})
        resp.raise_for_status()
        return self._parse_xml_logs(resp.text, log_type)

    def _parse_xml_logs(self, xml_text: str, log_type: str) -> List[Dict[str,Any]]:
        results = []
        try:
            root = ET.fromstring(xml_text)
            if root.get("status","") != "success":
                logger.warning("PAN-OS returned non-success: %s", root.findtext(".//msg"))
                return []
            for entry in root.findall(".//entry"):
                record: Dict[str,Any] = {"_log_type": log_type}
                for child in entry: record[child.tag] = child.text
                results.append(record)
        except ET.ParseError as exc:
            logger.error("XML parse error from PAN-OS: %s", exc)
        return results

    async def fetch_events(self, since: Optional[datetime] = None) -> List[SecurityEvent]:
        if self._settings.mock_mode: return self._generate_mock_events()
        if not self._settings.paloalto_hostname:
            logger.warning("Palo Alto polling skipped — PALOALTO_HOSTNAME not set")
            return []
        events = []
        for log_type in ("threat","wildfire"):
            try:
                records = await self._query_logs(log_type, since)
                events.extend(self._normalize(r) for r in records)
            except Exception as exc:
                logger.error("PAN-OS %s fetch error: %s", log_type, exc)
        return events

    async def health_check(self) -> bool:
        if self._settings.mock_mode: return True
        if not self._settings.paloalto_hostname: return False
        try:
            client = await self._get_client()
            resp = await client.get("/api/", params={"type":"op",
                "cmd":"<show><system><info></info></system></show>",
                "key":self._settings.paloalto_api_key or ""})
            return resp.status_code == 200
        except Exception as exc:
            logger.warning("PAN-OS health check failed: %s", exc)
            return False

    def _normalize(self, raw: Dict[str,Any]) -> SecurityEvent:
        log_type = raw.get("_log_type","threat")
        log_id = str(raw.get("seqno") or raw.get("logid") or uuid.uuid4())
        try: dst_port = int(raw.get("dport") or raw.get("dstport") or 0) or None
        except: dst_port = None
        return SecurityEvent(
            vendor="PaloAlto", source=f"PAN-OS {log_type}",
            alert_id=f"pa-{log_type}-{log_id}",
            severity=map_panos_severity(raw.get("severity","unknown")),
            title=f"{safe_str(raw.get('threatid',raw.get('threat','Threat')))} — {log_type}",
            threat_name=safe_str(raw.get("threatid",raw.get("threat",raw.get("app")))),
            threat_type=safe_str(raw.get("type",log_type)),
            source_ip=safe_str(raw.get("src",raw.get("srcip"))),
            source_user=safe_str(raw.get("srcuser",raw.get("src_user"))),
            destination_ip=safe_str(raw.get("dst",raw.get("dstip"))),
            destination_port=dst_port,
            application=safe_str(raw.get("app",raw.get("application"))),
            action=safe_str(raw.get("action",raw.get("action_flags"))),
            rule=safe_str(raw.get("rule",raw.get("rulename"))),
            url_or_domain=truncate(safe_str(raw.get("misc",raw.get("url",raw.get("domain"))))),
            detection_time=parse_datetime(raw.get("receive_time",raw.get("time_received"))),
            raw_json=raw)

    def _generate_mock_events(self) -> List[SecurityEvent]:
        events = []
        for _ in range(random.randint(1,2)):
            uid = uuid.uuid4().hex[:8]
            events.append(SecurityEvent(
                vendor="PaloAlto", source="PAN-OS threat (mock)",
                alert_id=f"mock-pa-{uid}",
                severity=random.choice(["high","critical","high"]),
                title=f"[MOCK] {random.choice(MOCK_THREATS)}",
                threat_name=random.choice(MOCK_THREATS),
                threat_type=random.choice(MOCK_TYPES),
                source_ip=f"10.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
                destination_ip=f"203.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
                destination_port=random.choice([80,443,8080,4444,22]),
                application=random.choice(MOCK_APPS),
                action=random.choice(["alert","block","drop"]),
                rule=f"Internet-{random.choice(MOCK_TYPES)}-block",
                url_or_domain=f"malicious-{uid}.example.com",
                detection_time=datetime.now(UTC),
                raw_json={"mock":True,"id":uid}))
        return events
PYEOF

# ── app/services/dedupe.py ────────────────────────────────────────────────────
cat > "$DEPLOY_DIR/app/services/dedupe.py" << 'PYEOF'
from __future__ import annotations
import logging
from datetime import datetime, UTC
from typing import List
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models import SecurityEvent, SecurityEventORM
logger = logging.getLogger(__name__)

async def filter_new_events(session: AsyncSession, events: List[SecurityEvent]) -> List[SecurityEvent]:
    if not events: return []
    hashes = [e.dedup_hash for e in events]
    result = await session.execute(select(SecurityEventORM.dedup_hash)
        .where(SecurityEventORM.dedup_hash.in_(hashes)))
    known = {row[0] for row in result.fetchall()}
    new = [e for e in events if e.dedup_hash not in known]
    logger.debug("Dedup: %d total, %d known, %d new", len(events), len(known), len(new))
    return new

async def mark_event_stored(session: AsyncSession, event: SecurityEvent) -> SecurityEventORM:
    orm = event.to_orm()
    session.add(orm)
    await session.flush()
    return orm

async def mark_event_notified(session: AsyncSession, orm_id: int) -> None:
    result = await session.execute(select(SecurityEventORM).where(SecurityEventORM.id == orm_id))
    row = result.scalar_one_or_none()
    if row:
        row.notified = True
        row.notified_at = datetime.now(UTC)
PYEOF

# ── app/services/access_control.py ───────────────────────────────────────────
cat > "$DEPLOY_DIR/app/services/access_control.py" << 'PYEOF'
from __future__ import annotations
import logging
from typing import Set
from telegram import Update
logger = logging.getLogger(__name__)

class AccessControl:
    def __init__(self, allowed_ids: Set[int]) -> None:
        self._allowed: Set[int] = allowed_ids

    def is_allowed(self, user_id: int) -> bool: return user_id in self._allowed

    def check(self, update: Update) -> bool:
        if update.effective_user is None: return False
        uid = update.effective_user.id
        if uid not in self._allowed:
            logger.warning("Denied access attempt from user_id=%d username=%s",
                uid, update.effective_user.username)
            return False
        return True

    def add_user(self, user_id: int) -> None:
        self._allowed.add(user_id)
        logger.info("Access granted to user_id=%d", user_id)

    def remove_user(self, user_id: int) -> None:
        self._allowed.discard(user_id)

    def list_users(self) -> Set[int]: return set(self._allowed)
PYEOF

# ── app/services/polling.py ───────────────────────────────────────────────────
cat > "$DEPLOY_DIR/app/services/polling.py" << 'PYEOF'
from __future__ import annotations
import asyncio, logging
from collections.abc import Callable, Coroutine
from datetime import datetime, UTC
from typing import Optional
from app.collectors.base import BaseCollector
from app.config import Settings
from app.models import SecurityEvent
from app.services.dedupe import filter_new_events, mark_event_notified, mark_event_stored
from app.severity import Severity
logger = logging.getLogger(__name__)
NotifyFn = Callable[[SecurityEvent], Coroutine]

class PollingService:
    def __init__(self, settings: Settings, collectors: list[BaseCollector],
                 notify_fn: NotifyFn, session_factory) -> None:
        self._settings = settings
        self._collectors = collectors
        self._notify_fn = notify_fn
        self._session_factory = session_factory
        self._paused = False
        self._running = False
        self._task: asyncio.Task | None = None
        self._threshold = Severity.from_str(settings.min_severity)
        self._sent_this_minute = 0
        self._minute_start = datetime.now(UTC)

    @property
    def paused(self) -> bool: return self._paused
    def pause(self) -> None: self._paused = True; logger.info("Polling paused")
    def resume(self) -> None: self._paused = False; logger.info("Polling resumed")

    def set_threshold(self, severity_str: str) -> bool:
        try:
            self._threshold = Severity.from_str(severity_str)
            logger.info("Severity threshold updated to %s", self._threshold.label())
            return True
        except Exception: return False

    def start(self) -> None:
        if not self._running:
            self._running = True
            self._task = asyncio.create_task(self._loop(), name="polling_loop")
            logger.info("Polling loop started (interval=%ds)", self._settings.poll_interval_seconds)

    def stop(self) -> None:
        self._running = False
        if self._task and not self._task.done(): self._task.cancel()

    async def _loop(self) -> None:
        while self._running:
            try: await self._tick()
            except asyncio.CancelledError: break
            except Exception as exc: logger.exception("Polling loop error: %s", exc)
            await asyncio.sleep(self._settings.poll_interval_seconds)

    async def _tick(self) -> None:
        if self._paused: return
        for collector in self._collectors:
            try:
                events = await collector.poll()
                await self._process_events(events)
            except Exception as exc:
                logger.error("Collector %s error: %s", collector.name, exc)

    def _rate_ok(self) -> bool:
        now = datetime.now(UTC)
        if (now - self._minute_start).total_seconds() >= 60:
            self._minute_start = now
            self._sent_this_minute = 0
        return self._sent_this_minute < self._settings.max_alerts_per_minute

    async def _process_events(self, events: list[SecurityEvent]) -> None:
        if not events: return
        qualifying = [e for e in events
            if Severity.from_str(e.severity).meets_threshold(self._threshold)]
        if not qualifying: return
        async with self._session_factory() as session:
            try:
                new_events = await filter_new_events(session, qualifying)
                for event in new_events:
                    orm = await mark_event_stored(session, event)
                    await session.commit()
                    if not self._rate_ok():
                        logger.warning("Rate limit reached — dropping event %s", event.alert_id)
                        continue
                    try:
                        await self._notify_fn(event)
                        self._sent_this_minute += 1
                        await mark_event_notified(session, orm.id)
                        await session.commit()
                    except Exception as exc:
                        logger.error("Failed to notify event %s: %s", event.alert_id, exc)
            except Exception as exc:
                logger.error("DB error: %s", exc)
                await session.rollback()
PYEOF

# ── app/notifier/formatters.py ────────────────────────────────────────────────
cat > "$DEPLOY_DIR/app/notifier/formatters.py" << 'PYEOF'
from __future__ import annotations
from typing import Optional
from app.models import SecurityEvent
from app.severity import Severity

def _fmt(label: str, value: Optional[str]) -> str:
    return f"• *{label}:* {value}\n" if value else ""

def _dt(event: SecurityEvent) -> str:
    if event.detection_time: return event.detection_time.strftime("%Y-%m-%d %H:%M:%S UTC")
    return "Unknown"

def format_trellix(event: SecurityEvent) -> str:
    sev = Severity.from_str(event.severity)
    return (f"🚨 *Trellix EDR Alert* {sev.emoji()}\n"
            f"• *Severity:* `{sev.label()}`\n"
            + _fmt("Host", event.host) + _fmt("User", event.username)
            + _fmt("Detection", event.title) + _fmt("Process", event.process_name)
            + _fmt("Command", event.command_line)
            + _fmt("MITRE", f"{event.tactic} / {event.technique}"
                   if event.tactic or event.technique else None)
            + _fmt("Status", event.status)
            + f"• *Time:* `{_dt(event)}`\n")

def format_paloalto(event: SecurityEvent) -> str:
    sev = Severity.from_str(event.severity)
    dst = event.destination_ip
    if dst and event.destination_port: dst = f"{dst}:{event.destination_port}"
    return (f"🔥 *Palo Alto Threat Alert* {sev.emoji()}\n"
            f"• *Severity:* `{sev.label()}`\n"
            + _fmt("Threat", event.threat_name or event.title)
            + _fmt("Type", event.threat_type) + _fmt("Source", event.source_ip)
            + _fmt("Destination", dst) + _fmt("User", event.source_user)
            + _fmt("App", event.application) + _fmt("Action", event.action)
            + _fmt("Rule", event.rule) + _fmt("URL/Domain", event.url_or_domain)
            + f"• *Time:* `{_dt(event)}`\n")

def format_event(event: SecurityEvent) -> str:
    if event.vendor.lower().startswith("trellix"): return format_trellix(event)
    if event.vendor.lower().startswith("palo"): return format_paloalto(event)
    sev = Severity.from_str(event.severity)
    return (f"⚠️ *Security Alert* {sev.emoji()}\n"
            f"• *Vendor:* {event.vendor}\n"
            f"• *Severity:* `{sev.label()}`\n"
            f"• *Title:* {event.title}\n"
            f"• *Time:* `{_dt(event)}`\n")
PYEOF

# ── app/notifier/telegram_bot.py ──────────────────────────────────────────────
cat > "$DEPLOY_DIR/app/notifier/telegram_bot.py" << 'PYEOF'
from __future__ import annotations
import logging
from datetime import datetime
from typing import List, Optional
from sqlalchemy import desc, select
from telegram import BotCommand, Update
from telegram.constants import ParseMode
from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters
from app.config import Settings
from app.models import SecurityEvent, SecurityEventORM
from app.notifier.formatters import format_event
from app.services.access_control import AccessControl
from app.severity import Severity
logger = logging.getLogger(__name__)

def _guard(access: AccessControl):
    def decorator(fn):
        async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE):
            if not access.check(update):
                await update.effective_message.reply_text(
                    "⛔ Access denied. Use /whoami to find your Telegram ID.")
                return
            return await fn(update, context)
        wrapper.__name__ = fn.__name__
        return wrapper
    return decorator

class SocBot:
    def __init__(self, settings: Settings, access_control: AccessControl,
                 session_factory, polling_service=None) -> None:
        self._settings = settings
        self._access = access_control
        self._session_factory = session_factory
        self._polling = polling_service
        self._app: Application | None = None

    def _guard(self, fn): return _guard(self._access)(fn)

    def build_application(self) -> Application:
        app = Application.builder().token(self._settings.telegram_bot_token).build()
        g = self._guard
        app.add_handler(CommandHandler("start",    g(self._cmd_start)))
        app.add_handler(CommandHandler("help",     g(self._cmd_help)))
        app.add_handler(CommandHandler("status",   g(self._cmd_status)))
        app.add_handler(CommandHandler("health",   g(self._cmd_health)))
        app.add_handler(CommandHandler("sources",  g(self._cmd_sources)))
        app.add_handler(CommandHandler("recent",         g(self._cmd_recent)))
        app.add_handler(CommandHandler("recent_trellix", g(self._cmd_recent_trellix)))
        app.add_handler(CommandHandler("recent_paloalto",g(self._cmd_recent_paloalto)))
        app.add_handler(CommandHandler("critical", g(self._cmd_critical)))
        app.add_handler(CommandHandler("set_severity", g(self._cmd_set_severity)))
        app.add_handler(CommandHandler("pause",    g(self._cmd_pause)))
        app.add_handler(CommandHandler("resume",   g(self._cmd_resume)))
        app.add_handler(CommandHandler("whoami",   self._cmd_whoami))
        app.add_handler(MessageHandler(filters.COMMAND, g(self._cmd_unknown)))
        self._app = app
        return app

    async def setup_commands(self) -> None:
        if not self._app: return
        await self._app.bot.set_my_commands([
            BotCommand("start","Welcome message"),
            BotCommand("help","List all commands"),
            BotCommand("status","Bot and poller status"),
            BotCommand("health","Upstream API health"),
            BotCommand("sources","Configured data sources"),
            BotCommand("recent","Last 5 alerts (all sources)"),
            BotCommand("recent_trellix","Last 5 Trellix alerts"),
            BotCommand("recent_paloalto","Last 5 Palo Alto alerts"),
            BotCommand("critical","Last 5 CRITICAL events"),
            BotCommand("set_severity","Set min severity"),
            BotCommand("pause","Pause notifications"),
            BotCommand("resume","Resume notifications"),
            BotCommand("whoami","Show your Telegram user ID"),
        ])

    async def send_alert(self, event: SecurityEvent) -> None:
        if not self._app:
            logger.error("Bot not initialised")
            return
        text = format_event(event)
        targets: list[int] = []
        if self._settings.telegram_chat_id:
            targets.append(self._settings.telegram_chat_id)
        else:
            targets.extend(self._access.list_users())
        for chat_id in targets:
            try:
                await self._app.bot.send_message(chat_id=chat_id, text=text,
                    parse_mode=ParseMode.MARKDOWN)
            except Exception as exc:
                logger.error("Failed to send alert to %d: %s", chat_id, exc)

    async def _cmd_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        await update.message.reply_text(
            "👋 *Pocket SIEM Bot* is running!\nUse /help for commands.",
            parse_mode=ParseMode.MARKDOWN)

    async def _cmd_help(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        await update.message.reply_text(
            "*Commands*\n/status /health /sources\n"
            "/recent /recent\\_trellix /recent\\_paloalto /critical\n"
            "/set\\_severity high|critical|medium|low\n"
            "/pause /resume /whoami",
            parse_mode=ParseMode.MARKDOWN)

    async def _cmd_status(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        paused = self._polling.paused if self._polling else False
        threshold = self._polling._threshold.label() if self._polling else self._settings.min_severity.upper()
        mock = "🟡 MOCK" if self._settings.mock_mode else "🟢 Live"
        await update.message.reply_text(
            f"*Bot Status*\n• Mode: {mock}\n"
            f"• Polling: {'⏸ Paused' if paused else '▶️ Active'}\n"
            f"• Min severity: `{threshold}`\n"
            f"• Interval: `{self._settings.poll_interval_seconds}s`\n"
            f"• Trellix: {'✅' if self._settings.enable_trellix else '❌'}\n"
            f"• Palo Alto: {'✅' if self._settings.enable_paloalto else '❌'}",
            parse_mode=ParseMode.MARKDOWN)

    async def _cmd_health(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        from app.collectors.paloalto import PaloAltoCollector
        from app.collectors.trellix import TrellixCollector
        lines = ["*Health Check*\n"]
        if self._settings.enable_trellix:
            ok = await TrellixCollector(self._settings).health_check()
            lines.append(f"• Trellix EDR: {'✅ OK' if ok else '❌ Unreachable'}")
        if self._settings.enable_paloalto:
            ok = await PaloAltoCollector(self._settings).health_check()
            lines.append(f"• Palo Alto: {'✅ OK' if ok else '❌ Unreachable'}")
        await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.MARKDOWN)

    async def _cmd_sources(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        lines = ["*Sources*\n"]
        if self._settings.enable_trellix:
            lines.append(f"• Trellix: `{self._settings.trellix_base_url}`")
        if self._settings.enable_paloalto:
            lines.append(f"• Palo Alto: `{self._settings.paloalto_hostname or 'not set'}`")
        await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.MARKDOWN)

    async def _cmd_recent(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        await self._send_recent(update)

    async def _cmd_recent_trellix(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        await self._send_recent(update, vendor="Trellix")

    async def _cmd_recent_paloalto(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        await self._send_recent(update, vendor="PaloAlto")

    async def _cmd_critical(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        await self._send_recent(update, severity="critical")

    async def _send_recent(self, update: Update, vendor: Optional[str] = None,
                           limit: int = 5, severity: Optional[str] = None) -> None:
        async with self._session_factory() as session:
            stmt = select(SecurityEventORM).order_by(desc(SecurityEventORM.received_at)).limit(limit)
            if vendor: stmt = stmt.where(SecurityEventORM.vendor == vendor)
            if severity: stmt = stmt.where(SecurityEventORM.severity == severity)
            result = await session.execute(stmt)
            rows = result.scalars().all()
        if not rows:
            await update.message.reply_text("No events found."); return
        for row in rows:
            dt = row.detection_time or row.received_at
            ts = dt.strftime("%Y-%m-%d %H:%M UTC") if dt else "unknown"
            sev = Severity.from_str(row.severity)
            await update.message.reply_text(
                f"{sev.emoji()} *{row.vendor}* — `{sev.label()}`\n• {row.title}\n• `{ts}`",
                parse_mode=ParseMode.MARKDOWN)

    async def _cmd_set_severity(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        args = context.args
        if not args or args[0].lower() not in {"low","medium","high","critical"}:
            await update.message.reply_text("Usage: /set_severity low|medium|high|critical"); return
        if self._polling: self._polling.set_threshold(args[0].lower())
        await update.message.reply_text(f"✅ Threshold: `{args[0].upper()}`",
            parse_mode=ParseMode.MARKDOWN)

    async def _cmd_pause(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        if self._polling: self._polling.pause()
        await update.message.reply_text("⏸ Paused. Use /resume to re-enable.")

    async def _cmd_resume(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        if self._polling: self._polling.resume()
        await update.message.reply_text("▶️ Resumed.")

    async def _cmd_whoami(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        user = update.effective_user
        if not user: await update.message.reply_text("Cannot identify user."); return
        await update.message.reply_text(
            f"👤 *Your Identity*\n• ID: `{user.id}`\n• Username: @{user.username or 'none'}\n"
            f"• Name: {user.full_name}\n\nAdd your ID (`{user.id}`) to `ALLOWED_TELEGRAM_USER_IDS`.",
            parse_mode=ParseMode.MARKDOWN)

    async def _cmd_unknown(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        await update.message.reply_text("Unknown command. Use /help.")
PYEOF

# ── app/api/routes.py ─────────────────────────────────────────────────────────
cat > "$DEPLOY_DIR/app/api/routes.py" << 'PYEOF'
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

def require_admin(credentials: HTTPAuthorizationCredentials = Security(bearer),
                  settings: Settings = Depends(get_settings)) -> None:
    if credentials.credentials != settings.admin_api_key:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Invalid admin API key")

@router.get("/health", tags=["public"])
async def health() -> dict[str, Any]:
    return {"status":"ok","timestamp":datetime.now(UTC).isoformat()}

@router.get("/ready", tags=["public"])
async def ready() -> dict[str, Any]: return {"ready":True}

@router.get("/admin/status", tags=["admin"], dependencies=[Depends(require_admin)])
async def admin_status(settings: Settings = Depends(get_settings)) -> dict[str, Any]:
    return {"mock_mode":settings.mock_mode,"environment":settings.environment,
            "trellix_enabled":settings.enable_trellix,"paloalto_enabled":settings.enable_paloalto,
            "min_severity":settings.min_severity,"poll_interval_seconds":settings.poll_interval_seconds}

class EventOut(BaseModel):
    id: int; vendor: str; source: str; alert_id: str; severity: str
    title: str; notified: bool; received_at: datetime; detection_time: Optional[datetime]
    model_config = {"from_attributes": True}

@router.get("/admin/events", response_model=list[EventOut], tags=["admin"], dependencies=[Depends(require_admin)])
async def admin_events(vendor: str | None = Query(None), severity: str | None = Query(None),
                       limit: int = Query(50, le=500), offset: int = Query(0)) -> list[EventOut]:
    from app.config import get_settings
    from app.db import get_session_factory
    settings = get_settings()
    factory = get_session_factory(settings.database_url)
    async with factory() as session:
        stmt = select(SecurityEventORM).order_by(desc(SecurityEventORM.received_at)).limit(limit).offset(offset)
        if vendor: stmt = stmt.where(SecurityEventORM.vendor == vendor)
        if severity: stmt = stmt.where(SecurityEventORM.severity == severity.lower())
        result = await session.execute(stmt)
        rows = result.scalars().all()
    return [EventOut.model_validate(r) for r in rows]

@router.get("/admin/stats", tags=["admin"], dependencies=[Depends(require_admin)])
async def admin_stats() -> dict[str, Any]:
    from app.config import get_settings
    from app.db import get_session_factory
    settings = get_settings()
    factory = get_session_factory(settings.database_url)
    async with factory() as session:
        total = (await session.execute(func.count(SecurityEventORM.id))).scalar() or 0
        notified = (await session.execute(
            func.count(SecurityEventORM.id).filter(SecurityEventORM.notified == True))).scalar() or 0  # noqa: E712
        by_sev = (await session.execute(
            select(SecurityEventORM.severity, func.count(SecurityEventORM.id)).group_by(SecurityEventORM.severity))).fetchall()
        by_ven = (await session.execute(
            select(SecurityEventORM.vendor, func.count(SecurityEventORM.id)).group_by(SecurityEventORM.vendor))).fetchall()
    return {"total_events":total,"notified_events":notified,
            "by_severity":{r[0]:r[1] for r in by_sev},"by_vendor":{r[0]:r[1] for r in by_ven}}

@router.post("/admin/pause", tags=["admin"], dependencies=[Depends(require_admin)])
async def admin_pause() -> dict[str,str]:
    from app.main import get_polling_service
    svc = get_polling_service()
    if svc: svc.pause()
    return {"status":"paused"}

@router.post("/admin/resume", tags=["admin"], dependencies=[Depends(require_admin)])
async def admin_resume() -> dict[str,str]:
    from app.main import get_polling_service
    svc = get_polling_service()
    if svc: svc.resume()
    return {"status":"resumed"}

@router.post("/admin/set_severity", tags=["admin"], dependencies=[Depends(require_admin)])
async def admin_set_severity(severity: str = Query(...)) -> dict[str,str]:
    from app.main import get_polling_service
    if severity.lower() not in {"low","medium","high","critical"}:
        raise HTTPException(400, "Invalid severity")
    svc = get_polling_service()
    if svc: svc.set_threshold(severity)
    return {"severity":severity.lower()}
PYEOF

# ── app/main.py ───────────────────────────────────────────────────────────────
cat > "$DEPLOY_DIR/app/main.py" << 'PYEOF'
"""Pocket SIEM bot entry point."""
from __future__ import annotations
import asyncio, logging, logging.config, os
from typing import Optional
import uvicorn
from fastapi import FastAPI
from telegram.ext import Application
from app.api.routes import router
from app.collectors.base import BaseCollector
from app.collectors.paloalto import PaloAltoCollector
from app.collectors.trellix import TrellixCollector
from app.config import Settings, get_settings
from app.db import get_session_factory, init_db
from app.notifier.telegram_bot import SocBot
from app.services.access_control import AccessControl
from app.services.polling import PollingService
logger = logging.getLogger(__name__)
_polling_service: Optional[PollingService] = None

def get_polling_service() -> Optional[PollingService]: return _polling_service

def configure_logging(level: str) -> None:
    logging.config.dictConfig({
        "version":1,"disable_existing_loggers":False,
        "formatters":{"json":{"()":"pythonjsonlogger.jsonlogger.JsonFormatter",
            "format":"%(asctime)s %(name)s %(levelname)s %(message)s"},
            "plain":{"format":"%(asctime)s [%(levelname)s] %(name)s: %(message)s"}},
        "handlers":{"console":{"class":"logging.StreamHandler","stream":"ext://sys.stdout",
            "formatter":"json"}},
        "root":{"handlers":["console"],"level":level},
        "loggers":{"httpx":{"level":"WARNING"},"telegram":{"level":"WARNING"},
                   "uvicorn":{"level":"WARNING"},"uvicorn.access":{"level":"WARNING"}}})

def build_fastapi(settings: Settings) -> FastAPI:
    return FastAPI(title="Pocket SIEM Admin API", version="1.0.0",
        docs_url="/docs" if settings.environment!="production" else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.environment!="production" else None,
    ).__class__(title="Pocket SIEM Admin API").__class__(
        title="Pocket SIEM Admin API", version="1.0.0",
        docs_url="/docs" if settings.environment!="production" else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.environment!="production" else None,
    ) if False else _build_fastapi(settings)

def _build_fastapi(settings: Settings) -> FastAPI:
    app = FastAPI(title="Pocket SIEM Admin API", version="1.0.0",
        docs_url="/docs" if settings.environment!="production" else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.environment!="production" else None)
    app.include_router(router)
    return app

async def run_bot(settings: Settings, bot: SocBot, bot_app: Application) -> None:
    await bot_app.initialize()
    await bot.setup_commands()
    await bot_app.start()
    await bot_app.updater.start_polling(drop_pending_updates=True)
    logger.info("Telegram bot started (polling)")

async def run_api(settings: Settings, fastapi_app: FastAPI) -> None:
    config = uvicorn.Config(fastapi_app, host=settings.api_host,
        port=settings.api_port, log_level="warning", loop="none")
    server = uvicorn.Server(config)
    logger.info("FastAPI listening on %s:%d", settings.api_host, settings.api_port)
    await server.serve()

async def main() -> None:
    global _polling_service
    settings = get_settings()
    configure_logging(settings.log_level)
    logger.info("Starting Pocket SIEM — %s", settings.masked_repr())
    await init_db(settings.database_url)
    session_factory = get_session_factory(settings.database_url)
    access = AccessControl(set(settings.allowed_telegram_user_ids))
    collectors: list[BaseCollector] = []
    if settings.enable_trellix: collectors.append(TrellixCollector(settings))
    if settings.enable_paloalto: collectors.append(PaloAltoCollector(settings))
    if not collectors: logger.warning("No collectors enabled")
    soc_bot = SocBot(settings=settings, access_control=access, session_factory=session_factory)
    bot_app = soc_bot.build_application()
    _polling_service = PollingService(settings=settings, collectors=collectors,
        notify_fn=soc_bot.send_alert, session_factory=session_factory)
    soc_bot._polling = _polling_service
    fastapi_app = _build_fastapi(settings)
    await run_bot(settings, soc_bot, bot_app)
    _polling_service.start()
    try:
        await run_api(settings, fastapi_app)
    except (KeyboardInterrupt, asyncio.CancelledError):
        logger.info("Shutdown signal received")
    finally:
        logger.info("Shutting down…")
        _polling_service.stop()
        await bot_app.updater.stop()
        await bot_app.stop()
        await bot_app.shutdown()
        logger.info("Shutdown complete")

if __name__ == "__main__":
    asyncio.run(main())
PYEOF

ok "Application code written"

# ─────────────────────────────────────────────────────────────────────────────
section "STAGE 4 — Requirements & Virtual Environment"
# ─────────────────────────────────────────────────────────────────────────────

cat > "$DEPLOY_DIR/requirements.txt" << 'EOF'
fastapi>=0.111.0
uvicorn[standard]>=0.29.0
python-telegram-bot>=21.0.0
httpx>=0.27.0
pydantic>=2.7.0
pydantic-settings>=2.2.0
sqlalchemy>=2.0.0
aiosqlite>=0.20.0
asyncpg>=0.29.0
tenacity>=8.2.0
python-json-logger>=2.0.7
python-dotenv>=1.0.0
EOF

info "Creating Python virtualenv…"
python3 -m venv "$DEPLOY_DIR/.venv"
"$DEPLOY_DIR/.venv/bin/pip" install --quiet --upgrade pip
"$DEPLOY_DIR/.venv/bin/pip" install --quiet -r "$DEPLOY_DIR/requirements.txt"
ok "Python dependencies installed"

# ─────────────────────────────────────────────────────────────────────────────
section "STAGE 5 — Environment Configuration"
# ─────────────────────────────────────────────────────────────────────────────

info "Writing .env file…"
cat > "$DEPLOY_DIR/.env" << ENVEOF
# Pocket SIEM Production Configuration
# Generated: ${TIMESTAMP}
# Permissions: 600 (root only)

# ── Telegram ──────────────────────────────────────────────────────────────────
TELEGRAM_BOT_TOKEN=${TELEGRAM_BOT_TOKEN}
ALLOWED_TELEGRAM_USER_IDS=${ALLOWED_TELEGRAM_USER_IDS}
# TELEGRAM_CHAT_ID=

# ── Admin API ─────────────────────────────────────────────────────────────────
ADMIN_API_KEY=${ADMIN_API_KEY}

# ── Trellix EDR ───────────────────────────────────────────────────────────────
ENABLE_TRELLIX=${ENABLE_TRELLIX}
TRELLIX_BASE_URL=${TRELLIX_BASE_URL}
TRELLIX_CLIENT_ID=${TRELLIX_CLIENT_ID}
TRELLIX_CLIENT_SECRET=${TRELLIX_CLIENT_SECRET}
TRELLIX_API_KEY=${TRELLIX_API_KEY}
TRELLIX_VERIFY_SSL=true

# ── Palo Alto Networks ────────────────────────────────────────────────────────
ENABLE_PALOALTO=${ENABLE_PALOALTO:-false}
PALOALTO_HOSTNAME=${PALOALTO_HOSTNAME}
PALOALTO_API_KEY=${PALOALTO_API_KEY}
PALOALTO_VSYS=vsys1
PALOALTO_VERIFY_SSL=true

# ── Polling ───────────────────────────────────────────────────────────────────
POLL_INTERVAL_SECONDS=${POLL_INTERVAL}
MIN_SEVERITY=${MIN_SEVERITY}
MAX_ALERTS_PER_MINUTE=20

# ── Database ─────────────────────────────────────────────────────────────────
DATABASE_URL=sqlite+aiosqlite:///./data/soc_bot.db

# ── FastAPI ───────────────────────────────────────────────────────────────────
API_HOST=127.0.0.1
API_PORT=8080

# ── Mock Mode ─────────────────────────────────────────────────────────────────
MOCK_MODE=${MOCK_MODE}

# ── Logging ───────────────────────────────────────────────────────────────────
LOG_LEVEL=INFO
ENVIRONMENT=production
ENVEOF

# Strict permissions — no world or group read
chmod 600 "$DEPLOY_DIR/.env"
ok ".env written with permissions 600"

# ─────────────────────────────────────────────────────────────────────────────
section "STAGE 6 — Docker Deployment"
# ─────────────────────────────────────────────────────────────────────────────

cat > "$DEPLOY_DIR/Dockerfile" << 'EOF'
FROM python:3.11-slim AS runtime
RUN groupadd -r socbot && useradd -r -g socbot -m -d /app socbot
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ ./app/
RUN mkdir -p /app/data && chown -R socbot:socbot /app
USER socbot
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1
EXPOSE 8080
CMD ["python", "-m", "app.main"]
EOF

cat > "$DEPLOY_DIR/docker-compose.yml" << EOF
services:
  pocket-siem:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: pocket-siem
    restart: unless-stopped
    env_file:
      - .env
    volumes:
      - soc_data:/app/data
    ports:
      - "127.0.0.1:8080:8080"
    healthcheck:
      test: ["CMD", "python", "-c",
             "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 20s
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
volumes:
  soc_data:
    driver: local
EOF

ok "Docker files written"

# ─────────────────────────────────────────────────────────────────────────────
section "STAGE 7 — Systemd Service"
# ─────────────────────────────────────────────────────────────────────────────

cat > "/etc/systemd/system/${SERVICE_NAME}.service" << EOF
[Unit]
Description=Pocket SIEM Telegram SOC Monitoring Bot
Documentation=https://github.com/sarat1kyan/pocket-siem
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
User=root
WorkingDirectory=${DEPLOY_DIR}
EnvironmentFile=${DEPLOY_DIR}/.env
ExecStart=${DEPLOY_DIR}/.venv/bin/python -m app.main
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10
TimeoutStopSec=30
StandardOutput=journal
StandardError=journal
SyslogIdentifier=pocket-siem
# Security hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=${DEPLOY_DIR}/data
ReadWritePaths=${DEPLOY_DIR}
ProtectHome=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "${SERVICE_NAME}.service"
ok "Systemd service configured and enabled"

# ─────────────────────────────────────────────────────────────────────────────
section "STAGE 8 — Log Rotation"
# ─────────────────────────────────────────────────────────────────────────────

cat > "/etc/logrotate.d/pocket-siem" << 'EOF'
/var/log/pocket-siem/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    copytruncate
    su root root
}
EOF

mkdir -p /var/log/pocket-siem
ok "Log rotation configured"

# ─────────────────────────────────────────────────────────────────────────────
section "STAGE 9 — File Permissions"
# ─────────────────────────────────────────────────────────────────────────────

chown -R root:root "$DEPLOY_DIR"
chmod 700 "$DEPLOY_DIR"
chmod 600 "$DEPLOY_DIR/.env"
chmod -R 755 "$DEPLOY_DIR/app"
chmod 755 "$DEPLOY_DIR/.venv/bin/python"
mkdir -p "$DEPLOY_DIR/data"
chmod 700 "$DEPLOY_DIR/data"
ok "Permissions set"

# ─────────────────────────────────────────────────────────────────────────────
section "STAGE 10 — Pre-launch Validation"
# ─────────────────────────────────────────────────────────────────────────────

info "Syntax check…"
cd "$DEPLOY_DIR"
"$DEPLOY_DIR/.venv/bin/python" -c "
import sys
sys.path.insert(0,'.')
from app.severity import Severity
from app.models import SecurityEvent
from app.normalizer import parse_datetime
from app.notifier.formatters import format_event
# Quick smoke test
e = SecurityEvent(vendor='Trellix',source='test',alert_id='t1',severity='high',title='Test')
assert e.dedup_hash
assert 'Trellix' in format_event(e)
print('  Syntax and smoke test: PASS')
"

info "Telegram bot token format check…"
TG_TOKEN="${TELEGRAM_BOT_TOKEN}"
if echo "$TG_TOKEN" | grep -qE '^[0-9]+:[A-Za-z0-9_-]{35,}$'; then
  ok "Telegram token format: valid"
else
  warn "Telegram token format looks unusual — check TELEGRAM_BOT_TOKEN"
fi

info "Telegram API connectivity check…"
TG_RESP=$(curl -s --max-time 10 \
  "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/getMe" 2>/dev/null || echo '{}')
BOT_OK=$(echo "$TG_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('ok','false'))" 2>/dev/null || echo "false")
BOT_NAME=$(echo "$TG_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('result',{}).get('username','unknown'))" 2>/dev/null || echo "unknown")
if [[ "$BOT_OK" == "True" ]] || [[ "$BOT_OK" == "true" ]]; then
  ok "Telegram API: connected as @${BOT_NAME}"
else
  warn "Telegram API connectivity check returned: ${TG_RESP:0:200}"
fi

# ─────────────────────────────────────────────────────────────────────────────
section "STAGE 11 — Service Start"
# ─────────────────────────────────────────────────────────────────────────────

info "Starting ${SERVICE_NAME} service…"
systemctl start "${SERVICE_NAME}.service"
sleep 5

STATUS=$(systemctl is-active "${SERVICE_NAME}.service" 2>/dev/null)
if [[ "$STATUS" == "active" ]]; then
  ok "Service is ACTIVE"
else
  err "Service status: $STATUS"
  journalctl -u "${SERVICE_NAME}.service" -n 30 --no-pager
  # Try direct run for diagnostics
  info "Running directly for diagnosis…"
  cd "$DEPLOY_DIR"
  timeout 5 "$DEPLOY_DIR/.venv/bin/python" -m app.main 2>&1 | head -20 || true
fi

# ─────────────────────────────────────────────────────────────────────────────
section "STAGE 12 — Health Check"
# ─────────────────────────────────────────────────────────────────────────────

sleep 3
info "Checking FastAPI health endpoint…"
HEALTH=$(curl -s --max-time 10 http://127.0.0.1:8080/health 2>/dev/null || echo '{}')
HEALTH_STATUS=$(echo "$HEALTH" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status','?'))" 2>/dev/null || echo "unreachable")
if [[ "$HEALTH_STATUS" == "ok" ]]; then
  ok "Health endpoint: OK"
else
  warn "Health endpoint returned: $HEALTH_STATUS (bot may still be starting)"
fi

# ─────────────────────────────────────────────────────────────────────────────
section "STAGE 13 — Mock Alert Test"
# ─────────────────────────────────────────────────────────────────────────────

info "Sending test alert via Telegram API directly…"
TEST_MSG="🧪 *Pocket SIEM Deployment Test*%0A%0ABot deployed successfully on: $(hostname)%0ATime: ${TIMESTAMP}%0A%0AThis is an automated deployment verification message."
TG_SEND=$(curl -s --max-time 15 \
  "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
  -d "chat_id=${ALLOWED_TELEGRAM_USER_IDS}&text=${TEST_MSG}&parse_mode=Markdown" 2>/dev/null)
SEND_OK=$(echo "$TG_SEND" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('ok','false'))" 2>/dev/null || echo "false")
if [[ "$SEND_OK" == "True" ]] || [[ "$SEND_OK" == "true" ]]; then
  ok "Test message sent to Telegram successfully"
else
  warn "Test message send result: ${TG_SEND:0:300}"
fi

# ─────────────────────────────────────────────────────────────────────────────
section "FINAL DEPLOYMENT REPORT"
# ─────────────────────────────────────────────────────────────────────────────

echo ""
echo "  Generated: ${TIMESTAMP}"
echo "  Hostname:  $(hostname)"
echo "  IP:        $(hostname -I | awk '{print $1}')"
echo ""
echo "  ┌────────────────────────────────────────────┐"
echo "  │  Component Status                          │"
echo "  ├────────────────────────────────────────────┤"
printf  "  │  %-40s │\n" "Python venv: $(ls "$DEPLOY_DIR/.venv/bin/python" &>/dev/null && echo '✅ OK' || echo '❌ MISSING')"
printf  "  │  %-40s │\n" "App code: $(ls "$DEPLOY_DIR/app/main.py" &>/dev/null && echo '✅ OK' || echo '❌ MISSING')"
printf  "  │  %-40s │\n" "Config (.env): $(ls "$DEPLOY_DIR/.env" &>/dev/null && echo '✅ OK (600)' || echo '❌ MISSING')"
printf  "  │  %-40s │\n" "Systemd service: $(systemctl is-active $SERVICE_NAME 2>/dev/null)"
printf  "  │  %-40s │\n" "Docker available: $(docker version &>/dev/null && echo '✅' || echo '⚠️  not running')"
printf  "  │  %-40s │\n" "Telegram: ${BOT_OK} (@${BOT_NAME})"
printf  "  │  %-40s │\n" "FastAPI health: ${HEALTH_STATUS}"
echo "  └────────────────────────────────────────────┘"
echo ""
echo "  Deploy directory:  $DEPLOY_DIR"
echo "  Service:           systemctl status $SERVICE_NAME"
echo "  Logs:              journalctl -u $SERVICE_NAME -f"
echo "  Health:            curl http://127.0.0.1:8080/health"
echo ""
echo "  Admin API key (masked): $(mask "$ADMIN_API_KEY")"
echo "  To get full admin key:  cat $DEPLOY_DIR/.env | grep ADMIN_API_KEY"
echo ""
echo "  To enable mock alerts for testing:"
echo "    sed -i 's/MOCK_MODE=false/MOCK_MODE=true/' $DEPLOY_DIR/.env"
echo "    systemctl restart $SERVICE_NAME"
echo ""
ok "Deployment complete!"
