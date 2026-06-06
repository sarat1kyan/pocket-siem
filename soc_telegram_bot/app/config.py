"""Central configuration via pydantic-settings — all values come from env / .env file."""
from __future__ import annotations

import re
from functools import lru_cache

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Telegram ─────────────────────────────────────────────────────────────
    telegram_bot_token: str = Field(..., description="Bot token from BotFather")
    allowed_telegram_user_ids: list[int] = Field(
        default_factory=list,
        description="Comma-separated Telegram user IDs allowed to use the bot",
    )
    telegram_chat_id: int | None = Field(
        None,
        description="Optional chat/channel ID for proactive push notifications",
    )

    # ── Trellix EDR ──────────────────────────────────────────────────────────
    enable_trellix: bool = Field(True, description="Enable Trellix EDR polling")
    trellix_base_url: str = Field(
        "https://api.manage.trellix.com",
        description="Trellix API base URL",
    )
    trellix_client_id: str | None = Field(None, description="OAuth2 client ID")
    trellix_client_secret: str | None = Field(None, description="OAuth2 client secret")
    trellix_api_key: str | None = Field(None, description="API key (alternative auth)")
    trellix_tenant_id: str | None = Field(None, description="Trellix tenant / account ID")
    trellix_verify_ssl: bool = Field(True, description="Validate TLS for Trellix API calls")

    # ── Palo Alto Networks ────────────────────────────────────────────────────
    enable_paloalto: bool = Field(True, description="Enable Palo Alto firewall polling")
    paloalto_hostname: str | None = Field(
        None, description="Firewall hostname or IP (e.g. firewall.corp.example.com)"
    )
    paloalto_api_key: str | None = Field(None, description="PAN-OS API key")
    paloalto_vsys: str = Field("vsys1", description="Virtual system name (default: vsys1)")
    paloalto_verify_ssl: bool = Field(True, description="Validate TLS for PAN-OS API calls")
    paloalto_log_count: int = Field(
        50, ge=1, le=500, description="Max log entries to fetch per poll"
    )

    # ── Polling ───────────────────────────────────────────────────────────────
    poll_interval_seconds: int = Field(
        60, ge=10, description="Seconds between collector poll cycles"
    )

    # ── Severity ─────────────────────────────────────────────────────────────
    min_severity: str = Field(
        "high",
        description="Minimum severity to notify: low | medium | high | critical",
    )

    # ── Database ─────────────────────────────────────────────────────────────
    database_url: str = Field(
        "sqlite+aiosqlite:///./data/soc_bot.db",
        description="SQLAlchemy async database URL",
    )

    # ── Admin / FastAPI ───────────────────────────────────────────────────────
    admin_api_key: str = Field(
        ...,
        description="API key required for FastAPI admin endpoints (Authorization: Bearer <key>)",
    )
    api_host: str = Field("0.0.0.0", description="FastAPI bind host")
    api_port: int = Field(8080, description="FastAPI bind port")

    # ── Mock mode ─────────────────────────────────────────────────────────────
    mock_mode: bool = Field(
        False, description="Generate fake events instead of calling real APIs"
    )

    # ── Rate limiting ─────────────────────────────────────────────────────────
    max_alerts_per_minute: int = Field(
        20, ge=1, description="Max Telegram messages sent per minute to avoid spam"
    )

    # ── Misc ──────────────────────────────────────────────────────────────────
    log_level: str = Field("INFO", description="Python logging level")
    environment: str = Field("production", description="Environment label (dev/staging/production)")

    # ── Validators ────────────────────────────────────────────────────────────
    @field_validator("min_severity", mode="before")
    @classmethod
    def normalize_severity(cls, v: str) -> str:
        valid = {"low", "medium", "high", "critical"}
        v = str(v).lower().strip()
        if v not in valid:
            raise ValueError(f"min_severity must be one of {valid}, got {v!r}")
        return v

    @field_validator("allowed_telegram_user_ids", mode="before")
    @classmethod
    def parse_user_ids(cls, v):
        if isinstance(v, list):
            return [int(i) for i in v]
        if isinstance(v, str):
            parts = re.split(r"[,\s]+", v.strip())
            return [int(p) for p in parts if p]
        return v

    @field_validator("log_level", mode="before")
    @classmethod
    def upper_log_level(cls, v: str) -> str:
        return str(v).upper()

    @model_validator(mode="after")
    def warn_insecure_tls(self) -> Settings:
        if not self.trellix_verify_ssl:
            import warnings
            warnings.warn(
                "TRELLIX_VERIFY_SSL=false — TLS verification disabled, "
                "use only in controlled lab environments!",
                stacklevel=2,
            )
        if not self.paloalto_verify_ssl:
            import warnings
            warnings.warn(
                "PALOALTO_VERIFY_SSL=false — TLS verification disabled, "
                "use only in controlled lab environments!",
                stacklevel=2,
            )
        return self

    def masked_repr(self) -> str:
        """Return a safe string representation with secrets masked."""
        def mask(v: str | None) -> str:
            if not v:
                return "<not set>"
            return v[:4] + "****" if len(v) > 4 else "****"

        return (
            f"Settings("
            f"env={self.environment}, "
            f"mock={self.mock_mode}, "
            f"trellix={'on' if self.enable_trellix else 'off'}, "
            f"paloalto={'on' if self.enable_paloalto else 'off'}, "
            f"min_severity={self.min_severity}, "
            f"poll_interval={self.poll_interval_seconds}s, "
            f"trellix_client_id={mask(self.trellix_client_id)}, "
            f"paloalto_host={self.paloalto_hostname or '<not set>'}"
            f")"
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
