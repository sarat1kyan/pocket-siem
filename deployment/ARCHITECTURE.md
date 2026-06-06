# Pocket SIEM — Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Linux Server                                 │
│                      /opt/pocket-siem/                              │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                    app/main.py (asyncio)                     │  │
│  │                                                              │  │
│  │  ┌──────────────┐  ┌────────────────────┐  ┌─────────────┐ │  │
│  │  │ PollingService│  │    SocBot          │  │  FastAPI    │ │  │
│  │  │ (background) │  │ (Telegram polling) │  │  :8080      │ │  │
│  │  └──────┬───────┘  └────────┬───────────┘  └──────┬──────┘ │  │
│  │         │                   │                       │        │  │
│  │  ┌──────▼───────────────────▼──────────────────┐   │        │  │
│  │  │              SecurityEvent pipeline          │   │        │  │
│  │  │  fetch → normalize → deduplicate → notify   │   │        │  │
│  │  └──────────────────────────────────────────────┘   │        │  │
│  │                                                      │        │  │
│  │  ┌─────────────────┐  ┌───────────────────────────┐ │        │  │
│  │  │ TrellixCollector│  │  PaloAltoCollector        │ │        │  │
│  │  │ (OAuth2 / key)  │  │  (PAN-OS XML API)         │ │        │  │
│  │  └────────┬────────┘  └─────────────┬─────────────┘ │        │  │
│  │           │                         │                 │        │  │
│  │  ┌────────▼─────────────────────────▼─────────────┐  │        │  │
│  │  │           SQLite / PostgreSQL (SQLAlchemy)      │  │        │  │
│  │  │           /opt/pocket-siem/data/soc_bot.db      │  │        │  │
│  │  └────────────────────────────────────────────────┘  │        │  │
│  └──────────────────────────────────────────────────────┘        │  │
│                                                                     │
│  ┌─────────────────────────┐  ┌──────────────────────────────────┐ │
│  │  systemd service        │  │  logrotate                       │ │
│  │  pocket-siem.service    │  │  /etc/logrotate.d/pocket-siem    │ │
│  │  Restart=on-failure     │  │  daily, 14 days, compress        │ │
│  └─────────────────────────┘  └──────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
           │                    │                    │
           ▼                    ▼                    ▼
   ┌──────────────┐   ┌──────────────────┐  ┌──────────────────────┐
   │ Telegram API │   │  Trellix EDR API │  │  Palo Alto PAN-OS    │
   │ api.telegram │   │ api.manage.      │  │  XML API             │
   │ .org         │   │ trellix.com      │  │  https://<firewall>  │
   └──────────────┘   └──────────────────┘  └──────────────────────┘
           │
           ▼
   ┌──────────────┐
   │ Telegram     │
   │ (SOC analyst │
   │  phone/PC)   │
   └──────────────┘
```

## Data Flow

1. **PollingService** wakes every `POLL_INTERVAL_SECONDS`
2. Calls `TrellixCollector.poll()` and `PaloAltoCollector.poll()`
3. Each collector calls the upstream API and returns `List[SecurityEvent]`
4. Events with severity below `MIN_SEVERITY` are dropped
5. Remaining events are checked against the `dedup_hash` in SQLite
6. New events are written to DB and sent via `SocBot.send_alert()`
7. Rate limiter enforces max `MAX_ALERTS_PER_MINUTE`
8. `notified=True` is written back to DB after successful send

## File Layout

```
/opt/pocket-siem/
├── app/
│   ├── main.py              Entry point
│   ├── config.py            Settings (pydantic-settings)
│   ├── models.py            ORM + Pydantic schemas
│   ├── db.py                Async SQLite/PostgreSQL
│   ├── severity.py          Severity enum
│   ├── normalizer.py        Date/string helpers
│   ├── collectors/
│   │   ├── base.py          BaseCollector
│   │   ├── trellix.py       Trellix EDR
│   │   └── paloalto.py      PAN-OS XML API
│   ├── notifier/
│   │   ├── telegram_bot.py  Bot + commands
│   │   └── formatters.py    Message formatters
│   ├── services/
│   │   ├── polling.py       Polling loop
│   │   ├── dedupe.py        Deduplication
│   │   └── access_control.py Allowlist
│   └── api/
│       └── routes.py        FastAPI endpoints
├── data/
│   └── soc_bot.db           SQLite database
├── .env                     Secrets (chmod 600)
├── requirements.txt
├── Dockerfile
└── docker-compose.yml
```

## Security Controls

| Control | Implementation |
|---|---|
| Secret storage | `.env` chmod 600, EnvironmentFile in systemd |
| Log masking | Tokens never logged, masked in `masked_repr()` |
| TLS validation | Default `verify=True` for all httpx clients |
| Access control | Telegram user ID allowlist (numeric, not username) |
| Admin API | Bearer token auth on all `/admin/*` endpoints |
| Process isolation | `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem` |
| Port exposure | FastAPI bound to 127.0.0.1 only |
