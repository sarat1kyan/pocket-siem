# Pocket SIEM — Telegram SOC Monitoring Bot

A production-ready Telegram bot that monitors **Trellix EDR** and **Palo Alto Networks** firewall threat data, deduplicates events, and delivers formatted alerts directly to your Telegram account.

```
┌─────────────────────────────────────────────────────┐
│  Trellix EDR API  ──┐                               │
│                     ├──► Pocket SIEM ──► Telegram   │
│  PAN-OS XML API  ───┘       bot                     │
│                         + FastAPI admin              │
└─────────────────────────────────────────────────────┘
```

---

## Features

- **Multi-source**: polls Trellix EDR Cloud API and PAN-OS XML API concurrently
- **Severity filtering**: only HIGH/CRITICAL by default; fully configurable
- **Deduplication**: each unique alert (vendor + alert ID) is sent exactly once
- **Rate limiting**: configurable max alerts/minute to prevent Telegram spam
- **Access control**: allowlist-only Telegram users; `/whoami` for self-service ID lookup
- **Admin commands**: `/pause`, `/resume`, `/set_severity`, `/recent`, `/critical`
- **FastAPI admin API**: health checks, event stats, pause/resume via HTTP
- **Mock mode**: generate synthetic high-severity events to test without real APIs
- **Structured JSON logging** with configurable log level
- **Retry with exponential backoff** on all API calls
- **Docker + docker-compose** ready

---

## Quick Start

### 1. Create a Telegram Bot

1. Open Telegram and search for **@BotFather**
2. Send `/newbot` and follow the prompts
3. Copy the **Bot Token** (format: `1234567890:ABCdef...`)
4. Keep the bot token secret — treat it like a password

### 2. Find Your Telegram User ID

Two options:

**Option A — use /whoami (recommended)**
1. Start your bot (even before configuring allowlist)
2. Send `/whoami` to your bot
3. The bot replies with your numeric Telegram ID
4. Add that ID to `ALLOWED_TELEGRAM_USER_IDS`

**Option B — use @userinfobot**
1. Search for `@userinfobot` on Telegram
2. Send it any message
3. It replies with your ID

### 3. Configure Environment Variables

```bash
cd soc_telegram_bot
cp .env.example .env
$EDITOR .env
```

**Minimum required variables:**

| Variable | Description |
|---|---|
| `TELEGRAM_BOT_TOKEN` | Token from BotFather |
| `ALLOWED_TELEGRAM_USER_IDS` | Comma-separated Telegram user IDs |
| `ADMIN_API_KEY` | Random key for FastAPI admin endpoints |

See `.env.example` for all variables with explanations.

### 4. Configure Trellix EDR

**Method A: OAuth2 (Trellix Cloud SaaS)**

1. Log into Trellix ePolicy Orchestrator
2. Go to **Settings → Client Management → Create Client**
3. Select scopes: `edr.dashboard.read`, `edr.alert.read`
4. Copy `client_id` and `client_secret`

```env
TRELLIX_CLIENT_ID=your-client-id
TRELLIX_CLIENT_SECRET=your-client-secret
TRELLIX_BASE_URL=https://api.manage.trellix.com
```

**Method B: API Key (ePO on-premises)**

```env
TRELLIX_API_KEY=your-api-key
TRELLIX_BASE_URL=https://your-epo-server.corp.example.com
```

**Disable Trellix polling:**
```env
ENABLE_TRELLIX=false
```

### 5. Configure Palo Alto Networks

**Generate a PAN-OS API Key:**

```bash
curl -k "https://<firewall>/api/?type=keygen&user=<admin>&password=<password>"
```

Response:
```xml
<response status="success">
  <result>
    <key>LUFRPT14MW5XamNtZW1abVRiYlVpR0paVFBac21...</key>
  </result>
</response>
```

Copy the `<key>` value.

```env
PALOALTO_HOSTNAME=firewall.corp.example.com
PALOALTO_API_KEY=LUFRPT14MW5XamNtZW1abVRiYlVpR0paVFBac21...
PALOALTO_VSYS=vsys1
```

**For Panorama:** set `PALOALTO_HOSTNAME` to your Panorama address.

**Disable Palo Alto polling:**
```env
ENABLE_PALOALTO=false
```

---

## Running Locally

### Prerequisites

- Python 3.11+
- pip

```bash
cd soc_telegram_bot

# Create virtual environment
python -m venv .venv
source .venv/bin/activate          # Linux/Mac
# .venv\Scripts\activate           # Windows

# Install dependencies
pip install -e ".[dev]"

# Set up environment
cp .env.example .env
# Edit .env with your values

# Run the bot
python -m app.main
```

The bot starts Telegram polling and the FastAPI server on port 8080.

---

## Running with Docker

```bash
cd soc_telegram_bot

# Copy and fill in your .env
cp .env.example .env
$EDITOR .env

# Build and start
docker compose up -d

# View logs
docker compose logs -f pocket-siem

# Stop
docker compose down
```

The SQLite database is persisted in a named Docker volume (`soc_data`).

**Check health:**
```bash
curl http://localhost:8080/health
```

---

## Testing with Mock Data

To test the bot end-to-end without real Trellix or Palo Alto credentials:

```env
MOCK_MODE=true
POLL_INTERVAL_SECONDS=30
MIN_SEVERITY=medium
```

The bot will generate 2–5 synthetic HIGH/CRITICAL events every poll cycle and send them to Telegram. Each event has a unique ID so deduplication works normally.

---

## Running Tests

```bash
cd soc_telegram_bot
pip install -e ".[dev]"
pytest -v --tb=short
```

Run with coverage:
```bash
pytest --cov=app --cov-report=term-missing
```

---

## Bot Commands

| Command | Description |
|---|---|
| `/start` | Welcome message |
| `/help` | List all commands |
| `/status` | Bot state, severity threshold, poller state |
| `/health` | Ping each upstream API |
| `/sources` | Show configured data sources |
| `/recent` | Last 5 alerts (all vendors) |
| `/recent_trellix` | Last 5 Trellix EDR alerts |
| `/recent_paloalto` | Last 5 Palo Alto alerts |
| `/critical` | Last 5 CRITICAL severity events |
| `/set_severity high` | Set minimum notification threshold |
| `/pause` | Pause all alert notifications |
| `/resume` | Resume alert notifications |
| `/whoami` | Show your Telegram ID (works for everyone) |

---

## Admin API

The FastAPI server exposes admin endpoints protected by `Authorization: Bearer <ADMIN_API_KEY>`.

```bash
export ADMIN_API_KEY=your-key-here

# Health (public)
curl http://localhost:8080/health

# Bot status
curl -H "Authorization: Bearer $ADMIN_API_KEY" http://localhost:8080/admin/status

# Recent events
curl -H "Authorization: Bearer $ADMIN_API_KEY" "http://localhost:8080/admin/events?limit=10"

# Event statistics
curl -H "Authorization: Bearer $ADMIN_API_KEY" http://localhost:8080/admin/stats

# Pause/resume notifications
curl -X POST -H "Authorization: Bearer $ADMIN_API_KEY" http://localhost:8080/admin/pause
curl -X POST -H "Authorization: Bearer $ADMIN_API_KEY" http://localhost:8080/admin/resume

# Change severity threshold
curl -X POST -H "Authorization: Bearer $ADMIN_API_KEY" \
  "http://localhost:8080/admin/set_severity?severity=critical"
```

---

## Alert Format Examples

**Trellix EDR Alert:**
```
🚨 Trellix EDR Alert 🟠

• Severity: HIGH
• Host: WORKSTATION-XF3A
• User: jdoe
• Detection: Suspicious powershell.exe activity — Execution
• Process: powershell.exe
• Command: powershell.exe -EncodedCommand SGVsbG8=
• MITRE: Execution / T1059.001
• Status: New
• Time: 2024-06-01 14:30:00 UTC
```

**Palo Alto Threat Alert:**
```
🔥 Palo Alto Threat Alert 🔴

• Severity: CRITICAL
• Threat: CVE-2021-44228 Log4j RCE
• Type: vulnerability
• Source: 10.10.5.42
• Destination: 203.0.113.1:443
• App: ssl
• Action: block
• Rule: block-internet-vuln
• Time: 2024-06-01 14:30:00 UTC
```

---

## Project Structure

```
soc_telegram_bot/
├── app/
│   ├── main.py              # Entry point — starts bot + polling + FastAPI
│   ├── config.py            # Pydantic settings (all env vars)
│   ├── models.py            # SQLAlchemy ORM + Pydantic SecurityEvent schema
│   ├── db.py                # Async database setup
│   ├── severity.py          # Severity enum with comparison/emoji
│   ├── normalizer.py        # Datetime/string parsing utilities
│   ├── collectors/
│   │   ├── base.py          # Abstract BaseCollector
│   │   ├── trellix.py       # Trellix EDR API client
│   │   └── paloalto.py      # PAN-OS XML API client
│   ├── notifier/
│   │   ├── telegram_bot.py  # Bot commands + send_alert()
│   │   └── formatters.py    # Vendor-specific message formatters
│   ├── services/
│   │   ├── polling.py       # Background polling loop with rate limiting
│   │   ├── dedupe.py        # DB-backed deduplication
│   │   └── access_control.py # Telegram user allowlist
│   └── api/
│       └── routes.py        # FastAPI health + admin routes
├── tests/
│   ├── test_severity.py
│   ├── test_normalizer.py
│   ├── test_models.py
│   ├── test_formatters.py
│   ├── test_collectors_mock.py
│   ├── test_dedupe.py
│   └── test_access_control.py
├── .env.example
├── pyproject.toml
├── Dockerfile
└── docker-compose.yml
```

---

## Configuration Reference

| Variable | Default | Description |
|---|---|---|
| `TELEGRAM_BOT_TOKEN` | — | **Required.** Bot token from BotFather |
| `ALLOWED_TELEGRAM_USER_IDS` | — | **Required.** Comma-separated user IDs |
| `ADMIN_API_KEY` | — | **Required.** Key for FastAPI admin endpoints |
| `TELEGRAM_CHAT_ID` | — | Optional push channel ID |
| `ENABLE_TRELLIX` | `true` | Enable Trellix polling |
| `TRELLIX_BASE_URL` | `https://api.manage.trellix.com` | Trellix API URL |
| `TRELLIX_CLIENT_ID` | — | OAuth2 client ID |
| `TRELLIX_CLIENT_SECRET` | — | OAuth2 client secret |
| `TRELLIX_API_KEY` | — | Static API key (alternative auth) |
| `TRELLIX_VERIFY_SSL` | `true` | Validate TLS |
| `ENABLE_PALOALTO` | `true` | Enable Palo Alto polling |
| `PALOALTO_HOSTNAME` | — | Firewall hostname/IP |
| `PALOALTO_API_KEY` | — | PAN-OS API key |
| `PALOALTO_VSYS` | `vsys1` | Virtual system |
| `PALOALTO_LOG_COUNT` | `50` | Max logs per poll (1–500) |
| `PALOALTO_VERIFY_SSL` | `true` | Validate TLS |
| `POLL_INTERVAL_SECONDS` | `60` | Seconds between polls |
| `MIN_SEVERITY` | `high` | Minimum severity: low/medium/high/critical |
| `MAX_ALERTS_PER_MINUTE` | `20` | Rate limit (messages/min) |
| `DATABASE_URL` | SQLite | SQLAlchemy async URL |
| `API_HOST` | `0.0.0.0` | FastAPI bind host |
| `API_PORT` | `8080` | FastAPI bind port |
| `MOCK_MODE` | `false` | Generate synthetic events |
| `LOG_LEVEL` | `INFO` | Logging verbosity |
| `ENVIRONMENT` | `production` | Disables /docs in production |

---

## Troubleshooting

**Bot not responding to commands**
- Verify `TELEGRAM_BOT_TOKEN` is correct
- Ensure your user ID is in `ALLOWED_TELEGRAM_USER_IDS`
- Send `/whoami` — this command works without being on the allowlist

**No alerts received**
- Check `MIN_SEVERITY` — default is `high`, so medium/low events are filtered
- Verify `MOCK_MODE=true` produces test events before connecting real APIs
- Check logs: `docker compose logs -f pocket-siem`

**Trellix connection errors**
- Test OAuth token endpoint manually:
  ```bash
  curl -X POST https://iam.mcafee-cloud.com/iam/v1.1/token \
    -d "grant_type=client_credentials&client_id=YOUR_ID&client_secret=YOUR_SECRET&scope=edr.alert.read"
  ```
- Check that `TRELLIX_BASE_URL` matches your tenant (SaaS vs on-prem)

**Palo Alto connection errors**
- Test API key:
  ```bash
  curl -k "https://YOUR_FIREWALL/api/?type=op&cmd=<show><system><info></info></system></show>&key=YOUR_KEY"
  ```
- Expected: XML response with `status="success"`
- Check firewall management ACL allows your IP

**TLS certificate errors (self-signed firewall)**
- Set `PALOALTO_VERIFY_SSL=false` **only in a lab environment**
- A warning is logged when TLS verification is disabled

**Duplicate alerts after restart**
- This is expected behavior: the database persists across restarts
- The `dedup_hash` is stable across restarts (vendor + alert_id)

**Database reset (development only)**
```bash
rm -f data/soc_bot.db
```

**Using PostgreSQL**
```env
DATABASE_URL=postgresql+asyncpg://user:password@localhost:5432/soc_bot
```
Uncomment the `postgres:` service in `docker-compose.yml`.

---

## Security Notes

- Secrets are never logged — tokens/keys are masked in log output
- TLS validation is enabled by default for all API calls
- Admin API endpoints require `Authorization: Bearer` header
- The FastAPI port (8080) should not be exposed publicly; use a reverse proxy
- Run as non-root inside Docker (`socbot` user)
- The Telegram bot allowlist prevents unauthorized access

---

## License

MIT
