# Pocket SIEM — Operational Runbook

## Day 0: Initial Deployment

```bash
# From your local machine (requires ssh access to server)
git clone https://github.com/sarat1kyan/pocket-siem.git
cd pocket-siem

# Edit credentials in run_deploy.sh (already pre-filled for this deployment)
bash deployment/run_deploy.sh
```

## Daily Operations

### Check service health
```bash
ssh root@46.224.84.130 'systemctl status pocket-siem'
ssh root@46.224.84.130 'curl -s http://127.0.0.1:8080/health'
```

### View live logs
```bash
ssh root@46.224.84.130 'journalctl -u pocket-siem -f'
```

### View last 50 log lines
```bash
ssh root@46.224.84.130 'journalctl -u pocket-siem -n 50 --no-pager'
```

### Check event statistics via API
```bash
ADMIN_KEY=$(ssh root@46.224.84.130 'grep ADMIN_API_KEY /opt/pocket-siem/.env | cut -d= -f2')
ssh -L 8080:127.0.0.1:8080 root@46.224.84.130 -N &   # SSH tunnel
curl -H "Authorization: Bearer $ADMIN_KEY" http://localhost:8080/admin/stats
```

## Configuration Changes

### Change severity threshold
```bash
# Via Telegram: send /set_severity critical  (or high, medium, low)

# Via systemd environment override:
ssh root@46.224.84.130
sed -i 's/MIN_SEVERITY=.*/MIN_SEVERITY=critical/' /opt/pocket-siem/.env
systemctl restart pocket-siem
```

### Enable mock mode for testing
```bash
ssh root@46.224.84.130 \
  "sed -i 's/MOCK_MODE=false/MOCK_MODE=true/' /opt/pocket-siem/.env && systemctl restart pocket-siem"
# Watch Telegram — mock alerts should arrive within POLL_INTERVAL seconds
# Disable when done:
ssh root@46.224.84.130 \
  "sed -i 's/MOCK_MODE=true/MOCK_MODE=false/' /opt/pocket-siem/.env && systemctl restart pocket-siem"
```

### Add a new allowed Telegram user
```bash
# Have the user send /whoami to the bot to get their ID
# Then:
ssh root@46.224.84.130 \
  "sed -i 's/ALLOWED_TELEGRAM_USER_IDS=.*/ALLOWED_TELEGRAM_USER_IDS=1526460067,NEW_USER_ID/' \
   /opt/pocket-siem/.env && systemctl restart pocket-siem"
```

### Update Trellix credentials
```bash
ssh root@46.224.84.130
vim /opt/pocket-siem/.env   # or use sed
systemctl restart pocket-siem
```

### Add Palo Alto firewall
```bash
ssh root@46.224.84.130
# Generate API key first:
# curl -k "https://FIREWALL/api/?type=keygen&user=admin&password=PASS"
sed -i 's/ENABLE_PALOALTO=false/ENABLE_PALOALTO=true/' /opt/pocket-siem/.env
echo "PALOALTO_HOSTNAME=firewall.corp.example.com" >> /opt/pocket-siem/.env
echo "PALOALTO_API_KEY=your-api-key" >> /opt/pocket-siem/.env
systemctl restart pocket-siem
```

## Incident Response

### Service not starting
```bash
journalctl -u pocket-siem -n 100 --no-pager
# Common causes:
# 1. Bad .env syntax
# 2. Missing TELEGRAM_BOT_TOKEN or ADMIN_API_KEY
# 3. Port 8080 already in use: ss -tlnp | grep 8080
```

### No alerts being received
```bash
# 1. Check service is running
systemctl status pocket-siem

# 2. Enable mock mode to verify Telegram pipeline works
sed -i 's/MOCK_MODE=false/MOCK_MODE=true/' /opt/pocket-siem/.env
systemctl restart pocket-siem
# Wait 60s — you should get mock alerts in Telegram

# 3. Check severity filter
grep MIN_SEVERITY /opt/pocket-siem/.env
# Set to 'low' temporarily to catch everything
```

### Duplicate alerts appearing
```bash
# This should not happen with dedup. Check DB:
sqlite3 /opt/pocket-siem/data/soc_bot.db \
  "SELECT vendor, alert_id, notified, received_at FROM security_events ORDER BY received_at DESC LIMIT 20;"
```

### Database growing too large
```bash
sqlite3 /opt/pocket-siem/data/soc_bot.db \
  "SELECT COUNT(*) FROM security_events; SELECT page_count * page_size / 1024 / 1024 as size_mb FROM pragma_page_count(), pragma_page_size();"
# Clean up old events (keep last 90 days):
sqlite3 /opt/pocket-siem/data/soc_bot.db \
  "DELETE FROM security_events WHERE received_at < datetime('now', '-90 days');"
sqlite3 /opt/pocket-siem/data/soc_bot.db "VACUUM;"
```

## Restart / Reload

```bash
# Restart (reloads config)
systemctl restart pocket-siem

# Stop
systemctl stop pocket-siem

# Start
systemctl start pocket-siem

# Disable auto-start
systemctl disable pocket-siem
```

## Backup

```bash
# Backup database and config
ssh root@46.224.84.130 \
  "tar -czf /tmp/pocket-siem-backup-$(date +%Y%m%d).tar.gz \
   /opt/pocket-siem/data/ && echo 'Backup created'"

# Download backup
scp root@46.224.84.130:/tmp/pocket-siem-backup-*.tar.gz .
```

## Upgrade

```bash
# 1. Back up database
ssh root@46.224.84.130 'cp -r /opt/pocket-siem/data /opt/pocket-siem/data.bak'

# 2. Copy new app code
scp -r soc_telegram_bot/app/ root@46.224.84.130:/opt/pocket-siem/

# 3. Update dependencies if needed
ssh root@46.224.84.130 '/opt/pocket-siem/.venv/bin/pip install -r /opt/pocket-siem/requirements.txt'

# 4. Restart
ssh root@46.224.84.130 'systemctl restart pocket-siem'
```

## Admin API Reference

All admin endpoints require: `Authorization: Bearer <ADMIN_API_KEY>`

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Public health check |
| `/ready` | GET | Readiness probe |
| `/admin/status` | GET | Bot configuration status |
| `/admin/events` | GET | Event list (filters: vendor, severity, limit, offset) |
| `/admin/stats` | GET | Event counts by vendor/severity |
| `/admin/pause` | POST | Pause notifications |
| `/admin/resume` | POST | Resume notifications |
| `/admin/set_severity` | POST | Change severity threshold (`?severity=high`) |
