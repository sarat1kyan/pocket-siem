# Pocket SIEM — Troubleshooting Guide

## Quick Diagnostics

```bash
# All-in-one status check
ssh root@46.224.84.130 << 'EOF'
echo "=== Service ===" && systemctl status pocket-siem --no-pager
echo "=== Health ===" && curl -s http://127.0.0.1:8080/health
echo "=== Last 20 log lines ===" && journalctl -u pocket-siem -n 20 --no-pager
echo "=== DB events ===" && sqlite3 /opt/pocket-siem/data/soc_bot.db \
  "SELECT vendor,severity,notified,substr(received_at,1,19) FROM security_events ORDER BY received_at DESC LIMIT 5;" 2>/dev/null || echo "DB empty or not created yet"
EOF
```

---

## Problem: Service fails to start

**Symptom:** `systemctl status pocket-siem` shows `failed` or `activating`

**Steps:**
```bash
journalctl -u pocket-siem -n 50 --no-pager
```

| Error in logs | Cause | Fix |
|---|---|---|
| `TELEGRAM_BOT_TOKEN is required` | Missing env var | Check `/opt/pocket-siem/.env` |
| `ADMIN_API_KEY is required` | Missing env var | Add `ADMIN_API_KEY=...` to `.env` |
| `ValidationError` | Bad value in .env | Check `MIN_SEVERITY`, `ALLOWED_TELEGRAM_USER_IDS` format |
| `ModuleNotFoundError` | Deps not installed | `cd /opt/pocket-siem && .venv/bin/pip install -r requirements.txt` |
| `Address already in use` | Port 8080 taken | `ss -tlnp \| grep 8080` — kill conflicting process or change `API_PORT` |
| `Permission denied` | Wrong file owner | `chown -R root:root /opt/pocket-siem` |

---

## Problem: No Telegram messages received

**Step 1 — Verify bot token**
```bash
TOKEN=$(grep TELEGRAM_BOT_TOKEN /opt/pocket-siem/.env | cut -d= -f2)
curl -s "https://api.telegram.org/bot${TOKEN}/getMe"
# Expected: {"ok":true, "result":{"username":"..."}}
```

**Step 2 — Verify your user ID is in the allowlist**
```bash
grep ALLOWED_TELEGRAM_USER_IDS /opt/pocket-siem/.env
# Send /whoami to the bot from Telegram — it shows your ID even if not on allowlist
```

**Step 3 — Enable mock mode**
```bash
sed -i 's/MOCK_MODE=false/MOCK_MODE=true/' /opt/pocket-siem/.env
sed -i 's/MIN_SEVERITY=.*/MIN_SEVERITY=low/' /opt/pocket-siem/.env
systemctl restart pocket-siem
# Wait 60-70 seconds — mock alerts should appear in Telegram
```

**Step 4 — Send a direct test message**
```bash
TOKEN=$(grep TELEGRAM_BOT_TOKEN /opt/pocket-siem/.env | cut -d= -f2)
USER_ID=$(grep ALLOWED_TELEGRAM_USER_IDS /opt/pocket-siem/.env | cut -d= -f2 | cut -d, -f1)
curl -s "https://api.telegram.org/bot${TOKEN}/sendMessage" \
  -d "chat_id=${USER_ID}&text=Test+from+server"
```

---

## Problem: Trellix authentication fails

**Symptom:** Logs show `Trellix HTTP error 401` or `Trellix fetch error`

**Step 1 — Verify credentials in .env**
```bash
grep TRELLIX /opt/pocket-siem/.env | grep -v "^#"
```

**Step 2 — Test OAuth2 manually**
```bash
CLIENT_ID=$(grep TRELLIX_CLIENT_ID /opt/pocket-siem/.env | cut -d= -f2)
CLIENT_SECRET=$(grep TRELLIX_CLIENT_SECRET /opt/pocket-siem/.env | cut -d= -f2)
curl -X POST "https://api.manage.trellix.com/iam/v1.1/token" \
  -d "grant_type=client_credentials&client_id=${CLIENT_ID}&client_secret=${CLIENT_SECRET}&scope=edr.dashboard.read%20edr.alert.read"
# Expected: {"access_token":"...","token_type":"Bearer","expires_in":3600}
```

**Step 3 — Try swapped credentials** (if Step 2 fails with 400/401)
```bash
# Swap client_id and client_secret in .env and retry:
sed -i 's/TRELLIX_CLIENT_ID=\(.*\)/TRELLIX_CLIENT_ID=SWAP_TEMP/' /opt/pocket-siem/.env
# This confirms which credential is which
```

**Step 4 — Verify Trellix API reachability**
```bash
curl -I https://api.manage.trellix.com/edr/v2/alerts
# Expected: HTTP 401 (needs auth) or HTTP 400 (bad request)
# If timeout/connection refused: check outbound firewall on server
```

**Remediation options:**

| Scenario | Fix |
|---|---|
| Both orderings return 400 | Credentials may be API keys not OAuth2 — set `TRELLIX_API_KEY` instead |
| Returns 403 | Check tenant ID, IP allowlist in Trellix portal |
| Returns 401 | Credentials revoked — re-generate in ePO → Client Management |
| Timeout | Server can't reach `api.manage.trellix.com` — check iptables/ufw |

---

## Problem: Palo Alto authentication fails

**Step 1 — Test API key**
```bash
KEY=$(grep PALOALTO_API_KEY /opt/pocket-siem/.env | cut -d= -f2)
HOST=$(grep PALOALTO_HOSTNAME /opt/pocket-siem/.env | cut -d= -f2)
curl -k "https://${HOST}/api/?type=op&cmd=<show><system><info></info></system></show>&key=${KEY}"
# Expected: XML with status="success"
```

**Step 2 — Generate a new key**
```bash
curl -k "https://${HOST}/api/?type=keygen&user=admin&password=YOUR_PASS"
# Copy the <key> value into PALOALTO_API_KEY in .env
systemctl restart pocket-siem
```

---

## Problem: High memory / CPU usage

```bash
# Check process stats
systemctl status pocket-siem
ps aux | grep python

# Reduce polling frequency
sed -i 's/POLL_INTERVAL_SECONDS=.*/POLL_INTERVAL_SECONDS=300/' /opt/pocket-siem/.env
systemctl restart pocket-siem

# Increase severity threshold to process fewer events
sed -i 's/MIN_SEVERITY=.*/MIN_SEVERITY=critical/' /opt/pocket-siem/.env
systemctl restart pocket-siem
```

---

## Problem: Database locked errors

```bash
# SQLite WAL mode is on by default — check if stale lock exists
ls -la /opt/pocket-siem/data/
# If .db-wal or .db-shm exist and service is stopped, they're safe to delete
systemctl stop pocket-siem
rm -f /opt/pocket-siem/data/soc_bot.db-wal /opt/pocket-siem/data/soc_bot.db-shm
systemctl start pocket-siem
```

---

## Emergency: Reset database (loses all event history)

```bash
systemctl stop pocket-siem
cp /opt/pocket-siem/data/soc_bot.db /tmp/soc_bot.db.backup.$(date +%s)
rm /opt/pocket-siem/data/soc_bot.db
systemctl start pocket-siem
# DB will be recreated from scratch on next start
```

---

## Log Location Reference

| Log | Location |
|---|---|
| Application logs | `journalctl -u pocket-siem` |
| systemd journal | `/var/log/journal/` |
| logrotate | `/var/log/pocket-siem/` (if configured for file output) |
| Docker logs | `docker logs pocket-siem` (if using Docker deployment) |
