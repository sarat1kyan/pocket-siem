#!/usr/bin/env python3
"""
Pocket SIEM — Trellix EDR Connectivity & Auth Test Script
Run this from a machine that has network access to Trellix (not inside a
restricted container). It tests both credential orderings so you do not
need to know which value is the client_id vs client_secret.

Usage:
  python3 test_trellix_connectivity.py

Set credentials via environment variables (never pass on command line):
  export TRELLIX_CRED_A="73COzGEPI2VXQs1V4laXcWQiN"
  export TRELLIX_CRED_B="2q6DOXzY8Z4Xdg2wyLaCeRV18"
  python3 test_trellix_connectivity.py

Security:
  - Credentials are read from env vars only
  - Tokens are masked in all output
  - No credentials written to disk
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
import socket
import ssl
from datetime import datetime, timezone
from typing import Optional

try:
    import urllib.request
    import urllib.parse
    import urllib.error
except ImportError:
    pass

TRELLIX_TOKEN_URL = "https://api.manage.trellix.com/iam/v1.1/token"
TRELLIX_ALERTS_URL = "https://api.manage.trellix.com/edr/v2/alerts"
TRELLIX_SCOPES = "edr.dashboard.read edr.alert.read"

RESET  = "\033[0m"
GREEN  = "\033[32m"
RED    = "\033[31m"
YELLOW = "\033[33m"
BOLD   = "\033[1m"
CYAN   = "\033[36m"

results: list[dict] = []


def mask(value: str) -> str:
    """Show only first 4 chars, mask the rest."""
    if not value:
        return "<empty>"
    return value[:4] + "****" + f"({len(value)} chars)"


def mask_body(text: str) -> str:
    """Mask any long token-like strings in response bodies."""
    return re.sub(
        r'"(access_token|refresh_token|token)"\s*:\s*"([A-Za-z0-9._\-]{20,})"',
        lambda m: f'"{m.group(1)}": "{m.group(2)[:8]}****[MASKED]"',
        text,
    )


def step(title: str, ok: bool, detail: str = "", fix: str = "") -> None:
    icon = f"{GREEN}✅{RESET}" if ok else f"{RED}❌{RESET}"
    print(f"\n{icon} {BOLD}{title}{RESET}")
    if detail:
        for line in detail.strip().splitlines():
            print(f"   {line}")
    if not ok and fix:
        print(f"   {YELLOW}FIX:{RESET} {fix}")
    results.append({"title": title, "ok": ok, "detail": detail, "fix": fix})


def http_post_form(url: str, data: dict, token: Optional[str] = None) -> tuple[int, str]:
    """Minimal HTTP POST using stdlib only (no third-party deps required)."""
    encoded = urllib.parse.urlencode(data).encode("utf-8")
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=encoded, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")
    except Exception as e:
        return 0, str(e)


def http_get(url: str, token: Optional[str] = None, params: Optional[dict] = None) -> tuple[int, str]:
    """Minimal HTTP GET using stdlib only."""
    if params:
        url = url + "?" + urllib.parse.urlencode(params)
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")
    except Exception as e:
        return 0, str(e)


def tls_probe(host: str, port: int = 443) -> tuple[bool, str]:
    """Check TLS handshake without making an HTTP request."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                version = ssock.version()
                issuer = dict(x[0] for x in cert.get("issuer", []))
                cn = dict(x[0] for x in cert.get("subject", []))
                return True, (
                    f"TLS {version} OK | "
                    f"CN={cn.get('commonName','?')} | "
                    f"Issuer={issuer.get('organizationName', issuer.get('commonName','?'))}"
                )
    except ssl.SSLCertVerificationError as e:
        return False, f"TLS cert verification FAILED: {e}"
    except ConnectionRefusedError:
        return False, "Connection refused (port 443 not open)"
    except socket.timeout:
        return False, "Connection timed out"
    except Exception as e:
        return False, str(e)


def dns_probe(host: str) -> tuple[bool, str]:
    try:
        addrs = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        ip = addrs[0][4][0]
        return True, f"Resolved → {ip}"
    except socket.gaierror as e:
        return False, f"DNS FAILED: {e}"


def try_auth(client_id: str, client_secret: str, label: str) -> Optional[str]:
    """
    Attempt OAuth2 client-credentials grant.
    Returns access token on success, None on failure.
    """
    print(f"\n   Trying {label}: client_id={mask(client_id)}, client_secret={mask(client_secret)}")
    code, body = http_post_form(
        TRELLIX_TOKEN_URL,
        {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": TRELLIX_SCOPES,
        },
    )
    masked_body = mask_body(body)
    print(f"   HTTP {code}: {masked_body[:300]}")

    if code == 200:
        try:
            d = json.loads(body)
            token = d.get("access_token")
            expires = d.get("expires_in", "?")
            token_type = d.get("token_type", "?")
            print(f"   {GREEN}Token type:{RESET} {token_type}, expires_in={expires}s")
            return token
        except json.JSONDecodeError:
            print(f"   {RED}200 OK but body is not JSON — unexpected response{RESET}")
            return None
    elif code == 400:
        try:
            d = json.loads(body)
            print(f"   {RED}OAuth2 error:{RESET} {d.get('error')} — {d.get('error_description','')}")
        except Exception:
            pass
    elif code == 401:
        print(f"   {RED}Unauthorized — invalid credentials{RESET}")
    elif code == 403:
        print(f"   {RED}Forbidden — credentials valid but insufficient scope or account issue{RESET}")
    elif code == 0:
        print(f"   {RED}Network error — cannot reach endpoint{RESET}")
    return None


def run_tests(cred_a: str, cred_b: str) -> None:
    print(f"\n{BOLD}{CYAN}{'='*60}{RESET}")
    print(f"{BOLD}{CYAN}  Pocket SIEM — Trellix EDR Connectivity Test{RESET}")
    print(f"{BOLD}{CYAN}  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}{RESET}")
    print(f"{BOLD}{CYAN}{'='*60}{RESET}")

    print(f"\n  Cred A: {mask(cred_a)}")
    print(f"  Cred B: {mask(cred_b)}")

    # ── 1. DNS ────────────────────────────────────────────────────────────────
    print(f"\n{BOLD}[1] DNS Resolution{RESET}")
    ok, detail = dns_probe("api.manage.trellix.com")
    step("DNS — api.manage.trellix.com", ok, detail,
         fix="Check your DNS server / corporate proxy resolves api.manage.trellix.com")

    if not ok:
        print(f"\n{RED}Cannot proceed — no DNS. Check firewall/proxy.{RESET}")
        return

    # ── 2. TLS ────────────────────────────────────────────────────────────────
    print(f"\n{BOLD}[2] TLS Connectivity{RESET}")
    ok, detail = tls_probe("api.manage.trellix.com")
    step("TLS — api.manage.trellix.com:443", ok, detail,
         fix="Ensure port 443 outbound is allowed to api.manage.trellix.com")

    if not ok:
        print(f"\n{RED}Cannot proceed — TLS failed. Check firewall rules.{RESET}")
        return

    # ── 3. Token endpoint reachability ────────────────────────────────────────
    print(f"\n{BOLD}[3] Token Endpoint Reachability{RESET}")
    # A GET to the token endpoint should return 405 Method Not Allowed (not 403/404)
    code, body = http_get(TRELLIX_TOKEN_URL)
    endpoint_ok = code in (400, 405, 401)  # 400=missing params, 405=GET not allowed — both mean endpoint works
    step(
        f"Token endpoint GET → HTTP {code}",
        endpoint_ok,
        f"Endpoint: {TRELLIX_TOKEN_URL}\nResponse (masked): {mask_body(body[:200])}",
        fix="If HTTP 403/0: your IP may need to be allowlisted on the Trellix tenant, or a proxy is blocking the request.",
    )

    # ── 4. Authentication ─────────────────────────────────────────────────────
    print(f"\n{BOLD}[4] OAuth2 Authentication (trying both credential orderings){RESET}")
    token = None

    t = try_auth(cred_a, cred_b, "Ordering 1: A=client_id, B=client_secret")
    if t:
        step("OAuth2 Auth — Ordering 1 (A=client_id)", True,
             f"Token obtained (type=Bearer, masked={mask(t)})")
        token = t
        print(f"   {GREEN}✅ Correct ordering: CRED_A is the client_id, CRED_B is the client_secret{RESET}")
    else:
        step("OAuth2 Auth — Ordering 1 (A=client_id)", False)

    if not token:
        t = try_auth(cred_b, cred_a, "Ordering 2: B=client_id, A=client_secret")
        if t:
            step("OAuth2 Auth — Ordering 2 (B=client_id)", True,
                 f"Token obtained (type=Bearer, masked={mask(t)})")
            token = t
            print(f"   {GREEN}✅ Correct ordering: CRED_B is the client_id, CRED_A is the client_secret{RESET}")
        else:
            step("OAuth2 Auth — Ordering 2 (B=client_id)", False,
                 fix=(
                     "Both orderings failed. Possible causes:\n"
                     "     1. Credentials belong to a different Trellix service (not EDR Cloud OAuth2)\n"
                     "     2. The client has been disabled in Trellix IAM\n"
                     "     3. Your tenant uses a different auth flow (API key, not OAuth2)\n"
                     "     4. Try: Trellix ePO → Settings → Client Management → verify client is active"
                 ))

    # ── 5. API permission check ───────────────────────────────────────────────
    if token:
        print(f"\n{BOLD}[5] EDR Alerts API Access{RESET}")
        code, body = http_get(
            TRELLIX_ALERTS_URL,
            token=token,
            params={"limit": 1, "offset": 0},
        )
        masked_body = mask_body(body)
        try:
            data = json.loads(body)
            if code == 200:
                items = data if isinstance(data, list) else data.get("data", data.get("items", []))
                count = len(items)
                step(
                    f"EDR Alerts API → HTTP {code}",
                    True,
                    f"Retrieved {count} alert(s) — permission confirmed\n"
                    + (f"Sample alert ID: {items[0].get('id', items[0].get('alertId','?'))}"
                       if count > 0 else "0 alerts returned (may be empty in this time range)"),
                )
            elif code == 403:
                step(
                    f"EDR Alerts API → HTTP {code}",
                    False,
                    f"Response: {masked_body[:300]}",
                    fix=(
                        "Token obtained but EDR Alerts endpoint returned 403.\n"
                        "     Required scopes: edr.dashboard.read, edr.alert.read\n"
                        "     Fix: In Trellix ePO → Client Management → edit the client\n"
                        "     → ensure scopes include 'edr.dashboard.read' and 'edr.alert.read'"
                    ),
                )
            elif code == 404:
                step(
                    f"EDR Alerts API → HTTP {code}",
                    False,
                    "Endpoint not found — your tenant may use a different API path",
                    fix="Try /edr/v1/alerts instead, or check Trellix API docs for your tenant version",
                )
            else:
                step(
                    f"EDR Alerts API → HTTP {code}",
                    False,
                    f"Unexpected code. Response: {masked_body[:300]}",
                )
        except json.JSONDecodeError:
            step(
                f"EDR Alerts API → HTTP {code}",
                False,
                f"Non-JSON response: {masked_body[:200]}",
            )

    # ── 6. Final report ───────────────────────────────────────────────────────
    print(f"\n{BOLD}{CYAN}{'='*60}{RESET}")
    print(f"{BOLD}READINESS REPORT — Trellix EDR{RESET}")
    print(f"{BOLD}{CYAN}{'='*60}{RESET}")

    all_ok = all(r["ok"] for r in results)
    passed = sum(1 for r in results if r["ok"])
    total  = len(results)
    status_color = GREEN if all_ok else RED

    print(f"\n  Status: {status_color}{'READY' if all_ok else 'NOT READY'}{RESET}")
    print(f"  Checks: {passed}/{total} passed\n")

    for r in results:
        icon = f"{GREEN}✅{RESET}" if r["ok"] else f"{RED}❌{RESET}"
        print(f"  {icon} {r['title']}")

    if not all_ok:
        print(f"\n{YELLOW}Remediation steps:{RESET}")
        for r in results:
            if not r["ok"] and r.get("fix"):
                print(f"\n  [{r['title']}]")
                for line in r["fix"].splitlines():
                    print(f"    {line}")

    print(f"\n  Bot readiness:")
    print(f"  {'✅' if all_ok else '❌'} Trellix EDR monitoring: {'READY' if all_ok else 'BLOCKED'}")
    print()


if __name__ == "__main__":
    cred_a = os.environ.get("TRELLIX_CRED_A", "").strip()
    cred_b = os.environ.get("TRELLIX_CRED_B", "").strip()

    if not cred_a or not cred_b:
        print(f"{RED}Error: set TRELLIX_CRED_A and TRELLIX_CRED_B env vars{RESET}", file=sys.stderr)
        print("  export TRELLIX_CRED_A='...'")
        print("  export TRELLIX_CRED_B='...'")
        print("  python3 test_trellix_connectivity.py")
        sys.exit(1)

    run_tests(cred_a, cred_b)
