"""
Cross-VPS Central Attack Database — GitHub Backend
====================================================
Stores attack data in GitHub repo as central_db.json.
Every VPS reads from and writes to the same file.

Rules enforced here (not in discord_alert.py):
  - Blank password  → skip report
  - Internal IP     → skip report
  - 24h cooldown    → 1 report per IP per day (globally across all VPS)
  - Campaign        → if 2+ IPs share same HASSH → report ALL linked IPs

Add a new VPS: just copy discord_alert.py + github_sync.py, fill CONFIG below.
"""

import os
import json
import time
import base64
import threading
import requests

# ====================== CONFIG ======================

GITHUB_REPO      = "tjxahmad/cowrie-soc-monitor"
CENTRAL_DB_FILE  = "central_db.json"

CAMPAIGN_MIN_IPS = 2       # 2+ IPs same HASSH = botnet campaign
REPORT_COOLDOWN  = 86400   # 24 hours in seconds

# Token NEVER hardcoded here (public repo). Read from env var or secret file.
#   Preferred: export GITHUB_TOKEN=ghp_xxx
#   Fallback : put token in /home/cowrie/.github_token  (chmod 600)
def _load_token():
    t = os.environ.get("GITHUB_TOKEN", "").strip()
    if t:
        return t
    for p in ("/home/cowrie/.github_token", os.path.expanduser("~/.github_token")):
        try:
            with open(p) as f:
                val = f.read().strip()
                if val:
                    return val
        except Exception:
            pass
    return ""

GITHUB_TOKEN = _load_token()

# ====================================================

_API_URL = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{CENTRAL_DB_FILE}"
_HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

if not GITHUB_TOKEN:
    print("[github_sync] WARNING: no GITHUB_TOKEN found (env or ~/.github_token) — cross-VPS sync disabled")

_lock = threading.Lock()

_INTERNAL = ("172.", "127.", "192.168.", "10.")

_EMPTY_DB = {
    "hassh_to_ips": {},  # hassh  -> [ip, ...]
    "ip_to_hashes": {},  # ip     -> [hassh, ...]
    "reported_ips": {},  # ip     -> last_reported_unix_timestamp
}


# ====================== GITHUB API ======================

def _fetch_db():
    """Fetch central_db.json from GitHub. Returns (data_dict, sha)."""
    try:
        resp = requests.get(_API_URL, headers=_HEADERS, timeout=12)
        if resp.status_code == 404:
            return dict({k: dict(v) for k, v in _EMPTY_DB.items()}), None
        resp.raise_for_status()
        j = resp.json()
        raw = base64.b64decode(j["content"]).decode("utf-8")
        return json.loads(raw), j["sha"]
    except Exception as e:
        print(f"[github_sync] fetch error: {e}")
        return None, None


def _push_db(data, sha):
    """
    Write updated data back to GitHub.
    Returns "ok" | "conflict" | "fail".
    "conflict" (HTTP 409) means another VPS pushed first — caller should
    re-fetch and retry.
    """
    try:
        encoded = base64.b64encode(
            json.dumps(data, indent=2, default=list).encode()
        ).decode()
        payload = {
            "message": "soc-auto: update central attack db",
            "content": encoded,
        }
        if sha:
            payload["sha"] = sha
        resp = requests.put(_API_URL, headers=_HEADERS, json=payload, timeout=20)
        if resp.status_code in (200, 201):
            return "ok"
        if resp.status_code == 409:
            return "conflict"
        print(f"[github_sync] push failed {resp.status_code}: {resp.text[:200]}")
        return "fail"
    except Exception as e:
        print(f"[github_sync] push error: {e}")
        return "fail"


# ====================== MAIN ENTRY POINT ======================

def register_and_report(ip, hassh, password, report_fn, session="N/A"):
    """
    Called on every cowrie.login.success event.

    Parameters
    ----------
    ip        : attacker IP
    hassh     : SSH client fingerprint hash (from cowrie.client.kex)
    password  : password they used (blank = skip)
    report_fn : discord_alert.py's report_to_abuseipdb(ip, categories, comment)
    session   : cowrie session ID (for comment)

    Returns
    -------
    dict with keys: skipped_blank, skipped_internal, reported, campaign, campaign_ips
    """

    if not password:
        return {"skipped_blank": True, "reported": [], "campaign": False, "campaign_ips": []}

    if ip == "Unknown IP" or ip.startswith(_INTERNAL):
        return {"skipped_internal": True, "reported": [], "campaign": False, "campaign_ips": []}

    to_report    = []
    campaign_ips = []
    is_campaign  = False
    push_status  = "fail"

    # _lock serializes writers WITHIN one VPS. Cross-VPS races are handled by
    # the fetch→modify→push→(retry on 409) loop below, since GitHub rejects a
    # PUT whose base SHA is stale. Reports fire only AFTER a successful push,
    # so a retry never double-reports.
    with _lock:
        for attempt in range(6):
            db, sha = _fetch_db()
            if db is None:
                time.sleep(min(2 ** attempt, 8))
                continue

            now          = time.time()
            to_report    = []
            campaign_ips = []
            is_campaign  = False
            changed      = False

            # Register IP → HASSH mapping
            if hassh:
                hashes_for_ip = db["ip_to_hashes"].setdefault(ip, [])
                if hassh not in hashes_for_ip:
                    hashes_for_ip.append(hassh)
                    changed = True

                ips_for_hash = db["hassh_to_ips"].setdefault(hassh, [])
                if ip not in ips_for_hash:
                    ips_for_hash.append(ip)
                    changed = True

                campaign_ips = list(db["hassh_to_ips"][hassh])
                is_campaign  = len(campaign_ips) >= CAMPAIGN_MIN_IPS

            # 24h cooldown for the triggering IP
            if (now - db["reported_ips"].get(ip, 0)) > REPORT_COOLDOWN:
                to_report.append(ip)
                db["reported_ips"][ip] = now
                changed = True

            # Campaign: also report other linked IPs that are due
            if is_campaign:
                for linked_ip in campaign_ips:
                    if linked_ip == ip:
                        continue
                    if (now - db["reported_ips"].get(linked_ip, 0)) > REPORT_COOLDOWN:
                        to_report.append(linked_ip)
                        db["reported_ips"][linked_ip] = now
                        changed = True

            # Nothing new to persist → skip the write entirely (avoids needless
            # commits + conflicts). Mapping already known, IP within cooldown.
            if not changed:
                push_status = "ok"
                break

            push_status = _push_db(db, sha)
            if push_status == "ok":
                break
            if push_status == "conflict":
                # Another VPS wrote first — re-fetch and recompute. The updated
                # cooldown timestamps will correctly de-dupe reports.
                time.sleep(0.5 + 0.3 * attempt)
                continue
            # hard failure — stop retrying
            break

    if push_status != "ok":
        return {"error": f"push_{push_status}", "reported": [], "campaign": is_campaign, "campaign_ips": campaign_ips}

    # Fire AbuseIPDB reports outside the lock — only after a confirmed write
    for r_ip in to_report:
        if is_campaign:
            cats    = "14,18,22"
            comment = (
                f"SSH brute-force honeypot (Cowrie). "
                f"Part of botnet campaign — HASSH {hassh} shared by "
                f"{len(campaign_ips)} IPs: "
                f"{', '.join(campaign_ips[:8])}{'...' if len(campaign_ips) > 8 else ''}. "
                f"Session: {session}"
            )
        else:
            cats    = "18,22"
            comment = (
                f"SSH brute-force honeypot (Cowrie). "
                f"HASSH fingerprint: {hassh}. Session: {session}"
            )
        report_fn(r_ip, cats, comment)

    return {
        "skipped_blank":    False,
        "skipped_internal": False,
        "reported":         to_report,
        "campaign":         is_campaign,
        "campaign_ips":     campaign_ips,
    }
