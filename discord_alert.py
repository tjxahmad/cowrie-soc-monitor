"""
SOC Threat Intel Monitor - Full Edition v2.0
==============================================
Original features:
1. Automated AbuseIPDB Reporting
2. VirusTotal Hash Lookup
3. Multi-API Failover for IP Geolocation
4. Live Terminal Shadowing
5. C2 / IOC Extraction + MalwareBazaar auto-share
6. Dynamic Sandbox Auto-Triage (Docker)
7. SSH Client Fingerprinting via HASSH
8. Crypto Wallet Scraper

New features in v2.0:
9.  Honeytoken Traps — Fake AWS keys / .env files / wallet seeds planted in
    honeypot filesystem. When attacker uses them, you get a canary-style alert.
    (AWS key canary works via CloudTrail / CanaryTokens.org; wallet canary via
    blockchain watch addresses)
10. Attacker Scorecard / Wall of Shame — Each IP gets points (login=+1,
    malware=+10, wallet found=+5, repeat visit=+3) and a title. Live Discord
    leaderboard updates automatically.
11. Tarpit / Zip-Bomb Decoy — When attacker downloads a file, optionally serve
    them a "zip bomb" style decoy that expands massively, stalling their bot.
    NOTE: This feature is Cowrie-side (Cowrie's honeyfs), documented here only.
12. Recidivism Tracker — Persistent cross-session memory (survives restarts).
    "REPEAT OFFENDER — last seen 3 days ago, total attempts: X" Discord alert.
13. Auto-Drafted Abuse Complaint — WHOIS/ASN lookup for attacker's hosting
    provider abuse email, ready-made professional complaint drafted to Discord.
14. Campaign Detector — Same HASSH or wallet across multiple IPs = one botnet
    operator. All linked IPs reported together automatically.
15. Live World-Map Attack Visualization — HTML dashboard auto-generated with
    real-time attack map (served locally, updates via JSON feed).
16. Daily "Body Count" Digest — Every night at midnight, Discord gets a full
    day summary: attempts, malware, reports, wallets, top attacker, etc.

Bug Fixes vs v1.0:
- BUG FIX: Log file rotation (logrotate) caused script to read stale handle
  after 24h. Fixed via inode-check loop that detects rotation and re-opens.
- BUG FIX: Single-threaded blocking meant cowrie.client.kex's slow geo-lookup
  could delay login/command event processing. Fixed via ThreadPoolExecutor.
- BUG FIX: live_sessions memory leak when cowrie.session.closed was missed.
  Fixed via TTL-based session expiry (30 min timeout).
- BUG FIX: Discord 429 rate-limit on edit_live_message was silently dropped.
  Fixed via exponential backoff retry.
- BUG FIX: reported_ips_cache lost on restart — fixed via persistent JSON file.
- BUG FIX: No crash recovery — added top-level exception handler with auto-
  restart loop so the monitor never goes down permanently.
"""

import time
import json
import re
import os
import csv
import io
import subprocess
import shutil
import socket
import smtplib
import threading
import ipaddress
from pathlib import Path
from datetime import datetime, date
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict

import requests
from github_sync import register_and_report as _gh_report

# ====================== CONFIG ======================

WEBHOOK_URL = "YOUR_DISCORD_WEBHOOK_URL_HERE"
# How to get: Discord Server → Channel Settings → Integrations → Webhooks → New Webhook → Copy URL

LOG_FILE_PATH = "/home/cowrie/cowrie-git/var/log/cowrie/cowrie.json"
# If Cowrie runs in Docker, find your path with:
#   find /var/lib/docker -name "cowrie.json" 2>/dev/null

ABUSEIPDB_API_KEY   = "YOUR_ABUSEIPDB_API_KEY_HERE"
# Free key at: https://www.abuseipdb.com/register

VIRUSTOTAL_API_KEY  = "YOUR_VIRUSTOTAL_API_KEY_HERE"
# Free key at: https://www.virustotal.com/gui/join-us

ABUSECH_AUTH_KEY    = ""
# Optional — free key at: https://auth.abuse.ch/
# Leave blank to skip MalwareBazaar auto-sharing

# Recidivism / scorecard persistent storage (survives restarts)
PERSISTENT_DB_PATH  = "/home/cowrie/soc_monitor_db.json"

# Where to save threat-intel markdown reports
REPORTS_DIR         = "/home/cowrie/threat_reports"

# Live shadowing
LIVE_SHADOW_CHAR_BUDGET = 950
LIVE_LOGS_DIR       = "/home/cowrie/live_sessions"

# Sandbox
SANDBOX_IMAGE       = "alpine:3.19"
SANDBOX_TIMEOUT     = 10

# HASSH databases
HASSHDB_URL              = "https://raw.githubusercontent.com/0x4D31/hassh-utils/master/hasshdb"
SALESFORCE_HASSH_CSV_URL = "https://github.com/salesforce/hassh/raw/refs/heads/master/python/hasshGen/hassh_fingerprints.csv"
HASSH_CACHE_DIR          = "/home/cowrie/hassh_cache"
HASSH_CACHE_MAX_AGE      = 30 * 24 * 60 * 60
CUSTOM_HASSH_FILE        = "/home/cowrie/custom_hassh.json"
UNKNOWN_HASSH_LOG        = "/home/cowrie/unknown_hassh.log"

# Report cooldown — don't re-report same IP within this many seconds
REPORT_COOLDOWN     = 24 * 60 * 60

# Daily digest time (24h format, local server time)
DIGEST_HOUR         = 0   # midnight
DIGEST_MINUTE       = 0

# Honeytoken config
# Place these fake credentials in your Cowrie honeyfs so attackers find them.
# When an attacker uses a fake AWS key externally, AWS CloudTrail fires an
# alert. Use https://canarytokens.org to generate keys that send YOU an email.
# The wallet addresses below are watch-addresses — use a blockchain notifier
# service (e.g. https://blockonomics.co or https://etherscan.io/myapikey alerts)
# to get notified if anyone sends to or from them.
HONEYTOKENS = {
    "aws_keys": [
        # Generate real canary AWS keys at https://canarytokens.org/generate
        # Format: {"access_key": "AKIA...", "secret_key": "...", "note": "found in /root/.aws/credentials"}
    ],
    "wallet_seeds": [
        # Fake BTC/ETH addresses you control or watch — if attacker tries to
        # drain them you'll see it on-chain
    ],
    "env_vars": [
        # Fake API keys to plant in /home/cowrie/honeyfs/root/.env
        # e.g. "STRIPE_SECRET_KEY=sk_live_FAKEFAKEFAKE"
    ],
}

# Campaign detector thresholds
CAMPAIGN_MIN_IPS         = 3    # how many different IPs with same HASSH/wallet before it's a "campaign"
CAMPAIGN_REPORT_COOLDOWN = 3600 # seconds between campaign Discord alerts for same fingerprint

INTERNAL_PREFIXES = ("172.", "127.", "192.168.", "10.")

# ====================== STATE (in-memory, backed by persistent DB) ======================

# Loaded from / saved to PERSISTENT_DB_PATH
_db = {
    "reported_ips":   {},   # ip -> last_reported_unix_timestamp
    "scorecard":      {},   # ip -> {score, title, attempts, malware, wallets, first_seen, last_seen, sessions:[]}
    "recidivism":     {},   # ip -> {count, first_seen, last_seen, sessions:[]}
    "daily_stats":    {},   # "YYYY-MM-DD" -> {attempts, malware, reports, wallets, top_ip}
    "hassh_to_ips":   {},   # hassh -> [ip, ip, ...]  (campaign detector)
    "wallet_to_ips":  {},   # wallet_addr -> [ip, ip, ...]
    "campaign_alerted": {}, # fingerprint -> last_alerted_timestamp
}

live_sessions  = {}          # session_id -> {...}  (in-memory only, TTL-expired)
_session_hassh = {}          # session_id -> hassh  (for cross-VPS github sync)
_db_lock = threading.Lock()
_discord_lock = threading.Lock()

custom_hassh_db    = {}
salesforce_hassh_db= {}
big_hassh_db       = {}

SANDBOX_ENABLED = shutil.which("docker") is not None
if not SANDBOX_ENABLED:
    print("⚠️  Docker nahi mila — Dynamic Sandbox disabled. (apt install docker.io)")

KNOWN_HASSH_DB = {
    "de30354b88bae4c2810426614e1b6976": "PowerShell Renci.SshNet — commonly used by Empire C2 framework",
    "fafc45381bfde997b6305c4e1600f1bf": "Ruby Net::SSH — commonly used by Metasploit modules",
    "b5752e36ba6c5979a575e43178908adf": "Python Paramiko 2.4.1 — common in bots/scanners, also Metasploit",
    "16f898dd8ed8279e1055350b4e20666c": "Dropbear SSH (2012.55) — typically embedded/IoT devices",
    "8a8ae540028bf433cd68356c1b9e8d5b": "CyberDuck 6.7.1 SFTP client",
    "06046964c022c6407d15a27b12a6a4fb": "OpenSSH 7.7p1 (Ubuntu) — standard Linux SSH client",
}

TELEGRAM_TOKEN_RE = re.compile(r'\b\d{8,10}:[A-Za-z0-9_-]{35}\b')
IPV4_RE           = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b')
URL_RE            = re.compile(r'https?://[^\s\'"<>]+')
BTC_RE            = re.compile(r'\b(bc1[a-z0-9]{25,90}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b')
ETH_RE            = re.compile(r'\b0x[a-fA-F0-9]{40}\b')
XMR_RE            = re.compile(r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b')

executor = ThreadPoolExecutor(max_workers=8)

# ====================== SCORECARD / TITLES ======================

SCORE_RULES = {
    "login":   1,
    "malware": 10,
    "wallet":  5,
    "repeat":  3,
    "command": 0,   # commands themselves don't add score (too spammy)
    "ioc":     2,
}

def _get_title(score):
    if score >= 50:  return "👹 APEX PREDATOR"
    if score >= 30:  return "💀 Persistent Menace"
    if score >= 15:  return "🔥 Botnet Operator"
    if score >= 8:   return "🤖 Botnet Drone"
    if score >= 3:   return "😈 Script Kiddie"
    return "🐣 Noob Probe"

def update_scorecard(ip, event_type, session=None):
    """Thread-safe scorecard update. Returns (new_score, title, is_new_high)."""
    points = SCORE_RULES.get(event_type, 0)
    today  = str(date.today())

    with _db_lock:
        sc = _db["scorecard"].setdefault(ip, {
            "score": 0, "attempts": 0, "malware": 0, "wallets": 0,
            "first_seen": time.time(), "last_seen": time.time(), "sessions": [],
        })
        old_score  = sc["score"]
        sc["score"] += points
        sc["last_seen"] = time.time()
        if event_type == "login":  sc["attempts"] += 1
        if event_type == "malware": sc["malware"] += 1
        if event_type == "wallet":  sc["wallets"] += 1
        if session and session not in sc["sessions"]:
            sc["sessions"].append(session)

        # daily stats
        ds = _db["daily_stats"].setdefault(today, {
            "attempts": 0, "malware": 0, "reports": 0, "wallets": 0,
            "ips": [], "top_ip": None,
        })
        if event_type == "login":   ds["attempts"] += 1
        if event_type == "malware": ds["malware"]  += 1
        if event_type == "wallet":  ds["wallets"]  += 1
        if ip not in ds["ips"]:     ds["ips"].append(ip)

        new_score = sc["score"]
        title     = _get_title(new_score)
        is_new_high = new_score > old_score
        sc["title"] = title

    _save_db()
    return new_score, title, is_new_high

def get_leaderboard(top_n=10):
    with _db_lock:
        scores = [(ip, d["score"], d.get("title",""), d.get("attempts",0),
                   d.get("malware",0), d.get("wallets",0))
                  for ip, d in _db["scorecard"].items()]
    scores.sort(key=lambda x: x[1], reverse=True)
    return scores[:top_n]

# ====================== PERSISTENT DB ======================

def _load_db():
    global _db
    if os.path.isfile(PERSISTENT_DB_PATH):
        try:
            with open(PERSISTENT_DB_PATH, "r") as f:
                loaded = json.load(f)
            # merge keys so new keys added in future versions survive
            for k in _db:
                if k in loaded:
                    _db[k] = loaded[k]
            print(f"✅ Persistent DB loaded ({PERSISTENT_DB_PATH})")
        except Exception as e:
            print(f"⚠️  Could not load persistent DB: {e} — starting fresh")

def _save_db():
    try:
        Path(os.path.dirname(PERSISTENT_DB_PATH)).mkdir(parents=True, exist_ok=True)
        tmp = PERSISTENT_DB_PATH + ".tmp"
        with open(tmp, "w") as f:
            json.dump(_db, f, indent=2, default=list)
        os.replace(tmp, PERSISTENT_DB_PATH)
    except Exception as e:
        print(f"⚠️  Could not save persistent DB: {e}")

# ====================== DISCORD HELPERS ======================

def _discord_post(url, payload, retries=3):
    """POST with exponential backoff on 429 rate limit."""
    for attempt in range(retries):
        try:
            with _discord_lock:
                resp = requests.post(url, json=payload, timeout=8)
            if resp.status_code == 429:
                wait = float(resp.headers.get("Retry-After", 2 ** attempt))
                print(f"⚠️  Discord rate-limited — waiting {wait:.1f}s")
                time.sleep(wait)
                continue
            return resp
        except Exception as e:
            print(f"⚠️  Discord POST error (attempt {attempt+1}): {e}")
            time.sleep(2 ** attempt)
    return None

def _discord_patch(url, payload, retries=3):
    """PATCH with exponential backoff."""
    for attempt in range(retries):
        try:
            with _discord_lock:
                resp = requests.patch(url, json=payload, timeout=8)
            if resp.status_code == 429:
                wait = float(resp.headers.get("Retry-After", 2 ** attempt))
                time.sleep(wait)
                continue
            return resp
        except Exception as e:
            print(f"⚠️  Discord PATCH error (attempt {attempt+1}): {e}")
            time.sleep(2 ** attempt)
    return None

def send_to_discord(embed_payload):
    executor.submit(_discord_post, WEBHOOK_URL, {"embeds": [embed_payload]})

def send_live_message(embed_payload):
    resp = _discord_post(f"{WEBHOOK_URL}?wait=true", {"embeds": [embed_payload]})
    if resp and resp.status_code in (200, 201):
        return resp.json().get("id")
    return None

def edit_live_message(message_id, embed_payload):
    _discord_patch(f"{WEBHOOK_URL}/messages/{message_id}", {"embeds": [embed_payload]})

def append_to_session_log(log_path, cmd):
    try:
        Path(os.path.dirname(log_path)).mkdir(parents=True, exist_ok=True)
        with open(log_path, "a") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {cmd}\n")
    except Exception as e:
        print(f"⚠️  Could not write session log: {e}")

# ====================== LIVE SHADOWING EMBED ======================

def build_live_embed(ip, country, city, isp, flag, session, buffer_commands,
                     part=1, total=None, log_path=None, ended=False, rolled_over=False,
                     score=0, title=""):
    transcript = "\n".join(f"$ {c}" for c in buffer_commands)
    if len(transcript) > 1000:
        transcript = transcript[-1000:]

    if ended:
        embed_title = f"🔚 SESSION ENDED (Part {part})"
        color = 9807270
    elif rolled_over:
        embed_title = f"📜 Part {part} Filled — Continued Below ⬇️"
        color = 3066993
    else:
        embed_title = f"🔴 LIVE — Attacker Typing Right Now (Part {part})"
        color = 8359053

    fields = [
        {"name": "👤 Attacker IP",  "value": str(ip),                     "inline": True},
        {"name": "🌍 Location",     "value": f"{flag} {city}, {country}", "inline": True},
        {"name": "🏢 ISP",          "value": str(isp),                    "inline": True},
        {"name": "🎖️ Threat Level", "value": f"{title}  (Score: {score})", "inline": True},
        {"name": "🖥️ Terminal Feed",
         "value": f"```bash\n{transcript}\n```",                            "inline": False},
        {"name": "🆔 Session",      "value": str(session),                "inline": True},
        {"name": "📊 Total Commands","value": str(total if total is not None else len(buffer_commands)), "inline": True},
    ]
    if log_path:
        fields.append({"name": "📁 Full Local Transcript", "value": log_path, "inline": False})

    return {
        "title": embed_title, "color": color, "fields": fields,
        "footer": {"text": "Interactive Shadowing — Live Honeypot Monitor"},
    }

# ====================== SESSION TTL EXPIRY (Bug Fix #3) ======================

SESSION_TTL = 30 * 60  # 30 minutes — if no event arrives, assume closed

def _expire_old_sessions():
    """Background thread that cleans up sessions with no activity for SESSION_TTL."""
    while True:
        time.sleep(60)
        now = time.time()
        to_remove = []
        for sess_id, sess in list(live_sessions.items()):
            if now - sess.get("last_activity", now) > SESSION_TTL:
                to_remove.append(sess_id)
        for sess_id in to_remove:
            sess = live_sessions.pop(sess_id, None)
            if sess and sess.get("message_id"):
                embed = build_live_embed(
                    sess["ip"], sess["country"], sess["city"], sess["isp"], sess["flag"],
                    sess_id, sess["buffer"], part=sess["part"],
                    total=sess["total_commands"], log_path=sess["log_path"],
                    ended=True, score=sess.get("score", 0), title=sess.get("title", ""),
                )
                edit_live_message(sess["message_id"], embed)
            print(f"⏱️  Session {sess_id} expired due to inactivity (TTL)")

# ====================== IP GEOLOCATION ======================

def _try_ip_api(ip):
    resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=4)
    if resp.status_code == 429:
        raise RuntimeError("rate-limited")
    data = resp.json()
    if data.get("status") == "success":
        return (data.get("country","Unknown"), data.get("city","Unknown"),
                data.get("isp","Unknown"), data.get("countryCode","").lower(),
                data.get("as",""), data.get("org",""))
    raise RuntimeError(data.get("message","lookup failed"))

def _try_ipinfo(ip):
    resp = requests.get(f"https://ipinfo.io/{ip}/json", timeout=4)
    data = resp.json()
    if "error" in data or "bogon" in data:
        raise RuntimeError("lookup failed")
    cc = data.get("country","")
    return (cc or "Unknown", data.get("city","Unknown"),
            data.get("org","Unknown"), cc.lower(), data.get("org",""), data.get("org",""))

def _try_ipapi_co(ip):
    resp = requests.get(f"https://ipapi.co/{ip}/json/", timeout=4)
    data = resp.json()
    if data.get("error"):
        raise RuntimeError(data.get("reason","lookup failed"))
    return (data.get("country_name","Unknown"), data.get("city","Unknown"),
            data.get("org","Unknown"), data.get("country_code","").lower(),
            data.get("asn",""), data.get("org",""))

def get_ip_intel(ip):
    if ip == "Unknown IP" or ip.startswith(INTERNAL_PREFIXES):
        return "Internal", "Local Network", "N/A", ":pirate_flag:", "", ""

    for name, func in (("ip-api.com", _try_ip_api), ("ipinfo.io", _try_ipinfo), ("ipapi.co", _try_ipapi_co)):
        try:
            country, city, isp, cc, asn, org = func(ip)
            flag = f":flag_{cc}:" if cc else ":world_map:"
            return country, city, isp, flag, asn, org
        except Exception as e:
            print(f"⚠️  {name} failed for {ip}: {e}")
            continue

    return "Unknown", "Unknown", "Unknown", ":world_map:", "", ""

# ====================== ABUSEIPDB REPORTING ======================

def should_report(ip):
    now = time.time()
    with _db_lock:
        last = _db["reported_ips"].get(ip)
        if REPORT_COOLDOWN <= 0 or last is None or (now - last) > REPORT_COOLDOWN:
            _db["reported_ips"][ip] = now
            _save_db()
            return True
    return False

def report_to_abuseipdb(ip, categories, comment):
    if ip == "Unknown IP" or ip.startswith(INTERNAL_PREFIXES):
        return None
    url = "https://api.abuseipdb.com/api/v2/report"
    headers = {"Accept": "application/json", "Key": ABUSEIPDB_API_KEY}
    params  = {"ip": ip, "categories": categories, "comment": comment}
    try:
        resp = requests.post(url, headers=headers, params=params, timeout=8)
        data = resp.json()
        if resp.status_code == 200:
            with _db_lock:
                today = str(date.today())
                _db["daily_stats"].setdefault(today, {
                    "attempts":0,"malware":0,"reports":0,"wallets":0,"ips":[],"top_ip":None
                })["reports"] = _db["daily_stats"][today].get("reports",0) + 1
            _save_db()
            return data
        print(f"⚠️  AbuseIPDB report failed for {ip}: {data}")
    except Exception as e:
        print(f"⚠️  AbuseIPDB network error for {ip}: {e}")
    return None

# ====================== RECIDIVISM TRACKER (Feature #4 / Bug Fix #5) ======================

def check_recidivism(ip, session):
    """Returns (is_repeat, visit_count, days_since_last) — persists across restarts."""
    now = time.time()
    with _db_lock:
        rec = _db["recidivism"].setdefault(ip, {
            "count": 0, "first_seen": now, "last_seen": now, "sessions": []
        })
        prev_count    = rec["count"]
        prev_last     = rec["last_seen"]
        rec["count"] += 1
        rec["last_seen"] = now
        if session not in rec["sessions"]:
            rec["sessions"].append(session)
    _save_db()

    if prev_count == 0:
        return False, 1, 0

    days_ago = (now - prev_last) / 86400
    return True, rec["count"], days_ago

# ====================== VIRUSTOTAL ======================

def check_virustotal_hash(file_hash):
    url     = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 404: return {"found": False}
        if resp.status_code == 429:
            print("⚠️  VirusTotal rate-limited (free tier: 4 req/min).")
            return None
        if resp.status_code != 200:
            print(f"⚠️  VirusTotal error {resp.status_code}")
            return None
        data       = resp.json()
        attributes = data.get("data",{}).get("attributes",{})
        stats      = attributes.get("last_analysis_stats",{}) or {}
        malicious  = stats.get("malicious",0)
        suspicious = stats.get("suspicious",0)
        total      = sum(stats.values()) if stats else 0
        threat_label = (attributes.get("popular_threat_classification",{}) or {}).get("suggested_threat_label","Unknown")
        return {
            "found": True, "malicious": malicious, "suspicious": suspicious,
            "total": total, "threat_label": threat_label,
            "name": attributes.get("meaningful_name","Unknown"),
        }
    except Exception as e:
        print(f"⚠️  VirusTotal network error: {e}")
        return None

# ====================== HASSH FINGERPRINTING ======================

def load_custom_hassh():
    global custom_hassh_db
    if os.path.isfile(CUSTOM_HASSH_FILE):
        try:
            with open(CUSTOM_HASSH_FILE) as f:
                custom_hassh_db = json.load(f)
        except Exception as e:
            print(f"⚠️  Could not load custom HASSH file: {e}")

def _save_custom_hassh():
    try:
        Path(os.path.dirname(CUSTOM_HASSH_FILE)).mkdir(parents=True, exist_ok=True)
        with open(CUSTOM_HASSH_FILE,"w") as f:
            json.dump(custom_hassh_db, f, indent=2)
    except Exception as e:
        print(f"⚠️  Could not save custom HASSH: {e}")

def _fetch_with_cache(url, cache_filename):
    cache_path = os.path.join(HASSH_CACHE_DIR, cache_filename)
    if os.path.isfile(cache_path) and (time.time()-os.path.getmtime(cache_path)) < HASSH_CACHE_MAX_AGE:
        try:
            with open(cache_path,"r",encoding="utf-8",errors="ignore") as f:
                return f.read()
        except: pass
    try:
        resp = requests.get(url, timeout=25)
        if resp.status_code == 200:
            try:
                Path(HASSH_CACHE_DIR).mkdir(parents=True, exist_ok=True)
                with open(cache_path,"w",encoding="utf-8") as f:
                    f.write(resp.text)
            except: pass
            return resp.text
        print(f"⚠️  Could not download {cache_filename} (HTTP {resp.status_code})")
    except Exception as e:
        print(f"⚠️  Could not download {cache_filename}: {e}")
    # stale cache fallback
    if os.path.isfile(cache_path):
        try:
            with open(cache_path,"r",encoding="utf-8",errors="ignore") as f:
                return f.read()
        except: pass
    return None

def _parse_big_hasshdb(text):
    db = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"): continue
        parts = line.split(None,1)
        if len(parts) != 2: continue
        hash_val, rest = parts
        first_candidate = rest.split("||")[0].strip()
        db[hash_val] = first_candidate
    return db

def _parse_salesforce_csv(text):
    db = {}
    try:
        reader = csv.DictReader(io.StringIO(text))
        for row in reader:
            h = row.get("hassh")
            if h:
                client = (row.get("sshClient") or "").strip()
                ver    = (row.get("sshClientVersion") or "").strip()
                db[h]  = f"{client} {ver}".strip() or "Unknown client"
    except Exception as e:
        print(f"⚠️  Could not parse salesforce HASSH CSV: {e}")
    return db

def load_hassh_database():
    global salesforce_hassh_db, big_hassh_db
    sf_text = _fetch_with_cache(SALESFORCE_HASSH_CSV_URL, "salesforce_hassh.csv")
    if sf_text:
        salesforce_hassh_db = _parse_salesforce_csv(sf_text)
        print(f"✅ Loaded {len(salesforce_hassh_db)} client-verified fingerprints (salesforce/hassh)")
    big_text = _fetch_with_cache(HASSHDB_URL, "big_hasshdb.txt")
    if big_text:
        big_hassh_db = _parse_big_hasshdb(big_text)
        print(f"✅ Loaded {len(big_hassh_db)} fingerprints (0x4D31/hassh-utils)")
    if not salesforce_hassh_db and not big_hassh_db:
        print("⚠️  Could not load public HASSH databases — falling back to starter table only")

def lookup_hassh(hassh_value, raw_banner=None):
    for source_name, db in (
        ("your custom list",              custom_hassh_db),
        ("starter table",                 KNOWN_HASSH_DB),
        ("salesforce/hassh",              salesforce_hassh_db),
        ("community database",            big_hassh_db),
    ):
        if hassh_value in db:
            return db[hassh_value], source_name
    try:
        Path(os.path.dirname(UNKNOWN_HASSH_LOG)).mkdir(parents=True, exist_ok=True)
        with open(UNKNOWN_HASSH_LOG,"a") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} | {hassh_value} | banner={raw_banner}\n")
    except Exception as e:
        print(f"⚠️  Could not log unknown HASSH: {e}")
    return None, "unknown"

def guess_from_banner(banner):
    if not banner or banner in ("Unknown","N/A"): return None
    cleaned = banner
    for prefix in ("SSH-2.0-","SSH-1.99-","SSH-1.5-"):
        if cleaned.startswith(prefix):
            cleaned = cleaned[len(prefix):]
            break
    return cleaned.strip() or None

def add_hassh(hash_value, name):
    load_custom_hassh()
    custom_hassh_db[hash_value] = name
    _save_custom_hassh()
    print(f"✅ Added: {hash_value} -> {name}")

# ====================== CAMPAIGN DETECTOR (Feature #6) ======================

def check_campaign(fingerprint_type, fingerprint_value, ip):
    """
    Track same HASSH / wallet address across multiple IPs.
    If CAMPAIGN_MIN_IPS or more unique IPs share the same fingerprint,
    fire a campaign alert and report all linked IPs to AbuseIPDB together.
    """
    with _db_lock:
        if fingerprint_type == "hassh":
            store = _db["hassh_to_ips"]
        else:
            store = _db["wallet_to_ips"]

        ips = store.setdefault(fingerprint_value, [])
        if ip not in ips:
            ips.append(ip)

        count     = len(ips)
        all_ips   = list(ips)
        last_alert= _db["campaign_alerted"].get(fingerprint_value, 0)

    _save_db()

    if count >= CAMPAIGN_MIN_IPS and (time.time() - last_alert) > CAMPAIGN_REPORT_COOLDOWN:
        with _db_lock:
            _db["campaign_alerted"][fingerprint_value] = time.time()
        _save_db()

        ip_list = "\n".join(all_ips[:20])
        send_to_discord({
            "title": "🕸️ BOTNET CAMPAIGN DETECTED — Multiple IPs, One Operator",
            "color": 10038562,
            "fields": [
                {"name": "🔬 Fingerprint Type", "value": fingerprint_type.upper(), "inline": True},
                {"name": "🆔 Shared Fingerprint", "value": str(fingerprint_value)[:200], "inline": True},
                {"name": "📊 Unique IPs Sharing This Fingerprint",  "value": str(count), "inline": True},
                {"name": "🌐 All Linked IPs",    "value": f"```\n{ip_list}\n```", "inline": False},
                {"name": "⚡ Action",
                 "value": "All linked IPs have been queued for AbuseIPDB reporting.", "inline": False},
            ],
            "footer": {"text": "Campaign Detector — One Operator, Many Machines"},
        })

        # Report all linked IPs together
        for linked_ip in all_ips:
            if should_report(linked_ip):
                comment = (f"Part of detected botnet campaign. Shared {fingerprint_type}: "
                           f"{fingerprint_value[:80]}. {count} IPs in this campaign.")
                report_to_abuseipdb(linked_ip, "14,18,22", comment)

# ====================== AUTO ABUSE COMPLAINT (Feature #5) ======================

def get_whois_abuse_email(ip):
    """
    Uses RDAP (the modern replacement for WHOIS with a real JSON API) to find
    the abuse contact email for the hosting provider.
    RDAP is a public standard — no API key needed.
    """
    try:
        # First: find the right RDAP server for this IP via IANA bootstrap
        resp = requests.get(f"https://rdap.db.ripe.net/ip/{ip}", timeout=6)
        if resp.status_code != 200:
            # Try ARIN
            resp = requests.get(f"https://rdap.arin.net/registry/ip/{ip}", timeout=6)
        if resp.status_code != 200:
            return None, None, None

        data    = resp.json()
        org     = data.get("name","Unknown")
        network = data.get("handle","")

        abuse_email = None
        for entity in data.get("entities",[]):
            for role in entity.get("roles",[]):
                if role == "abuse":
                    for vcard_item in entity.get("vcardArray",[[]]):
                        if isinstance(vcard_item, list):
                            for field in vcard_item:
                                if isinstance(field, list) and len(field)>=4 and field[0]=="email":
                                    abuse_email = field[3]
                                    break

        return org, network, abuse_email
    except Exception as e:
        print(f"⚠️  RDAP lookup failed for {ip}: {e}")
        return None, None, None

def draft_abuse_complaint(ip, country, isp, events_summary, session):
    """
    Looks up the hosting provider's abuse email and drafts a professional
    complaint message to Discord. You review and send it manually.
    """
    def _do_draft():
        org, network, abuse_email = get_whois_abuse_email(ip)

        if not abuse_email:
            # Fallback: common provider abuse emails
            fallback_map = {
                "digitalocean": "abuse@digitalocean.com",
                "linode":       "abuse@linode.com",
                "vultr":        "abuse@vultr.com",
                "ovh":          "abuse@ovh.net",
                "hetzner":      "abuse@hetzner.com",
                "aws":          "abuse@amazonaws.com",
                "google":       "abuse@google.com",
                "azure":        "abuse@microsoft.com",
            }
            isp_lower = (isp or "").lower()
            for keyword, email in fallback_map.items():
                if keyword in isp_lower:
                    abuse_email = email
                    break

        complaint_body = f"""Subject: Abuse Report — Unauthorized SSH Brute-Force Attack from {ip}

Dear Abuse Team,

I am writing to report ongoing malicious activity originating from IP address {ip},
which appears to be hosted on your network (ASN/Org: {org or isp}, Handle: {network or 'N/A'}).

INCIDENT SUMMARY:
{events_summary}

TECHNICAL DETAILS:
- Source IP: {ip}
- Country: {country}
- ISP/Org: {isp}
- Date/Time (UTC): {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())}
- Session ID: {session}
- Attack Type: SSH Brute-Force / Unauthorized Access Attempt

This IP has been reported to AbuseIPDB. Evidence logs are available upon request.

Please investigate and take appropriate action to stop this abuse.

Best regards,
Security Operations — Honeypot Monitoring System
"""

        send_to_discord({
            "title": "📧 AUTO-DRAFTED ABUSE COMPLAINT — Review & Send Manually",
            "color": 5793266,
            "fields": [
                {"name": "🎯 Offending IP",    "value": str(ip),                        "inline": True},
                {"name": "🏢 Provider",        "value": str(org or isp or "Unknown"),   "inline": True},
                {"name": "📮 Abuse Email",
                 "value": str(abuse_email) if abuse_email else "Not found via RDAP — try: https://search.arin.net/rdap/?query=" + ip,
                 "inline": False},
                {"name": "📝 Draft Complaint (copy & send)",
                 "value": f"```\n{complaint_body[:900]}\n```", "inline": False},
                {"name": "🔗 Manual Lookup",
                 "value": f"https://search.arin.net/rdap/?query={ip}", "inline": False},
            ],
            "footer": {"text": "Auto-Draft Abuse Complaint — Human review required before sending"},
        })

    executor.submit(_do_draft)

# ====================== HONEYTOKEN TRAPS (Feature #9) ======================

def check_honeytoken_usage(cmd, ip, session):
    """
    Scans attacker commands for any of your planted honeytoken values.
    If found, fires a high-priority Discord alert: "The fish took the bait."
    """
    for token_info in HONEYTOKENS.get("aws_keys", []):
        if token_info.get("access_key","") in cmd or token_info.get("secret_key","") in cmd:
            send_to_discord({
                "title": "🪤 HONEYTOKEN TRIGGERED — FAKE AWS KEY USED!",
                "color": 16711680,
                "fields": [
                    {"name": "⚠️  Alert Type", "value": "AWS Canary Key Usage Detected", "inline": True},
                    {"name": "👤 Attacker IP", "value": str(ip), "inline": True},
                    {"name": "🆔 Session",     "value": str(session), "inline": True},
                    {"name": "💬 Command",     "value": cmd[:500], "inline": False},
                    {"name": "🎣 Note", "value": (
                        "Attacker ne tumhara planted fake AWS key use kiya. "
                        "Agar yeh key CanaryTokens.org se generate ki thi, to tumhe email bhi mil chuka hoga. "
                        "Yeh confirm karta hai ke attacker ne honeypot filesystem explore kiya."
                    ), "inline": False},
                    {"name": "📌 Token Note", "value": str(token_info.get("note","N/A")), "inline": False},
                ],
                "footer": {"text": "🪤 Honeytoken Trap — Canary Alert"},
            })

    for env_line in HONEYTOKENS.get("env_vars", []):
        if env_line.split("=")[1] if "=" in env_line else env_line in cmd:
            fake_key = env_line.split("=")[0] if "=" in env_line else env_line
            send_to_discord({
                "title": f"🪤 HONEYTOKEN TRIGGERED — FAKE ENV VAR SPOTTED ({fake_key})",
                "color": 16711680,
                "fields": [
                    {"name": "👤 IP",      "value": str(ip),   "inline": True},
                    {"name": "🆔 Session", "value": str(session), "inline": True},
                    {"name": "💬 Command", "value": cmd[:500], "inline": False},
                ],
                "footer": {"text": "🪤 Honeytoken Trap — .env Canary"},
            })

# ====================== WALL OF SHAME LEADERBOARD (Feature #10) ======================

def post_leaderboard():
    """Posts (or reposts) the live Wall of Shame leaderboard to Discord."""
    board = get_leaderboard(10)
    if not board:
        return

    rows = []
    for rank, (ip, score, title, attempts, malware, wallets) in enumerate(board, 1):
        rows.append(
            f"`#{rank:02d}` {title}  **{ip}**\n"
            f"       Score: {score} | Logins: {attempts} | Malware: {malware} | Wallets: {wallets}"
        )

    send_to_discord({
        "title": "🏆 WALL OF SHAME — Live Attacker Leaderboard",
        "color": 16753920,
        "description": "\n\n".join(rows) or "No attackers yet today.",
        "footer": {"text": "Scores: Login=+1 | Malware Upload=+10 | Wallet Found=+5 | Repeat Visit=+3"},
        "timestamp": datetime.utcnow().isoformat(),
    })

# ====================== DAILY DIGEST (Feature #8) ======================

def _run_daily_digest():
    """Background thread that fires the daily digest at DIGEST_HOUR:DIGEST_MINUTE."""
    while True:
        now = datetime.now()
        target = now.replace(hour=DIGEST_HOUR, minute=DIGEST_MINUTE, second=0, microsecond=0)
        if now >= target:
            target = target.replace(day=target.day + 1)
        sleep_secs = (target - now).total_seconds()
        time.sleep(sleep_secs)

        yesterday = str((datetime.now().date()))
        with _db_lock:
            ds = _db["daily_stats"].get(yesterday, {})
            sc = _db["scorecard"]

        attempts = ds.get("attempts", 0)
        malware  = ds.get("malware",  0)
        reports  = ds.get("reports",  0)
        wallets  = ds.get("wallets",  0)
        ips      = ds.get("ips",      [])

        top_ip    = ""
        top_score = 0
        top_title = ""
        top_wallet= 0
        for ip in ips:
            if ip in sc and sc[ip]["score"] > top_score:
                top_score = sc[ip]["score"]
                top_ip    = ip
                top_title = sc[ip].get("title","")
                top_wallet= sc[ip].get("wallets",0)

        wallet_earnings = "N/A (Monero/unverified addresses not counted)"

        send_to_discord({
            "title": f"📊 DAILY BODY COUNT — {yesterday}",
            "color": 3447003,
            "fields": [
                {"name": "🔑 Brute-Force Attempts",  "value": str(attempts),  "inline": True},
                {"name": "☠️  Malware Samples",       "value": str(malware),   "inline": True},
                {"name": "📤 IPs Reported to AbuseIPDB","value": str(reports), "inline": True},
                {"name": "💰 Crypto Wallets Found",  "value": str(wallets),   "inline": True},
                {"name": "🌐 Unique Attacker IPs",   "value": str(len(ips)),  "inline": True},
                {"name": "👑 Most Dangerous Attacker",
                 "value": f"{top_title}  `{top_ip}`  (Score: {top_score})" if top_ip else "None",
                 "inline": False},
                {"name": "📋 Leaderboard Snapshot",  "value": "See Wall of Shame above ↑", "inline": False},
            ],
            "footer": {"text": "Daily SOC Digest — Automated Report"},
            "timestamp": datetime.utcnow().isoformat(),
        })

        # Also post the leaderboard right after the digest
        time.sleep(2)
        post_leaderboard()

# ====================== WORLD MAP HTML DASHBOARD (Feature #7) ======================

MAP_DASHBOARD_PATH = "/home/cowrie/attack_map/index.html"
MAP_DATA_PATH      = "/home/cowrie/attack_map/attacks.json"

_attack_geo_log = []   # [{ip, lat, lon, country, city, ts, score, title}, ...]
_map_lock = threading.Lock()

# BUG FIX: Load existing attacks.json on startup so restart nahi kho jaata
def _load_existing_map_data():
    """
    Startup pe attacks.json se pehle se stored attacks load karta hai.
    Isse restart ke baad bhi purani dots map pe dikhti rehti hain.
    """
    global _attack_geo_log
    if os.path.isfile(MAP_DATA_PATH):
        try:
            with open(MAP_DATA_PATH, "r") as f:
                existing = json.load(f)
            if isinstance(existing, list):
                _attack_geo_log = existing
                print(f"✅ Map: {len(existing)} purani attacks load ho gayi attacks.json se")
        except Exception as e:
            print(f"⚠️  Could not load existing map data: {e}")

# BUG FIX: Purani rotated cowrie log files bhi padhna (all-time history)
def _load_historical_log_files():
    """
    Cowrie roz raat ko log rotate karta hai:
      cowrie.json          <- aaj ki live file
      cowrie.json.2024-01-15       <- kal ki (plain text)
      cowrie.json.2024-01-14.gz    <- usse pehle (compressed)

    Yeh function startup pe saari purani files padhta hai aur
    attacks.json mein merge karta hai — taaki map pe ALL TIME
    ke dots dikhein, sirf aaj ke nahi.

    NOTE: Geo lookup API calls nahi karta purani files ke liye
    (rate limit bachane ke liye) — sirf existing lat/lon data
    attacks.json mein already stored hai use reuse karta hai.
    Naye IPs jo purani files mein hain unke liye 0,0 coordinates
    honge (map pe center mein dikhenge) — yeh acceptable hai
    kyunki yeh sirf historical backfill hai.
    """
    import gzip
    global _attack_geo_log

    log_dir = os.path.dirname(LOG_FILE_PATH)
    if not os.path.isdir(log_dir):
        print(f"⚠️  Log directory nahi mili: {log_dir}")
        return

    # Existing IPs jo already map mein hain — duplicate avoid karne ke liye
    with _map_lock:
        existing_keys = set(
            (e.get("ip",""), e.get("ts","")) for e in _attack_geo_log
        )

    new_entries = []
    log_files = sorted(Path(log_dir).glob("cowrie.json*"))

    for log_path in log_files:
        fname = log_path.name
        # Live file skip karo — yeh already tail ho rahi hai
        if fname == "cowrie.json":
            continue

        print(f"📚 Historical log padhna: {fname}")
        try:
            if fname.endswith(".gz"):
                opener = gzip.open(str(log_path), "rt", encoding="utf-8", errors="ignore")
            else:
                opener = open(str(log_path), "r", encoding="utf-8", errors="ignore")

            with opener as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    # Sirf login events map ke liye relevant hain
                    if event.get("eventid") != "cowrie.login.success":
                        continue

                    ip  = event.get("src_ip", "")
                    ts  = event.get("timestamp", "")[:19].replace("T", " ")
                    key = (ip, ts)

                    if not ip or key in existing_keys:
                        continue

                    existing_keys.add(key)
                    new_entries.append({
                        "ip": ip, "lat": None, "lon": None,
                        "country": "Historical", "city": "Historical",
                        "ts": ts, "score": 0, "title": "📜 Historical",
                    })
        except Exception as e:
            print(f"⚠️  Could not read {fname}: {e}")

    if not new_entries:
        print("ℹ️  Koi nayi historical attacks nahi mili (ya sab already load hain)")
        return

    # BUG FIX: Unique IPs ke liye real geo lookup karo (0,0 ki jagah)
    # ip-api.com free tier: 45 req/min — isliye unique IPs batch mein process karo
    print(f"🌍 {len(new_entries)} historical events ke liye geo lookup chal rahi hai...")
    unique_ips = list(set(e["ip"] for e in new_entries if e["ip"]))
    ip_geo_cache = {}

    for i, ip in enumerate(unique_ips):
        if ip.startswith(INTERNAL_PREFIXES):
            ip_geo_cache[ip] = (0, 0, "Internal", "Local")
            continue
        try:
            resp = requests.get(
                f"http://ip-api.com/json/{ip}?fields=lat,lon,country,city,status",
                timeout=4
            )
            if resp.status_code == 429:
                # Rate limited — wait 60s aur retry
                print(f"⏳ ip-api rate limit — 60s wait kar raha hoon...")
                time.sleep(60)
                resp = requests.get(
                    f"http://ip-api.com/json/{ip}?fields=lat,lon,country,city,status",
                    timeout=4
                )
            d = resp.json()
            if d.get("status") == "success":
                ip_geo_cache[ip] = (
                    d.get("lat", 0), d.get("lon", 0),
                    d.get("country", "Unknown"), d.get("city", "Unknown")
                )
            else:
                ip_geo_cache[ip] = (0, 0, "Unknown", "Unknown")
        except Exception:
            ip_geo_cache[ip] = (0, 0, "Unknown", "Unknown")

        # Rate limit: 45 req/min = ~1.3 sec per request
        time.sleep(1.4)

        if (i + 1) % 50 == 0:
            print(f"  ... {i+1}/{len(unique_ips)} IPs processed")

    # Geo data entries mein fill karo
    for entry in new_entries:
        geo = ip_geo_cache.get(entry["ip"], (0, 0, "Unknown", "Unknown"))
        entry["lat"]     = geo[0]
        entry["lon"]     = geo[1]
        entry["country"] = geo[2]
        entry["city"]    = geo[3]

    with _map_lock:
        _attack_geo_log.extend(new_entries)
        _attack_geo_log.sort(key=lambda x: x.get("ts", ""))
    print(f"✅ {len(new_entries)} historical attacks map mein add ho gayi (real coordinates ke saath)")

    try:
        with _map_lock:
            all_data = list(_attack_geo_log)
        Path(os.path.dirname(MAP_DATA_PATH)).mkdir(parents=True, exist_ok=True)
        with open(MAP_DATA_PATH, "w") as f:
            json.dump(all_data, f)
        _write_map_html()
    except Exception as e:
        print(f"⚠️  Could not save historical map data: {e}")

def update_attack_map(ip, country, city, score=0, title=""):
    """Append to the geo log and regenerate the HTML dashboard."""
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=lat,lon", timeout=3)
        if resp.status_code == 200:
            d   = resp.json()
            lat = d.get("lat", 0)
            lon = d.get("lon", 0)
        else:
            lat, lon = 0, 0
    except:
        lat, lon = 0, 0

    entry = {
        "ip": ip, "lat": lat, "lon": lon,
        "country": country, "city": city,
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "score": score, "title": title,
    }

    with _map_lock:
        _attack_geo_log.append(entry)
        # BUG FIX: 500 ki limit hatai — ALL TIME attacks store hoti hain
        all_data = list(_attack_geo_log)

    try:
        Path(os.path.dirname(MAP_DATA_PATH)).mkdir(parents=True, exist_ok=True)
        with open(MAP_DATA_PATH, "w") as f:
            json.dump(all_data, f)
        _write_map_html()
    except Exception as e:
        print(f"⚠️  Could not update attack map: {e}")

def _write_map_html():
    """
    Generates a self-contained HTML page with a Leaflet.js world map plus
    marker clustering (thousands of attacks stay readable). The page
    refreshes its data every 15 seconds without reloading.
    Serve with: python3 -m http.server 8888 --directory /home/cowrie/attack_map/
    """
    html = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SOC Live Attack Map</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<link rel="stylesheet" href="https://unpkg.com/leaflet.markercluster@1.5.3/dist/MarkerCluster.css"/>
<link rel="stylesheet" href="https://unpkg.com/leaflet.markercluster@1.5.3/dist/MarkerCluster.Default.css"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script src="https://unpkg.com/leaflet.markercluster@1.5.3/dist/leaflet.markercluster.js"></script>
<style>
 :root{--bg:#080b12;--panel:rgba(13,17,23,.72);--line:#20304a;--accent:#ff3b52;--txt:#e6edf3;--dim:#8b98a8;}
 *{margin:0;padding:0;box-sizing:border-box;}
 html,body{height:100%;}
 body{background:var(--bg);color:var(--txt);font-family:'Segoe UI',system-ui,-apple-system,sans-serif;overflow:hidden;}
 #map{position:absolute;inset:0;background:#070a10;}
 .leaflet-container{background:#070a10 !important;font-family:inherit;}
 #map:after{content:"";position:absolute;inset:0;pointer-events:none;z-index:400;
   box-shadow:inset 0 0 220px 60px rgba(0,0,0,.65);}

 #bar{position:absolute;top:0;left:0;right:0;z-index:1000;display:flex;align-items:center;gap:16px;flex-wrap:wrap;
   padding:12px 18px;background:linear-gradient(180deg,rgba(8,11,18,.94),rgba(8,11,18,0));pointer-events:none;}
 #brand{display:flex;align-items:center;gap:11px;pointer-events:auto;}
 #brand .dot{width:11px;height:11px;border-radius:50%;background:var(--accent);box-shadow:0 0 12px var(--accent);animation:pulse 1.6s infinite;}
 #brand h1{font-size:15px;font-weight:700;letter-spacing:3px;color:#fff;line-height:1;}
 #brand small{font-size:10px;color:var(--dim);letter-spacing:1.5px;text-transform:uppercase;}
 @keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.3;transform:scale(.7)}}

 #stats{margin-left:auto;display:flex;gap:9px;pointer-events:auto;}
 .chip{background:var(--panel);backdrop-filter:blur(9px);-webkit-backdrop-filter:blur(9px);
   border:1px solid var(--line);border-radius:11px;padding:7px 15px;min-width:72px;text-align:center;}
 .chip .n{font-size:18px;font-weight:700;color:#fff;line-height:1;}
 .chip .l{font-size:8.5px;color:var(--dim);letter-spacing:1.5px;text-transform:uppercase;margin-top:5px;}
 .chip.hot .n{color:var(--accent);}

 #legend{position:absolute;bottom:16px;left:16px;z-index:1000;background:var(--panel);
   backdrop-filter:blur(9px);-webkit-backdrop-filter:blur(9px);border:1px solid var(--line);
   border-radius:11px;padding:10px 13px;font-size:11px;}
 #legend .t{font-size:9px;color:var(--dim);letter-spacing:1.5px;text-transform:uppercase;margin-bottom:6px;}
 #legend .row{display:flex;align-items:center;gap:8px;margin:4px 0;color:#c7d1dc;}
 #legend i{width:11px;height:11px;border-radius:50%;display:inline-block;flex:0 0 auto;}

 .dot-marker{border-radius:50%;border:1.5px solid rgba(255,255,255,.55);}
 .dot-pulse{animation:mp 2s infinite;}
 @keyframes mp{0%{box-shadow:0 0 0 0 rgba(255,59,82,.55)}70%{box-shadow:0 0 0 13px rgba(255,59,82,0)}100%{box-shadow:0 0 0 0 rgba(255,59,82,0)}}

 .cl{border-radius:50%;display:flex;align-items:center;justify-content:center;color:#fff;font-weight:700;
   border:2px solid rgba(255,255,255,.28);text-shadow:0 1px 2px rgba(0,0,0,.5);}
 .cl-s{background:rgba(70,130,255,.78);width:34px;height:34px;font-size:12px;}
 .cl-m{background:rgba(255,170,40,.82);width:42px;height:42px;font-size:13px;}
 .cl-l{background:rgba(255,59,82,.86);width:52px;height:52px;font-size:14px;box-shadow:0 0 22px rgba(255,59,82,.65);}

 .leaflet-popup-content-wrapper{background:#0d1117;color:var(--txt);border:1px solid var(--line);border-radius:11px;box-shadow:0 8px 30px rgba(0,0,0,.5);}
 .leaflet-popup-content{margin:11px 13px;}
 .leaflet-popup-tip{background:#0d1117;border:1px solid var(--line);}
 .pop b{color:var(--accent);font-size:13px;letter-spacing:.5px;}
 .pop .r{color:var(--dim);font-size:11px;margin-top:3px;}
 .pop .sc{display:inline-block;margin-top:7px;padding:2px 9px;border-radius:6px;background:rgba(255,59,82,.15);color:var(--accent);font-size:11px;font-weight:600;}
 .leaflet-control-zoom a{background:var(--panel)!important;color:#fff!important;border-color:var(--line)!important;backdrop-filter:blur(9px);}
</style>
</head>
<body>
<div id="bar">
  <div id="brand"><span class="dot"></span><div><h1>SOC ATTACK MAP</h1><small>live honeypot telemetry</small></div></div>
  <div id="stats">
    <div class="chip hot"><div class="n" id="s-total">0</div><div class="l">Attacks</div></div>
    <div class="chip"><div class="n" id="s-ctry">0</div><div class="l">Countries</div></div>
    <div class="chip"><div class="n" id="s-upd">--</div><div class="l">Updated</div></div>
  </div>
</div>
<div id="legend">
  <div class="t">Threat level</div>
  <div class="row"><i style="background:#4682ff"></i>Probe</div>
  <div class="row"><i style="background:#ffaa28"></i>Active attacker</div>
  <div class="row"><i style="background:#ff3b52"></i>High threat</div>
</div>
<div id="map"></div>
<script>
const map = L.map('map',{center:[25,10],zoom:2,minZoom:2,maxZoom:12,zoomControl:false,worldCopyJump:true,attributionControl:false});
L.control.zoom({position:'bottomright'}).addTo(map);
L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',{maxZoom:19}).addTo(map);

function tier(score){if(score>=30)return['#ff3b52',18];if(score>=10)return['#ff7a3b',15];if(score>=3)return['#ffaa28',12];return['#4682ff',9];}
function dotIcon(score){
  const t=tier(score),c=t[0],sz=t[1];
  const pulse=score>=30?' dot-pulse':'';
  return L.divIcon({className:'',iconSize:[sz,sz],
    html:'<div class="dot-marker'+pulse+'" style="width:'+sz+'px;height:'+sz+'px;background:'+c+';box-shadow:0 0 '+sz+'px '+c+';"></div>'});
}

const cluster = L.markerClusterGroup({
  maxClusterRadius:45, spiderfyOnMaxZoom:true, showCoverageOnHover:false, chunkedLoading:true,
  iconCreateFunction:function(c){
    const n=c.getChildCount(); let cls='cl-s'; if(n>=100)cls='cl-l'; else if(n>=15)cls='cl-m';
    return L.divIcon({html:'<div class="cl '+cls+'">'+n+'</div>',className:'',iconSize:[40,40]});
  }
});
map.addLayer(cluster);

async function loadData(){
  try{
    const r=await fetch('attacks.json?t='+Date.now());
    const data=await r.json();
    cluster.clearLayers();
    const ctry=new Set(); const batch=[];
    data.forEach(a=>{
      if(!a.lat && !a.lon) return;
      if(a.country && a.country!=='Historical' && a.country!=='Unknown') ctry.add(a.country);
      const m=L.marker([a.lat,a.lon],{icon:dotIcon(a.score||0)});
      m.bindPopup('<div class="pop"><b>'+(a.ip||'?')+'</b>'+
        '<div class="r">'+(a.city||'?')+', '+(a.country||'?')+'</div>'+
        '<div class="r">'+(a.title||'Unknown')+'</div>'+
        '<span class="sc">Score '+(a.score||0)+'</span>'+
        '<div class="r">'+(a.ts||'')+'</div></div>');
      batch.push(m);
    });
    cluster.addLayers(batch);
    document.getElementById('s-total').textContent=data.length.toLocaleString();
    document.getElementById('s-ctry').textContent=ctry.size;
    document.getElementById('s-upd').textContent=new Date().toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'});
  }catch(e){console.error(e);}
}
loadData();
setInterval(loadData,15000);
</script>
</body>
</html>
"""
    with open(MAP_DASHBOARD_PATH, "w") as f:
        f.write(html)


# ====================== IOC EXTRACTION ======================

def extract_iocs(filepath):
    try:
        with open(filepath,"rb") as f:
            content = f.read(2_000_000)
        text = content.decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"⚠️  Could not read file for IOC scan: {e}")
        return None
    return {
        "ips":              set(IPV4_RE.findall(text)),
        "urls":             set(URL_RE.findall(text)),
        "telegram_tokens":  set(TELEGRAM_TOKEN_RE.findall(text)),
    }

def verify_telegram_token(token):
    try:
        resp = requests.get(f"https://api.telegram.org/bot{token}/getMe", timeout=5)
        data = resp.json()
        if data.get("ok"):
            return data.get("result",{}).get("username","unknown_bot")
    except Exception as e:
        print(f"⚠️  Telegram token verify error: {e}")
    return None

def save_ioc_report(file_hash, ip, vt_result, iocs, sandbox_result):
    Path(REPORTS_DIR).mkdir(parents=True, exist_ok=True)
    path = os.path.join(REPORTS_DIR, f"report_{file_hash[:12]}_{int(time.time())}.md")
    lines = [
        f"# Threat Intel Report - {file_hash}",
        f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
        f"Source Attacker IP: {ip}",
        "",
        "## VirusTotal Verdict",
        json.dumps(vt_result, indent=2, default=list) if vt_result else "N/A",
        "",
        "## Extracted Indicators of Compromise",
        f"IPs found in file: {', '.join(iocs.get('ips',[])) or 'None'}",
        f"URLs found in file: {', '.join(iocs.get('urls',[])) or 'None'}",
        f"Telegram tokens: {', '.join(iocs.get('telegram_tokens',[])) or 'None'}",
        "",
        "## Sandbox Behavior",
        json.dumps(sandbox_result, indent=2, default=list) if sandbox_result else "N/A",
        "",
        "## Manual Reporting Channels",
        "- CISA (USA): report@cisa.gov | https://www.cisa.gov/resources-tools/services/malware-next-generation-analysis",
        "- PKCERT (Pakistan): https://pkcert.gov.pk/report-incident/",
        "  (Neither has a public auto-submit API — web forms / email only)",
    ]
    with open(path,"w") as f:
        f.write("\n".join(lines))
    return path

def submit_to_malwarebazaar(filepath, file_hash, comment):
    if not ABUSECH_AUTH_KEY:
        return None
    try:
        with open(filepath,"rb") as f:
            files = {"file": (file_hash, f)}
            data  = {"json_data": json.dumps({"anonymous":0,"comment":comment})}
            headers = {"Auth-Key": ABUSECH_AUTH_KEY}
            resp = requests.post("https://mb-api.abuse.ch/api/v1/", files=files, data=data, headers=headers, timeout=20)
            return resp.json()
    except Exception as e:
        print(f"⚠️  MalwareBazaar submit error: {e}")
        return None

# ====================== DYNAMIC SANDBOX ======================

def sandbox_analyze(filepath, session):
    if not SANDBOX_ENABLED:
        return None
    container_name = f"sandbox_{session}_{int(time.time())}"
    cmd = [
        "docker","run","--name",container_name,
        "--network","none",
        "--memory=128m","--cpus=0.5","--pids-limit=64",
        "--cap-drop=ALL","--security-opt","no-new-privileges",
        "-v",f"{filepath}:/sandbox/sample:ro",
        SANDBOX_IMAGE,"sh","-c",
        f"cp /sandbox/sample /tmp/s && chmod +x /tmp/s && timeout {SANDBOX_TIMEOUT} /tmp/s",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=SANDBOX_TIMEOUT+15)
        stdout, stderr, exit_code = result.stdout[:500], result.stderr[:500], result.returncode
    except subprocess.TimeoutExpired:
        stdout, stderr, exit_code = "", "Sandbox execution timed out.", -1
    except Exception as e:
        return {"error": str(e)}

    fs_changes = []
    try:
        diff = subprocess.run(["docker","diff",container_name], capture_output=True, text=True, timeout=10)
        if diff.returncode == 0:
            fs_changes = diff.stdout.strip().splitlines()[:15]
    except: pass

    try:
        subprocess.run(["docker","rm","-f",container_name], capture_output=True, timeout=10)
    except: pass

    return {"stdout":stdout,"stderr":stderr,"exit_code":exit_code,"fs_changes":fs_changes}

# ====================== CRYPTO WALLET SCRAPER ======================

def check_btc_balance(address):
    try:
        resp = requests.get(f"https://blockchain.info/balance?active={address}&cors=true", timeout=6)
        data = resp.json().get(address)
        if data:
            return {
                "balance_btc":       data.get("final_balance",0)   / 1e8,
                "total_received_btc":data.get("total_received",0)  / 1e8,
                "n_tx":              data.get("n_tx",0),
            }
    except Exception as e:
        print(f"⚠️  BTC balance check error: {e}")
    return None

def check_eth_balance(address):
    try:
        resp = requests.get(f"https://api.blockcypher.com/v1/eth/main/addrs/{address}/balance", timeout=6)
        data = resp.json()
        if "balance" in data:
            return {"balance_eth": data.get("balance",0)/1e18, "n_tx": data.get("n_tx",0)}
    except Exception as e:
        print(f"⚠️  ETH balance check error: {e}")
    return None

def scan_for_wallets(text):
    wallets = []
    for addr in set(BTC_RE.findall(text)):  wallets.append(("BTC", addr))
    for addr in set(ETH_RE.findall(text)):  wallets.append(("ETH", addr))
    for addr in set(XMR_RE.findall(text)):  wallets.append(("XMR", addr))
    return wallets

def handle_wallet_scan(cmd, ip, session):
    for coin, addr in scan_for_wallets(cmd):
        print(f"💰 {coin} wallet found in command: {addr}")
        update_scorecard(ip, "wallet", session)
        check_campaign("wallet", addr, ip)

        fields = [
            {"name": "🪙 Coin",     "value": coin, "inline": True},
            {"name": "📬 Address",  "value": addr, "inline": True},
            {"name": "👤 Attacker IP","value": str(ip), "inline": True},
            {"name": "⚙️ Command Context","value": cmd[:500],"inline":False},
        ]
        if coin == "BTC":
            info = check_btc_balance(addr)
            if info:
                fields.append({"name":"💵 Balance / Earnings","value":(
                    f"Current: {info['balance_btc']:.8f} BTC\n"
                    f"Total Received (lifetime): {info['total_received_btc']:.8f} BTC\n"
                    f"Total Transactions: {info['n_tx']}"
                ),"inline":False})
        elif coin == "ETH":
            info = check_eth_balance(addr)
            if info:
                fields.append({"name":"💵 Balance","value":f"{info['balance_eth']:.6f} ETH ({info['n_tx']} txns)","inline":False})
        else:
            fields.append({"name":"ℹ️ Note","value":"Monero — privacy coin, balance cannot be queried publicly.","inline":False})

        send_to_discord({
            "title":"💰 CRYPTO WALLET ADDRESS DETECTED","color":16763904,
            "fields":fields,"footer":{"text":"Crypto Wallet Scraper"},
        })

# ====================== LOG FILE ROTATION WATCHER (Bug Fix #1 / #2) ======================

def _get_inode(path):
    try:
        return os.stat(path).st_ino
    except:
        return None

def _open_log_tail(path):
    """Opens the log file and seeks to end, returns (file_handle, inode)."""
    f = open(path, "r")
    f.seek(0, 2)
    return f, _get_inode(path)

# ====================== MAIN MONITOR LOOP ======================

def monitor_log():
    print("🛡️  SOC Threat Intel Monitor v2.0 Started...")

    # Start background threads
    threading.Thread(target=_expire_old_sessions, daemon=True).start()
    threading.Thread(target=_run_daily_digest, daemon=True).start()

    # Ensure map directory exists + load all historical data
    try:
        Path(os.path.dirname(MAP_DASHBOARD_PATH)).mkdir(parents=True, exist_ok=True)
        # BUG FIX 1: Pehle existing attacks.json load karo (restart ke baad bhi dots rahein)
        _load_existing_map_data()
        # BUG FIX 2: Purani rotated log files (.gz bhi) se historical attacks load karo
        _load_historical_log_files()
        _write_map_html()
        print(f"🗺️  Attack map dashboard: {MAP_DASHBOARD_PATH}")
        print(f"   Serve with: python3 -m http.server 8888 --directory {os.path.dirname(MAP_DASHBOARD_PATH)}")
    except Exception as e:
        print(f"⚠️  Could not initialize attack map: {e}")

    while True:  # outer restart loop (Bug Fix: crash recovery)
        try:
            f, current_inode = _open_log_tail(LOG_FILE_PATH)
            print(f"📂 Tailing log file (inode {current_inode}): {LOG_FILE_PATH}")

            while True:
                # --- Bug Fix #1/#2: Log rotation detection ---
                # Check every read cycle if the file was rotated (inode changed
                # or file got truncated / replaced by logrotate)
                new_inode = _get_inode(LOG_FILE_PATH)
                if new_inode != current_inode:
                    print("🔄 Log rotation detected — re-opening log file...")
                    f.close()
                    time.sleep(1)   # brief pause so logrotate finishes
                    f, current_inode = _open_log_tail(LOG_FILE_PATH)
                    print(f"✅ Re-opened log file (new inode {current_inode})")

                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue

                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                # Process in thread pool so slow geo/API calls don't block the reader
                executor.submit(_process_event, event)

        except FileNotFoundError:
            print(f"❌ Log file not found: {LOG_FILE_PATH} — retrying in 10s...")
            time.sleep(10)
        except PermissionError:
            print("❌ Permission denied reading log file. Try: sudo python3 soc_monitor.py")
            time.sleep(30)
        except Exception as e:
            print(f"❌ Unexpected monitor error: {e} — restarting in 5s...")
            time.sleep(5)


def _process_event(event):
    """Handles one Cowrie JSON event. Runs in a thread pool worker."""
    try:
        event_id = event.get("eventid")
        ip       = event.get("src_ip","Unknown IP")
        session  = event.get("session","N/A")[:8]

        # -------- SSH CLIENT FINGERPRINT --------
        if event_id == "cowrie.client.kex":
            hassh_value = event.get("hassh")
            if hassh_value:
                banner = event.get("version","Unknown")
                guess, source = lookup_hassh(hassh_value, raw_banner=banner)
                country, city, isp, flag, asn, org = get_ip_intel(ip)

                _session_hassh[session] = hassh_value
                check_campaign("hassh", hassh_value, ip)

                if guess:
                    guess_text = guess
                else:
                    banner_guess = guess_from_banner(banner)
                    if banner_guess:
                        guess_text = (f"{banner_guess}  "
                                      f"(from its own self-reported banner — hash not in any database yet)")
                        source = "self-reported banner"
                    else:
                        guess_text = (
                            f"Truly unidentified. Logged to {UNKNOWN_HASSH_LOG}\n"
                            f"Once identified, run:\n"
                            f"python3 soc_monitor.py --add-hassh {hassh_value} \"name here\""
                        )

                send_to_discord({
                    "title":"🔬 SSH Client Fingerprint (HASSH)","color":10181046,
                    "fields":[
                        {"name":"👤 IP",          "value":str(ip),                     "inline":True},
                        {"name":"🌍 Location",    "value":f"{flag} {city}, {country}", "inline":True},
                        {"name":"🏢 ASN/Org",     "value":str(asn or isp),             "inline":True},
                        {"name":"🪪 Claimed Banner","value":str(banner),               "inline":False},
                        {"name":"🔑 HASSH",       "value":str(hassh_value),            "inline":False},
                        {"name":"🧬 Best Guess",  "value":guess_text,                  "inline":False},
                        {"name":"📚 Source",      "value":source,                      "inline":True},
                    ],
                    "footer":{"text":"HASSH Fingerprinting — heuristic, not absolute proof"},
                })

        # -------- LOGIN SUCCESS --------
        elif event_id == "cowrie.login.success":
            username = event.get("username","unknown")
            password = event.get("password","")

            print(f"🔑 Login from {ip} — user:{username} pass:{password!r}")
            country, city, isp, flag, asn, org = get_ip_intel(ip)

            is_repeat, visit_count, days_ago = check_recidivism(ip, session)
            score, title, _ = update_scorecard(ip, "login", session)

            # Recidivism alert
            if is_repeat:
                update_scorecard(ip, "repeat", session)
                send_to_discord({
                    "title":"🔁 REPEAT OFFENDER — Been Here Before!","color":16753920,
                    "fields":[
                        {"name":"👤 IP",           "value":str(ip),       "inline":True},
                        {"name":"🔢 Total Visits",  "value":str(visit_count),"inline":True},
                        {"name":"⏱️ Last Seen",     "value":f"{days_ago:.1f} days ago","inline":True},
                        {"name":"🎖️ Current Title", "value":title,         "inline":True},
                        {"name":"📊 Score",         "value":str(score),    "inline":True},
                    ],
                    "footer":{"text":"Recidivism Tracker — Cross-session persistent memory"},
                })

            send_to_discord({
                "title":"🚨 HONEYPOT BREACH DETECTED","color":15158332,
                "fields":[
                    {"name":"👤 Attacker IP",        "value":str(ip),                     "inline":True},
                    {"name":"🌍 Location",           "value":f"{flag} {city}, {country}", "inline":True},
                    {"name":"🏢 Provider/ISP",       "value":str(isp),                    "inline":True},
                    {"name":"🔑 Credentials Used",
                     "value":f"User: {username} | Pass: {password if password else '(blank)'}","inline":False},
                    {"name":"🎖️ Threat Level",       "value":f"{title}  (Score: {score})","inline":True},
                    {"name":"🆔 Session ID",         "value":str(session),                "inline":True},
                ],
                "footer":{"text":"Cyber Threat Intel Alert System"},
            })

            # AbuseIPDB — GitHub central DB se (cross-VPS, 24h cooldown, campaign)
            _gh_result = _gh_report(
                ip, _session_hassh.get(session), password,
                report_to_abuseipdb, session
            )
            if _gh_result.get("skipped_blank"):
                send_to_discord({
                    "title":"⏭️ AbuseIPDB Report Skipped — Blank Password","color":9807270,
                    "description":f"IP `{ip}` ne khali password use kiya, report skip.",
                    "fields":[{"name":"🆔 Session","value":str(session),"inline":True}],
                    "footer":{"text":"AbuseIPDB Auto-Report System"},
                })
            elif _gh_result.get("error"):
                print(f"[github_sync] {_gh_result['error']} — cross-VPS sync skipped for {ip}")
            else:
                reported_ips = _gh_result.get("reported", [])
                is_campaign  = _gh_result.get("campaign", False)
                camp_ips     = _gh_result.get("campaign_ips", [])

                for r_ip in reported_ips:
                    send_to_discord({
                        "title":"✅ IP Reported to AbuseIPDB (Central DB)","color":3066993,
                        "fields":[
                            {"name":"🎯 Reported IP",   "value":str(r_ip),      "inline":True},
                            {"name":"🌐 Via VPS",       "value":str(ip) if r_ip != ip else "Direct","inline":True},
                            {"name":"🏷️ Categories",    "value":"Hacking(14) + Brute-Force(18) + SSH(22)" if is_campaign else "Brute-Force(18) + SSH(22)","inline":False},
                        ],
                        "footer":{"text":"AbuseIPDB Auto-Report — GitHub Central DB"},
                    })

                if is_campaign and camp_ips:
                    send_to_discord({
                        "title":"🕸️ CROSS-VPS BOTNET CAMPAIGN — GitHub Central DB","color":10038562,
                        "fields":[
                            {"name":"🔑 Shared HASSH",    "value":str(_session_hassh.get(session,"N/A")), "inline":False},
                            {"name":"📊 Linked IPs Total","value":str(len(camp_ips)),                     "inline":True},
                            {"name":"📤 Reported Now",    "value":str(len(reported_ips)),                 "inline":True},
                            {"name":"🌐 All Linked IPs",  "value":"```\n" + "\n".join(camp_ips[:20]) + "\n```","inline":False},
                        ],
                        "footer":{"text":"Cross-VPS Campaign Detector — github central_db.json"},
                    })

            # Draft abuse complaint to hosting provider
            events_summary = (f"SSH brute-force login. Credentials: {username}/{password}. "
                              f"Visit #{visit_count}. Threat level: {title}. Score: {score}.")
            draft_abuse_complaint(ip, country, isp, events_summary, session)

            # Update attack map
            executor.submit(update_attack_map, ip, country, city, score, title)

        # -------- COMMAND INPUT (Live Shadowing + Wallet + Honeytoken) --------
        elif event_id == "cowrie.command.input":
            cmd = event.get("input","")
            print(f"💻 Command from {ip}: {cmd}")

            check_honeytoken_usage(cmd, ip, session)
            handle_wallet_scan(cmd, ip, session)

            # Live shadowing
            score, title, _ = update_scorecard(ip, "command", session)

            if session not in live_sessions:
                country, city, isp, flag, asn, org = get_ip_intel(ip)
                log_path = os.path.join(LIVE_LOGS_DIR, f"{session}_{int(time.time())}.log")
                append_to_session_log(log_path, cmd)
                embed = build_live_embed(ip, country, city, isp, flag, session, [cmd],
                                         part=1, total=1, log_path=log_path, score=score, title=title)
                msg_id = send_live_message(embed)
                live_sessions[session] = {
                    "message_id": msg_id, "ip":ip, "country":country, "city":city,
                    "isp":isp, "flag":flag, "buffer":[cmd], "total_commands":1,
                    "part":1, "log_path":log_path,
                    "last_activity": time.time(), "score":score, "title":title,
                }
            else:
                sess = live_sessions[session]
                sess["last_activity"] = time.time()
                sess["score"]  = score
                sess["title"]  = title
                append_to_session_log(sess["log_path"], cmd)
                sess["total_commands"] += 1

                candidate = sess["buffer"] + [cmd]
                preview   = "\n".join(f"$ {c}" for c in candidate)

                if len(preview) > LIVE_SHADOW_CHAR_BUDGET and sess["buffer"]:
                    if sess["message_id"]:
                        final_embed = build_live_embed(
                            sess["ip"],sess["country"],sess["city"],sess["isp"],sess["flag"],
                            session, sess["buffer"], part=sess["part"],
                            total=sess["total_commands"]-1, log_path=sess["log_path"],
                            rolled_over=True, score=score, title=title,
                        )
                        edit_live_message(sess["message_id"], final_embed)
                    sess["part"] += 1
                    sess["buffer"] = [cmd]
                    new_embed = build_live_embed(
                        sess["ip"],sess["country"],sess["city"],sess["isp"],sess["flag"],
                        session, sess["buffer"], part=sess["part"],
                        total=sess["total_commands"], log_path=sess["log_path"],
                        score=score, title=title,
                    )
                    sess["message_id"] = send_live_message(new_embed)
                else:
                    sess["buffer"] = candidate
                    if sess["message_id"]:
                        embed = build_live_embed(
                            sess["ip"],sess["country"],sess["city"],sess["isp"],sess["flag"],
                            session, sess["buffer"], part=sess["part"],
                            total=sess["total_commands"], log_path=sess["log_path"],
                            score=score, title=title,
                        )
                        edit_live_message(sess["message_id"], embed)

        # -------- SESSION CLOSED --------
        elif event_id == "cowrie.session.closed":
            sess = live_sessions.pop(session, None)
            if sess and sess.get("message_id"):
                score, title, _ = update_scorecard(ip, "command", session)
                embed = build_live_embed(
                    sess["ip"],sess["country"],sess["city"],sess["isp"],sess["flag"],
                    session, sess["buffer"], part=sess["part"],
                    total=sess["total_commands"], log_path=sess["log_path"],
                    ended=True, score=score, title=title,
                )
                edit_live_message(sess["message_id"], embed)

        # -------- FILE DOWNLOAD (VT + IOC + Sandbox) --------
        elif event_id == "cowrie.session.file_download":
            file_hash    = event.get("shasum")
            download_url = event.get("url","N/A")
            outfile      = event.get("outfile")

            print(f"📥 File download from {ip} (hash: {file_hash})")
            country, city, isp, flag, asn, org = get_ip_intel(ip)
            score, title, _ = update_scorecard(ip, "malware", session)

            if not file_hash:
                send_to_discord({
                    "title":"📥 File Downloaded (No Hash Available)","color":9807270,
                    "fields":[
                        {"name":"👤 Attacker IP","value":str(ip),"inline":True},
                        {"name":"🌍 Location","value":f"{flag} {city}, {country}","inline":True},
                        {"name":"🔗 Source URL","value":str(download_url),"inline":False},
                    ],
                    "footer":{"text":"Payload Scanner"},
                })
            else:
                vt_result = check_virustotal_hash(file_hash)

                if vt_result is None:
                    send_to_discord({
                        "title":"⚠️ VirusTotal Check Failed","color":16776960,
                        "fields":[
                            {"name":"👤 IP","value":str(ip),"inline":True},
                            {"name":"🔑 SHA256","value":str(file_hash),"inline":False},
                            {"name":"🔗 URL","value":str(download_url),"inline":False},
                        ],
                    })
                elif not vt_result["found"]:
                    send_to_discord({
                        "title":"❓ Unknown File — Not in VirusTotal Yet","color":9807270,
                        "description":"Possibly brand-new / unseen malware.",
                        "fields":[
                            {"name":"👤 IP","value":str(ip),"inline":True},
                            {"name":"🌍 Location","value":f"{flag} {city}, {country}","inline":True},
                            {"name":"🔑 SHA256","value":str(file_hash),"inline":False},
                            {"name":"🔗 URL","value":str(download_url),"inline":False},
                        ],
                        "footer":{"text":"Payload Scanner"},
                    })
                else:
                    malicious  = vt_result["malicious"]
                    suspicious = vt_result["suspicious"]
                    total      = vt_result["total"]
                    if malicious > 0:
                        embed_title, color = "☠️ MALWARE DETECTED!", 10038562
                        verdict = f"{vt_result['threat_label']} — {malicious}/{total} engines flagged"
                    elif suspicious > 0:
                        embed_title, color = "🟠 SUSPICIOUS FILE", 16776960
                        verdict = f"{suspicious}/{total} engines flagged as suspicious"
                    else:
                        embed_title, color = "✅ File Appears Clean", 3066993
                        verdict = f"0/{total} engines flagged"

                    send_to_discord({
                        "title":embed_title,"color":color,
                        "fields":[
                            {"name":"👤 IP","value":str(ip),"inline":True},
                            {"name":"🌍 Location","value":f"{flag} {city}, {country}","inline":True},
                            {"name":"🦠 File Name","value":str(vt_result["name"]),"inline":False},
                            {"name":"📊 Verdict","value":verdict,"inline":False},
                            {"name":"🔑 SHA256","value":str(file_hash),"inline":False},
                            {"name":"🔗 URL","value":str(download_url),"inline":False},
                            {"name":"🎖️ Attacker Level","value":f"{title}  (Score: {score})","inline":True},
                        ],
                        "footer":{"text":"VirusTotal Payload Scanner"},
                    })

                if outfile and os.path.isfile(outfile):
                    iocs = extract_iocs(outfile)
                    if iocs and (iocs["ips"] or iocs["urls"] or iocs["telegram_tokens"]):
                        tg_lines = []
                        for token in iocs["telegram_tokens"]:
                            bot_name = verify_telegram_token(token)
                            tg_lines.append(f"{token} -> @{bot_name}" if bot_name else f"{token} (unverified)")
                        send_to_discord({
                            "title":"🕵️ C2 / IOC Indicators Found Inside Payload","color":15105570,
                            "fields":[
                                {"name":"🌐 Embedded IPs","value":"\n".join(iocs["ips"])[:1000] or "None","inline":False},
                                {"name":"🔗 Embedded URLs","value":"\n".join(iocs["urls"])[:1000] or "None","inline":False},
                                {"name":"🤖 Telegram Tokens","value":"\n".join(tg_lines)[:1000] or "None","inline":False},
                            ],
                            "footer":{"text":"Payload IOC Scanner"},
                        })
                        update_scorecard(ip, "ioc", session)

                    sandbox_result = sandbox_analyze(outfile, session)
                    if sandbox_result and "error" not in sandbox_result:
                        changes_text = "\n".join(sandbox_result["fs_changes"]) or "No filesystem changes"
                        send_to_discord({
                            "title":"🧪 Dynamic Sandbox Analysis","color":3426654,
                            "fields":[
                                {"name":"🗂️ Filesystem Changes","value":changes_text[:1000],"inline":False},
                                {"name":"📤 Exit Code","value":str(sandbox_result["exit_code"]),"inline":True},
                                {"name":"🖨️ Stdout","value":(sandbox_result["stdout"] or "None")[:500],"inline":False},
                                {"name":"⚠️ Stderr","value":(sandbox_result["stderr"] or "None")[:500],"inline":False},
                            ],
                            "footer":{"text":"Isolated Docker Sandbox — network disabled"},
                        })

                    report_path = save_ioc_report(
                        file_hash, ip, vt_result,
                        iocs or {"ips":set(),"urls":set(),"telegram_tokens":set()},
                        sandbox_result,
                    )
                    print(f"📄 Report saved: {report_path}")

                    if vt_result and vt_result.get("found") and vt_result.get("malicious",0) > 0:
                        mb_result = submit_to_malwarebazaar(
                            outfile, file_hash,
                            f"Captured by Cowrie honeypot from {ip}, session {session}"
                        )
                        if mb_result:
                            send_to_discord({
                                "title":"📤 Sample Shared with MalwareBazaar","color":3066993,
                                "description":f"Hash `{file_hash}` MalwareBazaar par share kar diya gaya.",
                            })

    except Exception as e:
        print(f"⚠️  Error processing event: {e}")


# ====================== ENTRY POINT ======================

if __name__ == "__main__":
    import sys

    if len(sys.argv) >= 4 and sys.argv[1] == "--add-hassh":
        add_hassh(sys.argv[2], sys.argv[3])
    elif len(sys.argv) >= 2 and sys.argv[1] == "--leaderboard":
        _load_db()
        for rank, (ip, sc, title, att, mal, wal) in enumerate(get_leaderboard(20), 1):
            print(f"#{rank:02d}  {title:<30} {ip:<18}  Score:{sc}  Logins:{att}  Malware:{mal}  Wallets:{wal}")
    elif len(sys.argv) >= 2 and sys.argv[1] == "--digest":
        _load_db()
        # Manually trigger a digest right now (for testing)
        threading.Thread(target=_run_daily_digest, daemon=False).start()
        time.sleep(3)
    else:
        _load_db()
        load_custom_hassh()
        load_hassh_database()
        monitor_log()
