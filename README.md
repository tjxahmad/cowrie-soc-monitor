# 🛡️ Cowrie Honeypot SOC Monitor

A real-time threat intelligence monitor for [Cowrie SSH/Telnet honeypots](https://github.com/cowrie/cowrie). Sends live Discord alerts, tracks attackers, visualizes attacks on a world map, and automatically reports malicious IPs to the security community.

**Now with cross-VPS central reporting** — run it on any number of honeypots and they all share one brain: a single `central_db.json` hosted on GitHub. When the same SSH client fingerprint (HASSH) shows up across different IPs on *different* servers, every linked IP is reported together as one botnet campaign.

> Built as a personal SOC (Security Operations Center) project to monitor real-world SSH brute-force attacks, malware, and botnet activity on VPS honeypots.

---

## ✨ Features

| # | Feature | Description |
|---|---------|-------------|
| 1 | **Discord Alerts** | Instant alerts for logins, commands, file downloads |
| 2 | **AbuseIPDB Auto-Report** | Automatically reports attacker IPs (skips blank passwords) |
| 3 | **VirusTotal Hash Lookup** | Scans every downloaded malware file |
| 4 | **IP Geolocation (Failover)** | ip-api.com → ipinfo.io → ipapi.co fallback chain |
| 5 | **Live Terminal Shadowing** | Watch attacker type commands in real-time on Discord |
| 6 | **C2 / IOC Extraction** | Extracts IPs, URLs, Telegram bot tokens from payloads |
| 7 | **Dynamic Sandbox** | Runs malware in isolated Docker container, reports behavior |
| 8 | **HASSH Fingerprinting** | Identifies SSH client (Paramiko/Metasploit/OpenSSH/PuTTY etc.) |
| 9 | **Crypto Wallet Scraper** | Detects BTC/ETH/XMR wallets in commands, checks balances |
| 10 | **Honeytoken Traps** | Fake AWS keys / .env files — alerts when attacker uses them |
| 11 | **Attacker Scorecard** | Points system with titles (Script Kiddie → Apex Predator) |
| 12 | **Wall of Shame Leaderboard** | Live Discord leaderboard of top attackers |
| 13 | **Recidivism Tracker** | "REPEAT OFFENDER" alert when same IP returns (persistent across restarts) |
| 14 | **Auto Abuse Complaint** | Drafts professional complaint email to attacker's hosting provider |
| 15 | **Campaign Detector** | Links multiple IPs sharing same HASSH/wallet = one botnet operator |
| 16 | **Live World Map** | HTML dashboard with real-time attack dots on a dark world map |
| 17 | **Daily Digest** | Midnight Discord summary: attempts, malware, wallets, top attacker |
| 18 | **MalwareBazaar Auto-Share** | Shares confirmed malware with abuse.ch community |
| 19 | **🌐 Cross-VPS Central Reporting** | All honeypots share one GitHub-hosted `central_db.json`. Same HASSH across servers = coordinated botnet report. |

---

## 🌐 Cross-VPS Central Reporting (How it works)

Every honeypot running this tool reads from and writes to **one shared file on GitHub**: `central_db.json`. This turns N independent honeypots into a single distributed sensor network.

```
   ┌────────────┐      ┌────────────┐      ┌────────────┐
   │  VPS #1    │      │  VPS #2    │      │  VPS #3    │
   │ (Cowrie +  │      │ (Cowrie +  │      │ (Cowrie +  │
   │  monitor)  │      │  monitor)  │      │  monitor)  │
   └─────┬──────┘      └─────┬──────┘      └─────┬──────┘
         │  fetch + save     │                   │
         └───────────────────┼───────────────────┘
                             ▼
              ┌──────────────────────────────┐
              │   GitHub: central_db.json     │
              │   { hassh_to_ips,             │
              │     ip_to_hashes,             │
              │     reported_ips }            │
              └──────────────────────────────┘
```

**What gets stored in `central_db.json`** (only threat-intel data — never secrets):

```json
{
  "hassh_to_ips":  { "<hassh>": ["ip1", "ip2", ...] },
  "ip_to_hashes":  { "<ip>":    ["hassh1", ...] },
  "reported_ips":  { "<ip>":    1712345678.9 }
}
```

**The reporting rules** (enforced in [`github_sync.py`](github_sync.py)):

1. **Blank password → skip.** No AbuseIPDB report for empty-password logins.
2. **Internal IP → skip.** `10.*`, `127.*`, `172.*`, `192.168.*` are ignored.
3. **1 report per IP per 24h — globally.** The cooldown lives in the shared file, so an IP reported by VPS #1 won't be re-reported by VPS #2 the same day.
4. **Campaign linking.** When a HASSH fingerprint is seen from **2 or more different IPs** (across any servers), all linked IPs are reported together as one botnet campaign (AbuseIPDB categories `14,18,22`).
5. **Conflict-safe writes.** If two servers write at the same moment, GitHub rejects the stale one (HTTP 409); the monitor re-fetches and retries, so no update is lost and no IP is double-reported.

> The HASSH for a session comes from the `cowrie.client.kex` event; the report fires on the following `cowrie.login.success` event for that session.

---

## 📋 Requirements

### System
- Linux VPS (Ubuntu 20.04+ recommended)
- Python 3.8+
- [Cowrie honeypot](https://github.com/cowrie/cowrie) running and generating JSON logs
- Docker (optional — needed only for sandbox feature; also common for running Cowrie itself)

### Python dependency
```bash
pip3 install requests --break-system-packages
```

### APIs / tokens needed

| Service | Required? | Get it here |
|---------|-----------|-------------|
| Discord Webhook | ✅ Yes | Server Settings → Integrations → Webhooks |
| AbuseIPDB | ✅ Yes | https://www.abuseipdb.com/register |
| VirusTotal | ✅ Yes | https://www.virustotal.com/gui/join-us |
| **GitHub PAT** | ✅ Yes (for cross-VPS sync) | https://github.com/settings/tokens — scope: `repo` |
| abuse.ch (MalwareBazaar) | ⬜ Optional | https://auth.abuse.ch/ |

> ip-api.com, ipinfo.io, ipapi.co — **no key needed**, used automatically for geolocation.

> ⚠️ **Never commit any real token/key/webhook.** This repo ships only placeholders. Secrets live on each server (in the file, or as an env var) — see below.

---

## 🚀 First-Time Installation (single VPS)

### Step 1 — Clone the repo
```bash
cd /home/cowrie
git clone https://github.com/tjxahmad/cowrie-soc-monitor.git
cp cowrie-soc-monitor/discord_alert.py /home/cowrie/discord_alert.py
cp cowrie-soc-monitor/github_sync.py   /home/cowrie/github_sync.py
```

### Step 2 — Configure your keys (in `discord_alert.py`)
```bash
nano /home/cowrie/discord_alert.py
```
Fill in the `CONFIG` section:
```python
WEBHOOK_URL        = "https://discord.com/api/webhooks/YOUR_WEBHOOK_URL"
LOG_FILE_PATH      = "/home/cowrie/cowrie-git/var/log/cowrie/cowrie.json"
ABUSEIPDB_API_KEY  = "your_abuseipdb_key"
VIRUSTOTAL_API_KEY = "your_virustotal_key"
ABUSECH_AUTH_KEY   = ""   # optional
```

**Finding your Cowrie log path:**
```bash
# Standard Cowrie install
ls /home/cowrie/cowrie-git/var/log/cowrie/cowrie.json

# If Cowrie runs in Docker (very common) — find the real path:
sudo find / -name "cowrie.json" 2>/dev/null
# e.g. /var/lib/docker/volumes/<id>/_data/log/cowrie/cowrie.json
```

### Step 3 — Set up the GitHub token (for cross-VPS sync)

The token is read from an **environment variable** first, then from a **secret file**. Never hardcode it.

```bash
# Option A (recommended): secret file, root-only
printf '%s' 'ghp_your_token_here' | sudo tee /home/cowrie/.github_token >/dev/null
sudo chmod 600 /home/cowrie/.github_token

# Option B: env var in the systemd unit (see discord-alert.service.example)
#   Environment=GITHUB_TOKEN=ghp_your_token_here
```

Also set your repo in [`github_sync.py`](github_sync.py) if you forked it:
```python
GITHUB_REPO      = "YOUR_USERNAME/cowrie-soc-monitor"
CENTRAL_DB_FILE  = "central_db.json"
CAMPAIGN_MIN_IPS = 2       # 2+ IPs sharing a HASSH = campaign
REPORT_COOLDOWN  = 86400   # 24h, one report per IP per day
```

### Step 4 — Run as a background service (systemd)
```bash
sudo cp cowrie-soc-monitor/discord-alert.service.example /etc/systemd/system/discord-alert.service
sudo systemctl daemon-reload
sudo systemctl enable --now discord-alert
```

### Step 5 — (Optional) Attack Map web server
```bash
sudo cp cowrie-soc-monitor/attack-map.service.example /etc/systemd/system/attack-map.service
sudo systemctl daemon-reload
sudo systemctl enable --now attack-map
sudo ufw allow 8888
```
Then open `http://YOUR_VPS_IP:8888` (also open port 8888 in your cloud firewall panel).

---

## ➕ Adding a NEW honeypot VPS to the network

Once the system is live, adding another honeypot is quick — the new server automatically joins the same `central_db.json` and starts contributing/receiving campaign intel. Nothing else needs to change.

### Manual way (on the new VPS)
```bash
# 1. Get the code
cd /home/cowrie
git clone https://github.com/tjxahmad/cowrie-soc-monitor.git
cp cowrie-soc-monitor/discord_alert.py /home/cowrie/discord_alert.py
cp cowrie-soc-monitor/github_sync.py   /home/cowrie/github_sync.py

# 2. Fill in CONFIG (webhook, keys, correct LOG_FILE_PATH) in discord_alert.py
nano /home/cowrie/discord_alert.py

# 3. Drop the SAME GitHub token used by your other servers
printf '%s' 'ghp_your_token_here' | sudo tee /home/cowrie/.github_token >/dev/null
sudo chmod 600 /home/cowrie/.github_token

# 4. Install + start the service (this alone joins central_db.json)
sudo cp cowrie-soc-monitor/discord-alert.service.example /etc/systemd/system/discord-alert.service
sudo systemctl daemon-reload
sudo systemctl enable --now discord-alert

# 5. (For the Watchtower / Cowork dashboard) push a heartbeat every 10 min.
#    Replace <name> with a short label for this server, e.g. azure / vps4.
sudo cp cowrie-soc-monitor/soc_heartbeat.py /home/cowrie/
( sudo crontab -l 2>/dev/null; echo '*/10 * * * * /usr/bin/python3 /home/cowrie/soc_heartbeat.py <name>' ) | sudo crontab -
sudo python3 /home/cowrie/soc_heartbeat.py <name>   # push one now so it shows up immediately
```
That's it — the new VPS is now part of the network **and** appears in the Watchtower / Cowork dashboard. ✅

**What each step sends to GitHub:**
- Steps 1–4 (the monitor) → writes attacker IPs + HASSH fingerprints into shared **`central_db.json`**.
- Step 5 (the heartbeat) → writes this server's live **`status/<name>.json`** (service health + today's attacks).
- Raw Cowrie logs stay **on the VPS** — only this derived intel goes to GitHub. The Watchtower / Cowork plugin reads both files back through the GitHub API, so a new VPS shows up automatically with **no extra config anywhere else**.

### Automated way (from your laptop) — `deploy_all.py`

The repo ships [`deploy_all.example.py`](deploy_all.example.py) with **placeholders**. Copy it to a private `deploy_all.py` (kept off GitHub), fill in your real servers, and run it. It backs up the old file, copies the new code, drops the token, and restarts the service on every server.

```bash
cp deploy_all.example.py deploy_all.py     # local only — do NOT commit real infra
# edit deploy_all.py: add a block per VPS (host, user, port, key path)
export GITHUB_TOKEN=ghp_your_token_here

python deploy_all.py          # deploy to ALL servers
python deploy_all.py vps1     # deploy to one server by name
```

To add a future VPS: just append another block to `VPS_LIST` in your private `deploy_all.py`:
```python
{
    "name": "vps4", "host": "1.2.3.4", "user": "youruser", "port": 2222,
    "key": r"C:\path\to\key.pem", "dest": "/home/cowrie", "service": "discord-alert",
},
```

> 🔒 **Why `deploy_all.example.py` and not `deploy_all.py`?** Your real `deploy_all.py` contains server IPs, usernames, and key paths — infrastructure details that must **not** be public. Only the placeholder example lives in the repo.

---

## 👁️ SOC Watchtower — one-command briefing + daily digest

A lightweight monitoring layer on top of the honeypots. Two parts:

**1. On-demand briefing** — [`soc_watchtower.py`](soc_watchtower.example.py) (laptop). Run it any time to get the whole network's status in one shot:
```bash
python soc_watchtower.py            # global intel + live SSH status of every VPS
python soc_watchtower.py --global   # only GitHub central_db (fast, no SSH)
python soc_watchtower.py --discord  # also post the briefing to Discord
```
It reads the **public** `central_db.json` (no token needed) for cross-VPS intel — total tracked IPs, active campaigns, biggest botnets — then SSHes into each VPS for live service health and today's attack count.

Example output:
```
🌐 GLOBAL (all honeypots, via GitHub central_db)
   Tracked IPs:        2,210
   Reported (last 24h):926
   🕸️  Biggest botnets:  eb0e0554… → 784 IPs   acaa53e0… → 534 IPs
🖥️  PER-VPS (live)
   ✅ Azure      svc:active  today:194 attacks  last:80.94.92.55
   ✅ Usman      svc:active  today:67 attacks   last:80.94.92.234
```

> Copy [`soc_watchtower.example.py`](soc_watchtower.example.py) → private `soc_watchtower.py`, fill in your VPS list (same shape as `deploy_all.py`). Adding a VPS = one more line in `VPS_LIST`.

**2. Proactive daily digest** — [`soc_daily_summary.py`](soc_daily_summary.py) runs on one VPS via cron and posts a cross-VPS summary to Discord automatically. No secrets in it: the webhook is read at runtime from `discord_alert.py`, and `central_db.json` is public.
```bash
# on the VPS:
sudo cp cowrie-soc-monitor/soc_daily_summary.py /home/cowrie/
( sudo crontab -l 2>/dev/null; echo '30 8 * * * /usr/bin/python3 /home/cowrie/soc_daily_summary.py' ) | sudo crontab -
```

**3. GitHub heartbeats → status from anywhere (incl. Cowork)** — [`soc_heartbeat.py`](soc_heartbeat.py) runs on each VPS via cron and pushes a small `status/<name>.json` (service health + today's attacks + last attacker) to this repo every 10 minutes. Each VPS writes its **own** file, so there are no write conflicts. Anything that can read GitHub — including a restricted sandbox like **Claude Cowork** — can then show live per-VPS status **without SSH or any credentials**.
```bash
# on each VPS (name = azure / lightsail / usman / ...):
sudo cp cowrie-soc-monitor/soc_heartbeat.py /home/cowrie/
( sudo crontab -l 2>/dev/null; echo '*/10 * * * * /usr/bin/python3 /home/cowrie/soc_heartbeat.py <name>' ) | sudo crontab -
```
> Adding a new VPS to the dashboard = deploy `soc_heartbeat.py` + one cron line with its name. Nothing else.

A companion **Cowork plugin** (`honeypot-watchtower`) reads these heartbeats + `central_db.json` purely through the GitHub API, so you can ask "honeypot status" inside Cowork. (If the Cowork sandbox blocks `api.github.com`, use `soc_watchtower.py` from a local terminal instead.)

---

## 🧰 Operator / setup scripts (in this repo)

| File | Purpose | Where to run |
|------|---------|--------------|
| [`discord_alert.py`](discord_alert.py) | The monitor itself (placeholder config) | each VPS |
| [`github_sync.py`](github_sync.py) | Cross-VPS central reporting logic (reads token from env/file) | each VPS |
| [`init_central_db.py`](init_central_db.py) | One-time: seed `central_db.json` on GitHub from a merged local DB | laptop |
| [`merge_db.py`](merge_db.py) | Merge multiple per-VPS `soc_monitor_db.json` dumps into one | laptop |
| [`cleanup_test_ip.py`](cleanup_test_ip.py) | Remove test/junk IPs from `central_db.json` | laptop |
| [`deploy_all.example.py`](deploy_all.example.py) | Template to deploy code + token to all servers | laptop (copy → `deploy_all.py`) |
| [`soc_watchtower.example.py`](soc_watchtower.example.py) | One-command cross-VPS briefing (on-demand) | laptop (copy → `soc_watchtower.py`) |
| [`soc_daily_summary.py`](soc_daily_summary.py) | Daily cross-VPS digest → Discord (via cron) | one VPS |
| [`soc_heartbeat.py`](soc_heartbeat.py) | Push per-VPS `status/<name>.json` to GitHub (cron) | each VPS |
| [`discord-alert.service.example`](discord-alert.service.example) | systemd unit for the monitor | each VPS |
| [`attack-map.service.example`](attack-map.service.example) | systemd unit for the map web server | each VPS |

All scripts that need the GitHub token read it from the `GITHUB_TOKEN` environment variable:
```bash
export GITHUB_TOKEN=ghp_your_token_here
python init_central_db.py
```

---

## 🪤 Honeytoken Setup (Optional but Powerful)

Plant fake credentials in Cowrie's fake filesystem so attackers find them. When they try to use them, you get an instant alert.

**1. Generate canary AWS keys** at https://canarytokens.org/generate (choose "AWS Keys") — you'll get an email when anyone uses them anywhere on the internet.

**2. Plant them in Cowrie's honeyfs:**
```bash
mkdir -p /home/cowrie/cowrie-git/honeyfs/root/.aws
nano /home/cowrie/cowrie-git/honeyfs/root/.aws/credentials
```
```ini
[default]
aws_access_key_id = AKIAIOSFODNN7CANARY1
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYCANARYKEY
```

**3. Add to config in `discord_alert.py`:**
```python
HONEYTOKENS = {
    "aws_keys": [
        {
            "access_key": "AKIAIOSFODNN7CANARY1",
            "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYCANARYKEY",
            "note": "planted in /root/.aws/credentials"
        }
    ],
}
```

---

## 🎮 Extra Commands

```bash
# View live logs
sudo journalctl -u discord-alert -f

# View top attackers leaderboard in terminal
python3 /home/cowrie/discord_alert.py --leaderboard

# Add a manually identified HASSH fingerprint
python3 /home/cowrie/discord_alert.py --add-hassh <hash> "Client Name"

# Find Cowrie log path if using Docker
sudo find / -name "cowrie.json" 2>/dev/null
```

---

## 📁 Files Created Automatically (per VPS)

| Path | What it is |
|------|-----------|
| `/home/cowrie/soc_monitor_db.json` | Local persistent DB — scores, recidivism, campaign data |
| `/home/cowrie/.github_token` | Your GitHub PAT (chmod 600, never committed) |
| `/home/cowrie/attack_map/index.html` | Live attack map dashboard |
| `/home/cowrie/attack_map/attacks.json` | All-time attack geo data |
| `/home/cowrie/live_sessions/` | Full transcripts per attacker session |
| `/home/cowrie/threat_reports/` | Markdown threat-intel reports per malware sample |
| `/home/cowrie/hassh_cache/` | Cached HASSH fingerprint databases |
| `/home/cowrie/unknown_hassh.log` | Unidentified HASSH hashes for manual research |

---

## 🔐 Security Notes

- **No secrets in this repo.** Webhook, API keys, and the GitHub token are all placeholders here and supplied per-server.
- **`central_db.json` is safe to be public** — it holds only attacker IPs and HASSH fingerprints (threat intel), no credentials.
- **Rotate the GitHub token** if it is ever exposed: regenerate at https://github.com/settings/tokens and redeploy `/home/cowrie/.github_token` to each server.
- Give the PAT the **minimum scope** it needs (`repo` → Contents). A fine-grained token limited to this single repo is ideal.

---

## ⚠️ Disclaimer

This tool is for **defensive security research only**. Run it on a dedicated honeypot VPS — not your main server. The sandbox feature runs unknown attacker files inside Docker; while network-disabled, container escapes are theoretically possible. Use a disposable VM.

---

## 📜 License

MIT License — free to use, modify, and share.

---

## 🙏 Credits

- [Cowrie](https://github.com/cowrie/cowrie) — the SSH/Telnet honeypot this tool monitors
- [salesforce/hassh](https://github.com/salesforce/hassh) — SSH fingerprint database
- [0x4D31/hassh-utils](https://github.com/0x4D31/hassh-utils) — community HASSH database
- [AbuseIPDB](https://www.abuseipdb.com/) — IP abuse reporting
- [VirusTotal](https://www.virustotal.com/) — malware scanning
- [abuse.ch MalwareBazaar](https://bazaar.abuse.ch/) — malware sharing
