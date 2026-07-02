# 🛡️ Cowrie Honeypot SOC Monitor

A real-time threat intelligence monitor for [Cowrie SSH/Telnet honeypots](https://github.com/cowrie/cowrie). Sends live Discord alerts, tracks attackers, visualizes attacks on a world map, and automatically reports malicious IPs to the security community.

> Built as a personal SOC (Security Operations Center) project to monitor real-world SSH brute-force attacks, malware, and botnet activity on a VPS honeypot.

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

---

## 📋 Requirements

### System
- Linux VPS (Ubuntu 20.04+ recommended)
- Python 3.8+
- [Cowrie honeypot](https://github.com/cowrie/cowrie) running and generating JSON logs
- Docker (optional — needed only for sandbox feature)

### Python dependency
```bash
pip3 install requests --break-system-packages
```

### APIs needed (all free)

| API | Required? | Get it here |
|-----|-----------|-------------|
| Discord Webhook | ✅ Yes | Server Settings → Integrations → Webhooks |
| AbuseIPDB | ✅ Yes | https://www.abuseipdb.com/register |
| VirusTotal | ✅ Yes | https://www.virustotal.com/gui/join-us |
| abuse.ch (MalwareBazaar) | ⬜ Optional | https://auth.abuse.ch/ |

> ip-api.com, ipinfo.io, ipapi.co — **no key needed**, used automatically for geolocation.

---

## 🚀 Installation

### Step 1 — Clone the repo
```bash
cd /home/cowrie
git clone https://github.com/YOUR_USERNAME/cowrie-soc-monitor.git
cp cowrie-soc-monitor/discord_alert.py /home/cowrie/discord_alert.py
```

### Step 2 — Configure your keys
```bash
nano /home/cowrie/discord_alert.py
```

Find the `CONFIG` section at the top and fill in:

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

# If Cowrie runs in Docker
find /var/lib/docker -name "cowrie.json" 2>/dev/null
```

**Getting your Discord Webhook URL:**
1. Open Discord → Your Server → Right-click a channel → Edit Channel
2. Integrations → Webhooks → New Webhook
3. Copy Webhook URL → paste into `WEBHOOK_URL`

### Step 3 — Run as a background service (systemd)

```bash
sudo nano /etc/systemd/system/discord-alert.service
```

Paste:
```ini
[Unit]
Description=SOC Honeypot Discord Alert Monitor
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/home/cowrie
ExecStart=/usr/bin/python3 /home/cowrie/discord_alert.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable discord-alert
sudo systemctl start discord-alert
```

### Step 4 — Run the Attack Map (optional)

```bash
sudo nano /etc/systemd/system/attack-map.service
```

Paste:
```ini
[Unit]
Description=Cowrie Attack Map Web Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 -m http.server 8888 --directory /home/cowrie/attack_map/
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable attack-map
sudo systemctl start attack-map

# Open port in firewall
sudo ufw allow 8888
```

Then open in browser: `http://YOUR_VPS_IP:8888`

> Also open port 8888 in your VPS provider's firewall panel (DigitalOcean/Vultr/Hetzner/AWS Security Groups).

---

## 🪤 Honeytoken Setup (Optional but Powerful)

Plant fake credentials in Cowrie's fake filesystem so attackers find them. When they try to use them, you get an instant alert.

**1. Generate canary AWS keys** at https://canarytokens.org/generate (choose "AWS Keys") — you'll get an email when anyone uses them anywhere on the internet.

**2. Plant them in Cowrie's honeyfs:**
```bash
mkdir -p /home/cowrie/cowrie-git/honeyfs/root/.aws
nano /home/cowrie/cowrie-git/honeyfs/root/.aws/credentials
```
Paste:
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

# Count total attacks on map
cat /home/cowrie/attack_map/attacks.json | python3 -m json.tool | grep '"ip"' | wc -l

# Find Cowrie log path if Docker container was restarted
find /var/lib/docker -name "cowrie.json" 2>/dev/null
```

---

## 📁 Files Created Automatically

| Path | What it is |
|------|-----------|
| `/home/cowrie/soc_monitor_db.json` | Persistent DB — scores, recidivism, campaign data |
| `/home/cowrie/attack_map/index.html` | Live attack map dashboard |
| `/home/cowrie/attack_map/attacks.json` | All-time attack geo data |
| `/home/cowrie/live_sessions/` | Full unlimited transcripts per attacker session |
| `/home/cowrie/threat_reports/` | Markdown threat intel reports for each malware sample |
| `/home/cowrie/hassh_cache/` | Cached HASSH fingerprint databases |
| `/home/cowrie/unknown_hassh.log` | Unidentified HASSH hashes for manual research |

---

## 🗺️ Attack Map Preview

Dark-theme world map (Leaflet.js + CartoDB Dark Matter tiles). Each red dot = one attacker. Dot size scales with threat score. Auto-refreshes every 15 seconds.

Serve with:
```bash
python3 -m http.server 8888 --directory /home/cowrie/attack_map/
```

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
