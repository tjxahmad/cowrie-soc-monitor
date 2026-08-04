"""
SOC Daily Summary — VPS-side cross-VPS digest -> Discord
=========================================================
Ek VPS pe cron se roz chalta hai. GitHub ke public central_db.json se
saare honeypots ka aggregate view banata hai (biggest botnets, 24h reports)
+ is host ke aaj ke attacks, aur Discord webhook pe post karta hai.

Webhook /home/cowrie/discord_alert.py se read hota hai (koi naya secret nahi).
Cron example:  30 8 * * *  /usr/bin/python3 /home/cowrie/soc_daily_summary.py
"""
import re, json, time, socket, subprocess, urllib.request

CENTRAL_DB_RAW   = "https://raw.githubusercontent.com/tjxahmad/cowrie-soc-monitor/main/central_db.json"
DISCORD_ALERT_PY = "/home/cowrie/discord_alert.py"
CAMPAIGN_MIN_IPS = 2


def get_webhook():
    try:
        txt = open(DISCORD_ALERT_PY, encoding="utf-8", errors="ignore").read()
        m = re.search(r'WEBHOOK_URL\s*=\s*"([^"]+)"', txt)
        if m and m.group(1).startswith("http"):
            return m.group(1)
    except Exception as e:
        print("webhook read error:", e)
    return None


def fetch_central():
    try:
        req = urllib.request.Request(CENTRAL_DB_RAW + "?t=" + str(int(time.time())),
                                     headers={"Cache-Control": "no-cache"})
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        print("central fetch error:", e)
        return None


def today_attacks():
    try:
        out = subprocess.run(
            "journalctl -u discord-alert --since today --no-pager 2>/dev/null | grep -c 'Login from'",
            shell=True, capture_output=True, text=True, timeout=20)
        return out.stdout.strip() or "0"
    except Exception:
        return "?"


def main():
    webhook = get_webhook()
    if not webhook:
        print("no webhook found — abort")
        return

    db = fetch_central()
    if not db:
        print("no central_db — abort")
        return

    hti = db.get("hassh_to_ips", {})
    reported = db.get("reported_ips", {})
    now = time.time()

    total_ips    = len(set(db.get("ip_to_hashes", {})) | set(reported))
    reported_24h = sum(1 for ts in reported.values() if now - ts < 86400)
    campaigns    = sorted(((h, len(i)) for h, i in hti.items() if len(i) >= CAMPAIGN_MIN_IPS),
                          key=lambda x: x[1], reverse=True)

    camp_lines = "\n".join(f"• `{h[:18]}…` → **{n}** IPs" for h, n in campaigns[:5]) or "None"
    host = socket.gethostname()

    embed = {
        "title": "🛡️ SOC Daily Summary — All Honeypots",
        "color": 3447003,
        "fields": [
            {"name": "🌐 Tracked IPs (network)",    "value": f"{total_ips:,}",       "inline": True},
            {"name": "🔬 SSH fingerprints",         "value": f"{len(hti):,}",        "inline": True},
            {"name": "📤 Reported (last 24h)",       "value": f"{reported_24h:,}",    "inline": True},
            {"name": "🕸️ Active campaigns",          "value": f"{len(campaigns)}",    "inline": True},
            {"name": f"🖥️ This host ({host}) today", "value": f"{today_attacks()} attacks", "inline": True},
            {"name": "🏆 Biggest botnets (shared HASSH)", "value": camp_lines, "inline": False},
        ],
        "footer": {"text": "SOC Watchtower — cross-VPS daily digest"},
    }
    payload = {"embeds": [embed]}
    try:
        req = urllib.request.Request(webhook, data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json",
                                              "User-Agent": "SOC-Watchtower/1.0 (+honeypot-monitor)"})
        urllib.request.urlopen(req, timeout=10)
        print("posted to Discord OK")
    except Exception as e:
        print("discord post error:", e)


if __name__ == "__main__":
    main()
