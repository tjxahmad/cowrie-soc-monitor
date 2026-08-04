"""
SOC WATCHTOWER — cross-VPS honeypot briefing
=============================================
Ek command mein teeno honeypots ka poora haal:
  - GitHub central_db.json (public) se global attack intel + biggest campaigns
  - Har VPS pe SSH: service health + aaj ke attacks + last attacker

Usage:
  python soc_watchtower.py            # full briefing (central + all VPS)
  python soc_watchtower.py --global   # sirf GitHub central_db (no SSH, fast)
  python soc_watchtower.py --discord  # briefing + Discord webhook pe post

Secrets: koi hardcoded token nahi. central_db.json PUBLIC hai (no auth).
VPS keys sirf local paths se use hoti hain.
"""
import sys, json, time, subprocess, urllib.request
from datetime import datetime, timezone

# ===================== CONFIG (local only — repo mein placeholder version) =====================
CENTRAL_DB_RAW = "https://raw.githubusercontent.com/YOUR_USERNAME/cowrie-soc-monitor/main/central_db.json"

# Discord webhook — proactive summary ke liye. Blank = --discord disabled.
DISCORD_WEBHOOK = ""   # yahan real webhook daalo agar --discord se laptop se post karna ho

VPS_LIST = [
    {"name":"VPS1", "host":"1.2.3.4",  "user":"youruser", "port":2222, "key":r"C:\path	o\key1.pem"},
    {"name":"VPS2", "host":"5.6.7.8",  "user":"youruser", "port":2222, "key":r"C:\path	o\key2.pem"},
    # add more VPS here - no other change needed
]

CAMPAIGN_MIN_IPS = 2
# ==============================================================================================


def fetch_central():
    try:
        req = urllib.request.Request(CENTRAL_DB_RAW + "?t=" + str(int(time.time())),
                                     headers={"Cache-Control": "no-cache"})
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        print(f"  [!] central_db fetch failed: {e}")
        return None


def global_intel(db):
    hti = db.get("hassh_to_ips", {})
    reported = db.get("reported_ips", {})
    now = time.time()

    all_ips = set(db.get("ip_to_hashes", {}).keys()) | set(reported.keys())
    reported_24h = sum(1 for ts in reported.values() if now - ts < 86400)

    campaigns = sorted(
        ((h, len(ips)) for h, ips in hti.items() if len(ips) >= CAMPAIGN_MIN_IPS),
        key=lambda x: x[1], reverse=True,
    )

    return {
        "total_ips":     len(all_ips),
        "total_hashes":  len(hti),
        "reported_all":  len(reported),
        "reported_24h":  reported_24h,
        "campaigns":     campaigns,
    }


def ssh_run(vps, remote_cmd, timeout=25):
    cmd = ["ssh", "-i", vps["key"], "-p", str(vps["port"]),
           "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=12",
           f"{vps['user']}@{vps['host']}", remote_cmd]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception as e:
        return f"__ERR__ {e}"


def vps_status(vps):
    remote = (
        "echo SVC=$(systemctl is-active discord-alert 2>/dev/null);"
        "echo MAP=$(systemctl is-active attack-map 2>/dev/null);"
        "N=$(sudo journalctl -u discord-alert --since today --no-pager 2>/dev/null | grep -c 'Login from');"
        "echo TODAY=$N;"
        "L=$(sudo journalctl -u discord-alert --since today --no-pager 2>/dev/null | grep 'Login from' | tail -1 | sed 's/.*Login from //');"
        "echo LAST=\"$L\";"
    )
    out = ssh_run(vps, remote)
    res = {"svc":"?", "map":"?", "today":"?", "last":"?"}
    if out.startswith("__ERR__"):
        res["svc"] = "unreachable"
        return res
    for line in out.splitlines():
        if line.startswith("SVC="):   res["svc"]   = line[4:] or "?"
        elif line.startswith("MAP="):  res["map"]   = line[4:] or "?"
        elif line.startswith("TODAY="):res["today"] = line[6:] or "0"
        elif line.startswith("LAST="): res["last"]  = line[5:] or "—"
    return res


def build_report(do_ssh=True):
    lines = []
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines.append(f"🛡️  SOC WATCHTOWER — {stamp}")
    lines.append("=" * 52)

    db = fetch_central()
    if db:
        g = global_intel(db)
        lines.append("🌐 GLOBAL (all honeypots, via GitHub central_db)")
        lines.append(f"   Tracked IPs:        {g['total_ips']:,}")
        lines.append(f"   SSH fingerprints:   {g['total_hashes']:,}")
        lines.append(f"   Reported (all-time):{g['reported_all']:,}")
        lines.append(f"   Reported (last 24h):{g['reported_24h']:,}")
        lines.append(f"   Active campaigns:   {len(g['campaigns'])}  (hashes shared by 2+ IPs)")
        if g["campaigns"]:
            lines.append("   🕸️  Biggest botnets:")
            for h, n in g["campaigns"][:5]:
                lines.append(f"      • {h[:16]}…  →  {n} IPs")
    else:
        lines.append("🌐 GLOBAL: central_db unavailable")

    if do_ssh:
        lines.append("")
        lines.append("🖥️  PER-VPS (live)")
        for vps in VPS_LIST:
            s = vps_status(vps)
            icon = "✅" if s["svc"] == "active" else "❌"
            lines.append(f"   {icon} {vps['name']:<10} svc:{s['svc']}  map:{s['map']}  "
                         f"today:{s['today']} attacks  last:{s['last'][:38]}")

    lines.append("=" * 52)
    return "\n".join(lines)


def post_discord(text):
    if not DISCORD_WEBHOOK:
        print("  [!] DISCORD_WEBHOOK blank — skip Discord post")
        return
    payload = {"embeds": [{
        "title": "🛡️ SOC Watchtower — Daily Briefing",
        "description": "```\n" + text[:3900] + "\n```",
        "color": 3447003,
    }]}
    try:
        req = urllib.request.Request(
            DISCORD_WEBHOOK,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json",
                     "User-Agent": "SOC-Watchtower/1.0 (+honeypot-monitor)"},
        )
        urllib.request.urlopen(req, timeout=10)
        print("  ✓ posted to Discord")
    except Exception as e:
        print(f"  [!] Discord post failed: {e}")


if __name__ == "__main__":
    args = sys.argv[1:]
    do_ssh = "--global" not in args
    report = build_report(do_ssh=do_ssh)
    print(report)
    if "--discord" in args:
        post_discord(report)
