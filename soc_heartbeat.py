"""
SOC Heartbeat — har VPS apna status GitHub pe push karta hai
=============================================================
Har VPS apni ALAG file likhta hai: status/<name>.json  (koi cross-VPS conflict nahi)
Isse Cowork (jise sirf GitHub tak access hai) bina SSH ke per-VPS status padh sakta hai.

Cron (root), har 10 min:
  */10 * * * *  /usr/bin/python3 /home/cowrie/soc_heartbeat.py <name>
  e.g.  */10 * * * *  /usr/bin/python3 /home/cowrie/soc_heartbeat.py azure

Token /home/cowrie/.github_token (ya env GITHUB_TOKEN) se — koi hardcode nahi.
"""
import sys, os, json, time, base64, socket, subprocess, urllib.request, urllib.error

NAME = (sys.argv[1] if len(sys.argv) > 1 else socket.gethostname()).strip().lower()
REPO = "tjxahmad/cowrie-soc-monitor"
API  = f"https://api.github.com/repos/{REPO}/contents/status/{NAME}.json"


def load_token():
    t = os.environ.get("GITHUB_TOKEN", "").strip()
    if t:
        return t
    for p in ("/home/cowrie/.github_token", os.path.expanduser("~/.github_token")):
        try:
            v = open(p).read().strip()
            if v:
                return v
        except Exception:
            pass
    return ""


TOKEN = load_token()
H = {"Authorization": f"token {TOKEN}", "Accept": "application/vnd.github+json",
     "User-Agent": "soc-heartbeat/1.0"}


def svc(name):
    try:
        return subprocess.run(["systemctl", "is-active", name],
                              capture_output=True, text=True, timeout=10).stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def sh(cmd):
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=25).stdout.strip()
    except Exception:
        return ""


def build_status():
    today = sh("journalctl -u discord-alert --since today --no-pager 2>/dev/null | grep -c 'Login from'")
    last  = sh("journalctl -u discord-alert --since today --no-pager 2>/dev/null | grep 'Login from' | tail -1 | sed 's/.*Login from //'")
    return {
        "name":          NAME,
        "discord_alert": svc("discord-alert"),
        "attack_map":    svc("attack-map"),
        "today_attacks": int(today) if today.isdigit() else -1,
        "last_attacker": last[:90],
        "updated":       int(time.time()),
        "updated_iso":   time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
    }


def get_sha():
    try:
        with urllib.request.urlopen(urllib.request.Request(API, headers=H), timeout=15) as r:
            return json.load(r).get("sha")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        print("sha lookup error:", e)
        return None
    except Exception as e:
        print("sha lookup error:", e)
        return None


def push(status):
    if not TOKEN:
        print("no token — abort")
        return
    sha = get_sha()
    payload = {"message": f"heartbeat: {NAME}",
               "content": base64.b64encode(json.dumps(status, indent=2).encode()).decode()}
    if sha:
        payload["sha"] = sha
    req = urllib.request.Request(API, data=json.dumps(payload).encode(),
                                 headers={**H, "Content-Type": "application/json"}, method="PUT")
    try:
        urllib.request.urlopen(req, timeout=20)
        print(f"heartbeat pushed: {NAME}")
    except Exception as e:
        print("push failed:", e)


if __name__ == "__main__":
    push(build_status())
