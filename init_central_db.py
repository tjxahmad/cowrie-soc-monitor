"""
One-time setup: merged_db.json se central_db.json bana ke GitHub pe upload karo.
Run once from your laptop. VPS pe nahi chalana.
"""
import os
import json
import base64
import requests

# ===== CONFIG =====
# Token env var se: PowerShell -> $env:GITHUB_TOKEN="ghp_xxx"; python init_central_db.py
GITHUB_TOKEN    = os.environ.get("GITHUB_TOKEN", "").strip()
GITHUB_REPO     = "tjxahmad/cowrie-soc-monitor"
CENTRAL_DB_FILE = "central_db.json"
MERGED_FILE     = "cowrie-soc-monitor/merged_db.json"
# ==================

if not GITHUB_TOKEN:
    print("ERROR: GITHUB_TOKEN env var set nahi hai. PowerShell mein: $env:GITHUB_TOKEN=\"ghp_xxx\"")
    import sys as _sys; _sys.exit(1)

API_URL = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{CENTRAL_DB_FILE}"
HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3+json",
}

print("Loading merged_db.json ...")
with open(MERGED_FILE) as f:
    merged = json.load(f)

# Build central_db — sirf zaruri fields
hassh_to_ips = merged.get("hassh_to_ips", {})

# Reverse map: ip -> hashes
ip_to_hashes = {}
for hassh, ips in hassh_to_ips.items():
    for ip in ips:
        ip_to_hashes.setdefault(ip, [])
        if hassh not in ip_to_hashes[ip]:
            ip_to_hashes[ip].append(hassh)

central_db = {
    "hassh_to_ips": hassh_to_ips,
    "ip_to_hashes": ip_to_hashes,
    "reported_ips": merged.get("reported_ips", {}),
}

print(f"  HASSH hashes: {len(hassh_to_ips)}")
print(f"  Unique IPs:   {len(ip_to_hashes)}")
print(f"  Reported IPs: {len(central_db['reported_ips'])}")

# Check if file already exists (need SHA for update)
sha = None
resp = requests.get(API_URL, headers=HEADERS, timeout=10)
if resp.status_code == 200:
    sha = resp.json()["sha"]
    print(f"Existing central_db.json found (SHA: {sha[:8]}...) — will update.")
elif resp.status_code == 404:
    print("No existing central_db.json — will create new.")
else:
    print(f"GitHub error: {resp.status_code} {resp.text}")
    exit(1)

# Upload
encoded = base64.b64encode(json.dumps(central_db, indent=2, default=list).encode()).decode()
payload = {
    "message": "soc-init: upload historical attack data from all 3 VPS",
    "content": encoded,
}
if sha:
    payload["sha"] = sha

print("Uploading to GitHub ...")
resp = requests.put(API_URL, headers=HEADERS, json=payload, timeout=30)
if resp.status_code in (200, 201):
    url = resp.json().get("content", {}).get("html_url", "")
    print(f"Done! File URL: {url}")
else:
    print(f"Upload failed: {resp.status_code}")
    print(resp.text[:500])
