import os, json, base64, requests

TOKEN = os.environ["GITHUB_TOKEN"]
REPO  = "tjxahmad/cowrie-soc-monitor"
FILE  = "central_db.json"
URL   = f"https://api.github.com/repos/{REPO}/contents/{FILE}"
H     = {"Authorization": f"token {TOKEN}", "Accept": "application/vnd.github+json"}

TEST_IP   = "203.0.113.99"
TEST_HASH = "testhash_deploycheck"

r = requests.get(URL, headers=H, timeout=15); r.raise_for_status()
j = r.json()
db = json.loads(base64.b64decode(j["content"]).decode())

removed = []
if TEST_IP in db.get("reported_ips", {}):
    del db["reported_ips"][TEST_IP]; removed.append("reported_ips")
if TEST_IP in db.get("ip_to_hashes", {}):
    del db["ip_to_hashes"][TEST_IP]; removed.append("ip_to_hashes")
if TEST_HASH in db.get("hassh_to_ips", {}):
    del db["hassh_to_ips"][TEST_HASH]; removed.append("hassh_to_ips")
# also scrub test IP from any hash lists
for h, ips in db.get("hassh_to_ips", {}).items():
    if TEST_IP in ips:
        ips.remove(TEST_IP); removed.append(f"hassh:{h}")

print("Removed from:", removed or "nothing (already clean)")

enc = base64.b64encode(json.dumps(db, indent=2, default=list).encode()).decode()
payload = {"message": "soc-cleanup: remove deploy-test IP", "content": enc, "sha": j["sha"]}
r2 = requests.put(URL, headers=H, json=payload, timeout=20)
print("Cleanup push:", r2.status_code)
