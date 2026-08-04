import json
from pathlib import Path

FILES = {
    "azure":    "cowrie-soc-monitor/soc_monitor_db.json",
    "lightsail":"cowrie-soc-monitor/lightsail_soc_monitor_db.json",
    "usman":    "cowrie-soc-monitor/usman_soc_monitor_db.json",
}

merged = {
    "reported_ips":    {},
    "scorecard":       {},
    "recidivism":      {},
    "daily_stats":     {},
    "hassh_to_ips":    {},
    "wallet_to_ips":   {},
    "campaign_alerted":{},
    "_sources":        {},  # ip -> [vps names] — kahan kahan dikh
}

for vps_name, fpath in FILES.items():
    print(f"Loading {vps_name} ...")
    with open(fpath, "r") as f:
        db = json.load(f)

    # reported_ips: ip -> most recent timestamp rakhna
    for ip, ts in db.get("reported_ips", {}).items():
        if ip not in merged["reported_ips"] or ts > merged["reported_ips"][ip]:
            merged["reported_ips"][ip] = ts
        merged["_sources"].setdefault(ip, [])
        if vps_name not in merged["_sources"][ip]:
            merged["_sources"][ip].append(vps_name)

    # scorecard: ip -> scores add karna, sessions merge karna
    for ip, sc in db.get("scorecard", {}).items():
        merged["_sources"].setdefault(ip, [])
        if vps_name not in merged["_sources"][ip]:
            merged["_sources"][ip].append(vps_name)

        if ip not in merged["scorecard"]:
            merged["scorecard"][ip] = dict(sc)
            merged["scorecard"][ip]["sessions"] = list(sc.get("sessions", []))
        else:
            m = merged["scorecard"][ip]
            m["score"]    += sc.get("score", 0)
            m["attempts"] += sc.get("attempts", 0)
            m["malware"]  += sc.get("malware", 0)
            m["wallets"]  += sc.get("wallets", 0)
            # first_seen: sab se pehli timing
            if sc.get("first_seen", 9e18) < m.get("first_seen", 9e18):
                m["first_seen"] = sc["first_seen"]
            # last_seen: sab se latest timing
            if sc.get("last_seen", 0) > m.get("last_seen", 0):
                m["last_seen"] = sc["last_seen"]
            # sessions: unique merge
            existing = set(m["sessions"])
            for s in sc.get("sessions", []):
                if s not in existing:
                    m["sessions"].append(s)
                    existing.add(s)

    # recidivism: count add, sessions merge
    for ip, rec in db.get("recidivism", {}).items():
        if ip not in merged["recidivism"]:
            merged["recidivism"][ip] = dict(rec)
            merged["recidivism"][ip]["sessions"] = list(rec.get("sessions", []))
        else:
            m = merged["recidivism"][ip]
            m["count"] += rec.get("count", 0)
            if rec.get("first_seen", 9e18) < m.get("first_seen", 9e18):
                m["first_seen"] = rec["first_seen"]
            if rec.get("last_seen", 0) > m.get("last_seen", 0):
                m["last_seen"] = rec["last_seen"]
            existing = set(m["sessions"])
            for s in rec.get("sessions", []):
                if s not in existing:
                    m["sessions"].append(s)
                    existing.add(s)

    # daily_stats: date ke andar counts add karna
    for date_str, ds in db.get("daily_stats", {}).items():
        if date_str not in merged["daily_stats"]:
            merged["daily_stats"][date_str] = dict(ds)
            merged["daily_stats"][date_str]["ips"] = list(ds.get("ips", []))
        else:
            m = merged["daily_stats"][date_str]
            m["attempts"] = m.get("attempts", 0) + ds.get("attempts", 0)
            m["malware"]  = m.get("malware", 0)  + ds.get("malware", 0)
            m["reports"]  = m.get("reports", 0)  + ds.get("reports", 0)
            m["wallets"]  = m.get("wallets", 0)  + ds.get("wallets", 0)
            existing = set(m["ips"])
            for ip in ds.get("ips", []):
                if ip not in existing:
                    m["ips"].append(ip)
                    existing.add(ip)

    # hassh_to_ips: same hash ke saare IPs merge (dono jagah likho)
    for hassh, ips in db.get("hassh_to_ips", {}).items():
        existing = merged["hassh_to_ips"].setdefault(hassh, [])
        existing_set = set(existing)
        for ip in ips:
            if ip not in existing_set:
                existing.append(ip)
                existing_set.add(ip)

    # wallet_to_ips: same
    for wallet, ips in db.get("wallet_to_ips", {}).items():
        existing = merged["wallet_to_ips"].setdefault(wallet, [])
        existing_set = set(existing)
        for ip in ips:
            if ip not in existing_set:
                existing.append(ip)
                existing_set.add(ip)

    # campaign_alerted: latest timestamp rakhna
    for key, ts in db.get("campaign_alerted", {}).items():
        if key not in merged["campaign_alerted"] or ts > merged["campaign_alerted"][key]:
            merged["campaign_alerted"][key] = ts

# Score ke hisab se title update karna
def get_title(score):
    if score >= 50:  return "👹 APEX PREDATOR"
    if score >= 30:  return "💀 Persistent Menace"
    if score >= 15:  return "🔥 Botnet Operator"
    if score >= 8:   return "🤖 Botnet Drone"
    if score >= 3:   return "😈 Script Kiddie"
    return "🐣 Noob Probe"

for ip, sc in merged["scorecard"].items():
    sc["title"] = get_title(sc["score"])
    sc["seen_on_vps"] = merged["_sources"].get(ip, [])

# Stats print
print(f"\n✅ Merge complete!")
print(f"   Unique IPs (scorecard): {len(merged['scorecard'])}")
print(f"   Unique HASSH hashes:    {len(merged['hassh_to_ips'])}")
print(f"   Unique wallets:         {len(merged['wallet_to_ips'])}")

# Multi-VPS IPs dikhao
multi = {ip: srcs for ip, srcs in merged["_sources"].items() if len(srcs) > 1}
print(f"   IPs seen on 2+ VPS:     {len(multi)}")
if multi:
    print("\n📌 IPs seen on multiple VPS servers:")
    for ip, srcs in list(multi.items())[:20]:
        sc = merged["scorecard"].get(ip, {})
        print(f"   {ip:<20} VPS: {', '.join(srcs):<30} Score: {sc.get('score',0)}")

# HASSH with multiple IPs
multi_hassh = {h: ips for h, ips in merged["hassh_to_ips"].items() if len(ips) > 1}
print(f"\n📌 HASSH hashes linked to 2+ IPs (campaign candidates): {len(multi_hassh)}")
for h, ips in list(multi_hassh.items())[:10]:
    print(f"   {h}  ->  {len(ips)} IPs: {', '.join(ips[:5])}")

# Save
out = "cowrie-soc-monitor/merged_db.json"
with open(out, "w") as f:
    json.dump(merged, f, indent=2, default=list)
print(f"\n💾 Saved: {out}")
