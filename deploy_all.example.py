"""
Deploy discord_alert.py + github_sync.py to all your Cowrie VPS servers.
Backs up the old file, copies new files, drops the GitHub token, restarts service.

SETUP:
  1. Copy this file to deploy_all.py
  2. Fill in your VPS list below (host, user, port, key path)
  3. Put your GitHub PAT in the GITHUB_TOKEN env var OR edit TOKEN below
  4. Run:  python deploy_all.py           (all VPS)
           python deploy_all.py azure     (single VPS by name)

NOTE: Files land in /tmp first, then `sudo cp` into /home/cowrie
      (the cowrie dir is usually root-owned). Passwordless sudo required.
"""
import os
import subprocess
import sys

# GitHub PAT — prefer env var, never commit a real token to a public repo.
TOKEN = os.environ.get("GITHUB_TOKEN", "PUT_TOKEN_IN_ENV_VAR")

VPS_LIST = [
    {
        "name":    "vps1",
        "host":    "YOUR.VPS.IP.HERE",
        "user":    "youruser",
        "port":    2222,
        "key":     r"C:\path\to\your_key.pem",
        "dest":    "/home/cowrie",
        "service": "discord-alert",
    },
    # Add more VPS by copying the block above. New servers auto-join the same
    # central_db.json on GitHub — no other change needed.
]

FILES_TO_DEPLOY = [
    r"cowrie-soc-monitor\discord_alert.py",
    r"cowrie-soc-monitor\github_sync.py",
]

SSH_OPTS = ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=15"]


def deploy_vps(vps):
    name   = vps["name"]
    key    = vps["key"]
    port   = str(vps["port"])
    target = f"{vps['user']}@{vps['host']}"
    dest   = vps["dest"]
    print(f"\n{'='*50}\nDeploying to: {name} ({target}:{port})\n{'='*50}")

    # 1. Upload files to /tmp
    for local_file in FILES_TO_DEPLOY:
        fname = local_file.split("\\")[-1]
        scp = ["scp", "-i", key, "-P", port] + SSH_OPTS + [local_file, f"{target}:/tmp/{fname}"]
        if subprocess.run(scp, capture_output=True, text=True).returncode != 0:
            print(f"  FAILED to upload {fname} — skipping {name}")
            return

    # 2. Backup, install, drop token, restart — all via sudo
    remote = f"""
      sudo cp {dest}/discord_alert.py {dest}/discord_alert.py.bak.$(date +%s) 2>/dev/null;
      sudo cp /tmp/discord_alert.py {dest}/discord_alert.py;
      sudo cp /tmp/github_sync.py   {dest}/github_sync.py;
      printf '%s' '{TOKEN}' | sudo tee {dest}/.github_token >/dev/null;
      sudo chmod 600 {dest}/.github_token;
      sudo chown root:root {dest}/.github_token {dest}/github_sync.py {dest}/discord_alert.py;
      rm -f /tmp/discord_alert.py /tmp/github_sync.py;
      sudo systemctl restart {vps['service']}; sleep 3;
      echo -n 'status: '; sudo systemctl is-active {vps['service']};
    """
    ssh = ["ssh", "-i", key, "-p", port] + SSH_OPTS + [target, remote]
    r = subprocess.run(ssh, capture_output=True, text=True)
    print(r.stdout.strip())
    if r.stderr.strip():
        print("  stderr:", r.stderr.strip()[:200])
    print(f"  done: {name}")


if __name__ == "__main__":
    only = sys.argv[1] if len(sys.argv) > 1 else "all"
    for vps in VPS_LIST:
        if only == "all" or vps["name"] == only:
            deploy_vps(vps)
    print("\nCheck Discord for alerts to confirm each monitor is running.")
