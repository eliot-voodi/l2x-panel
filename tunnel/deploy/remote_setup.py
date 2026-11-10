#!/usr/bin/env python3
"""Upload and install l2x-tunnel on a remote host via SSH/SFTP."""
from __future__ import annotations

import secrets
import sys
import time

import paramiko

HOST = sys.argv[1] if len(sys.argv) > 1 else "92.246.138.163"
USER = sys.argv[2] if len(sys.argv) > 2 else "root"
PASSWORD = sys.argv[3] if len(sys.argv) > 3 else ""
MASTER_UDP = sys.argv[4] if len(sys.argv) > 4 else "127.0.0.1:4443"  # lab: local portal

PSK = "l2x-" + secrets.token_urlsafe(24)
TOKEN = secrets.token_urlsafe(24)


def run(c: paramiko.SSHClient, cmd: str, check: bool = True) -> str:
    print(f"$ {cmd}")
    _, stdout, stderr = c.exec_command(cmd)
    out = stdout.read().decode()
    err = stderr.read().decode()
    code = stdout.channel.recv_exit_status()
    if out.strip():
        print(out.rstrip())
    if err.strip():
        print(err.rstrip())
    if check and code != 0:
        raise RuntimeError(f"cmd failed ({code}): {cmd}")
    return out


def main() -> None:
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(
        HOST,
        username=USER,
        password=PASSWORD,
        timeout=30,
        banner_timeout=60,
        allow_agent=False,
        look_for_keys=False,
    )
    sftp = c.open_sftp()
    run(c, "mkdir -p /usr/local/bin /etc/l2x-tunnel /var/log/l2x-tunnel")
    for local, remote in (
        (r"C:\temp\l2x-tunneld-linux", "/usr/local/bin/l2x-tunneld"),
        (r"C:\temp\l2x-tunnel-agent-linux", "/usr/local/bin/l2x-tunnel-agent"),
    ):
        print(f"upload {local} -> {remote}")
        sftp.put(local, remote)
        run(c, f"chmod 755 {remote}")

    tunneld_yaml = f"""role: portal
tunnel:
  psk: "{PSK}"
  token: "{TOKEN}"
  listen_udp: "0.0.0.0:4443"
  path_count: 8
  cipher: chacha20poly1305
  max_streams: 4000
proxy_listen: "127.0.0.1:18080"
socks_listen: "127.0.0.1:11080"
default_dial: "1.1.1.1:80"
metrics:
  listen: "127.0.0.1:9109"
"""
    agent_yaml = f"""role: agent
tunnel:
  psk: "{PSK}"
  token: "{TOKEN}"
  node_id: "romantic-apricot"
  peer_udp: "{MASTER_UDP}"
  listen_udp: "0.0.0.0:0"
  path_count: 8
  cipher: chacha20poly1305
  max_streams: 4000
  punch_interval_sec: 60
metrics:
  listen: "127.0.0.1:9110"
"""
    with sftp.file("/etc/l2x-tunnel/tunneld.yaml", "w") as f:
        f.write(tunneld_yaml)
    with sftp.file("/etc/l2x-tunnel/agent.yaml", "w") as f:
        f.write(agent_yaml)
    with sftp.file("/etc/l2x-tunnel/CREDENTIALS.txt", "w") as f:
        f.write(f"psk={PSK}\ntoken={TOKEN}\npeer_udp={MASTER_UDP}\n")
    run(c, "chmod 600 /etc/l2x-tunnel/*.yaml /etc/l2x-tunnel/CREDENTIALS.txt")

    for unit, name in (
        (r"C:\temp\l2x-panel\tunnel\deploy\l2x-tunneld.service", "l2x-tunneld.service"),
        (r"C:\temp\l2x-panel\tunnel\deploy\l2x-tunnel-agent.service", "l2x-tunnel-agent.service"),
    ):
        sftp.put(unit, f"/etc/systemd/system/{name}")

    # firewall UDP 4443 if ufw exists
    run(c, "command -v ufw >/dev/null && ufw allow 4443/udp || true", check=False)
    run(c, "systemctl daemon-reload")
    run(c, "systemctl enable --now l2x-tunneld l2x-tunnel-agent")
    time.sleep(2)
    run(c, "systemctl --no-pager --full status l2x-tunneld l2x-tunnel-agent | sed -n '1,80p'", check=False)
    run(c, "curl -s http://127.0.0.1:9109/health; echo; curl -s http://127.0.0.1:9110/health; echo", check=False)
    # TCP smoke through local portal proxy
    run(
        c,
        "printf 'GET / HTTP/1.0\\r\\nHost: 1.1.1.1\\r\\n\\r\\n' | timeout 8 nc -q 2 127.0.0.1 18080 | head -c 200; echo",
        check=False,
    )
    print("\n=== DEPLOY OK ===")
    print(f"PSK={PSK}")
    print(f"TOKEN={TOKEN}")
    print(f"AGENT_PEER={MASTER_UDP}")
    print("Credentials also in /etc/l2x-tunnel/CREDENTIALS.txt on host")
    sftp.close()
    c.close()


if __name__ == "__main__":
    main()
