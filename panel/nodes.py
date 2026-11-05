"""Multi-node registry: SSH provision, sync, promote-to-master, node as outbound."""
from __future__ import annotations

import json
import re
import secrets
import uuid
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SLUG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def slugify(name: str) -> str:
    s = re.sub(r"[^A-Za-z0-9_-]+", "_", (name or "node").strip())[:32]
    return s if SLUG_RE.match(s) else f"node_{secrets.token_hex(3)}"


def ensure_list(store: dict) -> list[dict]:
    nodes = store.setdefault("nodes", [])
    for n in nodes:
        n.setdefault("id", str(uuid.uuid4()))
        n.setdefault("name", n.get("url") or "node")
        n.setdefault("url", "")
        n.setdefault("token", "")
        n.setdefault("enabled", True)
        n.setdefault("sync_clients", True)
        n.setdefault("sync_inbounds", True)
        n.setdefault("as_outbound", False)
        n.setdefault("domain", "")
        n.setdefault("ssh_user", "")
        n.setdefault("ssh_port", 22)
        n.setdefault("bridge_uuid", "")
        n.setdefault("bridge_path", "")
        n.setdefault("base_path", "")
        n.setdefault("last_sync", "")
        n.setdefault("last_error", "")
        n.setdefault("last_ok", False)
        n.setdefault("role", "agent")  # on master registry entries are always agents
    return nodes


def agent_token(store: dict) -> str:
    s = store.setdefault("settings", {}).setdefault("nodes", {})
    if not s.get("agent_token"):
        s["agent_token"] = secrets.token_urlsafe(32)
    s.setdefault("agent_enabled", False)
    s.setdefault("role", "master")  # master | agent
    return s["agent_token"]


def is_master(store: dict) -> bool:
    ns = store.get("settings", {}).get("nodes") or {}
    if ns.get("agent_enabled") and ns.get("role") == "agent":
        return False
    return (ns.get("role") or "master") != "agent"


def ensure_bridge(node: dict) -> dict:
    """Allocate VLESS/WS bridge credentials used so the master can egress via this node."""
    if not node.get("bridge_uuid"):
        node["bridge_uuid"] = str(uuid.uuid4())
    if not node.get("bridge_path"):
        node["bridge_path"] = "/nb-" + secrets.token_urlsafe(8).replace("_", "").replace("-", "")[:12]
    return node


def bridge_inbound(node: dict) -> dict:
    """Inbound definition pushed to the remote node for master→node egress."""
    ensure_bridge(node)
    return {
        "id": 9000 + (abs(hash(node["id"])) % 1000),
        "tag": "node-bridge",
        "remark": "L2X node bridge (master egress)",
        "enabled": True,
        "listen": "127.0.0.1",
        "port": 19000,
        "protocol": "vless",
        "settings": {"flow": "", "decryption": "none", "encryption": ""},
        "stream": {
            "network": "ws",
            "security": "none",
            "ws": {"path": node["bridge_path"], "host": "", "accept_proxy_protocol": False},
            "tls": {"server_name": "", "cert_file": "", "key_file": "", "alpn": ["h2", "http/1.1"],
                    "fingerprint": "chrome", "min_version": "1.2", "allow_insecure": False,
                    "reject_unknown_sni": False, "ech_server_keys": ""},
            "reality": {"dest": "ya.ru:443", "server_names": ["ya.ru"], "private_key": "", "public_key": "",
                        "short_ids": [], "fingerprint": "chrome", "spider_x": "/", "show": False, "xver": 0},
            "raw": {"header": "none", "http_host": "", "http_path": "/", "accept_proxy_protocol": False},
            "grpc": {"service_name": "grpc", "multi_mode": False, "authority": ""},
            "httpupgrade": {"path": "/up", "host": "", "accept_proxy_protocol": False},
            "xhttp": {"path": "/xh", "host": "", "mode": "auto", "extra": ""},
            "kcp": {"mtu": 1350, "tti": 20, "uplink": 5, "downlink": 20, "congestion": False, "header": "none", "seed": ""},
            "sockopt": {"enabled": False},
        },
        "sniffing": {"enabled": False, "dest": ["http", "tls", "quic"], "route_only": False, "metadata_only": False},
        "fallbacks": [],
        "outbound": "direct",
    }


def node_outbound_tag(node: dict) -> str:
    return f"node_{slugify(node.get('name') or 'node')}"


def node_outbound_config(node: dict) -> dict:
    """Xray outbound on the master that tunnels through the remote node's bridge inbound."""
    ensure_bridge(node)
    domain = (node.get("domain") or "").strip()
    if not domain:
        # derive from URL
        from urllib.parse import urlparse
        domain = urlparse(node.get("url") or "").hostname or ""
    return {
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": domain,
                "port": 443,
                "users": [{"id": node["bridge_uuid"], "encryption": "none", "flow": ""}],
            }],
        },
        "streamSettings": {
            "network": "ws",
            "security": "tls",
            "wsSettings": {"path": node["bridge_path"], "headers": {}},
            "tlsSettings": {"serverName": domain, "allowInsecure": False, "fingerprint": "chrome",
                            "alpn": ["http/1.1"]},
        },
    }


def upsert_node_outbound(store: dict, node: dict) -> None:
    """Keep outbounds_custom in sync when node.as_outbound is enabled."""
    customs = store.setdefault("outbounds_custom", [])
    tag = node_outbound_tag(node)
    existing = next((o for o in customs if o.get("tag") == tag or o.get("node_id") == node.get("id")), None)
    if not node.get("as_outbound") or not node.get("enabled", True):
        if existing:
            customs.remove(existing)
        return
    ensure_bridge(node)
    domain = (node.get("domain") or "").strip()
    if not domain:
        from urllib.parse import urlparse
        domain = urlparse(node.get("url") or "").hostname or ""
    if not domain:
        return
    entry = {
        "tag": tag,
        "remark": f"Node {node.get('name')}",
        "kind": "node",
        "node_id": node.get("id"),
        "enabled": True,
        "in_sub": True,
        "country": (node.get("country") or "")[:2].upper(),
        "config": node_outbound_config(node),
    }
    if existing:
        existing.update(entry)
    else:
        customs.append(entry)


def sync_all_node_outbounds(store: dict) -> None:
    for n in ensure_list(store):
        upsert_node_outbound(store, n)
    # drop stale node_* outbounds whose node was deleted
    ids = {n.get("id") for n in store.get("nodes") or []}
    store["outbounds_custom"] = [
        o for o in (store.get("outbounds_custom") or [])
        if o.get("kind") != "node" or o.get("node_id") in ids
    ]


def _agent_safe_clients(clients: list[dict]) -> list[dict]:
    """Agent has no master's L2TP ifaces — remap dangling outbound tags to direct."""
    out = []
    for c in clients or []:
        c = dict(c)
        ob = (c.get("outbound") or "direct").strip()
        if ob.startswith("l2tp_") or ob.startswith("node_"):
            c["outbound"] = "direct"
        out.append(c)
    return out


def _agent_safe_routes(routes: list[dict]) -> list[dict]:
    out = []
    for r in routes or []:
        r = dict(r)
        ob = (r.get("outbound") or r.get("outbound_tag") or "direct").strip()
        if ob.startswith("l2tp_") or ob.startswith("node_"):
            r["outbound"] = "direct"
            r.pop("outbound_tag", None)
        out.append(r)
    return out


def _agent_safe_balancers(balancers: dict) -> dict:
    """Drop explicit L2TP members — agent will use connected local tunnels or [direct]."""
    bals = json.loads(json.dumps(balancers or {}))  # deep copy
    for b in bals.values():
        if not isinstance(b, dict):
            continue
        members = b.get("members") or []
        b["members"] = [m for m in members if not str(m).startswith("l2tp_") and not str(m).startswith("node_")]
    return bals


def build_payload(store: dict, node: dict, build_config) -> dict:
    """Subset for a remote agent: clients + inbounds + xray config without local L2TP ifaces."""
    clients = _agent_safe_clients(store.get("clients") or [])
    inbounds = list(store.get("inbounds") or [])
    # Ensure bridge inbound exists on agent when used as outbound
    if node.get("as_outbound"):
        ensure_bridge(node)
        inbounds = [i for i in inbounds if i.get("tag") != "node-bridge"]
        inbounds.append(bridge_inbound(node))
    self_tag = node_outbound_tag(node)
    # Also send bridge client into the main clients list so Xray email routing works if needed
    bridge_clients = []
    if node.get("as_outbound"):
        bridge_clients = [{
            "email": f"bridge@{slugify(node.get('name') or 'node')}",
            "uuid": node["bridge_uuid"], "enabled": True, "inbounds": ["node-bridge"],
            "outbound": "direct", "limit_gb": 0, "limit_ip": 0, "limit_hwid": 0,
            "sub_enabled": False, "comment": "node bridge (auto)",
        }]
    # Agent store snapshot (no master's L2TP-bound custom outbounds that need local ifaces)
    customs = []
    for o in store.get("outbounds_custom") or []:
        if o.get("tag") == self_tag or o.get("kind") == "node":
            continue
        customs.append(o)
    return {
        "clients": (clients if node.get("sync_clients", True) else []) + bridge_clients,
        "inbounds": inbounds if node.get("sync_inbounds", True) or node.get("as_outbound") else [],
        "outbounds_custom": customs,
        "routes": _agent_safe_routes(store.get("routes") or []),
        "balancers": _agent_safe_balancers(store.get("balancers") or {}),
        "dns": store.get("dns") or {},
        "xray_settings": store.get("xray_settings") or {},
        "pushed_at": now_iso(),
        "node_id": node.get("id"),
        "bridge": {
            "uuid": node.get("bridge_uuid"),
            "path": node.get("bridge_path"),
            "enabled": bool(node.get("as_outbound")),
        } if node.get("as_outbound") else None,
    }


def agent_apply_url(node: dict) -> str:
    """Agent endpoint lives under the node's secret base_path (nginx only proxies that prefix)."""
    base = (node.get("url") or "").rstrip("/")
    bp = (node.get("base_path") or "").strip().strip("/")
    if bp:
        return f"{base}/{bp}/agent/apply"
    return f"{base}/agent/apply"


def push(node: dict, payload: dict, timeout: int = 60, master_host: str = "") -> dict:
    domain = (node.get("domain") or "").strip()
    if not domain:
        from urllib.parse import urlparse
        domain = urlparse(node.get("url") or "").hostname or ""
    if master_host:
        self_err = same_host_as_master(domain, master_host)
        if self_err:
            node["last_sync"] = now_iso()
            node["last_ok"] = False
            node["last_error"] = self_err
            return {"ok": False, "error": self_err}
    url = agent_apply_url(node)
    token = node.get("token") or ""
    data = json.dumps(payload, ensure_ascii=False).encode()
    req = urllib.request.Request(url, data=data, method="POST", headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
        "User-Agent": "L2XPanel-NodeSync/1.0",
    })
    try:
        # Default HTTPS context — SNI comes from the URL hostname.
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode()
            try:
                parsed = json.loads(body)
            except json.JSONDecodeError:
                parsed = {"ok": resp.status < 300, "raw": body[:500]}
            ok = bool(parsed.get("ok", resp.status < 300))
            node["last_sync"] = now_iso()
            node["last_ok"] = ok
            err = "" if ok else str(parsed.get("error") or body[:300])
            try:
                from xray_runtime import clean_xray_error
                err = clean_xray_error(err) or err
            except Exception:
                pass
            node["last_error"] = err
            if isinstance(parsed, dict) and err:
                parsed = {**parsed, "error": err}
            return parsed if isinstance(parsed, dict) else {"ok": ok}
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8", "replace")[:500]
        except Exception:
            pass
        try:
            parsed = json.loads(body) if body else {}
        except json.JSONDecodeError:
            parsed = {}
        err = str(parsed.get("error") or body or exc)
        try:
            from xray_runtime import clean_xray_error
            err = clean_xray_error(err) or err
        except Exception:
            pass
        # Prefer explicit agent errors over opaque "HTTP Error 403"
        if exc.code == 403 and "agent" in err.lower():
            err = err
        elif body and "error" in (parsed or {}):
            err = str(parsed.get("error"))
        else:
            err = f"HTTP {exc.code}: {err}"
        node["last_sync"] = now_iso()
        node["last_ok"] = False
        node["last_error"] = err
        return {"ok": False, "error": err}
    except Exception as exc:  # noqa: BLE001
        node["last_sync"] = now_iso()
        node["last_ok"] = False
        node["last_error"] = str(exc)
        return {"ok": False, "error": str(exc)}


def apply_agent_payload(store: dict, payload: dict, apply_config) -> dict:
    if payload.get("clients") is not None:
        store["clients"] = payload["clients"]
    if payload.get("inbounds") is not None:
        store["inbounds"] = payload["inbounds"]
    if payload.get("outbounds_custom") is not None:
        store["outbounds_custom"] = payload["outbounds_custom"]
    if payload.get("routes") is not None:
        store["routes"] = payload["routes"]
    if payload.get("balancers") is not None:
        store["balancers"] = payload["balancers"]
    if payload.get("dns") is not None:
        store["dns"] = payload["dns"]
    if payload.get("xray_settings") is not None:
        store["xray_settings"] = payload["xray_settings"]
    return apply_config(store)


# ---------------------------------------------------------------- SSH provision

def _ssh_connect(host: str, user: str, password: str, port: int = 22, timeout: int = 30):
    import paramiko
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, port=int(port or 22), username=user, password=password,
                   timeout=timeout, banner_timeout=60, auth_timeout=30,
                   look_for_keys=False, allow_agent=False)
    return client


def _ssh_run(client, cmd: str, timeout: int = 600) -> dict:
    _stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    code = stdout.channel.recv_exit_status()
    return {"ok": code == 0, "code": code, "stdout": out, "stderr": err}


def _normalize_domain(value: str) -> str:
    return (value or "").strip().lower().removeprefix("https://").removeprefix("http://").split("/")[0]


def _local_ip_set() -> set[str]:
    import socket
    import subprocess
    ips: set[str] = {"127.0.0.1", "::1"}
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            ips.add(info[4][0])
    except OSError:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("1.1.1.1", 80))
        ips.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    for cmd in (("hostname", "-I"), ("ip", "-4", "-o", "addr", "show", "scope", "global")):
        try:
            out = subprocess.check_output(cmd, text=True, timeout=5, stderr=subprocess.DEVNULL)
        except (OSError, subprocess.SubprocessError):
            continue
        for tok in out.replace("/", " ").split():
            if tok.count(".") == 3 and all(p.isdigit() for p in tok.split(".")):
                ips.add(tok)
    return ips


def same_host_as_master(domain: str, master_host: str = "") -> str:
    """Return error text if domain points at this master; empty string if OK."""
    domain = _normalize_domain(domain)
    master = _normalize_domain(master_host)
    if not domain:
        return "некорректный domain"
    if master and domain == master:
        return f"нельзя провиженить сам master ({domain}) — укажите другой сервер"
    import socket
    try:
        remote_ips = {info[4][0] for info in socket.getaddrinfo(domain, 443)}
    except OSError as exc:
        return f"DNS {domain}: {exc}"
    local = _local_ip_set()
    if remote_ips & local:
        return f"{domain} резолвится в IP этого сервера — self-provision запрещён"
    return ""


def provision_via_ssh(
    *,
    domain: str,
    ssh_user: str,
    ssh_password: str,
    ssh_port: int = 22,
    name: str = "",
    master_url: str = "",
    master_token: str = "",
    master_host: str = "",
    as_outbound: bool = True,
    admin_password: str = "",
) -> dict:
    """Install/configure L2X on a remote host over SSH and return node registry fields."""
    domain = _normalize_domain(domain)
    if not domain or " " in domain:
        return {"ok": False, "error": "некорректный domain"}
    if not master_host and master_url:
        master_host = _normalize_domain(master_url)
    self_err = same_host_as_master(domain, master_host)
    if self_err:
        return {"ok": False, "error": self_err}
    name = slugify(name or domain.split(".")[0])
    admin_password = admin_password or secrets.token_urlsafe(12)
    panel_path = secrets.token_urlsafe(9).replace("_", "").replace("-", "")[:12]
    agent_tok = master_token or secrets.token_urlsafe(32)
    node_id = str(uuid.uuid4())
    node = {
        "id": node_id, "name": name, "domain": domain, "ssh_user": ssh_user, "ssh_port": int(ssh_port or 22),
        "token": agent_tok, "enabled": True, "sync_clients": True, "sync_inbounds": True,
        "as_outbound": bool(as_outbound), "base_path": panel_path, "role": "agent",
        "url": f"https://{domain}", "last_sync": "", "last_error": "", "last_ok": False,
    }
    ensure_bridge(node)
    log: list[str] = [f"provision {name} @ {domain}"]

    try:
        client = _ssh_connect(domain, ssh_user, ssh_password, int(ssh_port or 22))
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"SSH: {exc}", "log": "\n".join(log)}

    try:
        # Hard stop: SSH landed on this same machine (self-provision), even if DNS checks lied.
        local_mid = ""
        try:
            local_mid = Path("/etc/machine-id").read_text(encoding="utf-8").strip()
        except OSError:
            pass
        remote_mid = (_ssh_run(client, "cat /etc/machine-id 2>/dev/null || true").get("stdout") or "").strip()
        if local_mid and remote_mid and local_mid == remote_mid:
            try:
                client.close()
            except Exception:
                pass
            return {
                "ok": False,
                "error": f"SSH к {domain} попал на этот же сервер (machine-id совпал) — укажите другую ноду",
                "log": "\n".join(log),
            }

        sftp = client.open_sftp()
        # Non-interactive install: ensure curl, fail hard on errors (no silent "exit=0").
        env_body = "\n".join([
            "#!/bin/bash",
            "set -euo pipefail",
            "export PATH=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin${PATH:+:$PATH}\"",
            "export DEBIAN_FRONTEND=noninteractive",
            f"export L2X_HOST={json.dumps(domain)[1:-1]}",
            f"export L2X_DOMAIN={json.dumps(domain)[1:-1]}",
            "export L2X_SSL=domain",
            "export L2X_MODE=nginx",
            "export L2X_ADMIN=admin",
            f"export L2X_PASSWORD={json.dumps(admin_password)[1:-1]}",
            f"export L2X_PATH={json.dumps(panel_path)[1:-1]}",
            "",
            "if ! command -v curl >/dev/null 2>&1; then",
            "  if command -v apt-get >/dev/null 2>&1; then",
            "    apt-get update -y",
            "    apt-get install -y curl ca-certificates",
            "  elif command -v dnf >/dev/null 2>&1; then",
            "    dnf install -y curl ca-certificates",
            "  elif command -v yum >/dev/null 2>&1; then",
            "    yum install -y curl ca-certificates",
            "  else",
            "    echo 'curl is required but not installed' >&2",
            "    exit 127",
            "  fi",
            "fi",
            "command -v curl",
            "",
            "if [ -f /etc/l2xpanel/panel.env ] && [ -f /opt/l2xpanel/app.py ]; then",
            "  curl -fsSL https://raw.githubusercontent.com/eliot-voodi/l2x-panel/main/install.sh | bash -s -- --update",
            "else",
            "  curl -fsSL https://raw.githubusercontent.com/eliot-voodi/l2x-panel/main/install.sh | bash -s -- --yes",
            "fi",
            "",
        ])
        with sftp.file("/tmp/l2x_remote_install.sh", "w") as f:
            f.write(env_body)
        # Agent setup: keep existing secret path on re-provision; always re-apply nginx front.
        # Refuse to demote an existing master unless L2X_FORCE_AGENT=1 (set by us for real remotes).
        remote_py = f"""
import json, os, sys
from pathlib import Path
sys.path.insert(0, "/opt/l2xpanel")
TOKEN = {agent_tok!r}
DOMAIN = {domain!r}
PATH_NEW = {panel_path!r}
FORCE = os.environ.get("L2X_FORCE_AGENT") == "1"
store_path = Path("/var/lib/l2xpanel/store.json")
store = json.loads(store_path.read_text()) if store_path.exists() else {{}}
s = store.setdefault("settings", {{}})
ns = s.setdefault("nodes", {{}})
was_master = (ns.get("role") or "master") != "agent" and not ns.get("agent_enabled")
if was_master and not FORCE:
    print("refuse_demote_master")
    raise SystemExit(2)
ns["agent_enabled"] = True
ns["agent_token"] = TOKEN
ns["role"] = "agent"
panel = s.setdefault("panel", {{}})
panel["public_host"] = DOMAIN
# Preserve existing base_path so re-provision does not break the admin URL
existing_bp = (panel.get("base_path") or "").strip().strip("/")
panel["base_path"] = existing_bp or PATH_NEW
store_path.parent.mkdir(parents=True, exist_ok=True)
# atomic replace avoids partial reads by a racing panel process
tmp = store_path.with_suffix(".tmp")
tmp.write_text(json.dumps(store, ensure_ascii=False, indent=2))
tmp.replace(store_path)
bp = panel["base_path"]
print("agent_ok", TOKEN[:8], bp, "enabled", ns["agent_enabled"])
try:
    import front
    staged = front.stage(store)
    if staged.get("ok"):
        print("front", front.commit(staged))
    else:
        print("front_stage_fail", staged.get("error"))
except Exception as exc:
    print("front_err", exc)
"""
        with sftp.file("/tmp/l2x_agent_setup.py", "w") as f:
            f.write(remote_py)
        sftp.close()

        r = _ssh_run(client, "bash /tmp/l2x_remote_install.sh; ec=$?; rm -f /tmp/l2x_remote_install.sh; exit $ec", timeout=900)
        log.append(f"install exit={r['code']}")
        log.append((r["stdout"] or "")[-2500:])
        if r["stderr"]:
            log.append("stderr: " + r["stderr"][-1500:])
        if not r.get("ok"):
            return {
                "ok": False,
                "error": f"установка на ноде завершилась с кодом {r.get('code')}",
                "log": "\n".join(log),
                "node": node,
            }
        if not _ssh_run(client, "test -f /opt/l2xpanel/app.py")["ok"]:
            return {"ok": False, "error": "установка на ноде не удалась", "log": "\n".join(log), "node": node}

        # Stop panel before writing store so a live process cannot overwrite agent flags,
        # then start, wait for health, re-apply agent once more (beats delayed acme restarts),
        # and verify /agent/apply is not "agent disabled".
        r2 = _ssh_run(
            client,
            "set -a; . /etc/l2xpanel/panel.env; set +a; "
            "export L2X_FORCE_AGENT=1; "
            "systemctl stop l2xpanel || true; "
            "cd /opt/l2xpanel; PYTHONPATH=/opt/l2xpanel .venv/bin/python /tmp/l2x_agent_setup.py; "
            "ec=$?; "
            "systemctl start l2xpanel; "
            "for i in 1 2 3 4 5 6 7 8 9 10; do "
            "  sleep 1; curl -sf http://127.0.0.1:8090/health >/dev/null && break; "
            "done; "
            # acme may schedule restart +5s — rewrite agent flags again after settle
            "sleep 6; "
            "systemctl stop l2xpanel || true; "
            "PYTHONPATH=/opt/l2xpanel .venv/bin/python /tmp/l2x_agent_setup.py; "
            "systemctl start l2xpanel; "
            "sleep 2; "
            "curl -s http://127.0.0.1:8090/health || true; echo; "
            # verify agent endpoint (wrong token → 401 means agent is ON; 403 = disabled)
            "bp=$(python3 -c \"import json;from pathlib import Path;s=json.loads(Path('/var/lib/l2xpanel/store.json').read_text());print((s.get('settings') or {}).get('panel',{}).get('base_path') or '')\"); "
            "code=$(curl -s -o /tmp/l2x_agent_probe.json -w '%{http_code}' -X POST "
            "  -H 'Content-Type: application/json' -H 'Authorization: Bearer probe' "
            "  -d '{}' \"http://127.0.0.1:8090/${bp}/agent/apply\"); "
            "echo agent_probe $code $(cat /tmp/l2x_agent_probe.json 2>/dev/null); "
            "rm -f /tmp/l2x_agent_setup.py /tmp/l2x_agent_probe.json; "
            "test \"$code\" = \"401\" || test \"$code\" = \"200\"; exit $?",
            timeout=120,
        )
        log.append(r2["stdout"][-1500:])
        if "refuse_demote_master" in (r2["stdout"] or ""):
            return {
                "ok": False,
                "error": "удалённый хост уже master — demote запрещён (похоже на self-provision)",
                "log": "\n".join(log),
                "node": node,
            }
        if "agent disabled" in (r2["stdout"] or "") or not r2.get("ok"):
            return {
                "ok": False,
                "error": "agent не включился на ноде (403 agent disabled) — повторите provision",
                "log": "\n".join(log),
                "node": node,
            }
        # Prefer base_path reported by agent_ok
        used_bp = panel_path
        for line in (r2["stdout"] or "").splitlines():
            if line.startswith("agent_ok "):
                parts = line.split()
                if len(parts) >= 3:
                    used_bp = parts[2]
        node["url"] = f"https://{domain}"
        node["base_path"] = used_bp
        node["token"] = agent_tok
        # On --update the existing admin password is kept; do not pretend we set a new one.
        return {
            "ok": True,
            "node": node,
            "admin_password": "(без изменений, если панель уже была установлена)",
            "panel_url": f"https://{domain}/{used_bp}/",
            "log": "\n".join(log),
        }
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc), "log": "\n".join(log), "node": node}
    finally:
        try:
            client.close()
        except Exception:
            pass


def promote_via_ssh(
    node: dict,
    *,
    ssh_password: str,
    master_store_snapshot: dict,
    old_master_node: dict,
) -> dict:
    """Make remote node the new master: push store snapshot, disable agent, register old master as node."""
    domain = node.get("domain") or ""
    user = node.get("ssh_user") or "root"
    port = int(node.get("ssh_port") or 22)
    if not domain or not ssh_password:
        return {"ok": False, "error": "нужны domain и SSH-пароль ноды"}
    log = [f"promote {node.get('name')} → master"]
    try:
        client = _ssh_connect(domain, user, ssh_password, port)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"SSH: {exc}"}

    try:
        # Merge snapshot into remote store (clients/inbounds/routes/balancers/nodes)
        snap = {
            "clients": master_store_snapshot.get("clients") or [],
            "inbounds": master_store_snapshot.get("inbounds") or [],
            "routes": master_store_snapshot.get("routes") or [],
            "balancers": master_store_snapshot.get("balancers") or {},
            "outbounds_custom": master_store_snapshot.get("outbounds_custom") or [],
            "dns": master_store_snapshot.get("dns") or {},
            "xray_settings": master_store_snapshot.get("xray_settings") or {},
            "l2tp": [],  # L2TP stays local to each host
            "nodes": [old_master_node],
        }
        sftp = client.open_sftp()
        with sftp.file("/tmp/l2x_promote.json", "w") as f:
            f.write(json.dumps(snap, ensure_ascii=False))
        promote_py = """
import json
from pathlib import Path
snap = json.loads(Path('/tmp/l2x_promote.json').read_text())
store_path = Path('/var/lib/l2xpanel/store.json')
store = json.loads(store_path.read_text()) if store_path.exists() else {}
for k in ('clients','inbounds','routes','balancers','outbounds_custom','dns','xray_settings','nodes'):
    if k in snap:
        store[k] = snap[k]
store.setdefault('settings', {}).setdefault('nodes', {})
store['settings']['nodes']['agent_enabled'] = False
store['settings']['nodes']['role'] = 'master'
store_path.write_text(json.dumps(store, ensure_ascii=False, indent=2))
print('promoted')
"""
        with sftp.file("/tmp/l2x_promote.py", "w") as f:
            f.write(promote_py)
        sftp.close()
        r = _ssh_run(
            client,
            "set -a; . /etc/l2xpanel/panel.env; set +a; "
            "cd /opt/l2xpanel; .venv/bin/python /tmp/l2x_promote.py; "
            "systemctl restart l2xpanel; sleep 2; "
            "rm -f /tmp/l2x_promote.py /tmp/l2x_promote.json; "
            "curl -s http://127.0.0.1:8090/health",
            timeout=90,
        )
        log.append(r["stdout"][-500:])
        ok = r["ok"] and "promoted" in (r["stdout"] or "")
        return {"ok": ok, "log": "\n".join(log), "error": "" if ok else (r["stderr"] or "promote failed")}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc), "log": "\n".join(log)}
    finally:
        try:
            client.close()
        except Exception:
            pass
