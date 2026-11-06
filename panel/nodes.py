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
        # Full standby copy of master (clients/outbounds/routes/…) while still acting as outbound
        n.setdefault("mirror", False)
        n.setdefault("domain", "")
        n.setdefault("ssh_user", "")
        n.setdefault("ssh_port", 22)
        n.setdefault("bridge_uuid", "")
        n.setdefault("bridge_path", "")
        n.setdefault("base_path", "")
        n.setdefault("last_sync", "")
        n.setdefault("last_error", "")
        n.setdefault("last_ok", False)
        n.setdefault("panel_version", "")
        n.setdefault("last_update", "")
        # Auto-sync interval in minutes; 0 = disabled
        n.setdefault("sync_interval_min", 0)
        n.setdefault("role", "agent")  # on master registry entries are always agents
    return nodes


SYNC_INTERVAL_CHOICES = (
    (0, "выкл"),
    (5, "5 мин"),
    (15, "15 мин"),
    (30, "30 мин"),
    (60, "1 ч"),
    (180, "3 ч"),
    (360, "6 ч"),
    (720, "12 ч"),
    (1440, "24 ч"),
)


def normalize_sync_interval(raw) -> int:
    try:
        v = int(raw or 0)
    except (TypeError, ValueError):
        return 0
    allowed = {m for m, _ in SYNC_INTERVAL_CHOICES}
    return v if v in allowed else 0


def sync_interval_label(minutes: int) -> str:
    for m, label in SYNC_INTERVAL_CHOICES:
        if m == int(minutes or 0):
            return label
    return "выкл"


def node_sync_due(node: dict, now: datetime | None = None) -> bool:
    """True if enabled node with sync_interval_min > 0 is past due since last_sync."""
    if not node.get("enabled", True):
        return False
    interval = normalize_sync_interval(node.get("sync_interval_min"))
    if interval <= 0:
        return False
    last = (node.get("last_sync") or "").strip()
    if not last:
        return True
    try:
        ts = datetime.fromisoformat(last.replace("Z", "+00:00"))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        now = now or datetime.now(timezone.utc)
        return (now - ts).total_seconds() >= interval * 60
    except Exception:
        return True


def agent_token(store: dict) -> str:
    s = store.setdefault("settings", {}).setdefault("nodes", {})
    if not s.get("agent_token"):
        s["agent_token"] = secrets.token_urlsafe(32)
    s.setdefault("agent_enabled", False)
    s.setdefault("role", "master")  # master | agent
    s.setdefault("agent_manual_off", False)
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


def _agent_safe_clients(clients: list[dict], *, keep_node: bool = False) -> list[dict]:
    """Agent has no master's L2TP ifaces — remap dangling outbound tags to direct."""
    out = []
    for c in clients or []:
        c = dict(c)
        ob = (c.get("outbound") or "direct").strip()
        if ob.startswith("l2tp_") or (ob.startswith("node_") and not keep_node):
            c["outbound"] = "direct"
        out.append(c)
    return out


def _agent_safe_routes(routes: list[dict], *, keep_node: bool = False) -> list[dict]:
    out = []
    for r in routes or []:
        r = dict(r)
        ob = (r.get("outbound") or r.get("outbound_tag") or "direct").strip()
        if ob.startswith("l2tp_") or (ob.startswith("node_") and not keep_node):
            r["outbound"] = "direct"
            r.pop("outbound_tag", None)
        out.append(r)
    return out


def _agent_safe_balancers(balancers: dict, *, keep_node: bool = False) -> dict:
    """Drop explicit L2TP members — agent will use connected local tunnels or [direct]."""
    bals = json.loads(json.dumps(balancers or {}))  # deep copy
    for b in bals.values():
        if not isinstance(b, dict):
            continue
        members = b.get("members") or []
        cleaned = []
        for m in members:
            s = str(m)
            if s.startswith("l2tp_"):
                continue
            if s.startswith("node_") and not keep_node:
                continue
            cleaned.append(m)
        b["members"] = cleaned
    return bals


def _peer_node_export(n: dict) -> dict:
    """Registry fields safe to push to a mirror (no secrets beyond agent token)."""
    keys = (
        "id", "name", "url", "token", "enabled", "sync_clients", "sync_inbounds",
        "as_outbound", "mirror", "domain", "base_path", "ssh_user", "ssh_port",
        "bridge_uuid", "bridge_path", "role", "panel_version",
    )
    return {k: n.get(k) for k in keys if k in n or n.get(k) is not None}


def agent_runtime_store(store: dict) -> dict:
    """Deep copy for live Xray on an agent.

    - runtime_preserve: keep full config (former master just demoted — do not strip L2TP)
    - local l2tp entries present: keep them (this host still has tunnels)
    - mirror: keep peer node_* outbounds
    """
    s = json.loads(json.dumps(store))
    ns = (s.get("settings") or {}).get("nodes") or {}
    if ns.get("runtime_preserve"):
        return s
    has_local_l2tp = bool(s.get("l2tp"))
    keep_node = bool(ns.get("mirror"))
    if not has_local_l2tp:
        s["clients"] = _agent_safe_clients(s.get("clients") or [], keep_node=keep_node)
        s["routes"] = _agent_safe_routes(s.get("routes") or [], keep_node=keep_node)
        s["balancers"] = _agent_safe_balancers(s.get("balancers") or {}, keep_node=keep_node)
        s["l2tp"] = []
    else:
        # Former master / host with tunnels: only remap missing node_* if not mirroring
        s["clients"] = _agent_safe_clients(s.get("clients") or [], keep_node=keep_node)
        s["routes"] = _agent_safe_routes(s.get("routes") or [], keep_node=keep_node)
        s["balancers"] = _agent_safe_balancers(s.get("balancers") or {}, keep_node=True)
        # keep s["l2tp"]
    customs = []
    for o in s.get("outbounds_custom") or []:
        tag = str(o.get("tag") or "")
        if not has_local_l2tp and (tag.startswith("l2tp_") or o.get("kind") == "l2tp"):
            continue
        if not keep_node and (o.get("kind") == "node" or tag.startswith("node_")):
            continue
        customs.append(o)
    s["outbounds_custom"] = customs
    return s


def probe_role(node: dict, timeout: int = 10) -> dict:
    """Read /health from a node; expects role/master fields when panel ≥1.6.2."""
    h = probe_health(node, timeout=timeout)
    if not h.get("ok"):
        return h
    raw = h.get("raw") or {}
    role = str(raw.get("role") or "").strip().lower()
    agent = raw.get("agent")
    return {
        "ok": True,
        "version": h.get("version") or "",
        "role": role,
        "agent": agent,
        "is_master": role == "master" or (role == "" and agent is False),
        "raw": raw,
    }


def build_payload(store: dict, node: dict, build_config) -> dict:
    """Config push for a remote agent. mirror=True → full master copy for fast failover."""
    mirror = bool(node.get("mirror"))
    if mirror:
        node["sync_clients"] = True
        node["sync_inbounds"] = True
    inbounds = list(store.get("inbounds") or [])
    # Ensure bridge inbound exists on agent when used as outbound
    if node.get("as_outbound"):
        ensure_bridge(node)
        inbounds = [i for i in inbounds if i.get("tag") != "node-bridge"]
        inbounds.append(bridge_inbound(node))
    self_tag = node_outbound_tag(node)
    bridge_clients = []
    if node.get("as_outbound"):
        bridge_clients = [{
            "email": f"bridge@{slugify(node.get('name') or 'node')}",
            "uuid": node["bridge_uuid"], "enabled": True, "inbounds": ["node-bridge"],
            "outbound": "direct", "limit_gb": 0, "limit_ip": 0, "limit_hwid": 0,
            "sub_enabled": False, "comment": "node bridge (auto)",
        }]

    if mirror:
        # Full copy: keep outbound tags and all custom/node outbounds (except this node itself)
        clients = list(store.get("clients") or [])
        customs = [o for o in (store.get("outbounds_custom") or []) if o.get("tag") != self_tag]
        routes = list(store.get("routes") or [])
        balancers = json.loads(json.dumps(store.get("balancers") or {}))
        peers = [_peer_node_export(n) for n in ensure_list(store) if n.get("id") != node.get("id")]
    else:
        clients = _agent_safe_clients(store.get("clients") or [])
        customs = []
        for o in store.get("outbounds_custom") or []:
            if o.get("tag") == self_tag or o.get("kind") == "node":
                continue
            customs.append(o)
        routes = _agent_safe_routes(store.get("routes") or [])
        balancers = _agent_safe_balancers(store.get("balancers") or {})
        peers = None

    settings_out = None
    if mirror:
        # Mirror keeps a copy of master settings (DoH/Pi-hole, TG, sub, …) for fast promote
        settings_out = json.loads(json.dumps(store.get("settings") or {}))
        settings_out.pop("nodes", None)

    return {
        "mirror": mirror,
        "clients": (clients if node.get("sync_clients", True) else []) + bridge_clients,
        "inbounds": inbounds if node.get("sync_inbounds", True) or node.get("as_outbound") else [],
        "outbounds_custom": customs,
        "routes": routes,
        "balancers": balancers,
        "dns": store.get("dns") or {},
        "xray_settings": store.get("xray_settings") or {},
        "settings": settings_out,
        "nodes": peers,
        "pushed_at": now_iso(),
        "node_id": node.get("id"),
        "bridge": {
            "uuid": node.get("bridge_uuid"),
            "path": node.get("bridge_path"),
            "enabled": bool(node.get("as_outbound")),
        } if node.get("as_outbound") else None,
    }


def agent_endpoint(node: dict, path: str) -> str:
    """Agent API under the node's secret base_path (nginx only proxies that prefix)."""
    base = (node.get("url") or "").rstrip("/")
    bp = (node.get("base_path") or "").strip().strip("/")
    path = (path or "").lstrip("/")
    if bp:
        return f"{base}/{bp}/{path}"
    return f"{base}/{path}"


def agent_apply_url(node: dict) -> str:
    return agent_endpoint(node, "agent/apply")


def agent_update_url(node: dict) -> str:
    return agent_endpoint(node, "agent/update")


def agent_manage_url(node: dict) -> str:
    return agent_endpoint(node, "agent/manage")


def panel_login_url(node: dict) -> str:
    """Public login URL for a registered node panel."""
    base = (node.get("url") or "").rstrip("/")
    if not base:
        domain = (node.get("domain") or "").strip()
        base = f"https://{domain}" if domain else ""
    if not base:
        return ""
    bp = (node.get("base_path") or "").strip().strip("/")
    return f"{base}/{bp}/login" if bp else f"{base}/login"


def manage_request(node: dict, *, action: str = "", params: dict | None = None, timeout: int = 90) -> dict:
    """Call remote /agent/manage (GET snapshot or POST action). Works on agent and master peers."""
    url = agent_manage_url(node)
    token = node.get("token") or ""
    if not url or not token:
        return {"ok": False, "error": "нет url/token ноды"}
    headers = {
        "Authorization": f"Bearer {token}",
        "User-Agent": "L2XPanel-NodeManage/1.0",
        "Accept": "application/json",
    }
    try:
        if action:
            body = json.dumps({"action": action, **(params or {})}, ensure_ascii=False).encode()
            req = urllib.request.Request(url, data=body, method="POST", headers={
                **headers, "Content-Type": "application/json",
            })
        else:
            req = urllib.request.Request(url, method="GET", headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
            try:
                parsed = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                return {"ok": resp.status < 300, "raw": raw[:800]}
            if isinstance(parsed, dict):
                parsed.setdefault("ok", resp.status < 300)
                return parsed
            return {"ok": True, "data": parsed}
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8", "replace")[:800]
        except Exception:
            pass
        try:
            parsed = json.loads(body) if body else {}
        except json.JSONDecodeError:
            parsed = {}
        err = str(parsed.get("error") or body or f"HTTP {exc.code}")
        if exc.code == 404:
            err = "агент без /agent/manage — обновите панель на ноде"
        return {"ok": False, "error": err, "status": exc.code}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)}


def health_url(node: dict) -> str:
    """Public /health is outside the secret base_path."""
    base = (node.get("url") or "").rstrip("/")
    if base:
        return f"{base}/health"
    domain = (node.get("domain") or "").strip()
    return f"https://{domain}/health" if domain else ""


def probe_health(node: dict, timeout: int = 8) -> dict:
    """Fetch node /health and store panel_version on the registry entry."""
    url = health_url(node)
    if not url:
        return {"ok": False, "error": "no url"}
    req = urllib.request.Request(url, headers={"User-Agent": "L2XPanel-NodeProbe/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
            data = json.loads(body) if body else {}
            ver = str(data.get("version") or "").strip()
            if ver:
                node["panel_version"] = ver
            return {"ok": True, "version": ver, "raw": data}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)}


def trigger_update(node: dict, timeout: int = 45) -> dict:
    """Ask the remote agent to run panel self-update (returns after job is queued)."""
    url = agent_update_url(node)
    token = node.get("token") or ""
    data = json.dumps({"confirm": "yes"}).encode()
    req = urllib.request.Request(url, data=data, method="POST", headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
        "User-Agent": "L2XPanel-NodeUpdate/1.0",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
            try:
                parsed = json.loads(body)
            except json.JSONDecodeError:
                parsed = {"ok": resp.status < 300, "raw": body[:500]}
            ok = bool(parsed.get("ok", resp.status < 300))
            if parsed.get("current"):
                node["panel_version"] = str(parsed["current"])
            node["last_update"] = now_iso()
            if not ok:
                node["last_error"] = str(parsed.get("error") or body[:300])
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
        err = str(parsed.get("error") or body or f"HTTP {exc.code}")
        if exc.code == 404:
            err = "агент без /agent/update — укажите SSH-пароль или обновите ноду вручную"
        node["last_error"] = err
        return {"ok": False, "error": err}
    except Exception as exc:  # noqa: BLE001
        node["last_error"] = str(exc)
        return {"ok": False, "error": str(exc)}


def update_via_ssh(node: dict, ssh_password: str, ssh_user: str = "", ssh_port: int = 0) -> dict:
    """Run panel update on the node over SSH (works even if agent endpoint is missing)."""
    host = (node.get("domain") or "").strip()
    if not host:
        from urllib.parse import urlparse
        host = urlparse(node.get("url") or "").hostname or ""
    if not host:
        return {"ok": False, "error": "нет domain/url ноды", "log": ""}
    user = (ssh_user or node.get("ssh_user") or "root").strip() or "root"
    port = int(ssh_port or node.get("ssh_port") or 22)
    log: list[str] = [f"ssh {user}@{host}:{port} update"]
    client = None
    try:
        client = _ssh_connect(host, user, ssh_password, port=port, timeout=45)
        cmd = (
            "set -e; "
            "if [ -x /usr/local/bin/l2x ]; then /usr/local/bin/l2x update; "
            "else curl -fsSL https://raw.githubusercontent.com/eliot-voodi/l2x-panel/main/install.sh "
            "| bash -s -- --update; fi; "
            "sleep 2; curl -sS http://127.0.0.1:8090/health || true"
        )
        r = _ssh_run(client, cmd, timeout=900)
        log.append((r.get("stdout") or "")[-2500:])
        if r.get("stderr"):
            log.append((r.get("stderr") or "")[-800:])
        # parse version from health json in stdout
        ver = ""
        out = r.get("stdout") or ""
        for line in reversed(out.splitlines()):
            line = line.strip()
            if line.startswith("{") and "version" in line:
                try:
                    ver = str(json.loads(line).get("version") or "")
                except json.JSONDecodeError:
                    ver = ""
                if ver:
                    break
        if ver:
            node["panel_version"] = ver
        node["last_update"] = now_iso()
        ok = bool(r.get("ok"))
        if not ok:
            node["last_error"] = (r.get("stderr") or "ssh update failed")[:400]
        else:
            node["last_error"] = ""
            node["last_ok"] = True
        return {"ok": ok, "log": "\n".join(log), "version": ver,
                "error": "" if ok else (r.get("stderr") or "update failed")}
    except Exception as exc:  # noqa: BLE001
        node["last_error"] = str(exc)
        return {"ok": False, "error": str(exc), "log": "\n".join(log)}
    finally:
        if client:
            try:
                client.close()
            except Exception:
                pass


def _push_once(node: dict, payload: dict, timeout: int = 60) -> dict:
    """Single POST /agent/apply attempt."""
    url = agent_apply_url(node)
    token = node.get("token") or ""
    data = json.dumps(payload, ensure_ascii=False).encode()
    req = urllib.request.Request(url, data=data, method="POST", headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
        "User-Agent": "L2XPanel-NodeSync/1.0",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode()
            try:
                parsed = json.loads(body)
            except json.JSONDecodeError:
                parsed = {"ok": resp.status < 300, "raw": body[:500]}
            ok = bool(parsed.get("ok", resp.status < 300))
            err = "" if ok else str(parsed.get("error") or body[:300])
            try:
                from xray_runtime import clean_xray_error
                err = clean_xray_error(err) or err
            except Exception:
                pass
            if isinstance(parsed, dict) and err:
                parsed = {**parsed, "error": err}
            return parsed if isinstance(parsed, dict) else {"ok": ok, "error": err}
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
        if not (exc.code == 403 and "agent" in err.lower()):
            if body and "error" in (parsed or {}):
                err = str(parsed.get("error"))
            else:
                err = f"HTTP {exc.code}: {err}"
        return {"ok": False, "error": err, "status": exc.code}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)}


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
    result = _push_once(node, payload, timeout=timeout)
    # Auto-heal: agent was turned off by update/restart — re-enable via manage API and retry once.
    # Respects remote agent_manual_off (admin unchecked Settings → Nodes).
    err = str(result.get("error") or "")
    if not result.get("ok") and "agent disabled" in err.lower():
        heal = manage_request(node, action="enable_agent", timeout=30)
        if heal.get("ok"):
            result = _push_once(node, payload, timeout=timeout)
            if result.get("ok"):
                err = ""
            else:
                err = str(result.get("error") or err)
        elif heal.get("manual_off"):
            err = "agent выключен вручную на ноде"
            result = {"ok": False, "error": err, "manual_off": True}
        else:
            # Old panel without enable_agent: fall back to manage update_panel path is N/A;
            # surface a clear error so admin can Update (manage) or SSH.
            err = f"agent disabled (auto-enable: {heal.get('error') or 'fail'})"
            result = {"ok": False, "error": err}
    node["last_sync"] = now_iso()
    node["last_ok"] = bool(result.get("ok"))
    node["last_error"] = "" if result.get("ok") else err
    warns = result.get("warnings") or []
    if isinstance(warns, str):
        warns = [warns]
    node["last_warning"] = "; ".join(str(w) for w in warns if w)[:600]
    # Also surface as soft warning when sync ok but Pi-hole missing
    if result.get("ok") and node["last_warning"] and not node["last_error"]:
        pass  # keep last_ok True — warning only
    if result.get("ok"):
        try:
            probe_health(node, timeout=5)
        except Exception:
            pass
    return result


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
    mirror: bool = False,
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
    mirror = bool(mirror)
    if mirror:
        as_outbound = True
    node = {
        "id": node_id, "name": name, "domain": domain, "ssh_user": ssh_user, "ssh_port": int(ssh_port or 22),
        "token": agent_tok, "enabled": True, "sync_clients": True, "sync_inbounds": True,
        "as_outbound": bool(as_outbound), "mirror": mirror, "base_path": panel_path, "role": "agent",
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
ns["agent_manual_off"] = False
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


def _remap_outbound_tag(value: str, drop_tags: set[str]) -> str:
    v = (value or "direct").strip() or "direct"
    return "direct" if v in drop_tags else v


def _remap_clients_drop_tags(clients: list[dict], drop_tags: set[str]) -> list[dict]:
    out = []
    for c in clients or []:
        c = dict(c)
        c["outbound"] = _remap_outbound_tag(c.get("outbound") or "direct", drop_tags)
        out.append(c)
    return out


def _remap_routes_drop_tags(routes: list[dict], drop_tags: set[str]) -> list[dict]:
    out = []
    for r in routes or []:
        r = dict(r)
        if "outbound" in r or "outbound_tag" in r:
            tag = r.get("outbound") or r.get("outbound_tag") or "direct"
            r["outbound"] = _remap_outbound_tag(str(tag), drop_tags)
            r.pop("outbound_tag", None)
        out.append(r)
    return out


def _remap_balancers_drop_tags(balancers: dict, drop_tags: set[str]) -> dict:
    bals = json.loads(json.dumps(balancers or {}))
    for b in bals.values():
        if not isinstance(b, dict):
            continue
        members = []
        for m in b.get("members") or []:
            if str(m) in drop_tags:
                continue
            members.append(m)
        b["members"] = members or ["direct"]
    return bals


def _remap_inbounds_drop_tags(inbounds: list[dict], drop_tags: set[str]) -> list[dict]:
    out = []
    for ib in inbounds or []:
        ib = dict(ib)
        if ib.get("outbound"):
            ib["outbound"] = _remap_outbound_tag(str(ib.get("outbound")), drop_tags)
        out.append(ib)
    return out


def promote_l2tp_entries(store: dict) -> list[dict]:
    """Copy L2TP tunnel configs for the new master (disconnected — ifaces are host-local)."""
    out = []
    for t in store.get("l2tp") or []:
        item = json.loads(json.dumps(t))
        item["status"] = "disconnected"
        item["last_error"] = ""
        for k in ("ifname", "addr", "local_ip", "peer_ip", "public_ip", "vrf"):
            item[k] = ""
        item.pop("metrics", None)
        out.append(item)
    return out


def promote_snapshot(store: dict, target_node: dict, *, l2tp_secrets: dict | None = None) -> dict:
    """Full master copy for the new master.

    Transfers all outbounds/clients/routes/L2TP/settings (incl. DoH)/certs/Pi-hole files
    except the outbound that pointed at the target node itself (node_<slug>) — that tag
    is removed and every reference to it is rewritten to ``direct``. L2TP tunnels arrive
    disconnected; secrets are passed plaintext in ``l2tp_secrets`` so the new host can
    re-encrypt with its key.
    """
    import ops as ops_mod

    drop = {node_outbound_tag(target_node)}
    # Also drop by node_id match (tag may have been renamed)
    tid = target_node.get("id")
    customs = []
    for o in store.get("outbounds_custom") or []:
        tag = str(o.get("tag") or "")
        if tag in drop or (tid and o.get("node_id") == tid):
            if tag:
                drop.add(tag)
            continue
        customs.append(json.loads(json.dumps(o)))  # deep copy
    l2tp = promote_l2tp_entries(store)
    secrets = {}
    for name, sec in (l2tp_secrets or {}).items():
        if not name or not isinstance(sec, dict):
            continue
        secrets[str(name)] = {
            "password": str(sec.get("password") or ""),
            "psk": str(sec.get("psk") or ""),
        }
    settings = json.loads(json.dumps(store.get("settings") or {}))
    # Receiving node will force role=master; don't ship old agent flags as truth
    settings.pop("nodes", None)
    certs = ops_mod.export_certs_bundle()
    doh_bundle = ops_mod.export_doh_bundle()
    return {
        "clients": _remap_clients_drop_tags(store.get("clients") or [], drop),
        "inbounds": _remap_inbounds_drop_tags(store.get("inbounds") or [], drop),
        "routes": _remap_routes_drop_tags(store.get("routes") or [], drop),
        "balancers": _remap_balancers_drop_tags(store.get("balancers") or {}, drop),
        "outbounds_custom": customs,
        "dns": json.loads(json.dumps(store.get("dns") or {})),
        "xray_settings": json.loads(json.dumps(store.get("xray_settings") or {})),
        "settings": settings,
        "ip_bans": json.loads(json.dumps(store.get("ip_bans") or [])),
        "l2tp": l2tp,
        "l2tp_secrets": secrets,
        "certs": certs,
        "doh_bundle": doh_bundle,
        "drop_outbound_tags": sorted(drop),
        "transferred_custom": len(customs),
        "transferred_l2tp": len(l2tp),
        "transferred_certs": len(certs),
        "transferred_doh_files": len(doh_bundle),
    }


def slim_assets_for_api(snap: dict, *, max_total_b64: int = 1_500_000) -> dict:
    """Shrink certs/doh for HTTP promote — full trees go via SSH; API keeps essentials.

    Keeps all TLS certs that fit the budget, and DoH ``docker-compose.yml`` / ``.env``
    (plus other small files). Large gravity DB / lists are skipped so nginx/proxy
    timeouts and body limits do not turn promote into a bare 500.
    """
    out = json.loads(json.dumps(snap))
    total = 0
    certs: list[dict] = []
    for it in out.get("certs") or []:
        if not isinstance(it, dict):
            continue
        sz = len(it.get("data_b64") or "")
        if total + sz > max_total_b64:
            out["certs_truncated"] = True
            break
        certs.append(it)
        total += sz
    out["certs"] = certs
    out["transferred_certs"] = len(certs)

    essential = {"docker-compose.yml", ".env"}
    doh: list[dict] = []
    skipped = 0
    for it in out.get("doh_bundle") or []:
        if not isinstance(it, dict):
            continue
        rel = str(it.get("rel") or "").replace("\\", "/").lstrip("./")
        sz = len(it.get("data_b64") or "")
        keep = rel in essential or (sz < 80_000 and not rel.endswith(".db") and "/gravity" not in rel)
        if not keep:
            skipped += 1
            continue
        if total + sz > max_total_b64 and rel not in essential:
            skipped += 1
            out["doh_truncated"] = True
            continue
        doh.append(it)
        total += sz
    out["doh_bundle"] = doh
    out["transferred_doh_files"] = len(doh)
    out["doh_files_skipped"] = skipped
    out["assets_slimmed"] = True
    return out


def promote_payload(master_store_snapshot: dict, old_master_node: dict, extra_nodes: list[dict] | None = None,
                    *, for_api: bool = False) -> dict:
    """Body for /agent/promote — final snapshot + old master as a peer node."""
    peers = list(extra_nodes or [])
    peers = [n for n in peers if n.get("id") != old_master_node.get("id")]
    peers.insert(0, old_master_node)
    snap = master_store_snapshot
    if for_api:
        snap = slim_assets_for_api(snap)
    return {
        "confirm": "yes",
        "clients": snap.get("clients") or [],
        "inbounds": snap.get("inbounds") or [],
        "routes": snap.get("routes") or [],
        "balancers": snap.get("balancers") or {},
        "outbounds_custom": snap.get("outbounds_custom") or [],
        "l2tp": snap.get("l2tp") or [],
        "l2tp_secrets": snap.get("l2tp_secrets") or {},
        "dns": snap.get("dns") or {},
        "xray_settings": snap.get("xray_settings") or {},
        "settings": snap.get("settings") or {},
        "ip_bans": snap.get("ip_bans") or [],
        "certs": snap.get("certs") or [],
        "doh_bundle": snap.get("doh_bundle") or [],
        "assets_slimmed": bool(snap.get("assets_slimmed")),
        "doh_files_skipped": int(snap.get("doh_files_skipped") or 0),
        "nodes": peers,
        "old_master": old_master_node,
    }


def apply_promoted_settings(store: dict, incoming: dict | None) -> None:
    """Merge master settings onto the new master; keep local panel host/base_path."""
    if not isinstance(incoming, dict) or not incoming:
        return
    local = store.setdefault("settings", {})
    local_panel = dict(local.get("panel") or {})
    keep_bp = local_panel.get("base_path")
    keep_host = local_panel.get("public_host")
    merged = json.loads(json.dumps(incoming))
    merged.pop("nodes", None)  # role forced by caller
    # Deep-ish replace of known sections
    for key, val in merged.items():
        if isinstance(val, dict) and isinstance(local.get(key), dict):
            local[key] = {**local.get(key, {}), **val}
        else:
            local[key] = val
    panel = local.setdefault("panel", {})
    if keep_bp:
        panel["base_path"] = keep_bp
    if keep_host:
        panel["public_host"] = keep_host


def promote_via_api(node: dict, payload: dict, timeout: int = 180) -> dict:
    """Promote a mirrored agent to master over HTTP (no SSH). Uses already-synced store + final delta."""
    url = agent_endpoint(node, "agent/promote")
    token = node.get("token") or ""
    data = json.dumps(payload, ensure_ascii=False).encode()
    req = urllib.request.Request(url, data=data, method="POST", headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
        "User-Agent": "L2XPanel-NodePromote/1.0",
        "Content-Length": str(len(data)),
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
            try:
                parsed = json.loads(body)
            except json.JSONDecodeError:
                parsed = {"ok": resp.status < 300, "raw": body[:500]}
            ok = bool(parsed.get("ok", resp.status < 300))
            return parsed if isinstance(parsed, dict) else {"ok": ok, "log": body[:500]}
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8", "replace")[:800]
        except Exception:
            pass
        try:
            parsed = json.loads(body) if body else {}
        except json.JSONDecodeError:
            parsed = {}
        err = str(parsed.get("error") or "")
        if not err:
            low = body.lower()
            if "413" in str(exc.code) or "request entity too large" in low:
                err = f"HTTP {exc.code}: тело promote слишком большое — повторите с SSH-паролем или обновите ноду"
            elif "504" in str(exc.code) or "timeout" in low or "gateway" in low:
                err = f"HTTP {exc.code}: таймаут на ноде (Pi-hole/docker) — обновите панель на ноде и повторите"
            elif "internal server error" in low:
                err = (
                    f"HTTP {exc.code}: Internal Server Error на ноде — "
                    "обычно старая панель / таймаут docker при импорте DoH. "
                    "Обновите ноду и повторите promote (или укажите SSH)."
                )
            else:
                err = f"HTTP {exc.code}: {(body or '')[:300]}"
        if exc.code == 404:
            err = "агент без /agent/promote — обновите ноду или укажите SSH-пароль"
        return {"ok": False, "error": err, "log": body, "status": exc.code}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc), "log": ""}


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
        # Merge snapshot into remote store (clients/inbounds/routes/balancers/l2tp/settings/certs/doh/nodes)
        snap = {
            "clients": master_store_snapshot.get("clients") or [],
            "inbounds": master_store_snapshot.get("inbounds") or [],
            "routes": master_store_snapshot.get("routes") or [],
            "balancers": master_store_snapshot.get("balancers") or {},
            "outbounds_custom": master_store_snapshot.get("outbounds_custom") or [],
            "dns": master_store_snapshot.get("dns") or {},
            "xray_settings": master_store_snapshot.get("xray_settings") or {},
            "settings": master_store_snapshot.get("settings") or {},
            "ip_bans": master_store_snapshot.get("ip_bans") or [],
            "certs": master_store_snapshot.get("certs") or [],
            "doh_bundle": master_store_snapshot.get("doh_bundle") or [],
            "l2tp": master_store_snapshot.get("l2tp") or [],
            "l2tp_secrets": master_store_snapshot.get("l2tp_secrets") or {},
            "nodes": [old_master_node],
        }
        sftp = client.open_sftp()
        with sftp.file("/tmp/l2x_promote.json", "w") as f:
            f.write(json.dumps(snap, ensure_ascii=False))
        promote_py = """
import base64, hashlib, json, os, subprocess
from pathlib import Path
from cryptography.fernet import Fernet
snap = json.loads(Path('/tmp/l2x_promote.json').read_text())
store_path = Path('/var/lib/l2xpanel/store.json')
store = json.loads(store_path.read_text()) if store_path.exists() else {}
local_panel = dict((store.get('settings') or {}).get('panel') or {})
keep_bp = local_panel.get('base_path')
keep_host = local_panel.get('public_host')
for k in ('clients','inbounds','routes','balancers','outbounds_custom','dns','xray_settings','nodes','l2tp','ip_bans'):
    if k in snap:
        store[k] = snap[k]
incoming = snap.get('settings') or {}
if isinstance(incoming, dict) and incoming:
    cur = store.setdefault('settings', {})
    for key, val in incoming.items():
        if key == 'nodes':
            continue
        if isinstance(val, dict) and isinstance(cur.get(key), dict):
            cur[key] = {**cur.get(key, {}), **val}
        else:
            cur[key] = val
    panel = cur.setdefault('panel', {})
    if keep_bp:
        panel['base_path'] = keep_bp
    if keep_host:
        panel['public_host'] = keep_host
ns = store.setdefault('settings', {}).setdefault('nodes', {})
ns['agent_enabled'] = False
ns['role'] = 'master'
ns['mirror'] = False
ns['runtime_preserve'] = False
tmp = store_path.with_suffix('.tmp')
tmp.write_text(json.dumps(store, ensure_ascii=False, indent=2))
tmp.replace(store_path)
secrets = snap.get('l2tp_secrets') or {}
if secrets:
    sk = (os.environ.get('SECRET_KEY') or '').strip()
    if not sk:
        for _p in (Path('/var/lib/l2xpanel/secret_key'), Path('/opt/l2xpanel/data/secret_key')):
            if _p.exists():
                sk = _p.read_text(encoding='utf-8').strip()
                if sk:
                    break
    if not sk:
        raise SystemExit('SECRET_KEY missing for l2tp_secrets')
    f = Fernet(base64.urlsafe_b64encode(hashlib.sha256(sk.encode()).digest()))
    d = Path('/var/lib/l2xpanel/l2tp_secrets')
    d.mkdir(parents=True, exist_ok=True)
    for name, sec in secrets.items():
        if not isinstance(sec, dict):
            continue
        payload = {
            'password': f.encrypt((sec.get('password') or '').encode()).decode() if sec.get('password') else '',
            'psk': f.encrypt((sec.get('psk') or '').encode()).decode() if sec.get('psk') else '',
        }
        p = d / f'{name}.json'
        p.write_text(json.dumps(payload))
        os.chmod(p, 0o600)
# TLS certs
cert_dir = Path(os.environ.get('L2XPANEL_CERT_DIR', '/etc/l2xpanel/certs'))
n_certs = 0
for it in snap.get('certs') or []:
    if not isinstance(it, dict):
        continue
    rel = str(it.get('rel') or '').replace('\\\\', '/')
    if not rel or rel.startswith('/') or '..' in rel.split('/'):
        continue
    try:
        raw = base64.b64decode(it.get('data_b64') or '')
    except Exception:
        continue
    target = cert_dir / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(raw)
    if rel.endswith('.key'):
        try: os.chmod(target, 0o600)
        except OSError: pass
    n_certs += 1
# DoH / Pi-hole files
doh_dir = Path(os.environ.get('L2XPANEL_DOH_DIR', '/opt/l2xpanel/doh'))
n_doh = 0
for it in snap.get('doh_bundle') or []:
    if not isinstance(it, dict):
        continue
    rel = str(it.get('rel') or '').replace('\\\\', '/')
    if not rel or rel.startswith('/') or '..' in rel.split('/'):
        continue
    try:
        raw = base64.b64decode(it.get('data_b64') or '')
    except Exception:
        continue
    target = doh_dir / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(raw)
    if rel.endswith('.env'):
        try: os.chmod(target, 0o600)
        except OSError: pass
    n_doh += 1
if n_doh and (doh_dir / 'docker-compose.yml').is_file():
    for cmd in (
        ['docker', 'compose', '-f', str(doh_dir / 'docker-compose.yml'), 'up', '-d', '--force-recreate'],
        ['docker-compose', '-f', str(doh_dir / 'docker-compose.yml'), 'up', '-d', '--force-recreate'],
    ):
        try:
            r = subprocess.run(cmd, cwd=str(doh_dir), capture_output=True, text=True, timeout=180)
            if r.returncode == 0:
                break
        except Exception:
            pass
print('promoted', 'l2tp', len(store.get('l2tp') or []), 'custom', len(store.get('outbounds_custom') or []),
      'certs', n_certs, 'doh_files', n_doh, 'doh_enabled', bool((store.get('settings') or {}).get('doh', {}).get('enabled')))
"""
        with sftp.file("/tmp/l2x_promote.py", "w") as f:
            f.write(promote_py)
        sftp.close()
        r = _ssh_run(
            client,
            "set -a; . /etc/l2xpanel/panel.env; set +a; "
            "cd /opt/l2xpanel; .venv/bin/python /tmp/l2x_promote.py; "
            "systemctl restart l2xpanel; "
            "for i in 1 2 3 4 5 6 7 8 9 10; do sleep 1; "
            "  curl -sf http://127.0.0.1:8090/health >/dev/null && break; done; "
            "curl -s http://127.0.0.1:8090/health; echo; "
            "rm -f /tmp/l2x_promote.py /tmp/l2x_promote.json",
            timeout=300,
        )
        log.append(r["stdout"][-800:])
        out = r.get("stdout") or ""
        health_ok = '"status"' in out and "ok" in out
        ok = bool(r.get("ok")) and "promoted" in out and health_ok
        return {"ok": ok, "log": "\n".join(log), "error": "" if ok else (r.get("stderr") or "promote failed")}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc), "log": "\n".join(log)}
    finally:
        try:
            client.close()
        except Exception:
            pass
