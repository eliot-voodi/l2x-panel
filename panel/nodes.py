"""Multi-node registry: SSH provision, sync, promote-to-master, node as outbound."""
from __future__ import annotations

import json
import re
import secrets
import time
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
        n.setdefault("ssh_hostkey_fp", "")
        n.setdefault("bridge_uuid", "")
        n.setdefault("bridge_path", "")
        n.setdefault("base_path", "")
        n.setdefault("last_sync", "")
        n.setdefault("last_error", "")
        n.setdefault("last_ok", False)
        n.setdefault("panel_version", "")
        n.setdefault("xray_version", "")
        n.setdefault("xray_active", None)
        n.setdefault("xray_latest", "")
        n.setdefault("xray_available", False)
        n.setdefault("xray_checked_at", "")
        n.setdefault("last_update", "")
        # Auto-sync interval in minutes; 0 = disabled
        n.setdefault("sync_interval_min", 0)
        n.setdefault("role", "agent")  # on master registry entries are always agents
        # Reachability (master health probes) — online is None until first probe baseline
        n.setdefault("online", None)
        n.setdefault("fail_streak", 0)
        n.setdefault("last_seen", "")
        n.setdefault("last_probe", "")
        n.setdefault("last_probe_error", "")
        # NAT node: no inbound ports; node dials master (reverse tunnel + config pull)
        n.setdefault("nat", False)
        # Reverse outbound on a reachable node: node dials master instead of master → node
        n.setdefault("rv_mode", False)
        n.setdefault("last_pull", "")
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


def uses_reverse(node: dict) -> bool:
    """Master egress via this node goes through the VLESS reverse tunnel (node dials master)."""
    return bool(node.get("nat") or node.get("rv_mode"))


def ensure_bridge(node: dict) -> dict:
    """Allocate VLESS/WS bridge credentials used so the master can egress via this node."""
    if not node.get("bridge_uuid"):
        node["bridge_uuid"] = str(uuid.uuid4())
    if not node.get("bridge_path"):
        node["bridge_path"] = "/nb-" + secrets.token_urlsafe(8).replace("_", "").replace("-", "")[:12]
    return node


REVERSE_PORT_BASE = 19100
# NAT node is online while it keeps pulling (agent pulls every ~20s)
PULL_FRESH_SEC = 120


def _ws_like_path() -> str:
    """Same shape as user WS inbounds (/ws-xxxxxxxxxx) — tunnel path is indistinguishable."""
    alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "/ws-" + "".join(secrets.choice(alphabet) for _ in range(10))


def _xh_like_path() -> str:
    """Same shape as user XHTTP inbounds (/xh-xxxxxxxxxx)."""
    alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "/xh-" + "".join(secrets.choice(alphabet) for _ in range(10))


# Parallel reverse dials from each NAT agent (same UUID / reverse.tag → load pool)
REVERSE_DIALS_DEFAULT = 4
REVERSE_DIALS_MAX = 16


def ensure_reverse_master(store: dict) -> dict:
    """Master-wide reverse inbound (XHTTP stream-up behind nginx :443)."""
    ns = store.setdefault("settings", {}).setdefault("nodes", {})
    rv = ns.setdefault("rv", {})
    # Prefer XHTTP over legacy WS for throughput (multi-conn + no WS overhead)
    if rv.get("network") != "xhttp":
        rv["network"] = "xhttp"
        if not rv.get("path") or str(rv.get("path") or "").startswith("/ws-"):
            rv["path"] = _xh_like_path()
    if not rv.get("path"):
        rv["path"] = _xh_like_path()
    dials = int(rv.get("dials") or REVERSE_DIALS_DEFAULT)
    rv["dials"] = max(1, min(REVERSE_DIALS_MAX, dials))
    used = {
        int(i.get("port") or 0) for i in store.get("inbounds") or []
        if i.get("tag") != "rv-in"
    }
    port = int(rv.get("port") or 0)
    if not port or port in used:
        port = REVERSE_PORT_BASE
        while port in used:
            port += 1
        rv["port"] = port
    return rv


def ensure_reverse(node: dict) -> dict:
    """Per-node reverse credentials (VLESS user on master rv inbound + portal domain)."""
    if not node.get("rv_uuid"):
        node["rv_uuid"] = str(uuid.uuid4())
    if not node.get("rv_domain"):
        # Only inside the encrypted mux control stream — never seen on the wire
        node["rv_domain"] = f"{secrets.token_hex(6)}.rv.l2x.internal"
    node["rv_tag"] = node_outbound_tag(node)
    return node


def pull_fresh(node: dict, now: datetime | None = None) -> bool:
    last = (node.get("last_pull") or "").strip()
    if not last:
        return False
    try:
        ts = datetime.fromisoformat(last.replace("Z", "+00:00"))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        now = now or datetime.now(timezone.utc)
        return (now - ts).total_seconds() <= PULL_FRESH_SEC
    except Exception:
        return False


def payload_version(payload: dict) -> str:
    import hashlib
    body = {k: v for k, v in (payload or {}).items() if k != "pushed_at"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False, default=str).encode()).hexdigest()[:24]


def version_tuple(v: str) -> tuple[int, ...]:
    out = []
    for part in str(v or "").strip().lstrip("v").split("."):
        digits = "".join(ch for ch in part if ch.isdigit())
        out.append(int(digits) if digits else 0)
    return tuple(out)


def apply_pull_seen(
    node: dict, *, version: str = "", status: dict | None = None, master_version: str = "",
) -> list[dict]:
    """Master side: NAT node checked in → online + last apply status from the agent."""
    node["last_pull"] = now_iso()
    events = apply_health_probe(node, {"ok": True, "version": version})
    st = status if isinstance(status, dict) else {}
    warns: list[str] = []
    if st:
        node["last_ok"] = bool(st.get("ok"))
        node["last_error"] = "" if st.get("ok") else str(st.get("error") or "")[:400]
        raw = st.get("warnings") or []
        warns = [raw] if isinstance(raw, str) else [str(w) for w in raw if w]
    if version and master_version and version_tuple(version) < version_tuple(master_version):
        warns.insert(0, (
            f"Нода на v{version}, мастер v{master_version} — обновление через agent pull"
        ))
    if node.get("update_requested"):
        warns.insert(0, "Обновление поставлено в очередь (agent pull ≤20 с)")
    if node.get("xray_update_requested"):
        warns.insert(0, f"Xray {node.get('xray_update_requested')}: в очереди agent pull")
    xv = str(st.get("xray_version") or "").strip()
    if xv:
        node["xray_version"] = xv.lstrip("vV")
    if "xray_active" in st:
        node["xray_active"] = bool(st.get("xray_active"))
    if st.get("reverse_ok") is False and uses_reverse(node) and node.get("as_outbound"):
        warns.append("NAT reverse на ноде не поднят (нет rv-up/rv-direct)")
    elif st.get("reverse_ok") is True:
        node["reverse_ok"] = True
    if isinstance(st.get("rv_conns"), int):
        node["rv_conns"] = st["rv_conns"]
    node["last_warning"] = "; ".join(warns)[:600]
    return events


def pull_wants_update(node: dict, agent_version: str, master_version: str) -> bool:
    """NAT agent should self-update via pull: manual queue, or while behind master."""
    manual = bool(node.pop("update_requested", None))
    if not agent_version or not master_version:
        return manual
    if version_tuple(agent_version) < version_tuple(master_version):
        return True
    return manual


def pull_request(master_url: str, token: str, body: dict, timeout: int = 30) -> dict:
    """Agent side: POST /agent/pull on master (plain HTTPS, outbound only)."""
    url = master_url.rstrip("/") + "/agent/pull"
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method="POST", headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", "replace") or "{}")
    except urllib.error.HTTPError as exc:
        try:
            parsed = json.loads(exc.read().decode("utf-8", "replace") or "{}")
        except Exception:
            parsed = {}
        if not isinstance(parsed, dict):
            parsed = {}
        detail = parsed.get("error") or ""
        return {**parsed, "ok": False, "status": exc.code, "error": f"HTTP {exc.code} {detail}".strip()}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)}


def node_pull_base(node: dict) -> str:
    """https://host/base_path — what a NAT agent uses as master_url when this node is master."""
    base = (node.get("url") or "").rstrip("/")
    if not base:
        dom = _normalize_domain(node.get("domain") or "")
        base = f"https://{dom}" if dom else ""
    if not base:
        return ""
    bp = (node.get("base_path") or "").strip().strip("/")
    return f"{base}/{bp}" if bp else base


def master_candidates(store: dict, *, self_url: str = "", exclude_id: str = "") -> list[str]:
    """Pull URLs a NAT agent may fail over to: this master first, then mirror peers."""
    out: list[str] = []
    if self_url:
        out.append(self_url.rstrip("/"))
    for n in ensure_list(store):
        if n.get("id") == exclude_id or n.get("nat") or not n.get("enabled", True):
            continue
        if not n.get("mirror"):
            continue
        u = node_pull_base(n)
        if u and u not in out:
            out.append(u)
    return out


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
                    "fingerprint": "firefox", "min_version": "1.2", "allow_insecure": False,
                    "reject_unknown_sni": False, "ech_server_keys": ""},
            "reality": {"dest": "ya.ru:443", "server_names": ["ya.ru"], "private_key": "", "public_key": "",
                        "short_ids": [], "fingerprint": "firefox", "spider_x": "/", "show": False, "xver": 0},
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
            "tlsSettings": {"serverName": domain, "allowInsecure": False, "fingerprint": "firefox",
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
    if uses_reverse(node):
        # Portal tag on master = outbound; master never dials the node
        ensure_reverse_master(store)
        ensure_reverse(node)
        entry = {
            "tag": tag,
            "remark": f"{node.get('name')} ({'NAT' if node.get('nat') else 'reverse'})",
            "kind": "node",
            "reverse": True,
            "node_id": node.get("id"),
            "enabled": True,
            "in_sub": True,
            "country": (node.get("country") or "")[:2].upper(),
            "config": {},
        }
        if existing:
            keep = existing.get("last_test")
            existing.clear()
            existing.update(entry)
            if keep:
                existing["last_test"] = keep
        else:
            customs.append(entry)
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
        "remark": str(node.get("name") or tag),
        "kind": "node",
        "node_id": node.get("id"),
        "enabled": True,
        "in_sub": True,
        "country": (node.get("country") or "")[:2].upper(),
        "config": node_outbound_config(node),
    }
    if existing:
        existing.pop("reverse", None)
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
        "ssh_hostkey_fp", "bridge_uuid", "bridge_path", "role", "panel_version", "nat", "rv_mode",
        "rv_uuid", "rv_domain", "rv_tag",
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
    nat = bool(node.get("nat"))
    rv_on = uses_reverse(node)
    if mirror:
        node["sync_clients"] = True
        node["sync_inbounds"] = True
    # NAT node: no inbound ports → no client inbounds / bridge inbound; only reverse egress.
    # Reverse mode: the node dials master, so the bridge inbound is not needed either.
    bridge_on = bool(node.get("as_outbound")) and not rv_on
    inbounds = list(store.get("inbounds") or []) if not nat else []
    # Path/TLS share domains must be the node hostname, not the master
    node_dom = node_public_domain(node)
    if inbounds and node_dom and (node.get("sync_inbounds", True) or mirror or bridge_on):
        inbounds = remap_inbounds_for_host(
            inbounds,
            new_host=node_dom,
            old_hosts=master_public_domains(store),
        )
    # Ensure bridge inbound exists on agent when used as outbound
    if bridge_on:
        ensure_bridge(node)
        inbounds = [i for i in inbounds if i.get("tag") != "node-bridge"]
        inbounds.append(bridge_inbound(node))
    self_tag = node_outbound_tag(node)
    bridge_clients = []
    if bridge_on:
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

    reverse_bridge = None
    if rv_on and node.get("as_outbound") and node.get("enabled", True):
        rv = ensure_reverse_master(store)
        ensure_reverse(node)
        master_host = ""
        try:
            import front as front_mod
            master_host = _normalize_domain(front_mod.public_domain(store) or "")
        except Exception:
            pass
        if not master_host:
            master_host = next(iter(sorted(master_public_domains(store))), "")
        if master_host:
            reverse_bridge = {
                "master_host": master_host,
                "port": 443,
                "path": rv["path"],
                "uuid": node["rv_uuid"],
                "domain": node["rv_domain"],
                "fingerprint": "chrome",
                "network": rv.get("network") or "xhttp",
                "mode": "stream-up",
                "dials": int(rv.get("dials") or REVERSE_DIALS_DEFAULT),
            }

    out = {
        "mirror": mirror,
        "nat": nat,
        "clients": (clients if node.get("sync_clients", True) and not nat else []) + bridge_clients,
        "inbounds": inbounds if node.get("sync_inbounds", True) or bridge_on else [],
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
    # Include reverse_bridge only when we have a full bridge, or when reverse is off
    # (explicit null clears it). If rv_on but build failed, omit the key so the agent
    # keeps its working reverse_bridge instead of wiping it mid-sync.
    if reverse_bridge:
        out["reverse_bridge"] = reverse_bridge
    elif not rv_on:
        out["reverse_bridge"] = None
    return out


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
    """Fetch node /health (does not mutate reachability fields — use apply_health_probe).

    Sends Bearer agent token when known so the node returns detail fields
    (version/role/xray). Without a token only ``status=ok`` is public.
    """
    url = health_url(node)
    if not url:
        return {"ok": False, "error": "no url"}
    headers = {"User-Agent": "L2XPanel-NodeProbe/1.0"}
    token = str(node.get("token") or "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
            data = json.loads(body) if body else {}
            ver = str(data.get("version") or "").strip()
            if ver:
                node["panel_version"] = ver
            xv = str(data.get("xray_version") or "").strip()
            if xv:
                node["xray_version"] = xv.lstrip("vV")
            if "xray_active" in data:
                node["xray_active"] = bool(data.get("xray_active"))
            return {"ok": True, "version": ver, "raw": data}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)}


OFFLINE_FAIL_STREAK = 2  # consecutive probe fails before marking offline


def apply_health_probe(node: dict, probe: dict) -> list[dict]:
    """Update online/last_seen from a probe result.

    Returns Telegram-worthy events:
      {type: online|offline|version, name, ...}
    First successful/failed baseline (online is None) is silent — no spam on master restart.
    """
    events: list[dict] = []
    name = str(node.get("name") or node.get("domain") or node.get("id") or "node")
    ok = bool(probe.get("ok"))
    prev = node.get("online")  # True / False / None
    old_ver = str(node.get("panel_version") or "")
    new_ver = str(probe.get("version") or "").strip()
    node["last_probe"] = now_iso()

    if ok:
        node["fail_streak"] = 0
        node["last_seen"] = node["last_probe"]
        node["last_probe_error"] = ""
        if new_ver:
            if old_ver and new_ver != old_ver and prev is not None:
                events.append({
                    "type": "version", "name": name, "from": old_ver, "to": new_ver,
                    "domain": node.get("domain") or "",
                })
            node["panel_version"] = new_ver
        if prev is False:
            node["online"] = True
            events.append({
                "type": "online", "name": name,
                "version": node.get("panel_version") or "",
                "domain": node.get("domain") or "",
            })
        else:
            node["online"] = True
        return events

    err = str(probe.get("error") or "unreachable")[:300]
    node["fail_streak"] = int(node.get("fail_streak") or 0) + 1
    node["last_probe_error"] = err
    if int(node["fail_streak"]) >= OFFLINE_FAIL_STREAK:
        if prev is True:
            node["online"] = False
            events.append({
                "type": "offline", "name": name, "reason": err,
                "domain": node.get("domain") or "",
            })
        elif prev is None:
            # Baseline: known offline, no notify
            node["online"] = False
        else:
            node["online"] = False
    return events


def probe_all_health(nodes: list[dict], *, timeout: int = 5) -> list[dict]:
    """Probe enabled nodes; mutate each in place; return combined events."""
    events: list[dict] = []
    for n in nodes or []:
        if not n.get("enabled", True):
            continue
        if n.get("nat"):
            # Unreachable from master by design — online = recent /agent/pull
            if pull_fresh(n):
                continue  # apply_pull_seen already marked it online
            events.extend(apply_health_probe(n, {
                "ok": False, "error": "нет связи от ноды за NAT (pull не приходит)",
            }))
            continue
        if not (n.get("url") or n.get("domain")):
            continue
        try:
            probe = probe_health(n, timeout=timeout)
        except Exception as exc:  # noqa: BLE001
            probe = {"ok": False, "error": str(exc)}
        events.extend(apply_health_probe(n, probe))
        raw = probe.get("raw") if isinstance(probe.get("raw"), dict) else {}
        if isinstance(raw.get("rv_conns"), int):
            n["rv_conns"] = raw["rv_conns"]
        elif not uses_reverse(n):
            n.pop("rv_conns", None)
        xv = str(raw.get("xray_version") or "").strip()
        if xv:
            n["xray_version"] = xv.lstrip("vV")
        if "xray_active" in raw:
            n["xray_active"] = bool(raw.get("xray_active"))
    return events


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
        client, fp = _ssh_connect(
            host, user, ssh_password, port=port, timeout=45,
            expected_fp=str(node.get("ssh_hostkey_fp") or ""),
        )
        if fp:
            node["ssh_hostkey_fp"] = fp
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
    if node.get("nat"):
        # Node has no open ports — it pulls /agent/pull every ~20s; config is already queued.
        return {"ok": True, "queued": True, "warnings": [], "error": ""}
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
    err = str(result.get("error") or "")
    # Transient network / busy agent / nginx reload mid-response: one retry
    # "Remote end closed without response" is common when agent reloads nginx while
    # answering /agent/apply — config is often already applied; retry usually succeeds.
    _transient = (
        "timed out", "timeout", "temporarily", "connection reset",
        "remote end closed", "remotdisconnected", "connection aborted",
        "broken pipe", "connection refused",
    )
    _drop = (
        "remote end closed", "remotdisconnected", "connection aborted", "broken pipe",
    )
    if not result.get("ok") and any(x in err.lower() for x in _transient):
        time.sleep(1.2)
        result = _push_once(node, payload, timeout=max(timeout, 180))
        err = str(result.get("error") or "")
    # Still dropped with no HTTP status: nginx likely reloaded after apply. If /health
    # answers, treat as soft-ok so the UI does not stick on a false sync err.
    if not result.get("ok") and any(x in err.lower() for x in _drop):
        time.sleep(1.0)
        probe = probe_health(node, timeout=8)
        if probe.get("ok"):
            warn = (
                f"ответ sync оборван ({err[:100]}), но /health ок — "
                "конфиг скорее всего уже применён (nginx reload)"
            )
            result = {
                "ok": True,
                "soft": True,
                "warnings": list(result.get("warnings") or []) + [warn],
                "error": "",
            }
            err = ""
    # Auto-heal: agent was turned off by update/restart — re-enable via manage API and retry once.
    # Respects remote agent_manual_off (admin unchecked Settings → Nodes).
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
        inbounds = payload["inbounds"]
        # Safety: force inbound domains to this agent's public host (master may still send its own)
        local_host = ""
        try:
            import front as front_mod
            local_host = _normalize_domain(front_mod.public_domain(store) or "")
        except Exception:
            local_host = ""
        if not local_host:
            local_host = _normalize_domain(
                ((store.get("settings") or {}).get("panel") or {}).get("public_host") or ""
            )
        if local_host:
            # Treat any non-local share_host in the payload as "old" (master)
            old = {
                _normalize_domain(ib.get("share_host") or "")
                for ib in (inbounds or [])
                if isinstance(ib, dict)
            }
            old.discard("")
            old.discard(local_host)
            inbounds = remap_inbounds_for_host(inbounds, new_host=local_host, old_hosts=old)
        store["inbounds"] = inbounds
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
    ns = store.setdefault("settings", {}).setdefault("nodes", {})
    if "reverse_bridge" in payload:
        rb = payload.get("reverse_bridge")
        if isinstance(rb, dict) and rb.get("uuid") and rb.get("path") and rb.get("master_host"):
            ns["reverse_bridge"] = rb
            if payload.get("nat"):
                ns["nat"] = True
            else:
                ns.pop("nat", None)
        elif rb is None or payload.get("nat") is False:
            ns.pop("reverse_bridge", None)
            ns.pop("nat", None)
    return apply_config(store)


# ---------------------------------------------------------------- SSH provision

def _ssh_connect(
    host: str,
    user: str,
    password: str,
    port: int = 22,
    timeout: int = 30,
    expected_fp: str = "",
) -> tuple:
    """Connect over SSH with host-key pinning.

    Returns (client, fingerprint). On first connect (no expected_fp) the key is
    accepted once and the fingerprint returned for persistence. Later connects
    reject a mismatched key (MITM protection).
    """
    import paramiko
    import security as sec

    class _PinPolicy(paramiko.MissingHostKeyPolicy):
        def __init__(self):
            self.fp = ""

        def missing_host_key(self, client, hostname, key):
            fp = sec.ssh_key_fingerprint(key)
            self.fp = fp
            want = (expected_fp or "").strip()
            if want and not sec.token_eq(fp, want):
                raise paramiko.SSHException(
                    f"SSH host key mismatch for {hostname}: got {fp}, expected {want}"
                )
            client.get_host_keys().add(hostname, key.get_name(), key)

    client = paramiko.SSHClient()
    policy = _PinPolicy()
    client.set_missing_host_key_policy(policy)
    # If we already trust a fingerprint, also seed HostKeys so paramiko does not
    # treat a cached mismatch silently — Reject via policy on missing only.
    client.connect(
        host, port=int(port or 22), username=user, password=password,
        timeout=timeout, banner_timeout=60, auth_timeout=30,
        look_for_keys=False, allow_agent=False,
    )
    fp = policy.fp or (expected_fp or "").strip()
    # When the key was already in an empty HostKeys and paramiko accepted via
    # transport — ensure we still capture fingerprint from the remote key.
    if not fp:
        try:
            tkey = client.get_transport().get_remote_server_key()
            fp = sec.ssh_key_fingerprint(tkey)
            if expected_fp and not sec.token_eq(fp, expected_fp.strip()):
                client.close()
                raise paramiko.SSHException(
                    f"SSH host key mismatch for {host}: got {fp}, expected {expected_fp}"
                )
        except AttributeError:
            pass
    return client, fp


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
    nat: bool = False,
    master_pull_url: str = "",
) -> dict:
    """Install/configure L2X on a remote host over SSH and return node registry fields.

    nat=True: host has no open inbound ports except SSH. No Let's Encrypt, no inbounds;
    the agent pulls config from master_pull_url and egress goes through a reverse tunnel.
    """
    domain = _normalize_domain(domain)
    if not domain or " " in domain:
        return {"ok": False, "error": "некорректный domain"}
    if nat and not master_pull_url:
        return {"ok": False, "error": "для ноды за NAT у мастера должен быть публичный домен (Настройки → Панель)"}
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
    mirror = bool(mirror) and not nat
    if mirror or nat:
        as_outbound = True
    node = {
        "id": node_id, "name": name, "domain": domain, "ssh_user": ssh_user, "ssh_port": int(ssh_port or 22),
        "token": agent_tok, "enabled": True,
        "sync_clients": not nat, "sync_inbounds": not nat,
        "as_outbound": bool(as_outbound), "mirror": mirror, "base_path": panel_path, "role": "agent",
        "url": f"https://{domain}", "last_sync": "", "last_error": "", "last_ok": False,
        "nat": bool(nat),
    }
    if nat:
        ensure_reverse(node)
    else:
        ensure_bridge(node)
    log: list[str] = [f"provision {name} @ {domain}" + (" [NAT/reverse]" if nat else "")]

    try:
        client, fp = _ssh_connect(domain, ssh_user, ssh_password, int(ssh_port or 22))
        if fp:
            node["ssh_hostkey_fp"] = fp
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
            *([] if nat else [f"export L2X_DOMAIN={json.dumps(domain)[1:-1]}"]),
            # NAT: :80 unreachable → no Let's Encrypt; node never serves public HTTPS
            "export L2X_SSL=none" if nat else "export L2X_SSL=domain",
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
            # Bootstrap install.sh with retries — raw.githubusercontent.com / GitHub often 503
            "INSTALL_SH=/tmp/l2x_install.sh",
            "ok=0",
            "for u in \\",
            "  https://raw.githubusercontent.com/eliot-voodi/l2x-panel/main/install.sh \\",
            "  https://cdn.jsdelivr.net/gh/eliot-voodi/l2x-panel@main/install.sh",
            "do",
            "  for i in 1 2 3 4 5; do",
            "    echo \"bootstrap $u try $i\"",
            "    if curl -fsSL --connect-timeout 20 --max-time 120 -o \"$INSTALL_SH\" \"$u\" \\",
            "       && [ -s \"$INSTALL_SH\" ] && head -1 \"$INSTALL_SH\" | grep -q bash; then",
            "      ok=1; break 2",
            "    fi",
            "    sleep $((i * 3))",
            "  done",
            "done",
            "[ \"$ok\" = 1 ] || { echo 'не удалось скачать install.sh с GitHub' >&2; exit 22; }",
            "chmod +x \"$INSTALL_SH\"",
            "if [ -f /etc/l2xpanel/panel.env ] && [ -f /opt/l2xpanel/app.py ]; then",
            "  bash \"$INSTALL_SH\" --update",
            "else",
            "  bash \"$INSTALL_SH\" --yes",
            "fi",
            "rm -f \"$INSTALL_SH\"",
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
NAT = {bool(nat)!r}
PULL_URL = {master_pull_url!r}
NODE_ID = {node_id!r}
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
if NAT:
    # Outbound-only control channel: agent polls master (no inbound ports needed)
    ns["pull"] = {{"master_url": PULL_URL, "node_id": NODE_ID}}
else:
    ns.pop("pull", None)
    ns.pop("reverse_bridge", None)
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


def node_public_domain(node: dict) -> str:
    """Hostname clients use for this node (panel domain / URL host)."""
    domain = _normalize_domain(node.get("domain") or "")
    if domain:
        return domain
    from urllib.parse import urlparse
    return _normalize_domain(urlparse(node.get("url") or "").hostname or "")


def master_public_domains(store: dict) -> set[str]:
    """Domains that identify the master — rewritten to the node domain on sync."""
    out: set[str] = set()
    settings = store.get("settings") or {}
    for raw in (
        (settings.get("panel") or {}).get("public_host"),
        (settings.get("sub") or {}).get("domain"),
    ):
        d = _normalize_domain(str(raw or ""))
        if d:
            out.add(d)
    try:
        import front as front_mod
        d = _normalize_domain(front_mod.public_domain(store) or "")
        if d:
            out.add(d)
    except Exception:
        pass
    return out


def remap_inbounds_for_host(
    inbounds: list | None,
    *,
    new_host: str,
    old_hosts: set[str] | list[str] | None = None,
) -> list:
    """Deep-copy inbounds with share_host / TLS SNI / transport Host pointed at new_host.

    Used when syncing master → node so Path/TLS inbounds advertise the node domain,
    not the master. Reality camouflage SNIs that are not in old_hosts are left alone.
    """
    new_host = _normalize_domain(new_host)
    if not new_host:
        return json.loads(json.dumps(inbounds or []))
    old = {_normalize_domain(h) for h in (old_hosts or []) if h}
    for ib in inbounds or []:
        if not isinstance(ib, dict):
            continue
        sh = _normalize_domain(ib.get("share_host") or "")
        if sh and sh != new_host:
            old.add(sh)
    old.discard("")
    old.discard(new_host)

    def _swap(val: str) -> str:
        dn = _normalize_domain(val)
        return new_host if dn and dn in old else val

    out = json.loads(json.dumps(inbounds or []))
    for ib in out:
        if not isinstance(ib, dict):
            continue
        # Always publish the node domain in share links / nginx Path sites
        ib["share_host"] = new_host
        stream = ib.get("stream")
        if not isinstance(stream, dict):
            continue
        tls = stream.get("tls")
        if isinstance(tls, dict) and tls.get("server_name"):
            tls["server_name"] = _swap(str(tls.get("server_name") or ""))
        reality = stream.get("reality")
        if isinstance(reality, dict):
            names = reality.get("server_names")
            if isinstance(names, list) and names:
                reality["server_names"] = [
                    _swap(str(n)) if _normalize_domain(str(n)) in old else n for n in names
                ]
            dest = str(reality.get("dest") or "")
            if dest:
                host_part, _, port = dest.partition(":")
                if _normalize_domain(host_part) in old:
                    reality["dest"] = f"{new_host}:{port or '443'}"
        for key in ("ws", "httpupgrade", "xhttp", "splithttp"):
            cfg = stream.get(key)
            if isinstance(cfg, dict) and cfg.get("host"):
                cfg["host"] = _swap(str(cfg.get("host") or ""))
        for key in ("raw", "tcp"):
            cfg = stream.get(key)
            if isinstance(cfg, dict) and cfg.get("http_host"):
                parts = [p.strip() for p in str(cfg.get("http_host") or "").split(",")]
                cfg["http_host"] = ",".join(_swap(p) if p else p for p in parts)
        grpc = stream.get("grpc")
        if isinstance(grpc, dict) and grpc.get("authority"):
            grpc["authority"] = _swap(str(grpc.get("authority") or ""))
        for ep in ib.get("external_proxies") or []:
            if not isinstance(ep, dict) or not ep.get("address"):
                continue
            addr = str(ep["address"])
            host_part, sep, rest = addr.partition(":")
            if _normalize_domain(host_part) in old:
                ep["address"] = new_host + (sep + rest if sep else "")
    return out


def remap_inbound_share_hosts(store: dict, *, new_host: str, old_hosts: list[str] | None = None) -> int:
    """Point inbound share_host (+ related domain fields) at the new master domain after promote.

    Without this, subscriptions keep advertising the old master (n/a after cutover).
    """
    new_host = _normalize_domain(new_host)
    if not new_host:
        return 0
    before = json.dumps(store.get("inbounds") or [], sort_keys=True)
    store["inbounds"] = remap_inbounds_for_host(
        store.get("inbounds") or [],
        new_host=new_host,
        old_hosts=old_hosts,
    )
    after = json.dumps(store.get("inbounds") or [], sort_keys=True)
    return 0 if before == after else sum(1 for _ in store.get("inbounds") or [])


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
        client, fp = _ssh_connect(
            domain, user, ssh_password, port,
            expected_fp=str(node.get("ssh_hostkey_fp") or ""),
        )
        if fp:
            node["ssh_hostkey_fp"] = fp
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
# Remap subscription share_host from old master domain to this host
new_host = ((store.get('settings') or {}).get('panel') or {}).get('public_host') or keep_host or ''
old_hosts = set()
om = snap.get('old_master_domain') or ''
if om: old_hosts.add(str(om).strip().lower())
inc = ((snap.get('settings') or {}).get('panel') or {}).get('public_host') or ''
if inc: old_hosts.add(str(inc).strip().lower())
nh = str(new_host or '').strip().lower()
if nh:
    for ib in store.get('inbounds') or []:
        sh = str(ib.get('share_host') or '').strip().lower()
        if (not sh) or (sh != nh and (not old_hosts or sh in old_hosts)):
            ib['share_host'] = nh
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
