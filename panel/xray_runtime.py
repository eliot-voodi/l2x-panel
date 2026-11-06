"""Xray config builder: multi-inbound, L2TP/custom outbounds, balancers, per-user routing, quotas."""
from __future__ import annotations

import base64
import copy
import ipaddress
import json
import os
import re
import secrets
import shutil
import subprocess
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import protocols as P

XRAY_BIN = os.environ.get("XRAY_BIN", "/usr/local/bin/xray")
XRAY_CONFIG = Path(os.environ.get("XRAY_CONFIG", "/etc/xray/config.json"))
XRAY_CONFIG_PREV = XRAY_CONFIG.with_name(XRAY_CONFIG.name + ".prev")
XRAY_API = os.environ.get("XRAY_API", "127.0.0.1:10085")
XRAY_LOG_DIR = Path(os.environ.get("XRAY_LOG_DIR", "/var/log/xray"))
GB = 1024 ** 3
IPLIMIT_CHAIN = "L2X_IPLIMIT"

def public_host() -> str:
    return os.environ.get("L2XPANEL_PUBLIC_HOST", "127.0.0.1")


PUBLIC_HOST = public_host()


def _run(cmd: list[str], timeout: int = 60) -> dict:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"cmd": " ".join(cmd), "exit_code": 127, "stdout": "", "stderr": str(exc)}
    return {"cmd": " ".join(cmd), "exit_code": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------- units

def gb_to_bytes(gb: float | int | str | None) -> int:
    try:
        v = float(gb or 0)
    except (TypeError, ValueError):
        return 0
    return int(v * GB) if v > 0 else 0


def bytes_to_gb(n: int | float | None) -> float:
    return round(float(n or 0) / GB, 6)


def format_traffic(n: int | float | None) -> str:
    n = int(n or 0)
    if n < 1024:
        return f"{n} B"
    if n < 1024 ** 2:
        return f"{n / 1024:.1f} KB"
    if n < GB:
        return f"{n / (1024 ** 2):.2f} MB"
    if n < 1024 * GB:
        return f"{n / GB:.2f} GB"
    return f"{n / (1024 * GB):.2f} TB"


def parse_expire_at(value: str | None) -> datetime | None:
    raw = (value or "").strip()
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        try:
            dt = datetime.strptime(raw, "%Y-%m-%d")
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    if len(raw) <= 10:
        dt = dt.replace(hour=23, minute=59, second=59)
    return dt


def expire_unix(item: dict) -> int:
    dt = parse_expire_at(item.get("expire_at"))
    return int(dt.timestamp()) if dt else 0


def days_left(item: dict) -> float | None:
    dt = parse_expire_at(item.get("expire_at"))
    if not dt:
        return None
    return (dt - now_utc()).total_seconds() / 86400


# ---------------------------------------------------------------- keys

def generate_reality_keys() -> dict:
    r = _run([XRAY_BIN, "x25519"])
    return _parse_keypair(r)


def generate_wg_keys() -> dict:
    r = _run([XRAY_BIN, "wg"])
    return _parse_keypair(r)


def wg_public_from_private(private_key: str) -> dict:
    """Derive WireGuard public key from a base64 private key."""
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        raw = base64.b64decode(private_key.strip() + "=" * (-len(private_key.strip()) % 4))
        if len(raw) != 32:
            return {"ok": False, "error": "private key must be 32 bytes"}
        pub = X25519PrivateKey.from_private_bytes(raw).public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        return {"ok": True, "private_key": private_key.strip(), "public_key": base64.b64encode(pub).decode()}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc) or "derive failed"}


def _parse_keypair(r: dict) -> dict:
    text = f"{r['stdout']}\n{r['stderr']}"
    priv = pub = ""
    for line in text.splitlines():
        low = line.lower()
        if "private" in low and ":" in line:
            priv = line.split(":", 1)[1].strip()
        elif "public" in low and ":" in line:
            pub = line.split(":", 1)[1].strip()
    if not priv or not pub:
        return {"ok": False, "error": text or "keygen failed"}
    return {"ok": True, "private_key": priv, "public_key": pub}


def generate_short_id(nbytes: int = 4) -> str:
    return secrets.token_hex(nbytes)


def generate_short_ids(count: int = 8) -> list[str]:
    """Mixed-length shortIds like common panel UIs (0..16 hex chars)."""
    lengths = (0, 2, 4, 6, 8, 10, 12, 14, 16)
    out = [""]
    for i in range(max(1, count) - 1):
        out.append(secrets.token_hex(lengths[(i % (len(lengths) - 1)) + 1] // 2))
    return out


def generate_mldsa65() -> dict:
    r = _run([XRAY_BIN, "mldsa65"])
    text = f"{r['stdout']}\n{r['stderr']}"
    seed = verify = ""
    for line in text.splitlines():
        low = line.lower()
        if "seed" in low and ":" in line:
            seed = line.split(":", 1)[1].strip()
        elif ("verify" in low or "public" in low) and ":" in line:
            verify = line.split(":", 1)[1].strip()
    if not seed:
        return {"ok": False, "error": text or "mldsa65 failed"}
    return {"ok": True, "seed": seed, "verify": verify}


def generate_vless_encryption() -> dict:
    """Return X25519 and ML-KEM-768 auth pairs from `xray vlessenc`."""
    r = _run([XRAY_BIN, "vlessenc"])
    text = f"{r['stdout']}\n{r['stderr']}"
    pairs: list[dict] = []
    cur: dict = {}

    def _kv(line: str) -> tuple[str, str] | None:
        # accepts: decryption: value  OR  "decryption": "value"
        raw = line.strip().strip(",").strip()
        if ":" not in raw:
            return None
        key, _, val = raw.partition(":")
        key = key.strip().strip('"').strip("'").lower()
        val = val.strip().strip(",").strip().strip('"').strip("'")
        return (key, val) if key and val else None

    for line in text.splitlines():
        stripped = line.strip()
        low = stripped.lower()
        # Only section headers — do NOT match key values that contain "x25519"/"mlkem"
        if low.startswith("authentication:") or low.startswith("authentication "):
            if cur.get("decryption") and cur.get("encryption"):
                pairs.append(cur)
            label = "mlkem768" if ("ml-kem" in low or "mlkem" in low or "post-quantum" in low) else "x25519"
            if "x25519" in low and "ml-kem" not in low and "mlkem" not in low:
                label = "x25519"
            cur = {"id": label, "label": stripped}
            continue
        parsed = _kv(stripped)
        if not parsed or not cur:
            continue
        key, val = parsed
        if key in ("decryption", "encryption"):
            cur[key] = val
    if cur.get("decryption") and cur.get("encryption"):
        pairs.append(cur)
    if not pairs:
        return {"ok": False, "error": "не удалось разобрать вывод xray vlessenc"}
    return {"ok": True, "auths": pairs}


# ---------------------------------------------------------------- countries / flags

COUNTRY_BY_NAME = {
    "israel": "IL", "germany": "DE", "australia": "AU", "china": "CN", "japan": "JP",
    "korea": "KR", "malaysia": "MY", "new_zealand": "NZ", "singapore": "SG",
    "switzerland": "CH", "czech": "CZ", "denmark": "DK", "spain": "ES", "finland": "FI",
    "france": "FR", "united_kingdom": "GB", "uk": "GB", "italy": "IT", "luxembourg": "LU",
    "netherlands": "NL", "poland": "PL", "sweden": "SE", "turkey": "TR", "ukraine": "UA",
    "brazil": "BR", "canada": "CA", "costa_rica": "CR", "us": "US", "usa": "US",
}
COUNTRY_BY_HOST = {"uk": "GB", "sk": "KR", "netflix": "US", "is": "IL"}


def country_code(item: dict) -> str:
    explicit = str(item.get("country") or "").strip().upper()
    if re.fullmatch(r"[A-Z]{2}", explicit):
        return explicit
    name = str(item.get("name") or "").lower()
    for key in sorted(COUNTRY_BY_NAME, key=len, reverse=True):
        if name == key or name.startswith(key + "_") or name.startswith(key):
            return COUNTRY_BY_NAME[key]
    host = str(item.get("server_host") or "").lower()
    prefix = re.split(r"[-.]", host, maxsplit=1)[0] if host else ""
    if prefix in COUNTRY_BY_HOST:
        return COUNTRY_BY_HOST[prefix]
    if re.fullmatch(r"[a-z]{2}", prefix):
        return prefix.upper()
    return ""


def flag_emoji(code: str) -> str:
    code = (code or "").upper()
    if not re.fullmatch(r"[A-Z]{2}", code):
        return "🌐"
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in code)


# ---------------------------------------------------------------- balancers

BALANCER_LEAST_PING = "lb_least_ping"
BALANCER_LEAST_LOAD = "lb_least_load"
BALANCER_LABELS = {
    BALANCER_LEAST_PING: "⚡ Авто: наименьший пинг",
    BALANCER_LEAST_LOAD: "⚖️ Авто: наименьшая загрузка",
}


def default_balancers() -> dict:
    return {
        "least_ping": {
            "tag": BALANCER_LEAST_PING, "enabled": True, "strategy": "leastPing", "members": [],
            "probe_url": "https://www.gstatic.com/generate_204", "probe_interval": "15s", "fallback": "direct",
        },
        "least_load": {
            "tag": BALANCER_LEAST_LOAD, "enabled": True, "strategy": "leastLoad", "members": [],
            "probe_url": "https://www.gstatic.com/generate_204", "probe_interval": "20s",
            "expected": 1, "max_rtt": "1s", "tolerance": 0.15, "fallback": "direct",
        },
    }


def ensure_balancers(store: dict) -> dict:
    bals = store.setdefault("balancers", {})
    for key, default in default_balancers().items():
        cur = bals.setdefault(key, {})
        for k, v in default.items():
            cur.setdefault(k, v)
        cur["tag"] = default["tag"]
        cur["strategy"] = default["strategy"]
    return bals


def balancer_tags(store: dict) -> list[str]:
    ensure_balancers(store)
    return [b["tag"] for b in store["balancers"].values() if b.get("enabled", True) and b.get("tag")]


def _is_balancer_target(store: dict, tag: str) -> bool:
    return tag in balancer_tags(store)


def _l2tp_tag(t: dict) -> str:
    return t.get("outbound") or f"l2tp_{t['name']}"


def connected_l2tp_tags(store: dict) -> list[str]:
    return [_l2tp_tag(t) for t in store.get("l2tp") or [] if t.get("status") == "connected"]


def balancer_member_tags(store: dict, balancer: dict) -> list[str]:
    """explicit members ∩ (connected L2TP ∪ enabled custom outbounds); empty → all connected L2TP."""
    connected = connected_l2tp_tags(store)
    members = balancer.get("members") or []
    if not members:
        return connected
    custom = {o["tag"] for o in store.get("outbounds_custom") or [] if o.get("enabled", True)}
    pool = set(connected) | custom
    return [t for t in members if t in pool]


# ---------------------------------------------------------------- outbounds

def _l2tp_outbounds(store: dict) -> list[dict]:
    out = []
    for t in store.get("l2tp") or []:
        if t.get("status") != "connected":
            continue
        out.append({
            "tag": _l2tp_tag(t),
            "protocol": "freedom",
            "settings": {"domainStrategy": "UseIPv4"},
            "streamSettings": {"sockopt": {"interface": t.get("ifname") or f"l2x-{t['name']}"}},
        })
    return out


def _custom_outbounds(store: dict) -> list[dict]:
    out = []
    for o in store.get("outbounds_custom") or []:
        if not o.get("enabled", True):
            continue
        cfg = copy.deepcopy(o.get("config") or {})
        cfg["tag"] = o["tag"]
        out.append(cfg)
    return out


def reverse_portal_tags(store: dict) -> list[str]:
    return [p["tag"] for p in (store.get("reverse") or {}).get("portals") or [] if p.get("tag")]


def all_outbound_tags(store: dict) -> list[str]:
    tags = ["direct", "block"]
    tags += [_l2tp_tag(t) for t in store.get("l2tp") or []]
    tags += [o["tag"] for o in store.get("outbounds_custom") or []]
    tags += reverse_portal_tags(store)
    tags += balancer_tags(store)
    return tags


def outbound_label(store: dict, tag: str) -> str:
    if tag in BALANCER_LABELS:
        return BALANCER_LABELS[tag]
    if tag == "direct":
        return "🏠 Direct"
    if tag == "block":
        return "⛔ Block"
    for t in store.get("l2tp") or []:
        if _l2tp_tag(t) == tag:
            return f"{flag_emoji(country_code(t))} {t['name'].replace('_', ' ')}"
    for o in store.get("outbounds_custom") or []:
        if o["tag"] == tag:
            cc = o.get("country") or ""
            if o.get("kind") == "node":
                icon = flag_emoji(cc) if cc else "🖥️"
                return f"{icon} Node {o.get('remark') or tag}"
            icon = flag_emoji(cc) if cc else "🔗"
            return f"{icon} {o.get('remark') or tag}"
    if tag.startswith("node_"):
        return f"🖥️ {tag}"
    return tag


def _route_target(store: dict, tag: str, *, known_outbounds: set[str] | None = None) -> dict:
    """Map a logical tag to a routing target.

    Balancers are only referenced when they have live members (and thus appear in
    the config with observatory). Otherwise fall back to the balancer's fallback
    outbound (usually direct). Unknown outbound tags also fall back to direct.
    """
    tag = (tag or "direct").strip() or "direct"
    if _is_balancer_target(store, tag):
        for b in ensure_balancers(store).values():
            if b.get("tag") != tag or not b.get("enabled", True):
                continue
            if balancer_member_tags(store, b):
                return {"balancerTag": tag}
            return {"outboundTag": b.get("fallback") or "direct"}
        return {"outboundTag": "direct"}
    if known_outbounds is not None and tag not in known_outbounds:
        return {"outboundTag": "direct"}
    return {"outboundTag": tag}


# ---------------------------------------------------------------- inbounds

def ensure_inbounds(store: dict) -> list[dict]:
    """Multi-inbound list; migrates legacy single `inbound` (VLESS Reality)."""
    inbounds = store.get("inbounds")
    if inbounds is None:
        inbounds = []
        legacy = store.get("inbound")
        if legacy:
            ib = P.default_inbound("vless", int(legacy.get("port") or 443), legacy.get("tag") or "vless-in")
            ib["remark"] = "VLESS Reality"
            ib["enabled"] = legacy.get("enabled", True)
            ib["listen"] = legacy.get("listen") or "0.0.0.0"
            ib["settings"]["flow"] = legacy.get("flow") or "xtls-rprx-vision"
            r = ib["stream"]["reality"]
            r["dest"] = legacy.get("dest") or r["dest"]
            r["server_names"] = legacy.get("server_names") or r["server_names"]
            r["private_key"] = legacy.get("private_key") or ""
            r["public_key"] = legacy.get("public_key") or ""
            r["short_ids"] = legacy.get("short_ids") or r["short_ids"]
            r["fingerprint"] = legacy.get("fingerprint") or "chrome"
            r["spider_x"] = legacy.get("spider_x") or "/"
            inbounds.append(ib)
        store["inbounds"] = inbounds
    next_id = max([int(i.get("id") or 0) for i in inbounds] + [0]) + 1
    for ib in inbounds:
        P.ensure_inbound_shape(ib)
        if not ib.get("id"):
            ib["id"] = next_id
            next_id += 1
        ensure_inbound_keys(ib)
        ib["listen"] = P.INBOUND_LISTEN
        P.normalize_http_inbound(ib)
    # Inbounds from older versions (or pushed by a master node) may sit on a forbidden port
    for ib in inbounds:
        if port_forbidden_reason(int(ib.get("port") or 0)):
            ib["port"] = free_inbound_port(store, exclude=ib)
    return inbounds


def system_ports() -> set[int]:
    """Ports used by the panel itself on this host; inbounds may not take them."""
    ports = {P.FRONT_INTERNAL_PORT, int(str(XRAY_API).rsplit(":", 1)[-1])}
    try:
        ports.add(int(os.environ.get("PORT") or 8090))
    except ValueError:
        pass
    return ports


def port_forbidden_reason(port: int) -> str:
    if not 1 <= port <= 65535:
        return "Порт 1..65535"
    if port in P.RESERVED_PORTS:
        return f"Порт {port} запрещён для inbound (22, 80, 443 заняты SSH и nginx)"
    if port in system_ports():
        return f"Порт {port} занят панелью"
    return ""


def free_inbound_port(store: dict, exclude: dict | None = None, start: int = 10000) -> int:
    used = {int(i.get("port") or 0) for i in store.get("inbounds") or [] if i is not exclude}
    return next(p for p in range(start, 65535) if p not in used and not port_forbidden_reason(p))


def ensure_inbound_keys(ib: dict) -> None:
    st = ib["stream"]
    if st.get("security") == "reality":
        r = st["reality"]
        if not r.get("private_key") or not r.get("public_key"):
            keys = generate_reality_keys()
            if keys.get("ok"):
                r["private_key"], r["public_key"] = keys["private_key"], keys["public_key"]
        if not r.get("short_ids"):
            r["short_ids"] = [generate_short_id()]
    if ib["protocol"] == "wireguard":
        s = ib["settings"]
        if not s.get("secret_key") or not s.get("public_key"):
            keys = generate_wg_keys()
            if keys.get("ok"):
                s["secret_key"], s["public_key"] = keys["private_key"], keys["public_key"]


def inbound_by_tag(store: dict, tag: str) -> dict | None:
    return next((i for i in ensure_inbounds(store) if i["tag"] == tag), None)


def inbound_by_id(store: dict, ib_id: int) -> dict | None:
    return next((i for i in ensure_inbounds(store) if int(i.get("id") or 0) == int(ib_id)), None)


def inbound_used_bytes(ib: dict) -> int:
    t = ib.get("traffic") or {}
    return int(t.get("up") or 0) + int(t.get("down") or 0)


def inbound_access_ok(ib: dict) -> bool:
    if not ib.get("enabled", True):
        return False
    dt = parse_expire_at(ib.get("expire_at"))
    if dt and now_utc() >= dt:
        return False
    limit = gb_to_bytes(ib.get("total_gb"))
    if limit and inbound_used_bytes(ib) >= limit:
        return False
    return True


def client_capable_inbounds(store: dict) -> list[dict]:
    return [i for i in ensure_inbounds(store) if i["protocol"] in P.USER_PROTOCOLS + ("wireguard", "socks", "http")]


def client_inbounds(store: dict, client: dict) -> list[dict]:
    wanted = client.get("inbounds") or []
    capable = client_capable_inbounds(store)
    if not wanted:
        return capable
    return [i for i in capable if i["tag"] in wanted]


# ---------------------------------------------------------------- clients

RESET_PERIODS = {"": None, "daily": 1, "weekly": 7, "monthly": 30}


def ensure_client(client: dict) -> dict:
    client.setdefault("uuid", str(uuid.uuid4()))
    client.setdefault("password", secrets.token_hex(12))
    client.setdefault("enabled", True)
    client.setdefault("outbound", "direct")
    client.setdefault("inbounds", [])
    client.setdefault("limit_gb", 0)
    client.setdefault("expire_at", "")
    client.setdefault("start_on_first_use", False)
    client.setdefault("duration_days", 0)
    client.setdefault("reset_period", "")
    client.setdefault("next_reset", "")
    client.setdefault("renew_on_reset", False)
    client.setdefault("limit_ip", 0)
    client.setdefault("limit_hwid", 0)
    client.setdefault("hwids", [])
    client.setdefault("comment", "")
    client.setdefault("tg_id", "")
    client.setdefault("tg_username", "")
    client.setdefault("tg_first_name", "")
    client.setdefault("tg_last_name", "")
    client.setdefault("tg_fio", "")
    client.setdefault("allowed_tags", [])
    client.setdefault("outbound_limits", {})
    client.setdefault("sub_enabled", True)
    client.setdefault("last_online", "")
    client.setdefault("ips", {})
    client.setdefault("created_at", now_utc().isoformat())
    traffic = client.setdefault("traffic", {})
    traffic.setdefault("up", 0)
    traffic.setdefault("down", 0)
    traffic.setdefault("by_email", {})
    return client


ensure_client_quota = ensure_client  # backward compat


def ensure_wg_peer(store: dict, client: dict) -> None:
    if not any(i["protocol"] == "wireguard" for i in client_inbounds(store, client)):
        return
    if not client.get("wg_private") or not client.get("wg_public"):
        keys = generate_wg_keys()
        if keys.get("ok"):
            client["wg_private"], client["wg_public"] = keys["private_key"], keys["public_key"]
    if not client.get("wg_index"):
        used = {int(c.get("wg_index") or 0) for c in store.get("clients") or []}
        idx = 2
        while idx in used:
            idx += 1
        client["wg_index"] = idx


def wg_ip(ib: dict, client: dict) -> str:
    try:
        net = ipaddress.ip_network((ib.get("settings") or {}).get("address_pool") or "10.66.0.0/24", strict=False)
        return str(net.network_address + int(client.get("wg_index") or 2))
    except ValueError:
        return ""


def client_used_bytes(client: dict) -> int:
    t = ensure_client(client)["traffic"]
    return int(t.get("up") or 0) + int(t.get("down") or 0)


def client_remaining_bytes(client: dict) -> int | None:
    """Bytes left until limit_gb; None if unlimited."""
    limit = gb_to_bytes(client.get("limit_gb"))
    if not limit:
        return None
    return max(0, int(limit) - client_used_bytes(client))


def client_remaining_gb(client: dict) -> float | None:
    left = client_remaining_bytes(client)
    if left is None:
        return None
    return left / (1024 ** 3)


def client_tag_used_bytes(client: dict, tag: str) -> int:
    by = ensure_client(client)["traffic"].get("by_email") or {}
    email = client.get("email") or ""
    keys = [f"{email}~{tag}"]
    if (client.get("outbound") or "direct") == tag:
        keys.append(email)
    total = 0
    for k in keys:
        row = by.get(k) or {}
        total += int(row.get("up") or 0) + int(row.get("down") or 0)
    return total


def client_is_expired(client: dict, now: datetime | None = None) -> bool:
    dt = parse_expire_at(client.get("expire_at"))
    return bool(dt and (now or now_utc()) >= dt)


def client_total_exceeded(client: dict) -> bool:
    limit = gb_to_bytes(client.get("limit_gb"))
    return bool(limit and client_used_bytes(client) >= limit)


def client_tag_exceeded(client: dict, tag: str) -> bool:
    limit = gb_to_bytes((client.get("outbound_limits") or {}).get(tag))
    return bool(limit and client_tag_used_bytes(client, tag) >= limit)


def client_access_ok(client: dict) -> bool:
    return bool(client.get("enabled", True)) and not client_is_expired(client) and not client_total_exceeded(client)


def tag_allowed_for_client(client: dict, tag: str) -> bool:
    allowed = client.get("allowed_tags") or []
    if allowed and tag not in allowed:
        return False
    return not client_tag_exceeded(client, tag)


def client_status(client: dict) -> str:
    if not client.get("enabled", True):
        return "disabled"
    if client_is_expired(client):
        return "expired"
    if client_total_exceeded(client):
        return "limited"
    return "active"


def selectable_outbound_tags(store: dict) -> list[dict]:
    ensure_balancers(store)
    out: list[dict] = []
    for b in store["balancers"].values():
        if b.get("enabled", True):
            out.append({"tag": b["tag"], "label": outbound_label(store, b["tag"]), "kind": "balancer"})
    for t in sorted(store.get("l2tp") or [], key=lambda x: x["name"]):
        tag = _l2tp_tag(t)
        out.append({"tag": tag, "label": outbound_label(store, tag), "kind": "l2tp", "status": t.get("status") or ""})
    for o in store.get("outbounds_custom") or []:
        out.append({"tag": o["tag"], "label": outbound_label(store, o["tag"]), "kind": "custom",
                    "status": "enabled" if o.get("enabled", True) else "disabled"})
    return out


def subscription_entries(store: dict, client: dict, *, ignore_quota: bool = False) -> list[dict]:
    """One identity per balancer / connected country / enabled custom outbound."""
    if not client.get("uuid") or not client.get("sub_enabled", True):
        return []
    if not ignore_quota and not client_access_ok(client):
        return []
    tags = [b["tag"] for b in ensure_balancers(store).values() if b.get("enabled", True)]
    tags += [_l2tp_tag(t) for t in sorted(store.get("l2tp") or [], key=lambda t: t["name"]) if t.get("status") == "connected"]
    tags += [o["tag"] for o in store.get("outbounds_custom") or [] if o.get("enabled", True) and o.get("in_sub", True)]
    entries = []
    for tag in tags:
        if not ignore_quota and not tag_allowed_for_client(client, tag):
            continue
        ident_uuid = P.identity_uuid(client["uuid"], tag)
        entries.append({
            "tag": tag,
            "label": outbound_label(store, tag),
            "uuid": ident_uuid,
            "password": P.derived_password(ident_uuid),
            "email": f"{client['email']}~{tag}",
        })
    return entries


def client_identities(store: dict, client: dict, ib: dict) -> list[dict]:
    main = {"uuid": client["uuid"], "email": client["email"], "password": client["password"], "main": True, "tag": ""}
    if ib["protocol"] == "wireguard":
        main.update({"wg_public": client.get("wg_public"), "wg_private": client.get("wg_private"), "wg_ip": wg_ip(ib, client)})
        return [main]
    if ib["protocol"] in ("socks", "http"):
        return [main]
    out = [main]
    for e in subscription_entries(store, client):
        out.append({"uuid": e["uuid"], "email": e["email"], "password": e["password"], "main": False, "tag": e["tag"], "label": e["label"]})
    return out


def tag_quota_suffix(client: dict, tag: str) -> str:
    limits = client.get("outbound_limits") or {}
    limit = gb_to_bytes(limits.get(tag))
    if limit <= 0:
        return ""
    used = client_tag_used_bytes(client, tag)
    return f" · {format_traffic(used)} / {float(limits[tag]):g} ГБ · ост. {format_traffic(max(limit - used, 0))}"


def client_endpoints(store: dict, client: dict, host: str | None = None) -> list[dict]:
    if not client_access_ok(client):
        return []
    if not host:
        try:
            import front as _front
            host = _front.public_domain(store) or public_host()
        except Exception:
            host = public_host()
    ibs = [i for i in client_inbounds(store, client) if inbound_access_ok(i)]
    multi = len(ibs) > 1
    eps = []
    for ib in ibs:
        prefix = f"[{ib.get('remark') or ib['tag']}] " if multi else ""
        for ident in client_identities(store, client, ib):
            if ident["main"]:
                ob = client.get("outbound") or "direct"
                if ob != "direct" and not tag_allowed_for_client(client, ob):
                    continue
                remark = f"{prefix}{client['email']} · {outbound_label(store, ob)}{tag_quota_suffix(client, ob)}"
            else:
                remark = f"{prefix}{ident['label']}{tag_quota_suffix(client, ident['tag'])}"
            ep = P.endpoint_for(ib, ident, host, remark)
            if ep:
                eps.extend(P._apply_external_proxy(ep, ib))
    return eps


def subscription_links(store: dict, client: dict, host: str | None = None) -> list[str]:
    return [P.endpoint_to_link(ep) for ep in client_endpoints(store, client, host)]


def client_share_link(store: dict, client: dict, host: str | None = None) -> str:
    links = subscription_links(store, client, host)
    return links[0] if links else ""


def subscription_userinfo(client: dict) -> str:
    t = ensure_client(client)["traffic"]
    return (f"upload={int(t.get('up') or 0)}; download={int(t.get('down') or 0)}; "
            f"total={gb_to_bytes(client.get('limit_gb'))}; expire={expire_unix(client)}")


# ---------------------------------------------------------------- routing presets

ROUTE_PRESETS = {
    "block_ads": {"name": "block-ads", "outbound": "block", "domain": ["geosite:category-ads-all"]},
    "block_torrent": {"name": "block-torrent", "outbound": "block", "protocol": ["bittorrent"]},
    "block_private": {"name": "block-private-ip", "outbound": "block", "ip": ["geoip:private"]},
    "block_quic": {"name": "block-quic", "outbound": "block", "network": "udp", "port": "443"},
    "direct_ru": {"name": "direct-ru", "outbound": "direct", "domain": ["geosite:category-ru", "regexp:.*\\.ru$"], "ip": ["geoip:ru"]},
    "direct_cn": {"name": "direct-cn", "outbound": "direct", "domain": ["geosite:cn"], "ip": ["geoip:cn"]},
    "direct_ir": {"name": "direct-ir", "outbound": "direct", "domain": ["regexp:.*\\.ir$"], "ip": ["geoip:ir"]},
    "block_porn": {"name": "block-porn", "outbound": "block", "domain": ["geosite:category-porn"]},
}


def _rule_from_route(store: dict, r: dict, *, known_outbounds: set[str] | None = None) -> dict | None:
    if not r.get("enabled", True):
        return None
    target = r.get("outbound") or r.get("outbound_tag") or "direct"
    rule: dict[str, Any] = {"type": "field", **_route_target(store, target, known_outbounds=known_outbounds)}
    for key, xkey in (("domain", "domain"), ("ip", "ip"), ("user", "user"), ("protocol", "protocol"),
                      ("source", "source"), ("inbound_tags", "inboundTag")):
        val = r.get(key)
        if val:
            rule[xkey] = val if isinstance(val, list) else [val]
    for key, xkey in (("network", "network"), ("port", "port"), ("source_port", "sourcePort")):
        if r.get(key):
            rule[xkey] = str(r[key])
    if r.get("name"):
        rule["ruleTag"] = re.sub(r"[^A-Za-z0-9_.-]", "_", str(r["name"]))[:64]
    keys = ("domain", "ip", "user", "protocol", "source", "inboundTag", "network", "port", "sourcePort")
    return rule if any(k in rule for k in keys) else None


# ---------------------------------------------------------------- dns / reverse / settings

def default_xray_settings() -> dict:
    return {"log_level": "warning", "access_log": False, "dns_log": False, "template_patch": {}}


def default_dns() -> dict:
    return {
        "enabled": False,
        "servers": ["https+local://1.1.1.1/dns-query", "8.8.8.8", "localhost"],
        "query_strategy": "UseIP",
        "disable_cache": False,
        "hosts": {},
        "fakedns": {"enabled": False, "pool": "198.18.0.0/15", "size": 65535},
    }


def _ensure_section(store: dict, key: str, default: dict) -> dict:
    cur = store.setdefault(key, {})
    for k, v in default.items():
        cur.setdefault(k, v)
    return cur


def deep_merge(base: Any, patch: Any) -> Any:
    if isinstance(base, dict) and isinstance(patch, dict):
        out = dict(base)
        for k, v in patch.items():
            out[k] = deep_merge(base.get(k), v) if k in base else copy.deepcopy(v)
        return out
    return copy.deepcopy(patch)


# ---------------------------------------------------------------- build

def build_config(store: dict) -> dict:
    ensure_balancers(store)
    inbounds_model = ensure_inbounds(store)
    xs = _ensure_section(store, "xray_settings", default_xray_settings())
    dns = _ensure_section(store, "dns", default_dns())
    fake = (dns.get("fakedns") or {}) if dns.get("enabled") else {}

    clients = [ensure_client(c) for c in store.get("clients") or []]
    active_clients = [c for c in clients if client_access_ok(c)]

    inbounds: list[dict] = []
    for ib in inbounds_model:
        if not inbound_access_ok(ib):
            continue
        identities: list[dict] = []
        for c in active_clients:
            if ib in client_inbounds(store, c):
                identities.extend(client_identities(store, c, ib))
        built = P.build_inbound(ib, identities)
        if fake.get("enabled") and "sniffing" in built:
            dest = built["sniffing"]["destOverride"]
            if "fakedns" not in dest:
                dest.append("fakedns")
        inbounds.append(built)

    inbounds.append({
        "tag": "api", "listen": "127.0.0.1", "port": int(str(XRAY_API).rsplit(":", 1)[-1]),
        "protocol": "dokodemo-door", "settings": {"address": "127.0.0.1"},
    })

    outbounds = [
        {"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "UseIPv4"}},
        {"tag": "block", "protocol": "blackhole", "settings": {}},
    ]
    outbounds.extend(_l2tp_outbounds(store))
    outbounds.extend(_custom_outbounds(store))
    if fake.get("enabled"):
        outbounds.append({"tag": "dns-out", "protocol": "dns"})

    # Build balancers before rules so we know which tags actually exist on this host
    bals_cfg, observatory, burst = _balancers_cfg(store)
    known_outbounds = {o.get("tag") for o in outbounds if o.get("tag")} | {"api"}

    # Rebuild per-inbound rules with known outbound set (first pass used bare _route_target)
    per_inbound_rules = []
    for ib in inbounds_model:
        if not inbound_access_ok(ib):
            continue
        if ib["protocol"] not in P.USER_PROTOCOLS:
            ob = ib.get("outbound") or "direct"
            per_inbound_rules.append(
                {"type": "field", "inboundTag": [ib["tag"]], **_route_target(store, ob, known_outbounds=known_outbounds)}
            )

    rules: list[dict] = [{"type": "field", "inboundTag": ["api"], "outboundTag": "api"}]
    for r in store.get("routes") or []:
        rule = _rule_from_route(store, r, known_outbounds=known_outbounds)
        if rule:
            rules.append(rule)
    for c in active_clients:
        for e in subscription_entries(store, c):
            rules.append({
                "type": "field", "user": [e["email"]],
                **_route_target(store, e["tag"], known_outbounds=known_outbounds),
            })
        ob = c.get("outbound") or "direct"
        if ob != "direct" and not tag_allowed_for_client(c, ob):
            rules.append({"type": "field", "user": [c["email"]], "outboundTag": "block"})
        elif ob != "direct":
            rules.append({
                "type": "field", "user": [c["email"]],
                **_route_target(store, ob, known_outbounds=known_outbounds),
            })
    rules.extend(per_inbound_rules)
    rules.append({"type": "field", "network": "tcp,udp", "outboundTag": "direct"})

    routing: dict[str, Any] = {"domainStrategy": "AsIs", "rules": rules}
    if bals_cfg:
        routing["balancers"] = bals_cfg

    log: dict[str, Any] = {"loglevel": xs.get("log_level") or "warning"}
    if xs.get("access_log"):
        log["access"] = str(XRAY_LOG_DIR / "access.log")
    if xs.get("dns_log"):
        log["dnsLog"] = True

    cfg: dict[str, Any] = {
        "log": log,
        "stats": {},
        "api": {"tag": "api", "services": ["StatsService", "HandlerService", "RoutingService"]},
        "policy": {
            "levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True, "statsUserOnline": True}},
            "system": {"statsInboundUplink": True, "statsInboundDownlink": True,
                       "statsOutboundUplink": True, "statsOutboundDownlink": True},
        },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": routing,
    }
    if observatory:
        cfg["observatory"] = observatory
    if burst:
        cfg["burstObservatory"] = burst

    if dns.get("enabled"):
        servers: list[Any] = list(dns.get("servers") or [])
        if fake.get("enabled"):
            servers = ["fakedns", *servers]
            cfg["fakedns"] = [{"ipPool": fake.get("pool") or "198.18.0.0/15", "poolSize": int(fake.get("size") or 65535)}]
        dns_cfg: dict[str, Any] = {"servers": servers, "queryStrategy": dns.get("query_strategy") or "UseIP"}
        if dns.get("disable_cache"):
            dns_cfg["disableCache"] = True
        if dns.get("hosts"):
            dns_cfg["hosts"] = dns["hosts"]
        cfg["dns"] = dns_cfg

    rev = store.get("reverse") or {}
    if rev.get("bridges") or rev.get("portals"):
        cfg["reverse"] = {
            **({"bridges": [{"tag": b["tag"], "domain": b["domain"]} for b in rev.get("bridges") or []]} if rev.get("bridges") else {}),
            **({"portals": [{"tag": p["tag"], "domain": p["domain"]} for p in rev.get("portals") or []]} if rev.get("portals") else {}),
        }

    patch = xs.get("template_patch") or {}
    if patch:
        cfg = deep_merge(cfg, patch)
    return cfg


def _balancers_cfg(store: dict) -> tuple[list[dict], dict | None, dict | None]:
    """Emit balancers only when they have live members.

    leastPing/leastLoad require observatory/burstObservatory — emitting a balancer
    with selector [direct] and no observatory makes Xray fail with
    'not all dependencies are resolved'. Routes to empty balancers fall back via
    _route_target().
    """
    bals = ensure_balancers(store)
    out: list[dict] = []
    observatory = burst = None
    ping_b = bals.get("least_ping") or {}
    if ping_b.get("enabled", True):
        members = balancer_member_tags(store, ping_b)
        if members:
            out.append({"tag": ping_b["tag"], "selector": members, "fallbackTag": ping_b.get("fallback") or "direct",
                        "strategy": {"type": "leastPing"}})
            observatory = {
                "subjectSelector": sorted(set(members)),
                "probeURL": ping_b.get("probe_url") or "https://www.gstatic.com/generate_204",
                "probeInterval": ping_b.get("probe_interval") or "15s",
                "enableConcurrency": True,
            }
    load_b = bals.get("least_load") or {}
    if load_b.get("enabled", True):
        members = balancer_member_tags(store, load_b)
        if members:
            out.append({
                "tag": load_b["tag"], "selector": members, "fallbackTag": load_b.get("fallback") or "direct",
                "strategy": {"type": "leastLoad", "settings": {
                    "expected": int(load_b.get("expected") or 1), "maxRTT": load_b.get("max_rtt") or "1s",
                    "tolerance": float(load_b.get("tolerance") or 0.15), "baselines": ["1s"]}},
            })
            burst = {
                "subjectSelector": sorted(set(members)),
                "pingConfig": {
                    "destination": load_b.get("probe_url") or "https://www.gstatic.com/generate_204",
                    "interval": load_b.get("probe_interval") or "20s", "timeout": "5s", "sampling": 2,
                    "connectivity": "http://connectivitycheck.gstatic.com/generate_204",
                },
            }
    return out, observatory, burst


def clean_xray_error(text: str) -> str:
    """Drop version banner / deprecation spam; keep the real failure line."""
    raw = (text or "").strip()
    if not raw:
        return ""
    lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
    for ln in reversed(lines):
        low = ln.lower()
        if ln.startswith("Failed to start:") or "not found" in low or "failed to" in low:
            return ln[:500]
    skip = ("xray ", "penetrates", "anti-censorship", "a unified platform", "[info]", "[warning]", "reading config")
    keep = [ln for ln in lines if not any(s in ln.lower() for s in skip)]
    return (" | ".join(keep[-3:]) if keep else lines[-1])[:500]


def test_config(cfg: dict) -> dict:
    """Validate cfg with `xray run -test`. Writes a temp file next to the live config.

    Mandatory for every apply — there is no setting/env/API flag that skips this.
    """
    XRAY_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    if not Path(XRAY_BIN).is_file():
        return {"ok": False, "tmp": None, "error": f"xray binary not found: {XRAY_BIN}"}
    tmp = XRAY_CONFIG.parent / (XRAY_CONFIG.stem + ".tmp.json")
    tmp.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
    test = _run([XRAY_BIN, "run", "-test", "-config", str(tmp)])
    err = clean_xray_error(test["stderr"] or test["stdout"])
    return {"ok": test["exit_code"] == 0, "tmp": tmp, "error": err}


def _xray_active() -> bool:
    return (_run(["systemctl", "is-active", "xray"])["stdout"] or "").strip() == "active"


def _restart_xray() -> dict:
    _run(["systemctl", "enable", "xray"])
    return _run(["systemctl", "restart", "xray"], timeout=30)


def _restore_prev_config() -> str:
    """Restore the last known-good config and restart. Returns error text (empty if OK)."""
    if not XRAY_CONFIG_PREV.is_file():
        return "previous config missing; cannot roll back"
    try:
        shutil.copy2(XRAY_CONFIG_PREV, XRAY_CONFIG)
        os.chmod(XRAY_CONFIG, 0o644)
    except OSError as exc:
        return f"rollback copy failed: {exc}"
    restart = _restart_xray()
    if _xray_active():
        return ""
    return restart["stderr"] or restart["stdout"] or "xray still inactive after rollback"


def apply_config(store: dict) -> dict:
    """Build, verify, then atomically install Xray config. Never skips verification.

    Flow (hardcoded, not configurable):
      1. build JSON
      2. `xray run -test` — reject without touching the live file
      3. keep a copy of the previous live config
      4. replace live config + restart
      5. if Xray is not active — restore previous config and restart again
    """
    try:
        harvest_traffic(store)
        enforce_quotas(store)
    except Exception:
        pass
    for c in store.get("clients") or []:
        ensure_client(c)
        ensure_wg_peer(store, c)
    cfg = build_config(store)
    if (store.get("xray_settings") or {}).get("access_log"):
        XRAY_LOG_DIR.mkdir(parents=True, exist_ok=True)

    t = test_config(cfg)
    if not t["ok"]:
        if t.get("tmp"):
            try:
                t["tmp"].unlink()
            except OSError:
                pass
        return {"ok": False, "error": t["error"] or "xray config test failed", "verified": False}

    # Snapshot the currently running config before we touch it.
    if XRAY_CONFIG.is_file():
        try:
            shutil.copy2(XRAY_CONFIG, XRAY_CONFIG_PREV)
        except OSError as exc:
            try:
                t["tmp"].unlink()
            except OSError:
                pass
            return {"ok": False, "error": f"cannot backup current config: {exc}", "verified": False}

    os.replace(t["tmp"], XRAY_CONFIG)
    try:
        os.chmod(XRAY_CONFIG, 0o644)
    except OSError:
        pass

    restart = _restart_xray()
    if _xray_active():
        ban_inbound_ports(store)
        return {"ok": True, "error": "", "config": cfg, "verified": True}

    # New config passed -test but broke the running service — roll back.
    rb = _restore_prev_config()
    detail = restart["stderr"] or restart["stdout"] or "xray not active after restart"
    if rb:
        return {
            "ok": False,
            "error": f"{detail}; rollback failed: {rb}",
            "config": cfg,
            "verified": True,
            "rolled_back": False,
        }
    return {
        "ok": False,
        "error": f"{detail}; previous config restored",
        "config": cfg,
        "verified": True,
        "rolled_back": True,
    }


PORTBAN_CHAIN = "L2X_PORTBAN"


def ban_inbound_ports(store: dict) -> None:
    """Drop incoming non-loopback traffic to every inbound port: clients reach Xray only via nginx :443."""
    # 2096/2053 — legacy dedicated listeners; never expose them (subs/panel live on :443)
    ports = sorted(({int(ib["port"]) for ib in ensure_inbounds(store)} | {2096, 2053}) - P.RESERVED_PORTS)
    for tool in ("iptables", "ip6tables"):
        if not shutil.which(tool):
            continue
        if _run([tool, "-L", PORTBAN_CHAIN, "-n"])["exit_code"] != 0:
            _run([tool, "-N", PORTBAN_CHAIN])
        _run([tool, "-F", PORTBAN_CHAIN])
        for port in ports:
            for proto in ("tcp", "udp"):
                _run([tool, "-A", PORTBAN_CHAIN, "!", "-i", "lo", "-p", proto, "--dport", str(port), "-j", "DROP"])
                # ACCEPT rules left by older panel versions that published inbounds directly
                while _run([tool, "-D", "INPUT", "-p", proto, "--dport", str(port), "-j", "ACCEPT"])["exit_code"] == 0:
                    pass
        # always first in INPUT, so no ACCEPT added later (by hand or by other tools) can bypass it
        while _run([tool, "-D", "INPUT", "-j", PORTBAN_CHAIN])["exit_code"] == 0:
            pass
        _run([tool, "-I", "INPUT", "1", "-j", PORTBAN_CHAIN])


def xray_status() -> dict:
    active = (_run(["systemctl", "is-active", "xray"])["stdout"] or "").strip()
    ver = (_run([XRAY_BIN, "version"])["stdout"] or "").splitlines()
    return {"active": active == "active", "state": active, "version": ver[0].split()[1] if ver and len(ver[0].split()) > 1 else ""}


# ---------------------------------------------------------------- stats

def query_stats(pattern: str = "", reset: bool = False) -> dict[str, int]:
    cmd = [XRAY_BIN, "api", "statsquery", f"--server={XRAY_API}"]
    if pattern:
        cmd += ["-pattern", pattern]
    if reset:
        cmd.append("-reset")
    r = _run(cmd, timeout=15)
    out: dict[str, int] = {}
    if r["exit_code"] != 0:
        return out
    try:
        data = json.loads(r["stdout"] or "{}")
        for st in data.get("stat") or []:
            out[st.get("name") or ""] = int(st.get("value") or 0)
    except ValueError:
        for m in re.finditer(r'name:\s*"([^"]+)"\s+value:\s*(\d+)', r["stdout"] or ""):
            out[m.group(1)] = int(m.group(2))
    return out


def query_user_stats() -> dict[str, dict[str, int]]:
    result: dict[str, dict[str, int]] = {}
    for name, value in query_stats("user>>>").items():
        parts = name.split(">>>")
        if len(parts) == 4 and parts[2] == "traffic":
            row = result.setdefault(parts[1], {"up": 0, "down": 0})
            row["up" if parts[3] == "uplink" else "down"] = value
    return result


def query_online() -> dict[str, dict[str, int]]:
    """{email: {ip: last_seen_unix}} for currently online users."""
    r = _run([XRAY_BIN, "api", "statsonlineiplist", f"--server={XRAY_API}", "-all"], timeout=15)
    out: dict[str, dict[str, int]] = {}
    if r["exit_code"] != 0 or not (r["stdout"] or "").strip():
        return out
    try:
        data = json.loads(r["stdout"])
    except ValueError:
        return out
    users = data.get("users") if isinstance(data, dict) else data
    if isinstance(users, dict):
        users = [{"email": k, **(v if isinstance(v, dict) else {"ips": v})} for k, v in users.items()]
    for u in users or []:
        name = str(u.get("email") or u.get("name") or "")
        name = name.replace("user>>>", "").replace(">>>online", "")
        ips = u.get("ips") or u.get("ip_list") or u.get("ipList") or {}
        if isinstance(ips, list):
            ips = {str(i.get("ip") if isinstance(i, dict) else i):
                   int((i.get("lastSeen") or i.get("time") or i.get("last_seen") or 0) if isinstance(i, dict) else 0)
                   for i in ips}
        if name:
            out[name] = {str(k): int(v or 0) for k, v in dict(ips).items()}
    return out


def _accumulate(row: dict, up: int, down: int) -> bool:
    changed = False
    for key, last_key, cur_v in (("up", "last_up", up), ("down", "last_down", down)):
        last_v = int(row.get(last_key) or 0)
        delta = cur_v - last_v if cur_v >= last_v else cur_v
        if delta:
            row[key] = int(row.get(key) or 0) + delta
            changed = True
        if cur_v != last_v:
            row[last_key] = cur_v
            changed = True
    return changed


def harvest_traffic(store: dict) -> bool:
    stats = query_stats("")
    if not stats:
        return False
    changed = False
    users: dict[str, dict[str, int]] = {}
    inb: dict[str, dict[str, int]] = {}
    outb: dict[str, dict[str, int]] = {}
    for name, value in stats.items():
        parts = name.split(">>>")
        if len(parts) != 4 or parts[2] != "traffic":
            continue
        bucket = {"user": users, "inbound": inb, "outbound": outb}.get(parts[0])
        if bucket is None:
            continue
        row = bucket.setdefault(parts[1], {"up": 0, "down": 0})
        row["up" if parts[3] == "uplink" else "down"] = value

    now_iso = now_utc().isoformat()
    for client in store.get("clients") or []:
        ensure_client(client)
        by = client["traffic"]["by_email"]
        emails = {client["email"]} | {e["email"] for e in subscription_entries(store, client, ignore_quota=True)}
        active = False
        for email in emails:
            cur = users.get(email)
            if not cur:
                continue
            row = by.setdefault(email, {"up": 0, "down": 0, "last_up": 0, "last_down": 0})
            before = int(row.get("up") or 0) + int(row.get("down") or 0)
            if _accumulate(row, cur["up"], cur["down"]):
                changed = True
            if int(row.get("up") or 0) + int(row.get("down") or 0) > before:
                active = True
        up = sum(int(r.get("up") or 0) for r in by.values())
        down = sum(int(r.get("down") or 0) for r in by.values())
        if client["traffic"].get("up") != up or client["traffic"].get("down") != down:
            client["traffic"]["up"], client["traffic"]["down"] = up, down
            changed = True
        if active:
            client["last_online"] = now_iso
            changed = True

    for ib in ensure_inbounds(store):
        cur = inb.get(ib["tag"])
        if cur and _accumulate(ib["traffic"], cur["up"], cur["down"]):
            changed = True

    ot = store.setdefault("outbound_traffic", {})
    for tag, cur in outb.items():
        if tag == "api":
            continue
        row = ot.setdefault(tag, {"up": 0, "down": 0, "last_up": 0, "last_down": 0})
        if _accumulate(row, cur["up"], cur["down"]):
            changed = True
    return changed


def reset_client_traffic(client: dict) -> None:
    by = ensure_client(client)["traffic"]["by_email"]
    for row in by.values():
        row["up"] = row["down"] = 0
    client["traffic"]["up"] = client["traffic"]["down"] = 0
    client["quota_exceeded"] = False
    client["tag_exceeded"] = {}
    # Allow a fresh one-shot low-traffic Telegram alert after reset
    client.pop("tg_notify_low_gb", None)


def _period_delta(period: str, base: datetime) -> datetime:
    if period == "monthly":
        month = base.month + 1
        year = base.year + (month - 1) // 12
        month = (month - 1) % 12 + 1
        day = min(base.day, 28)
        return base.replace(year=year, month=month, day=day)
    days = RESET_PERIODS.get(period) or 0
    return base + timedelta(days=days)


def enforce_quotas(store: dict) -> bool:
    """Delayed start, auto-reset, expiry and quota flags. True → Xray rebuild needed."""
    changed = False
    events: list[dict] = store.setdefault("_events", [])
    now = now_utc()
    for client in store.get("clients") or []:
        ensure_client(client)
        if client.get("start_on_first_use") and not client.get("expire_at") and client_used_bytes(client) > 0:
            days = int(client.get("duration_days") or 0)
            if days > 0:
                client["expire_at"] = (now + timedelta(days=days)).isoformat(timespec="seconds")
                client["start_on_first_use"] = False
                changed = True
        period = client.get("reset_period") or ""
        if period:
            nxt = parse_expire_at(client.get("next_reset"))
            if not nxt:
                client["next_reset"] = _period_delta(period, now).isoformat(timespec="seconds")
            elif now >= nxt:
                reset_client_traffic(client)
                if client.get("renew_on_reset") and client.get("expire_at"):
                    exp = parse_expire_at(client["expire_at"]) or now
                    client["expire_at"] = _period_delta(period, max(exp, now)).isoformat(timespec="seconds")
                client["next_reset"] = _period_delta(period, now).isoformat(timespec="seconds")
                events.append({"type": "auto_reset", "email": client["email"]})
                changed = True
        for flag, value in (("expired", client_is_expired(client)), ("quota_exceeded", client_total_exceeded(client))):
            if bool(client.get(flag)) != value:
                client[flag] = value
                changed = True
                if value:
                    events.append({"type": flag, "email": client["email"]})
        flags = client.setdefault("tag_exceeded", {})
        for tag in set((client.get("outbound_limits") or {}).keys()) | set(client.get("allowed_tags") or []):
            hit = client_tag_exceeded(client, tag)
            if bool(flags.get(tag)) != hit:
                flags[tag] = hit
                changed = True
                if hit:
                    events.append({"type": "tag_exceeded", "email": client["email"], "tag": tag})
    for ib in ensure_inbounds(store):
        period = ib.get("traffic_reset") or "never"
        if period and period != "never":
            nxt = parse_expire_at(ib.get("next_reset"))
            if not nxt:
                ib["next_reset"] = _period_delta(period, now).isoformat(timespec="seconds")
                changed = True
            elif now >= nxt:
                t = ib.setdefault("traffic", {})
                t["up"] = t["down"] = 0
                ib["next_reset"] = _period_delta(period, now).isoformat(timespec="seconds")
                events.append({"type": "inbound_reset", "tag": ib.get("tag")})
                changed = True
        ok = inbound_access_ok(ib)
        if bool(ib.get("_blocked")) == ok:
            ib["_blocked"] = not ok
            changed = True
    del events[:-200]
    return changed


# ---------------------------------------------------------------- online / IP limit

def update_online(store: dict, online: dict[str, dict[str, int]]) -> dict[str, list[str]]:
    """Attach online IPs to clients. Returns {client_email: [ips]}."""
    now = now_utc()
    result: dict[str, list[str]] = {}
    for client in store.get("clients") or []:
        ensure_client(client)
        emails = {client["email"]} | {e["email"] for e in subscription_entries(store, client, ignore_quota=True)}
        ips: dict[str, int] = {}
        for email in emails:
            for ip, ts in (online.get(email) or {}).items():
                ips[ip] = max(ips.get(ip, 0), ts)
        if ips:
            result[client["email"]] = sorted(ips, key=lambda i: ips[i])
            client["last_online"] = now.isoformat()
            log = client.setdefault("ips", {})
            for ip, ts in ips.items():
                log[ip] = datetime.fromtimestamp(ts, timezone.utc).isoformat() if ts else now.isoformat()
            if len(log) > 50:
                for ip in sorted(log, key=lambda i: log[i])[:-50]:
                    log.pop(ip, None)
    return result


def _ensure_iplimit_chain() -> None:
    if _run(["iptables", "-L", IPLIMIT_CHAIN, "-n"])["exit_code"] != 0:
        _run(["iptables", "-N", IPLIMIT_CHAIN])
    if _run(["iptables", "-C", "INPUT", "-j", IPLIMIT_CHAIN])["exit_code"] != 0:
        _run(["iptables", "-I", "INPUT", "1", "-j", IPLIMIT_CHAIN])


def enforce_ip_limits(store: dict, online_by_client: dict[str, list[str]], ban_minutes: int = 30) -> list[dict]:
    """Ban newest IPs beyond limit_ip via iptables; unban expired. Returns new bans."""
    bans = store.setdefault("ip_bans", [])
    now = now_utc()
    keep = []
    for b in bans:
        if (parse_expire_at(b.get("until")) or now) <= now:
            _run(["iptables", "-D", IPLIMIT_CHAIN, "-s", b["ip"], "-j", "DROP"])
        else:
            keep.append(b)
    store["ip_bans"] = bans = keep
    banned = {b["ip"] for b in bans}
    new: list[dict] = []
    for client in store.get("clients") or []:
        limit = int(client.get("limit_ip") or 0)
        ips = online_by_client.get(client["email"]) or []
        if limit <= 0 or len(ips) <= limit:
            continue
        _ensure_iplimit_chain()
        for ip in ips[limit:]:
            if ip in banned:
                continue
            _run(["iptables", "-I", IPLIMIT_CHAIN, "-s", ip, "-j", "DROP"])
            item = {"ip": ip, "email": client["email"], "since": now.isoformat(),
                    "until": (now + timedelta(minutes=ban_minutes)).isoformat()}
            bans.append(item)
            new.append(item)
            banned.add(ip)
            _record_ban(store, ip, client["email"], now.isoformat())
    return new


def _record_ban(store: dict, ip: str, email: str, when: str) -> None:
    """Lifetime per-IP ban counter (survives unban and expiry)."""
    st = store.setdefault("ip_ban_stats", {}).setdefault(ip, {"count": 0, "first": when, "emails": []})
    st["count"] = int(st.get("count") or 0) + 1
    st["last"] = when
    if email and email not in st["emails"]:
        st["emails"].append(email)


def unban_ip(store: dict, ip: str) -> None:
    _run(["iptables", "-D", IPLIMIT_CHAIN, "-s", ip, "-j", "DROP"])
    store["ip_bans"] = [b for b in store.get("ip_bans") or [] if b.get("ip") != ip]


def forget_ip(store: dict, ip: str) -> None:
    """Reset the ban counter of an IP (does not unban it)."""
    (store.get("ip_ban_stats") or {}).pop(ip, None)


def ban_overview(store: dict) -> tuple[list[dict], list[dict]]:
    """(active bans with counters, history of every IP ever banned — most banned first)."""
    stats = store.get("ip_ban_stats") or {}
    now = now_utc()
    active = []
    for b in store.get("ip_bans") or []:
        until = parse_expire_at(b.get("until"))
        active.append({**b, "count": int((stats.get(b["ip"]) or {}).get("count") or 1),
                       "left_min": max(0, int(((until or now) - now).total_seconds() // 60))})
    active.sort(key=lambda b: b.get("since") or "", reverse=True)
    banned = {b["ip"] for b in active}
    history = [{"ip": ip, **v, "active": ip in banned} for ip, v in stats.items()]
    history.sort(key=lambda h: (-int(h.get("count") or 0), h.get("last") or ""))
    return active, history


# ---------------------------------------------------------------- outbound test

def test_outbound(store: dict, tag: str, url: str = "https://www.gstatic.com/generate_204", timeout: int = 10) -> dict:
    """Spin a throwaway Xray with socks→outbound and time a request through it."""
    import socket
    import time

    ob = None
    for o in _l2tp_outbounds(store) + _custom_outbounds(store):
        if o["tag"] == tag:
            ob = copy.deepcopy(o)
    if tag == "direct":
        ob = {"tag": "direct", "protocol": "freedom"}
    if not ob:
        return {"ok": False, "error": "outbound не найден или не активен"}
    ob["tag"] = "out"
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    cfg = {
        "log": {"loglevel": "error"},
        "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": {"udp": False}}],
        "outbounds": [ob],
    }
    path = Path(f"/tmp/l2x-obtest-{port}.json")
    path.write_text(json.dumps(cfg), encoding="utf-8")
    proc = subprocess.Popen([XRAY_BIN, "run", "-c", str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(0.8)
        r = _run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code} %{time_total}", "--max-time", str(timeout),
                  "--socks5-hostname", f"127.0.0.1:{port}", url], timeout=timeout + 5)
        parts = (r["stdout"] or "").split()
        code = parts[0] if parts else "000"
        ms = int(float(parts[1]) * 1000) if len(parts) > 1 else 0
        ok = code.startswith("2") or code.startswith("3")
        return {"ok": ok, "code": code, "ms": ms, "error": "" if ok else (r["stderr"] or f"HTTP {code}")}
    finally:
        proc.terminate()
        try:
            path.unlink()
        except OSError:
            pass


EMAIL_RE = re.compile(r"^[^\s@~]+@[^\s@~]+$|^[A-Za-z0-9][A-Za-z0-9_.+\-]{0,63}$")
TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,40}$")
