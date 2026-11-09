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
BALANCER_RANDOM = "lb_random"
BALANCER_LABELS = {
    BALANCER_LEAST_PING: "⚡ Авто: наименьший пинг",
    BALANCER_LEAST_LOAD: "⚖️ Авто: наименьшая загрузка",
    BALANCER_RANDOM: "🎲 Авто: распределение по живым",
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
        # Spreads connections across currently live outbounds (panel health gate + Xray random).
        "random": {
            "tag": BALANCER_RANDOM, "enabled": True, "strategy": "random", "members": [],
            "probe_url": "https://www.gstatic.com/generate_204", "probe_interval": "15s", "fallback": "direct",
        },
    }


def balancer_fallback_tag(balancer: dict) -> str:
    """Outbound used when all balancer members are down.

    ``none`` / empty → ``block`` (blackhole). Must always set Xray ``fallbackTag``:
    if omitted and Observatory marks every member dead, Xray returns an empty pick
    and falls through to the default outbound (first in list = ``direct``).
    """
    fb = str(balancer.get("fallback") or "").strip()
    if not fb or fb.lower() in ("none", "-", "off", "null"):
        return "block"
    return fb


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


def sub_health_settings(store: dict) -> dict:
    """Subscription health gate: hide disconnected / high-loss outbounds from client links."""
    sub = ((store.get("settings") or {}).get("sub") or {})
    try:
        max_loss = float(sub.get("max_loss_pct") if sub.get("max_loss_pct") not in (None, "") else 20)
    except (TypeError, ValueError):
        max_loss = 20.0
    return {
        "hide_unhealthy": bool(sub.get("hide_unhealthy", True)),
        "max_loss_pct": max(0.0, min(100.0, max_loss)),
    }


def custom_outbound_status(o: dict) -> str:
    """UI status: enabled + successful probe → connected; explicit fail → disconnected."""
    if not o.get("enabled", True):
        return "disabled"
    lt = o.get("last_test")
    if isinstance(lt, dict) and lt.get("ok") is True:
        return "connected"
    if isinstance(lt, dict) and lt.get("ok") is False:
        return "disconnected"
    # Not probed yet — treat as live for UI until first fail
    return "connected"


def custom_outbound_healthy(o: dict) -> bool:
    """Standalone custom may appear in subscription (hide on explicit probe fail)."""
    if not o.get("enabled", True):
        return False
    lt = o.get("last_test")
    if isinstance(lt, dict) and lt.get("ok") is False:
        return False
    return True


def _reverse_portal_member_ok(store: dict, outbound: dict) -> bool:
    """NAT/reverse portal is live only while the node keeps the tunnel up."""
    try:
        import nodes as nodes_mod
        node = next(
            (n for n in nodes_mod.ensure_list(store) if n.get("id") == outbound.get("node_id")),
            None,
        )
    except Exception:
        node = None
    if not node or not node.get("enabled", True):
        return False
    if node.get("online") is False:
        return False
    try:
        import nodes as nodes_mod
        if node.get("nat") or nodes_mod.uses_reverse(node):
            if not nodes_mod.pull_fresh(node):
                return False
            if node.get("reverse_ok") is False:
                return False
            conns = node.get("rv_conns")
            if isinstance(conns, int) and conns <= 0:
                return False
    except Exception:
        return False
    return True


def outbound_member_ok(store: dict, tag: str) -> bool:
    """Whether tag can sit in a balancer selector / Xray observatory pool.

    Custom dial outbounds are included when enabled — Xray observatory does the
    live probe. Requiring panel last_test here emptied balancers after sync/probe
    and wiped subscription configs for clients that only use leastPing/leastLoad.
    Reverse/NAT portals have no dial path: gate on pull/online instead.
    """
    tag = str(tag or "").strip()
    if not tag or tag in ("direct", "block", "blackhole"):
        return True
    max_loss = sub_health_settings(store)["max_loss_pct"]
    for t in store.get("l2tp") or []:
        if _l2tp_tag(t) != tag:
            continue
        if t.get("status") != "connected":
            return False
        metrics = t.get("metrics") or {}
        loss = metrics.get("loss_pct")
        try:
            if loss is not None and float(loss) > max_loss:
                return False
        except (TypeError, ValueError):
            pass
        return True
    for o in store.get("outbounds_custom") or []:
        if o.get("tag") != tag:
            continue
        if not o.get("enabled", True):
            return False
        if o.get("reverse") or (o.get("kind") == "node" and not (o.get("config") or {})):
            return _reverse_portal_member_ok(store, o)
        return True
    return True


def outbound_ok_for_sub(store: dict, tag: str, *, _seen: set[str] | None = None) -> bool:
    """Whether an outbound/balancer tag may appear in a client subscription."""
    tag = str(tag or "").strip()
    if not tag or tag in ("direct", "block", "blackhole"):
        return True
    cfg = sub_health_settings(store)
    if not cfg["hide_unhealthy"]:
        return True
    seen = _seen if _seen is not None else set()
    if tag in seen:
        return False
    seen.add(tag)

    for t in store.get("l2tp") or []:
        if _l2tp_tag(t) != tag:
            continue
        return outbound_member_ok(store, tag)

    for o in store.get("outbounds_custom") or []:
        if o.get("tag") != tag:
            continue
        if not o.get("in_sub", True):
            return False
        return custom_outbound_healthy(o)

    for b in ensure_balancers(store).values():
        if b.get("tag") != tag:
            continue
        if not b.get("enabled", True):
            return False
        # Enabled balancers always appear in subscription. Member pool may be empty
        # (no L2TP / customs down) — Xray then uses fallback; clients still get links.
        return True

    return True


def balancer_auto_pool(store: dict) -> list[str]:
    """Default balancer pool when members is empty: connected L2TP + enabled customs."""
    connected = connected_l2tp_tags(store)
    seen = set(connected)
    out = list(connected)
    for o in store.get("outbounds_custom") or []:
        if not o.get("enabled", True):
            continue
        tag = o.get("tag")
        if not tag or tag in seen:
            continue
        seen.add(tag)
        out.append(tag)
    return out


def balancer_member_tags(store: dict, balancer: dict, *, healthy_only: bool = False) -> list[str]:
    """explicit members ∩ live outbounds; empty members → auto pool (L2TP + enabled customs)."""
    connected = connected_l2tp_tags(store)
    members = balancer.get("members") or []
    if not members:
        pool_list = balancer_auto_pool(store)
    else:
        custom = {o["tag"] for o in store.get("outbounds_custom") or [] if o.get("enabled", True)}
        pool = set(connected) | custom
        pool_list = [t for t in members if t in pool]
    if not healthy_only or not sub_health_settings(store)["hide_unhealthy"]:
        return pool_list
    return [t for t in pool_list if outbound_member_ok(store, t)]


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
            "streamSettings": {
                "sockopt": {
                    "interface": t.get("ifname") or f"l2x-{t['name']}",
                    "tcpCongestion": "bbr",
                    "tcpNoDelay": True,
                },
            },
        })
    return out


def _custom_outbounds(store: dict) -> list[dict]:
    out = []
    for o in store.get("outbounds_custom") or []:
        if not o.get("enabled", True):
            continue
        # Reverse/NAT node outbounds are Xray portals (no dial config)
        if o.get("reverse") or (o.get("kind") == "node" and not (o.get("config") or {})):
            continue
        cfg = copy.deepcopy(o.get("config") or {})
        if not cfg:
            continue
        # Panel-only markers (not part of Xray schema)
        cfg.pop("piaHostname", None)
        cfg["tag"] = o["tag"]
        out.append(cfg)
    return out


def reverse_nat_nodes(store: dict) -> list[dict]:
    """Enabled NAT nodes used as reverse outbounds (portal tags)."""
    try:
        import nodes as nodes_mod
        nodes = nodes_mod.ensure_list(store)
    except Exception:
        nodes = store.get("nodes") or []
    out = []
    for n in nodes:
        if not n.get("enabled", True) or not n.get("as_outbound") or not (n.get("nat") or n.get("rv_mode")):
            continue
        try:
            import nodes as nodes_mod
            nodes_mod.ensure_reverse(n)
        except Exception:
            continue
        out.append(n)
    return out


def reverse_portal_tags(store: dict) -> list[str]:
    """Outbound tags created by VLESS reverse (inbound clients[].reverse.tag)."""
    tags: list[str] = []
    for n in reverse_nat_nodes(store):
        tag = n.get("rv_tag") or f"node_{n.get('name') or 'node'}"
        if tag and tag not in tags:
            tags.append(tag)
    # Custom outbounds marked reverse (portal only)
    for o in store.get("outbounds_custom") or []:
        if o.get("enabled", True) and o.get("reverse") and o.get("tag") and o["tag"] not in tags:
            tags.append(o["tag"])
    return tags


def _direct_tls_cert(store: dict, ib: dict, built: dict) -> None:
    """Direct-port TLS without explicit cert files: reuse the domain certificate nginx/ACME manages."""
    ss = built.get("streamSettings") or {}
    if ss.get("security") != "tls":
        return
    tls = ss.setdefault("tlsSettings", {})
    certs = [c for c in tls.get("certificates") or [] if c.get("certificateFile") and c.get("keyFile")]
    if certs:
        tls["certificates"] = certs
        return
    try:
        import front as front_mod
        t = (ib.get("stream") or {}).get("tls") or {}
        domain = front_mod.normalize_host(t.get("server_name") or ib.get("share_host") or "")
        if not front_mod.is_domain(domain):
            domain = front_mod.public_domain(store)
        if not domain:
            return
        crt, key, _ = front_mod.cert_for(domain)
    except Exception:
        return
    tls["certificates"] = [{"certificateFile": crt, "keyFile": key, "ocspStapling": 3600}]
    if not tls.get("serverName"):
        tls["serverName"] = domain


def _front_raw_tls(store: dict, ib: dict, built: dict) -> None:
    """Plain RAW on :443: Xray terminates TLS (public cert); non-proxy traffic falls back to nginx."""
    try:
        import front as front_mod
        sel = front_mod.raw_front_inbound(store)
        if not sel or sel.get("tag") != ib.get("tag"):
            return
        domain = front_mod.public_domain(store)
        crt, key, _ = front_mod.cert_for(domain)
    except Exception:
        return
    ss = built.setdefault("streamSettings", {})
    ss["security"] = "tls"
    ss["tlsSettings"] = {
        "serverName": domain,
        "alpn": ["h2", "http/1.1"],
        "minVersion": "1.2",
        # Re-read certificate files hourly so Let's Encrypt renewals apply without restart
        "certificates": [{"certificateFile": crt, "keyFile": key, "ocspStapling": 3600}],
    }
    built.setdefault("settings", {})["fallbacks"] = [
        {"alpn": "h2", "dest": P.FRONT_FALLBACK_H2_PORT, "xver": 1},
        {"dest": P.FRONT_FALLBACK_H1_PORT, "xver": 1},
    ]


def _inject_reverse(store: dict, cfg: dict) -> None:
    """VLESS Reverse Proxy (Xray ≥ 25.10; legacy bridge/portal is removed from core).

    Master: rv-in inbound whose clients carry reverse.tag = node_… (routable outbound).
    NAT agent: VLESS outbound with reverse.tag dials master; traffic arriving on that
    tag goes to direct (node egress).
    """
    import nodes as nodes_mod

    cfg.pop("reverse", None)

    # --- NAT agent: dial master, expose reverse inbound tag locally ---
    ns = (store.get("settings") or {}).get("nodes") or {}
    rb = ns.get("reverse_bridge") if isinstance(ns.get("reverse_bridge"), dict) else None
    if rb and rb.get("uuid") and rb.get("path") and rb.get("master_host"):
        in_tag = "rv-bridge"
        direct_tag = "rv-direct"
        net = (rb.get("network") or "xhttp").lower()
        if net not in ("xhttp", "ws"):
            net = "xhttp"
        dials = max(1, min(16, int(rb.get("dials") or 4)))
        outs = cfg.setdefault("outbounds", [])
        outs[:] = [
            o for o in outs
            if not (str(o.get("tag") or "").startswith("rv-up") or o.get("tag") == direct_tag)
        ]
        # Xray ≥26.5: vless-reverse traffic is blackholed unless freedom has finalRules allow.
        # Match official "home broadband egress" example: allow public internet via reverse.
        outs.append({
            "tag": direct_tag,
            "protocol": "freedom",
            "settings": {
                "finalRules": [{
                    "action": "allow",
                    "network": "tcp,udp",
                    "ip": ["!geoip:private"],
                }],
            },
        })
        tls = {
            "serverName": rb["master_host"],
            "allowInsecure": False,
            "fingerprint": rb.get("fingerprint") or "chrome",
            "alpn": ["h2", "http/1.1"] if net == "xhttp" else ["http/1.1"],
        }
        sockopt = {
            "tcpFastOpen": True,
            "tcpCongestion": "bbr",
            "tcpNoDelay": True,
        }
        for i in range(dials):
            tag = "rv-up" if dials == 1 else f"rv-up-{i}"
            stream: dict = {"network": net, "security": "tls", "tlsSettings": tls, "sockopt": sockopt}
            if net == "xhttp":
                # maxConcurrency=1 → more TCP/H2 under concurrent load (better multi-thread speed)
                stream["xhttpSettings"] = {
                    "path": rb["path"],
                    "host": rb["master_host"],
                    "mode": rb.get("mode") or "stream-up",
                    "xmux": {"maxConcurrency": 1},
                }
            else:
                stream["wsSettings"] = {
                    "path": rb["path"],
                    "host": rb["master_host"],
                    "heartbeatPeriod": 10,
                }
            outs.append({
                "tag": tag,
                "protocol": "vless",
                "settings": {
                    "address": rb["master_host"],
                    "port": int(rb.get("port") or 443),
                    "id": rb["uuid"],
                    "encryption": "none",
                    "flow": "",
                    "reverse": {"tag": in_tag},
                },
                "streamSettings": stream,
            })
        rules = cfg.setdefault("routing", {}).setdefault("rules", [])
        rules[:] = [
            r for r in rules
            if not (
                r.get("inboundTag") in ([in_tag], ["rv-in"], ["rv-bridge"])
                and r.get("outboundTag") in ("direct", direct_tag, "rv-direct")
            )
        ]
        rules.insert(1 if rules else 0, {
            "type": "field", "inboundTag": [in_tag], "outboundTag": direct_tag,
        })
        # Larger buffers help high-BDP reverse tunnels (never lower an existing value)
        try:
            levels = cfg.setdefault("policy", {}).setdefault("levels", {})
            lvl = levels.setdefault("0", {})
            if int(lvl.get("bufferSize") or 0) < 1024:
                lvl["bufferSize"] = 1024
        except Exception:
            pass
        return

    # --- Master: shared reverse inbound behind nginx Path ---
    nat_nodes = reverse_nat_nodes(store)
    if not nat_nodes:
        return
    rv = nodes_mod.ensure_reverse_master(store)
    path = rv.get("path") or "/xh-rv"
    port = int(rv.get("port") or 19100)
    net = (rv.get("network") or "xhttp").lower()
    if net not in ("xhttp", "ws"):
        net = "xhttp"
    clients = []
    for n in nat_nodes:
        email = f"rv@{nodes_mod.slugify(n.get('name') or 'node')}"
        tag = n.get("rv_tag") or nodes_mod.node_outbound_tag(n)
        clients.append({
            "id": n["rv_uuid"], "email": email, "level": 0, "flow": "",
            "reverse": {"tag": tag},
        })
        n["rv_email"] = email
    if net == "xhttp":
        # Server "auto" accepts stream-up / stream-one / packet-up from agents
        stream = {
            "network": "xhttp",
            "security": "none",
            "xhttpSettings": {"path": path, "mode": "auto"},
        }
    else:
        stream = {
            "network": "ws",
            "security": "none",
            "wsSettings": {"path": path, "heartbeatPeriod": 10},
        }
    ib = {
        "tag": "rv-in",
        "listen": "127.0.0.1",
        "port": port,
        "protocol": "vless",
        "settings": {"clients": clients, "decryption": "none"},
        "streamSettings": stream,
    }
    # Panel-shaped inbound must exist before front.stage() so nginx publishes the path
    ensure_reverse_front_inbound(store)

    # Raw inbound: build_inbound would drop clients[].reverse
    inbounds = [i for i in cfg.setdefault("inbounds", []) if i.get("tag") != "rv-in"]
    inbounds.append(ib)
    cfg["inbounds"] = inbounds
    try:
        levels = cfg.setdefault("policy", {}).setdefault("levels", {})
        lvl = levels.setdefault("0", {})
        if int(lvl.get("bufferSize") or 0) < 1024:
            lvl["bufferSize"] = 1024
    except Exception:
        pass


def ensure_reverse_front_inbound(store: dict) -> dict | None:
    """Register/update the panel-shaped rv-in inbound so nginx publishes its Path on :443.

    Must run BEFORE front.stage() — otherwise the first apply after enabling reverse
    reloads nginx without the reverse location and agents cannot dial the tunnel.
    """
    try:
        import nodes as nodes_mod
    except Exception:
        return None
    if not reverse_nat_nodes(store):
        return None
    rv = nodes_mod.ensure_reverse_master(store)
    path = rv.get("path") or "/xh-rv"
    port = int(rv.get("port") or 19100)
    net = (rv.get("network") or "xhttp").lower()
    if net not in ("xhttp", "ws"):
        net = "xhttp"
    panel_ibs = store.setdefault("inbounds", [])
    existing = next((i for i in panel_ibs if i.get("tag") == "rv-in"), None)
    share = ""
    try:
        import front as front_mod
        share = front_mod.public_domain(store) or ""
    except Exception:
        pass
    shape = {
        "id": existing.get("id") if existing else 9100,
        "tag": "rv-in",
        "remark": "NAT reverse (master)",
        "enabled": True,
        "listen": "127.0.0.1",
        "port": port,
        "protocol": "vless",
        "share_host": share,
        "settings": {"flow": "", "decryption": "none", "encryption": ""},
        "stream": {
            "network": net,
            "security": "none",
            "fingerprint": "chrome",
            "ws": {"path": path if net == "ws" else "/ws", "host": "", "headers": "", "heartbeat": 10, "accept_proxy_protocol": False},
            "tls": {}, "reality": {}, "raw": {"header": "none"}, "grpc": {}, "httpupgrade": {},
            "xhttp": {
                "path": path if net == "xhttp" else "/xh",
                "host": "",
                # auto: accept whatever mode the agent dials (stream-up default on agent)
                "mode": "auto",
                "extra": "",
                "x_padding_bytes": "100-1000",
                "sc_max_buffered_posts": 30,
                "sc_max_each_post_bytes": "1000000",
                "sc_min_each_post_bytes": "1",
                "sc_stream_up_server_secs": "20-80",
                "sc_min_posts_interval_ms": 30,
                "no_sse_header": False,
                "no_grpc_header": False,
                "headers": "",
                "xmux": {
                    "enabled": True,
                    "max_concurrency": "1",
                    "max_connections": 0,
                    "c_max_reuse_times": "0",
                    "c_max_lifetime_ms": "0",
                    "h_max_request_times": "0",
                    "h_max_reusable_secs": "0",
                },
            },
            "kcp": {}, "sockopt": {"enabled": False},
        },
        "sniffing": {"enabled": True, "dest": ["http", "tls", "quic"], "route_only": False, "metadata_only": False},
        "fallbacks": [], "outbound": "direct",
        "_system": True,
    }
    if existing:
        existing.update(shape)
        return existing
    panel_ibs.append(shape)
    return shape


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
                remark = str(o.get("remark") or tag)
                # remark already starts with "Node …" from upsert_node_outbound
                if remark.lower().startswith("node "):
                    return f"{icon} {remark}"
                return f"{icon} Node {remark}"
            icon = flag_emoji(cc) if cc else "🔗"
            return f"{icon} {o.get('remark') or tag}"
    if tag.startswith("node_"):
        return f"🖥️ {tag}"
    return tag


def _route_target(store: dict, tag: str, *, known_outbounds: set[str] | None = None) -> dict:
    """Map a logical tag to a routing target.

    Balancers are only referenced when they have live members (and thus appear in
    the config with observatory). Otherwise use the balancer's fallback outbound
    (``direct`` by default, ``block`` when fallback is ``none``).
    """
    tag = (tag or "direct").strip() or "direct"
    if _is_balancer_target(store, tag):
        for b in ensure_balancers(store).values():
            if b.get("tag") != tag or not b.get("enabled", True):
                continue
            if balancer_member_tags(store, b):
                return {"balancerTag": tag}
            return {"outboundTag": balancer_fallback_tag(b)}
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
            r["fingerprint"] = legacy.get("fingerprint") or "firefox"
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
        ib["listen"] = P.inbound_listen(ib)
        P.normalize_http_inbound(ib)
    # Inbounds from older versions (or pushed by a master node) may sit on a forbidden port
    for ib in inbounds:
        if port_forbidden_reason(int(ib.get("port") or 0)):
            ib["port"] = free_inbound_port(store, exclude=ib)
    return inbounds


def system_ports() -> set[int]:
    """Ports used by the panel itself on this host; inbounds may not take them."""
    ports = {
        P.FRONT_INTERNAL_PORT, P.FRONT_FALLBACK_H1_PORT, P.FRONT_FALLBACK_H2_PORT,
        int(str(XRAY_API).rsplit(":", 1)[-1]),
    }
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
    return [
        i for i in ensure_inbounds(store)
        if i["protocol"] in P.USER_PROTOCOLS + ("wireguard", "socks", "http")
        and not i.get("_system")
    ]


def client_inbounds(store: dict, client: dict) -> list[dict]:
    wanted = client_effective_inbounds(store, client)
    capable = client_capable_inbounds(store)
    if not wanted:
        return capable
    return [i for i in capable if i["tag"] in wanted]


# ---------------------------------------------------------------- client groups
# Groups define which outbounds (subscription connections) and inbounds a client gets.
# Empty allowed_tags / inbounds on a group = all. Client without group_id keeps personal lists.

def ensure_groups(store: dict) -> list[dict]:
    groups = store.setdefault("groups", [])
    if not isinstance(groups, list):
        groups = []
        store["groups"] = groups
    cleaned: list[dict] = []
    for g in groups:
        if not isinstance(g, dict):
            continue
        if not g.get("id"):
            g["id"] = "g_" + secrets.token_urlsafe(9).replace("-", "").replace("_", "")[:12]
        g.setdefault("name", str(g.get("id") or "group"))
        g.setdefault("comment", "")
        if not isinstance(g.get("allowed_tags"), list):
            g["allowed_tags"] = []
        if not isinstance(g.get("inbounds"), list):
            g["inbounds"] = []
        g.setdefault("outbound", "")
        cleaned.append(g)
    store["groups"] = cleaned
    return cleaned


def get_group(store: dict, group_id: str | None) -> dict | None:
    gid = str(group_id or "").strip()
    if not gid:
        return None
    for g in ensure_groups(store):
        if str(g.get("id") or "") == gid:
            return g
    return None


def client_group(store: dict, client: dict) -> dict | None:
    return get_group(store, client.get("group_id"))


def client_effective_allowed_tags(store: dict, client: dict) -> list[str]:
    """Outbound tags allowed in subscription. Empty list = all."""
    g = client_group(store, client)
    if g is not None:
        return list(g.get("allowed_tags") or [])
    return list(client.get("allowed_tags") or [])


def client_effective_inbounds(store: dict, client: dict) -> list[str]:
    """Inbound tags for the client. Empty list = all capable."""
    g = client_group(store, client)
    if g is not None:
        return list(g.get("inbounds") or [])
    return list(client.get("inbounds") or [])


def client_default_outbound(store: dict, client: dict) -> str:
    g = client_group(store, client)
    if g is not None and g.get("outbound"):
        return str(g["outbound"])
    return str(client.get("outbound") or "direct")


def new_group(*, name: str = "", comment: str = "") -> dict:
    return {
        "id": "g_" + secrets.token_urlsafe(9).replace("-", "").replace("_", "")[:12],
        "name": (name or "Группа").strip() or "Группа",
        "comment": (comment or "").strip(),
        "allowed_tags": [],
        "inbounds": [],
        "outbound": "",
    }


# ---------------------------------------------------------------- clients

RESET_PERIODS = {"": None, "daily": 1, "weekly": 7, "monthly": 30}

# What to do when expire_at / total limit_gb is hit.
# block  — keep client, deny access (default)
# disable — set enabled=False
# delete — remove client
# renew  — reset traffic counters and start a new period (same limit_gb / duration)
LIMIT_ACTIONS = ("block", "disable", "delete", "renew")


def ensure_client(client: dict) -> dict:
    client.setdefault("uuid", str(uuid.uuid4()))
    client.setdefault("password", secrets.token_hex(12))
    client.setdefault("enabled", True)
    client.setdefault("outbound", "direct")
    client.setdefault("inbounds", [])
    client.setdefault("limit_gb", 0)
    client.setdefault("daily_limit_gb", 0)
    client.setdefault("expire_at", "")
    client.setdefault("start_on_first_use", False)
    client.setdefault("duration_days", 0)
    client.setdefault("reset_period", "")
    client.setdefault("next_reset", "")
    client.setdefault("renew_on_reset", False)
    client.setdefault("on_expire", "block")
    client.setdefault("on_quota", "block")
    if client.get("on_expire") not in LIMIT_ACTIONS:
        client["on_expire"] = "block"
    if client.get("on_quota") not in LIMIT_ACTIONS:
        client["on_quota"] = "block"
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
    client.setdefault("group_id", "")
    client.setdefault("outbound_limits", {})
    client.setdefault("daily_outbound_limits", {})
    client.setdefault("sub_enabled", True)
    client.setdefault("doh_enabled", False)
    client.setdefault("doh_in_tunnel", False)
    if not client.get("doh_token"):
        client["doh_token"] = secrets.token_urlsafe(18)
    client.setdefault("last_online", "")
    client.setdefault("ips", {})
    client.setdefault("created_at", now_utc().isoformat())
    traffic = client.setdefault("traffic", {})
    traffic.setdefault("up", 0)
    traffic.setdefault("down", 0)
    traffic.setdefault("by_email", {})
    _ensure_daily_bucket(client)
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


def _utc_day(now: datetime | None = None) -> str:
    return (now or now_utc()).strftime("%Y-%m-%d")


def _ensure_daily_bucket(client: dict, now: datetime | None = None) -> dict:
    """Roll calendar-day counters (UTC). Same limit_gb/daily_* values apply to the new day."""
    day = _utc_day(now)
    d = client.setdefault("daily_traffic", {})
    if d.get("day") != day:
        d.clear()
        d["day"] = day
        d["up"] = 0
        d["down"] = 0
        d["by_tag"] = {}
        client["daily_exceeded"] = False
        client["daily_tag_exceeded"] = {}
    d.setdefault("by_tag", {})
    d.setdefault("up", 0)
    d.setdefault("down", 0)
    return d


def client_daily_used_bytes(client: dict) -> int:
    d = _ensure_daily_bucket(client)
    return int(d.get("up") or 0) + int(d.get("down") or 0)


def client_daily_tag_used_bytes(client: dict, tag: str) -> int:
    d = _ensure_daily_bucket(client)
    row = (d.get("by_tag") or {}).get(tag) or {}
    return int(row.get("up") or 0) + int(row.get("down") or 0)


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


def client_daily_exceeded(client: dict) -> bool:
    limit = gb_to_bytes(client.get("daily_limit_gb"))
    return bool(limit and client_daily_used_bytes(client) >= limit)


def client_tag_exceeded(client: dict, tag: str) -> bool:
    limit = gb_to_bytes((client.get("outbound_limits") or {}).get(tag))
    return bool(limit and client_tag_used_bytes(client, tag) >= limit)


def client_daily_tag_exceeded(client: dict, tag: str) -> bool:
    limit = gb_to_bytes((client.get("daily_outbound_limits") or {}).get(tag))
    return bool(limit and client_daily_tag_used_bytes(client, tag) >= limit)


def client_access_ok(client: dict) -> bool:
    return (
        bool(client.get("enabled", True))
        and not client_is_expired(client)
        and not client_total_exceeded(client)
        and not client_daily_exceeded(client)
    )


def tag_allowed_for_client(store: dict, client: dict, tag: str) -> bool:
    allowed = client_effective_allowed_tags(store, client)
    if allowed and tag not in allowed:
        return False
    if client_tag_exceeded(client, tag):
        return False
    if client_daily_tag_exceeded(client, tag):
        return False
    return True


def client_status(client: dict) -> str:
    if not client.get("enabled", True):
        return "disabled"
    if client_is_expired(client):
        return "expired"
    if client_total_exceeded(client):
        return "limited"
    if client_daily_exceeded(client):
        return "daily_limited"
    return "active"


def _renew_days(client: dict) -> int:
    """Length of the next paid period for renew actions."""
    days = int(client.get("duration_days") or 0)
    if days > 0:
        return days
    period = client.get("reset_period") or ""
    mapped = RESET_PERIODS.get(period)
    if mapped:
        return int(mapped)
    return 30


def renew_client_period(client: dict, *, now: datetime | None = None) -> None:
    """Reset GB counters and start a new expire window with the same limits."""
    now = now or now_utc()
    reset_client_traffic(client)
    days = _renew_days(client)
    client["expire_at"] = (now + timedelta(days=days)).isoformat(timespec="seconds")
    client["start_on_first_use"] = False
    client["expired"] = False
    client["quota_exceeded"] = False
    if client.get("reset_period"):
        client["next_reset"] = _period_delta(client["reset_period"], now).isoformat(timespec="seconds")


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
                    "status": custom_outbound_status(o)})
    return out


def subscription_entries(store: dict, client: dict, *, ignore_quota: bool = False) -> list[dict]:
    """One identity per balancer / connected country / enabled custom outbound.

    Unhealthy outbounds (disconnected L2TP, high packet loss, failed custom probe)
    are omitted so clients do not keep dead nodes until the next refresh.
    """
    if not client.get("uuid") or not client.get("sub_enabled", True):
        return []
    if not ignore_quota and not client_access_ok(client):
        return []
    tags = [b["tag"] for b in ensure_balancers(store).values() if b.get("enabled", True)]
    tags += [_l2tp_tag(t) for t in sorted(store.get("l2tp") or [], key=lambda t: t["name"]) if t.get("status") == "connected"]
    tags += [o["tag"] for o in store.get("outbounds_custom") or [] if o.get("enabled", True) and o.get("in_sub", True)]
    entries = []
    for tag in tags:
        if not ignore_quota and not tag_allowed_for_client(store, client, tag):
            continue
        if not outbound_ok_for_sub(store, tag):
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
    bits: list[str] = []
    limits = client.get("outbound_limits") or {}
    limit = gb_to_bytes(limits.get(tag))
    if limit > 0:
        used = client_tag_used_bytes(client, tag)
        bits.append(f"{format_traffic(used)} / {float(limits[tag]):g} ГБ · ост. {format_traffic(max(limit - used, 0))}")
    dlimits = client.get("daily_outbound_limits") or {}
    dlim = gb_to_bytes(dlimits.get(tag))
    if dlim > 0:
        dused = client_daily_tag_used_bytes(client, tag)
        bits.append(f"день {format_traffic(dused)} / {float(dlimits[tag]):g} ГБ")
    return (" · " + " · ".join(bits)) if bits else ""


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
                ob = client_default_outbound(store, client)
                if ob != "direct" and not tag_allowed_for_client(store, client, ob):
                    continue
                if ob != "direct" and not outbound_ok_for_sub(store, ob):
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
        if P.front_mode(ib) == "raw":
            _front_raw_tls(store, ib, built)
        elif P.is_direct(ib):
            _direct_tls_cert(store, ib, built)
        inbounds.append(built)

    inbounds.append({
        "tag": "api", "listen": "127.0.0.1", "port": int(str(XRAY_API).rsplit(":", 1)[-1]),
        "protocol": "dokodemo-door", "settings": {"address": "127.0.0.1"},
    })

    # Telegram Bot API via panel outbound (VLESS/Trojan/…): local SOCKS → chosen outbound.
    tg_proxy = ((store.get("settings") or {}).get("tg") or {}).get("proxy") or {}
    tg_via = ""
    if (
        tg_proxy.get("enabled")
        and str(tg_proxy.get("type") or "").lower() == "outbound"
        and str(tg_proxy.get("outbound") or "").strip()
    ):
        try:
            import tgbot as _tgbot
            tg_via = str(tg_proxy.get("outbound") or "").strip()
            inbounds.append({
                "tag": _tgbot.TG_LOCAL_SOCKS_TAG,
                "listen": "127.0.0.1",
                "port": int(_tgbot.TG_LOCAL_SOCKS_PORT),
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": False},
            })
        except Exception:
            tg_via = ""

    # sockopt on freedom: BBR/NoDelay on egress (client upload path through the proxy)
    _egress_sock = {"tcpCongestion": "bbr", "tcpNoDelay": True, "tcpFastOpen": True}
    outbounds = [
        {
            "tag": "direct", "protocol": "freedom",
            "settings": {"domainStrategy": "UseIPv4"},
            "streamSettings": {"sockopt": dict(_egress_sock)},
        },
        {"tag": "block", "protocol": "blackhole", "settings": {}},
    ]
    outbounds.extend(_l2tp_outbounds(store))
    outbounds.extend(_custom_outbounds(store))
    if fake.get("enabled"):
        outbounds.append({"tag": "dns-out", "protocol": "dns"})

    # Sync NAT reverse stubs into outbounds_custom before balancer/subscription logic
    try:
        import nodes as nodes_mod
        if nodes_mod.is_master(store):
            nodes_mod.sync_all_node_outbounds(store)
    except Exception:
        pass

    # Build balancers before rules so we know which tags actually exist on this host
    bals_cfg, observatory, burst = _balancers_cfg(store)
    # Reverse portals are outbounds without dial objects — still valid routing targets
    known_outbounds = (
        {o.get("tag") for o in outbounds if o.get("tag")}
        | set(reverse_portal_tags(store))
        | {"api"}
    )

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
    if tg_via:
        try:
            import tgbot as _tgbot
            # Prefer explicit outbound; if balancer/missing — _route_target falls back safely.
            rules.append({
                "type": "field",
                "inboundTag": [_tgbot.TG_LOCAL_SOCKS_TAG],
                **_route_target(store, tg_via, known_outbounds=known_outbounds),
            })
        except Exception:
            pass
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
        ob = client_default_outbound(store, c)
        if ob != "direct" and not tag_allowed_for_client(store, c, ob):
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
            # bufferSize is KB; 1024 helps high-RTT paths (upload often starved with default)
            "levels": {
                "0": {
                    "statsUserUplink": True, "statsUserDownlink": True, "statsUserOnline": True,
                    "bufferSize": 1024, "connIdle": 300, "handshake": 8, "uplinkOnly": 2, "downlinkOnly": 5,
                },
            },
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

    try:
        _inject_reverse(store, cfg)
    except Exception:
        cfg.pop("reverse", None)

    patch = xs.get("template_patch") or {}
    if patch:
        cfg = deep_merge(cfg, patch)
    # Legacy reverse{} is rejected by current Xray — never emit it (even via template patch)
    cfg.pop("reverse", None)
    return cfg


def _balancers_cfg(store: dict) -> tuple[list[dict], dict | None, dict | None]:
    """Emit balancers only when they have live members.

    leastPing/leastLoad require observatory/burstObservatory — emitting a balancer
    with selector [direct] and no observatory makes Xray fail with
    'not all dependencies are resolved'. ``random`` only needs a non-empty selector
    of healthy members (panel drops dead L2TP / disabled customs on each apply).
    Routes to empty balancers fall back via _route_target().
    """
    bals = ensure_balancers(store)
    out: list[dict] = []
    observatory = burst = None
    obs_subjects: set[str] = set()

    ping_b = bals.get("least_ping") or {}
    if ping_b.get("enabled", True):
        members = balancer_member_tags(store, ping_b, healthy_only=True)
        if members:
            entry = {
                "tag": ping_b["tag"], "selector": members, "strategy": {"type": "leastPing"},
                "fallbackTag": balancer_fallback_tag(ping_b),
            }
            out.append(entry)
            obs_subjects.update(members)
            observatory = {
                "subjectSelector": sorted(obs_subjects),
                "probeURL": ping_b.get("probe_url") or "https://www.gstatic.com/generate_204",
                "probeInterval": ping_b.get("probe_interval") or "15s",
                "enableConcurrency": True,
            }

    load_b = bals.get("least_load") or {}
    if load_b.get("enabled", True):
        members = balancer_member_tags(store, load_b, healthy_only=True)
        if members:
            entry = {
                "tag": load_b["tag"], "selector": members,
                "strategy": {"type": "leastLoad", "settings": {
                    "expected": int(load_b.get("expected") or 1), "maxRTT": load_b.get("max_rtt") or "1s",
                    "tolerance": float(load_b.get("tolerance") or 0.15), "baselines": ["1s"]}},
                "fallbackTag": balancer_fallback_tag(load_b),
            }
            out.append(entry)
            burst = {
                "subjectSelector": sorted(set(members)),
                "pingConfig": {
                    "destination": load_b.get("probe_url") or "https://www.gstatic.com/generate_204",
                    "interval": load_b.get("probe_interval") or "20s", "timeout": "5s", "sampling": 2,
                    "connectivity": "http://connectivitycheck.gstatic.com/generate_204",
                },
            }

    # Distribute connections across live outbounds (not “everyone → best ping”).
    rand_b = bals.get("random") or {}
    if rand_b.get("enabled", True):
        members = balancer_member_tags(store, rand_b, healthy_only=True)
        if members:
            entry = {
                "tag": rand_b["tag"], "selector": members, "strategy": {"type": "random"},
                "fallbackTag": balancer_fallback_tag(rand_b),
            }
            out.append(entry)
            # Probe the same pool so leastPing (if on) sees them; random itself
            # still picks only from the healthy selector rebuilt by the panel.
            if observatory is None:
                observatory = {
                    "subjectSelector": sorted(set(members)),
                    "probeURL": rand_b.get("probe_url") or "https://www.gstatic.com/generate_204",
                    "probeInterval": rand_b.get("probe_interval") or "15s",
                    "enableConcurrency": True,
                }
            else:
                observatory["subjectSelector"] = sorted(set(observatory["subjectSelector"]) | set(members))

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
    # Compact JSON: faster write/parse for large client lists; xray only needs valid JSON
    tmp.write_text(json.dumps(cfg, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    test = _run([XRAY_BIN, "run", "-test", "-config", str(tmp)])
    err = clean_xray_error(test["stderr"] or test["stdout"])
    return {"ok": test["exit_code"] == 0, "tmp": tmp, "error": err}


def _xray_active() -> bool:
    return (_run(["systemctl", "is-active", "xray"])["stdout"] or "").strip() == "active"


_XRAY_ENABLED_ONCE = False


def _restart_xray() -> dict:
    # systemctl enable on every apply is pure overhead once the unit is already enabled
    global _XRAY_ENABLED_ONCE
    if not _XRAY_ENABLED_ONCE:
        _run(["systemctl", "enable", "xray"])
        _XRAY_ENABLED_ONCE = True
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


def apply_config(store: dict, *, xray_only: bool = False, clients_only: bool = False) -> dict:
    """Build, verify, then atomically install Xray config. Never skips verification.

    Flow (hardcoded, not configurable):
      1. build JSON
      2. `xray run -test` — reject without touching the live file
      3. keep a copy of the previous live config
      4. replace live config + restart
      5. if Xray is not active — restore previous config and restart again

    xray_only / clients_only: skip traffic harvest and iptables port-ban refresh
    (inbound ports / nginx front are unchanged). Still builds, tests, and restarts
    Xray so routing/clients/outbounds go live.
    """
    xray_only = bool(xray_only or clients_only)
    if not xray_only:
        try:
            harvest_traffic(store)
            enforce_quotas(store)
        except Exception:
            pass
    else:
        # Quotas still matter (expired/limited clients must leave the config)
        try:
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

    # Identical live config + already running → skip restart (common for no-op apply)
    try:
        new_text = t["tmp"].read_text(encoding="utf-8")
        live_text = XRAY_CONFIG.read_text(encoding="utf-8") if XRAY_CONFIG.is_file() else None
    except OSError:
        new_text = None
        live_text = object()
    if new_text is not None and live_text == new_text and _xray_active():
        try:
            t["tmp"].unlink()
        except OSError:
            pass
        if not xray_only:
            ban_inbound_ports(store)
        return {"ok": True, "error": "", "config": cfg, "verified": True, "unchanged": True}

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
        if not xray_only:
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
    """Drop incoming non-loopback traffic to every inbound port: clients reach Xray only via nginx :443.

    Ports listed in settings.sub.legacy_ports (e.g. 2096 for old 3x-ui subscription links)
    stay open so nginx can serve plain-HTTP subscription aliases there.
    """
    import front as front_mod
    keep = set(front_mod.legacy_sub_ports(store))
    # 2053 always banned; 2096 banned only when not declared as a legacy sub port
    forced = {2053} | ({2096} - keep)
    ports = sorted(({int(ib["port"]) for ib in ensure_inbounds(store)} | forced) - P.RESERVED_PORTS - keep)
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
        # Explicitly allow legacy subscription ports (nginx HTTP listeners)
        for port in sorted(keep):
            if _run([tool, "-C", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"])["exit_code"] != 0:
                _run([tool, "-I", "INPUT", "1", "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"])


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
        # Keep imported top-level counters if by_email was never seeded (legacy migrate bug)
        if not by:
            tu = int(client["traffic"].get("up") or 0)
            td = int(client["traffic"].get("down") or 0)
            if tu or td:
                email0 = str(client.get("email") or "")
                if email0:
                    by[email0] = {"up": tu, "down": td, "last_up": 0, "last_down": 0}
                    changed = True
        emails = {client["email"]} | {e["email"] for e in subscription_entries(store, client, ignore_quota=True)}
        active = False
        daily = _ensure_daily_bucket(client)
        for email in emails:
            cur = users.get(email)
            if not cur:
                continue
            row = by.setdefault(email, {"up": 0, "down": 0, "last_up": 0, "last_down": 0})
            before_up = int(row.get("up") or 0)
            before_down = int(row.get("down") or 0)
            if _accumulate(row, cur["up"], cur["down"]):
                changed = True
            d_up = int(row.get("up") or 0) - before_up
            d_down = int(row.get("down") or 0) - before_down
            if d_up or d_down:
                active = True
                daily["up"] = int(daily.get("up") or 0) + max(0, d_up)
                daily["down"] = int(daily.get("down") or 0) + max(0, d_down)
                tag = email.split("~", 1)[1] if "~" in email else (client.get("outbound") or "direct")
                trow = daily.setdefault("by_tag", {}).setdefault(tag, {"up": 0, "down": 0})
                trow["up"] = int(trow.get("up") or 0) + max(0, d_up)
                trow["down"] = int(trow.get("down") or 0) + max(0, d_down)
                changed = True
        if by:
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
    # Fresh daily bucket for the current UTC day
    d = client.setdefault("daily_traffic", {})
    d.clear()
    d["day"] = _utc_day()
    d["up"] = d["down"] = 0
    d["by_tag"] = {}
    client["daily_exceeded"] = False
    client["daily_tag_exceeded"] = {}
    # Allow a fresh one-shot low-traffic Telegram alert after reset
    client.pop("tg_notify_low_gb", None)


def _period_delta(period: str, base: datetime) -> datetime:
    if period == "hourly":
        return base + timedelta(hours=1)
    if period == "monthly":
        month = base.month + 1
        year = base.year + (month - 1) // 12
        month = (month - 1) % 12 + 1
        day = min(base.day, 28)
        return base.replace(year=year, month=month, day=day)
    days = RESET_PERIODS.get(period) or 0
    return base + timedelta(days=days)


def _apply_limit_action(client: dict, *, kind: str, action: str, now: datetime, events: list[dict]) -> str | None:
    """Apply on_expire / on_quota action. Returns email if client should be deleted."""
    action = action if action in LIMIT_ACTIONS else "block"
    email = client.get("email") or ""
    if action == "renew":
        renew_client_period(client, now=now)
        events.append({"type": "renewed", "email": email, "reason": kind, "days": _renew_days(client)})
        return None
    if action == "disable":
        if client.get("enabled", True):
            client["enabled"] = False
            events.append({"type": "auto_disable", "email": email, "reason": kind})
        return None
    if action == "delete":
        events.append({"type": "auto_delete", "email": email, "reason": kind})
        return email
    # block — flag only; access denied via client_access_ok
    return None


def enforce_quotas(store: dict) -> bool:
    """Delayed start, auto-reset, daily roll, expiry/quota actions. True → Xray rebuild needed."""
    changed = False
    events: list[dict] = store.setdefault("_events", [])
    now = now_utc()
    to_delete: list[str] = []
    for client in store.get("clients") or []:
        ensure_client(client)
        _ensure_daily_bucket(client, now)
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

        # Expire action (renew may clear expired in the same cycle)
        was_expired = bool(client.get("expired"))
        is_expired = client_is_expired(client, now)
        if is_expired and not was_expired:
            victim = _apply_limit_action(
                client, kind="expire", action=str(client.get("on_expire") or "block"), now=now, events=events,
            )
            if victim:
                to_delete.append(victim)
            changed = True
            is_expired = client_is_expired(client, now)
        if bool(client.get("expired")) != is_expired:
            client["expired"] = is_expired
            changed = True
            if is_expired:
                events.append({"type": "expired", "email": client["email"]})

        # Total GB quota action
        was_quota = bool(client.get("quota_exceeded"))
        is_quota = client_total_exceeded(client)
        if is_quota and not was_quota:
            victim = _apply_limit_action(
                client, kind="quota", action=str(client.get("on_quota") or "block"), now=now, events=events,
            )
            if victim:
                to_delete.append(victim)
            changed = True
            is_quota = client_total_exceeded(client)
        if bool(client.get("quota_exceeded")) != is_quota:
            client["quota_exceeded"] = is_quota
            changed = True
            if is_quota:
                events.append({"type": "quota_exceeded", "email": client["email"]})

        # Daily total (auto-lifts next UTC day — no destructive action)
        daily_hit = client_daily_exceeded(client)
        if bool(client.get("daily_exceeded")) != daily_hit:
            client["daily_exceeded"] = daily_hit
            changed = True
            if daily_hit:
                events.append({"type": "daily_exceeded", "email": client["email"]})

        flags = client.setdefault("tag_exceeded", {})
        watch_tags = (
            set((client.get("outbound_limits") or {}).keys())
            | set(client_effective_allowed_tags(store, client))
        )
        for tag in watch_tags:
            hit = client_tag_exceeded(client, tag)
            if bool(flags.get(tag)) != hit:
                flags[tag] = hit
                changed = True
                if hit:
                    events.append({"type": "tag_exceeded", "email": client["email"], "tag": tag})

        dflags = client.setdefault("daily_tag_exceeded", {})
        dwatch = (
            set((client.get("daily_outbound_limits") or {}).keys())
            | set(client_effective_allowed_tags(store, client))
        )
        for tag in dwatch:
            hit = client_daily_tag_exceeded(client, tag)
            if bool(dflags.get(tag)) != hit:
                dflags[tag] = hit
                changed = True
                if hit:
                    events.append({"type": "daily_tag_exceeded", "email": client["email"], "tag": tag})

    if to_delete:
        drop = set(to_delete)
        before = len(store.get("clients") or [])
        store["clients"] = [c for c in (store.get("clients") or []) if c.get("email") not in drop]
        if len(store["clients"]) != before:
            changed = True

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

    # Reverse portal: live only while the NAT node keeps the tunnel up (tracked via pull)
    for o in store.get("outbounds_custom") or []:
        if o.get("tag") != tag:
            continue
        if o.get("reverse") or (o.get("kind") == "node" and not (o.get("config") or {})):
            try:
                import nodes as nodes_mod
                node = next(
                    (n for n in nodes_mod.ensure_list(store) if n.get("id") == o.get("node_id")),
                    None,
                )
            except Exception:
                node = None
            if node and not node.get("nat"):
                # Reverse mode on a reachable node: ask the node live (stored rv_conns may be stale)
                t0 = time.time()
                try:
                    probe = nodes_mod.probe_health(dict(node), timeout=8)
                except Exception as exc:  # noqa: BLE001
                    probe = {"ok": False, "error": str(exc)}
                ms = int((time.time() - t0) * 1000)
                raw = probe.get("raw") if isinstance(probe.get("raw"), dict) else {}
                conns = raw.get("rv_conns")
                if not probe.get("ok"):
                    return {"ok": False, "error": f"нода не на связи: {probe.get('error') or ''}"[:200], "ms": ms}
                if isinstance(conns, int) and conns > 0:
                    return {"ok": True, "code": "204", "ms": ms, "error": "", "rv_conns": conns}
                return {"ok": False, "error": f"reverse-туннель от ноды не поднят (rv_conns={conns})", "ms": ms}
            if node and nodes_mod.pull_fresh(node) and node.get("online") is not False:
                return {"ok": True, "code": "204", "ms": 0, "error": ""}
            return {"ok": False, "error": "NAT-нода не на связи (нет reverse pull)", "ms": 0}

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
