"""Xray config builder: multi-inbound, custom outbounds, balancers, per-user routing, quotas."""
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


def _x25519_public_from_private(private_key: str) -> dict:
    """Derive X25519 public key (WireGuard / Reality) from a private key string."""
    priv = (private_key or "").strip()
    if not priv:
        return {"ok": False, "error": "empty private key"}
    # Prefer xray CLI (same encoding as keygen)
    r = _run([XRAY_BIN, "x25519", "-i", priv], timeout=15)
    parsed = _parse_keypair(r)
    if parsed.get("ok") and parsed.get("public_key"):
        return {"ok": True, "private_key": priv, "public_key": parsed["public_key"]}
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        pad = "=" * (-len(priv) % 4)
        try:
            raw = base64.urlsafe_b64decode(priv + pad)
        except Exception:
            raw = base64.b64decode(priv + pad)
        if len(raw) != 32:
            return {"ok": False, "error": "private key must be 32 bytes"}
        pub = X25519PrivateKey.from_private_bytes(raw).public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        return {"ok": True, "private_key": priv, "public_key": base64.urlsafe_b64encode(pub).decode().rstrip("=")}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc) or "derive failed"}


def wg_public_from_private(private_key: str) -> dict:
    """Derive WireGuard public key from a base64 private key."""
    return _x25519_public_from_private(private_key)


def reality_public_from_private(private_key: str) -> dict:
    """Derive Reality public key from private (restore from backup without regenerating)."""
    return _x25519_public_from_private(private_key)


def _parse_keypair(r: dict) -> dict:
    text = f"{r['stdout']}\n{r['stderr']}"
    priv = pub = ""
    for line in text.splitlines():
        if ":" not in line:
            continue
        low = line.lower()
        val = line.split(":", 1)[1].strip()
        if "private" in low:
            priv = val
        elif "public" in low or low.startswith("password"):
            # xray wg (new): "Password (PublicKey): …"
            pub = val
    if not priv or not pub:
        return {"ok": False, "error": text or "keygen failed"}
    return {"ok": True, "private_key": priv, "public_key": pub}


def generate_short_id(nbytes: int = 4) -> str:
    return secrets.token_hex(nbytes)


def generate_short_ids(count: int = 8) -> list[str]:
    """Mixed-length shortIds (2..16 hex chars). Never includes an empty id."""
    lengths = (2, 4, 6, 8, 10, 12, 14, 16)
    n = max(1, int(count or 8))
    out: list[str] = []
    for i in range(n):
        out.append(secrets.token_hex(lengths[i % len(lengths)] // 2))
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

# ISO → short RU label for inbound flag picker (shown in subscription as emoji + remark).
FLAG_CHOICES: list[tuple[str, str]] = [
    ("", "без флага"),
    ("RU", "Россия"), ("UA", "Украина"), ("BY", "Беларусь"), ("KZ", "Казахстан"),
    ("DE", "Германия"), ("NL", "Нидерланды"), ("FI", "Финляндия"), ("SE", "Швеция"),
    ("NO", "Норвегия"), ("DK", "Дания"), ("PL", "Польша"), ("CZ", "Чехия"),
    ("AT", "Австрия"), ("CH", "Швейцария"), ("FR", "Франция"), ("GB", "Великобритания"),
    ("IE", "Ирландия"), ("ES", "Испания"), ("IT", "Италия"), ("PT", "Португалия"),
    ("BE", "Бельгия"), ("LU", "Люксембург"), ("RO", "Румыния"), ("BG", "Болгария"),
    ("HU", "Венгрия"), ("SK", "Словакия"), ("SI", "Словения"), ("HR", "Хорватия"),
    ("RS", "Сербия"), ("TR", "Турция"), ("GR", "Греция"), ("CY", "Кипр"),
    ("IL", "Израиль"), ("AE", "ОАЭ"), ("SA", "Саудовская Аравия"),
    ("US", "США"), ("CA", "Канада"), ("MX", "Мексика"), ("BR", "Бразилия"),
    ("AR", "Аргентина"), ("CL", "Чили"),
    ("JP", "Япония"), ("KR", "Корея"), ("CN", "Китай"), ("HK", "Гонконг"),
    ("TW", "Тайвань"), ("SG", "Сингапур"), ("MY", "Малайзия"), ("TH", "Таиланд"),
    ("VN", "Вьетнам"), ("ID", "Индонезия"), ("IN", "Индия"), ("AU", "Австралия"),
    ("NZ", "Новая Зеландия"), ("ZA", "ЮАР"),
]


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


def flag_choices() -> list[dict]:
    """UI options: [{code, label, flag}] for inbound country select."""
    out: list[dict] = []
    for code, name in FLAG_CHOICES:
        out.append({
            "code": code,
            "label": name,
            "flag": flag_emoji(code) if code else "🌐",
        })
    return out


def inbound_sub_label(ib: dict | None) -> str:
    """Subscription profile name: optional country flag + inbound remark."""
    if not isinstance(ib, dict):
        return "inbound"
    name = str(ib.get("remark") or ib.get("tag") or "inbound").strip() or "inbound"
    cc = country_code(ib)
    if cc:
        return f"{flag_emoji(cc)} {name}"
    return name


def subscription_profile_remark(
    store: dict,
    client: dict,
    ib: dict,
    *,
    outbound_tag: str = "",
    outbound_label_text: str = "",
    quota_suffix: str = "",
    with_outbound: bool = False,
) -> str:
    """Build the `#remark` shown in client apps for a subscription link.

    Primary name is always the inbound (custom remark + country flag).
    Outbound/node label is appended only when needed to disambiguate.
    """
    base = inbound_sub_label(ib)
    ob = str(outbound_tag or "").strip()
    label = str(outbound_label_text or "").strip()
    if with_outbound and ob and ob != "direct":
        if not label:
            label = outbound_label(store, ob)
        if label:
            base = f"{base} · {label}"
    return f"{base}{quota_suffix or ''}"


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
            "label": "", "sub_direct_pool": False,
        },
        "least_load": {
            "tag": BALANCER_LEAST_LOAD, "enabled": True, "strategy": "leastLoad", "members": [],
            "probe_url": "https://www.gstatic.com/generate_204", "probe_interval": "20s",
            "expected": 1, "max_rtt": "1s", "tolerance": 0.15, "fallback": "direct",
            # Label is admin-only; balancers never appear in user subscriptions.
            "label": "Зарубеж", "sub_direct_pool": False,
        },
        # Spreads connections across currently live outbounds (panel health gate + Xray random).
        "random": {
            "tag": BALANCER_RANDOM, "enabled": True, "strategy": "random", "members": [],
            "probe_url": "https://www.gstatic.com/generate_204", "probe_interval": "15s", "fallback": "direct",
            "label": "", "sub_direct_pool": False,
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
        if not isinstance(cur.get("label"), str):
            cur["label"] = str(cur.get("label") or "")
        # Routing-only: never expose balancers / Direct-pools in subscriptions.
        cur["sub_direct_pool"] = False
    return bals


def balancer_tags(store: dict) -> list[str]:
    ensure_balancers(store)
    return [b["tag"] for b in store["balancers"].values() if b.get("enabled", True) and b.get("tag")]


def balancer_by_tag(store: dict, tag: str) -> dict | None:
    tag = str(tag or "").strip()
    if not tag:
        return None
    for b in ensure_balancers(store).values():
        if b.get("tag") == tag:
            return b
    return None


def balancer_display_label(store: dict, balancer: dict | None, *, tag: str = "") -> str:
    """Subscription / UI name for a balancer (custom label overrides built-in)."""
    b = balancer if isinstance(balancer, dict) else balancer_by_tag(store, tag)
    tg = str((b or {}).get("tag") or tag or "").strip()
    custom = str((b or {}).get("label") or "").strip()
    if custom:
        return custom
    return BALANCER_LABELS.get(tg, tg or "balancer")


def _is_balancer_target(store: dict, tag: str) -> bool:
    return tag in balancer_tags(store)


def _direct_node_online_load(store: dict, tag: str) -> int:
    """Approximate load: distinct online client IPs reported for ``email~tag``."""
    tag = str(tag or "").strip()
    if not tag:
        return 0
    suffix = f"~{tag}"
    ips: set[str] = set()
    bucket = store.get("_agent_online") if isinstance(store.get("_agent_online"), dict) else {}
    for email, ipmap in bucket.items():
        if not str(email).endswith(suffix) or not isinstance(ipmap, dict):
            continue
        for ip in ipmap:
            if ip:
                ips.add(str(ip))
    return len(ips)


def direct_pool_candidate_tags(store: dict, balancer: dict) -> list[str]:
    """Enabled Direct-connect members suitable for a one-link subscription pool."""
    out: list[str] = []
    try:
        import nodes as nodes_mod
    except Exception:
        return out
    for tag in balancer_member_tags(store, balancer, healthy_only=False):
        if not outbound_ok_for_sub(store, tag):
            continue
        node = nodes_mod.node_by_outbound_tag(store, tag)
        if not nodes_mod.uses_direct_connect(node):
            continue
        if node is not None and node.get("online") is False:
            continue
        out.append(tag)
    return out


def pick_direct_pool_tag(store: dict, balancer: dict) -> str:
    """Least-load Direct node for subscription: fewest reported online IPs, then tag."""
    cands = direct_pool_candidate_tags(store, balancer)
    if not cands:
        return ""
    return min(cands, key=lambda t: (_direct_node_online_load(store, t), t))


def direct_pool_hidden_member_tags(store: dict) -> set[str]:
    """Formerly hid Direct nodes covered by a sub Direct-pool balancer.

    Balancers no longer appear in subscriptions, so members are never hidden here.
    """
    return set()


PROBE_HISTORY_N = 20  # rolling window for outbound packet-loss %


def sub_health_settings(store: dict) -> dict:
    """Subscription health gate: hide disconnected / high-loss outbounds from client links."""
    sub = ((store.get("settings") or {}).get("sub") or {})
    try:
        max_loss = float(sub.get("max_loss_pct") if sub.get("max_loss_pct") not in (None, "") else 20)
    except (TypeError, ValueError):
        max_loss = 20.0
    try:
        probe_sec = int(sub.get("ob_probe_sec") if sub.get("ob_probe_sec") not in (None, "") else 60)
    except (TypeError, ValueError):
        probe_sec = 60
    return {
        "hide_unhealthy": bool(sub.get("hide_unhealthy", True)),
        "max_loss_pct": max(0.0, min(100.0, max_loss)),
        # How often the panel probes every enabled custom outbound
        "ob_probe_sec": max(30, min(3600, probe_sec)),
    }


def outbound_loss_pct(o: dict) -> float | None:
    """Rolling probe loss % from ``probe_history`` / ``last_test.loss_pct``."""
    lt = o.get("last_test") if isinstance(o.get("last_test"), dict) else {}
    hist = o.get("probe_history")
    if isinstance(hist, list) and hist:
        fails = sum(1 for x in hist if not x)
        return round(100.0 * fails / len(hist), 1)
    if isinstance(lt, dict) and lt.get("loss_pct") is not None:
        try:
            return float(lt["loss_pct"])
        except (TypeError, ValueError):
            pass
    return None


def custom_outbound_status(o: dict, *, max_loss_pct: float | None = None) -> str:
    """UI status: enabled + successful probe → connected; fail → disconnected; high loss → degraded."""
    if not o.get("enabled", True):
        return "disabled"
    # Direct-connect entries are judged by node reachability, not bridge hairpin probe
    if o.get("direct_connect") or o.get("kind") == "local_direct":
        return "connected"
    lt = o.get("last_test")
    if isinstance(lt, dict) and lt.get("ok") is False:
        return "disconnected"
    if isinstance(lt, dict) and lt.get("ok") is True:
        if max_loss_pct is not None:
            loss = outbound_loss_pct(o)
            if loss is not None and loss > max_loss_pct:
                return "degraded"
        return "connected"
    # Not probed yet — treat as live for UI until first fail
    return "connected"


def custom_outbound_healthy(o: dict, *, max_loss_pct: float | None = None) -> bool:
    """Standalone custom may appear in subscription (hide on probe fail / high loss)."""
    if not o.get("enabled", True):
        return False
    lt = o.get("last_test")
    if isinstance(lt, dict) and lt.get("ok") is False:
        return False
    if max_loss_pct is not None:
        loss = outbound_loss_pct(o)
        if loss is not None and loss > max_loss_pct:
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
        if node.get("nat"):
            # NAT reverse/L2X: live while pull is fresh
            if not nodes_mod.pull_fresh(node):
                return False
            if node.get("reverse_ok") is False:
                return False
            conns = node.get("rv_conns")
            if isinstance(conns, int) and conns <= 0:
                return False
        elif nodes_mod.uses_reverse(node):
            # Reachable reverse: push-synced — do not require last_pull
            if node.get("reverse_ok") is False:
                return False
            conns = node.get("rv_conns")
            # Missing rv_conns = unknown (probe will refresh); only fail on explicit 0
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
    for o in store.get("outbounds_custom") or []:
        if o.get("tag") != tag:
            continue
        if not o.get("enabled", True):
            return False
        if o.get("tunnel") or (
            o.get("kind") == "node" and (o.get("config") or {}).get("protocol") == "socks"
        ):
            return _tunnel_outbound_member_ok(store, o)
        if o.get("reverse") or (o.get("kind") == "node" and not (o.get("config") or {})):
            return _reverse_portal_member_ok(store, o)
        return True
    return True


def _tunnel_outbound_member_ok(store: dict, outbound: dict) -> bool:
    """l2x_udp node: live while tunneld reports an online peer.

    Panel pull freshness applies only when the node has an agent token (pull cycle).
    Tunnel-only agents (SOCKS egress, no panel pull) are gated by tunneld /health.
    """
    try:
        import nodes as nodes_mod

        node = next(
            (n for n in nodes_mod.ensure_list(store) if n.get("id") == outbound.get("node_id")),
            None,
        )
    except Exception:
        node = None
    tunnel_only = False
    if node:
        # Pure L2X tunnel agent: no panel token/pull — health is tunneld peer only.
        try:
            import nodes as nodes_mod
            tunnel_only = nodes_mod.is_tunnel_only_node(node)
        except Exception:
            tunnel_only = bool(str(node.get("tunnel_mode") or "") == "l2x_udp" and not (node.get("token") or "").strip())
        if not tunnel_only:
            if node.get("online") is False:
                return False
            try:
                import nodes as nodes_mod
                if node.get("nat") and not nodes_mod.pull_fresh(node):
                    return False
            except Exception:
                pass
    # Best-effort: local tunneld /health (per-agent when multi-peer)
    try:
        import json
        import urllib.request
        with urllib.request.urlopen("http://127.0.0.1:9109/health", timeout=1.5) as resp:
            data = json.loads(resp.read().decode() or "{}")
            if node is not None:
                try:
                    import nodes as nodes_mod
                    ok = nodes_mod.tunnel_agent_online(data, node)
                except Exception:
                    ok = bool(data.get("online"))
            else:
                ok = bool(data.get("online"))
            if ok and node is not None and tunnel_only:
                node["online"] = True
                node["last_seen"] = node.get("last_seen") or ""
            return ok
    except Exception:
        # If metrics unreachable, keep in pool (avoid emptying balancer on panel restart)
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

    for o in store.get("outbounds_custom") or []:
        if o.get("tag") != tag:
            continue
        if not o.get("in_sub", True):
            return False
        # Direct-connect: clients dial the node host. Master bridge/hairpin probe
        # must not hide the entry (probe can fail while public Path/Reality works).
        if o.get("direct_connect") or o.get("kind") == "local_direct":
            try:
                import nodes as nodes_mod
                node = nodes_mod.node_by_outbound_tag(store, tag)
                if nodes_mod.uses_direct_connect(node):
                    if node.get("online") is False:
                        return False
                    return True
            except Exception:
                return True
        return custom_outbound_healthy(o, max_loss_pct=cfg["max_loss_pct"])

    # Balancers are for routing only — never as subscription profiles.
    if balancer_by_tag(store, tag):
        return False

    return True


def balancer_auto_pool(store: dict) -> list[str]:
    """Default balancer pool when members is empty: enabled custom outbounds."""
    out: list[str] = []
    seen: set[str] = set()
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
    """explicit members ∩ live outbounds; empty members → auto pool (enabled customs)."""
    members = balancer.get("members") or []
    if not members:
        pool_list = balancer_auto_pool(store)
    else:
        custom = {o["tag"] for o in store.get("outbounds_custom") or [] if o.get("enabled", True)}
        pool_list = [t for t in members if t in custom]
    if not healthy_only or not sub_health_settings(store)["hide_unhealthy"]:
        return pool_list
    return [t for t in pool_list if outbound_member_ok(store, t)]


def balancer_sticky_member(
    store: dict, balancer: dict, *, known_outbounds: set[str] | None = None,
) -> str:
    """Pick one stable egress for apps that break when exit IP flips (Telegram).

    Prefers last_test.ok with lowest RTT; falls back to first selector member.
    Choice is fixed until the next apply_config — not on every observatory tick.
    """
    members = balancer_member_tags(store, balancer, healthy_only=False)
    if known_outbounds is not None:
        members = [m for m in members if m in known_outbounds]
    if not members:
        return ""
    by_tag = {
        str(o.get("tag") or ""): o
        for o in (store.get("outbounds_custom") or [])
        if o.get("tag")
    }
    scored: list[tuple[int, int, int, str]] = []
    for idx, tag in enumerate(members):
        lt = (by_tag.get(tag) or {}).get("last_test") or {}
        if lt.get("ok") is False:
            continue
        try:
            ms = int(lt.get("ms") or 999999)
        except (TypeError, ValueError):
            ms = 999999
        # ok True → rank 0; missing probe → rank 1
        rank = 0 if lt.get("ok") is True else 1
        scored.append((rank, ms, idx, tag))
    if scored:
        scored.sort()
        return scored[0][3]
    return members[0]


# Apps whose long-lived sessions break when balancer spreads TCP across exit IPs.
_STICKY_BALANCER_DOMAINS = ["geosite:telegram"]
_STICKY_BALANCER_IPS = ["geoip:telegram"]


def _telegram_sticky_rules(
    store: dict,
    active_clients: list[dict],
    *,
    known_outbounds: set[str] | None = None,
) -> list[dict]:
    """Pin Telegram to one balancer member per user (before user→balancerTag rules)."""
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for c in active_clients:
        pairs: list[tuple[str, str]] = []
        try:
            for e in subscription_entries(store, c):
                pairs.append((str(e.get("email") or ""), str(e.get("tag") or "")))
        except Exception:
            pass
        try:
            ob = client_default_outbound(store, c)
            if ob and ob != NONE_TAG:
                pairs.append((str(c.get("email") or ""), str(ob)))
        except Exception:
            pass
        for email, tag in pairs:
            email = (email or "").strip()
            tag = normalize_outbound_tag(tag)
            if not email or not tag:
                continue
            bal = balancer_by_tag(store, tag) if _is_balancer_target(store, tag) else None
            if not bal:
                rt = _route_target(store, tag, known_outbounds=known_outbounds)
                btag = str(rt.get("balancerTag") or "").strip()
                bal = balancer_by_tag(store, btag) if btag else None
            if not bal:
                continue
            sticky = balancer_sticky_member(store, bal, known_outbounds=known_outbounds)
            if not sticky:
                continue
            key = (email, sticky)
            if key in seen:
                continue
            seen.add(key)
            out.append({
                "type": "field",
                "user": [email],
                "domain": list(_STICKY_BALANCER_DOMAINS),
                "outboundTag": sticky,
            })
            out.append({
                "type": "field",
                "user": [email],
                "ip": list(_STICKY_BALANCER_IPS),
                "outboundTag": sticky,
            })
    return out


# ---------------------------------------------------------------- outbounds

def _custom_outbounds(store: dict) -> list[dict]:
    out = []
    for o in store.get("outbounds_custom") or []:
        if not o.get("enabled", True):
            continue
        # Xray VLESS reverse portals have no dial config (traffic via reverse.tag)
        if o.get("reverse") and not (o.get("config") or {}):
            continue
        if o.get("kind") == "node" and not (o.get("config") or {}) and not o.get("tunnel"):
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
    """Enabled NAT nodes used as Xray VLESS reverse outbounds (portal tags).

    Nodes with tunnel_mode=l2x_udp use l2x-tunneld SOCKS instead — excluded here.
    """
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
            if nodes_mod.uses_l2x_tunnel(n):
                continue
            if not nodes_mod.uses_reverse(n):
                continue
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
    if not P.fallbacks_allowed(ib):
        return
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
        # Drop stale VLESS reverse inbound when all NAT nodes use l2x_udp / are gone
        cfg["inbounds"] = [i for i in cfg.get("inbounds") or [] if i.get("tag") != "rv-in"]
        clear_reverse_front_inbound(store)
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


def clear_reverse_front_inbound(store: dict) -> None:
    """Remove panel-shaped rv-in when no Xray reverse NAT nodes remain."""
    panel_ibs = store.get("inbounds") or []
    store["inbounds"] = [i for i in panel_ibs if i.get("tag") != "rv-in"]


def clear_master_backhaul_front_inbound(store: dict) -> None:
    try:
        import nodes as nodes_mod
        tag = nodes_mod.MASTER_BACKHAUL_TAG
    except Exception:
        tag = "master-backhaul"
    store["inbounds"] = [i for i in (store.get("inbounds") or []) if i.get("tag") != tag]


def ensure_master_backhaul_front_inbound(store: dict) -> dict | None:
    """Panel-shaped inbound so nginx publishes the master-backhaul Path for Direct agents."""
    try:
        import nodes as nodes_mod
    except Exception:
        return None
    nodes = nodes_mod.direct_connect_nodes(store)
    if not nodes:
        clear_master_backhaul_front_inbound(store)
        return None
    mb = nodes_mod.ensure_master_backhaul(store)
    for n in nodes:
        nodes_mod.ensure_node_master_egress(n)
    path = mb.get("path") or "/mb-backhaul"
    port = int(mb.get("port") or nodes_mod.MASTER_BACKHAUL_PORT)
    panel_ibs = store.setdefault("inbounds", [])
    tag = nodes_mod.MASTER_BACKHAUL_TAG
    existing = next((i for i in panel_ibs if i.get("tag") == tag), None)
    share = ""
    try:
        import front as front_mod
        share = front_mod.public_domain(store) or ""
    except Exception:
        pass
    shape = {
        "id": existing.get("id") if existing else 9150,
        "tag": tag,
        "remark": "Direct → master egress",
        "enabled": True,
        "listen": "127.0.0.1",
        "port": port,
        "protocol": "vless",
        "share_host": share,
        "settings": {"flow": "", "decryption": "none", "encryption": ""},
        "stream": {
            "network": "ws",
            "security": "none",
            "fingerprint": "chrome",
            "ws": {
                "path": path, "host": "", "headers": "", "heartbeat": 10,
                "accept_proxy_protocol": False,
            },
            "tls": {}, "reality": {}, "raw": {"header": "none"}, "grpc": {},
            "httpupgrade": {}, "xhttp": {}, "kcp": {}, "sockopt": {"enabled": False},
        },
        "sniffing": {
            "enabled": True, "dest": ["http", "tls", "quic"],
            "route_only": False, "metadata_only": False,
        },
        "fallbacks": [],
        "outbound": "direct",
        "_system": True,
    }
    if existing:
        existing.update(shape)
        return existing
    panel_ibs.append(shape)
    return shape


def _inject_master_backhaul(store: dict, cfg: dict) -> None:
    """Master: VLESS/WS inbound accepting Direct agents; traffic exits via freedom."""
    try:
        import nodes as nodes_mod
    except Exception:
        return
    if not nodes_mod.is_master(store):
        return
    nodes = nodes_mod.direct_connect_nodes(store)
    tag = nodes_mod.MASTER_BACKHAUL_TAG
    if not nodes:
        cfg["inbounds"] = [i for i in cfg.get("inbounds") or [] if i.get("tag") != tag]
        clear_master_backhaul_front_inbound(store)
        return
    mb = nodes_mod.ensure_master_backhaul(store)
    path = mb.get("path") or "/mb-backhaul"
    port = int(mb.get("port") or nodes_mod.MASTER_BACKHAUL_PORT)
    clients = []
    for n in nodes:
        nodes_mod.ensure_node_master_egress(n)
        clients.append({
            "id": n["master_egress_uuid"],
            "email": f"mb@{nodes_mod.slugify(n.get('name') or 'node')}",
            "level": 0,
            "flow": "",
        })
    ensure_master_backhaul_front_inbound(store)
    ib = {
        "tag": tag,
        "listen": "127.0.0.1",
        "port": port,
        "protocol": "vless",
        "settings": {"clients": clients, "decryption": "none"},
        "streamSettings": {
            "network": "ws",
            "security": "none",
            "wsSettings": {"path": path, "heartbeatPeriod": 10},
        },
    }
    inbounds = [i for i in cfg.setdefault("inbounds", []) if i.get("tag") != tag]
    inbounds.append(ib)
    cfg["inbounds"] = inbounds
    # Traffic from backhaul always exits locally (master IP)
    rules = cfg.setdefault("routing", {}).setdefault("rules", [])
    rules[:] = [
        r for r in rules
        if not (r.get("inboundTag") == [tag] and r.get("outboundTag") in ("direct", "master"))
    ]
    insert_at = 1 if rules else 0
    rules.insert(insert_at, {
        "type": "field", "inboundTag": [tag], "outboundTag": "direct",
    })


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
        clear_reverse_front_inbound(store)
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
    try:
        import nodes as nodes_mod
        tags.append(nodes_mod.MASTER_EGRESS_TAG)
    except Exception:
        tags.append("master")
    tags += [o["tag"] for o in store.get("outbounds_custom") or [] if o.get("tag") not in tags]
    tags += reverse_portal_tags(store)
    tags += balancer_tags(store)
    return tags


def outbound_label(store: dict, tag: str) -> str:
    tag = str(tag or "").strip()
    if not tag or tag.lower() in ("none", "-", "off"):
        return "— none —"
    b = balancer_by_tag(store, tag)
    if b is not None:
        return balancer_display_label(store, b, tag=tag)
    if tag in BALANCER_LABELS:
        return BALANCER_LABELS[tag]
    if tag == "direct":
        return "🏠 Direct"
    if tag in ("master", "master_egress"):
        return "🏠 Мастер (IP панели)"
    if tag == "block":
        return "⛔ Block"
    for o in store.get("outbounds_custom") or []:
        if o["tag"] == tag:
            cc = o.get("country") or ""
            if o.get("kind") in ("node", "local_direct") or o.get("direct_connect"):
                icon = flag_emoji(cc) if cc else "🖥️"
                title = ""
                nid = o.get("node_id")
                if nid:
                    try:
                        import nodes as _nodes
                        for n in _nodes.ensure_list(store):
                            if n.get("id") == nid:
                                title = _nodes.node_user_title(n)
                                break
                    except Exception:
                        title = ""
                if not title:
                    title = str(o.get("remark") or tag).strip() or tag
                return f"{icon} {title}"
            icon = flag_emoji(cc) if cc else "🔗"
            return f"{icon} {o.get('remark') or tag}"
    if tag.startswith("node_"):
        return f"🖥️ {tag}"
    return tag


def normalize_outbound_tag(tag: str | None) -> str:
    """Map aliases (3x-ui / Xray) onto panel tags. Unknown tags kept as-is."""
    t = (tag or "direct").strip() or "direct"
    low = t.lower()
    if low in ("block", "blocked", "blackhole", "deny", "reject"):
        return "block"
    if low in ("direct", "freedom", "passthrough"):
        return "direct"
    if low in ("master", "master_egress", "panel"):
        return "master"
    return t


def _route_target(store: dict, tag: str, *, known_outbounds: set[str] | None = None) -> dict:
    """Map a logical tag to a routing target.

    Balancer tags stay as ``balancerTag`` whenever the balancer is enabled and has
    any selectable members (enabled customs). Do **not** rewrite
    to fallback based on momentary probe health — that made routes flip on every
    watchdog apply. Dead members are handled by Xray observatory + ``fallbackTag``.
    """
    tag = normalize_outbound_tag(tag)
    # On master, "master" means local freedom (panel IP). On Direct agents a real
    # master_egress dial outbound is present in known_outbounds.
    if tag in ("master", "master_egress"):
        try:
            import nodes as nodes_mod
            if nodes_mod.is_master(store):
                return {"outboundTag": "direct"}
            tag = nodes_mod.MASTER_EGRESS_TAG
        except Exception:
            return {"outboundTag": "direct"}
    # Direct-pool balancers: clients keep email~lb_* UUID but dial a node host.
    # On that agent, exit locally (local_direct) — do not re-enter Xray balancer.
    bal_pool = balancer_by_tag(store, tag)
    if bal_pool and bal_pool.get("sub_direct_pool"):
        try:
            import nodes as nodes_mod
            if not nodes_mod.is_master(store):
                ns = (store.get("settings") or {}).get("nodes") or {}
                self_tag = str(ns.get("direct_connect_tag") or "").strip()
                if ns.get("direct_connect") and self_tag:
                    if known_outbounds is None or self_tag in known_outbounds:
                        return {"outboundTag": self_tag}
                    return {"outboundTag": "direct"}
        except Exception:
            pass
    if _is_balancer_target(store, tag):
        for b in ensure_balancers(store).values():
            if b.get("tag") != tag or not b.get("enabled", True):
                continue
            # Pool without health gate — same set _balancers_cfg emits
            if balancer_member_tags(store, b, healthy_only=False):
                return {"balancerTag": tag}
            return {"outboundTag": balancer_fallback_tag(b)}
        return {"outboundTag": "direct"}
    if known_outbounds is not None and tag not in known_outbounds:
        # Never "leak" intended blocks to freedom when the tag is missing
        if tag == "block":
            return {"outboundTag": "block"}
        # Keep "master" even if dial outbound was not synced yet — falling back to
        # direct silently exits via the node IP instead of the panel IP.
        try:
            import nodes as nodes_mod
            if tag == nodes_mod.MASTER_EGRESS_TAG:
                return {"outboundTag": tag}
        except Exception:
            if tag == "master":
                return {"outboundTag": "master"}
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
        ib.setdefault("country", "")
        cc = str(ib.get("country") or "").strip().upper()
        ib["country"] = cc if re.fullmatch(r"[A-Z]{2}", cc) else ""
        if not ib.get("id"):
            ib["id"] = next_id
            next_id += 1
        # Inbound→outbound binding removed; routing uses client/group outbound only.
        ib["outbound"] = ""
        ensure_inbound_keys(ib)
        ib["listen"] = P.inbound_listen(ib)
        P.normalize_http_inbound(ib)
    # Inbounds from older versions (or pushed by a master node) may sit on a forbidden port
    for ib in inbounds:
        if port_forbidden_reason(int(ib.get("port") or 0), ib):
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


def _udp_can_share_reserved(ib: dict | None) -> bool:
    """Hysteria/mKCP are UDP-only — can share 443 with nginx (TCP) / nothing on UDP."""
    if not ib:
        return False
    proto = str(ib.get("protocol") or "").lower()
    net = str((ib.get("stream") or {}).get("network") or "").lower()
    return proto in ("hysteria", "hysteria2") or net in ("hysteria", "kcp")


def port_forbidden_reason(port: int, ib: dict | None = None) -> str:
    if not 1 <= port <= 65535:
        return "Порт 1..65535"
    if port in P.RESERVED_PORTS:
        # UDP Hysteria/mKCP may use 443 alongside nginx TCP:443 (Ascella-style LTE).
        if port == 443 and _udp_can_share_reserved(ib):
            return ""
        return f"Порт {port} запрещён для inbound (22, 80, 443 заняты SSH и nginx)"
    if port in system_ports():
        return f"Порт {port} занят панелью"
    return ""


def free_inbound_port(store: dict, exclude: dict | None = None, start: int = 10000) -> int:
    used = {int(i.get("port") or 0) for i in store.get("inbounds") or [] if i is not exclude}
    return next(p for p in range(start, 65535) if p not in used and not port_forbidden_reason(p, exclude))


def ensure_inbound_keys(ib: dict) -> None:
    st = ib["stream"]
    if st.get("security") == "reality":
        r = st["reality"]
        if r.get("private_key") and not r.get("public_key"):
            derived = reality_public_from_private(str(r["private_key"]))
            if derived.get("ok"):
                r["public_key"] = derived["public_key"]
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


def _is_client_capable_inbound(ib: dict) -> bool:
    if not isinstance(ib, dict) or ib.get("_system"):
        return False
    tag = str(ib.get("tag") or "").strip()
    if not tag:
        return False
    return ib.get("protocol") in P.USER_PROTOCOLS + ("wireguard", "socks", "http")


def client_capable_inbounds(store: dict) -> list[dict]:
    """Inbounds assignable to clients/groups.

    Master live list first (same object refs — needed by ``build_config`` identity
    checks), then unique tags from non-inherit core snapshots so groups can assign
    inbounds that exist only on node cores.
    """
    out: list[dict] = []
    seen: set[str] = set()
    for i in ensure_inbounds(store):
        if not _is_client_capable_inbound(i):
            continue
        tag = str(i.get("tag") or "")
        if tag in seen:
            continue
        seen.add(tag)
        out.append(i)
    try:
        import cores as cores_mod
        for core in cores_mod.ensure_cores(store) or []:
            if not isinstance(core, dict) or core.get("inherit_master"):
                continue
            cname = str(core.get("name") or core.get("id") or "core")
            cid = str(core.get("id") or "")
            for raw in cores_mod.apply_exclude_inbounds(list(core.get("inbounds") or []), core):
                if not _is_client_capable_inbound(raw):
                    continue
                tag = str(raw.get("tag") or "")
                if tag in seen:
                    continue
                seen.add(tag)
                ib = copy.deepcopy(raw)
                try:
                    P.ensure_inbound_shape(ib)
                except Exception:
                    pass
                ib["_from_core"] = cname
                ib["_core_id"] = cid
                out.append(ib)
    except Exception:
        pass
    return out


def client_inbounds(store: dict, client: dict) -> list[dict]:
    wanted = client_effective_inbounds(store, client)
    capable = client_capable_inbounds(store)
    if not wanted:
        return capable
    # Case-insensitive: UI / legacy data may store BUHAREST vs Buharest
    want = {str(t).strip().lower() for t in wanted if str(t).strip()}
    return [i for i in capable if str(i.get("tag") or "").strip().lower() in want]


def client_inbound_tags(store: dict, client: dict) -> set[str]:
    """Lowercased inbound tags assigned to the client (for build_config matching)."""
    return {str(i.get("tag") or "").strip().lower() for i in client_inbounds(store, client) if i.get("tag")}


# ---------------------------------------------------------------- client groups
# Groups assign inbounds only (outbounds / routing live in cores).
# Empty inbounds on a group = all. Client without group_id keeps personal inbound lists.
# Legacy allowed_tags / outbound fields may still exist in store; empty allowed_tags = all.

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
        # Explicit modes: empty lists alone used to mean «all», which flipped
        # «выбранные» (only primary / partial) back to «все» after save.
        if g.get("ib_mode") not in ("all", "select"):
            g["ib_mode"] = "select" if g.get("inbounds") else "all"
        if g.get("select_mode") not in ("all", "select"):
            g["select_mode"] = "select" if g.get("allowed_tags") else "all"
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


# Client outbound "none" = no main link; allowed_tags ["none"] = no extra connections.
NONE_TAG = "none"


def _merge_tag_lists(base: list[str], extra: list[str]) -> list[str]:
    """Union preserving order. Empty ``base`` means «all» — personal ``extra`` ignored."""
    if not base:
        return []
    seen = set(base)
    out = list(base)
    for tag in extra or []:
        t = str(tag or "").strip()
        if t and t != NONE_TAG and t not in seen:
            seen.add(t)
            out.append(t)
    return out


def client_effective_allowed_tags(store: dict, client: dict) -> list[str]:
    """Outbound tags allowed in subscription. Empty list = all.

    With a group: group list is the base; personal tags may add extras.
    Without a group: personal list only.
    """
    personal = list(client.get("allowed_tags") or [])
    g = client_group(store, client)
    if g is not None:
        return _merge_tag_lists(list(g.get("allowed_tags") or []), personal)
    return personal


def client_effective_inbounds(store: dict, client: dict) -> list[str]:
    """Inbound tags for the client. Empty list = all capable.

    With a group: group list is the base; personal inbounds may add extras.
    """
    personal = list(client.get("inbounds") or [])
    g = client_group(store, client)
    if g is not None:
        return _merge_tag_lists(list(g.get("inbounds") or []), personal)
    return personal


def client_default_outbound(store: dict, client: dict) -> str:
    """Main subscription link. Group (if any) always owns this; else personal."""
    g = client_group(store, client)
    if g is not None:
        ob = str(g.get("outbound") or "").strip()
        if ob:
            return ob
        for tag in g.get("allowed_tags") or []:
            if tag:
                return str(tag)
        return "direct"
    return str(client.get("outbound") or "direct")


def new_group(*, name: str = "", comment: str = "") -> dict:
    return {
        "id": "g_" + secrets.token_urlsafe(9).replace("-", "").replace("_", "")[:12],
        "name": (name or "Группа").strip() or "Группа",
        "comment": (comment or "").strip(),
        "allowed_tags": [],
        "inbounds": [],
        "ib_mode": "all",
        "select_mode": "all",
        "outbound": "",
    }


def list_mode(obj: dict | None, *, list_key: str, mode_key: str) -> str:
    """Resolve all|select for inbounds / allowed_tags (legacy: non-empty list ⇒ select)."""
    if not isinstance(obj, dict):
        return "all"
    mode = str(obj.get(mode_key) or "").strip().lower()
    if mode in ("all", "select"):
        return mode
    return "select" if obj.get(list_key) else "all"


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
    if client.get("ib_mode") not in ("all", "select"):
        client["ib_mode"] = "select" if client.get("inbounds") else "all"
    if client.get("select_mode") not in ("all", "select"):
        client["select_mode"] = "select" if client.get("allowed_tags") else "all"
    client.setdefault("outbound_limits", {})
    client.setdefault("daily_outbound_limits", {})
    client.setdefault("wg_private", "")
    client.setdefault("wg_public", "")
    client.setdefault("wg_ip", "")
    client.setdefault("wg_index", 0)
    client.setdefault("sub_enabled", True)
    client.setdefault("doh_enabled", False)
    client.setdefault("doh_in_tunnel", False)
    if not client.get("doh_token"):
        client["doh_token"] = secrets.token_urlsafe(18)
    # Cosmetic per-user path for WS/HTTPUpgrade/XHTTP (nginx rewrites to inbound path).
    ensure_client_link_token(client)
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


def ensure_client_link_token(client: dict) -> str:
    """Stable random token for per-user subscription paths (``/u-<token>``)."""
    tok = re.sub(r"[^A-Za-z0-9]", "", str(client.get("link_token") or ""))
    if len(tok) < 8:
        tok = re.sub(r"[^A-Za-z0-9]", "", secrets.token_urlsafe(16))[:16]
        client["link_token"] = tok
    else:
        client["link_token"] = tok[:32]
    return client["link_token"]


def client_cosmetic_path(store: dict, client: dict, ib: dict) -> str:
    """Unique path for the client link; nginx rewrites it to the inbound's real path.

    No extra Xray inbound — only subscription cosmetics + front regex location.
    """
    st = ib.get("stream") or {}
    net = st.get("network") or "raw"
    if P.front_mode(ib) != "http" or net not in ("ws", "httpupgrade", "xhttp"):
        return P.front_http_path(ib)
    token = ensure_client_link_token(client)
    domain = ""
    try:
        import front as front_mod
        domain = front_mod.normalize_host(ib.get("share_host") or "") or front_mod.public_domain(store) or ""
    except Exception:
        domain = str(ib.get("share_host") or "").strip().lower()
    # Multiple path inbounds on one host need distinct prefixes so regex locations do not clash.
    peers = 0
    for other in store.get("inbounds") or []:
        if not other.get("enabled", True) or P.front_mode(other) != "http":
            continue
        onet = ((other.get("stream") or {}).get("network") or "")
        if onet not in ("ws", "httpupgrade", "xhttp"):
            continue
        try:
            import front as front_mod
            od = front_mod.normalize_host(other.get("share_host") or "") or front_mod.public_domain(store) or ""
        except Exception:
            od = str(other.get("share_host") or "").strip().lower()
        if od and domain and od == domain:
            peers += 1
    if peers > 1:
        tag = re.sub(r"[^A-Za-z0-9]", "", str(ib.get("tag") or "x"))[:12] or "x"
        return f"/u-{tag}-{token}"
    return f"/u-{token}"


def _wg_pool(ib: dict) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    try:
        return ipaddress.ip_network(
            (ib.get("settings") or {}).get("address_pool") or "10.66.0.0/24",
            strict=False,
        )
    except ValueError:
        return None


def _wg_used_ips(store: dict, ib: dict, *, skip_email: str = "") -> set[str]:
    """IPs already assigned to other clients on this WireGuard inbound's pool."""
    used: set[str] = set()
    tag = str(ib.get("tag") or "")
    for c in store.get("clients") or []:
        if skip_email and c.get("email") == skip_email:
            continue
        on_ib = any(
            i.get("tag") == tag
            for i in client_inbounds(store, c)
            if i.get("protocol") == "wireguard"
        )
        if not on_ib:
            continue
        ip = str(c.get("wg_ip") or "").strip()
        if ip:
            used.add(ip.split("/")[0])
            continue
        derived = wg_ip(ib, c, allocate=False)
        if derived:
            used.add(derived)
    return used


def _wg_alloc_ip(store: dict, ib: dict, client: dict) -> str:
    """Pick first free host in inbound address_pool (skip network/broadcast/.1 gateway)."""
    net = _wg_pool(ib)
    if net is None:
        return ""
    used = _wg_used_ips(store, ib, skip_email=str(client.get("email") or ""))
    hosts = list(net.hosts())
    # Prefer .2+ — .1 is conventionally the server/gateway in the pool.
    for host in hosts:
        if int(host) == int(net.network_address) + 1:
            continue
        s = str(host)
        if s not in used:
            return s
    for host in hosts:
        s = str(host)
        if s not in used:
            return s
    return ""


def ensure_wg_peer(store: dict, client: dict) -> None:
    """Generate WG keys + unique tunnel IP from each WG inbound pool (unless set manually)."""
    wgs = [i for i in client_inbounds(store, client) if i.get("protocol") == "wireguard"]
    if not wgs:
        return
    if not client.get("wg_private") or not client.get("wg_public"):
        keys = generate_wg_keys()
        if keys.get("ok"):
            client["wg_private"], client["wg_public"] = keys["private_key"], keys["public_key"]
    manual = str(client.get("wg_ip") or "").strip()
    if manual:
        # Keep index in sync when possible (first WG inbound).
        try:
            net = _wg_pool(wgs[0])
            if net is not None:
                idx = int(ipaddress.ip_address(manual.split("/")[0])) - int(net.network_address)
                if idx > 0:
                    client["wg_index"] = idx
        except ValueError:
            pass
        return
    # Allocate unique IP in the primary WG inbound pool.
    ip = _wg_alloc_ip(store, wgs[0], client)
    if ip:
        client["wg_ip"] = ip
        try:
            net = _wg_pool(wgs[0])
            if net is not None:
                client["wg_index"] = int(ipaddress.ip_address(ip)) - int(net.network_address)
        except ValueError:
            pass
    elif not client.get("wg_index"):
        used = {int(c.get("wg_index") or 0) for c in store.get("clients") or []}
        idx = 2
        while idx in used:
            idx += 1
        client["wg_index"] = idx


def wg_ip(ib: dict, client: dict, *, allocate: bool = True) -> str:
    """Client tunnel IP for this WireGuard inbound.

    Prefer explicit client.wg_ip (manual or previously allocated). Otherwise derive
    from wg_index within the inbound address_pool.
    """
    manual = str(client.get("wg_ip") or "").strip()
    if manual:
        return manual.split("/")[0]
    try:
        net = ipaddress.ip_network((ib.get("settings") or {}).get("address_pool") or "10.66.0.0/24", strict=False)
        idx = int(client.get("wg_index") or 0)
        if idx <= 0:
            return ""
        return str(net.network_address + idx)
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
    if tag == NONE_TAG:
        return False
    default = client_default_outbound(store, client)
    # «Основная» всегда допустима, даже если чекбокс extras не отмечен.
    if tag == default and default and default != NONE_TAG:
        pass
    else:
        allowed = client_effective_allowed_tags(store, client)
        if NONE_TAG in allowed:
            # Only the main link: extra connections are off
            allowed = [t for t in allowed if t != NONE_TAG]
            if tag not in allowed:
                return False
        elif allowed and tag not in allowed:
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


def selectable_outbound_tags(store: dict, *, include_system: bool = True) -> list[dict]:
    """Outbounds historically shown in client/group subscription pickers.

    Balancers are excluded — they are routing-only and must not appear to users.
    ``direct`` is a system tag (opt-in): selectable in UI, but not auto-added when
    mode is «все» / when freezing new outbound tags onto users.
    """
    ensure_balancers(store)
    out: list[dict] = []
    if include_system:
        out.append({"tag": "direct", "label": outbound_label(store, "direct"), "kind": "system"})
    for o in store.get("outbounds_custom") or []:
        kind = "custom"
        if o.get("kind") == "node" or str(o.get("tag") or "").startswith("node_"):
            kind = "node"
        status = custom_outbound_status(o)
        if o.get("direct_connect") or o.get("kind") == "local_direct":
            status = "Direct" if status in ("connected", "enabled", "", None) else status
        out.append({
            "tag": o["tag"], "label": outbound_label(store, o["tag"]), "kind": kind,
            "status": status, "direct_connect": bool(o.get("direct_connect") or o.get("kind") == "local_direct"),
        })
    return out


def _all_inbound_tags(store: dict, *, exclude: str = "") -> list[str]:
    tags = [i["tag"] for i in client_capable_inbounds(store) if i.get("tag")]
    if exclude:
        tags = [t for t in tags if t != exclude]
    return tags


def _all_outbound_assign_tags(store: dict, *, exclude: str = "") -> list[str]:
    # Exclude system tags (direct): freeze/propagate must not silently opt everyone into Direct.
    tags = [x["tag"] for x in selectable_outbound_tags(store, include_system=False) if x.get("tag")]
    if exclude:
        tags = [t for t in tags if t != exclude]
    return tags


def apply_tag_to_users(store: dict, *, kind: str, tag: str, propagate: bool) -> dict:
    """Add a new inbound/outbound tag to clients and groups, or freeze «all» lists without it.

    Empty ``inbounds`` / ``allowed_tags`` means «all». Without an explicit freeze, every new
    tag instantly appears for those users. ``propagate=False`` materializes the previous
    universe (all tags except ``tag``) so the new one stays opt-in.
    """
    tag = str(tag or "").strip()
    if not tag or kind not in ("inbound", "outbound"):
        return {"clients": 0, "groups": 0, "mode": "skip"}
    key = "inbounds" if kind == "inbound" else "allowed_tags"
    universe = (
        _all_inbound_tags(store, exclude=tag) if kind == "inbound"
        else _all_outbound_assign_tags(store, exclude=tag)
    )
    clients_n = groups_n = 0
    for c in store.get("clients") or []:
        cur = list(c.get(key) or [])
        if propagate:
            if not cur:
                continue  # empty = all → already includes the new tag
            if tag not in cur and NONE_TAG not in cur:
                cur.append(tag)
                c[key] = cur
                clients_n += 1
        else:
            if not cur:
                c[key] = list(universe)
                clients_n += 1
            # non-empty personal lists already exclude the new tag unless listed
    for g in ensure_groups(store):
        cur = list(g.get(key) or [])
        if propagate:
            if not cur:
                continue
            if tag not in cur and NONE_TAG not in cur:
                cur.append(tag)
                g[key] = cur
                groups_n += 1
        else:
            if not cur:
                g[key] = list(universe)
                groups_n += 1
    return {"clients": clients_n, "groups": groups_n, "mode": "add" if propagate else "freeze"}


def subscription_entries(store: dict, client: dict, *, ignore_quota: bool = False) -> list[dict]:
    """Extra subscription identities beyond the main inbound profile.

    Users are assigned **inbounds only**; routing/outbounds live in cores.
    Therefore subscription shows one profile per inbound (main UUID) — no
    extra outbound rows (no ``🖥️ tag · GB …`` lines).

    Legacy: if ``allowed_tags`` is a non-empty explicit list, those custom
    outbound tags may still be emitted (API / old data). Empty list = none.
    Balancers never appear.
    """
    if not client.get("uuid") or not client.get("sub_enabled", True):
        return []
    if not ignore_quota and not client_access_ok(client):
        return []
    # Explicit opt-in only (non-empty allowed_tags). Mode «все» / empty → no extras.
    eff = [t for t in client_effective_allowed_tags(store, client) if t and t != NONE_TAG]
    if not eff:
        return []
    in_sub_customs = {
        o["tag"] for o in store.get("outbounds_custom") or []
        if o.get("enabled", True) and o.get("in_sub", True) and o.get("tag")
    }
    default = client_default_outbound(store, client)
    if balancer_by_tag(store, default):
        default = "direct"
    entries = []
    for tag in eff:
        if tag == default or tag == "direct":
            continue
        if balancer_by_tag(store, tag):
            continue
        if tag not in in_sub_customs:
            continue
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


def _is_direct_connect_tag(store: dict, tag: str) -> bool:
    """True when ``tag`` is a Direct-connect node outbound (master registry or agent self-tag).

    Unlike ``_direct_connect_endpoint_host``, does **not** require a resolvable public host —
    sync on agents must still emit ``email~node_*`` identities when panel host is briefly empty.
    """
    tag = str(tag or "").strip()
    if not tag or tag in ("direct", "block", "master"):
        return False
    try:
        import nodes as nodes_mod
        node = nodes_mod.node_by_outbound_tag(store, tag)
        if nodes_mod.uses_direct_connect(node):
            return True
        ns = (store.get("settings") or {}).get("nodes") or {}
        if ns.get("direct_connect") and str(ns.get("direct_connect_tag") or "").strip() == tag:
            return True
    except Exception:
        pass
    return False


def client_identities(store: dict, client: dict, ib: dict) -> list[dict]:
    main = {"uuid": client["uuid"], "email": client["email"], "password": client["password"], "main": True, "tag": ""}
    if ib["protocol"] == "wireguard":
        main.update({"wg_public": client.get("wg_public"), "wg_private": client.get("wg_private"), "wg_ip": wg_ip(ib, client)})
        return [main]
    if ib["protocol"] in ("socks", "http"):
        return [main]
    # Direct-connect primary: share link dials the node with email~node_* UUID.
    # Register that identity even when subscription_entries skips the default tag.
    default = client_default_outbound(store, client)
    out: list[dict] = []
    if default and default != "direct" and _is_direct_connect_tag(store, default):
        ident_uuid = P.identity_uuid(client["uuid"], default)
        out.append({
            "uuid": ident_uuid,
            "email": f"{client['email']}~{default}",
            "password": P.derived_password(ident_uuid),
            "main": True,
            "tag": default,
            "label": outbound_label(store, default),
        })
        # On Direct agents also keep the base UUID so a flaky sync that only
        # emitted the legacy identity still accepts the client.
        try:
            import nodes as nodes_mod
            if not nodes_mod.is_master(store):
                out.append(dict(main))
        except Exception:
            out.append(dict(main))
    else:
        out.append(main)
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


def _direct_connect_endpoint_host(store: dict, tag: str) -> tuple[str, dict | None]:
    """If tag is a direct_connect node outbound, return (node_host, remapped_ib_helper_node).

    On a Direct agent the nodes registry is empty — fall back to
    ``settings.nodes.direct_connect_tag`` + local public host.
    """
    tag = str(tag or "").strip()
    if not tag or not _is_direct_connect_tag(store, tag):
        return "", None
    try:
        import nodes as nodes_mod
        node = nodes_mod.node_by_outbound_tag(store, tag)
        if nodes_mod.uses_direct_connect(node):
            return nodes_mod.node_public_domain(node) or "", node
        host = ""
        try:
            import front as front_mod
            host = front_mod.public_domain(store) or ""
        except Exception:
            host = ""
        if not host:
            host = str(((store.get("settings") or {}).get("panel") or {}).get("public_host") or "")
        return str(host or "").strip(), None
    except Exception:
        pass
    return "", None


def _apply_cosmetic_path(store: dict, client: dict, ib: dict, ep: dict) -> None:
    """Swap subscription path to per-user /u-… (nginx rewrites to the real inbound path)."""
    if not ep:
        return
    net = str(ep.get("net") or ((ib.get("stream") or {}).get("network") or ""))
    if P.front_mode(ib) != "http" or net not in ("ws", "httpupgrade", "xhttp"):
        return
    real = str(ep.get("path") or P.front_http_path(ib) or "/")
    _base, sep, query = real.partition("?")
    cosmetic = client_cosmetic_path(store, client, ib)
    ep["path"] = f"{cosmetic}?{query}" if sep and query else cosmetic


def _core_id_for_inbound(store: dict, ib: dict) -> str:
    """Core id that owns this inbound (from ``_core_id`` marker or tag match)."""
    cid = str(ib.get("_core_id") or "").strip()
    if cid:
        return cid
    tag = str(ib.get("tag") or "").strip()
    if not tag:
        return ""
    try:
        import cores as cores_mod
        for core in cores_mod.ensure_cores(store) or []:
            if not isinstance(core, dict) or core.get("inherit_master"):
                continue
            for raw in core.get("inbounds") or []:
                if isinstance(raw, dict) and str(raw.get("tag") or "") == tag:
                    return str(core.get("id") or "").strip()
    except Exception:
        pass
    return ""


def _direct_node_host_for_inbound(store: dict, ib: dict, master_hosts: set[str]) -> tuple[str, dict | None]:
    """If inbound belongs to a Direct node's core, return (node_domain, remapped_ib).

    Subscription must dial the node (e.g. ``buh.ro0t.dev``), not the panel host
    (``web.ro0t.dev``). Bridge/tunnel nodes keep the master domain.
    """
    try:
        import nodes as nodes_mod
    except Exception:
        return "", None
    # Explicit share_host that is already a non-master domain wins.
    try:
        import front as front_mod
        explicit = front_mod.normalize_host(ib.get("share_host") or "")
    except Exception:
        explicit = str(ib.get("share_host") or "").strip().lower()
    if explicit and explicit not in master_hosts:
        return explicit, None

    cid = _core_id_for_inbound(store, ib)
    if not cid:
        return "", None
    best = None
    for node in nodes_mod.ensure_list(store):
        if str(node.get("core_id") or "").strip() != cid:
            continue
        if not nodes_mod.uses_direct_connect(node):
            continue
        dom = nodes_mod.node_public_domain(node) or ""
        if not dom:
            continue
        best = (dom, node)
        break
    if not best:
        return "", None
    dom, _node = best
    try:
        remapped = nodes_mod.remap_inbounds_for_host(
            [ib], new_host=dom, old_hosts=master_hosts,
        )
        return dom, (remapped[0] if remapped else None)
    except Exception:
        return dom, None


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
    master_hosts: set[str] = set()
    try:
        import nodes as nodes_mod
        master_hosts = nodes_mod.master_public_domains(store)
    except Exception:
        master_hosts = set()
    pool_hidden = direct_pool_hidden_member_tags(store)
    # Several identities from one inbound (or several inbounds) → append outbound label
    multi_idents = multi or any(len(client_identities(store, client, i)) > 1 for i in ibs)
    for ib in ibs:
        core_host, core_ib = _direct_node_host_for_inbound(store, ib, master_hosts)
        ib_base = core_ib or ib
        for ident in client_identities(store, client, ib):
            if ident["main"]:
                ob = client_default_outbound(store, client)
                if ob == NONE_TAG:
                    continue
                # Balancers are routing-only — never emit a balancer profile to the user.
                if balancer_by_tag(store, ob):
                    ob = "direct"
                if ob != "direct" and not tag_allowed_for_client(store, client, ob):
                    continue
                if ob != "direct" and not outbound_ok_for_sub(store, ob):
                    continue
                remark = subscription_profile_remark(
                    store, client, ib,
                    outbound_tag=ob,
                    quota_suffix=tag_quota_suffix(client, ob),
                    # Main profile: inbound name only (even for Direct node)
                    with_outbound=False,
                )
                dc_host, _dc_node = _direct_connect_endpoint_host(store, ob)
                # Direct node as основная: dial node host with email~node_* (agent local_direct)
                if ob and ob != "direct" and _is_direct_connect_tag(store, ob):
                    ident_uuid = P.identity_uuid(client["uuid"], ob)
                    ident_use = {
                        "uuid": ident_uuid,
                        "email": f"{client['email']}~{ob}",
                        "password": P.derived_password(ident_uuid),
                        "main": True,
                        "tag": ob,
                        "label": outbound_label(store, ob),
                    }
                else:
                    ident_use = ident
            else:
                tag = str(ident.get("tag") or "")
                # Balancers never appear as separate subscription profiles.
                if balancer_by_tag(store, tag):
                    continue
                if tag in pool_hidden:
                    continue
                remark = subscription_profile_remark(
                    store, client, ib,
                    outbound_tag=tag,
                    outbound_label_text=str(ident.get("label") or outbound_label(store, tag)),
                    quota_suffix=tag_quota_suffix(client, tag),
                    with_outbound=True,
                )
                dc_host, _dc_node = _direct_connect_endpoint_host(store, tag)
                ident_use = ident
            ib_use = ib_base
            host_use = core_host or host
            if dc_host:
                host_use = dc_host
                try:
                    import nodes as nodes_mod
                    remapped = nodes_mod.remap_inbounds_for_host(
                        [ib_base], new_host=dc_host, old_hosts=master_hosts,
                    )
                    if remapped:
                        ib_use = remapped[0]
                except Exception:
                    ib_use = ib_base
            ep = P.endpoint_for(ib_use, ident_use, host_use, remark)
            if ep:
                _apply_cosmetic_path(store, client, ib_use, ep)
                eps.extend(P._apply_external_proxy(ep, ib_use))
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
    # RU: Loyalsoldier category + TLD .ru / .su / .рф (punycode xn--p1ai) + geoip:ru
    # After installing Russia pack: add ext:geosite_RU.dat:ru / ext:geoip_RU.dat:ru via edit
    "direct_ru": {
        "name": "direct-ru",
        "outbound": "direct",
        "domain": [
            "geosite:category-ru",
            "regexp:.*\\.ru$",
            "regexp:.*\\.su$",
            "regexp:.*\\.xn--p1ai$",
            "regexp:.*\\.рф$",
        ],
        "ip": ["geoip:ru"],
    },
    "direct_ru_pack": {
        "name": "direct-ru-pack",
        "outbound": "direct",
        "domain": [
            "ext:geosite_RU.dat:ru",
            "geosite:category-ru",
            "regexp:.*\\.ru$",
            "regexp:.*\\.su$",
            "regexp:.*\\.xn--p1ai$",
            "regexp:.*\\.рф$",
        ],
        "ip": ["ext:geoip_RU.dat:ru", "geoip:ru"],
    },
    "direct_cn": {"name": "direct-cn", "outbound": "direct", "domain": ["geosite:cn"], "ip": ["geoip:cn"]},
    "direct_ir": {"name": "direct-ir", "outbound": "direct", "domain": ["regexp:.*\\.ir$"], "ip": ["geoip:ir"]},
    "direct_ir_pack": {
        "name": "direct-ir-pack",
        "outbound": "direct",
        "domain": ["ext:geosite_IR.dat:ir", "regexp:.*\\.ir$"],
        "ip": ["ext:geoip_IR.dat:ir", "geoip:ir"],
    },
    "block_porn": {"name": "block-porn", "outbound": "block", "domain": ["geosite:category-porn"]},
}


GEO_DIR = Path(os.environ.get("XRAY_LOCATION_ASSET", "/usr/local/share/xray"))
_EXT_GEO_RE = re.compile(r"^ext:([A-Za-z0-9_.-]+\.dat):", re.I)


def ext_geo_file(entry: Any) -> str:
    """'ext:geosite_RU.dat:ru' → 'geosite_RU.dat' ('' for non-ext entries)."""
    m = _EXT_GEO_RE.match(str(entry or "").strip())
    return m.group(1) if m else ""


def geo_file_present(name: str) -> bool:
    p = GEO_DIR / name
    try:
        return p.is_file() and p.stat().st_size >= 1024
    except OSError:
        return False


def route_missing_geo(r: dict) -> list[str]:
    """ext:*.dat files referenced by a route that are not on disk yet."""
    out: set[str] = set()
    for key in ("domain", "ip"):
        for entry in r.get(key) or []:
            name = ext_geo_file(entry)
            if name and not geo_file_present(name):
                out.add(name)
    return sorted(out)


def missing_ext_geo(store: dict) -> list[str]:
    """All missing ext:*.dat files across enabled routes."""
    out: set[str] = set()
    for r in store.get("routes") or []:
        if r.get("enabled", True):
            out.update(route_missing_geo(r))
    return sorted(out)


def _filter_geo_entries(vals: list) -> list | None:
    """Drop ext:*.dat entries whose files are missing. None = nothing left (skip that arm)."""
    kept = [v for v in vals if not ext_geo_file(v) or geo_file_present(ext_geo_file(v))]
    return kept or None


def expand_route_users(store: dict, users: list) -> list[str]:
    """Expand selected client emails to all Xray emails (main + email~tag)."""
    if not users:
        return []
    wanted = {str(u).strip() for u in users if str(u).strip()}
    if not wanted:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for client in store.get("clients") or []:
        ensure_client(client)
        main = str(client.get("email") or "").strip()
        if not main:
            continue
        emails = [main]
        try:
            for e in subscription_entries(store, client, ignore_quota=True):
                em = str(e.get("email") or "").strip()
                if em and em not in emails:
                    emails.append(em)
        except Exception:
            pass
        if main in wanted or any(em in wanted for em in emails):
            for em in emails:
                if em not in seen:
                    seen.add(em)
                    out.append(em)
    for u in users:
        u = str(u).strip()
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out


def route_picker_clients(store: dict) -> list[dict]:
    """Clients for routing multi-select: email + known IPs as name-ip labels."""
    rows: list[dict] = []
    for client in store.get("clients") or []:
        ensure_client(client)
        email = str(client.get("email") or "").strip()
        if not email:
            continue
        ips_map = client.get("ips") or {}
        ips: list[dict] = []
        if isinstance(ips_map, dict):
            # newest first
            ordered = sorted(ips_map.items(), key=lambda kv: str(kv[1] or ""), reverse=True)
            for ip, _seen in ordered:
                ip = str(ip or "").strip()
                if not ip:
                    continue
                ips.append({"ip": ip, "label": f"{email}-{ip}"})
        rows.append({"email": email, "label": email, "ips": ips})
    rows.sort(key=lambda r: r["label"].lower())
    return rows


def route_picker_source_ips(store: dict) -> list[dict]:
    """Flat IP options for routing source multi-select (label = name-ip)."""
    seen: set[str] = set()
    out: list[dict] = []
    for row in route_picker_clients(store):
        for item in row.get("ips") or []:
            ip = item.get("ip") or ""
            if not ip or ip in seen:
                continue
            seen.add(ip)
            out.append({"ip": ip, "label": item.get("label") or f"{row['email']}-{ip}", "email": row["email"]})
    return out


def _rule_from_route(store: dict, r: dict, *, known_outbounds: set[str] | None = None) -> list[dict]:
    """Build Xray field rule(s) from a panel route.

    Xray ANDs attributes on one rule. Panel UI treats domain and IP as alternative
    match arms (OR) — emit separate rules when both are set, sharing other filters.
    """
    if not r.get("enabled", True):
        return []
    target = r.get("outbound") or r.get("outbound_tag") or "direct"
    base: dict[str, Any] = {"type": "field", **_route_target(store, target, known_outbounds=known_outbounds)}
    for key, xkey in (("user", "user"), ("protocol", "protocol"),
                      ("source", "source"), ("inbound_tags", "inboundTag")):
        val = r.get(key)
        if not val:
            continue
        vals = val if isinstance(val, list) else [val]
        if key == "user":
            vals = expand_route_users(store, vals)
        if not vals:
            continue
        base[xkey] = vals
    for key, xkey in (("network", "network"), ("port", "port"), ("source_port", "sourcePort")):
        if r.get(key):
            base[xkey] = str(r[key])

    raw_domain = r.get("domain") or []
    raw_ip = r.get("ip") or []
    if not isinstance(raw_domain, list):
        raw_domain = [raw_domain]
    if not isinstance(raw_ip, list):
        raw_ip = [raw_ip]
    raw_domain = [_normalize_route_domain(v) for v in raw_domain if v]
    raw_ip = [v for v in raw_ip if v]
    # Drop master-only system inbounds from inboundTag (agents don't have them)
    if isinstance(base.get("inboundTag"), list):
        try:
            import nodes as nodes_mod
            sys_tags = {nodes_mod.MASTER_BACKHAUL_TAG, "rv-in", "api", "node-bridge"}
        except Exception:
            sys_tags = {"master-backhaul", "rv-in", "api", "node-bridge"}
        base["inboundTag"] = [t for t in base["inboundTag"] if t and t not in sys_tags]
        if not base["inboundTag"]:
            base.pop("inboundTag", None)
    domain_vals = _filter_geo_entries(raw_domain) if raw_domain else None
    ip_vals = _filter_geo_entries(raw_ip) if raw_ip else None
    # All geo entries missing (ext:*.dat not downloaded yet) → skip, don't widen match
    if (raw_domain or raw_ip) and not domain_vals and not ip_vals:
        return []

    arms: list[dict[str, Any]] = []
    if domain_vals:
        arms.append({"domain": domain_vals})
    if ip_vals:
        arms.append({"ip": ip_vals})
    if not arms:
        # No domain/ip — rule may still match on user/protocol/source/inbound/network/port
        arms.append({})

    tag_base = re.sub(r"[^A-Za-z0-9_.-]", "_", str(r.get("name") or ""))[:56] if r.get("name") else ""
    keys = ("domain", "ip", "user", "protocol", "source", "inboundTag", "network", "port", "sourcePort")
    out: list[dict] = []
    for i, arm in enumerate(arms):
        rule = {**base, **arm}
        if tag_base:
            rule["ruleTag"] = tag_base if len(arms) == 1 else f"{tag_base}_{i + 1}"[:64]
        if any(k in rule for k in keys):
            out.append(rule)
    return out


_ROUTE_DOMAIN_PREFIXES = (
    "domain:", "full:", "keyword:", "regexp:", "geosite:", "ext:", "dotless:", "root:",
)


def _normalize_route_domain(entry: Any) -> str:
    """Bare hostnames → domain:host so SNI matches the site and its subdomains.

    Legacy 3x-ui imports often store plain ``2ip.ru`` (Xray keyword/substring).
    Prefixed entries and geosite/regexp/ext are left unchanged.
    """
    s = str(entry or "").strip()
    if not s:
        return s
    low = s.lower()
    if any(low.startswith(p) for p in _ROUTE_DOMAIN_PREFIXES):
        return s
    # geosite: / ext: without going through lower for unicode hosts
    if ":" in s and not re.match(r"^[A-Za-z0-9*._-]+$", s):
        return s
    if re.match(r"^[A-Za-z0-9*._-]+$", s):
        return f"domain:{s}"
    return s


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
    # Match by tag (case-insensitive), not object identity — core views / agent
    # copies are different dicts with the same tag.
    client_ib_tags = {id(c): client_inbound_tags(store, c) for c in active_clients}
    for ib in inbounds_model:
        if not inbound_access_ok(ib):
            continue
        ib_tag_l = str(ib.get("tag") or "").strip().lower()
        identities: list[dict] = []
        for c in active_clients:
            if ib_tag_l and ib_tag_l in client_ib_tags.get(id(c), set()):
                identities.extend(client_identities(store, c, ib))
        built = P.build_inbound(ib, identities)
        # Panel routes (domain / protocol / ads / geo) need sniffing every time —
        # without it matches flap depending on whether the client dialed by IP or name.
        if ib.get("protocol") in P.USER_PROTOCOLS:
            _force_routing_sniff(built)
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
    # Sync node_* outbounds (reverse portals / l2x SOCKS) before they enter the config
    try:
        import nodes as nodes_mod
        if nodes_mod.is_master(store):
            nodes_mod.sync_all_node_outbounds(store)
    except Exception:
        pass

    outbounds.extend(_custom_outbounds(store))
    if fake.get("enabled"):
        outbounds.append({"tag": "dns-out", "protocol": "dns"})

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
            ob = str(ib.get("outbound") or "").strip()
            if not ob or ob.lower() in ("none", "-", "off"):
                # none: do not bind inbound→direct (can loop via dialerProxy / reverse)
                continue
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
    # Domain/ip/user rules before inbound-only catch-alls (first match wins).
    # Prevents a misplaced ``inbound → balancer`` from stealing destinations that
    # have an earlier-intended panel route when the admin reorders the list.
    try:
        import nodes as _nodes_rt
        _has_sel = _nodes_rt._route_has_selector
    except Exception:
        def _has_sel(r: dict) -> bool:  # type: ignore[misc]
            for key in ("domain", "ip", "user", "source", "protocol"):
                val = r.get(key)
                if isinstance(val, list) and any(str(x).strip() for x in val):
                    return True
                if isinstance(val, str) and val.strip():
                    return True
            return False
    _routes = list(store.get("routes") or [])
    _routes = [r for r in _routes if _has_sel(r)] + [r for r in _routes if not _has_sel(r)]
    for r in _routes:
        rules.extend(_rule_from_route(store, r, known_outbounds=known_outbounds))
    # Telegram (and similar) must not spread across balancer exit IPs — MTProto
    # hangs/reconnects when sibling TCP connections leave via different nodes.
    # Pin geosite/geoip:telegram to one sticky member before user→balancerTag.
    rules.extend(_telegram_sticky_rules(store, active_clients, known_outbounds=known_outbounds))
    for c in active_clients:
        for e in subscription_entries(store, c):
            rules.append({
                "type": "field", "user": [e["email"]],
                **_route_target(store, e["tag"], known_outbounds=known_outbounds),
            })
        ob = client_default_outbound(store, c)
        if ob == NONE_TAG or (ob != "direct" and not tag_allowed_for_client(store, c, ob)):
            rules.append({"type": "field", "user": [c["email"]], "outboundTag": "block"})
        elif ob != "direct":
            rules.append({
                "type": "field", "user": [c["email"]],
                **_route_target(store, ob, known_outbounds=known_outbounds),
            })
            # Direct-connect primary identity is email~node_* (see client_identities)
            if _is_direct_connect_tag(store, ob):
                rules.append({
                    "type": "field",
                    "user": [f"{c['email']}~{ob}"],
                    **_route_target(store, ob, known_outbounds=known_outbounds),
                })
    rules.extend(per_inbound_rules)
    rules.append({"type": "field", "network": "tcp,udp", "outboundTag": "direct"})

    # AsIs + forced sniffing/routeOnly: routing sees sniffed domain AND original IP
    # without a second DNS pass (IPIfNonMatch was flaky when DNS/cache lagged).
    routing: dict[str, Any] = {
        "domainStrategy": "AsIs",
        "domainMatcher": "hybrid",
        "rules": rules,
    }
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
                    # connIdle 120: drop idle proxy sessions sooner (was 300; nginx stream timeout 10m)
                    "bufferSize": 1024, "connIdle": 120, "handshake": 8, "uplinkOnly": 2, "downlinkOnly": 5,
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
    try:
        _inject_master_backhaul(store, cfg)
    except Exception:
        pass

    patch = xs.get("template_patch") or {}
    if patch:
        cfg = deep_merge(cfg, patch)
    # Legacy reverse{} is rejected by current Xray — never emit it (even via template patch)
    cfg.pop("reverse", None)
    return cfg


def _balancers_cfg(store: dict) -> tuple[list[dict], dict | None, dict | None]:
    """Emit enabled balancers with a stable selector (no probe-health filter).

    Health probes still update ``last_test`` for subscriptions, but routing must not
    rebuild selector on every probe spike — that flipped user routes between balancer
    and fallback. Observatory + ``fallbackTag`` handle dead peers.
    Selector = enabled customs (outbounds that exist in config).
    """
    bals = ensure_balancers(store)
    out: list[dict] = []
    observatory = burst = None
    obs_subjects: set[str] = set()

    ping_b = bals.get("least_ping") or {}
    if ping_b.get("enabled", True):
        members = balancer_member_tags(store, ping_b, healthy_only=False)
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
        members = balancer_member_tags(store, load_b, healthy_only=False)
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

    rand_b = bals.get("random") or {}
    if rand_b.get("enabled", True):
        members = balancer_member_tags(store, rand_b, healthy_only=False)
        if members:
            entry = {
                "tag": rand_b["tag"], "selector": members, "strategy": {"type": "random"},
                "fallbackTag": balancer_fallback_tag(rand_b),
            }
            out.append(entry)
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


def _force_routing_sniff(built: dict) -> None:
    """Sniffing + routeOnly so domain/protocol panel routes always see SNI/Host + original IP."""
    sn = built.setdefault("sniffing", {})
    sn["enabled"] = True
    dest = [d for d in (sn.get("destOverride") or []) if d]
    for d in ("http", "tls", "quic"):
        if d not in dest:
            dest.append(d)
    sn["destOverride"] = dest
    sn["routeOnly"] = True
    sn["metadataOnly"] = False


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


def _inbound_users_map(cfg: dict) -> dict[str, dict[str, dict]]:
    """tag → {email → client dict} for user-protocol inbounds."""
    out: dict[str, dict[str, dict]] = {}
    for ib in cfg.get("inbounds") or []:
        tag = str(ib.get("tag") or "")
        if not tag or tag in ("api",):
            continue
        clients = ((ib.get("settings") or {}).get("clients")) or []
        if not isinstance(clients, list):
            continue
        bucket: dict[str, dict] = {}
        for c in clients:
            if not isinstance(c, dict):
                continue
            email = str(c.get("email") or "").strip()
            if email:
                bucket[email] = c
        if bucket:
            out[tag] = bucket
    return out


def _user_routing_fingerprint(cfg: dict) -> str:
    """Stable fingerprint of per-user routing rules (email → target)."""
    rows: list[str] = []
    for r in (cfg.get("routing") or {}).get("rules") or []:
        if not isinstance(r, dict):
            continue
        users = r.get("user")
        if not isinstance(users, list) or not users:
            continue
        target = r.get("outboundTag") or r.get("balancerTag") or ""
        rows.append(json.dumps([sorted(str(u) for u in users), target], sort_keys=True))
    return "\n".join(sorted(rows))


def _structure_fingerprint(cfg: dict) -> str:
    """Config without inbound clients and without per-user routing rules."""
    c = copy.deepcopy(cfg)
    for ib in c.get("inbounds") or []:
        settings = ib.get("settings")
        if isinstance(settings, dict) and "clients" in settings:
            settings["clients"] = []
    routing = c.get("routing")
    if isinstance(routing, dict) and isinstance(routing.get("rules"), list):
        routing["rules"] = [
            r for r in routing["rules"]
            if not (isinstance(r, dict) and isinstance(r.get("user"), list) and r.get("user"))
        ]
    return json.dumps(c, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _api_rmu(tag: str, emails: list[str]) -> dict:
    if not emails:
        return {"ok": True, "removed": 0}
    cmd = [XRAY_BIN, "api", "rmu", f"--server={XRAY_API}", f"-tag={tag}", *emails]
    r = _run(cmd, timeout=20)
    return {"ok": r["exit_code"] == 0, "stderr": (r.get("stderr") or "")[-300:], "stdout": (r.get("stdout") or "")[-300:]}


def _api_adu_inbound(tag: str, protocol: str, clients: list[dict], listen: str = "0.0.0.0", port: int = 0) -> dict:
    """Add users via ``xray api adu`` using a minimal inbound stub JSON."""
    if not clients:
        return {"ok": True, "added": 0}
    stub = {
        "inbounds": [{
            "tag": tag,
            "protocol": protocol or "vless",
            "listen": listen or "0.0.0.0",
            "port": int(port or 0),
            "settings": {"clients": clients, "decryption": "none"} if (protocol or "vless") == "vless"
            else {"clients": clients},
        }],
    }
    if (protocol or "") == "trojan":
        stub["inbounds"][0]["settings"] = {"clients": clients}
    elif (protocol or "") in ("shadowsocks", "ss"):
        stub["inbounds"][0]["settings"] = {"clients": clients}
    elif (protocol or "") == "vmess":
        stub["inbounds"][0]["settings"] = {"clients": clients}
    tmp = XRAY_CONFIG.parent / f".l2x-adu-{secrets.token_hex(4)}.json"
    try:
        tmp.write_text(json.dumps(stub, ensure_ascii=False), encoding="utf-8")
        r = _run([XRAY_BIN, "api", "adu", f"--server={XRAY_API}", str(tmp)], timeout=30)
        ok = r["exit_code"] == 0 or "already exists" in ((r.get("stderr") or "") + (r.get("stdout") or "")).lower()
        return {"ok": ok, "stderr": (r.get("stderr") or "")[-400:], "stdout": (r.get("stdout") or "")[-400:]}
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass


def sync_clients_via_api(live_cfg: dict, new_cfg: dict) -> dict:
    """Diff inbound users and apply via HandlerService (adu/rmu). No restart."""
    live_users = _inbound_users_map(live_cfg)
    new_users = _inbound_users_map(new_cfg)
    tags = set(live_users) | set(new_users)
    proto_by_tag = {
        str(ib.get("tag") or ""): str(ib.get("protocol") or "vless")
        for ib in (new_cfg.get("inbounds") or [])
        if ib.get("tag")
    }
    listen_port = {
        str(ib.get("tag") or ""): (
            str(ib.get("listen") or "0.0.0.0"),
            int(ib.get("port") or 0),
        )
        for ib in (new_cfg.get("inbounds") or [])
        if ib.get("tag")
    }
    added = removed = 0
    errors: list[str] = []
    for tag in sorted(tags):
        old = live_users.get(tag) or {}
        new = new_users.get(tag) or {}
        to_rm = [e for e in old if e not in new]
        to_add = [new[e] for e in new if e not in old]
        # Changed credentials (same email, different id/password): remove then add
        for e in list(new.keys()):
            if e in old and old[e] != new[e]:
                if e not in to_rm:
                    to_rm.append(e)
                if new[e] not in to_add:
                    to_add.append(new[e])
        if to_rm:
            res = _api_rmu(tag, to_rm)
            if not res.get("ok"):
                errors.append(f"rmu {tag}: {res.get('stderr') or res.get('stdout') or 'fail'}")
            else:
                removed += len(to_rm)
        if to_add:
            listen, port = listen_port.get(tag, ("0.0.0.0", 0))
            res = _api_adu_inbound(tag, proto_by_tag.get(tag, "vless"), to_add, listen=listen, port=port)
            if not res.get("ok"):
                errors.append(f"adu {tag}: {res.get('stderr') or res.get('stdout') or 'fail'}")
            else:
                added += len(to_add)
    return {"ok": not errors, "added": added, "removed": removed, "errors": errors}


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

    clients_only hot path: when inbounds/outbounds/dns/routing *structure* matches live
    and only users / per-user rules differ — sync users via HandlerService (adu/rmu).
    Restart only when per-user routing fingerprint changes (new emails need new rules).
    """
    xray_only = bool(xray_only or clients_only)
    prefer_hot = bool(clients_only)
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
            enforce_conn_limits(store)
        return {"ok": True, "error": "", "config": cfg, "verified": True, "unchanged": True}

    # Hot client sync: structure same, only users (± routing user rules) differ.
    live_cfg: dict | None = None
    if prefer_hot and _xray_active() and isinstance(live_text, str) and new_text:
        try:
            live_cfg = json.loads(live_text)
            new_cfg_obj = json.loads(new_text)
        except (TypeError, ValueError):
            live_cfg = None
            new_cfg_obj = None
        if live_cfg is not None and new_cfg_obj is not None:
            if _structure_fingerprint(live_cfg) == _structure_fingerprint(new_cfg_obj):
                hot = sync_clients_via_api(live_cfg, new_cfg_obj)
                routing_same = _user_routing_fingerprint(live_cfg) == _user_routing_fingerprint(new_cfg_obj)
                # Always persist the verified config so disk matches store.
                if XRAY_CONFIG.is_file():
                    try:
                        shutil.copy2(XRAY_CONFIG, XRAY_CONFIG_PREV)
                    except OSError:
                        pass
                os.replace(t["tmp"], XRAY_CONFIG)
                try:
                    os.chmod(XRAY_CONFIG, 0o644)
                except OSError:
                    pass
                if routing_same and hot.get("ok"):
                    return {
                        "ok": True, "error": "", "config": cfg, "verified": True,
                        "hot_clients": True, "added": hot.get("added", 0), "removed": hot.get("removed", 0),
                    }
                if routing_same and not hot.get("ok"):
                    # API failed — fall through to full restart with config already on disk.
                    pass
                elif not routing_same:
                    # Need restart so new per-user routing rules load; users already synced when possible.
                    pass
                else:
                    pass
                # Config already replaced; just restart (skip second replace below).
                restart = _restart_xray()
                if _xray_active():
                    note = ""
                    if not hot.get("ok") and hot.get("errors"):
                        note = "; hot-api: " + "; ".join(hot["errors"][:3])
                    return {
                        "ok": True, "error": "", "config": cfg, "verified": True,
                        "hot_clients": bool(hot.get("ok")), "restarted": True,
                        "warning": note.lstrip("; ").strip() or None,
                    }
                rb = _restore_prev_config()
                detail = restart["stderr"] or restart["stdout"] or "xray not active after restart"
                return {
                    "ok": False,
                    "error": f"{detail}" + (f"; rollback failed: {rb}" if rb else "; previous config restored"),
                    "config": cfg, "verified": True, "rolled_back": not bool(rb),
                }

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
            enforce_conn_limits(store)
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

    Direct inbounds (ib.direct) listen publicly on their own port and must stay reachable.
    Ports listed in settings.sub.legacy_ports (e.g. 2096 for old subscription links)
    stay open so nginx can serve plain-HTTP subscription aliases there.
    """
    import front as front_mod
    keep = set(front_mod.legacy_sub_ports(store))
    # Public direct inbounds (Reality Vision etc.) are not behind nginx — do not DROP them.
    keep |= {
        int(ib["port"])
        for ib in ensure_inbounds(store)
        if ib.get("enabled", True) and P.is_direct(ib) and int(ib.get("port") or 0) > 0
    }
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


def query_observatory_health() -> dict[str, dict]:
    """Per-outbound observatory snapshot from ``xray api bi`` (alive / delay / last error).

    Returns ``{outboundTag: {alive, delay_ms, error}}``. Empty when balancers/observatory
    are off or RoutingService is unreachable — panel probes remain the source of truth.
    """
    r = _run([XRAY_BIN, "api", "bi", f"--server={XRAY_API}"], timeout=8)
    if r["exit_code"] != 0 or not (r.get("stdout") or "").strip():
        return {}
    raw = r["stdout"] or ""
    out: dict[str, dict] = {}

    def _ingest(tag: str, alive, delay, err: str = "") -> None:
        tag = str(tag or "").strip()
        if not tag:
            return
        delay_ms = None
        try:
            if delay is not None and delay != "":
                # Xray may report delay as ms int or duration string
                if isinstance(delay, (int, float)):
                    delay_ms = int(delay)
                else:
                    s = str(delay).strip().lower()
                    if s.endswith("ms"):
                        delay_ms = int(float(s[:-2]))
                    elif s.endswith("s"):
                        delay_ms = int(float(s[:-1]) * 1000)
                    else:
                        delay_ms = int(float(s))
        except (TypeError, ValueError):
            delay_ms = None
        prev = out.get(tag)
        # Prefer dead / higher-delay reports when the same tag appears in several balancers
        if prev and prev.get("alive") is False and alive is not False:
            return
        out[tag] = {
            "alive": bool(alive) if alive is not None else True,
            "delay_ms": delay_ms,
            "error": str(err or "")[:200],
        }

    try:
        data = json.loads(raw)
    except ValueError:
        data = None
    if isinstance(data, dict):
        bals = data.get("balancer") or data.get("balancers") or data.get("Balancer") or []
        if isinstance(bals, dict):
            bals = list(bals.values())
        for bal in bals or []:
            if not isinstance(bal, dict):
                continue
            obs = bal.get("observatory") or bal.get("Observatory") or {}
            statuses = []
            if isinstance(obs, dict):
                statuses = obs.get("status") or obs.get("Status") or obs.get("outboundStatus") or []
            elif isinstance(obs, list):
                statuses = obs
            for st in statuses or []:
                if not isinstance(st, dict):
                    continue
                _ingest(
                    st.get("outboundTag") or st.get("outbound_tag") or st.get("tag") or "",
                    st.get("alive") if "alive" in st else st.get("Alive"),
                    st.get("delay") if "delay" in st else st.get("Delay"),
                    str(st.get("lastErrorReason") or st.get("last_error_reason") or st.get("error") or ""),
                )
    else:
        # Protobuf text dump fallback
        cur_tag = alive = delay = err = None
        for line in raw.splitlines():
            s = line.strip()
            m = re.match(r'outboundTag:\s*"([^"]+)"', s) or re.match(r'tag:\s*"([^"]+)"', s)
            if m:
                if cur_tag:
                    _ingest(cur_tag, alive, delay, err or "")
                cur_tag, alive, delay, err = m.group(1), None, None, ""
                continue
            if s.startswith("alive:"):
                alive = "true" in s.lower()
            elif s.startswith("delay:"):
                delay = s.split(":", 1)[1].strip().strip('"')
            elif "lastErrorReason" in s or "last_error_reason" in s:
                err = s.split(":", 1)[-1].strip().strip('"')
        if cur_tag:
            _ingest(cur_tag, alive, delay, err or "")
    return out


def apply_outbound_probe(
    o: dict,
    *,
    ok: bool,
    ms: int = 0,
    error: str = "",
    at: str | None = None,
    obs: dict | None = None,
    max_loss_pct: float = 20.0,
) -> list[dict]:
    """Persist probe + rolling loss on outbound; return Telegram-worthy health events."""
    tag = str(o.get("tag") or "")
    prev_lt = o.get("last_test") if isinstance(o.get("last_test"), dict) else {}
    prev_ok = prev_lt.get("ok")  # None = never probed
    prev_loss = outbound_loss_pct(o)
    prev_high = bool(o.get("tg_high_loss"))

    # Merge observatory: dead observatory overrides a flaky successful curl (and vice versa for alive delay)
    obs_alive = None
    obs_delay = None
    obs_err = ""
    if isinstance(obs, dict):
        if "alive" in obs:
            obs_alive = bool(obs.get("alive"))
        if obs.get("delay_ms") is not None:
            try:
                obs_delay = int(obs["delay_ms"])
            except (TypeError, ValueError):
                obs_delay = None
        obs_err = str(obs.get("error") or "")[:200]
        if obs_alive is False:
            ok = False
            if not error:
                error = obs_err or "observatory: not alive"
        elif obs_alive is True and ok and obs_delay is not None and (not ms or ms <= 0):
            ms = obs_delay

    hist = list(o.get("probe_history") or [])
    hist.append(bool(ok))
    hist = hist[-PROBE_HISTORY_N:]
    o["probe_history"] = hist
    fails = sum(1 for x in hist if not x)
    loss = round(100.0 * fails / len(hist), 1) if hist else 0.0

    o["last_test"] = {
        "ok": bool(ok),
        "ms": int(ms or 0),
        "at": at or now_utc().isoformat(),
        "error": str(error or "")[:300],
        "loss_pct": loss,
        "samples": len(hist),
    }
    if obs_alive is not None:
        o["last_test"]["obs_alive"] = obs_alive
    if obs_delay is not None:
        o["last_test"]["obs_ms"] = obs_delay

    events: list[dict] = []
    label = str(o.get("remark") or tag)
    # Connect / disconnect only after we have a prior baseline (avoid spam on first boot)
    if prev_ok is True and not ok:
        events.append({
            "type": "disconnect", "tag": tag, "label": label,
            "ms": int(ms or 0), "loss_pct": loss, "error": str(error or "")[:200],
        })
    elif prev_ok is False and ok:
        events.append({
            "type": "connect", "tag": tag, "label": label,
            "ms": int(ms or 0), "loss_pct": loss,
        })

    high_now = loss > float(max_loss_pct) and len(hist) >= 3
    if high_now and not prev_high:
        o["tg_high_loss"] = True
        events.append({
            "type": "high_loss", "tag": tag, "label": label,
            "loss_pct": loss, "max_loss_pct": float(max_loss_pct),
            "ok": bool(ok), "ms": int(ms or 0),
        })
    elif (not high_now) and prev_high:
        o.pop("tg_high_loss", None)
        events.append({
            "type": "loss_ok", "tag": tag, "label": label,
            "loss_pct": loss, "max_loss_pct": float(max_loss_pct),
            "ok": bool(ok), "ms": int(ms or 0),
        })
    elif prev_loss is None:
        # Seed flag without notifying when already unhealthy at first window fill
        if high_now:
            o["tg_high_loss"] = True

    return events


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
    """Apply on_expire / on_quota action. Returns email if client should be deleted.

    ``block`` (default): client stays in the panel but ``client_access_ok`` is false —
    they are removed from Xray (master + Direct nodes on next sync) so active sessions
    drop and new dials fail.
    """
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
    # block — deny access; apply_config / Direct push remove the user from Xray
    events.append({"type": "auto_block", "email": email, "reason": kind})
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
    # Merge direct_connect agent reports (email~node_tag → ips) into local stats
    agent_online = store.get("_agent_online") if isinstance(store.get("_agent_online"), dict) else {}
    if agent_online:
        merged = dict(online or {})
        for email, ips in agent_online.items():
            if not isinstance(ips, dict):
                continue
            row = merged.setdefault(str(email), {})
            for ip, ts in ips.items():
                row[str(ip)] = max(int(row.get(str(ip)) or 0), int(ts or 0))
        online = merged
    result: dict[str, list[str]] = {}
    online = online or {}
    for client in store.get("clients") or []:
        ensure_client(client)
        base = str(client.get("email") or "")
        if not base:
            continue
        # Direct nodes report ``email~node_*``; subscription_entries often empty
        # (inbounds-only model) — match base + any ``email~…`` keys.
        prefix = base + "~"
        now_ts = int(now.timestamp())
        ips: dict[str, int] = {}
        for email, ipmap in online.items():
            em = str(email or "")
            if em != base and not em.startswith(prefix):
                continue
            if not isinstance(ipmap, dict):
                continue
            for ip, ts in ipmap.items():
                if not ip:
                    continue
                ts_i = int(ts or 0)
                # Drop stale agent IPs (no fresh report for >2 min)
                if ts_i and (now_ts - ts_i) > 120:
                    continue
                ips[str(ip)] = max(int(ips.get(str(ip)) or 0), ts_i)
        if ips:
            result[base] = sorted(ips, key=lambda i: ips[i])
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


CONNLIMIT_CHAIN = "L2X_CONNLIMIT"
# XHTTP/xmux opens many parallel :443 sockets; 64 was killing real clients.
DEFAULT_MAX_CONN_PER_IP = 256
# Conntrack often under-counts ESTAB on this host, so connlimit alone is leaky.
# SYN rate must still allow XHTTP multi-conn bursts; ss prune enforces the real cap.
_SYN_HASHLIMIT = "30/sec"
_SYN_HASHLIMIT_BURST = "120"


def _connlimit_rules_ok(tool: str, limit: int, mask: str) -> bool:
    """True when L2X_CONNLIMIT already has the expected syn-hashlimit + connlimit rules."""
    out = (_run([tool, "-S", CONNLIMIT_CHAIN]).get("stdout") or "")
    if f"--connlimit-above {limit}" not in out and f"--connlimit-above={limit}" not in out:
        return False
    if f"--connlimit-mask {mask}" not in out and f"--connlimit-mask={mask}" not in out:
        return False
    if "hashlimit" not in out or "--syn" not in out:
        return False
    # Detect stale low SYN caps from v1.9.177–179 (broke XHTTP handshake bursts).
    if "hashlimit-above 5/sec" in out or "hashlimit-above=5/sec" in out:
        return False
    return True


def _prune_excess_443(limit: int) -> None:
    """Drop only ESTAB :443 sockets above the per-IP cap (never wipe the whole IP).

    Previous ``ss -K dst <ip>`` killed *all* sockets once over limit — XHTTP/xmux
    then looked completely dead every prune tick.
    """
    if limit <= 0 or not shutil.which("ss"):
        return
    from collections import defaultdict
    by_ip: dict[str, list[str]] = defaultdict(list)
    out = _run(["ss", "-H", "-tan"]).get("stdout") or ""
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0] != "ESTAB":
            continue
        local, peer = parts[3], parts[4]
        if not local.endswith(":443"):
            continue
        host = peer.rsplit(":", 1)[0]
        by_ip[host].append(peer)
    for host, peers in by_ip.items():
        if len(peers) <= limit:
            continue
        # Keep the first ``limit`` peers; kill only the overflow (stable order).
        peers.sort()
        for peer in peers[limit:]:
            _run(["ss", "-K", "dst", peer])


def enforce_conn_limits(store: dict) -> None:
    """Cap concurrent TCP to :443 per source IP (iptables L2X_CONNLIMIT + ss prune).

    settings.iplimit.max_conn_per_ip: 0 disables; default 256 (XHTTP-friendly).
    Rules are updated only when missing/changed — never flushed every watchdog tick
    (a flush window lets SYN floods establish hundreds of ESTAB sockets).
    """
    raw = ((store.get("settings") or {}).get("iplimit") or {}).get("max_conn_per_ip", DEFAULT_MAX_CONN_PER_IP)
    try:
        limit = max(0, int(raw or 0))
    except (TypeError, ValueError):
        limit = DEFAULT_MAX_CONN_PER_IP
    for tool, mask, hl_name in (
        ("iptables", "32", "l2x443syn4c"),
        ("ip6tables", "128", "l2x443syn6c"),
    ):
        if not shutil.which(tool):
            continue
        if _run([tool, "-L", CONNLIMIT_CHAIN, "-n"])["exit_code"] != 0:
            _run([tool, "-N", CONNLIMIT_CHAIN])
        has_jump = _run([tool, "-C", "INPUT", "-j", CONNLIMIT_CHAIN])["exit_code"] == 0
        if limit <= 0:
            _run([tool, "-F", CONNLIMIT_CHAIN])
            while _run([tool, "-D", "INPUT", "-j", CONNLIMIT_CHAIN])["exit_code"] == 0:
                pass
            continue
        if not _connlimit_rules_ok(tool, limit, mask):
            _run([tool, "-F", CONNLIMIT_CHAIN])
            # SYN rate first — shrinks parallel handshake races past connlimit.
            _run([
                tool, "-A", CONNLIMIT_CHAIN,
                "-p", "tcp", "--dport", "443", "--syn",
                "-m", "hashlimit",
                f"--hashlimit-above={_SYN_HASHLIMIT}",
                f"--hashlimit-burst={_SYN_HASHLIMIT_BURST}",
                "--hashlimit-mode", "srcip",
                f"--hashlimit-name={hl_name}",
                "-j", "DROP",
            ])
            _run([
                tool, "-A", CONNLIMIT_CHAIN,
                "-p", "tcp", "--dport", "443",
                "-m", "connlimit", f"--connlimit-above={limit}", f"--connlimit-mask={mask}",
                "-j", "REJECT", "--reject-with", "tcp-reset",
            ])
        if not has_jump:
            _run([tool, "-I", "INPUT", "1", "-j", CONNLIMIT_CHAIN])
    if limit > 0:
        _prune_excess_443(limit)


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

    for o in store.get("outbounds_custom") or []:
        if o.get("tag") != tag:
            continue
        # L2X Go tunnel: probe via local SOCKS published by l2x-tunneld (not reverse pull).
        if o.get("tunnel") or (
            o.get("kind") == "node" and (o.get("config") or {}).get("protocol") == "socks"
        ):
            if not _tunnel_outbound_member_ok(store, o):
                return {
                    "ok": False,
                    "error": (
                        "L2X tunnel offline (tunneld peer) — Sync ноды / restart "
                        "l2x-tunnel-agent / профиль NoDPI (WSS)"
                    ),
                    "ms": 0,
                }
            t0 = time.time()
            cfg = o.get("config") or {}
            servers = ((cfg.get("settings") or {}).get("servers") or [{}])
            srv0 = servers[0] or {}
            host = str(srv0.get("address") or "127.0.0.1")
            try:
                port = int(srv0.get("port") or 11080)
            except (TypeError, ValueError):
                port = 11080
            # Multi-agent portal requires SOCKS user=node_id (without it curl always fails).
            sock_user = ""
            sock_pass = "l2x"
            users = srv0.get("users") or []
            if users and isinstance(users[0], dict):
                sock_user = str(users[0].get("user") or "").strip()
                sock_pass = str(users[0].get("pass") or "l2x") or "l2x"
            curl_cmd = [
                "curl", "-s", "-o", "/dev/null", "-w", "%{http_code} %{time_total}",
                "--max-time", str(timeout),
                "--socks5-hostname", f"{host}:{port}",
            ]
            if sock_user:
                curl_cmd.extend(["-U", f"{sock_user}:{sock_pass}"])
            curl_cmd.append(url)
            r = _run(curl_cmd, timeout=timeout + 5)
            parts = (r.get("stdout") or "").strip().split()
            code = parts[0] if parts else "000"
            ms = int(float(parts[1]) * 1000) if len(parts) > 1 else int((time.time() - t0) * 1000)
            ok = code.startswith("2") or code.startswith("3")
            return {
                "ok": ok,
                "code": code,
                "ms": ms,
                "error": "" if ok else (r.get("stderr") or f"socks probe http={code}"),
            }
        # Reverse portal: live only while the NAT node keeps the tunnel up (tracked via pull)
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
    for o in _custom_outbounds(store):
        if o["tag"] == tag:
            ob = copy.deepcopy(o)
    if tag == "direct":
        ob = {"tag": "direct", "protocol": "freedom"}
    if not ob:
        return {"ok": False, "error": "outbound не найден или не активен"}
    # Include dialerProxy chain targets so sockopt.dialerProxy resolves in the throwaway Xray.
    outs: list[dict] = []
    seen_tags: set[str] = set()

    def _add_ob(o: dict) -> None:
        t = str(o.get("tag") or "")
        if not t or t in seen_tags:
            return
        seen_tags.add(t)
        outs.append(o)

    probe = copy.deepcopy(ob)
    probe["tag"] = "out"
    # WireGuard userspace stack (WARP) — kernel TUN often fails / needs CAP_NET_ADMIN.
    if str(probe.get("protocol") or "").lower() == "wireguard":
        stg = probe.setdefault("settings", {})
        if isinstance(stg, dict) and "noKernelTun" not in stg:
            stg["noKernelTun"] = True
    _add_ob(probe)
    via = str(((probe.get("streamSettings") or {}).get("sockopt") or {}).get("dialerProxy") or "").strip()
    pending = [via] if via else []
    custom_by_tag = {o["tag"]: copy.deepcopy(o) for o in _custom_outbounds(store) if o.get("tag")}
    while pending:
        dep = pending.pop(0)
        if not dep or dep in seen_tags or dep == "out":
            continue
        if dep == "direct":
            _add_ob({"tag": "direct", "protocol": "freedom"})
            continue
        dep_ob = custom_by_tag.get(dep)
        if not dep_ob:
            return {"ok": False, "error": f"dialerProxy «{dep}» не найден / выключен", "ms": 0}
        _add_ob(dep_ob)
        nxt = str(((dep_ob.get("streamSettings") or {}).get("sockopt") or {}).get("dialerProxy") or "").strip()
        if nxt and nxt not in seen_tags:
            pending.append(nxt)
    if "direct" not in seen_tags:
        _add_ob({"tag": "direct", "protocol": "freedom"})
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    cfg = {
        "log": {"loglevel": "error"},
        "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": {"udp": False}}],
        "outbounds": outs,
    }
    path = Path(f"/tmp/l2x-obtest-{port}.json")
    path.write_text(json.dumps(cfg), encoding="utf-8")
    proc = subprocess.Popen([XRAY_BIN, "run", "-c", str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        # WireGuard handshake (~1–2s) needs longer boot than plain VLESS/freedom.
        boot = 1.8 if str(probe.get("protocol") or "").lower() == "wireguard" else 0.35
        time.sleep(boot)
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
