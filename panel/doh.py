"""DoH (DNS-over-HTTPS) in front of Pi-hole, exposed via nginx :443.

Public URLs:
  https://<domain>/doh/<token>/dns-query

Client apps with ``doh_in_tunnel`` use this URL with detour=proxy (queries inside VPN).
Standalone device DoH uses the same URL without a tunnel.
"""
from __future__ import annotations

import base64
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import time
from pathlib import Path

COMPOSE_DIR = Path(os.environ.get("L2XPANEL_DOH_DIR", "/opt/l2xpanel/doh"))
TICKETS_FILE = Path(os.environ.get(
    "L2XPANEL_PIHOLE_TICKETS",
    str(Path(os.environ.get("L2XPANEL_DATA", "/var/lib/l2xpanel")) / "pihole_tickets.json"),
))
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
PATH_RE = re.compile(r"^[A-Za-z0-9_-]{2,32}$")
# One-time gate link TTL; session after redeem lasts longer
PIHOLE_LINK_TTL_SEC = 15 * 60
PIHOLE_SESSION_TTL_SEC = 2 * 3600


def default_settings() -> dict:
    return {
        "enabled": False,
        "path_prefix": "doh",
        "upstream": "127.0.0.1",
        "upstream_port": 53,
        "pihole_web": "127.0.0.1:8089",
        "pihole_password": "",
        "timeout_sec": 4,
    }


def _run(cmd: list[str], timeout: int = 120, cwd: str | None = None) -> dict:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)
        return {"ok": p.returncode == 0, "stdout": p.stdout, "stderr": p.stderr, "code": p.returncode}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "stdout": "", "stderr": str(exc), "code": 127}


def normalize_prefix(value: str) -> str:
    v = re.sub(r"[^A-Za-z0-9_-]", "", str(value or "doh")).strip("_-") or "doh"
    return v[:32]


def new_token() -> str:
    return secrets.token_urlsafe(18)


def ensure_client_doh(client: dict) -> dict:
    client.setdefault("doh_enabled", False)
    client.setdefault("doh_in_tunnel", False)
    if not client.get("doh_token") or not TOKEN_RE.match(str(client.get("doh_token"))):
        client["doh_token"] = new_token()
    return client


def client_by_token(store: dict, token: str) -> dict | None:
    tok = (token or "").strip()
    if not TOKEN_RE.match(tok):
        return None
    for c in store.get("clients") or []:
        if not c.get("doh_enabled"):
            continue
        if not c.get("enabled", True):
            continue
        if secrets.compare_digest(str(c.get("doh_token") or ""), tok):
            return c
    return None


def public_url(store: dict, client: dict, *, host: str = "") -> str:
    """https://domain/doh/<token>/dns-query"""
    cfg = ((store.get("settings") or {}).get("doh") or {})
    if not cfg.get("enabled"):
        return ""
    if not client.get("doh_enabled") or not client.get("doh_token"):
        return ""
    prefix = normalize_prefix(cfg.get("path_prefix") or "doh")
    domain = (host or "").strip()
    if not domain:
        try:
            import front as front_mod
            domain = front_mod.public_domain(store)
        except Exception:
            domain = ""
    if not domain:
        return ""
    return f"https://{domain}/{prefix}/{client['doh_token']}/dns-query"


def b64url_decode(value: str) -> bytes:
    pad = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + pad)


def resolve_wire(query: bytes, *, upstream: str = "127.0.0.1", port: int = 53, timeout: float = 4) -> bytes:
    if not query or len(query) < 12:
        raise ValueError("empty DNS query")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(query, (upstream, int(port)))
        data, _ = sock.recvfrom(65535)
        return data
    finally:
        sock.close()


def status(cfg: dict | None = None) -> dict:
    cfg = {**default_settings(), **(cfg or {})}
    up = str(cfg.get("upstream") or "127.0.0.1")
    port = int(cfg.get("upstream_port") or 53)
    dns_ok = False
    err = ""
    try:
        # minimal DNS query for "." SOA — just check UDP reachability with empty A for localhost
        # Use a tiny valid header: QR=0, QDCOUNT=1, question for "pi.hole" A — or simpler: send and expect any reply
        q = _probe_query()
        resolve_wire(q, upstream=up, port=port, timeout=2)
        dns_ok = True
    except Exception as exc:  # noqa: BLE001
        err = str(exc)
    compose = COMPOSE_DIR / "docker-compose.yml"
    return {
        "enabled": bool(cfg.get("enabled")),
        "upstream": f"{up}:{port}",
        "dns_ok": dns_ok,
        "error": err,
        "docker": bool(shutil.which("docker")),
        "compose_present": compose.is_file(),
        "pihole_web": cfg.get("pihole_web") or "",
        "path_prefix": normalize_prefix(cfg.get("path_prefix") or "doh"),
    }


def _probe_query() -> bytes:
    """Build a minimal DNS A query for example.com."""
    # Header: id=0x1234, flags=0x0100 (RD), qdcount=1
    name = b"".join(len(p).to_bytes(1, "big") + p.encode() for p in "example.com".split(".")) + b"\x00"
    return b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + name + b"\x00\x01\x00\x01"


COMPOSE_YML = """\
# Managed by L2X Panel — Pi-hole + UDP DNS for DoH frontend
services:
  pihole:
    image: pihole/pihole:latest
    container_name: l2x-pihole
    restart: unless-stopped
    environment:
      TZ: Europe/Moscow
      FTLCONF_webserver_api_password: "${PIHOLE_PASSWORD}"
      FTLCONF_dns_listeningMode: ALL
    ports:
      - "127.0.0.1:53:53/tcp"
      - "127.0.0.1:53:53/udp"
      - "127.0.0.1:8089:80/tcp"
    volumes:
      - ./etc-pihole:/etc/pihole
      - ./etc-dnsmasq.d:/etc/dnsmasq.d
    cap_add:
      - NET_ADMIN
"""


def write_compose(*, password: str = "") -> Path:
    COMPOSE_DIR.mkdir(parents=True, exist_ok=True)
    (COMPOSE_DIR / "docker-compose.yml").write_text(COMPOSE_YML, encoding="utf-8")
    env = COMPOSE_DIR / ".env"
    pwd = password or secrets.token_urlsafe(12)
    env.write_text(f"PIHOLE_PASSWORD={pwd}\n", encoding="utf-8")
    try:
        os.chmod(env, 0o600)
    except OSError:
        pass
    return COMPOSE_DIR


def install_pihole(*, password: str = "") -> dict:
    if not shutil.which("docker"):
        return {"ok": False, "error": "docker не установлен"}
    write_compose(password=password)
    # Prefer docker compose v2
    base = ["docker", "compose", "-f", str(COMPOSE_DIR / "docker-compose.yml")]
    r = _run([*base, "pull"], timeout=300, cwd=str(COMPOSE_DIR))
    if not r["ok"]:
        # try docker-compose
        base = ["docker-compose", "-f", str(COMPOSE_DIR / "docker-compose.yml")]
        r = _run([*base, "pull"], timeout=300, cwd=str(COMPOSE_DIR))
    if not r["ok"]:
        return {"ok": False, "error": r["stderr"] or r["stdout"] or "pull failed", "log": r}
    up = _run([*base, "up", "-d"], timeout=180, cwd=str(COMPOSE_DIR))
    if not up["ok"]:
        return {"ok": False, "error": up["stderr"] or up["stdout"] or "up failed", "log": up}
    time.sleep(3)
    return {"ok": True, "dir": str(COMPOSE_DIR), "log": up["stdout"]}


def stop_pihole() -> dict:
    yml = COMPOSE_DIR / "docker-compose.yml"
    if not yml.is_file():
        return {"ok": False, "error": "compose не найден"}
    for base in (
        ["docker", "compose", "-f", str(yml)],
        ["docker-compose", "-f", str(yml)],
    ):
        r = _run([*base, "down"], timeout=120, cwd=str(COMPOSE_DIR))
        if r["ok"]:
            return {"ok": True, "log": r["stdout"]}
    return {"ok": False, "error": r.get("stderr") or "down failed"}


def dns_servers_for_client(doh_https: str, *, in_tunnel: bool) -> dict:
    """Fragments for sing-box / clash / xray client configs."""
    if not doh_https:
        return {}
    return {
        "url": doh_https,
        "in_tunnel": bool(in_tunnel),
        "singbox": {
            "tag": "remote",
            "address": doh_https,
            **({"detour": "proxy"} if in_tunnel else {}),
        },
        "xray": [doh_https.replace("https://", "https+local://") if not in_tunnel else doh_https],
        "clash_nameserver": [doh_https],
        "clash_nameserver_policy": {"PROXY": [doh_https]} if in_tunnel else {},
    }


# ---------------------------------------------------------------- one-time Pi-hole admin access

def pihole_upstream(cfg: dict | None = None) -> tuple[str, int]:
    """Parse pihole_web → (host, port), default 127.0.0.1:8089."""
    cfg = {**default_settings(), **(cfg or {})}
    raw = str(cfg.get("pihole_web") or "127.0.0.1:8089").strip()
    raw = raw.replace("http://", "").replace("https://", "").split("/")[0]
    if ":" in raw:
        host, _, port_s = raw.rpartition(":")
        try:
            return (host or "127.0.0.1"), int(port_s)
        except ValueError:
            return "127.0.0.1", 8089
    return raw or "127.0.0.1", 8089


def _load_tickets() -> list[dict]:
    try:
        if TICKETS_FILE.is_file():
            data = json.loads(TICKETS_FILE.read_text(encoding="utf-8"))
            if isinstance(data, list):
                return data
    except Exception:
        pass
    return []


def _save_tickets(items: list[dict]) -> None:
    TICKETS_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = TICKETS_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(TICKETS_FILE)
    try:
        os.chmod(TICKETS_FILE, 0o600)
    except OSError:
        pass


def _purge_tickets(items: list[dict], now: float | None = None) -> list[dict]:
    now = time.time() if now is None else now
    return [
        t for t in items
        if isinstance(t, dict)
        and t.get("token")
        and float(t.get("exp") or 0) > now
        and not t.get("used")
    ]


def create_pihole_ticket(*, ttl_sec: int = PIHOLE_LINK_TTL_SEC, by: str = "") -> dict:
    """Create a single-use ticket. Returns {token, exp, url_path, ttl_sec}."""
    now = time.time()
    token = secrets.token_urlsafe(24)
    exp = now + max(60, int(ttl_sec))
    items = _purge_tickets(_load_tickets(), now)
    items.append({"token": token, "exp": exp, "used": False, "by": (by or "")[:64], "created": now})
    _save_tickets(items)
    return {
        "token": token,
        "exp": exp,
        "ttl_sec": int(exp - now),
        "url_path": f"/pihole-gate/{token}",
    }


def redeem_pihole_ticket(token: str) -> dict:
    """Consume a single-use ticket. Returns {ok, session_ttl} or {ok: False, error}."""
    tok = (token or "").strip()
    if not tok or len(tok) < 16:
        return {"ok": False, "error": "некорректная ссылка"}
    now = time.time()
    items = _load_tickets()
    kept: list[dict] = []
    found: dict | None = None
    for t in items:
        ttok = str(t.get("token") or "")
        if found is None and len(ttok) == len(tok) and secrets.compare_digest(ttok, tok):
            found = t
            continue
        if float(t.get("exp") or 0) > now and not t.get("used"):
            kept.append(t)
    _save_tickets(kept)
    if not found:
        return {"ok": False, "error": "ссылка не найдена или уже использована"}
    if found.get("used") or float(found.get("exp") or 0) <= now:
        return {"ok": False, "error": "ссылка уже использована или истекла"}
    return {"ok": True, "session_ttl": PIHOLE_SESSION_TTL_SEC}
