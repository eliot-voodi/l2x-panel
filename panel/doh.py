"""DoH (DNS-over-HTTPS) in front of Pi-hole, exposed via nginx :443.

Public URLs (no /dns-query suffix — never shown to users):
  https://<domain>/doh/<token>

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
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

COMPOSE_DIR = Path(os.environ.get("L2XPANEL_DOH_DIR", "/opt/l2xpanel/doh"))
_DATA_DIR = Path(os.environ.get("L2XPANEL_DATA", "/var/lib/l2xpanel"))
TICKETS_FILE = Path(os.environ.get(
    "L2XPANEL_PIHOLE_TICKETS",
    str(_DATA_DIR / "pihole_tickets.json"),
))
DOH_CLIENT_STATS_FILE = Path(os.environ.get(
    "L2XPANEL_DOH_CLIENT_STATS",
    str(_DATA_DIR / "doh_client_stats.json"),
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
    """https://domain/doh/<token> — never append /dns-query in any UI or subscription."""
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
    return f"https://{domain}/{prefix}/{client['doh_token']}"


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


# ---------------------------------------------------------------- DoH client attribution (top clients)

_PRIV_NETS = (
    ("127.",),
    ("10.",),
    ("192.168.",),
    ("169.254.",),
    ("0.",),
    ("::1",),
    ("fc",), ("fd",), ("fe80",),
)
_STATS_LOCK = threading.Lock()
_STATS: dict = {"day": "", "clients": {}, "writes": 0}
_SELF_IPS: set[str] = set()
_SELF_IPS_AT = 0.0


def _ip_in_priv_172(ip: str) -> bool:
    """172.16.0.0/12 (incl. Docker bridge 172.17–172.31)."""
    if not ip.startswith("172."):
        return False
    try:
        second = int(ip.split(".")[1])
    except (IndexError, ValueError):
        return False
    return 16 <= second <= 31


def is_private_or_local_ip(ip: str) -> bool:
    ip = (ip or "").strip().lower().split("%")[0]
    if not ip or ip in ("unknown", "null", "-"):
        return True
    if _ip_in_priv_172(ip):
        return True
    for p in _PRIV_NETS:
        if ip.startswith(p[0]):
            return True
    return False


def refresh_self_ips(*, force: bool = False) -> set[str]:
    """Local / public addresses of this host — DoH via VLESS often loops back as these."""
    global _SELF_IPS, _SELF_IPS_AT
    now = time.time()
    if not force and _SELF_IPS and now - _SELF_IPS_AT < 300:
        return _SELF_IPS
    found: set[str] = {"127.0.0.1", "::1", "0.0.0.0"}
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            addr = info[4][0]
            if addr:
                found.add(addr)
    except OSError:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("1.1.1.1", 80))
            found.add(s.getsockname()[0])
        finally:
            s.close()
    except OSError:
        pass
    # Optional: hostname from env / common docker gateway
    found.add("172.17.0.1")
    found.add("172.18.0.1")
    _SELF_IPS = {a for a in found if a}
    _SELF_IPS_AT = now
    return _SELF_IPS


def request_client_ip(headers: dict | None = None, *, fallback: str = "") -> str:
    """Best-effort external IP from nginx X-Real-IP / X-Forwarded-For."""
    h = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    xff = (h.get("x-forwarded-for") or "").split(",")[0].strip()
    xri = (h.get("x-real-ip") or "").strip()
    cf = (h.get("cf-connecting-ip") or "").strip()
    for cand in (cf, xri, xff, fallback):
        ip = (cand or "").strip().strip("[]")
        if ip and ip.lower() not in ("unknown", "null", "-"):
            return ip
    return (fallback or "").strip()


def doh_client_label(client: dict, request_ip: str, *, self_ips: set[str] | None = None) -> dict:
    """Label for Top clients: external IP, or panel client name when request came via VLESS/local.

    DoH is proxied by the panel → Pi-hole always sees localhost/docker. Attribution happens here.
    """
    email = str(client.get("email") or "").strip() or "client"
    ip = (request_ip or "").strip()
    self_ips = self_ips if self_ips is not None else refresh_self_ips()
    # VLESS/tunneled DoH hits nginx from loopback, docker bridge, or this host's own IP
    via_tunnel = is_private_or_local_ip(ip) or ip in self_ips
    if via_tunnel:
        return {
            "name": email,
            "kind": "name",
            "email": email,
            "ip": ip,
            "via_tunnel": True,
        }
    # Direct DoH from the internet → external IP
    return {
        "name": ip,
        "kind": "ip",
        "email": email,
        "ip": ip,
        "via_tunnel": False,
    }


def _load_client_stats() -> dict:
    try:
        if DOH_CLIENT_STATS_FILE.is_file():
            data = json.loads(DOH_CLIENT_STATS_FILE.read_text(encoding="utf-8"))
            if isinstance(data, dict) and isinstance(data.get("clients"), dict):
                return {
                    "day": str(data.get("day") or ""),
                    "clients": data["clients"],
                    "writes": 0,
                }
    except Exception:
        pass
    return {"day": "", "clients": {}, "writes": 0}


def _save_client_stats(data: dict) -> None:
    try:
        DOH_CLIENT_STATS_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = DOH_CLIENT_STATS_FILE.with_suffix(".tmp")
        payload = {"day": data.get("day") or "", "clients": data.get("clients") or {}}
        tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        tmp.replace(DOH_CLIENT_STATS_FILE)
    except OSError:
        pass


def record_doh_client(label: dict) -> None:
    """Increment today's counter for a DoH client label (name or external IP)."""
    name = str((label or {}).get("name") or "").strip()
    if not name:
        return
    day = time.strftime("%Y-%m-%d")
    with _STATS_LOCK:
        global _STATS
        if not _STATS.get("clients") and not _STATS.get("day"):
            _STATS = _load_client_stats()
        if _STATS.get("day") != day:
            _STATS = {"day": day, "clients": {}, "writes": 0}
        entry = _STATS["clients"].get(name) or {
            "count": 0, "kind": "ip", "email": "", "ip": "", "via_tunnel": False,
        }
        entry["count"] = int(entry.get("count") or 0) + 1
        entry["kind"] = label.get("kind") or entry.get("kind") or "ip"
        entry["email"] = str(label.get("email") or entry.get("email") or "")
        entry["ip"] = str(label.get("ip") or entry.get("ip") or "")
        entry["via_tunnel"] = bool(label.get("via_tunnel"))
        _STATS["clients"][name] = entry
        _STATS["writes"] = int(_STATS.get("writes") or 0) + 1
        # Flush every 25 queries (and always keep memory hot)
        if _STATS["writes"] >= 25:
            _STATS["writes"] = 0
            _save_client_stats(_STATS)


def top_doh_clients(limit: int = 10) -> list[dict]:
    """Today's DoH clients for the dashboard (external IP or client name)."""
    day = time.strftime("%Y-%m-%d")
    with _STATS_LOCK:
        global _STATS
        if not _STATS.get("clients") and not _STATS.get("day"):
            _STATS = _load_client_stats()
        if _STATS.get("day") != day:
            return []
        rows = [
            {
                "name": str(name),
                "count": int((meta or {}).get("count") or 0),
                "kind": (meta or {}).get("kind") or "ip",
                "email": (meta or {}).get("email") or "",
                "ip": (meta or {}).get("ip") or "",
                "via_tunnel": bool((meta or {}).get("via_tunnel")),
            }
            for name, meta in (_STATS.get("clients") or {}).items()
        ]
    rows.sort(key=lambda r: r["count"], reverse=True)
    return rows[: max(1, min(50, int(limit or 10)))]


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
# Admin password is applied with ``docker exec … pihole setpassword`` into the
# volume — not via an FTLCONF env key (read-only + .env `$` interpolation bugs).
services:
  pihole:
    image: pihole/pihole:latest
    container_name: l2x-pihole
    restart: unless-stopped
    environment:
      TZ: Europe/Moscow
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


def _env_quote(value: str) -> str:
    """Quote a value for docker compose .env (safe with $, #, spaces, quotes)."""
    s = str(value or "")
    if re.fullmatch(r"[A-Za-z0-9_./:@%+=-]+", s):
        return s
    return "'" + s.replace("'", "'\"'\"'") + "'"


def write_compose(*, password: str = "") -> Path:
    COMPOSE_DIR.mkdir(parents=True, exist_ok=True)
    (COMPOSE_DIR / "docker-compose.yml").write_text(COMPOSE_YML, encoding="utf-8")
    env = COMPOSE_DIR / ".env"
    pwd = password or secrets.token_urlsafe(12)
    env.write_text(f"PIHOLE_PASSWORD={_env_quote(pwd)}\n", encoding="utf-8")
    try:
        os.chmod(env, 0o600)
    except OSError:
        pass
    return COMPOSE_DIR


def _compose_base() -> list[str] | None:
    yml = COMPOSE_DIR / "docker-compose.yml"
    if not yml.is_file():
        return None
    for cand in (
        ["docker", "compose", "-f", str(yml)],
        ["docker-compose", "-f", str(yml)],
    ):
        probe = _run([*cand, "version"], timeout=30, cwd=str(COMPOSE_DIR))
        if probe["ok"]:
            return cand
    return None


def _compose_has_env_password() -> bool:
    """Old compose pinned password via FTLCONF — setpassword is ignored until removed."""
    yml = COMPOSE_DIR / "docker-compose.yml"
    if not yml.is_file():
        return False
    try:
        text = yml.read_text(encoding="utf-8")
    except OSError:
        return False
    return "FTLCONF_webserver_api_password" in text


def wait_pihole_http(*, cfg: dict | None = None, timeout: float = 60) -> dict:
    """Wait until local Pi-hole web/API answers (after up/recreate)."""
    cfg = {**default_settings(), **(cfg or {})}
    deadline = time.time() + max(5.0, float(timeout))
    last = "timeout"
    while time.time() < deadline:
        r = _pihole_http("GET", "/api/auth", cfg=cfg, timeout=3)
        if r.get("status") in (200, 401) or r.get("ok"):
            return {"ok": True, "error": ""}
        # Connection refused / empty while FTL boots
        last = str(r.get("error") or f"HTTP {r.get('status') or '?'}")
        time.sleep(1.5)
    return {"ok": False, "error": last}


def verify_pihole_password(password: str, *, cfg: dict | None = None) -> dict:
    """Check that Pi-hole accepts this admin password via /api/auth."""
    cfg = {**default_settings(), **(cfg or {}), "pihole_password": str(password or "")}
    invalidate_pihole_session(cfg)
    r = _pihole_http("POST", "/api/auth", cfg=cfg, body={"password": str(password or "")}, timeout=8)
    if not r.get("ok"):
        return {"ok": False, "error": r.get("error") or f"HTTP {r.get('status') or '?'}"}
    sess = (r.get("data") or {}).get("session") or {}
    if sess.get("valid") or sess.get("sid"):
        return {"ok": True, "error": ""}
    return {"ok": False, "error": "Pi-hole отклонил пароль"}


def pihole_ready() -> dict:
    """Whether local l2x-pihole can serve DNS for DoH on this host."""
    if not shutil.which("docker"):
        return {"ok": False, "reason": "docker не установлен"}
    running = _run(["docker", "inspect", "-f", "{{.State.Running}}", "l2x-pihole"], timeout=20)
    if not running["ok"] or "true" not in (running.get("stdout") or "").lower():
        compose = COMPOSE_DIR / "docker-compose.yml"
        if not compose.is_file():
            return {"ok": False, "reason": "Pi-hole не установлен (нет compose)"}
        return {"ok": False, "reason": "контейнер l2x-pihole не запущен"}
    return {"ok": True, "reason": ""}


def ensure_docker() -> dict:
    """Install Docker Engine + compose plugin if missing (Debian/Ubuntu via get.docker.com)."""
    log: list[str] = []
    if shutil.which("docker"):
        # Ensure daemon is up
        st = _run(["docker", "info"], timeout=30)
        if st["ok"]:
            return {"ok": True, "installed": False, "log": "docker already present"}
        _run(["systemctl", "enable", "--now", "docker"], timeout=60)
        st = _run(["docker", "info"], timeout=30)
        if st["ok"]:
            return {"ok": True, "installed": False, "log": "docker started"}
        return {"ok": False, "error": "docker есть, но daemon не отвечает", "log": st.get("stderr") or st.get("stdout") or ""}

    geteuid = getattr(os, "geteuid", None)
    if callable(geteuid) and geteuid() != 0:
        return {"ok": False, "error": "нужен root для установки docker"}

    # Official convenience script covers Debian/Ubuntu/CentOS
    log.append("installing docker via get.docker.com")
    script = Path("/tmp/l2x-get-docker.sh")
    dl = _run(["curl", "-fsSL", "https://get.docker.com", "-o", str(script)], timeout=120)
    if not dl["ok"]:
        # fallback: apt packages on Debian/Ubuntu
        log.append("get.docker.com download failed, trying apt")
        for cmd in (
            ["apt-get", "update", "-y"],
            ["apt-get", "install", "-y", "docker.io", "docker-compose-v2"],
        ):
            r = _run(cmd, timeout=300)
            log.append((r.get("stderr") or r.get("stdout") or "")[:400])
            if not r["ok"] and cmd[0] != "apt-get":
                break
        _run(["systemctl", "enable", "--now", "docker"], timeout=60)
    else:
        try:
            os.chmod(script, 0o755)
        except OSError:
            pass
        r = _run(["sh", str(script)], timeout=600)
        log.append((r.get("stdout") or "")[-800:])
        if not r["ok"]:
            log.append((r.get("stderr") or "")[-400:])
            return {"ok": False, "error": "установка docker не удалась", "log": "\n".join(log)}
        _run(["systemctl", "enable", "--now", "docker"], timeout=60)

    # Wait until docker answers
    for _ in range(15):
        if shutil.which("docker"):
            st = _run(["docker", "info"], timeout=20)
            if st["ok"]:
                # Prefer compose v2 plugin; install if missing
                plug = _run(["docker", "compose", "version"], timeout=30)
                if not plug["ok"]:
                    _run(["apt-get", "install", "-y", "docker-compose-plugin", "docker-compose-v2"], timeout=180)
                return {"ok": True, "installed": True, "log": "\n".join(log)}
        time.sleep(2)
    return {"ok": False, "error": "docker установлен, но не отвечает", "log": "\n".join(log)}


def install_pihole(*, password: str = "") -> dict:
    dock = ensure_docker()
    if not dock.get("ok"):
        return {"ok": False, "error": dock.get("error") or "docker недоступен", "log": dock.get("log")}
    pwd = password or secrets.token_urlsafe(12)
    write_compose(password=pwd)
    base = _compose_base()
    if not base:
        return {"ok": False, "error": "docker compose недоступен"}
    r = _run([*base, "pull"], timeout=300, cwd=str(COMPOSE_DIR))
    if not r["ok"]:
        return {"ok": False, "error": r["stderr"] or r["stdout"] or "pull failed", "log": r}
    up = _run([*base, "up", "-d", "pihole"], timeout=180, cwd=str(COMPOSE_DIR))
    if not up["ok"]:
        return {"ok": False, "error": (up.get("stderr") or up.get("stdout") or "up failed").strip(), "log": up}
    sp = set_pihole_password(pwd, update_env=True)
    if not sp.get("ok"):
        return {**sp, "dir": str(COMPOSE_DIR), "docker_installed": bool(dock.get("installed"))}
    return {
        "ok": True, "dir": str(COMPOSE_DIR), "password": pwd, "log": sp.get("log"),
        "docker_installed": bool(dock.get("installed")),
    }


def set_pihole_password(password: str, *, update_env: bool = True) -> dict:
    """Apply admin password into the running Pi-hole volume.

    We deliberately do **not** use ``FTLCONF_webserver_api_password``:
    docker-compose ``.env`` interpolation mangles ``$`` / special chars, and with
    that env set ``pihole setpassword`` is ignored («set by environment variable»).
    Password is applied via ``docker exec … pihole setpassword`` (argv, no shell).
    """
    pwd = str(password or "")
    if not pwd:
        return {"ok": False, "error": "пустой пароль"}
    if not shutil.which("docker"):
        return {"ok": False, "error": "docker не установлен"}
    COMPOSE_DIR.mkdir(parents=True, exist_ok=True)
    yml = COMPOSE_DIR / "docker-compose.yml"
    need_rewrite = (not yml.is_file()) or _compose_has_env_password()
    if need_rewrite:
        write_compose(password=pwd)
    elif update_env:
        env = COMPOSE_DIR / ".env"
        env.write_text(f"PIHOLE_PASSWORD={_env_quote(pwd)}\n", encoding="utf-8")
        try:
            os.chmod(env, 0o600)
        except OSError:
            pass

    base = _compose_base()
    if not base:
        return {"ok": False, "error": "docker compose недоступен"}

    # Recreate only when migrating off FTLCONF env password (or first write)
    up_args = [*base, "up", "-d"]
    if need_rewrite:
        up_args.append("--force-recreate")
    up_args.append("pihole")
    up = _run(up_args, timeout=180, cwd=str(COMPOSE_DIR))
    if not up["ok"]:
        return {"ok": False, "error": (up.get("stderr") or up.get("stdout") or "up failed").strip(), "log": up}

    ready = wait_pihole_http(timeout=75)
    if not ready.get("ok"):
        return {
            "ok": False,
            "error": f"Pi-hole не отвечает после запуска: {ready.get('error') or 'timeout'}",
            "log": (up.get("stdout") or "").strip(),
        }

    # argv form — no shell, so $, quotes, spaces are safe
    sp = _run(["docker", "exec", "l2x-pihole", "pihole", "setpassword", pwd], timeout=60)
    if not sp["ok"]:
        # Older images / PATH: fall back to FTL config setter
        sp2 = _run(
            ["docker", "exec", "l2x-pihole", "pihole-FTL", "--config", "webserver.api.password", pwd],
            timeout=60,
        )
        if not sp2["ok"]:
            err = (sp.get("stderr") or sp.get("stdout") or sp2.get("stderr") or "setpassword failed").strip()
            return {"ok": False, "error": err, "log": {"setpassword": sp, "ftl": sp2}}

    check = verify_pihole_password(pwd)
    if not check.get("ok"):
        return {
            "ok": False,
            "error": f"пароль записан, но вход не проходит: {check.get('error') or 'auth failed'}",
            "log": (up.get("stdout") or "").strip(),
        }
    return {"ok": True, "log": (up.get("stdout") or "").strip()}


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


# ---------------------------------------------------------------- Pi-hole stats dashboard (API only)

_SID_LOCK = threading.Lock()
_SID_CACHE: dict[str, dict] = {}  # host:port → {sid, exp, csrf}


def _pihole_base_url(cfg: dict | None = None) -> str:
    host, port = pihole_upstream(cfg)
    return f"http://{host}:{port}"


def _pihole_http(
    method: str,
    path: str,
    *,
    cfg: dict | None = None,
    sid: str = "",
    body: dict | None = None,
    timeout: float = 4,
) -> dict:
    """Low-level JSON call to local Pi-hole web API. Returns {ok, status, data, error}."""
    url = _pihole_base_url(cfg).rstrip("/") + path
    data = None
    headers = {"Accept": "application/json", "User-Agent": "L2XPanel-DoH/1.0"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if sid:
        headers["X-FTL-SID"] = sid
        headers["sid"] = sid
    req = urllib.request.Request(url, data=data, method=method.upper(), headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            try:
                payload = json.loads(raw) if raw.strip() else {}
            except json.JSONDecodeError:
                return {"ok": False, "status": resp.status, "data": {}, "error": "не JSON от Pi-hole"}
            return {"ok": True, "status": resp.status, "data": payload if isinstance(payload, dict) else {"value": payload}, "error": ""}
    except urllib.error.HTTPError as exc:
        raw = ""
        try:
            raw = exc.read().decode("utf-8", errors="replace")
        except Exception:
            pass
        try:
            payload = json.loads(raw) if raw.strip() else {}
        except json.JSONDecodeError:
            payload = {}
        err = ""
        if isinstance(payload, dict):
            e = payload.get("error") or {}
            if isinstance(e, dict):
                err = str(e.get("message") or e.get("key") or "")
        return {
            "ok": False,
            "status": int(exc.code or 0),
            "data": payload if isinstance(payload, dict) else {},
            "error": err or f"HTTP {exc.code}",
        }
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {"ok": False, "status": 0, "data": {}, "error": str(exc) or "Pi-hole недоступен"}


def _pihole_auth(cfg: dict | None = None, *, force: bool = False) -> dict:
    """Obtain / reuse Pi-hole v6 SID. Returns {ok, sid, error}."""
    cfg = {**default_settings(), **(cfg or {})}
    host, port = pihole_upstream(cfg)
    key = f"{host}:{port}"
    now = time.time()
    with _SID_LOCK:
        cached = _SID_CACHE.get(key) or {}
        if not force and cached.get("sid") and float(cached.get("exp") or 0) > now + 15:
            return {"ok": True, "sid": cached["sid"], "error": ""}
    pwd = str(cfg.get("pihole_password") or "")
    # Empty password is valid when Pi-hole has no password set
    r = _pihole_http("POST", "/api/auth", cfg=cfg, body={"password": pwd}, timeout=5)
    if not r["ok"]:
        # v5 fallback probe — no SID needed for summaryRaw with auth token later
        return {"ok": False, "sid": "", "error": r.get("error") or "auth failed", "status": r.get("status")}
    sess = (r.get("data") or {}).get("session") or {}
    sid = str(sess.get("sid") or "")
    if not sid and sess.get("valid"):
        # No password configured — API allows unauthenticated reads
        sid = ""
    validity = float(sess.get("validity") or 280)
    with _SID_LOCK:
        _SID_CACHE[key] = {
            "sid": sid,
            "csrf": str(sess.get("csrf") or ""),
            "exp": now + max(60.0, validity - 30),
        }
    return {"ok": True, "sid": sid, "error": ""}


def invalidate_pihole_session(cfg: dict | None = None) -> None:
    host, port = pihole_upstream(cfg)
    with _SID_LOCK:
        _SID_CACHE.pop(f"{host}:{port}", None)


def _pihole_get(path: str, cfg: dict | None = None, *, retry: bool = True) -> dict:
    auth = _pihole_auth(cfg)
    if not auth.get("ok"):
        # Open (no-password) installs may still answer without SID
        r = _pihole_http("GET", path, cfg=cfg, sid="", timeout=5)
        if r.get("ok"):
            return r
        return {
            "ok": False,
            "data": {},
            "error": auth.get("error") or r.get("error") or "auth failed",
            "status": auth.get("status") or r.get("status"),
        }
    r = _pihole_http("GET", path, cfg=cfg, sid=auth.get("sid") or "", timeout=5)
    if r["ok"]:
        return r
    if retry and int(r.get("status") or 0) == 401:
        auth = _pihole_auth(cfg, force=True)
        if not auth.get("ok"):
            return {"ok": False, "data": {}, "error": auth.get("error") or "re-auth failed", "status": 401}
        return _pihole_http("GET", path, cfg=cfg, sid=auth.get("sid") or "", timeout=5)
    return r


def _num(value, default: float | int = 0):
    try:
        if value is None or value == "":
            return default
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, (int, float)):
            return value
        s = str(value).replace(",", "").strip()
        if "." in s:
            return float(s)
        return int(s)
    except (TypeError, ValueError):
        return default


def _normalize_top_list(items, *, name_keys: tuple[str, ...] = ("domain", "name", "client", "ip")) -> list[dict]:
    out: list[dict] = []
    if isinstance(items, dict):
        # v5 style {domain: count}
        for k, v in items.items():
            out.append({"name": str(k), "count": int(_num(v, 0))})
    elif isinstance(items, list):
        for it in items:
            if not isinstance(it, dict):
                continue
            name = ""
            for key in name_keys:
                if it.get(key):
                    name = str(it.get(key))
                    break
            if not name and it.get("client"):
                c = it["client"]
                if isinstance(c, dict):
                    name = str(c.get("name") or c.get("ip") or "")
                else:
                    name = str(c)
            count = _num(it.get("count", it.get("hits", it.get("queries"))), 0)
            out.append({"name": name or "—", "count": int(count)})
    out.sort(key=lambda x: x["count"], reverse=True)
    return out[:10]


def _dashboard_from_v6(cfg: dict) -> dict | None:
    summary = _pihole_get("/api/stats/summary", cfg)
    if not summary.get("ok"):
        return None
    data = summary.get("data") or {}
    queries = data.get("queries") or {}
    clients = data.get("clients") or {}
    gravity = data.get("gravity") or {}

    top_all = _pihole_get("/api/stats/top_domains?count=10", cfg)
    top_blocked = _pihole_get("/api/stats/top_domains?blocked=true&count=10", cfg)
    top_clients = _pihole_get("/api/stats/top_clients?count=10", cfg)

    domains_payload = (top_all.get("data") or {}) if top_all.get("ok") else {}
    blocked_payload = (top_blocked.get("data") or {}) if top_blocked.get("ok") else {}
    clients_payload = (top_clients.get("data") or {}) if top_clients.get("ok") else {}

    total = int(_num(queries.get("total"), 0))
    blocked = int(_num(queries.get("blocked"), 0))
    pct = _num(queries.get("percent_blocked"), 0)
    if not pct and total:
        pct = round(100.0 * blocked / total, 2)

    return {
        "ok": True,
        "source": "pihole-v6",
        "error": "",
        "queries": {
            "total": total,
            "blocked": blocked,
            "forwarded": int(_num(queries.get("forwarded"), 0)),
            "cached": int(_num(queries.get("cached"), 0)),
            "percent_blocked": round(float(pct), 2),
            "frequency": _num(queries.get("frequency"), 0),
            "types": queries.get("types") if isinstance(queries.get("types"), dict) else {},
        },
        "clients": {
            "active": int(_num(clients.get("active"), _num(clients.get("total"), 0))),
            "total": int(_num(clients.get("total"), _num(clients.get("active"), 0))),
        },
        "gravity": {
            "domains": int(_num(
                gravity.get("domains_being_blocked"),
                _num(gravity.get("domains"), 0),
            )),
            "last_update": gravity.get("last_update") or gravity.get("updated") or "",
        },
        "top_domains": _normalize_top_list(
            domains_payload.get("domains") or domains_payload.get("top_domains") or domains_payload
        ),
        "top_blocked": _normalize_top_list(
            blocked_payload.get("domains") or blocked_payload.get("top_domains") or blocked_payload
        ),
        "top_clients": _normalize_top_list(
            clients_payload.get("clients") or clients_payload.get("top_clients") or clients_payload,
            name_keys=("name", "ip", "client"),
        ),
        "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def _dashboard_from_v5(cfg: dict) -> dict | None:
    """Legacy admin/api.php — only if v6 is unavailable."""
    host, port = pihole_upstream(cfg)
    pwd = str(cfg.get("pihole_password") or "")
    q = urllib.parse.urlencode({"summaryRaw": "", "topItems": "10", "getQuerySources": "", "auth": pwd})
    url = f"http://{host}:{port}/admin/api.php?{q}"
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "L2XPanel-DoH/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception:  # noqa: BLE001
        return None
    if not isinstance(data, dict) or data.get("status") == "error":
        return None
    total = int(_num(data.get("dns_queries_today"), 0))
    blocked = int(_num(data.get("ads_blocked_today"), 0))
    pct = _num(data.get("ads_percentage_today"), 0)
    top_q = data.get("top_queries") or {}
    top_ads = data.get("top_ads") or {}
    sources = data.get("top_sources") or data.get("top_sources_blocked") or {}
    return {
        "ok": True,
        "source": "pihole-v5",
        "error": "",
        "queries": {
            "total": total,
            "blocked": blocked,
            "forwarded": int(_num(data.get("queries_forwarded"), 0)),
            "cached": int(_num(data.get("queries_cached"), 0)),
            "percent_blocked": round(float(pct), 2),
            "frequency": 0,
            "types": {},
        },
        "clients": {
            "active": int(_num(data.get("unique_clients"), 0)),
            "total": int(_num(data.get("unique_clients"), 0)),
        },
        "gravity": {
            "domains": int(_num(data.get("domains_being_blocked"), 0)),
            "last_update": "",
        },
        "top_domains": _normalize_top_list(top_q),
        "top_blocked": _normalize_top_list(top_ads),
        "top_clients": _normalize_top_list(sources),
        "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def _with_doh_top_clients(dash: dict) -> dict:
    """Replace Pi-hole localhost/docker top_clients with DoH-attributed names/IPs."""
    if not isinstance(dash, dict):
        return dash
    ours = top_doh_clients(10)
    if ours:
        dash = {**dash, "top_clients": ours, "top_clients_source": "doh"}
    else:
        dash = {**dash, "top_clients_source": dash.get("top_clients_source") or "pihole"}
    return dash


def pihole_dashboard(cfg: dict | None = None) -> dict:
    """Pull summary + top lists from local Pi-hole API; clients attributed from DoH."""
    cfg = {**default_settings(), **(cfg or {})}
    empty = {
        "ok": False,
        "source": "",
        "error": "",
        "queries": {"total": 0, "blocked": 0, "forwarded": 0, "cached": 0, "percent_blocked": 0, "frequency": 0, "types": {}},
        "clients": {"active": 0, "total": 0},
        "gravity": {"domains": 0, "last_update": ""},
        "top_domains": [],
        "top_blocked": [],
        "top_clients": [],
        "top_clients_source": "doh",
        "fetched_at": "",
    }

    dash = _dashboard_from_v6(cfg)
    if dash and dash.get("ok"):
        return _with_doh_top_clients(dash)

    dash5 = _dashboard_from_v5(cfg)
    if dash5 and dash5.get("ok"):
        return _with_doh_top_clients(dash5)

    # Even if Pi-hole API is down, still show DoH client attribution
    ours = top_doh_clients(10)
    if ours:
        empty = {**empty, "ok": True, "source": "doh-clients", "top_clients": ours, "error": ""}

    probe = _pihole_get("/api/stats/summary", cfg)
    err = probe.get("error") or ""
    status = int(probe.get("status") or 0)
    if status in (401, 403) or "unauthor" in err.lower():
        err = "неверный или пустой пароль Pi-hole — сохраните его в настройках DoH"
    if not err:
        ready = pihole_ready()
        err = ready.get("reason") if not ready.get("ok") else "не удалось получить статистику Pi-hole"
    if ours and empty.get("ok"):
        empty["error"] = err  # soft: show clients even if summary failed
        return empty
    return {**empty, "error": err, "source": "pihole"}
