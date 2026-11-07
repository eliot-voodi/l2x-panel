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
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
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
    # Prefer docker compose v2
    base = ["docker", "compose", "-f", str(COMPOSE_DIR / "docker-compose.yml")]
    r = _run([*base, "pull"], timeout=300, cwd=str(COMPOSE_DIR))
    if not r["ok"]:
        # try docker-compose
        base = ["docker-compose", "-f", str(COMPOSE_DIR / "docker-compose.yml")]
        r = _run([*base, "pull"], timeout=300, cwd=str(COMPOSE_DIR))
    if not r["ok"]:
        return {"ok": False, "error": r["stderr"] or r["stdout"] or "pull failed", "log": r}
    # Force recreate so FTLCONF_webserver_api_password from .env is applied
    sp = set_pihole_password(pwd, update_env=False)
    if not sp.get("ok"):
        return {**sp, "dir": str(COMPOSE_DIR), "docker_installed": bool(dock.get("installed"))}
    return {
        "ok": True, "dir": str(COMPOSE_DIR), "password": pwd, "log": sp.get("log"),
        "docker_installed": bool(dock.get("installed")),
    }


def set_pihole_password(password: str, *, update_env: bool = True) -> dict:
    """Apply admin password.

    Pi-hole v6 with FTLCONF_webserver_api_password ignores ``pihole setpassword``
    («set by environment variable»). We update ``.env`` and recreate the container
    so the new env value is picked up; DNS volumes are kept.
    """
    pwd = str(password or "")
    if not pwd:
        return {"ok": False, "error": "пустой пароль"}
    if not shutil.which("docker"):
        return {"ok": False, "error": "docker не установлен"}
    COMPOSE_DIR.mkdir(parents=True, exist_ok=True)
    yml = COMPOSE_DIR / "docker-compose.yml"
    if not yml.is_file():
        write_compose(password=pwd)
    elif update_env:
        env = COMPOSE_DIR / ".env"
        env.write_text(f"PIHOLE_PASSWORD={pwd}\n", encoding="utf-8")
        try:
            os.chmod(env, 0o600)
        except OSError:
            pass
    else:
        # Still ensure .env matches even when caller said update_env=False after write_compose
        env = COMPOSE_DIR / ".env"
        if not env.is_file():
            env.write_text(f"PIHOLE_PASSWORD={pwd}\n", encoding="utf-8")

    base = None
    for cand in (
        ["docker", "compose", "-f", str(yml)],
        ["docker-compose", "-f", str(yml)],
    ):
        probe = _run([*cand, "version"], timeout=30, cwd=str(COMPOSE_DIR))
        if probe["ok"]:
            base = cand
            break
    if not base:
        return {"ok": False, "error": "docker compose недоступен"}

    # Recreate so FTLCONF_webserver_api_password is re-read from .env
    up = _run([*base, "up", "-d", "--force-recreate", "pihole"], timeout=180, cwd=str(COMPOSE_DIR))
    if not up["ok"]:
        return {"ok": False, "error": (up.get("stderr") or up.get("stdout") or "recreate failed").strip(), "log": up}
    time.sleep(2)
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


def pihole_dashboard(cfg: dict | None = None) -> dict:
    """Pull summary + top lists from local Pi-hole API (no local DNS accounting)."""
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
        "fetched_at": "",
    }

    dash = _dashboard_from_v6(cfg)
    if dash and dash.get("ok"):
        return dash

    dash5 = _dashboard_from_v5(cfg)
    if dash5 and dash5.get("ok"):
        return dash5

    probe = _pihole_get("/api/stats/summary", cfg)
    err = probe.get("error") or ""
    status = int(probe.get("status") or 0)
    if status in (401, 403) or "unauthor" in err.lower():
        err = "неверный или пустой пароль Pi-hole — сохраните его в настройках DoH"
    if not err:
        ready = pihole_ready()
        err = ready.get("reason") if not ready.get("ok") else "не удалось получить статистику Pi-hole"
    return {**empty, "error": err, "source": "pihole"}
