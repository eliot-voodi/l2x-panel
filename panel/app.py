#!/usr/bin/env python3
"""L2X Panel — Xray (multi-inbound) control panel."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import shutil
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from urllib.request import Request as UrlRequest, urlopen
from urllib.error import HTTPError, URLError

import bcrypt
import yaml
from cryptography.fernet import Fernet
from fastapi import BackgroundTasks, FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool
from starlette.middleware.sessions import SessionMiddleware

import admins
import front
import hwid
import inbound_lint
import migrate as migrate_mod
import nodes as nodes_mod
import ops
import protocols as P
import doh as doh_mod
import masterdns as masterdns_mod
import settings_history as shist
import sysmon
import tgbot
import totp
import webhooks
import security as sec
import xray_runtime as xray
from copy import deepcopy

try:
    import segno
except ImportError:  # pragma: no cover
    segno = None

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover
    ZoneInfo = None

ROOT = Path(__file__).resolve().parent
DATA = Path(os.environ.get("L2XPANEL_DATA", "/var/lib/l2xpanel"))
DATA.mkdir(parents=True, exist_ok=True)
APP_NAME_DEFAULT = os.environ.get("APP_NAME", "L2X Panel")
ADMIN_USER_ENV = os.environ.get("PANEL_ADMIN_USER", "admin")
ADMIN_PASSWORD_ENV = os.environ.get("PANEL_ADMIN_PASSWORD", "").strip()
PUBLIC_HOST_ENV = os.environ.get("L2XPANEL_PUBLIC_HOST", "127.0.0.1")
STORE = DATA / "store.json"
STORE_BAK = DATA / "store.bak"
CREDS_FILE = DATA / "initial_credentials.txt"
STORE_LOCK = threading.RLock()
STARTED_AT = time.time()
# Fail-closed when store.json is corrupt and .bak cannot be recovered.
STORE_OK = True
STORE_ERR = ""


def panel_version() -> str:
    """Panel release version from VERSION (shipped next to app.py)."""
    for path in (ROOT / "VERSION", ROOT.parent / "VERSION"):
        try:
            v = path.read_text(encoding="utf-8").strip().splitlines()[0].strip()
            if v:
                return v
        except (OSError, IndexError):
            continue
    return "0.0.0"


def _load_or_create_secret_key() -> str:
    env = os.environ.get("SECRET_KEY", "").strip()
    key_file = DATA / "secret_key"
    if env:
        if not key_file.exists():
            try:
                key_file.write_text(env, encoding="utf-8")
                os.chmod(key_file, 0o600)
            except OSError:
                pass
        return env
    if key_file.exists():
        value = key_file.read_text(encoding="utf-8").strip()
        if value:
            return value
    value = secrets.token_urlsafe(48)
    key_file.write_text(value, encoding="utf-8")
    os.chmod(key_file, 0o600)
    return value


SECRET_KEY = _load_or_create_secret_key()
SLUG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$")


def _fernet() -> Fernet:
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(SECRET_KEY.encode()).digest()))


def _enc(text: str) -> str:
    return _fernet().encrypt(text.encode()).decode()


def _dec(token: str) -> str:
    return _fernet().decrypt(token.encode()).decode()


# ================================================================ store

def default_settings() -> dict:
    return {
        "panel": {
            "title": APP_NAME_DEFAULT, "session_hours": 12, "timezone": "Europe/Moscow", "lang": "ru",
            "theme": "dark", "base_path": "", "public_host": "",
            # Extra HTTPS hostnames that also open the panel (same base_path); primary stays canonical for subs.
            "extra_hosts": [],
            "extra_listen": {"enabled": False, "port": 2053, "cert_file": "", "key_file": ""},
        },
        "sub": {
            "enabled": True, "server_enabled": False, "listen": "0.0.0.0", "port": 2096, "path": "sub",
            # Extra URI prefixes that also serve subscriptions (e.g. old panel subPath)
            "path_aliases": [],
            # Extra HTTP ports nginx listens on for old clients (e.g. 2096); not TLS :443
            "legacy_ports": [],
            # Extra HTTPS ports (e.g. PasarGuard https://host:8000/sub/…), cert of public domain
            "legacy_tls_ports": [],
            "domain": "", "cert_file": "", "key_file": "", "update_hours": 1, "title": "",
            "support_url": "", "announce": "", "show_page": True,
            "json_fragment": "", "json_noise": "", "json_mux": "",
            "hwid_required": False, "hwid_fallback": "device", "migrate_url": False, "happ_provider_id": "",
            # Hide disconnected / high-loss outbounds from subscription until healthy again
            "hide_unhealthy": True, "max_loss_pct": 20,
            # PasarGuard/Marzban jwt.secret_key values — accept signed legacy sub tokens
            "legacy_jwt_secrets": [],
        },
        "tg": tgbot.default_settings(),
        "webhooks": webhooks.default_settings(),
        "nodes": {
            "agent_enabled": True, "agent_token": "", "role": "master", "agent_manual_off": False,
            # When True, /agent/manage may mutate this host even if role=master (default off).
            "allow_master_manage": False,
        },
        "panel_update": {"auto_check": True, "interval_hours": 12},
        "iplimit": {"ban_minutes": 30},
        "xray_update": {"auto_check": True, "interval_hours": 12, "include_prerelease": False},
        "pia": {
            "username": "", "password_enc": "", "token_enc": "", "token_expires_at": "",
            "auto_refresh": True, "reconnect_hours": 24, "last_refresh_at": "",
            "last_reconnect_at": "", "last_error": "", "last_ok_at": "",
        },
        "security": {
            "totp_enabled": False, "totp_secret": "",
            # Direct peers allowed to send X-Forwarded-For (nginx on localhost by default)
            "trusted_proxies": ["127.0.0.1", "::1"],
        },
        "api_tokens": [],
        "geo_custom": [],
        "geo_update": {"auto": True, "interval_hours": 168},
        "doh": {
            "enabled": False, "path_prefix": "doh", "upstream": "127.0.0.1",
            "upstream_port": doh_mod.PIHOLE_DNS_HOST_PORT,
            "pihole_web": "127.0.0.1:8089", "pihole_password": "", "timeout_sec": 4,
        },
        "masterdns": {
            "enabled": False, "domain": "", "ns_hostname": "", "ns_ip": "",
            "listen": ":53", "encryption_method": 2, "encryption_key": "",
            "resolvers": ["8.8.8.8", "1.1.1.1", "9.9.9.9", "8.8.4.4", "1.0.0.1"],
            "client_listen_ip": "127.0.0.1", "client_listen_port": 18000,
            "protocol_type": "SOCKS5",
        },
    }


def _ensure_settings(store: dict) -> dict:
    s = store.setdefault("settings", {})
    for k, v in default_settings().items():
        if isinstance(v, dict):
            cur = s.setdefault(k, {})
            for kk, vv in v.items():
                if isinstance(vv, dict):
                    sub = cur.setdefault(kk, {})
                    for k3, v3 in vv.items():
                        sub.setdefault(k3, v3)
                else:
                    cur.setdefault(kk, vv)
        else:
            s.setdefault(k, v)
    s.pop("l2tp_auto", None)
    masterdns_mod.ensure_settings(store)
    return s


def _is_legacy_l2tp_tag(tag: str) -> bool:
    t = str(tag or "").strip()
    return t == "l2tp" or t.startswith("l2tp_")


def _purge_legacy_l2tp(data: dict) -> bool:
    """One-shot: drop L2TP feature leftovers and remap outbound refs → direct."""
    dirty = False
    if "l2tp" in data:
        data.pop("l2tp", None)
        dirty = True
    if "l2tp_auto_state" in data:
        data.pop("l2tp_auto_state", None)
        dirty = True
    settings = data.get("settings")
    if isinstance(settings, dict) and "l2tp_auto" in settings:
        settings.pop("l2tp_auto", None)
        dirty = True
    for c in data.get("clients") or []:
        if not isinstance(c, dict):
            continue
        if _is_legacy_l2tp_tag(c.get("outbound") or ""):
            c["outbound"] = "direct"
            dirty = True
    for r in data.get("routes") or []:
        if not isinstance(r, dict):
            continue
        ob = str(r.get("outbound") or r.get("outbound_tag") or "")
        if _is_legacy_l2tp_tag(ob):
            r["outbound"] = "direct"
            r.pop("outbound_tag", None)
            dirty = True
    customs = data.get("outbounds_custom") or []
    if isinstance(customs, list):
        kept = [
            o for o in customs
            if isinstance(o, dict)
            and not _is_legacy_l2tp_tag(o.get("tag") or "")
            and o.get("kind") != "l2tp"
        ]
        if len(kept) != len(customs):
            data["outbounds_custom"] = kept
            dirty = True
    bals = data.get("balancers") or {}
    if isinstance(bals, dict):
        for b in bals.values():
            if not isinstance(b, dict):
                continue
            members = b.get("members") or []
            if not isinstance(members, list):
                continue
            cleaned = [m for m in members if not _is_legacy_l2tp_tag(str(m))]
            if cleaned != members:
                b["members"] = cleaned
                dirty = True
    meta = data.setdefault("meta", {})
    if isinstance(meta, dict) and meta.get("l2tp_purged") != 1:
        meta["l2tp_purged"] = 1
        dirty = True
    return dirty


def _backup_corrupt_store() -> Path | None:
    try:
        if not STORE.exists():
            return None
        dest = DATA / f"store.corrupt.{int(time.time())}.json"
        shutil.copy2(STORE, dest)
        try:
            os.chmod(dest, 0o600)
        except OSError:
            pass
        return dest
    except OSError:
        return None


def _read_store_json(path: Path) -> dict:
    raw = path.read_text(encoding="utf-8")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("store root must be object")
    return data


def _load_store() -> dict:
    global STORE_OK, STORE_ERR
    data: dict = {}
    loaded_ok = False
    if STORE.exists():
        try:
            data = _read_store_json(STORE)
            loaded_ok = True
            STORE_OK = True
            STORE_ERR = ""
        except (ValueError, OSError, json.JSONDecodeError) as exc:
            _backup_corrupt_store()
            recovered = False
            if STORE_BAK.exists():
                try:
                    data = _read_store_json(STORE_BAK)
                    loaded_ok = True
                    recovered = True
                    STORE_OK = True
                    STORE_ERR = f"store.json повреждён, загружен store.bak ({exc})"
                except (ValueError, OSError, json.JSONDecodeError):
                    recovered = False
            if not recovered:
                STORE_OK = False
                STORE_ERR = f"store.json повреждён и store.bak недоступен: {exc}"
                # Fail-closed: empty in-memory view, never persist until fixed.
                data = {}
    else:
        STORE_OK = True
        STORE_ERR = ""
        loaded_ok = True

    for key, default in (("clients", []), ("routes", []), ("outbounds_custom", []), ("ip_bans", []),
                         ("ip_ban_stats", {}), ("xray_update_state", {}),
                         ("panel_update_state", {}), ("nodes", []), ("groups", [])):
        data.setdefault(key, default)
    data.setdefault("reverse", {"bridges": [], "portals": []})
    data.setdefault("meta", {})
    xray.ensure_balancers(data)
    xray.ensure_inbounds(data)
    xray.ensure_groups(data)
    xray._ensure_section(data, "xray_settings", xray.default_xray_settings())
    xray._ensure_section(data, "dns", xray.default_dns())
    _ensure_settings(data)
    dirty = _purge_legacy_l2tp(data)
    for c in data["clients"]:
        xray.ensure_client(c)
        if not c.get("sub_token"):
            c["sub_token"] = secrets.token_urlsafe(18)
            dirty = True
    if "inbound" in data:
        data.pop("inbound", None)
        dirty = True
    # Never write an empty/default store over a corrupt file.
    if dirty and STORE_OK and loaded_ok:
        _save_store(data)
    return data


def _save_store(data: dict) -> None:
    if not STORE_OK:
        raise RuntimeError(f"store read-only: {STORE_ERR or 'corrupt'}")
    payload = json.dumps(data, ensure_ascii=False, indent=2)
    if STORE.exists():
        try:
            shutil.copy2(STORE, STORE_BAK)
            try:
                os.chmod(STORE_BAK, 0o600)
            except OSError:
                pass
        except OSError:
            pass
    tmp = STORE.with_suffix(".tmp")
    tmp.write_text(payload, encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, STORE)


@contextmanager
def mutate(*, history_section: str = "", history_note: str = ""):
    """Yield store for edits. Auto-records version history for clients/inbounds/settings/…"""
    with STORE_LOCK:
        if not STORE_OK:
            raise RuntimeError(f"store read-only: {STORE_ERR or 'corrupt'}")
        store = _load_store()
        if not STORE_OK:
            raise RuntimeError(f"store read-only: {STORE_ERR or 'corrupt'}")
        before_state = shist.canonical_state(store)
        yield store
        after_state = shist.canonical_state(store)
        if after_state != before_state:
            meta = tgbot.get_actor_meta()
            shist.record(
                before_state, after_state,
                user=meta.get("user") or "", ip=meta.get("ip") or "",
                section=history_section, note=history_note,
            )
        _save_store(store)


FRONT_CERT_RETRY = 3600
_front_cert_tried: dict[str, float] = {}


def _commit_front_safe(staged: dict) -> None:
    """Background nginx reload after /agent/apply response has been sent."""
    try:
        fr = front.commit(staged)
        if not fr.get("ok"):
            try:
                front.rollback(staged)
                front.commit(staged)
            except Exception:
                pass
    except Exception:
        try:
            front.rollback(staged)
        except Exception:
            pass


def _apply_xray(
    store: dict,
    *,
    persist: bool = True,
    defer_front_reload: float = 0,
    hold_front_commit: bool = False,
    xray_only: bool = False,
    clients_only: bool = False,
) -> dict:
    """nginx front and Xray are verified before either is loaded; nothing is applied if a check fails.

    On agent nodes, Xray is built from a runtime view while the persisted
    store may still hold a full mirror of the master for fast failover.

    hold_front_commit: stage+test nginx but leave reload to the caller (BackgroundTasks on
    /agent/apply) so the sync HTTP response is not cut by reloading the proxying nginx.
    defer_front_reload: legacy Timer-based delay inside commit (prefer hold_front_commit).
    xray_only: clients / outbounds / routing / Xray DNS — skip nginx stage/reload,
    cert jobs, and iptables (front unchanged). Still rebuilds+tests+restarts Xray.
    clients_only: alias of xray_only (kept for older call sites).
    """
    xray_only = bool(xray_only or clients_only)
    ns = (store.get("settings") or {}).get("nodes") or {}
    is_agent = bool(ns.get("agent_enabled") and (ns.get("role") or "") == "agent")
    runtime = nodes_mod.agent_runtime_store(store) if is_agent else store
    with STORE_LOCK:
        xray.ensure_inbounds(runtime)
        staged = {"ok": True, "skipped": True, "changed": False, "problems": [], "error": ""}
        if not xray_only:
            # Register rv-in / master-backhaul Path in store before nginx stage
            # (otherwise first enable ships nginx without the location → 404 dial).
            if not is_agent:
                try:
                    xray.ensure_reverse_front_inbound(store)
                except Exception:
                    pass
                try:
                    xray.ensure_master_backhaul_front_inbound(store)
                except Exception:
                    pass
            # Front/certs use the real store (domains, base_path); Xray uses runtime
            staged = front.stage(store)
            if not staged["ok"]:
                return {"ok": False, "error": staged["error"], "verified": False}
        result = xray.apply_config(runtime, xray_only=xray_only)
        if not result.get("ok"):
            if not xray_only:
                front.rollback(staged)
            if persist:
                _save_store(store)
            return result
        if xray_only:
            pass
        elif hold_front_commit:
            result = {**result, "_front_staged": staged}
            if staged.get("problems"):
                result["warning"] = "; ".join(staged["problems"])
        else:
            fr = front.commit(staged, defer_reload_sec=defer_front_reload)
            if not fr["ok"]:
                result = {**result, "ok": False, "error": fr["error"]}
            elif staged.get("problems"):
                result = {**result, "warning": "; ".join(staged["problems"])}
        if persist:
            _save_store(store)
    if result.get("ok") and not xray_only:
        direct_ports = [
            int(ib.get("port") or 0) for ib in runtime.get("inbounds") or []
            if ib.get("enabled", True) and P.is_direct(ib)
        ]
        if direct_ports:
            try:
                ops.ensure_ports_open(direct_ports)
            except Exception:
                pass
    if not xray_only and not hold_front_commit:
        _issue_front_certs(store)
    try:
        geo = _ensure_ext_geo(runtime)
    except Exception:
        geo = {}
    if geo.get("missing"):
        note = "правила с " + ", ".join(geo["missing"]) + " пропущены до скачивания"
        if geo.get("started"):
            note += " (скачивание запущено)"
        if geo.get("unknown"):
            note += f"; нет источника для {', '.join(geo['unknown'])} — добавьте в Xray → Geo"
        result = {**result, "warning": "; ".join(x for x in (result.get("warning"), note) if x)}
    return result


def _issue_front_certs(store: dict) -> None:
    """Let's Encrypt for share domains still on a self-signed certificate; re-applies nginx when issued."""
    if not front.available():
        return
    now = time.time()
    for domain in front.domains_without_cert(store):
        if now - _front_cert_tried.get(domain, 0) < FRONT_CERT_RETRY:
            continue
        _front_cert_tried[domain] = now

        def issue(d: str = domain) -> dict:
            r = ops.issue_cert(d, "")
            if r.get("ok"):
                _apply_xray(_load_store())
            return r

        ops.start_job(f"cert-{domain}", issue)


def _settings() -> dict:
    return _load_store()["settings"]


SETTINGS_CACHE: dict = {}


def _refresh_settings_cache() -> dict:
    SETTINGS_CACHE.clear()
    SETTINGS_CACHE.update(_settings())
    return SETTINGS_CACHE


def public_host() -> str:
    """Public hostname for links: changeable domain (preferred) or env/IP fallback."""
    store_host = (SETTINGS_CACHE.get("panel") or {}).get("public_host") or ""
    host = front.normalize_host(store_host) or front.normalize_host(PUBLIC_HOST_ENV)
    return host or PUBLIC_HOST_ENV


def public_https_base() -> str:
    """Canonical client-facing base URL — always HTTPS on :443 when a domain is configured."""
    host = public_host()
    if front.is_domain(host):
        return f"https://{host}"
    return f"http://{host}"


def base_path() -> str:
    bp = ((SETTINGS_CACHE.get("panel") or {}).get("base_path") or "").strip().strip("/")
    return f"/{bp}" if bp else ""


# Public site root and these prefixes belong to nginx / subscriptions, never to the panel
BASE_PATH_RESERVED = {
    "sub", "panel", "health", "static", "login", "logout", "well-known",
    "pihole", "pihole-gate", "doh", "api",
}


def _clean_base_path(value: str) -> str:
    bp = re.sub(r"[^A-Za-z0-9_-]", "", str(value or ""))
    return "" if bp.lower() in BASE_PATH_RESERVED else bp


def _new_base_path() -> str:
    return secrets.token_urlsafe(9).replace("-", "").replace("_", "")[:12]


def _ensure_base_path() -> None:
    """The panel is only ever served under a secret prefix; `/` of the public site is camouflage."""
    with mutate() as store:
        p = store["settings"].setdefault("panel", {})
        bp = _clean_base_path(p.get("base_path") or "")
        if bp != p.get("base_path") or not bp:
            p["base_path"] = bp or _new_base_path()
        if not isinstance(p.get("extra_hosts"), list):
            p["extra_hosts"] = []


def app_title() -> str:
    return (SETTINGS_CACHE.get("panel") or {}).get("title") or APP_NAME_DEFAULT


# ================================================================ admin auth

def _write_initial_credentials(username: str, password: str) -> None:
    CREDS_FILE.write_text(
        f"username={username}\npassword={password}\n"
        f"# Shown once on first start. Change in Settings or: l2x reset-password\n",
        encoding="utf-8",
    )
    os.chmod(CREDS_FILE, 0o600)
    print(
        f"\n  L2X Panel first start credentials\n"
        f"  Login:    {username}\n"
        f"  Password: {password}\n"
        f"  Saved to: {CREDS_FILE}\n",
        flush=True,
    )


def _ensure_admins() -> None:
    admins.ensure(
        default_user=ADMIN_USER_ENV,
        default_password_env=ADMIN_PASSWORD_ENV,
        on_new_password=_write_initial_credentials,
    )


def _admin() -> dict:
    """Primary administrator (legacy helpers / node snapshots)."""
    _ensure_admins()
    return admins.primary()


def _admin_record_for_user(username: str | None) -> dict | None:
    _ensure_admins()
    if not username:
        return admins.primary()
    return admins.get_by_username(username) or admins.primary()


def _check_credentials(username: str, password: str) -> bool:
    _ensure_admins()
    return admins.check_credentials(username, password)


def _verify_current_password(request: Request, current: str) -> bool:
    user = _user(request)
    if not user:
        return False
    return _check_credentials(str(user), current)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _set_agent_token(ns: dict, raw: str) -> None:
    """Store plaintext (needed for outbound Bearer) + hash for verification."""
    tok = str(raw or "").strip()
    ns["agent_token"] = tok
    ns["agent_token_hash"] = _hash_token(tok) if tok else ""


def _agent_token_ok(ns: dict, got: str | None) -> bool:
    got_s = str(got or "")
    if not got_s:
        return False
    th = str(ns.get("agent_token_hash") or "")
    if th and sec.token_eq(_hash_token(got_s), th):
        return True
    expected = str(ns.get("agent_token") or "")
    return bool(expected) and sec.token_eq(got_s, expected)


# ================================================================ app + middleware

app = FastAPI(title=APP_NAME_DEFAULT, docs_url=None, redoc_url=None, openapi_url=None)


class BasePathMiddleware:
    """Serve the panel under a secret prefix; public sub/API paths stay reachable."""

    # /panel/api/ is intentionally NOT public — only reachable under secret base_path
    PUBLIC = ("/sub/", "/api/sub/", "/health", "/static/")

    def __init__(self, inner):
        self.inner = inner

    def _public(self, path: str) -> bool:
        if path.startswith(self.PUBLIC):
            return True
        # Subscription path aliases (old panel subPath etc.)
        for sp in front.sub_uri_paths({"settings": SETTINGS_CACHE} if SETTINGS_CACHE else None):
            if path == f"/{sp}" or path.startswith(f"/{sp}/"):
                return True
        # DoH is always outside the secret base path (nginx → panel)
        prefix = doh_mod.normalize_prefix(
            str((SETTINGS_CACHE.get("doh") or {}).get("path_prefix") or "doh")
        )
        return path == f"/{prefix}" or path.startswith(f"/{prefix}/")

    def _rewrite_doh(self, path: str) -> str | None:
        """Map /{prefix}/{token}[/dns-query] → /doh/{token} for the FastAPI handler."""
        prefix = doh_mod.normalize_prefix(
            str((SETTINGS_CACHE.get("doh") or {}).get("path_prefix") or "doh")
        )
        root = f"/{prefix}/"
        if not path.startswith(root):
            return None
        rest = path[len(root):]
        token = rest.split("/", 1)[0]
        if not doh_mod.TOKEN_RE.match(token):
            return None
        return f"/doh/{token}"

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            bp = base_path()
            path = scope.get("path") or "/"
            if bp:
                if path == bp or path.startswith(bp + "/"):
                    scope = dict(scope)
                    scope["path"] = path[len(bp):] or "/"
                    path = scope["path"]
                elif not self._public(path):
                    resp = PlainTextResponse("404 page not found", status_code=404)
                    await resp(scope, receive, send)
                    return
            rewritten = self._rewrite_doh(path)
            if rewritten and rewritten != path:
                scope = dict(scope)
                scope["path"] = rewritten
        await self.inner(scope, receive, send)


class CsrfMiddleware:
    """Require csrf_token on browser form POSTs (session cookie auth).

    Must sit inside SessionMiddleware (so session works) and inside BasePathMiddleware
    (so path is already stripped of the secret prefix).
    """

    EXEMPT_PREFIXES = (
        "/agent/", "/panel/api/", "/sub/", "/api/sub/", "/doh/", "/pihole/", "/health", "/static/",
    )

    def __init__(self, inner):
        self.inner = inner

    def _exempt(self, path: str) -> bool:
        return any(path == p.rstrip("/") or path.startswith(p) for p in self.EXEMPT_PREFIXES)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("method", "GET").upper() not in ("POST", "PUT", "PATCH", "DELETE"):
            await self.inner(scope, receive, send)
            return
        path = scope.get("path") or "/"
        if self._exempt(path):
            await self.inner(scope, receive, send)
            return
        headers = {k.decode().lower(): v.decode() for k, v in (scope.get("headers") or [])}
        auth = headers.get("authorization") or ""
        if auth.lower().startswith("bearer ") or headers.get("x-api-key"):
            await self.inner(scope, receive, send)
            return

        chunks: list[bytes] = []
        while True:
            message = await receive()
            if message["type"] != "http.request":
                async def _once():
                    return message
                await self.inner(scope, _once, send)
                return
            chunks.append(message.get("body") or b"")
            if not message.get("more_body"):
                break
        body = b"".join(chunks)

        sent = {"n": 0}

        async def replay():
            if sent["n"] == 0:
                sent["n"] = 1
                return {"type": "http.request", "body": body, "more_body": False}
            return {"type": "http.request", "body": b"", "more_body": False}

        from starlette.requests import Request as StarletteRequest
        req = StarletteRequest(scope, replay)
        try:
            session = req.session
        except AssertionError:
            sent["n"] = 0
            await self.inner(scope, replay, send)
            return

        got = headers.get("x-csrf-token") or ""
        ctype = (headers.get("content-type") or "").lower()
        if not got and "application/json" not in ctype:
            if "application/x-www-form-urlencoded" in ctype:
                from urllib.parse import parse_qs
                got = (parse_qs(body.decode("utf-8", "replace")).get("csrf_token") or [""])[0]
            elif "multipart/form-data" in ctype:
                marker = b'name="csrf_token"'
                idx = body.find(marker)
                if idx >= 0:
                    rest = body[idx + len(marker):]
                    sep = rest.find(b"\r\n\r\n")
                    if sep >= 0:
                        val = rest[sep + 4:]
                        end = val.find(b"\r\n")
                        got = val[:end].decode("utf-8", "replace") if end >= 0 else ""

        if path == "/login" or session.get("user"):
            if not sec.csrf_ok(session, got):
                resp = PlainTextResponse("CSRF rejected", status_code=403)

                async def _empty():
                    return {"type": "http.request", "body": b"", "more_body": False}

                await resp(scope, _empty, send)
                return

        sent["n"] = 0
        await self.inner(scope, replay, send)


# Innermost → outermost: Csrf → Session → BasePath
_COOKIE_INSECURE = os.environ.get("L2XPANEL_COOKIE_INSECURE", "").strip() in ("1", "true", "yes")
app.add_middleware(CsrfMiddleware)
app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    max_age=12 * 3600,
    same_site="lax",
    https_only=not _COOKIE_INSECURE,
)
app.add_middleware(BasePathMiddleware)
templates = Jinja2Templates(directory=str(ROOT / "ui"))

# ================================================================ i18n / template helpers

I18N_EN = {
    "Дашборд": "Dashboard", "Inbounds": "Inbounds", "Клиенты": "Clients",
    "Outbounds": "Outbounds", "Балансировщики": "Balancers", "Маршрутизация": "Routing", "Xray": "Xray",
    "Логи": "Logs", "Настройки": "Settings", "Выход": "Logout", "Сохранить": "Save", "Удалить": "Delete",
    "Добавить": "Add", "Изменить": "Edit", "Отмена": "Cancel", "Применить": "Apply", "Поиск": "Search",
    "Онлайн": "Online", "Трафик": "Traffic", "Срок": "Expiry", "Статус": "Status", "Лимит": "Limit",
    "Подписка": "Subscription", "Включён": "Enabled", "Выключен": "Disabled", "Действия": "Actions",
    "Сбросить трафик": "Reset traffic", "Системa": "System", "Память": "Memory", "Диск": "Disk",
    "Аптайм": "Uptime", "Сеть": "Network", "Процессор": "CPU", "Перезапустить": "Restart",
    "Остановить": "Stop", "Запустить": "Start", "Версия": "Version", "Новый клиент": "New client",
    "Новый inbound": "New inbound", "Безопасность": "Security", "Бэкап": "Backup", "Панель": "Panel",
    "Подписки": "Subscriptions", "Сертификаты": "Certificates", "Система": "System", "Все": "All",
    "Активные": "Active", "Истёкшие": "Expired", "Исчерпан": "Depleted", "Отключённые": "Disabled",
    "Вход": "Sign in", "Логин": "Username", "Пароль": "Password", "Код 2FA": "2FA code",
    "Обновить": "Refresh", "Тест": "Test", "Импорт": "Import", "Шаблон": "Template", "Ядро": "Core",
}


def t(text: str) -> str:
    lang = (SETTINGS_CACHE.get("panel") or {}).get("lang") or "ru"
    return I18N_EN.get(text, text) if lang == "en" else text


def fmt_dt(value: str | None, with_time: bool = True) -> str:
    if not value:
        return "—"
    dt = xray.parse_expire_at(value)
    if not dt:
        return str(value)
    tz = (SETTINGS_CACHE.get("panel") or {}).get("timezone") or "UTC"
    if ZoneInfo:
        try:
            dt = dt.astimezone(ZoneInfo(tz))
        except Exception:
            pass
    return dt.strftime("%d.%m.%Y %H:%M" if with_time else "%d.%m.%Y")


def _panel_tz():
    tz = (SETTINGS_CACHE.get("panel") or {}).get("timezone") or "UTC"
    if ZoneInfo:
        try:
            return ZoneInfo(tz)
        except Exception:
            pass
    return timezone.utc


def fmt_rate(bytes_per_sec: float | int | None) -> str:
    bits = float(bytes_per_sec or 0) * 8
    for unit, div in (("Гбит/с", 1e9), ("Мбит/с", 1e6), ("Кбит/с", 1e3)):
        if bits >= div:
            return f"{bits / div:.1f} {unit}"
    return f"{bits:.0f} бит/с"


def fmt_ts(ts: float | int | None) -> str:
    if not ts:
        return "—"
    return datetime.fromtimestamp(float(ts), _panel_tz()).strftime("%d.%m.%Y %H:%M")


def dt_input(value: str | None) -> str:
    """ISO (UTC) → value for <input type=datetime-local> in panel timezone."""
    dt = xray.parse_expire_at(value)
    return dt.astimezone(_panel_tz()).strftime("%Y-%m-%dT%H:%M") if dt else ""


def local_to_iso(value: str | None) -> str:
    """datetime-local (panel timezone, no offset) → ISO with offset."""
    raw = (value or "").strip()
    if not raw:
        return ""
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return raw
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_panel_tz())
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def ago(value: str | None) -> str:
    dt = xray.parse_expire_at(value)
    if not dt:
        return "никогда"
    sec = int((xray.now_utc() - dt).total_seconds())
    if sec < 60:
        return "только что"
    if sec < 3600:
        return f"{sec // 60} мин назад"
    if sec < 86400:
        return f"{sec // 3600} ч назад"
    return f"{sec // 86400} дн назад"


def fmt_uptime(sec: int) -> str:
    d, r = divmod(int(sec), 86400)
    h, r = divmod(r, 3600)
    return f"{d}д {h}ч {r // 60}м" if d else f"{h}ч {r // 60}м"


def qr_svg(text: str, scale: int = 4) -> str:
    if not segno or not text:
        return ""
    return segno.make(text, error="m").svg_inline(scale=scale, dark="#0b1220", light="#ffffff", border=2)


for _name, _fn in {
    "t": t, "fmt_dt": fmt_dt, "ago": ago, "dt_input": dt_input, "fmt_ts": fmt_ts, "fmt_rate": fmt_rate, "fmt_uptime": fmt_uptime, "qr_svg": qr_svg,
    "format_traffic": xray.format_traffic, "bytes_to_gb": xray.bytes_to_gb, "country_code": xray.country_code,
    "flag_emoji": xray.flag_emoji, "outbound_label": xray.outbound_label, "client_status": xray.client_status,
    "client_used_bytes": xray.client_used_bytes, "gb_to_bytes": xray.gb_to_bytes, "days_left": xray.days_left,
    "inbound_used_bytes": xray.inbound_used_bytes, "inbound_access_ok": xray.inbound_access_ok,
}.items():
    templates.env.globals[_name] = _fn
templates.env.globals["P"] = P


def flash(request: Request, message: str, level: str = "info") -> None:
    request.session["flash"] = {"message": message, "level": level}


def pop_flash(request: Request):
    return request.session.pop("flash", None)


def go(path: str) -> RedirectResponse:
    if not path.startswith("/") or path.startswith("//") or "\\" in path:
        path = "/"
    return RedirectResponse(base_path() + path, status_code=303)


def _user(request: Request):
    return request.session.get("user")


def _trusted_proxies() -> list[str]:
    sec_cfg = (SETTINGS_CACHE.get("security") or {}) if SETTINGS_CACHE else {}
    raw = sec_cfg.get("trusted_proxies")
    if isinstance(raw, list) and raw:
        return [str(x) for x in raw]
    env = os.environ.get("L2XPANEL_TRUSTED_PROXIES", "").strip()
    if env:
        return [x.strip() for x in env.split(",") if x.strip()]
    return list(sec.DEFAULT_TRUSTED_PROXIES)


def _client_ip(request: Request) -> str:
    return sec.client_ip(request, _trusted_proxies())


def _require(request: Request):
    if not _user(request):
        tgbot.clear_actor()
        return go("/login")
    exp = request.session.get("exp", 0)
    if exp and time.time() > exp:
        request.session.clear()
        tgbot.clear_actor()
        return go("/login")
    # Always attribute subsequent TG change/node notices to this panel session
    tgbot.bind_actor(str(_user(request) or "?"), _client_ip(request))
    return None


def _cur_path(request: Request) -> str:
    """Current page path without the secret base path (for ?next= redirects)."""
    path = request.url.path or "/"
    bp = base_path()
    if bp and path.startswith(bp):
        path = path[len(bp):] or "/"
    return path if path.startswith("/") else "/"


def page(request: Request, template: str, active: str = "", status_code: int = 200, **ctx) -> HTMLResponse:
    s = SETTINGS_CACHE or _refresh_settings_cache()
    csrf = sec.ensure_csrf(request.session)
    base = {
        "request": request, "app_name": app_title(), "user": _user(request), "flash": pop_flash(request),
        "bp": base_path(), "active": active, "theme": (s.get("panel") or {}).get("theme") or "dark",
        "lang": (s.get("panel") or {}).get("lang") or "ru", "public_host": public_host(),
        "panel_version": panel_version(),
        "xray_update": xray_update_banner() if _user(request) else None,
        "panel_update": panel_update_banner() if _user(request) else None,
        "cur_path": _cur_path(request),
        "is_master": nodes_mod.is_master(_load_store()) if _user(request) else True,
        "csrf_token": csrf,
    }
    base.update(ctx)
    return templates.TemplateResponse(template, base, status_code=status_code)


def _ok_msg(prefix: str, result: dict) -> tuple[str, str]:
    if result.get("ok") and result.get("warning"):
        # Soft front/routing notes (other inbounds still published) — not a hard failure
        return f"{prefix}. Замечание: {result['warning']}", "info"
    if result.get("ok"):
        return prefix, "info"
    return f"{prefix} / Xray: {result.get('error')}", "error"


def _split_lines(value: str) -> list[str]:
    return [x.strip() for x in (value or "").replace(",", "\n").splitlines() if x.strip()]


def _float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _allowed_outbounds(store: dict) -> set[str]:
    return set(xray.all_outbound_tags(store))


# ================================================================ background workers

WATCHDOG_INTERVAL = int(os.environ.get("L2XPANEL_WATCHDOG_SEC", "20"))
_stop = threading.Event()
ONLINE: dict[str, list[str]] = {}
HISTORY = sysmon.History(DATA / "history.json")
OB_STATS = sysmon.OutboundStats(DATA / "outbound_history.json")


def _ob_totals(store: dict) -> dict[str, tuple[int, int]]:
    return {tag: (int(r.get("up") or 0), int(r.get("down") or 0))
            for tag, r in (store.get("outbound_traffic") or {}).items()}
_expiry_notified: dict[str, str] = {}


def _bot_settings() -> dict:
    return (SETTINGS_CACHE or _refresh_settings_cache()).get("tg") or {}


def _tg_report() -> str:
    store = _load_store()
    snap = sysmon.snapshot()
    xs = xray.xray_status()
    mem = snap["mem"]
    total_up = sum(int(c["traffic"].get("up") or 0) for c in store["clients"])
    total_down = sum(int(c["traffic"].get("down") or 0) for c in store["clients"])
    return (
        f"<b>{app_title()}</b>\n"
        f"CPU {snap['cpu']}% · RAM {xray.format_traffic(mem['used'])}/{xray.format_traffic(mem['total'])}\n"
        f"Uptime {fmt_uptime(snap['uptime'])} · Load {snap['load'][0]}\n"
        f"Xray {xs['version']} {'🟢' if xs['active'] else '🔴'}\n"
        f"Клиенты: {len(store['clients'])} (онлайн {len(ONLINE)})\n"
        f"Трафик клиентов: ↑{xray.format_traffic(total_up)} ↓{xray.format_traffic(total_down)}"
    )


def _tg_usage(email: str) -> str:
    store = _load_store()
    c = next((x for x in store["clients"] if x["email"] == email), None)
    if not c:
        return f"Клиент {email} не найден"
    return _client_summary(c)


def _client_summary(c: dict) -> str:
    used = xray.client_used_bytes(c)
    rem = xray.client_remaining_gb(c)
    if c.get("limit_gb"):
        traffic = f"Трафик: {xray.format_traffic(used)} / {c['limit_gb']:g} ГБ"
        if rem is not None:
            traffic += f"\nОсталось: <b>{rem:.2f} ГБ</b>"
    else:
        traffic = f"Трафик: {xray.format_traffic(used)} / ∞"
    if c.get("daily_limit_gb"):
        dused = xray.client_daily_used_bytes(c)
        traffic += f"\nДень: {xray.format_traffic(dused)} / {c['daily_limit_gb']:g} ГБ"
    left = xray.days_left(c)
    if c.get("expire_at"):
        expire = f"Срок: {fmt_dt(c.get('expire_at'))}"
        if left is not None and left > 0:
            expire += f"\nОсталось: <b>{left:.0f} дн</b>"
        elif left is not None and left <= 0:
            expire += "\n<b>срок истёк</b>"
    elif c.get("start_on_first_use"):
        expire = f"Срок: {c.get('duration_days') or '?'} дн с 1-го подключения"
    else:
        expire = "Срок: бессрочно"
    return (
        f"<b>{c['email']}</b> — {xray.client_status(c)}\n"
        f"{traffic}\n{expire}\n"
        f"Онлайн: {'да' if c['email'] in ONLINE else 'нет'} · последний {ago(c.get('last_online'))}"
    )


def _tg_client_by_tg(chat_id: str) -> str:
    store = _load_store()
    c = next((x for x in store["clients"] if str(x.get("tg_id") or "") == chat_id), None)
    return _client_summary(c) if c else ""


def _apply_tg_profile(client: dict, chat_id: str, profile: dict | None = None) -> None:
    """Persist Telegram id + username + FIO on a client record."""
    p = profile or {}
    client["tg_id"] = str(p.get("id") or chat_id or "").strip()
    client["tg_username"] = str(p.get("username") or "").strip().lstrip("@")
    client["tg_first_name"] = str(p.get("first_name") or "").strip()
    client["tg_last_name"] = str(p.get("last_name") or "").strip()
    fio = str(p.get("fio") or "").strip()
    if not fio:
        fio = " ".join(x for x in (client["tg_first_name"], client["tg_last_name"]) if x).strip()
    client["tg_fio"] = fio


def _clear_tg_profile(client: dict) -> None:
    client["tg_id"] = ""
    client["tg_username"] = ""
    client["tg_first_name"] = ""
    client["tg_last_name"] = ""
    client["tg_fio"] = ""
    client.pop("tg_bind", None)


def _tg_bind(bind_token: str, chat_id: str, profile: dict | None = None) -> tuple[bool, str]:
    token = (bind_token or "").strip()
    if not token or len(token) < 8:
        return False, "Некорректная ссылка привязки. Откройте страницу подписки снова."
    now = datetime.now(timezone.utc)
    with mutate() as store:
        target = None
        for c in store.get("clients") or []:
            b = c.get("tg_bind") or {}
            if not b.get("token") or not secrets.compare_digest(str(b.get("token")), token):
                continue
            exp = xray.parse_expire_at(b.get("exp"))
            if exp and now > exp:
                c.pop("tg_bind", None)
                return False, "Ссылка устарела. Нажмите «Привязать Telegram» на странице подписки ещё раз."
            target = c
            break
        if not target:
            return False, "Ссылка не найдена или уже использована."
        # One Telegram account → one client
        for c in store.get("clients") or []:
            if c is not target and str(c.get("tg_id") or "") == str(chat_id):
                _clear_tg_profile(c)
        _apply_tg_profile(target, chat_id, profile)
        target.pop("tg_bind", None)
        email = target.get("email") or ""
        uname = target.get("tg_username") or ""
        fio = target.get("tg_fio") or ""
        summary = _client_summary(target)
    extra = ""
    if uname or fio:
        extra = f"\nАккаунт: {('@' + uname) if uname else '—'} · {fio or '—'}"
    return True, f"✅ Telegram привязан к <b>{email}</b>{extra}\n\n{summary}\n\n/status — статус · /unlink — отвязать"


def _tg_unlink(chat_id: str) -> tuple[bool, str]:
    with mutate() as store:
        found = False
        for c in store.get("clients") or []:
            if str(c.get("tg_id") or "") == str(chat_id):
                _clear_tg_profile(c)
                found = True
        if not found:
            return False, "К этому Telegram ничего не привязано."
    return True, "Telegram отвязан от подписки."


def _tg_touch_profile(chat_id: str, profile: dict | None = None) -> None:
    """Refresh username/FIO for an already linked client (best-effort)."""
    if not chat_id or not profile:
        return
    with mutate() as store:
        for c in store.get("clients") or []:
            if str(c.get("tg_id") or "") != str(chat_id):
                continue
            _apply_tg_profile(c, chat_id, profile)
            break


def _tg_online() -> str:
    return "\n".join(f"🟢 {email}: {', '.join(ips)}" for email, ips in ONLINE.items())


def _tg_clients() -> str:
    store = _load_store()
    return "\n".join(f"{'🟢' if c['email'] in ONLINE else '⚪'} {c['email']} — {xray.client_status(c)} — "
                     f"{xray.format_traffic(xray.client_used_bytes(c))}" for c in store["clients"]) or "Нет клиентов"


def _tg_backup() -> tuple[str, bytes]:
    return f"l2xpanel-{datetime.now().strftime('%Y%m%d-%H%M')}.zip", ops.make_backup(DATA)


def _send_backup_to_telegram(*, caption: str = "Бэкап L2X Panel", scheduled: bool = False) -> dict:
    """Write backup to disk → send to Telegram admins → delete the file on success."""
    written = ops.write_backup(DATA)
    if not written.get("ok"):
        return {"ok": False, "error": written.get("error") or "write failed"}
    path = written["path"]
    name = written["name"]
    blob = written.get("bytes") or Path(path).read_bytes()
    try:
        sent = BOT.send_document(name, blob, caption)
    except Exception as exc:  # noqa: BLE001
        ops.delete_backup_file(path)
        return {"ok": False, "error": str(exc)[:300], "deleted": True}
    if sent:
        ops.delete_backup_file(path)
        ops.cleanup_staged_backups(DATA, keep_newest=0)
        ops.cleanup_pre_restore(DATA, keep_newest=1)
        return {
            "ok": True, "name": name, "size": written.get("size") or len(blob),
            "deleted": True, "scheduled": scheduled,
        }
    # Keep file briefly on failure so admin can download / retry; still prune older leftovers
    ops.cleanup_staged_backups(DATA, keep_newest=1)
    return {
        "ok": False, "error": "Telegram sendDocument failed",
        "path": path, "name": name, "deleted": False,
    }


def _tg_restart_xray() -> str:
    r = ops.xray_control("restart")
    return "Xray перезапущен" if r["ok"] else f"Ошибка: {r['stderr']}"


def _bot_should_poll() -> bool:
    """Only the master long-polls Telegram — avoids 409 Conflict when several nodes share a token."""
    try:
        return nodes_mod.is_master(_load_store())
    except Exception:
        return True


BOT = tgbot.Bot(_bot_settings, {
    "report": _tg_report, "usage": _tg_usage, "online": _tg_online, "clients": _tg_clients,
    "backup": _tg_backup,
    "backup_send": lambda: _send_backup_to_telegram(
        caption="Автоматический бэкап L2X Panel", scheduled=True,
    ),
    "restart_xray": _tg_restart_xray,
    "cpu": sysmon.cpu_percent, "client_by_tg": _tg_client_by_tg,
    "bind_tg": _tg_bind, "unlink_tg": _tg_unlink, "touch_tg_profile": _tg_touch_profile,
}, should_poll=_bot_should_poll)

# Low-traffic threshold for one-shot user Telegram alert (GB remaining)
TG_LOW_GB = 5.0


def _local_node_label() -> str:
    """Public host + role for admin Telegram footers (which panel ran the action)."""
    host = (public_host() or "").strip()
    try:
        role = "master" if nodes_mod.is_master(_load_store()) else "agent"
    except Exception:
        role = ""
    if host and role:
        return f"{host} · {role}"
    return host or role or ""


def _tg_admin(text: str, *, flag: str = "notify_changes", actor: str | None = None) -> None:
    """Send HTML message to Telegram admins if the given notify flag is on.

    Always append which local node (host · role) executed the action.
    For notify_changes / notify_nodes also append who (login) and from which IP
    when the action came from a panel session (or an inherited background job).
    """
    try:
        s = _bot_settings()
        if not s.get("enabled") or not s.get(flag, True):
            return
        node = _local_node_label()
        if node:
            text = f"{text}\n🖥 <code>{tgbot.escape(node)}</code>"
        if flag in ("notify_changes", "notify_nodes"):
            suffix = tgbot.get_actor() if actor is None else (actor or "")
            if suffix:
                text = f"{text}{suffix}"
        BOT.send(text)
    except Exception:
        pass


def _tg_change(summary: str, *details: str) -> None:
    """notify_changes with a clear «what changed» body + actor footer via _tg_admin.

    Runs off the request thread so Telegram latency does not block panel actions.
    Actor footer is captured on the caller thread (ContextVar).
    """
    lines = [summary]
    for d in details:
        d = str(d or "").strip()
        if d:
            lines.append(d)
    text = "\n".join(lines)
    actor = tgbot.get_actor()
    threading.Thread(
        target=_tg_admin, kwargs={"text": text, "flag": "notify_changes", "actor": actor}, daemon=True,
    ).start()


def _tg_node_events(events: list[dict]) -> None:
    """Notify admins about node online/offline/version (and similar) events."""
    for e in events or []:
        typ = e.get("type")
        name = tgbot.escape(e.get("name") or "node")
        domain = tgbot.escape(e.get("domain") or "")
        suffix = f"\n<code>{domain}</code>" if domain else ""
        if typ == "offline":
            reason = tgbot.escape(e.get("reason") or "unreachable")
            _tg_admin(
                f"🔴 Нода <b>{name}</b> отключилась{suffix}\n{reason}",
                flag="notify_nodes",
            )
        elif typ == "online":
            ver = tgbot.escape(e.get("version") or "")
            extra = f"\nv{ver}" if ver else ""
            _tg_admin(
                f"🟢 Нода <b>{name}</b> снова онлайн{suffix}{extra}",
                flag="notify_nodes",
            )
        elif typ == "version":
            _tg_admin(
                f"📦 Нода <b>{name}</b>: версия {tgbot.escape(e.get('from') or '?')} → "
                f"<b>{tgbot.escape(e.get('to') or '?')}</b>{suffix}",
                flag="notify_nodes",
            )
        elif typ == "change":
            _tg_admin(
                f"🖥 Нода <b>{name}</b>: {tgbot.escape(e.get('detail') or 'изменение')}{suffix}",
                flag="notify_nodes",
            )


def _notify_events(events: list[dict]) -> None:
    s = _bot_settings()
    for e in events:
        typ = e.get("type")
        if typ in (
            "expired", "quota_exceeded", "tag_exceeded", "auto_reset",
            "daily_exceeded", "daily_tag_exceeded", "renewed", "auto_disable", "auto_delete",
        ) and s.get("notify_quota"):
            text = {
                "expired": f"⏰ {e['email']}: срок истёк",
                "quota_exceeded": f"📛 {e['email']}: исчерпан общий лимит трафика",
                "tag_exceeded": f"📛 {e['email']}: исчерпан лимит на {e.get('tag')}",
                "daily_exceeded": f"📅 {e['email']}: исчерпан дневной лимит",
                "daily_tag_exceeded": f"📅 {e['email']}: дневной лимит на {e.get('tag')}",
                "auto_reset": f"🔄 {e['email']}: трафик сброшен по расписанию",
                "renewed": f"♻️ {e['email']}: новый период (+{e.get('days') or '?'} дн), трафик обнулён ({e.get('reason')})",
                "auto_disable": f"⛔️ {e['email']}: отключён ({e.get('reason')})",
                "auto_delete": f"🗑 {e['email']}: удалён ({e.get('reason')})",
            }.get(typ) or f"{e.get('email')}: {typ}"
            BOT.send(text)
            # Also notify the linked subscriber
            email = e.get("email")
            if email and typ in ("expired", "quota_exceeded", "auto_reset", "daily_exceeded", "renewed", "auto_disable"):
                store = _load_store()
                c = next((x for x in store.get("clients") or [] if x.get("email") == email), None)
                if c and c.get("tg_id"):
                    user_text = {
                        "expired": f"⏰ Срок вашей подписки <b>{email}</b> истёк.",
                        "quota_exceeded": f"📛 Трафик по подписке <b>{email}</b> исчерпан.",
                        "daily_exceeded": f"📅 Дневной лимит по подписке <b>{email}</b> исчерпан. Завтра лимит обновится.",
                        "auto_reset": f"🔄 Трафик по подписке <b>{email}</b> сброшен по расписанию.",
                        "renewed": f"♻️ Подписка <b>{email}</b> продлена, счётчик трафика обнулён.",
                        "auto_disable": f"⛔️ Подписка <b>{email}</b> отключена.",
                    }.get(typ)
                    if user_text:
                        BOT.send(user_text + "\n\n" + _client_summary(c), c["tg_id"])
        elif typ == "ip_ban" and s.get("notify_iplimit"):
            BOT.send(f"🚫 {e['email']}: превышен лимит IP, заблокирован {e['ip']}")


def _expiry_warnings(store: dict) -> None:
    """Daily expiry warnings (≤ N days) + one-shot low-traffic (<5 GB) to linked Telegram."""
    s = _bot_settings()
    if not s.get("enabled"):
        return
    days = _float(s.get("notify_expire_days"), 3)
    if days <= 0:
        days = 3
    today = datetime.now(timezone.utc).date().isoformat()
    pending: list[tuple[str | None, str]] = []  # (chat_id or None=admins, text)
    with STORE_LOCK:
        st = _load_store()
        changed = False
        for c in st.get("clients") or []:
            tg = str(c.get("tg_id") or "").strip()
            left = xray.days_left(c)
            # --- expiry: once per day while within window ---
            if left is not None and 0 < left <= days and c.get("tg_notify_expire_on") != today:
                rem = xray.client_remaining_gb(c)
                rem_txt = f"\nОсталось трафика: <b>{rem:.2f} ГБ</b>" if rem is not None else ""
                sent = False
                if tg:
                    pending.append((
                        tg,
                        f"⌛ Подписка <b>{c['email']}</b> истекает через <b>{left:.0f} дн</b>\n"
                        f"Дата: {fmt_dt(c.get('expire_at'))}{rem_txt}\n\n/status — актуальный статус",
                    ))
                    sent = True
                if s.get("notify_quota"):
                    pending.append((
                        None,
                        f"⌛ {c['email']}: срок истекает через {left:.0f} дн ({fmt_dt(c.get('expire_at'))})",
                    ))
                    sent = True
                if sent:
                    c["tg_notify_expire_on"] = today
                    _expiry_notified[c["email"]] = today
                    changed = True
            # --- low traffic: once until reset / top-up ---
            rem_gb = xray.client_remaining_gb(c)
            if rem_gb is not None and rem_gb < TG_LOW_GB:
                if not c.get("tg_notify_low_gb"):
                    sent = False
                    if tg:
                        pending.append((
                            tg,
                            f"📉 По подписке <b>{c['email']}</b> осталось меньше 5 ГБ\n"
                            f"Сейчас: <b>{rem_gb:.2f} ГБ</b>\n"
                            f"Срок: {fmt_dt(c.get('expire_at')) or 'бессрочно'}\n\n/status — актуальный статус",
                        ))
                        sent = True
                    if s.get("notify_quota"):
                        pending.append((None, f"📉 {c['email']}: осталось {rem_gb:.2f} ГБ (&lt; {TG_LOW_GB:g})"))
                        sent = True
                    if sent:
                        c["tg_notify_low_gb"] = True
                        changed = True
            elif rem_gb is not None and rem_gb >= TG_LOW_GB and c.get("tg_notify_low_gb"):
                c.pop("tg_notify_low_gb", None)
                changed = True
        if changed:
            _save_store(st)
    for chat, text in pending:
        BOT.send(text, chat)


def _watchdog_cycle() -> None:
    global ONLINE
    need_apply = False
    with STORE_LOCK:
        store = _load_store()
        events: list[dict] = []
        # traffic + quotas
        try:
            xray.harvest_traffic(store)
            OB_STATS.update(_ob_totals(store))
        except Exception:
            pass
        store["_events"] = []
        if xray.enforce_quotas(store):
            need_apply = True
        events.extend(store.pop("_events", []))
        # 3) online + IP limit
        online = xray.query_online()
        ONLINE = xray.update_online(store, online)
        ban_min = _int(store["settings"]["iplimit"].get("ban_minutes"), 30)
        for b in xray.enforce_ip_limits(store, ONLINE, ban_min):
            events.append({"type": "ip_ban", **b})
        if STORE_OK:
            _save_store(store)
        if need_apply and STORE_OK:
            _apply_xray(store, xray_only=True)
    if STORE_OK:
        _expiry_warnings(store)
        _notify_events(events)
        # Public direct_connect agents push traffic counters to master
        try:
            _agent_direct_connect_report(store)
        except Exception:
            pass


def _agent_direct_connect_report(store: dict | None = None) -> None:
    """Agent → master traffic/online for clients that dial this node directly."""
    store = store or _load_store()
    ns = (store.get("settings") or {}).get("nodes") or {}
    if (ns.get("role") or "") != "agent" or not ns.get("direct_connect"):
        return
    body = nodes_mod.collect_direct_connect_report(store)
    if not body:
        return
    master_url = (
        str(ns.get("upstream_master_url") or "").rstrip("/")
        or str(ns.get("master_pull_url") or "").rstrip("/")
        or str((ns.get("pull") or {}).get("master_url") or "").rstrip("/")
    )
    token = str(ns.get("agent_token") or "").strip()
    if not master_url or not token:
        return
    nodes_mod.report_request(master_url, token, body, timeout=15)


OUTBOUND_PROBE_INTERVAL = int(os.environ.get("L2XPANEL_OB_PROBE_SEC", "300"))


def _outbounds_probe_cycle() -> None:
    """Ping enabled custom/node outbounds; status + subscription gate use last_test."""
    store = _load_store()
    tags = [o["tag"] for o in (store.get("outbounds_custom") or []) if o.get("enabled", True) and o.get("tag")]
    if not tags:
        return
    results: dict[str, dict] = {}

    def _one(tag: str) -> tuple[str, dict]:
        try:
            return tag, xray.test_outbound(store, tag)
        except Exception as exc:  # noqa: BLE001
            return tag, {"ok": False, "error": str(exc), "ms": 0}

    # Parallel probes (cap workers) — serial Xray spawn was the slow path
    workers = max(1, min(6, len(tags)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for tag, res in pool.map(lambda t: _one(t), tags):
            results[tag] = res
    now = xray.now_utc().isoformat()
    with mutate() as st:
        for o in st.get("outbounds_custom") or []:
            tag = o.get("tag")
            if tag not in results:
                continue
            r = results[tag]
            o["last_test"] = {
                "ok": bool(r.get("ok")),
                "ms": int(r.get("ms") or 0),
                "at": now,
                "error": str(r.get("error") or "")[:300],
            }


def _outbounds_probe_loop() -> None:
    # First pass soon after startup apply finishes
    if _stop.wait(25):
        return
    while True:
        try:
            _outbounds_probe_cycle()
        except Exception:
            pass
        if _stop.wait(max(60, OUTBOUND_PROBE_INTERVAL)):
            return


def _tg_backup_cycle() -> None:
    """Scheduled Telegram backup: write zip → sendDocument → delete from disk."""
    try:
        if not nodes_mod.is_master(_load_store()):
            return
    except Exception:
        return
    s = _bot_settings()
    try:
        hours = float(s.get("backup_hours") or 0)
    except (TypeError, ValueError):
        hours = 0
    if hours <= 0 or not s.get("enabled") or not s.get("token"):
        return
    if not (s.get("admin_ids") or []):
        return
    try:
        last = float(s.get("last_backup_at") or 0)
    except (TypeError, ValueError):
        last = 0
    if last and time.time() - last < hours * 3600:
        return
    res = _send_backup_to_telegram(
        caption="Автоматический бэкап L2X Panel", scheduled=True,
    )
    if res.get("ok"):
        with mutate() as st:
            tg = st.setdefault("settings", {}).setdefault("tg", {})
            tg["last_backup_at"] = time.time()
            tg["last_backup_name"] = res.get("name") or ""
            tg["last_backup_ok"] = True
            tg["last_backup_error"] = ""
        _refresh_settings_cache()
    else:
        with mutate() as st:
            tg = st.setdefault("settings", {}).setdefault("tg", {})
            tg["last_backup_ok"] = False
            tg["last_backup_error"] = str(res.get("error") or "")[:300]
            # Soft bump so we don't hammer Telegram every minute on persistent failure
            if not last:
                tg["last_backup_at"] = time.time() - hours * 3600 + 600
        _refresh_settings_cache()


def _tg_backup_loop() -> None:
    if _stop.wait(45):
        return
    while True:
        try:
            _tg_backup_cycle()
        except Exception:
            pass
        if _stop.wait(60):
            return


def _watchdog_loop() -> None:
    while not _stop.wait(WATCHDOG_INTERVAL):
        try:
            _watchdog_cycle()
        except Exception:
            pass


# ================================================================ Xray core update check

XRAY_UPDATE_JOB: dict[str, str] = {}


def check_xray_update(force: bool = False) -> dict:
    """Compare installed Xray with GitHub; persist the result in store['xray_update_state']."""
    cfg = (_settings().get("xray_update") or {})
    latest = ops.xray_latest(bool(cfg.get("include_prerelease")))
    current = xray.xray_status().get("version") or ""
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    notify_tag = ""
    with mutate() as store:
        st = store.setdefault("xray_update_state", {})
        st.update({"checked_at": now, "current": current, "error": "" if latest.get("ok") else latest.get("error", "")})
        if latest.get("ok"):
            st.update({"latest": latest["tag"], "url": latest["url"], "published": latest["published"],
                       "prerelease": latest["prerelease"], "notes": latest["notes"]})
        available = bool(st.get("latest")) and ops.version_tuple(st["latest"]) > ops.version_tuple(current)
        st["available"] = available
        tag = str(st.get("latest") or "")
        if available and tag and st.get("tg_notified") != tag:
            st["dismissed"] = ""
            st["tg_notified"] = tag
            notify_tag = tag
        result = dict(st)
    if notify_tag:
        pre = " (pre-release)" if result.get("prerelease") else ""
        url = result.get("url") or ""
        link = f"\n{tgbot.escape(url)}" if url else ""
        _tg_admin(
            f"⬆️ <b>Xray</b>: доступна {tgbot.escape(notify_tag)}{pre}\n"
            f"Сейчас: <code>{tgbot.escape(current or '?')}</code>\n"
            f"Установка — Xray → Ядро.{link}",
            flag="notify_updates",
        )
    return result


def xray_update_banner() -> dict | None:
    st = _load_store().get("xray_update_state") or {}
    if not st.get("available") or st.get("dismissed") == st.get("latest"):
        return None
    return st


def _xray_update_loop() -> None:
    if _stop.wait(60):
        return
    while True:
        cfg = (_settings().get("xray_update") or {})
        hours = max(1, _int(cfg.get("interval_hours"), 12))
        if cfg.get("auto_check", True):
            try:
                check_xray_update()
            except Exception:
                pass
        if _stop.wait(hours * 3600):
            return


def _run_geo_update(*, reason: str = "manual") -> dict:
    """Download geoip/geosite (+ custom) and record state."""
    custom = (_settings().get("geo_custom") or [])
    res = ops.update_geo(custom)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with mutate() as store:
        st = store.setdefault("geo_update_state", {})
        st.update({
            "last_at": now,
            "last_ok": bool(res.get("ok")),
            "last_log": (res.get("log") or "")[:2000],
            "last_reason": reason,
            "missing": ops.geo_missing_core(),
        })
    return res


_EXT_GEO_TRIED: dict[str, float] = {}
_EXT_GEO_RETRY_SEC = 3600


def _known_geo_urls() -> dict[str, str]:
    urls = {f["name"]: f["url"] for p in ops.GEO_PACKS.values() for f in p.get("files") or []}
    for item in _settings().get("geo_custom") or []:
        if isinstance(item, dict) and item.get("name") and item.get("url"):
            name = str(item["name"])
            urls[name if name.endswith(".dat") else f"{name}.dat"] = str(item["url"])
    return urls


def _ensure_ext_geo(store: dict, *, force: bool = False) -> dict:
    """Start a background download for ext:*.dat files referenced by routes but missing on disk.

    Rules using them are skipped in the Xray config until the file exists; after download
    Xray is re-applied so they become active.
    """
    missing = xray.missing_ext_geo(store)
    if not missing:
        return {"missing": [], "started": [], "unknown": []}
    known = _known_geo_urls()
    now = time.time()
    want = [n for n in missing if n in known and (force or now - _EXT_GEO_TRIED.get(n, 0) > _EXT_GEO_RETRY_SEC)]
    unknown = [n for n in missing if n not in known]
    if not want or any(j.get("name") == "geo-ext" and j.get("status") == "running" for j in ops.JOBS.values()):
        return {"missing": missing, "started": [], "unknown": unknown}
    for n in want:
        _EXT_GEO_TRIED[n] = now

    def job():
        with mutate() as st:
            custom = st["settings"].setdefault("geo_custom", [])
            have = {str(x.get("name") or "") for x in custom if isinstance(x, dict)}
            for n in want:
                if n not in have:
                    custom.append({"name": n, "url": known[n]})
        _refresh_settings_cache()
        res = _run_geo_update(reason="ext-missing")
        _apply_xray(_load_store(), xray_only=True)
        return res

    ops.start_job("geo-ext", job)
    return {"missing": missing, "started": want, "unknown": unknown}


def _geo_update_loop() -> None:
    """Periodically refresh Loyalsoldier geoip/geosite (+ custom packs)."""
    if _stop.wait(120):
        return
    # First boot: if core files missing, fetch once
    try:
        if ops.geo_missing_core():
            _run_geo_update(reason="startup-missing")
    except Exception:
        pass
    while True:
        cfg = (_settings().get("geo_update") or {})
        hours = max(6, _int(cfg.get("interval_hours"), 168))
        if cfg.get("auto", True):
            try:
                _run_geo_update(reason="auto")
            except Exception:
                pass
        if _stop.wait(hours * 3600):
            return


# ================================================================ Panel self-update

PANEL_UPDATE_JOB: dict[str, str] = {}


def check_panel_update(force: bool = False) -> dict:
    latest = ops.panel_latest(False)
    current = panel_version()
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    notify_tag = ""
    with mutate() as store:
        st = store.setdefault("panel_update_state", {})
        st.update({"checked_at": now, "current": current, "error": "" if latest.get("ok") else latest.get("error", "")})
        if latest.get("ok"):
            st.update({"latest": latest["tag"], "url": latest.get("url") or "", "notes": latest.get("notes") or ""})
        available = bool(st.get("latest")) and ops.version_tuple(st["latest"]) > ops.version_tuple(current)
        st["available"] = available
        tag = str(st.get("latest") or "")
        if available and tag and st.get("tg_notified") != tag:
            st["dismissed"] = ""
            st["tg_notified"] = tag
            notify_tag = tag
        result = dict(st)
    if notify_tag:
        url = result.get("url") or ""
        link = f"\n{tgbot.escape(url)}" if url else ""
        notes = str(result.get("notes") or "").strip()
        # First line / short blurb from release notes
        blurb = ""
        if notes:
            line = notes.splitlines()[0].strip()[:180]
            if line:
                blurb = f"\n<i>{tgbot.escape(line)}</i>"
        _tg_admin(
            f"🧩 <b>Панель</b>: доступна {tgbot.escape(notify_tag)}\n"
            f"Сейчас: <code>{tgbot.escape(current or '?')}</code>\n"
            f"Обновление — Система / баннер на дашборде.{blurb}{link}",
            flag="notify_updates",
        )
    return result


def panel_update_banner() -> dict | None:
    st = _load_store().get("panel_update_state") or {}
    if not st.get("available") or st.get("dismissed") == st.get("latest"):
        return None
    return st


def _panel_update_loop() -> None:
    if _stop.wait(90):
        return
    while True:
        cfg = (_settings().get("panel_update") or {})
        hours = max(1, _int(cfg.get("interval_hours"), 12))
        if cfg.get("auto_check", True):
            try:
                check_panel_update()
            except Exception:
                pass
        if _stop.wait(hours * 3600):
            return


def _history_loop() -> None:
    sysmon.cpu_percent()
    try:
        OB_STATS.sample(_ob_totals(_load_store()))
    except Exception:
        pass
    while not _stop.wait(60):
        try:
            HISTORY.sample(online=len(ONLINE))
            OB_STATS.sample(_ob_totals(_load_store()))
        except Exception:
            pass


# ================================================================ extra uvicorn servers (sub / panel TLS)

class ServerThread:
    def __init__(self, name: str):
        self.name = name
        self.server = None
        self.thread: threading.Thread | None = None
        self.sig: tuple | None = None
        self.error = ""

    def ensure(self, target_app, enabled: bool, host: str, port: int, cert: str = "", key: str = "") -> None:
        import uvicorn

        sig = (enabled, host, port, cert, key)
        if sig == self.sig and (not enabled or (self.thread and self.thread.is_alive())):
            return
        self.stop()
        self.sig = sig
        self.error = ""
        if not enabled:
            return
        kwargs: dict[str, Any] = {"host": host, "port": int(port), "log_level": "warning", "lifespan": "off"}
        if cert and key and Path(cert).exists() and Path(key).exists():
            kwargs.update(ssl_certfile=cert, ssl_keyfile=key)
        self.server = uvicorn.Server(uvicorn.Config(target_app, **kwargs))

        def run():
            try:
                self.server.run()
            except BaseException as exc:  # noqa: BLE001
                self.error = str(exc)

        self.thread = threading.Thread(target=run, name=self.name, daemon=True)
        self.thread.start()
        if xray._run(["iptables", "-C", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"])["exit_code"] != 0:
            xray._run(["iptables", "-I", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"])

    def stop(self) -> None:
        if self.server:
            self.server.should_exit = True
        if self.thread:
            self.thread.join(timeout=5)
        self.server = None
        self.thread = None

    @property
    def running(self) -> bool:
        return bool(self.thread and self.thread.is_alive())


SUB_SERVER = ServerThread("l2x-sub")
PANEL_TLS = ServerThread("l2x-panel-tls")
sub_app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


def _sync_servers() -> None:
    # Clients only use :443 via nginx. Dedicated :2096 / :2053 listeners stay off.
    SUB_SERVER.ensure(sub_app, False, "127.0.0.1", 2096, "", "")
    PANEL_TLS.ensure(app, False, "127.0.0.1", 2053, "", "")


def _sync_xray_config() -> None:
    """Re-apply when the running Xray config was generated by an older panel version."""
    try:
        with STORE_LOCK:
            store = _load_store()
            for c in store.get("clients") or []:
                xray.ensure_client(c)
            wanted = xray.build_config(store)
        current = json.loads(xray.XRAY_CONFIG.read_text(encoding="utf-8")) if xray.XRAY_CONFIG.exists() else None
        if current != wanted:
            _apply_xray(_load_store())
            return
        # Xray unchanged, but the nginx front may be missing or stale (fresh update, renewed certificate)
        with STORE_LOCK:
            store = _load_store()
            staged = front.stage(store)
            if staged["ok"]:
                front.commit(staged)
            # iptables rules do not survive a reboot
            xray.ban_inbound_ports(store)
        _issue_front_certs(store)
    except Exception:
        pass


def _ensure_agent_sticky() -> None:
    """Keep Agent API on after restarts/updates/promote unless admin turned it off.

    Role (master|agent) is independent: master also keeps agent_enabled so
    /agent/manage, promote and health never hit «agent disabled».
    """
    try:
        with mutate() as store:
            ns = store.setdefault("settings", {}).setdefault("nodes", {})
            ns.setdefault("agent_manual_off", False)
            if not ns.get("agent_manual_off") and not ns.get("agent_enabled"):
                ns["agent_enabled"] = True
            # Token must exist for manage/apply even before first provision push
            if not ns.get("agent_token"):
                _set_agent_token(ns, secrets.token_urlsafe(32))
            elif not ns.get("agent_token_hash"):
                _set_agent_token(ns, ns["agent_token"])
    except Exception:
        pass


@app.on_event("startup")
def _startup():
    _ensure_admins()
    _ensure_base_path()
    _ensure_agent_sticky()
    _refresh_settings_cache()
    # BBR + TCP buffers — without this, upload on ~100ms RTT often caps at ~10–30 Mbps
    try:
        ops.ensure_network_perf()
    except Exception:
        pass
    # Free host :53 for MasterDNS: move local Pi-hole bind 53 → 5353
    def _bg_pihole_dns_port():
        try:
            doh_mod.ensure_pihole_dns_host_port(recreate=True)
            with mutate() as st:
                doh = st["settings"].setdefault("doh", {})
                doh_mod.migrate_doh_upstream_port(doh)
        except Exception:
            pass
    threading.Thread(target=_bg_pihole_dns_port, name="pihole-dns-port", daemon=True).start()
    for target in (_sync_xray_config, _watchdog_loop, _history_loop, _xray_update_loop, _panel_update_loop,
                   _geo_update_loop, _nodes_sync_loop, _pia_loop, _outbounds_probe_loop,
                   _agent_pull_loop, _tg_backup_loop):
        threading.Thread(target=target, daemon=True).start()
    BOT.start()
    _sync_servers()


@app.on_event("shutdown")
def _shutdown():
    _stop.set()
    BOT.stop()
    SUB_SERVER.stop()
    PANEL_TLS.stop()


# ================================================================ subscriptions

def sub_url(client: dict) -> str:
    """Subscription link — always on the public domain over HTTPS :443 (no other port)."""
    s = SETTINGS_CACHE.get("sub") or {}
    token = client.get("sub_token", "")
    path = (s.get("path") or "sub").strip("/") or "sub"
    return f"{public_https_base()}/{path}/{token}"


def _netloc(scheme: str, netloc: str) -> str:
    netloc = netloc.strip().lower()
    for sch, port in (("https", ":443"), ("http", ":80")):
        if scheme == sch and netloc.endswith(port):
            return netloc[: -len(port)]
    return netloc


def _sub_new_url(request: Request, client: dict) -> str:
    """Canonical subscription URL when the client fetched it from a different scheme/host/port."""
    target = sub_url(client)
    t = urlsplit(target)
    scheme = (request.headers.get("x-forwarded-proto") or request.url.scheme or "").split(",")[0].strip().lower()
    host = (request.headers.get("x-forwarded-host") or request.headers.get("host") or "").split(",")[0]
    if not host:
        return ""
    if (t.scheme, _netloc(t.scheme, t.netloc)) == (scheme, _netloc(scheme, host)):
        return ""
    return target


def _find_by_token(store: dict, token: str) -> dict | None:
    tok = str(token or "")
    if not tok:
        return None
    hit = next(
        (
            c for c in store["clients"]
            if c.get("sub_token") and secrets.compare_digest(str(c["sub_token"]), tok)
        ),
        None,
    )
    if hit:
        return hit
    # PasarGuard/Marzban: subscription URL token is HMAC/JWT signed, not stored as opaque id.
    secrets_list = list((store.get("settings") or {}).get("sub", {}).get("legacy_jwt_secrets") or [])
    if not secrets_list:
        return None
    payload = migrate_mod.parse_pasarguard_sub_token(tok, secrets_list)
    if not payload:
        return None
    clients = store.get("clients") or []
    username = str(payload.get("username") or "").strip()
    if username:
        email = username.lower()
        found = next((c for c in clients if str(c.get("email") or "").lower() == email), None)
        if found:
            return found
    uid = payload.get("user_id")
    if uid is not None:
        sid = str(uid)
        found = next(
            (c for c in clients if str(c.get("source_id") or "") == sid),
            None,
        )
        if found:
            return found
    return None


def _sub_response(request: Request, token: str) -> Response:
    store = _load_store()
    s = store["settings"]["sub"]
    if not s.get("enabled", True):
        return PlainTextResponse("subscriptions disabled", status_code=404)
    client = _find_by_token(store, token)
    if not client:
        return PlainTextResponse("not found", status_code=404)
    hwid.ensure(client)
    title = s.get("title") or f"{app_title()} · {client['email']}"
    headers = {
        "profile-title": "base64:" + base64.b64encode(title.encode()).decode(),
        "profile-update-interval": str(_int(s.get("update_hours"), 1) or 1),
        "subscription-userinfo": xray.subscription_userinfo(client),
        "cache-control": "no-store",
    }
    if s.get("support_url"):
        headers["support-url"] = s["support_url"]
    if s.get("announce"):
        headers["announce"] = "base64:" + base64.b64encode(s["announce"].encode()).decode()
    if s.get("happ_provider_id"):
        headers["providerid"] = s["happ_provider_id"]
    hwid_required = bool(s.get("hwid_required"))
    if hwid_required:
        headers["subscription-always-hwid-enable"] = "1"
    if s.get("migrate_url"):
        new_url = _sub_new_url(request, client)
        if new_url:
            headers["new-url"] = new_url
    fmt = (request.query_params.get("format") or "").lower()
    ua = (request.headers.get("user-agent") or "").lower()
    accept = request.headers.get("accept") or ""
    if not fmt:
        if "clash" in ua or "mihomo" in ua or "stash" in ua:
            fmt = "clash"
        elif "sing-box" in ua or "sfa" in ua or "sfi" in ua:
            fmt = "singbox"
        elif "text/html" in accept and s.get("show_page", True) and "mozilla" in ua:
            fmt = "html"
    eps = xray.client_endpoints(store, client, s.get("domain") or None)
    if fmt == "html":
        links = [P.endpoint_to_link(e) for e in eps]
        tg_s = store["settings"].get("tg") or {}
        tg_bot = ""
        try:
            tg_bot = BOT.username() if (tg_s.get("enabled") and tg_s.get("token")) else ""
        except Exception:
            tg_bot = ""
        # Bind works only with enabled bot + resolvable @username; section always shown
        tg_ready = bool(tg_s.get("enabled") and tg_s.get("token") and tg_bot)
        rem_gb = xray.client_remaining_gb(client)
        rem_bytes = xray.client_remaining_bytes(client)
        md = store["settings"].get("masterdns") or {}
        md_ok = bool(md.get("enabled") and md.get("domain"))
        md_link = masterdns_mod.share_link(md, name=str(client.get("email") or "MasterDNS")) if md_ok else ""
        return templates.TemplateResponse("sub_page.html", {
            "request": request, "client": client, "links": list(zip(eps, links)), "sub_link": sub_url(client),
            "status": xray.client_status(client), "used": xray.client_used_bytes(client), "settings": s,
            "app_name": app_title(), "qr_svg": qr_svg, "format_traffic": xray.format_traffic, "fmt_dt": fmt_dt,
            "days_left": xray.days_left(client), "theme": "dark", "bp": "", "hwid": hwid.status(client),
            "tg_ready": tg_ready, "tg_configured": bool(tg_s.get("enabled") and tg_s.get("token")),
            "tg_linked": bool(client.get("tg_id")),
            "tg_bot": tg_bot, "remaining_gb": rem_gb, "remaining_bytes": rem_bytes,
            "sub_token": client.get("sub_token") or token,
            "doh_url": doh_mod.public_url(store, client) if (store["settings"].get("doh") or {}).get("enabled") else "",
            "doh_in_tunnel": bool(client.get("doh_in_tunnel")),
            "masterdns_enabled": md_ok,
            "masterdns_zip": f"/sub/{token}/masterdns.zip" if md_ok else "",
            "masterdns_link": md_link,
            "masterdns_qr": qr_svg(md_link, 4) if md_link else "",
        }, headers={"cache-control": "no-store"})
    if not xray.client_access_ok(client):
        return PlainTextResponse(xray.client_status(client), status_code=403, headers=headers)
    # HWID gate applies only to machine-readable subscription bodies
    req_headers = {k.lower(): v for k, v in request.headers.items()}
    fallback = s.get("hwid_fallback") if s.get("hwid_fallback") in hwid.FALLBACK_MODES else "device"
    gate = hwid.gate(client, req_headers, register=True, required=hwid_required, fallback=fallback)
    headers.update(gate["headers"])
    if not gate["allowed"]:
        if gate["reason"] == "full":
            webhooks.fire(store["settings"], "client.hwid_full", {"email": client["email"], "limit": gate["limit"]})
        with STORE_LOCK:
            st = _load_store()
            c = _find_by_token(st, token)
            if c:
                c["hwids"] = client.get("hwids") or []
                _save_store(st)
        return PlainTextResponse("", status_code=404, headers=headers)
    if gate.get("recorded"):
        with STORE_LOCK:
            st = _load_store()
            c = _find_by_token(st, token)
            if c:
                c["hwids"] = client.get("hwids") or []
                _save_store(st)
    filename = re.sub(r"[^A-Za-z0-9_.-]", "_", client["email"])
    extras = {"fragment": s.get("json_fragment"), "noise": s.get("json_noise"), "mux": s.get("json_mux")}
    doh_cfg = store["settings"].get("doh") or {}
    doh_url = ""
    doh_tunnel = False
    if doh_cfg.get("enabled") and client.get("doh_enabled") and client.get("doh_in_tunnel"):
        doh_url = doh_mod.public_url(store, client)
        doh_tunnel = True
    if fmt == "json":
        body = json.dumps(
            [P.xray_client_config(e, extras, doh_url=doh_url, doh_in_tunnel=doh_tunnel)
             for e in eps if e["protocol"] != "wireguard"],
            ensure_ascii=False, indent=2,
        )
        return Response(body, media_type="application/json", headers=headers)
    if fmt == "clash":
        body = yaml.safe_dump(
            P.clash_config(eps, doh_url=doh_url, doh_in_tunnel=doh_tunnel),
            allow_unicode=True, sort_keys=False,
        )
        headers["content-disposition"] = f'attachment; filename="{filename}.yaml"'
        return Response(body, media_type="text/yaml; charset=utf-8", headers=headers)
    if fmt in ("singbox", "sing-box"):
        body = json.dumps(
            P.singbox_config(eps, doh_url=doh_url, doh_in_tunnel=doh_tunnel),
            ensure_ascii=False, indent=2,
        )
        return Response(body, media_type="application/json", headers=headers)
    body = "\n".join(P.endpoint_to_link(e) for e in eps)
    if fmt != "plain":
        body = base64.b64encode(body.encode()).decode()
    headers["content-disposition"] = f'attachment; filename="{filename}.txt"'
    return PlainTextResponse(body, headers=headers)


@app.get("/sub/{token}")
def sub_main(token: str, request: Request):
    return _sub_response(request, token)


@app.get("/api/sub/{token}")
@app.get("/api/sub/{token}/{client_type}")
def sub_remnawave_alias(token: str, request: Request, client_type: str = ""):
    """Remnawave-compatible subscription path so migrated shortUuid links keep working."""
    return _sub_response(request, token)


@app.post("/sub/{token}/tg/link")
def sub_tg_link(token: str, request: Request):
    """Start Telegram bind: create one-time token and redirect to t.me/bot?start=bind_…"""
    store = _load_store()
    s = store["settings"].get("sub") or {}
    if not s.get("enabled", True):
        return PlainTextResponse("subscriptions disabled", status_code=404)
    client = _find_by_token(store, token)
    if not client:
        return PlainTextResponse("not found", status_code=404)
    tg_s = store["settings"].get("tg") or {}
    if not (tg_s.get("enabled") and tg_s.get("token")):
        return PlainTextResponse("Telegram-бот выключен", status_code=400)
    deep = ""
    with mutate() as st:
        c = _find_by_token(st, token)
        if not c:
            return PlainTextResponse("not found", status_code=404)
        bind = secrets.token_urlsafe(18)
        c["tg_bind"] = {
            "token": bind,
            "exp": (datetime.now(timezone.utc) + timedelta(minutes=20)).isoformat(timespec="seconds"),
        }
        deep = BOT.deep_link(f"bind_{bind}")
    if not deep:
        return PlainTextResponse(
            "Не удалось получить username бота. Проверьте токен в Настройки → Telegram.",
            status_code=502,
        )
    return RedirectResponse(deep, status_code=303)


@app.post("/sub/{token}/tg/unlink")
def sub_tg_unlink(token: str, request: Request):
    store = _load_store()
    client = _find_by_token(store, token)
    if not client:
        return PlainTextResponse("not found", status_code=404)
    with mutate() as st:
        c = _find_by_token(st, token)
        if c:
            c["tg_id"] = ""
            c.pop("tg_bind", None)
    # Back to HTML sub page
    return RedirectResponse(sub_url(client) + "?format=html", status_code=303)


@sub_app.get("/{path}/{token}")
def sub_dedicated(path: str, token: str, request: Request):
    expected = ((SETTINGS_CACHE.get("sub") or {}).get("path") or "sub").strip("/")
    if path != expected:
        return PlainTextResponse("not found", status_code=404)
    return _sub_response(request, token)


@sub_app.post("/{path}/{token}/tg/link")
def sub_dedicated_tg_link(path: str, token: str, request: Request):
    expected = ((SETTINGS_CACHE.get("sub") or {}).get("path") or "sub").strip("/")
    if path != expected:
        return PlainTextResponse("not found", status_code=404)
    return sub_tg_link(token, request)


@sub_app.post("/{path}/{token}/tg/unlink")
def sub_dedicated_tg_unlink(path: str, token: str, request: Request):
    expected = ((SETTINGS_CACHE.get("sub") or {}).get("path") or "sub").strip("/")
    if path != expected:
        return PlainTextResponse("not found", status_code=404)
    return sub_tg_unlink(token, request)


def _health_detail_authorized(request: Request) -> bool:
    """Detail /health fields require a valid agent token (or panel session)."""
    if _user(request):
        return True
    auth = request.headers.get("authorization") or ""
    token = auth.removeprefix("Bearer ").strip() if auth.startswith("Bearer ") else ""
    if not token:
        return False
    store = _load_store()
    ns = (store.get("settings") or {}).get("nodes") or {}
    if _agent_token_ok(ns, token):
        return True
    return sec.any_token_eq(token, [n.get("token") or "" for n in (store.get("nodes") or [])])


@app.get("/health")
def health(request: Request):
    # Public surface is minimal; version/role/xray only with agent Bearer or session
    out = {"status": "ok" if STORE_OK else "degraded"}
    if not STORE_OK:
        out["store_ok"] = False
    if not _health_detail_authorized(request):
        return out
    store = _load_store()
    ns = (store.get("settings") or {}).get("nodes") or {}
    # Role is independent of agent_enabled (API may stay on for masters)
    role = "agent" if (ns.get("role") or "master") == "agent" else "master"
    out.update({
        "app": app_title(),
        "version": panel_version(),
        "role": role,
        "agent": role == "agent",
        "agent_enabled": bool(ns.get("agent_enabled")),
        "store_ok": STORE_OK,
        "time": datetime.now(timezone.utc).isoformat(),
    })
    if STORE_ERR:
        out["store_error"] = STORE_ERR[:200]
    try:
        xs = xray.xray_status()
        out["xray_version"] = xs.get("version") or ""
        out["xray_active"] = bool(xs.get("active"))
    except Exception:
        out["xray_version"] = ""
        out["xray_active"] = False
    if role == "agent":
        # Who this node treats as master (pull / promote redirect / reverse / last push)
        pull = ns.get("pull") if isinstance(ns.get("pull"), dict) else {}
        master_url = (
            str(pull.get("master_url") or "").rstrip("/")
            or str(ns.get("master_pull_url") or "").rstrip("/")
            or str(ns.get("upstream_master_url") or "").rstrip("/")
        )
        rb = ns.get("reverse_bridge") if isinstance(ns.get("reverse_bridge"), dict) else {}
        master_host = str(rb.get("master_host") or "")
        if not master_host and master_url:
            try:
                from urllib.parse import urlparse
                master_host = (urlparse(master_url).hostname or "") or ""
            except Exception:
                master_host = ""
        if master_url:
            out["master_url"] = master_url
        if master_host:
            out["master_host"] = master_host
        if rb:
            out["rv_conns"] = _reverse_conn_count(rb)
    return out


# ================================================================ auth pages

_login_fail: dict[str, list[float]] = {}


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return page(request, "login.html", error=None, totp_enabled=SETTINGS_CACHE.get("security", {}).get("totp_enabled"))


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...), code: str = Form("")):
    ip = _client_ip(request)
    # Dual limit: per-IP (trusted XFF) + direct peer, so spoofed XFF cannot wipe the bucket
    peer = str(request.client.host) if request.client else "?"
    if not sec.LOGIN_LIMITER.allow(f"login:{ip}", limit=8, window_sec=900):
        return page(request, "login.html", error="Слишком много попыток, подождите 15 минут",
                    totp_enabled=_settings()["security"].get("totp_enabled"), status_code=429)
    if not sec.LOGIN_LIMITER.allow(f"login-peer:{peer}", limit=20, window_sec=900):
        return page(request, "login.html", error="Слишком много попыток, подождите 15 минут",
                    totp_enabled=_settings()["security"].get("totp_enabled"), status_code=429)
    fails = [t_ for t_ in _login_fail.get(ip, []) if time.time() - t_ < 900]
    security_cfg = _settings()["security"]
    if len(fails) >= 8:
        return page(request, "login.html", error="Слишком много попыток, подождите 15 минут",
                    totp_enabled=security_cfg.get("totp_enabled"), status_code=429)
    ok = _check_credentials(username, password)
    if ok and security_cfg.get("totp_enabled") and not totp.verify(security_cfg.get("totp_secret") or "", code):
        ok = False
    if not ok:
        fails.append(time.time())
        _login_fail[ip] = fails
        if _bot_settings().get("notify_login"):
            BOT.send(f"⚠️ Неудачный вход в панель: {username} с {ip}")
        return page(request, "login.html", error="Неверный логин, пароль или код 2FA",
                    totp_enabled=security_cfg.get("totp_enabled"), status_code=401)
    _login_fail.pop(ip, None)
    hours = _float(_settings()["panel"].get("session_hours"), 12) or 12
    # Rotate session id material on login
    request.session.clear()
    sec.ensure_csrf(request.session)
    request.session["user"] = username
    request.session["exp"] = time.time() + hours * 3600
    if _bot_settings().get("notify_login"):
        BOT.send(f"🔐 Вход в панель: {username} с {ip}")
    webhooks.fire(_settings(), "login", {"user": username, "ip": ip})
    return go("/")


@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return go("/login")


# ================================================================ dashboard

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    if redir := _require(request):
        return redir
    store = _load_store()
    snap = sysmon.snapshot()
    clients = store["clients"]
    stats = {
        "clients": len(clients),
        "online": len(ONLINE),
        "active": sum(1 for c in clients if xray.client_status(c) == "active"),
        "expired": sum(1 for c in clients if xray.client_status(c) == "expired"),
        "limited": sum(1 for c in clients if xray.client_status(c) == "limited"),
        "inbounds": len(store["inbounds"]),
        "customs": len(store.get("outbounds_custom") or []),
        "up": sum(int(i["traffic"].get("up") or 0) for i in store["inbounds"]),
        "down": sum(int(i["traffic"].get("down") or 0) for i in store["inbounds"]),
    }
    top = sorted(clients, key=xray.client_used_bytes, reverse=True)[:5]
    return page(request, "dashboard.html", active="dashboard", snap=snap, xs=xray.xray_status(), stats=stats,
                top=top, online=ONLINE, panel_uptime=int(time.time() - STARTED_AT),
                sub_running=SUB_SERVER.running, bbr=ops.bbr_status(), ob=_outbound_usage(store))


def _sparkline(values: list[float], w: int = 120, h: int = 28) -> str:
    if len(values) < 2 or not any(values):
        return ""
    m = max(values)
    return " ".join(f"{w * i / (len(values) - 1):.1f},{h - 2 - (h - 4) * v / m:.1f}" for i, v in enumerate(values))


def _outbound_usage(store: dict) -> dict:
    """Per-outbound totals, share, current/avg/peak speed and 1h sparkline."""
    ot = store.get("outbound_traffic") or {}
    kinds: dict[str, tuple[str, str]] = {"direct": ("system", "active")}
    for o in store.get("outbounds_custom") or []:
        kinds[o["tag"]] = (o.get("kind") or "custom", "active" if o.get("enabled", True) else "disabled")
    tags = list(kinds) + [t_ for t_ in ot if t_ not in kinds]
    h1, h24 = OB_STATS.summary(60), OB_STATS.summary(1440)
    last = OB_STATS.points[-60:]
    rows = []
    for tag in tags:
        tr = ot.get(tag) or {}
        up, down = int(tr.get("up") or 0), int(tr.get("down") or 0)
        rate = OB_STATS.rates.get(tag) or {"up": 0, "down": 0}
        if not (up or down) and kinds.get(tag, ("", ""))[1] != "connected" and tag != "direct":
            continue
        kind, status = kinds.get(tag, ("system", "active"))
        rows.append({
            "tag": tag, "label": xray.outbound_label(store, tag), "kind": kind, "status": status,
            "up": up, "down": down, "total": up + down, "rate": rate,
            "h1": h1.get(tag) or {}, "h24": h24.get(tag) or {},
            "spark": _sparkline([sum((p["d"].get(tag) or (0, 0))) for p in last]),
        })
    grand = sum(r["total"] for r in rows) or 1
    for r in rows:
        r["share"] = round(100 * r["total"] / grand, 1)
    rows.sort(key=lambda r: r["total"], reverse=True)
    return {
        "rows": rows, "up": sum(r["up"] for r in rows), "down": sum(r["down"] for r in rows),
        "rate_up": sum(r["rate"]["up"] for r in rows), "rate_down": sum(r["rate"]["down"] for r in rows),
        "peak24": max((max(s["peak_up"], s["peak_down"]) for s in h24.values()), default=0),
        "points": len(OB_STATS.points),
    }


@app.get("/api/outbounds")
def api_outbounds(request: Request):
    if not _user(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    tag = request.query_params.get("tag") or None
    n = _int(request.query_params.get("n"), 60)
    return {"rates": OB_STATS.rates, "series": OB_STATS.series(tag, n)}


@app.get("/api/status")
def api_status(request: Request):
    if not _user(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    snap = sysmon.snapshot()
    return {**snap, "xray": xray.xray_status(), "online": len(ONLINE), "ob_rates": OB_STATS.rates}


@app.get("/api/history")
def api_history(request: Request):
    if not _user(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return HISTORY.points[-int(request.query_params.get("n") or 360):]


@app.post("/xray/control/{action}")
def xray_control(action: str, request: Request):
    if redir := _require(request):
        return redir
    r = ops.xray_control(action)
    flash(request, f"Xray {action}: {'ok' if r['ok'] else r['stderr']}", "info" if r["ok"] else "error")
    return go(request.query_params.get("next") or "/")


@app.post("/xray/apply")
def xray_apply(request: Request):
    if redir := _require(request):
        return redir
    result = _apply_xray(_load_store())
    flash(request, *(("Конфиг Xray применён", "info") if result.get("ok") else (f"Xray: {result.get('error')}", "error")))
    ref = request.headers.get("referer") or ""
    for path in ("/inbounds", "/clients", "/balancers", "/routing", "/schema", "/outbounds", "/xray", "/settings"):
        if path in ref:
            return go(path)
    return go("/")


# ================================================================ inbounds

def _inbound_form_to_model(form, ib: dict) -> str | None:
    proto = str(form.get("protocol") or ib.get("protocol") or "vless")
    if proto not in P.ALL_PROTOCOLS:
        return "Неизвестный протокол"
    if proto != ib.get("protocol"):
        ib["protocol"] = proto
        ib["settings"] = P.default_settings(proto)
    tag = str(form.get("tag") or "").strip()
    if not xray.TAG_RE.match(tag):
        return "Tag: латиница/цифры/._-"
    ib["tag"] = tag
    ib["remark"] = str(form.get("remark") or tag).strip()
    ib["enabled"] = form.get("enabled") == "1"
    ib["direct"] = form.get("direct") == "1"
    ib["listen"] = P.inbound_listen(ib)
    ib["port"] = _int(form.get("port"), 0)
    if reason := xray.port_forbidden_reason(ib["port"]):
        return reason
    share = str(form.get("share_host") or "").strip().lower()
    share = re.sub(r"^[a-z]+://", "", share).split("/", 1)[0].split(":", 1)[0]
    ib["share_host"] = share
    ib["total_gb"] = _float(form.get("total_gb"))
    ib["expire_at"] = local_to_iso(str(form.get("expire_at") or ""))
    raw_ob = str(form.get("outbound") or "").strip()
    # empty / none = no per-inbound route (avoids Direct loops); explicit tags keep working
    ib["outbound"] = "" if raw_ob.lower() in ("", "none", "-", "off") else raw_ob
    reset = str(form.get("traffic_reset") or "never")
    ib["traffic_reset"] = reset if reset in P.TRAFFIC_RESETS else "never"
    ext = []
    for line in str(form.get("external_proxies") or "").splitlines():
        parts = [p.strip() for p in line.split("|")]
        if not any(parts):
            continue
        parts += [""] * (4 - len(parts))
        addr, port_s, force, remark = parts[0], parts[1], parts[2], parts[3]
        if not addr:
            continue
        ext.append({
            "address": addr,
            "port": _int(port_s, 0) or None,
            "force_tls": force or "",
            "remark": remark,
        })
    ib["external_proxies"] = ext
    s = ib["settings"]
    if proto == "vless":
        s["flow"] = str(form.get("flow") or "")
        s["decryption"] = str(form.get("vless_decryption") or "none").strip() or "none"
        s["encryption"] = str(form.get("vless_encryption") or "none").strip() or "none"
        if form.get("vless_enc_clear") == "1":
            s["decryption"] = s["encryption"] = "none"
    elif proto == "shadowsocks":
        method = str(form.get("ss_method") or s.get("method"))
        if method != s.get("method") or form.get("ss_regen") == "1" or not s.get("password"):
            s["password"] = P.ss_server_key(method)
        s["method"] = method
        s["network"] = str(form.get("ss_network") or "tcp,udp")
    elif proto == "wireguard":
        s["mtu"] = _int(form.get("wg_mtu"), 1420)
        s["address_pool"] = str(form.get("wg_pool") or "10.66.0.0/24")
        if form.get("wg_regen") == "1":
            s["secret_key"] = s["public_key"] = ""
    elif proto in ("socks", "http"):
        s["auth"] = "noauth" if form.get("auth") == "noauth" else "password"
        s["udp"] = form.get("udp") == "1"
    elif proto == "dokodemo-door":
        s["address"] = str(form.get("dk_address") or "1.1.1.1")
        s["port"] = _int(form.get("dk_port"), 53)
        s["network"] = str(form.get("dk_network") or "tcp,udp")
        s["follow_redirect"] = form.get("dk_follow") == "1"
    elif proto == "hysteria":
        s["udp_idle"] = _int(form.get("hy_idle"), 60)
        s["brutal_up"] = str(form.get("hy_up") or "100mbps")
        s["brutal_down"] = str(form.get("hy_down") or "300mbps")
        s["masquerade_type"] = str(form.get("hy_mask") or "string")
        s["masquerade_content"] = str(form.get("hy_mask_content") or "OK")
        s["masquerade_url"] = str(form.get("hy_mask_url") or "")
        s["masquerade_dir"] = P.hysteria_masq_dir(form.get("hy_mask_dir"))
    st = ib["stream"]
    st["network"] = str(form.get("network") or "raw")
    st["security"] = str(form.get("security") or "none")
    if proto == "hysteria":
        st["network"], st["security"] = "hysteria", "tls"
    elif proto not in ("vless", "vmess", "trojan") or (st["security"] == "reality" and proto == "vmess"):
        st["security"] = "none" if proto not in ("vmess",) else "tls"
    if st["network"] not in P.NETWORKS:
        st["network"] = "raw"
    # Path transports behind nginx TLS use security=none; Reality/TLS → SNI passthrough
    if st["network"] in P.FRONT_HTTP_NETWORKS and st["security"] not in ("reality", "tls"):
        st["security"] = "none"
    if st["security"] == "reality" and proto not in ("vless", "trojan"):
        st["security"] = "tls" if proto == "vmess" else "none"
    if st["security"] == "reality" and st["network"] not in ("raw", "grpc", "xhttp"):
        # Reality only on tcp/grpc/xhttp
        st["network"] = "raw"
    # Browser fingerprint for all inbounds (share links / client uTLS)
    fp = str(form.get("client_fp") or form.get("tls_fp") or form.get("r_fp") or "firefox").strip()
    if fp not in P.FINGERPRINTS:
        fp = "firefox"
    st["fingerprint"] = fp
    st["accept_proxy_protocol"] = form.get("accept_proxy") == "1"
    st["raw"].update({
        "header": str(form.get("raw_header") or "none"),
        "http_host": str(form.get("raw_host") or ""),
        "http_path": str(form.get("raw_path") or "/"),
        "http_method": str(form.get("raw_method") or "GET"),
        "http_headers": str(form.get("raw_headers") or "").strip(),
        "accept_proxy_protocol": form.get("accept_proxy") == "1",
    })
    st["ws"].update({
        "path": str(form.get("ws_path") or "/"), "host": str(form.get("ws_host") or ""),
        "headers": str(form.get("ws_headers") or "").strip(),
        "heartbeat": max(0, _int(form.get("ws_heartbeat"), 0)),
        "accept_proxy_protocol": form.get("accept_proxy") == "1",
    })
    st["grpc"].update({
        "service_name": str(form.get("grpc_service") or "grpc"),
        "multi_mode": form.get("grpc_multi") == "1",
        "authority": str(form.get("grpc_authority") or ""),
        "idle_timeout": max(0, _int(form.get("grpc_idle"), 0)),
        "health_check_timeout": max(0, _int(form.get("grpc_health"), 0)),
        "permit_without_stream": form.get("grpc_permit") == "1",
        "initial_windows_size": max(0, _int(form.get("grpc_window"), 0)),
    })
    st["httpupgrade"].update({
        "path": str(form.get("hu_path") or "/"), "host": str(form.get("hu_host") or ""),
        "headers": str(form.get("hu_headers") or "").strip(),
        "accept_proxy_protocol": form.get("accept_proxy") == "1",
    })
    xmux = {
        "enabled": form.get("xh_xmux") == "1",
        "max_concurrency": str(form.get("xh_xmux_conc") or "16-32").strip() or "16-32",
        "max_connections": max(0, _int(form.get("xh_xmux_conn"), 0)),
        "c_max_reuse_times": str(form.get("xh_xmux_reuse") or "0").strip() or "0",
        "c_max_lifetime_ms": str(form.get("xh_xmux_life") or "0").strip() or "0",
        "h_max_request_times": str(form.get("xh_xmux_req") or "0").strip() or "0",
        "h_max_reusable_secs": str(form.get("xh_xmux_secs") or "0").strip() or "0",
    }
    st["xhttp"].update({
        "path": str(form.get("xh_path") or "/"), "host": str(form.get("xh_host") or ""),
        "mode": str(form.get("xh_mode") or "auto") if str(form.get("xh_mode") or "auto") in P.XH_MODES else "auto",
        "extra": str(form.get("xh_extra") or "").strip(),
        "headers": str(form.get("xh_headers") or "").strip(),
        "x_padding_bytes": str(form.get("xh_padding") or "100-1000").strip() or "100-1000",
        "sc_max_buffered_posts": max(0, _int(form.get("xh_buf_posts"), 30)),
        "sc_max_each_post_bytes": str(form.get("xh_max_post") or "1000000").strip() or "1000000",
        "sc_min_each_post_bytes": str(form.get("xh_min_post") or "1").strip() or "1",
        "sc_stream_up_server_secs": str(form.get("xh_stream_secs") or "20-80").strip() or "20-80",
        "sc_min_posts_interval_ms": max(0, _int(form.get("xh_post_interval"), 30)),
        "no_sse_header": form.get("xh_no_sse") == "1",
        "no_grpc_header": form.get("xh_no_grpc") == "1",
        "xmux": xmux,
    })
    st["kcp"].update({
        "mtu": _int(form.get("kcp_mtu"), 1350), "tti": _int(form.get("kcp_tti"), 20),
        "uplink": _int(form.get("kcp_up"), 5), "downlink": _int(form.get("kcp_down"), 20),
        "congestion": form.get("kcp_congestion") == "1",
        "header": str(form.get("kcp_header") or "none"),
        "seed": str(form.get("kcp_seed") or ""),
        "read_buffer": max(0, _int(form.get("kcp_rbuf"), 2)),
        "write_buffer": max(0, _int(form.get("kcp_wbuf"), 2)),
    })
    st["tls"].update({
        "server_name": str(form.get("tls_sni") or ""), "cert_file": str(form.get("tls_cert") or ""),
        "key_file": str(form.get("tls_key") or ""), "alpn": _split_lines(str(form.get("tls_alpn") or "h2,http/1.1")),
        "fingerprint": fp,
        "min_version": str(form.get("tls_min") or "1.2"),
        "max_version": str(form.get("tls_max") or "1.3"),
        "cipher_suites": str(form.get("tls_ciphers") or "").strip(),
        "allow_insecure": form.get("tls_insecure") == "1",
        "reject_unknown_sni": form.get("tls_reject_sni") == "1",
        "disable_system_root": form.get("tls_no_system") == "1",
        "ech_server_keys": str(form.get("tls_ech") or "").strip(),
    })
    r = st["reality"]
    if form.get("r_regen_sids") == "1":
        short_ids = xray.generate_short_ids()
    else:
        short_ids = [x for x in str(form.get("r_sids") or "").replace(",", " ").split() if x]
        if not short_ids:
            short_ids = [xray.generate_short_id()]
    r.update({
        "show": form.get("r_show") == "1",
        "dest": str(form.get("r_dest") or "www.cloudflare.com:443"),
        "xver": _int(form.get("r_xver"), 0),
        "server_names": _split_lines(str(form.get("r_names") or "")) or ["www.cloudflare.com"],
        "fingerprint": fp,
        "spider_x": str(form.get("r_spx") or "/"),
        "short_ids": short_ids,
        "private_key": str(form.get("r_priv") or "").strip(),
        "public_key": str(form.get("r_pub") or "").strip(),
        "max_time_diff": _int(form.get("r_max_diff"), 0),
        "min_client_ver": str(form.get("r_min_ver") or "").strip(),
        "max_client_ver": str(form.get("r_max_ver") or "").strip(),
        "mldsa65_seed": str(form.get("r_mldsa_seed") or "").strip(),
        "mldsa65_verify": str(form.get("r_mldsa_verify") or "").strip(),
    })
    if form.get("r_regen") == "1":
        r["private_key"] = r["public_key"] = ""
    if form.get("r_mldsa_clear") == "1":
        r["mldsa65_seed"] = r["mldsa65_verify"] = ""
    so = st.setdefault("sockopt", {})
    so.update({
        "enabled": form.get("sockopt_on") == "1",
        "tcp_fast_open": form.get("so_tfo") == "1",
        "tcp_keep_alive_interval": _int(form.get("so_kai"), 0),
        "tcp_keep_alive_idle": _int(form.get("so_kaidle"), 0),
        "tcp_user_timeout": _int(form.get("so_uto"), 0),
        "tcp_congestion": str(form.get("so_cong") or ""),
        "tcp_window_clamp": max(0, _int(form.get("so_clamp"), 0)),
        "tcp_max_seg": max(0, _int(form.get("so_mss"), 0)),
        "mark": _int(form.get("so_mark"), 0),
        "tproxy": str(form.get("so_tproxy") or ""),
        "domain_strategy": str(form.get("so_ds") or "AsIs"),
        "dialer_proxy": str(form.get("so_dialer") or "").strip(),
        "interface": str(form.get("so_iface") or "").strip(),
        "penetrate": form.get("so_penetrate") == "1",
        "tcp_mptcp": form.get("so_mptcp") == "1",
        "tcp_no_delay": form.get("so_nodelay") == "1",
        "v6only": form.get("so_v6only") == "1",
    })
    ib["sniffing"] = {
        "enabled": form.get("sniff") == "1",
        "dest": [d for d in ("http", "tls", "quic", "bittorrent", "fakedns") if form.get(f"sniff_{d}") == "1"] or ["http", "tls", "quic"],
        "route_only": form.get("sniff_route_only") == "1",
        "metadata_only": form.get("sniff_meta") == "1",
        "excluded_domains": _split_lines(str(form.get("sniff_excl") or "")),
    }
    fbs = []
    for line in str(form.get("fallbacks") or "").splitlines():
        parts = [p.strip() for p in line.split("|")]
        if not any(parts):
            continue
        parts += [""] * (5 - len(parts))
        fbs.append({"name": parts[0], "alpn": parts[1], "path": parts[2], "dest": parts[3], "xver": _int(parts[4])})
    ib["fallbacks"] = fbs
    ib["fallbacks_enabled"] = form.get("fallbacks_enabled") == "1"
    xray.ensure_inbound_keys(ib)
    mode = P.front_mode(ib)
    share = ib["share_host"] or front.public_domain({"settings": SETTINGS_CACHE}) or public_host()
    if mode == "http" and not front.is_domain(share):
        return f"Для {st['network']} задайте публичный домен в Настройках или URL share"
    if P.is_direct(ib) and ib["port"] in front.legacy_sub_ports({"settings": SETTINGS_CACHE}):
        return f"Порт {ib['port']} слушает nginx (старые ссылки подписок) — выберите другой"
    if mode == "raw" and not front.public_domain({"settings": SETTINGS_CACHE}):
        return "RAW на :443 работает через публичный домен — задайте его в Настройки → Панель"
    if mode == "http" and not front.PATH_RE.match(P.front_http_path(ib)):
        return "Путь/serviceName: только латиница, цифры и /_.~-"
    return None


@app.get("/inbounds", response_class=HTMLResponse)
async def inbounds_page(request: Request):
    if redir := _require(request):
        return redir
    store = _load_store()
    rows = []
    for ib in store["inbounds"]:
        n_clients = sum(1 for c in store["clients"] if ib in xray.client_inbounds(store, c))
        try:
            lint = inbound_lint.summarize(inbound_lint.inbound_issues(store, ib))
        except Exception:
            lint = {"errors": 0, "warnings": 0, "title": ""}
        rows.append({**ib, "n_clients": n_clients, "used": xray.inbound_used_bytes(ib),
                     "ok": xray.inbound_access_ok(ib), "lint": lint})
    xtest = await run_in_threadpool(inbound_lint.xray_dry_test, store)
    return page(request, "inbounds.html", active="inbounds", items=rows, store=store, xtest=xtest)


def _inbound_check_model(store: dict, form) -> tuple[dict, list[dict]]:
    """Parse the edit form onto a copy of the inbound; return (inbound, issues)."""
    ib_id = _int(form.get("id"))
    ib = None
    if ib_id:
        ib = deepcopy(xray.inbound_by_id(store, ib_id) or {}) or None
    if ib is None:
        ib = P.default_inbound(str(form.get("protocol") or "vless"))
        ib["id"] = ib_id or -1
    P.ensure_inbound_shape(ib)
    issues: list[dict] = []
    err = _inbound_form_to_model(form, ib)
    if err:
        issues.append({"field": "", "level": inbound_lint.ERROR, "msg": err})
    issues.extend(inbound_lint.inbound_issues(store, ib))
    return ib, issues


@app.post("/inbounds/check")
async def inbound_check(request: Request):
    """Live validation for the inbound form: field issues + dry `xray run -test`."""
    if redir := _require(request):
        return JSONResponse({"ok": False, "error": "auth"}, status_code=401)
    form = await request.form()
    store = deepcopy(_load_store())

    def _run() -> dict:
        ib, issues = _inbound_check_model(store, form)
        store["inbounds"] = [i for i in store.get("inbounds") or [] if i.get("id") != ib.get("id")] + [ib]
        xt = inbound_lint.xray_dry_test(store) if ib.get("enabled", True) else {"ok": None, "skipped": True, "error": "inbound выключен"}
        # Map Xray dry-test failure onto form fields so they highlight (not just a badge)
        if xt.get("ok") is False and xt.get("error"):
            known = {(i.get("field"), i.get("msg")) for i in issues}
            for mapped in inbound_lint.map_xray_error_fields(ib, str(xt.get("error") or "")):
                key = (mapped.get("field"), mapped.get("msg"))
                if key not in known:
                    issues.append(mapped)
                    known.add(key)
        return {"ok": True, "issues": issues, "summary": inbound_lint.summarize(issues), "xray": xt}

    return await run_in_threadpool(_run)


@app.get("/inbounds/new", response_class=HTMLResponse)
def inbound_new(request: Request):
    if redir := _require(request):
        return redir
    store = _load_store()
    proto = request.query_params.get("protocol") or "vless"
    port = xray.free_inbound_port(store)
    ib = P.default_inbound(proto, port, f"{proto}-{port}")
    xray.ensure_inbound_keys(ib)
    try:
        lint_issues = inbound_lint.inbound_issues(store, ib)
    except Exception:
        lint_issues = []
    return page(request, "inbound_edit.html", active="inbounds", ib=ib, is_new=True, store=store,
                outbounds=xray.all_outbound_tags(store), certs=ops.list_certs(), lint_issues=lint_issues)


@app.get("/inbounds/{ib_id}/edit", response_class=HTMLResponse)
def inbound_edit(ib_id: int, request: Request):
    if redir := _require(request):
        return redir
    store = _load_store()
    ib = xray.inbound_by_id(store, ib_id)
    if not ib:
        flash(request, "Inbound не найден", "error")
        return go("/inbounds")
    try:
        lint_issues = inbound_lint.inbound_issues(store, ib)
    except Exception:
        lint_issues = []
    return page(request, "inbound_edit.html", active="inbounds", ib=ib, is_new=False, store=store,
                outbounds=xray.all_outbound_tags(store), certs=ops.list_certs(), lint_issues=lint_issues)


@app.post("/inbounds/save")
async def inbound_save(request: Request):
    if redir := _require(request):
        return redir
    form = await request.form()
    ib_id = _int(form.get("id"))
    prop_note = ""
    with mutate() as store:
        if ib_id:
            ib = xray.inbound_by_id(store, ib_id)
            if not ib:
                flash(request, "Inbound не найден", "error")
                return go("/inbounds")
            old_tag = ib["tag"]
        else:
            ib = P.default_inbound(str(form.get("protocol") or "vless"))
            ib["id"] = max([i["id"] for i in store["inbounds"]] + [0]) + 1
            old_tag = None
        err = _inbound_form_to_model(form, ib)
        if not err and any(i is not ib and i["tag"] == ib["tag"] for i in store["inbounds"]):
            err = "Такой tag уже есть"
        if not err and any(i is not ib and int(i["port"]) == int(ib["port"]) for i in store["inbounds"]):
            err = f"Порт {ib['port']} уже занят другим inbound"
        if not err:
            others = [i for i in store["inbounds"] if i is not ib]
            problems = front.plan({"inbounds": [*others, ib]})["problems"]
            mine = [p for p in problems if p.startswith(f"{ib['tag']}:") or ib["share_host"] and p.startswith(ib["share_host"])]
            if mine:
                err = mine[0]
        if not err:
            bad = [i for i in inbound_lint.inbound_issues(store, ib) if i["level"] == inbound_lint.ERROR]
            if bad:
                err = "Исправьте: " + "; ".join(i["msg"] for i in bad[:3])
        if err:
            flash(request, err, "error")
            return go(f"/inbounds/{ib_id}/edit" if ib_id else "/inbounds/new")
        if not ib_id:
            store["inbounds"].append(ib)
            propagate = form.get("propagate_users") == "1"
            stats = xray.apply_tag_to_users(store, kind="inbound", tag=ib["tag"], propagate=propagate)
            if propagate:
                prop_note = f" · всем клиентам (+{stats['clients']} списков, +{stats['groups']} групп)"
            else:
                prop_note = f" · без автораздачи (зафиксировано {stats['clients']} клиентов / {stats['groups']} групп)"
        elif old_tag != ib["tag"]:
            for c in store["clients"]:
                c["inbounds"] = [ib["tag"] if x == old_tag else x for x in c.get("inbounds") or []]
    result = _apply_xray(_load_store())
    st = ib.get("stream") or {}
    act = "создан" if not ib_id else "обновлён"
    _tg_change(
        f"📥 Inbound <b>{tgbot.escape(ib['tag'])}</b> {act}",
        f"<code>{tgbot.escape(ib.get('protocol') or '')}</code> · "
        f"port <code>{tgbot.escape(str(ib.get('port') or ''))}</code> · "
        f"{tgbot.escape(st.get('network') or '')}/{tgbot.escape(st.get('security') or '')} · "
        f"fp=<code>{tgbot.escape(st.get('fingerprint') or '')}</code>",
    )
    flash(request, *_ok_msg(f"Inbound {ib['tag']} сохранён{prop_note}", result))
    return go("/inbounds")


@app.post("/inbounds/{ib_id}/{action}")
def inbound_action(ib_id: int, action: str, request: Request):
    if redir := _require(request):
        return redir
    what = ""
    tag = ""
    with mutate() as store:
        ib = xray.inbound_by_id(store, ib_id)
        if not ib:
            flash(request, "Inbound не найден", "error")
            return go("/inbounds")
        tag = ib["tag"]
        if action == "toggle":
            ib["enabled"] = not ib.get("enabled", True)
            what = "включён" if ib["enabled"] else "выключен"
        elif action == "reset":
            ib["traffic"].update({"up": 0, "down": 0})
            what = "сброс трафика"
        elif action == "delete":
            if len(store["inbounds"]) == 1:
                flash(request, "Нельзя удалить последний inbound", "error")
                return go("/inbounds")
            store["inbounds"] = [i for i in store["inbounds"] if i is not ib]
            for c in store["clients"]:
                c["inbounds"] = [x for x in c.get("inbounds") or [] if x != ib["tag"]]
            what = "удалён"
        elif action == "clone":
            clone = json.loads(json.dumps(ib))
            used = {i["port"] for i in store["inbounds"]}
            clone["port"] = next(p for p in range(int(ib["port"]) + 1, 65535) if p not in used)
            clone["id"] = max(i["id"] for i in store["inbounds"]) + 1
            clone["tag"] = f"{ib['tag']}-copy{clone['id']}"
            clone["remark"] = f"{ib.get('remark') or ib['tag']} (копия)"
            clone["traffic"] = {"up": 0, "down": 0, "last_up": 0, "last_down": 0}
            if clone["stream"].get("security") == "reality":
                clone["stream"]["reality"]["private_key"] = clone["stream"]["reality"]["public_key"] = ""
            xray.ensure_inbound_keys(clone)
            store["inbounds"].append(clone)
            # Clone is a new inbound — do not auto-spread to «all» clients
            xray.apply_tag_to_users(store, kind="inbound", tag=clone["tag"], propagate=False)
            what = f"клонирован → <b>{tgbot.escape(clone['tag'])}</b> port <code>{clone['port']}</code>"
        else:
            flash(request, "Неизвестное действие", "error")
            return go("/inbounds")
    result = _apply_xray(_load_store())
    _tg_change(f"📥 Inbound <b>{tgbot.escape(tag)}</b>: {what}")
    flash(request, *_ok_msg(f"Inbound {tag}: {action}", result))
    return go("/inbounds")


@app.get("/inbounds/{ib_id}/export")
def inbound_export(ib_id: int, request: Request):
    if redir := _require(request):
        return redir
    store = _load_store()
    cfg = xray.build_config(store)
    ib = xray.inbound_by_id(store, ib_id)
    built = next((i for i in cfg["inbounds"] if ib and i["tag"] == ib["tag"]), None)
    return JSONResponse(built or {"error": "inbound disabled or not found"})


# ================================================================ clients

def _client_row(store: dict, c: dict) -> dict:
    used = xray.client_used_bytes(c)
    limit = xray.gb_to_bytes(c.get("limit_gb"))
    daily_used = xray.client_daily_used_bytes(c)
    daily_limit = xray.gb_to_bytes(c.get("daily_limit_gb"))
    grp = xray.client_group(store, c)
    return {
        **c, "used": used, "limit_bytes": limit, "pct": min(100, int(100 * used / limit)) if limit else 0,
        "daily_used": daily_used, "daily_limit_bytes": daily_limit,
        "daily_pct": min(100, int(100 * daily_used / daily_limit)) if daily_limit else 0,
        "status": xray.client_status(c), "online_ips": ONLINE.get(c["email"], []), "sub_url": sub_url(c),
        "inbound_tags": [i["tag"] for i in xray.client_inbounds(store, c)], "days_left": xray.days_left(c),
        "group_name": (grp or {}).get("name") or "",
        "effective_outbound": xray.client_default_outbound(store, c),
    }


@app.get("/clients", response_class=HTMLResponse)
def clients_page(request: Request):
    if redir := _require(request):
        return redir
    store = _load_store()
    q = (request.query_params.get("q") or "").strip().lower()
    status = request.query_params.get("status") or ""
    rows = []
    for c in store["clients"]:
        row = _client_row(store, c)
        if q and q not in c["email"].lower() and q not in (c.get("comment") or "").lower() and q not in c["uuid"]:
            continue
        if status == "online" and not row["online_ips"]:
            continue
        if status and status != "online" and row["status"] != status:
            continue
        rows.append(row)
    return page(request, "clients.html", active="clients", items=rows, q=q, status=status, store=store,
                total=len(store["clients"]), groups=xray.ensure_groups(store))


def _client_form(form, store: dict, client: dict) -> str | None:
    email = str(form.get("email") or "").strip()
    if not xray.EMAIL_RE.match(email):
        return "Некорректный email (без пробелов и ~)"
    if email != client.get("email") and any(c["email"] == email for c in store["clients"]):
        return "Такой email уже есть"
    gid = str(form.get("group_id") or "").strip()
    if gid and not xray.get_group(store, gid):
        return "Неизвестная группа"
    allowed_obs = _allowed_outbounds(store)
    outbound = str(form.get("outbound") or "").strip()
    if gid:
        # Personal outbound optional while grouped (effective main link comes from group).
        if outbound and outbound not in allowed_obs:
            return f"Неизвестный outbound {outbound}"
        client["outbound"] = outbound  # empty = use group
    else:
        outbound = outbound or "direct"
        if outbound != xray.NONE_TAG and outbound not in allowed_obs:
            return f"Неизвестный outbound {outbound}"
        client["outbound"] = outbound
    old_email = client.get("email")
    client["email"] = email
    client["enabled"] = form.get("enabled", "1") == "1"
    client["comment"] = str(form.get("comment") or "").strip()
    client["tg_id"] = str(form.get("tg_id") or "").strip()
    client["tg_username"] = str(form.get("tg_username") or "").strip().lstrip("@")
    client["tg_first_name"] = str(form.get("tg_first_name") or "").strip()
    client["tg_last_name"] = str(form.get("tg_last_name") or "").strip()
    fio = str(form.get("tg_fio") or "").strip()
    if not fio:
        fio = " ".join(x for x in (client["tg_first_name"], client["tg_last_name"]) if x).strip()
    client["tg_fio"] = fio
    if not client["tg_id"]:
        client["tg_username"] = client["tg_first_name"] = client["tg_last_name"] = client["tg_fio"] = ""
    client["limit_gb"] = _float(form.get("limit_gb"))
    client["daily_limit_gb"] = _float(form.get("daily_limit_gb"))
    client["limit_ip"] = _int(form.get("limit_ip"))
    client["limit_hwid"] = _int(form.get("limit_hwid"))
    hwid.ensure(client)
    client["start_on_first_use"] = form.get("start_on_first_use") == "1"
    client["duration_days"] = _int(form.get("duration_days"))
    expire = local_to_iso(str(form.get("expire_at") or ""))
    days = _int(form.get("expire_days"))
    if client["start_on_first_use"]:
        expire = "" if xray.client_used_bytes(client) == 0 else (expire or client.get("expire_at") or "")
    elif days > 0 and not expire:
        expire = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat(timespec="seconds")
    if expire and not xray.parse_expire_at(expire):
        return "Некорректная дата"
    client["expire_at"] = expire
    period = str(form.get("reset_period") or "")
    if period not in xray.RESET_PERIODS:
        period = ""
    if period != client.get("reset_period"):
        client["next_reset"] = ""
    client["reset_period"] = period
    client["renew_on_reset"] = form.get("renew_on_reset") == "1"
    on_expire = str(form.get("on_expire") or "block")
    on_quota = str(form.get("on_quota") or "block")
    client["on_expire"] = on_expire if on_expire in xray.LIMIT_ACTIONS else "block"
    client["on_quota"] = on_quota if on_quota in xray.LIMIT_ACTIONS else "block"
    client["sub_enabled"] = form.get("sub_enabled", "1") == "1"
    doh_mod.ensure_client_doh(client)
    client["doh_enabled"] = form.get("doh_enabled") == "1"
    client["doh_in_tunnel"] = form.get("doh_in_tunnel") == "1"
    if form.get("doh_regen") == "1" or not client.get("doh_token"):
        client["doh_token"] = doh_mod.new_token()
    if client["doh_in_tunnel"] and not client["doh_enabled"]:
        client["doh_enabled"] = True
    client["group_id"] = gid
    known_ib = {i["tag"] for i in xray.client_capable_inbounds(store)}
    sel_ib = [str(x) for x in form.getlist("inbounds") if str(x) in known_ib]
    # Always save personal lists (optional extras when grouped; sole source without group).
    if form.get("ib_mode", "all") == "all" or set(sel_ib) == known_ib:
        client["inbounds"] = []
    else:
        client["inbounds"] = sel_ib
    known = {t_["tag"] for t_ in xray.selectable_outbound_tags(store)}
    selected = [str(x) for x in form.getlist("allowed_tags") if str(x) in known]
    if form.get("select_mode", "all") == "all":
        client["allowed_tags"] = []
    elif selected:
        client["allowed_tags"] = selected
    elif gid:
        client["allowed_tags"] = []
    elif client["outbound"] == xray.NONE_TAG:
        return "Выберите основную ссылку или хотя бы одно подключение"
    else:
        client["allowed_tags"] = [xray.NONE_TAG]  # only the main link
    limits = {}
    daily_limits = {}
    for tag in known:
        gb = _float(form.get(f"limit_{tag}"))
        if gb > 0:
            limits[tag] = gb
        dgb = _float(form.get(f"daily_limit_{tag}"))
        if dgb > 0:
            daily_limits[tag] = dgb
    client["outbound_limits"] = limits
    client["daily_outbound_limits"] = daily_limits
    if old_email and old_email != email:
        for r in store.get("routes") or []:
            if isinstance(r.get("user"), list):
                r["user"] = [email if u == old_email else u for u in r["user"]]
        by = client["traffic"].get("by_email") or {}
        client["traffic"]["by_email"] = {k.replace(old_email, email, 1) if k.startswith(old_email) else k: v for k, v in by.items()}
    return None


@app.get("/clients/new", response_class=HTMLResponse)
def client_new(request: Request):
    if redir := _require(request):
        return redir
    store = _load_store()
    c = xray.ensure_client({"email": "", "sub_token": ""})
    doh_mod.ensure_client_doh(c)
    return page(request, "client_edit.html", active="clients", c=c, row=None, is_new=True, store=store,
                tags=xray.selectable_outbound_tags(store), inbounds=xray.client_capable_inbounds(store),
                groups=xray.ensure_groups(store), group=None,
                eff_tags=[], eff_inbounds=[], eff_outbound="",
                hwids=[], bans=[], links=[], wg_confs=[], doh_url="",
                doh_system_on=bool((store["settings"].get("doh") or {}).get("enabled")))


MIGRATE_CACHE = DATA / "migrate_preview.json"


def _migrate_cache_save(users: list) -> None:
    payload = {
        "users": [u.to_dict() if hasattr(u, "to_dict") else u for u in users],
        "meta": dict(migrate_mod.LAST_SOURCE_META or {}),
    }
    MIGRATE_CACHE.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    try:
        os.chmod(MIGRATE_CACHE, 0o600)
    except OSError:
        pass


def _migrate_cache_load() -> list:
    if not MIGRATE_CACHE.exists():
        return []
    try:
        raw = json.loads(MIGRATE_CACHE.read_text(encoding="utf-8"))
    except ValueError:
        return []
    # New format: {users, meta}; old format: bare list
    if isinstance(raw, dict):
        meta = raw.get("meta") if isinstance(raw.get("meta"), dict) else {}
        if meta:
            migrate_mod.LAST_SOURCE_META = dict(meta)
        items = raw.get("users") or []
    else:
        items = raw or []
    out = []
    for item in items:
        if not isinstance(item, dict):
            continue
        extra = {}
        ibs = item.get("inbounds")
        if isinstance(ibs, list) and ibs:
            extra["inbounds"] = [str(t) for t in ibs if t]
        out.append(migrate_mod.NormalizedUser(
            email=str(item.get("email") or ""),
            uuid=str(item.get("uuid") or ""),
            password=str(item.get("password") or ""),
            sub_token=str(item.get("sub_token") or ""),
            limit_gb=float(item.get("limit_gb") or 0),
            expire_at=str(item.get("expire_at") or ""),
            enabled=bool(item.get("enabled", True)),
            comment=str(item.get("comment") or ""),
            tg_id=str(item.get("tg_id") or ""),
            up=int(item.get("up") or 0),
            down=int(item.get("down") or 0),
            source=str(item.get("source") or ""),
            source_id=str(item.get("source_id") or ""),
            extra=extra,
        ))
    return out


def _migrate_page(request: Request, *, preview=None, report=None, **form_kw):
    store = _load_store()
    inbounds = xray.client_capable_inbounds(store)
    meta = migrate_mod.LAST_SOURCE_META or {}
    return page(
        request, "migrate.html", active="migrate",
        sources=list(migrate_mod.SOURCE_LABELS.items()),
        inbounds=inbounds,
        preview=preview, report=report,
        source=form_kw.get("source") or "3xui",
        mode=form_kw.get("mode") or "api",
        url=form_kw.get("url") or "",
        username=form_kw.get("username") or "",
        web_base=form_kw.get("web_base") or "",
        insecure=bool(form_kw.get("insecure")),
        update_existing=bool(form_kw.get("update_existing")),
        selected_inbounds=form_kw.get("selected_inbounds"),
        legacy_path=form_kw.get("legacy_path") or "",
        legacy_port=form_kw.get("legacy_port") or "",
        apply_legacy=bool(form_kw.get("apply_legacy")),
        migrate_what=str(form_kw.get("migrate_what") or "all"),
        source_meta=meta,
    )


@app.get("/clients/migrate", response_class=HTMLResponse)
def clients_migrate_page(request: Request):
    if redir := _require(request):
        return redir
    return _migrate_page(request)


@app.post("/clients/migrate")
async def clients_migrate_run(request: Request):
    if redir := _require(request):
        return redir
    form = await request.form()
    source = str(form.get("source") or "3xui").strip().lower()
    mode = str(form.get("mode") or "api").strip().lower()
    action = str(form.get("action") or "preview").strip().lower()
    url = str(form.get("url") or "").strip()
    username = str(form.get("username") or "").strip()
    password = str(form.get("password") or "")
    api_token = str(form.get("api_token") or "").strip()
    web_base = str(form.get("web_base") or "").strip()
    insecure = form.get("insecure") == "1"
    update_existing = form.get("update_existing") == "1"
    migrate_what = str(form.get("migrate_what") or "all").strip().lower()
    if migrate_what not in ("clients", "outbounds", "routes", "all"):
        migrate_what = "all"
    want_clients = migrate_what in ("clients", "all")
    want_inbounds = migrate_what == "all"
    want_outbounds = migrate_what in ("outbounds", "all")
    want_routes = migrate_what in ("routes", "all")
    selected = [str(x) for x in form.getlist("inbounds")]
    legacy_path = re.sub(r"[^A-Za-z0-9_-]", "", str(form.get("legacy_path") or ""))
    legacy_port = _int(form.get("legacy_port"), 0)
    apply_legacy = form.get("apply_legacy") == "1"
    form_kw = {
        "source": source, "mode": mode, "url": url, "username": username,
        "web_base": web_base, "insecure": insecure, "update_existing": update_existing,
        "selected_inbounds": selected,
        "legacy_path": legacy_path, "legacy_port": legacy_port or "",
        "apply_legacy": apply_legacy,
        "migrate_what": migrate_what,
    }

    users: list = []
    err = ""
    try:
        if mode == "file":
            up = form.get("file")
            raw = b""
            filename = ""
            if up is not None and hasattr(up, "read"):
                raw = await up.read()
                filename = getattr(up, "filename", "") or ""
            if not raw and action == "import":
                users = _migrate_cache_load()
                meta_cached = migrate_mod.LAST_SOURCE_META or {}
                if not users and not meta_cached.get("structure"):
                    err = "Нет кэша preview — сначала нажмите «Проверить» с файлом"
            elif not raw:
                err = "Выберите файл бэкапа / экспорта"
            else:
                users = migrate_mod.parse_backup(source, raw, filename)
                _migrate_cache_save(users)
        else:
            if action == "import" and not (url or password or api_token or username):
                users = _migrate_cache_load()
            if not users:
                users = migrate_mod.fetch_api(
                    source, url,
                    username=username, password=password, api_token=api_token,
                    insecure=insecure, web_base=web_base,
                )
                _migrate_cache_save(users)
    except Exception as exc:  # noqa: BLE001
        err = str(exc)

    # Auto-fill path/port from x-ui backup settings when empty
    meta = migrate_mod.LAST_SOURCE_META or {}
    if not legacy_path and meta.get("path"):
        legacy_path = re.sub(r"[^A-Za-z0-9_-]", "", str(meta["path"]))
        form_kw["legacy_path"] = legacy_path
    if not legacy_port and meta.get("port"):
        legacy_port = int(meta["port"])
        form_kw["legacy_port"] = legacy_port

    if err:
        flash(request, err, "error")
        return _migrate_page(request, **form_kw)

    has_structure = bool(meta.get("structure")) and source == "3xui"
    need_structure = want_inbounds or want_outbounds or want_routes
    if want_clients and not users and not need_structure:
        flash(request, "Пользователи не найдены", "error")
        return _migrate_page(request, **form_kw)
    if need_structure and not has_structure and not (want_clients and users):
        flash(request, "В файле нет структуры X-UI (нужен полный x-ui.db / getDb)", "error")
        return _migrate_page(request, **form_kw)
    if not users and not has_structure:
        flash(request, "Пользователи не найдены", "error")
        return _migrate_page(request, **form_kw)

    store = _load_store()
    if action != "import":
        prev = migrate_mod.preview(store, users) if users else {
            "total": 0, "create": 0, "skip": 0, "conflicts": [], "sample": [],
        }
        hint = ""
        if legacy_path or legacy_port:
            hint = f" · старый path/port: /{legacy_path or '?'} :{legacy_port or '?'}"
        meta = migrate_mod.LAST_SOURCE_META or {}
        tb = int(meta.get("traffic_bytes") or 0)
        if want_clients and tb > 0:
            hint += f" · трафик в файле: {xray.format_traffic(tb)}"
        elif want_clients and source == "3xui":
            hint += " · трафик в файле: 0 (нужен полный x-ui.db с таблицей client_traffics, не JSON export)"
        if source == "3xui" and (meta.get("inbounds") or meta.get("outbounds") or meta.get("routes")):
            hint += (
                f" · структура: in {meta.get('inbounds', 0)}"
                f" / out {meta.get('outbounds', 0)}"
                f" / route {meta.get('routes', 0)}"
            )
        scope = {"clients": "только клиенты", "outbounds": "только outbound",
                 "routes": "только маршруты", "all": "всё"}.get(migrate_what, migrate_what)
        hint += f" · перенос: {scope}"
        jwt_n = len(meta.get("jwt_secrets") or [])
        if source == "pasarguard":
            if jwt_n:
                hint += f" · JWT secret найден ({jwt_n}) — старые ссылки подписки сохранятся"
            else:
                hint += " · JWT secret не найден в файле — для тех же ссылок нужен API или бэкап с таблицей jwt"
            if meta.get("port"):
                hint += f" · порт PasarGuard {meta['port']} ({'HTTPS' if meta.get('tls') else 'HTTP'})"
        if want_clients:
            flash(request, f"Найдено {prev['total']}: новых {prev['create']}, пропуск {prev['skip']}{hint}", "info")
        else:
            flash(request, f"Готово к импорту структуры{hint}", "info")
        return _migrate_page(request, preview=prev, **form_kw)

    with mutate() as st:
        meta = migrate_mod.LAST_SOURCE_META or {}
        struct_rep = {}
        if source == "3xui" and meta.get("structure") and (want_inbounds or want_outbounds or want_routes):
            struct_rep = migrate_mod.apply_3xui_structure(
                st, meta.get("structure"),
                restore_inbounds=want_inbounds,
                restore_outbounds=want_outbounds,
                restore_routes=want_routes,
            )
            if want_clients and not selected and struct_rep.get("inbound_tags"):
                selected = list(struct_rep["inbound_tags"])
        if want_clients:
            report = migrate_mod.apply(st, users, selected, update_existing=update_existing)
        else:
            report = {"created": 0, "updated": 0, "skipped": 0, "errors": [], "traffic_bytes": 0, "traffic_fixed": 0}
        if struct_rep:
            report["structure"] = struct_rep
        report["migrate_what"] = migrate_what
        sub = st["settings"].setdefault("sub", {})
        # PasarGuard file import: keep jwt secrets so already-issued client sub URLs keep working
        jwt_secrets = [str(s).strip() for s in (meta.get("jwt_secrets") or []) if str(s).strip()]
        if jwt_secrets and want_clients:
            existing = [str(s) for s in (sub.get("legacy_jwt_secrets") or []) if s]
            for s in jwt_secrets:
                if s not in existing:
                    existing.append(s)
            sub["legacy_jwt_secrets"] = existing
            report["jwt_secrets"] = len(jwt_secrets)
        if apply_legacy and want_clients and (legacy_path or legacy_port):
            if legacy_path:
                aliases = list(sub.get("path_aliases") or [])
                primary = (sub.get("path") or "sub").strip()
                if legacy_path != primary and legacy_path not in aliases:
                    aliases.append(legacy_path)
                sub["path_aliases"] = aliases
            if legacy_port and 1 <= legacy_port <= 65535 and legacy_port not in (80, 443):
                # PasarGuard served subscriptions over HTTPS (uvicorn SSL) — keep the scheme
                use_tls = bool(meta.get("tls")) and int(meta.get("port") or 0) == legacy_port
                key = "legacy_tls_ports" if use_tls else "legacy_ports"
                other = "legacy_ports" if use_tls else "legacy_tls_ports"
                ports = list(sub.get(key) or [])
                if legacy_port not in ports:
                    ports.append(legacy_port)
                sub[key] = ports
                sub[other] = [p for p in (sub.get(other) or []) if int(p) != legacy_port]
            report["legacy"] = {"path": legacy_path, "port": legacy_port,
                                "tls": bool(meta.get("tls")) and int(meta.get("port") or 0) == legacy_port}
    result = _apply_xray(_load_store())
    _tg_change(
        f"📦 Миграция <b>{migrate_mod.SOURCE_LABELS.get(source, source)}</b>: "
        f"создано {report.get('created', 0)}, обновлено {report.get('updated', 0)}, "
        f"пропуск {report.get('skipped', 0)}",
    )
    extra = ""
    if report.get("legacy"):
        extra = (f" · legacy /{report['legacy'].get('path')}:{report['legacy'].get('port')}"
                 f"{' https' if report['legacy'].get('tls') else ''}")
    if report.get("jwt_secrets"):
        extra += f" · JWT secrets {report['jwt_secrets']} (старые PG-ссылки активны)"
    sr = report.get("structure") or {}
    if sr:
        extra += (
            f" · in +{sr.get('inbounds_created', 0)}/~{sr.get('inbounds_updated', 0)}"
            f" · out +{sr.get('outbounds_created', 0)}/~{sr.get('outbounds_updated', 0)}"
            f" · route +{sr.get('routes_created', 0)}/~{sr.get('routes_updated', 0)}"
        )
    tb = int(report.get("traffic_bytes") or 0)
    tf = int(report.get("traffic_fixed") or 0)
    traffic_hint = ""
    if tb > 0:
        traffic_hint = f" · трафик {xray.format_traffic(tb)}"
    if tf:
        traffic_hint += f" (восстановлен у {tf})"
    flash(request, *_ok_msg(
        f"Импорт: +{report.get('created', 0)} / ~{report.get('updated', 0)} / skip {report.get('skipped', 0)}"
        f"{traffic_hint}{extra}",
        result,
    ))
    return _migrate_page(request, report=report, **form_kw)


@app.get("/clients/{email}/edit", response_class=HTMLResponse)
def client_edit(email: str, request: Request):
    if redir := _require(request):
        return redir
    store = _load_store()
    c = next((x for x in store["clients"] if x["email"] == email), None)
    if not c:
        flash(request, "Клиент не найден", "error")
        return go("/clients")
    tags = []
    for tg in xray.selectable_outbound_tags(store):
        tags.append({
            **tg,
            "used": xray.client_tag_used_bytes(c, tg["tag"]),
            "limit": (c.get("outbound_limits") or {}).get(tg["tag"], ""),
            "exceeded": xray.client_tag_exceeded(c, tg["tag"]),
            "daily_used": xray.client_daily_tag_used_bytes(c, tg["tag"]),
            "daily_limit": (c.get("daily_outbound_limits") or {}).get(tg["tag"], ""),
            "daily_exceeded": xray.client_daily_tag_exceeded(c, tg["tag"]),
        })
    bans = [b for b in store.get("ip_bans") or [] if b.get("email") == email]
    eps = xray.client_endpoints(store, c, store["settings"]["sub"].get("domain") or None)
    links = [(e, P.endpoint_to_link(e)) for e in eps]
    wg_confs = [(e, P.wireguard_conf(e)) for e in eps if e["protocol"] == "wireguard"]
    doh_mod.ensure_client_doh(c)
    grp = xray.client_group(store, c)
    md = masterdns_mod.ensure_settings(store)
    md_ok = bool(md.get("enabled") and md.get("domain"))
    md_link = masterdns_mod.share_link(md, name=str(c.get("email") or "MasterDNS")) if md_ok else ""
    return page(request, "client_edit.html", active="clients", c=c, row=_client_row(store, c), is_new=False,
                store=store, tags=tags, inbounds=xray.client_capable_inbounds(store), bans=bans, links=links,
                groups=xray.ensure_groups(store), group=grp,
                eff_tags=xray.client_effective_allowed_tags(store, c),
                eff_inbounds=xray.client_effective_inbounds(store, c),
                eff_outbound=xray.client_default_outbound(store, c) if grp else "",
                wg_confs=wg_confs, hwids=hwid.public_list(c),
                doh_url=doh_mod.public_url(store, c),
                doh_system_on=bool((store["settings"].get("doh") or {}).get("enabled")),
                masterdns_link=md_link,
                masterdns_qr=qr_svg(md_link, 4) if md_link else "")


@app.post("/clients/save")
async def client_save(request: Request):
    if redir := _require(request):
        return redir
    form = await request.form()
    original = str(form.get("original_email") or "")
    with mutate() as store:
        if original:
            c = next((x for x in store["clients"] if x["email"] == original), None)
            if not c:
                flash(request, "Клиент не найден", "error")
                return go("/clients")
        else:
            c = xray.ensure_client({"email": "", "sub_token": secrets.token_urlsafe(18)})
        err = _client_form(form, store, c)
        if err:
            flash(request, err, "error")
            return go(f"/clients/{original}/edit" if original else "/clients/new")
        if not original:
            store["clients"].append(c)
        xray.ensure_wg_peer(store, c)
    result = _apply_xray(_load_store(), xray_only=True)
    act = "создан" if not original else "обновлён"
    bits = []
    if c.get("limit_gb"):
        bits.append(f"лимит {c['limit_gb']} GB")
    if c.get("expire_at"):
        bits.append(f"до {str(c['expire_at'])[:10]}")
    if c.get("outbound"):
        bits.append(f"out=<code>{tgbot.escape(str(c['outbound']))}</code>")
    ibs = c.get("inbounds") or []
    if ibs:
        bits.append("inbounds: " + ", ".join(f"<code>{tgbot.escape(str(x))}</code>" for x in ibs[:8]))
    _tg_change(
        f"👤 Клиент <b>{tgbot.escape(c['email'])}</b> {act}",
        " · ".join(bits),
    )
    flash(request, *_ok_msg(f"Клиент {c['email']} сохранён", result))
    return go(f"/clients/{c['email']}/edit")


@app.post("/clients/bulk")
async def clients_bulk(request: Request):
    if redir := _require(request):
        return redir
    form = await request.form()
    action = str(form.get("action") or "")
    selected = [str(x) for x in form.getlist("sel")]
    msg = ""
    with mutate() as store:
        if action == "add":
            prefix = str(form.get("prefix") or "user").strip() or "user"
            count = max(1, min(_int(form.get("count"), 1), 500))
            start = _int(form.get("start"), 1)
            existing = {c["email"] for c in store["clients"]}
            created = 0
            n = start
            while created < count:
                email = f"{prefix}{n}"
                n += 1
                if email in existing:
                    continue
                bulk_gid = str(form.get("group_id") or "").strip()
                if bulk_gid and not xray.get_group(store, bulk_gid):
                    bulk_gid = ""
                c = xray.ensure_client({"email": email, "sub_token": secrets.token_urlsafe(18),
                                        "limit_gb": _float(form.get("limit_gb")),
                                        "outbound": str(form.get("outbound") or "direct"),
                                        "group_id": bulk_gid})
                days = _int(form.get("days"))
                if days and form.get("first_use") == "1":
                    c["start_on_first_use"], c["duration_days"] = True, days
                elif days:
                    c["expire_at"] = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat(timespec="seconds")
                store["clients"].append(c)
                xray.ensure_wg_peer(store, c)
                created += 1
            msg = f"Создано клиентов: {created}"
        elif action == "reset_all":
            for c in store["clients"]:
                xray.reset_client_traffic(c)
            msg = "Трафик всех клиентов сброшен"
        elif action == "delete_depleted":
            before = len(store["clients"])
            store["clients"] = [c for c in store["clients"] if xray.client_status(c) not in ("expired", "limited")]
            msg = f"Удалено исчерпанных: {before - len(store['clients'])}"
        elif action == "set_group" and selected:
            gid = str(form.get("group_id") or "").strip()
            if gid and not xray.get_group(store, gid):
                flash(request, "Неизвестная группа", "error")
                return go("/clients")
            for c in store["clients"]:
                if c["email"] in selected:
                    c["group_id"] = gid
            gname = (xray.get_group(store, gid) or {}).get("name") if gid else "без группы"
            msg = f"группа «{gname}»: {len(selected)}"
        elif action in ("enable", "disable", "delete", "reset") and selected:
            for c in list(store["clients"]):
                if c["email"] not in selected:
                    continue
                if action == "enable":
                    c["enabled"] = True
                elif action == "disable":
                    c["enabled"] = False
                elif action == "reset":
                    xray.reset_client_traffic(c)
                elif action == "delete":
                    store["clients"].remove(c)
            msg = f"{action}: {len(selected)}"
        else:
            flash(request, "Ничего не выбрано", "error")
            return go("/clients")
    result = _apply_xray(_load_store(), xray_only=True)
    _tg_change(f"👤 Клиенты (bulk): {tgbot.escape(msg)}")
    flash(request, *_ok_msg(msg, result))
    return go("/clients")


# ================================================================ client groups

def _group_form(form, store: dict, group: dict) -> str | None:
    name = str(form.get("name") or "").strip()
    if not name:
        return "Укажите название группы"
    group["name"] = name
    group["comment"] = str(form.get("comment") or "").strip()
    known = {t["tag"] for t in xray.selectable_outbound_tags(store)}
    selected = [str(x) for x in form.getlist("allowed_tags") if str(x) in known]
    group["allowed_tags"] = [] if form.get("select_mode", "all") == "all" or not selected else selected
    known_ib = {i["tag"] for i in xray.client_capable_inbounds(store)}
    sel_ib = [str(x) for x in form.getlist("inbounds") if str(x) in known_ib]
    group["inbounds"] = [] if form.get("ib_mode", "all") == "all" or set(sel_ib) == known_ib else sel_ib
    outbound = str(form.get("outbound") or "").strip()
    if outbound and outbound != "direct" and outbound not in known:
        return f"Неизвестный outbound {outbound}"
    group["outbound"] = outbound
    return None


@app.get("/groups", response_class=HTMLResponse)
def groups_page(request: Request):
    if redir := _require(request):
        return redir
    store = _load_store()
    groups = xray.ensure_groups(store)
    counts: dict[str, int] = {}
    for c in store.get("clients") or []:
        gid = str(c.get("group_id") or "")
        if gid:
            counts[gid] = counts.get(gid, 0) + 1
    rows = [{**g, "clients": counts.get(str(g.get("id") or ""), 0)} for g in groups]
    return page(
        request, "groups.html", active="groups", items=rows, store=store,
        tags=xray.selectable_outbound_tags(store),
        inbounds=xray.client_capable_inbounds(store),
    )


@app.get("/groups/new", response_class=HTMLResponse)
def groups_new(request: Request):
    if redir := _require(request):
        return redir
    store = _load_store()
    g = xray.new_group()
    return page(
        request, "group_edit.html", active="groups", g=g, is_new=True, store=store,
        tags=xray.selectable_outbound_tags(store),
        inbounds=xray.client_capable_inbounds(store),
        clients_count=0,
    )


@app.get("/groups/{gid}/edit", response_class=HTMLResponse)
def groups_edit(gid: str, request: Request):
    if redir := _require(request):
        return redir
    store = _load_store()
    g = xray.get_group(store, gid)
    if not g:
        flash(request, "Группа не найдена", "error")
        return go("/groups")
    n = sum(1 for c in store.get("clients") or [] if str(c.get("group_id") or "") == gid)
    return page(
        request, "group_edit.html", active="groups", g=g, is_new=False, store=store,
        tags=xray.selectable_outbound_tags(store),
        inbounds=xray.client_capable_inbounds(store),
        clients_count=n,
    )


@app.post("/groups/save")
async def groups_save(request: Request):
    if redir := _require(request):
        return redir
    form = await request.form()
    gid = str(form.get("id") or "").strip()
    with mutate(history_section="groups") as store:
        xray.ensure_groups(store)
        if gid:
            g = xray.get_group(store, gid)
            if not g:
                flash(request, "Группа не найдена", "error")
                return go("/groups")
        else:
            g = xray.new_group()
            store.setdefault("groups", []).append(g)
        err = _group_form(form, store, g)
        if err:
            flash(request, err, "error")
            return go(f"/groups/{g['id']}/edit" if gid else "/groups/new")
    result = _apply_xray(_load_store(), xray_only=True)
    _tg_change(f"👥 Группа <b>{tgbot.escape(g['name'])}</b> сохранена")
    flash(request, *_ok_msg(f"Группа «{g['name']}» сохранена", result))
    return go(f"/groups/{g['id']}/edit")


@app.post("/groups/{gid}/delete")
def groups_delete(gid: str, request: Request):
    if redir := _require(request):
        return redir
    with mutate(history_section="groups") as store:
        g = xray.get_group(store, gid)
        if not g:
            flash(request, "Группа не найдена", "error")
            return go("/groups")
        name = g.get("name") or gid
        store["groups"] = [x for x in store.get("groups") or [] if str(x.get("id")) != gid]
        for c in store.get("clients") or []:
            if str(c.get("group_id") or "") == gid:
                c["group_id"] = ""
    result = _apply_xray(_load_store(), xray_only=True)
    _tg_change(f"👥 Группа <b>{tgbot.escape(str(name))}</b> удалена")
    flash(request, *_ok_msg(f"Группа «{name}» удалена", result))
    return go("/groups")


@app.post("/clients/{email}/{action}")
def client_action(email: str, action: str, request: Request):
    if redir := _require(request):
        return redir
    what = ""
    with mutate() as store:
        c = next((x for x in store["clients"] if x["email"] == email), None)
        if not c:
            flash(request, "Клиент не найден", "error")
            return go("/clients")
        if action == "toggle":
            c["enabled"] = not c.get("enabled", True)
            what = "включён" if c["enabled"] else "выключен"
        elif action == "reset":
            xray.reset_client_traffic(c)
            what = "сброс трафика"
        elif action == "regen_sub":
            c["sub_token"] = secrets.token_urlsafe(18)
            what = "новый sub-token"
        elif action == "regen_uuid":
            c["uuid"] = str(uuid.uuid4())
            c["password"] = secrets.token_hex(12)
            what = "новый UUID/пароль"
        elif action == "delete":
            store["clients"].remove(c)
            for r in store.get("routes") or []:
                if isinstance(r.get("user"), list):
                    r["user"] = [u for u in r["user"] if u != email]
            webhooks.fire(store["settings"], "client.deleted", {"email": email})
            what = "удалён"
        elif action == "clear_ips":
            c["ips"] = {}
            what = "очищены IP"
        elif action == "clear_hwids":
            hwid.clear(c)
            what = "очищены HWID"
        else:
            flash(request, "Неизвестное действие", "error")
            return go("/clients")
    need_xray = action not in ("regen_sub", "clear_ips", "clear_hwids")
    result = _apply_xray(_load_store(), xray_only=True) if need_xray else {"ok": True}
    _tg_change(f"👤 Клиент <b>{tgbot.escape(email)}</b>: {what}")
    flash(request, *_ok_msg(f"{email}: {action}", result))
    if action == "delete":
        return go("/clients")
    nxt = request.query_params.get("next")
    return go(nxt or f"/clients/{email}/edit")


@app.get("/bans", response_class=HTMLResponse)
def bans_page(request: Request):
    if redir := _require(request):
        return redir
    store = _load_store()
    active, history = xray.ban_overview(store)
    ban_min = _int(store["settings"]["iplimit"].get("ban_minutes"), 30)
    return page(request, "bans.html", active="bans", bans=active, history=history, ban_minutes=ban_min)


@app.post("/ipban/{ip}/unban")
def ip_unban(ip: str, request: Request):
    if redir := _require(request):
        return redir
    with mutate() as store:
        xray.unban_ip(store, ip)
    flash(request, f"{ip} разблокирован", "info")
    return go(request.query_params.get("next") or "/bans")


@app.post("/ipban/{ip}/forget")
def ip_forget(ip: str, request: Request):
    if redir := _require(request):
        return redir
    with mutate() as store:
        xray.forget_ip(store, ip)
    flash(request, f"{ip}: счётчик банов сброшен", "info")
    return go("/bans")


@app.get("/clients/{email}/qr")
def client_qr(email: str, request: Request):
    if redir := _require(request):
        return redir
    store = _load_store()
    c = next((x for x in store["clients"] if x["email"] == email), None)
    if not c:
        return PlainTextResponse("not found", status_code=404)
    text = request.query_params.get("text") or sub_url(c)
    return Response(qr_svg(text, 6), media_type="image/svg+xml")


@app.get("/clients/{email}/wg.conf")
def client_wg_conf(email: str, request: Request):
    if redir := _require(request):
        return redir
    store = _load_store()
    c = next((x for x in store["clients"] if x["email"] == email), None)
    if not c:
        return PlainTextResponse("not found", status_code=404)
    eps = [e for e in xray.client_endpoints(store, c) if e["protocol"] == "wireguard"]
    if not eps:
        return PlainTextResponse("no wireguard inbound", status_code=404)
    return PlainTextResponse(P.wireguard_conf(eps[0]), headers={"content-disposition": f'attachment; filename="{email}.conf"'})


# ================================================================ PIA account + auto reconnect

def _pia_settings(store: dict | None = None) -> dict:
    s = (store or _load_store())["settings"].setdefault("pia", {})
    for k, v in default_settings()["pia"].items():
        s.setdefault(k, v)
    return s


def _pia_account_view(cfg: dict | None = None) -> dict:
    cfg = cfg or _pia_settings()
    user = str(cfg.get("username") or "").strip()
    hint = (user[:2] + "…" + user[-2:]) if len(user) > 4 else (user or "")
    return {
        "logged_in": bool(user and cfg.get("password_enc")),
        "username": user,
        "username_hint": hint,
        "has_token": bool(cfg.get("token_enc")),
        "token_expires_at": cfg.get("token_expires_at") or "",
        "auto_refresh": bool(cfg.get("auto_refresh", True)),
        "reconnect_hours": float(cfg.get("reconnect_hours") or 24),
        "last_refresh_at": cfg.get("last_refresh_at") or "",
        "last_reconnect_at": cfg.get("last_reconnect_at") or "",
        "last_error": cfg.get("last_error") or "",
        "last_ok_at": cfg.get("last_ok_at") or "",
    }


def _pia_save_credentials(store: dict, username: str, password: str, *, token: str = "",
                          token_ttl: int | None = None) -> None:
    import pia as pia_mod

    cfg = _pia_settings(store)
    user = (username or "").strip()
    if user:
        cfg["username"] = user
    if password:
        cfg["password_enc"] = _enc(password)
    if token:
        cfg["token_enc"] = _enc(token)
        ttl = int(token_ttl if token_ttl is not None else pia_mod.TOKEN_TTL_SECONDS)
        cfg["token_expires_at"] = (datetime.now(timezone.utc) + timedelta(seconds=ttl)).isoformat()
        cfg["last_refresh_at"] = datetime.now(timezone.utc).isoformat()
        cfg["last_error"] = ""
        cfg["last_ok_at"] = cfg["last_refresh_at"]


def _pia_clear_account(store: dict) -> None:
    cfg = _pia_settings(store)
    cfg["username"] = ""
    cfg["password_enc"] = ""
    cfg["token_enc"] = ""
    cfg["token_expires_at"] = ""
    cfg["last_refresh_at"] = ""
    cfg["last_reconnect_at"] = ""
    cfg["last_ok_at"] = ""
    cfg["last_error"] = ""


def _pia_creds(store: dict | None = None) -> tuple[str, str]:
    cfg = _pia_settings(store)
    user = str(cfg.get("username") or "").strip()
    pwd = ""
    if cfg.get("password_enc"):
        try:
            pwd = _dec(cfg["password_enc"])
        except Exception:
            pwd = ""
    return user, pwd


def _pia_token_valid(cfg: dict) -> bool:
    import pia as pia_mod

    if not cfg.get("token_enc"):
        return False
    exp_raw = cfg.get("token_expires_at") or ""
    if not exp_raw:
        return False
    try:
        exp = datetime.fromisoformat(exp_raw.replace("Z", "+00:00"))
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
    except Exception:
        return False
    return datetime.now(timezone.utc) + timedelta(seconds=pia_mod.TOKEN_REFRESH_SKEW_SECONDS) < exp


def _pia_ensure_token(store: dict, *, force: bool = False) -> dict:
    """Return {ok, token} using cached token or re-login with stored credentials."""
    cfg = _pia_settings(store)
    user, pwd = _pia_creds(store)
    if not force and _pia_token_valid(cfg):
        try:
            return {"ok": True, "token": _dec(cfg["token_enc"]), "refreshed": False}
        except Exception:
            pass
    if not user or not pwd:
        return {"ok": False, "error": "PIA: нет сохранённого логина/пароля"}
    auth = ops.pia_authenticate(user, pwd)
    if not auth.get("ok"):
        cfg["last_error"] = str(auth.get("error") or "auth failed")
        return auth
    _pia_save_credentials(store, user, pwd, token=auth["token"])
    return {"ok": True, "token": auth["token"], "refreshed": True}


def _pia_outbound_meta(o: dict) -> tuple[str, str]:
    """(region_id, hostname) for a stored PIA outbound."""
    cfg = o.get("config") or {}
    host = str(o.get("pia_hostname") or cfg.get("piaHostname") or "").strip()
    region = str(o.get("pia_region") or "").strip()
    if not host:
        # tag: pia-<region>-<hostlabel>
        parts = str(o.get("tag") or "").split("-")
        if len(parts) >= 3 and parts[0] == "pia":
            region = region or "-".join(parts[1:-1])
            host = parts[-1]
    return region, host


def _pia_is_outbound(o: dict) -> bool:
    return o.get("kind") == "pia" or str(o.get("tag") or "").startswith("pia-")


def _pia_due_for_reconnect(o: dict, hours: float) -> bool:
    if hours <= 0:
        return True
    last = o.get("pia_reconnected_at") or ""
    if not last:
        return True
    try:
        ts = datetime.fromisoformat(str(last).replace("Z", "+00:00"))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) - ts >= timedelta(hours=hours)
    except Exception:
        return True


def _pia_reconnect_one(tag: str, *, token: str | None = None) -> dict:
    """Re-register WireGuard for a single PIA outbound, apply Xray, keep others untouched.

    Order matters when several PIA exits exist: call one-by-one so at least one
    peer stays on the previous keys while another is being rotated.
    """
    import copy

    with mutate() as store:
        o = next((x for x in store.get("outbounds_custom") or [] if x.get("tag") == tag), None)
        if not o or not _pia_is_outbound(o):
            return {"ok": False, "error": f"{tag}: не PIA outbound"}
        tok = {"ok": True, "token": token} if token else _pia_ensure_token(store, force=False)
        if not tok.get("ok"):
            return tok
        use_token = tok["token"]
        region, host = _pia_outbound_meta(o)
        if not host and not region:
            return {"ok": False, "error": f"{tag}: нет hostname"}
        prev = copy.deepcopy(o.get("config") or {})
        res = ops.pia_provision(use_token, region_id=region, hostname=host)
        if not res.get("ok") and "token" in str(res.get("error") or "").lower():
            tok2 = _pia_ensure_token(store, force=True)
            if not tok2.get("ok"):
                return tok2
            use_token = tok2["token"]
            res = ops.pia_provision(use_token, region_id=region, hostname=host)
        if not res.get("ok"):
            _pia_settings(store)["last_error"] = f"{tag}: {res.get('error')}"
            return {"ok": False, "error": f"{tag}: {res.get('error')}", "token": use_token}
        cfg_ob = res["config"]
        cfg_ob.pop("tag", None)
        # Keep dialerProxy chain across peer rotation
        via_prev = _outbound_via(prev)
        if via_prev:
            _apply_outbound_wrap(cfg_ob, wrap_on=True, wrap_via=via_prev, self_tag=tag)
        o["config"] = cfg_ob
        o["info"] = res.get("info") or o.get("info")
        o["pia_hostname"] = res.get("hostname") or host
        o["pia_region"] = res.get("region_id") or region
        o["kind"] = "pia"
        o["pia_reconnected_at"] = datetime.now(timezone.utc).isoformat()
        o.pop("last_test", None)
    xr = _apply_xray(_load_store(), xray_only=True)
    if not xr.get("ok"):
        with mutate() as store:
            o = next((x for x in store.get("outbounds_custom") or [] if x.get("tag") == tag), None)
            if o:
                o["config"] = prev
                o.pop("pia_reconnected_at", None)
            _pia_settings(store)["last_error"] = f"{tag}: Xray {xr.get('error')}"
        _apply_xray(_load_store(), xray_only=True)
        return {"ok": False, "error": f"{tag}: Xray отклонил конфиг — откат", "token": use_token}
    # brief settle so this peer is up before rotating the next one
    time.sleep(2)
    probe = xray.test_outbound(_load_store(), tag)
    with mutate() as store:
        o = next((x for x in store.get("outbounds_custom") or [] if x.get("tag") == tag), None)
        if o:
            o["last_test"] = {"ok": probe.get("ok"), "ms": probe.get("ms"), "at": xray.now_utc().isoformat()}
        cfg = _pia_settings(store)
        if probe.get("ok"):
            cfg["last_ok_at"] = datetime.now(timezone.utc).isoformat()
            if cfg.get("last_error", "").startswith(f"{tag}:"):
                cfg["last_error"] = ""
        else:
            # Keep new keys (old peer may already be replaced on PIA side); others still online.
            cfg["last_error"] = f"{tag}: reconnect ok, probe fail: {probe.get('error') or ''}"[:500]
    return {"ok": True, "tag": tag, "probe_ok": bool(probe.get("ok")), "token": use_token,
            "ms": probe.get("ms")}


def _pia_reconnect_outbounds(*, force: bool = False, only_tag: str | None = None) -> dict:
    """Rotate PIA WireGuard peers one-by-one (apply after each) so one exit stays live."""
    store = _load_store()
    cfg = _pia_settings(store)
    if not cfg.get("auto_refresh", True) and not force:
        return {"ok": True, "skipped": True, "reason": "auto_refresh off"}
    hours = float(cfg.get("reconnect_hours") or 24)
    targets: list[str] = []
    for o in store.get("outbounds_custom") or []:
        if not _pia_is_outbound(o):
            continue
        if not o.get("enabled", True):
            continue
        tag = str(o.get("tag") or "")
        if only_tag and tag != only_tag:
            continue
        if only_tag or force or _pia_due_for_reconnect(o, hours):
            targets.append(tag)
    if not targets:
        with mutate() as st:
            tok = _pia_ensure_token(st, force=False)
        return {"ok": bool(tok.get("ok")), "skipped": True, "updated": 0, "token_ok": tok.get("ok")}

    with mutate() as st:
        tok = _pia_ensure_token(st, force=force)
    if not tok.get("ok"):
        return tok
    token = tok["token"]
    updated: list[str] = []
    errors: list[str] = []
    for i, tag in enumerate(targets):
        res = _pia_reconnect_one(tag, token=token)
        if res.get("token"):
            token = res["token"]
        if res.get("ok"):
            updated.append(tag)
        else:
            errors.append(str(res.get("error") or tag))
            # continue with remaining — other exits stay on previous keys
        # pause between rotations so traffic can stay on untouched peers
        if i + 1 < len(targets):
            time.sleep(3)
    with mutate() as st:
        cfg = _pia_settings(st)
        if updated:
            cfg["last_reconnect_at"] = datetime.now(timezone.utc).isoformat()
            cfg["last_ok_at"] = cfg["last_reconnect_at"]
        if errors:
            cfg["last_error"] = "; ".join(errors)[:500]
        elif updated:
            cfg["last_error"] = ""
    return {"ok": bool(updated) or not errors, "updated": len(updated), "tags": updated, "errors": errors}


def _pia_loop() -> None:
    """Keep PIA token fresh; rotate due WireGuard peers one-at-a-time (never all at once)."""
    while not _stop.wait(900):  # 15 min
        try:
            store = _load_store()
            cfg = _pia_settings(store)
            if not cfg.get("username") or not cfg.get("password_enc"):
                continue
            if not cfg.get("auto_refresh", True):
                continue
            hours = float(cfg.get("reconnect_hours") or 24)
            due = [
                o.get("tag") for o in (store.get("outbounds_custom") or [])
                if _pia_is_outbound(o) and o.get("enabled", True) and _pia_due_for_reconnect(o, hours)
            ]
            if due:
                # One outbound per tick when several are due — keeps others online
                res = _pia_reconnect_outbounds(force=True, only_tag=due[0])
                if res.get("updated"):
                    BOT.send(f"PIA reconnect (по очереди): {', '.join(res.get('tags') or [])}"
                             + (f" · осталось {len(due) - 1}" if len(due) > 1 else ""))
                elif not res.get("ok") and (res.get("error") or res.get("errors")):
                    BOT.send(f"PIA auto: {res.get('error') or res.get('errors')}")
            else:
                with mutate() as st:
                    res = _pia_ensure_token(st, force=False)
                if isinstance(res, dict) and not res.get("ok") and res.get("error"):
                    BOT.send(f"PIA auto: {res.get('error')}")
        except Exception:
            pass


# ================================================================ outbounds

@app.get("/outbounds", response_class=HTMLResponse)
def outbounds_page(request: Request):
    if redir := _require(request):
        return redir
    store = _load_store()
    ot = store.get("outbound_traffic") or {}
    rows = [{"tag": "direct", "kind": "system", "label": "🏠 Direct", "enabled": True, "status": "active"}]
    hide_unhealthy = xray.sub_health_settings(store)["hide_unhealthy"]
    for o in store["outbounds_custom"]:
        status = xray.custom_outbound_status(o)
        in_sub = bool(o.get("in_sub", True))
        live = status == "connected" or not hide_unhealthy
        cfg = o.get("config") or {}
        rows.append({
            "tag": o["tag"], "kind": o.get("kind") or "custom",
            "label": xray.outbound_label(store, o["tag"]),
            "enabled": o.get("enabled", True), "status": status,
            "info": o.get("info") or cfg.get("protocol"),
            "via": _outbound_via(cfg),
            "in_sub": in_sub,
            "sub_live": in_sub and live,
            "custom": True, "last_test": o.get("last_test"),
        })
    for r in rows:
        tr = ot.get(r["tag"]) or {}
        r["up"], r["down"] = int(tr.get("up") or 0), int(tr.get("down") or 0)
        r.setdefault("via", "")
    custom = {o["tag"]: {"config": o.get("config") or {}, "remark": o.get("remark") or "", "country": o.get("country") or ""}
              for o in store["outbounds_custom"]}
    return page(request, "outbounds.html", active="outbounds", items=rows, nord_countries=[], custom=custom,
                dialer_tags=[r["tag"] for r in rows], ss_methods=P.SS_METHODS, fingerprints=P.FINGERPRINTS,
                pia=_pia_account_view())


@app.post("/outbounds/parse")
async def outbound_parse(request: Request):
    if not _user(request):
        return JSONResponse({"ok": False, "error": "auth"}, status_code=401)
    form = await request.form()
    try:
        ep = P.link_to_endpoint(str(form.get("link") or ""))
        config = P.endpoint_to_xray_outbound(ep, "")
        config.pop("tag", None)
        return {"ok": True, "config": config, "remark": ep.get("remark") or ""}
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"ok": False, "error": str(exc) or "не удалось разобрать ссылку"}, status_code=400)


def _outbound_info(config: dict) -> str:
    proto = config.get("protocol") or "?"
    s = config.get("settings") or {}
    srv = (s.get("vnext") or s.get("servers") or [None])[0]
    if isinstance(srv, dict) and srv.get("address"):
        return f"{proto} {srv['address']}:{srv.get('port', '')}"
    if s.get("address") and s.get("port"):
        return f"{proto} {s['address']}:{s['port']}"
    peer = (s.get("peers") or [None])[0]
    if isinstance(peer, dict) and peer.get("endpoint"):
        return f"{proto} {peer['endpoint']}"
    return proto


def _outbound_via(config: dict | None) -> str:
    """Return dialerProxy tag if this outbound is chained through another."""
    if not isinstance(config, dict):
        return ""
    so = ((config.get("streamSettings") or {}).get("sockopt") or {})
    return str(so.get("dialerProxy") or "").strip()


def _apply_outbound_wrap(config: dict, *, wrap_on: bool, wrap_via: str, self_tag: str = "") -> str | None:
    """Set or clear streamSettings.sockopt.dialerProxy. Returns error or None."""
    via = (wrap_via or "").strip()
    self_tag = (self_tag or "").strip()
    if wrap_on:
        if not via:
            return "Выберите outbound для заворачивания трафика"
        if self_tag and via == self_tag:
            return "Нельзя заворачивать outbound через самого себя"
        ss = config.setdefault("streamSettings", {})
        if not isinstance(ss, dict):
            return "streamSettings повреждён"
        so = ss.setdefault("sockopt", {})
        if not isinstance(so, dict):
            return "sockopt повреждён"
        so["dialerProxy"] = via
        return None
    # Wrap off → drop dialerProxy only (keep other sockopt keys)
    ss = config.get("streamSettings")
    if not isinstance(ss, dict):
        return None
    so = ss.get("sockopt")
    if isinstance(so, dict) and "dialerProxy" in so:
        so.pop("dialerProxy", None)
        if not so:
            ss.pop("sockopt", None)
        if not ss:
            config.pop("streamSettings", None)
    return None


def _add_custom_outbound(store: dict, tag: str, remark: str, config: dict, kind: str, info: str = "", country: str = "") -> str | None:
    if not xray.TAG_RE.match(tag):
        return "Tag: латиница/цифры/._-"
    if tag in xray.all_outbound_tags(store) or tag in ("api",):
        return f"Tag {tag} уже занят"
    config.pop("tag", None)
    store["outbounds_custom"].append({"tag": tag, "remark": remark or tag, "config": config, "kind": kind,
                                      "enabled": True, "in_sub": True, "info": info, "country": country.upper()})
    return None


@app.post("/outbounds/add")
async def outbound_add(request: Request):
    if redir := _require(request):
        return redir
    form = await request.form()
    mode = str(form.get("mode") or "link")
    tag = str(form.get("tag") or "").strip()
    remark = str(form.get("remark") or "").strip()
    country = str(form.get("country") or "").strip()
    edit_tag = str(form.get("edit_tag") or "").strip()
    try:
        if mode == "link":
            ep = P.link_to_endpoint(str(form.get("link") or ""))
            config = P.endpoint_to_xray_outbound(ep, tag)
            remark = remark or ep.get("remark") or tag
            info = f"{ep['protocol']} {ep['address']}:{ep['port']}"
        elif mode in ("json", "form"):
            config = json.loads(str(form.get("json") or "{}"))
            if not isinstance(config, dict) or not config.get("protocol"):
                raise ValueError("в JSON нет поля protocol")
            tag = tag or str(config.get("tag") or "")
            info = _outbound_info(config)
        elif mode == "warp":
            license_key = str(form.get("warp_license") or "").strip()
            res = ops.warp_register(license_key)
            if not res.get("ok"):
                raise ValueError(res.get("error"))
            plus = bool(res.get("warp_plus") or license_key)
            label = res.get("label") or ("Cloudflare WARP+" if plus else "Cloudflare WARP")
            acc = res.get("account") if isinstance(res.get("account"), dict) else {}
            hint = str(acc.get("license_hint") or "")
            info = label + (f" · …{hint}" if hint else "")
            config, remark = res["config"], remark or label
            tag = tag or ("warp-plus" if plus else "warp")
            country = country or "CF"
        elif mode == "nord":
            key = ops.nord_private_key(str(form.get("nord_token") or "").strip())
            if not key.get("ok") or not key.get("private_key"):
                raise ValueError(f"NordVPN token: {key.get('error') or 'нет ключа'}")
            servers = ops.nord_servers(_int(form.get("nord_country")) or None, 1)
            if not servers:
                raise ValueError("NordVPN: не найден сервер")
            srv = servers[0]
            config = ops.nord_outbound(key["private_key"], srv)
            info = f"NordVPN {srv['hostname']} load {srv['load']}%"
            remark = remark or f"NordVPN {srv['country']}"
            country = country or (srv.get("code") or "")
            tag = tag or f"nord_{(srv.get('code') or 'xx').lower()}"
        elif mode == "pia":
            form_user = str(form.get("pia_user") or "").strip()
            form_pass = str(form.get("pia_pass") or "")
            region_id = str(form.get("pia_region") or "").strip()
            hostname = str(form.get("pia_hostname") or "").strip()
            remember = form.get("pia_remember") != "0"
            with mutate() as st0:
                saved_user, saved_pass = _pia_creds(st0)
                user = form_user or saved_user
                pwd = form_pass or saved_pass
                if not user or not pwd:
                    raise ValueError("Укажите PIA username и password (сохранятся для auto-reconnect)")
                if remember:
                    _pia_save_credentials(st0, user, pwd)
            with mutate() as st1:
                tok = _pia_ensure_token(st1, force=bool(form_pass))
                if not tok.get("ok"):
                    raise ValueError(tok.get("error") or "PIA auth")
                token = tok["token"]
            res = ops.pia_create_outbound(user, pwd, region_id=region_id, hostname=hostname, token=token)
            if not res.get("ok"):
                raise ValueError(res.get("error") or "PIA ошибка")
            if remember and res.get("token"):
                with mutate() as st3:
                    _pia_save_credentials(st3, user, pwd, token=res["token"])
            config = res["config"]
            info = res.get("info") or "PIA WireGuard"
            remark = remark or res.get("remark") or "PIA"
            country = country or (res.get("country") or "")
            tag = tag or res.get("tag") or "pia"
            pia_meta = {"pia_hostname": res.get("hostname") or hostname, "pia_region": res.get("region_id") or region_id}
        else:
            raise ValueError("неизвестный режим")
    except Exception as exc:  # noqa: BLE001
        flash(request, f"Outbound: {exc}", "error")
        return go("/outbounds")
    wrap_on = form.get("wrap_on") == "1"
    wrap_via = str(form.get("wrap_via") or "").strip()
    if wrap_on and wrap_via:
        known = set(xray.all_outbound_tags(_load_store()))
        if wrap_via not in known:
            flash(request, f"Outbound: неизвестный via «{wrap_via}»", "error")
            return go("/outbounds")
    wrap_err = _apply_outbound_wrap(
        config, wrap_on=wrap_on, wrap_via=wrap_via, self_tag=edit_tag or tag,
    )
    if wrap_err:
        flash(request, f"Outbound: {wrap_err}", "error")
        return go("/outbounds")
    prop_note = ""
    with mutate() as store:
        previous = json.loads(json.dumps(store["outbounds_custom"]))
        if edit_tag:
            o = next((x for x in store["outbounds_custom"] if x["tag"] == edit_tag), None)
            if o:
                config.pop("tag", None)
                o.update({"config": config, "remark": remark or edit_tag, "country": country.upper(), "info": info})
                if mode == "pia":
                    o["kind"] = "pia"
                    o.update(pia_meta)
                o.pop("last_test", None)
                err = None
            else:
                err = "Outbound не найден"
            tag = edit_tag
        else:
            kind = "pia" if mode == "pia" else ("custom" if mode == "form" else mode)
            err = _add_custom_outbound(store, tag, remark, config, kind, info, country)
            if not err and mode == "pia":
                o = next((x for x in store["outbounds_custom"] if x["tag"] == tag), None)
                if o:
                    o.update(pia_meta)
                    o["pia_reconnected_at"] = datetime.now(timezone.utc).isoformat()
                    cfg = _pia_settings(store)
                    cfg["last_reconnect_at"] = o["pia_reconnected_at"]
            if not err:
                propagate = form.get("propagate_users") == "1"
                stats = xray.apply_tag_to_users(store, kind="outbound", tag=tag, propagate=propagate)
                prop_note = (
                    f" · всем клиентам (+{stats['clients']} списков, +{stats['groups']} групп)"
                    if propagate else
                    f" · без автораздачи (зафиксировано {stats['clients']} клиентов / {stats['groups']} групп)"
                )
    if err:
        flash(request, err, "error")
        return go("/outbounds")
    xr = _apply_xray(_load_store(), xray_only=True)
    if not xr.get("ok"):
        with mutate() as store:
            store["outbounds_custom"] = previous
        flash(request, f"Outbound {tag} не сохранён — Xray отклонил конфиг: {xr.get('error')}", "error")
        return go("/outbounds")
    act = "обновлён" if edit_tag else "добавлен"
    _tg_change(f"📤 Outbound <b>{tgbot.escape(tag)}</b> {act}")
    flash(request, f"Outbound {tag} {act}{prop_note}", "info")
    return go("/outbounds")


@app.get("/outbounds/nord/countries")
def nord_countries(request: Request):
    if not _user(request):
        return JSONResponse([], status_code=401)
    return ops.nord_countries()


@app.get("/outbounds/pia/countries")
def pia_countries(request: Request):
    if not _user(request):
        return JSONResponse([], status_code=401)
    return ops.pia_countries()


@app.get("/outbounds/pia/status")
def pia_status(request: Request):
    if not _user(request):
        return JSONResponse({"ok": False}, status_code=401)
    return {"ok": True, **_pia_account_view()}


@app.post("/outbounds/pia/logout")
def pia_logout(request: Request):
    if redir := _require(request):
        return redir
    with mutate() as store:
        _pia_clear_account(store)
    flash(request, "PIA: логин и token очищены (outbounds не тронуты)", "info")
    return go("/outbounds")


@app.post("/outbounds/pia/reconnect")
def pia_reconnect(request: Request):
    if redir := _require(request):
        return redir
    # Sequential: one outbound → apply → next (others stay online)
    res = _pia_reconnect_outbounds(force=True)
    if res.get("ok"):
        msg = f"PIA reconnect по очереди: {res.get('updated', 0)}"
        if res.get("tags"):
            msg += f" ({', '.join(res['tags'])})"
        if res.get("errors"):
            msg += f" · ошибки: {'; '.join(res['errors'])}"
        flash(request, msg, "info" if res.get("updated") else "error")
    else:
        flash(request, f"PIA reconnect: {res.get('error') or res.get('errors')}", "error")
    return go("/outbounds")


@app.get("/api/keys/wg")
def api_wg_keys(request: Request):
    if not _user(request):
        return JSONResponse({"ok": False, "error": "auth"}, status_code=401)
    priv = str(request.query_params.get("private") or "").strip()
    if priv:
        return xray.wg_public_from_private(priv)
    return xray.generate_wg_keys()


@app.get("/api/keys/reality")
def api_reality_keys(request: Request):
    if not _user(request):
        return JSONResponse({"ok": False, "error": "auth"}, status_code=401)
    return xray.generate_reality_keys()


@app.get("/api/keys/shortids")
def api_short_ids(request: Request):
    if not _user(request):
        return JSONResponse({"ok": False, "error": "auth"}, status_code=401)
    return {"ok": True, "short_ids": xray.generate_short_ids()}


@app.get("/api/keys/mldsa65")
def api_mldsa65(request: Request):
    if not _user(request):
        return JSONResponse({"ok": False, "error": "auth"}, status_code=401)
    return xray.generate_mldsa65()


@app.get("/api/keys/vlessenc")
def api_vlessenc(request: Request):
    if not _user(request):
        return JSONResponse({"ok": False, "error": "auth"}, status_code=401)
    return xray.generate_vless_encryption()


@app.post("/outbounds/{tag}/{action}")
def outbound_action(tag: str, action: str, request: Request):
    if redir := _require(request):
        return redir
    if action == "test":
        res = xray.test_outbound(_load_store(), tag)
        with mutate() as store:
            o = next((x for x in store["outbounds_custom"] if x["tag"] == tag), None)
            if o:
                o["last_test"] = {"ok": res["ok"], "ms": res.get("ms"), "at": xray.now_utc().isoformat()}
        flash(request, f"{tag}: {'OK ' + str(res.get('ms')) + ' мс' if res['ok'] else 'ошибка ' + str(res.get('error'))}",
              "info" if res["ok"] else "error")
        return go("/outbounds")
    if action == "reconnect":
        res = _pia_reconnect_one(tag)
        if res.get("ok"):
            probe = "probe OK" if res.get("probe_ok") else "probe fail"
            flash(request, f"PIA reconnect {tag}: ok · {probe}", "info")
        else:
            flash(request, f"PIA reconnect {tag}: {res.get('error')}", "error")
        return go("/outbounds")
    with mutate() as store:
        if action == "reset":
            store.setdefault("outbound_traffic", {}).setdefault(tag, {}).update({"up": 0, "down": 0})
        else:
            o = next((x for x in store["outbounds_custom"] if x["tag"] == tag), None)
            if not o:
                flash(request, "Outbound не найден", "error")
                return go("/outbounds")
            if action == "toggle":
                o["enabled"] = not o.get("enabled", True)
            elif action == "sub":
                o["in_sub"] = not o.get("in_sub", True)
            elif action == "delete":
                used = [c["email"] for c in store["clients"] if c.get("outbound") == tag]
                if used:
                    flash(request, f"{tag} используется клиентами: {', '.join(used)}", "error")
                    return go("/outbounds")
                store["outbounds_custom"].remove(o)
    xr = _apply_xray(_load_store(), xray_only=True) if action != "reset" else {"ok": True}
    labels = {
        "delete": "удалён", "toggle": "вкл/выкл", "sub": "в подписке вкл/выкл",
        "reset": "сброс трафика",
    }
    if action in labels:
        _tg_change(f"📤 Outbound <b>{tgbot.escape(tag)}</b>: {labels[action]}")
    flash(request, *_ok_msg(f"{tag}: {action}", xr))
    return go("/outbounds")


# ================================================================ balancers

@app.get("/balancers", response_class=HTMLResponse)
def balancers_page(request: Request):
    if redir := _require(request):
        return redir
    store = _load_store()
    bals = xray.ensure_balancers(store)
    active = {k: xray.balancer_member_tags(store, b) for k, b in bals.items()}
    return page(request, "balancers.html", active="balancers", balancers=bals, active_members=active,
                custom=store["outbounds_custom"], watchdog_sec=WATCHDOG_INTERVAL, store=store,
                default_balancer_labels=xray.BALANCER_LABELS)


@app.post("/balancers/{key}")
async def balancers_save(key: str, request: Request):
    if redir := _require(request):
        return redir
    if key not in ("least_ping", "least_load", "random"):
        return go("/balancers")
    form = await request.form()
    with mutate() as store:
        b = xray.ensure_balancers(store)[key]
        b["enabled"] = form.get("enabled") == "1"
        b["label"] = str(form.get("label") or "").strip()[:80]
        b["sub_direct_pool"] = form.get("sub_direct_pool") == "1"
        b["probe_url"] = str(form.get("probe_url") or b["probe_url"]).strip()
        b["probe_interval"] = str(form.get("probe_interval") or b["probe_interval"]).strip()
        raw_fb = str(form.get("fallback") or "direct").strip()
        b["fallback"] = "none" if raw_fb.lower() in ("none", "-", "off") else (raw_fb or "direct")
        members = [str(x) for x in form.getlist("members")]
        all_custom = {o["tag"] for o in store.get("outbounds_custom") or [] if o.get("enabled", True) and o.get("tag")}
        all_auto = all_custom
        # [] = auto pool (enabled customs).
        if not members or set(members) == all_auto:
            b["members"] = []
        else:
            b["members"] = members
        if key == "least_load":
            b["expected"] = max(1, _int(form.get("expected"), 1))
            b["max_rtt"] = str(form.get("max_rtt") or "1s")
            b["tolerance"] = _float(form.get("tolerance"), 0.15)
    xr = _apply_xray(_load_store(), xray_only=True)
    with_state = "вкл" if form.get("enabled") == "1" else "выкл"
    label_txt = str(form.get("label") or "").strip() or key
    _tg_change(
        f"⚖ Balancer <b>{tgbot.escape(key)}</b> сохранён ({with_state})",
        f"label=<code>{tgbot.escape(label_txt)}</code> · "
        f"direct_pool={'да' if form.get('sub_direct_pool') == '1' else 'нет'} · "
        f"fallback=<code>{tgbot.escape(str(form.get('fallback') or 'direct'))}</code>",
    )
    flash(request, *_ok_msg(f"{key} сохранён", xr))
    return go("/balancers")


# ================================================================ traffic schema

@app.get("/schema", response_class=HTMLResponse)
def schema_page(request: Request):
    if redir := _require(request):
        return redir
    store = _load_store()
    import traffic_schema as tschema
    schema = tschema.build_schema(store, online=ONLINE)
    return page(
        request, "traffic_schema.html", active="schema",
        schema=schema, store=store,
    )


@app.post("/schema/check")
async def schema_check(request: Request):
    if not _user(request):
        return JSONResponse({"ok": False, "error": "auth"}, status_code=401)
    form = await request.form()
    store = _load_store()
    import traffic_schema as tschema
    return JSONResponse(tschema.check_destination(
        store,
        email=str(form.get("email") or ""),
        inbound_tag=str(form.get("inbound") or ""),
        dest=str(form.get("dest") or ""),
    ))


@app.post("/schema/apply")
def schema_apply(request: Request):
    if redir := _require(request):
        return redir
    xr = _apply_xray(_load_store(), xray_only=True)
    flash(request, *_ok_msg("Схема: конфиг Xray применён", xr))
    return go("/schema")


# ================================================================ routing

def _route_rule_from_form(form) -> tuple[dict | None, str]:
    """Parse routing form → (rule, error). Name may be empty for callers that set it."""
    name = str(form.get("name") or "").strip()
    users = [str(x).strip() for x in form.getlist("user") if str(x).strip()]
    # Backward compat: old textarea posted as a single multi-line field
    if not users and form.get("user"):
        users = _split_lines(str(form.get("user") or ""))
    sources = [str(x).strip() for x in form.getlist("source") if str(x).strip()]
    sources += _split_lines(str(form.get("source_extra") or ""))
    # Dedupe preserving order
    seen_src: set[str] = set()
    source_out: list[str] = []
    for ip in sources:
        if ip not in seen_src:
            seen_src.add(ip)
            source_out.append(ip)
    rule = {
        "name": name,
        "enabled": form.get("enabled") != "0",
        "outbound": xray.normalize_outbound_tag(str(form.get("outbound") or "direct")),
        "domain": _split_lines(str(form.get("domain") or "")),
        "ip": _split_lines(str(form.get("ip") or "")),
        "user": users,
        "source": source_out,
        "protocol": [p for p in ("http", "tls", "quic", "bittorrent") if form.get(f"proto_{p}") == "1"],
        "inbound_tags": [
            str(x) for x in form.getlist("inbound_tags")
            if str(x) and str(x) not in nodes_mod._SYSTEM_INBOUND_TAGS
        ],
        "network": str(form.get("network") or ""),
        "port": str(form.get("port") or "").strip(),
    }
    # «all» → no inboundTag filter in Xray (matches every inbound, including future ones)
    if form.get("inbound_all") == "1":
        rule["inbound_all"] = True
        rule["inbound_tags"] = []
    else:
        rule["inbound_all"] = False
    has_cond = any(rule[k] for k in ("domain", "ip", "user", "source", "protocol", "inbound_tags", "network", "port"))
    if not has_cond and not rule.get("inbound_all"):
        return None, "Нужно хотя бы одно условие"
    return rule, ""


@app.get("/routing", response_class=HTMLResponse)
def routing_page(request: Request):
    if redir := _require(request):
        return redir
    store = _load_store()
    route_clients = xray.route_picker_clients(store)
    route_source_ips = xray.route_picker_source_ips(store)
    return page(request, "routing.html", active="routing", routes=store["routes"], store=store,
                route_missing={r.get("name"): xray.route_missing_geo(r) for r in store["routes"]},
                ext_missing=xray.missing_ext_geo(store),
                outbounds=xray.all_outbound_tags(store), presets=xray.ROUTE_PRESETS,
                route_clients=route_clients,
                route_source_ips=route_source_ips,
                route_ip_labels={o["ip"]: o["label"] for o in route_source_ips},

                inbound_tags=[
                    i["tag"] for i in store["inbounds"]
                    if i.get("tag") and not i.get("_system")
                    and i.get("tag") not in (
                        nodes_mod.MASTER_BACKHAUL_TAG, "rv-in", "api", "node-bridge",
                    )
                ],
                geo=ops.geo_files(), geo_missing=ops.geo_missing_core(),
                geo_cfg=store["settings"].get("geo_update") or {},
                geo_state=store.get("geo_update_state") or {},
                geo_packs=ops.GEO_PACKS,
                jobs=sorted(ops.JOBS.items(), key=lambda kv: -kv[1]["started"])[:5])


@app.post("/routing")
async def routing_add(request: Request):
    if redir := _require(request):
        return redir
    form = await request.form()
    rule, err = _route_rule_from_form(form)
    if err or not rule:
        flash(request, err or "Ошибка формы", "error")
        return go("/routing")
    name = rule["name"]
    with mutate() as store:
        if not name or any(r.get("name") == name for r in store["routes"]):
            flash(request, "Нужно уникальное имя правила", "error")
            return go("/routing")
        rule["enabled"] = True
        store["routes"].append(rule)
    xr = _apply_xray(_load_store(), xray_only=True)
    _tg_change(
        f"🗺 Routing: правило <b>{tgbot.escape(name)}</b> добавлено",
        f"→ <code>{tgbot.escape(str(rule.get('outbound') or 'direct'))}</code>",
    )
    flash(request, *_ok_msg(f"Правило {name} добавлено", xr))
    return go("/routing")


@app.post("/routing/{name}/save")
async def routing_save(name: str, request: Request):
    """Update an existing routing rule (edit form)."""
    if redir := _require(request):
        return redir
    form = await request.form()
    rule, err = _route_rule_from_form(form)
    if err or not rule:
        flash(request, err or "Ошибка формы", "error")
        return go("/routing")
    new_name = rule["name"] or name
    rule["name"] = new_name
    with mutate() as store:
        routes = store["routes"]
        idx = next((i for i, r in enumerate(routes) if r.get("name") == name), None)
        if idx is None:
            flash(request, "Правило не найдено", "error")
            return go("/routing")
        if new_name != name and any(r.get("name") == new_name for r in routes):
            flash(request, f"Имя «{new_name}» уже занято", "error")
            return go("/routing")
        rule["enabled"] = form.get("enabled") == "1"
        routes[idx] = rule
    xr = _apply_xray(_load_store(), xray_only=True)
    _tg_change(
        f"🗺 Routing: правило <b>{tgbot.escape(name)}</b> изменено"
        + (f" → <b>{tgbot.escape(new_name)}</b>" if new_name != name else ""),
        f"→ <code>{tgbot.escape(str(rule.get('outbound') or 'direct'))}</code>",
    )
    flash(request, *_ok_msg(f"Правило {new_name} сохранено", xr))
    return go("/routing")


@app.post("/routing/preset/{key}")
def routing_preset(key: str, request: Request):
    if redir := _require(request):
        return redir
    preset = xray.ROUTE_PRESETS.get(key)
    if not preset:
        return go("/routing")
    with mutate() as store:
        if any(r.get("name") == preset["name"] for r in store["routes"]):
            flash(request, f"{preset['name']} уже есть", "error")
            return go("/routing")
        store["routes"].insert(0, {"enabled": True, **json.loads(json.dumps(preset))})
    xr = _apply_xray(_load_store(), xray_only=True)
    _tg_change(f"🗺 Routing: preset <b>{tgbot.escape(preset['name'])}</b> добавлен")
    flash(request, *_ok_msg(f"Добавлено {preset['name']}", xr))
    return go("/routing")


@app.post("/routing/{name}/{action}")
def routing_action(name: str, action: str, request: Request):
    if redir := _require(request):
        return redir
    nxt = _next(request, "/routing")
    if action == "save":
        # Handled by routing_save — avoid falling through if route order mismatches
        return go(nxt)
    what = action
    with mutate() as store:
        routes = store["routes"]
        idx = next((i for i, r in enumerate(routes) if r.get("name") == name), None)
        if idx is None:
            return go(nxt)
        if action == "delete":
            routes.pop(idx)
            what = "удалено"
        elif action == "toggle":
            routes[idx]["enabled"] = not routes[idx].get("enabled", True)
            what = "включено" if routes[idx]["enabled"] else "выключено"
        elif action == "up" and idx > 0:
            routes[idx - 1], routes[idx] = routes[idx], routes[idx - 1]
            what = "выше"
        elif action == "down" and idx < len(routes) - 1:
            routes[idx + 1], routes[idx] = routes[idx], routes[idx + 1]
            what = "ниже"
        else:
            return go(nxt)
    xr = _apply_xray(_load_store(), xray_only=True)
    _tg_change(f"🗺 Routing: <b>{tgbot.escape(name)}</b> — {tgbot.escape(what)}")
    flash(request, *_ok_msg(f"{name}: {action}", xr))
    return go(nxt)


# ================================================================ xray settings

@app.get("/xray", response_class=HTMLResponse)
def xray_page(request: Request):
    if redir := _require(request):
        return redir
    store = _load_store()
    tab = request.query_params.get("tab") or "general"
    ctx: dict[str, Any] = {}
    if tab == "core":
        ctx["releases"] = ops.xray_releases()
        ctx["upd"] = store.get("xray_update_state") or {}
        ctx["upd_cfg"] = store["settings"].get("xray_update") or {}
        ctx["xray_bak"] = ops.xray_backup_info()
    if tab == "template":
        ctx["final"] = json.dumps(xray.build_config(store), ensure_ascii=False, indent=2)
    if tab == "geo":
        ctx["geo"] = ops.geo_files()
        ctx["geo_missing"] = ops.geo_missing_core()
        ctx["geo_cfg"] = store["settings"].get("geo_update") or {}
        ctx["geo_state"] = store.get("geo_update_state") or {}
        ctx["geo_packs"] = ops.GEO_PACKS
    return page(request, "xray.html", active="xray", tab=tab, store=store, xs=xray.xray_status(),
                jobs=sorted(ops.JOBS.items(), key=lambda kv: -kv[1]["started"])[:5], **ctx)


@app.post("/xray/settings")
async def xray_settings_save(request: Request):
    if redir := _require(request):
        return redir
    form = await request.form()
    section = str(form.get("section") or "")
    with mutate() as store:
        try:
            if section == "general":
                xs = store["xray_settings"]
                if form.get("disable_logs") == "1":
                    xs["log_level"] = "none"
                    xs["access_log"] = False
                    xs["dns_log"] = False
                else:
                    xs["log_level"] = str(form.get("log_level") or "warning")
                    xs["access_log"] = form.get("access_log") == "1"
                    xs["dns_log"] = form.get("dns_log") == "1"
            elif section == "dns":
                d = store["dns"]
                d["enabled"] = form.get("enabled") == "1"
                d["servers"] = _split_lines(str(form.get("servers") or "").replace(",", "\n"))
                d["query_strategy"] = str(form.get("query_strategy") or "UseIP")
                d["disable_cache"] = form.get("disable_cache") == "1"
                hosts = {}
                for line in str(form.get("hosts") or "").splitlines():
                    if "=" in line:
                        k, v = line.split("=", 1)
                        hosts[k.strip()] = v.strip()
                d["hosts"] = hosts
                d["fakedns"] = {"enabled": form.get("fakedns") == "1", "pool": str(form.get("fake_pool") or "198.18.0.0/15"),
                                "size": _int(form.get("fake_size"), 65535)}
            elif section == "reverse":
                def parse(text: str) -> list[dict]:
                    out = []
                    for line in text.splitlines():
                        if "|" in line:
                            tg, dom = [x.strip() for x in line.split("|", 1)]
                            if tg and dom:
                                out.append({"tag": tg, "domain": dom})
                    return out
                store["reverse"] = {"bridges": parse(str(form.get("bridges") or "")), "portals": parse(str(form.get("portals") or ""))}
            elif section == "template":
                raw = str(form.get("patch") or "").strip()
                patch = json.loads(raw) if raw else {}
                if not isinstance(patch, dict):
                    raise ValueError("JSON должен быть объектом")
                store["xray_settings"]["template_patch"] = patch
            elif section == "geo_custom":
                items = []
                for line in str(form.get("geo_custom") or "").splitlines():
                    if "|" in line:
                        n, u = [x.strip() for x in line.split("|", 1)]
                        if not n or not u:
                            continue
                        u = sec.validate_outbound_url(u, allow_http=False)
                        items.append({"name": n, "url": u})
                store["settings"]["geo_custom"] = items
        except ValueError as exc:
            flash(request, f"Ошибка: {exc}", "error")
            return go(f"/xray?tab={section}")
    if section != "geo_custom":
        # apply_config always runs xray -test + live restart check; rejects/rolls back on failure
        xr = _apply_xray(_load_store(), xray_only=True)
        flash(request, *_ok_msg("Настройки Xray применены", xr))
    else:
        flash(request, "Сохранено", "info")
    return go(f"/xray?tab={section}")


@app.post("/xray/install")
def xray_install(request: Request, version: str = Form(...)):
    if redir := _require(request):
        return redir
    ops.start_job("xray-install", ops.install_xray, version)
    flash(request, f"Установка Xray {version} запущена", "info")
    return go("/xray?tab=core")


@app.post("/xray/rollback")
def xray_rollback(request: Request, version: str = Form(""), confirm: str = Form("")):
    """Roll Xray back to local .bak (empty version) or a specific GitHub tag."""
    if redir := _require(request):
        return redir
    if confirm != "yes":
        flash(request, "Откат Xray не подтверждён", "error")
        return go("/xray?tab=core")
    running = XRAY_UPDATE_JOB.get("id")
    if running and ops.JOBS.get(running, {}).get("status") == "running":
        flash(request, "Установка/откат Xray уже идёт", "info")
        return go("/xray?tab=core")
    target = (version or "").strip()

    def do_rb(v: str) -> dict:
        res = ops.rollback_xray(v)
        try:
            check_xray_update(force=True)
        except Exception:
            pass
        return res

    XRAY_UPDATE_JOB["id"] = ops.start_job("xray-rollback", do_rb, target)
    if target:
        flash(request, f"Откат Xray на {ops.normalize_tag(target)} запущен", "info")
    else:
        flash(request, "Откат Xray на предыдущий бинарник (.bak) запущен", "info")
    return go("/xray?tab=core")


def _next(request: Request, default: str = "/xray?tab=core") -> str:
    nxt = request.query_params.get("next") or default
    return nxt if nxt.startswith("/") and not nxt.startswith("//") else default


@app.post("/panel/update/check")
def panel_update_check(request: Request):
    if redir := _require(request):
        return redir
    st = check_panel_update(force=True)
    if st.get("error"):
        flash(request, f"Проверка панели: {st['error']}", "error")
    elif st.get("available"):
        flash(request, f"Доступна панель {st['latest']} (сейчас {st.get('current')})", "info")
    else:
        flash(request, f"Установлена актуальная панель {st.get('current')}", "info")
    return go(_next(request, "/settings?tab=system"))


@app.post("/panel/update/install")
def panel_update_install(request: Request, version: str = Form(...), confirm: str = Form("")):
    if redir := _require(request):
        return redir
    st = _load_store().get("panel_update_state") or {}
    if confirm != "yes" or version != st.get("latest"):
        flash(request, "Обновление панели не подтверждено", "error")
        return go("/settings?tab=system")
    running = PANEL_UPDATE_JOB.get("id")
    if running and ops.JOBS.get(running, {}).get("status") == "running":
        flash(request, "Обновление панели уже идёт", "info")
        return go("/settings?tab=system")

    def do_update():
        res = ops.update_panel()
        try:
            check_panel_update(force=True)
        except Exception:
            pass
        return res

    PANEL_UPDATE_JOB["id"] = ops.start_job("panel-update", do_update)
    flash(request, f"Обновление панели до {version} запущено. Сервис перезапустится; обновите страницу через минуту.", "info")
    return go("/settings?tab=system")


@app.post("/panel/update/rollback")
def panel_update_rollback(request: Request, version: str = Form(...), confirm: str = Form("")):
    """Install a specific panel release tag (rollback or pin). Keeps data; does not touch Xray."""
    if redir := _require(request):
        return redir
    tag = ops.normalize_tag(version)
    if confirm != "yes" or not tag:
        flash(request, "Откат панели не подтверждён", "error")
        return go("/settings?tab=system")
    cur = ops.normalize_tag(panel_version())
    if tag == cur:
        flash(request, f"Уже установлена {tag}", "info")
        return go("/settings?tab=system")
    running = PANEL_UPDATE_JOB.get("id")
    if running and ops.JOBS.get(running, {}).get("status") == "running":
        flash(request, "Обновление/откат панели уже идёт", "info")
        return go("/settings?tab=system")

    def do_rollback():
        res = ops.rollback_panel(tag)
        try:
            check_panel_update(force=True)
        except Exception:
            pass
        return res

    PANEL_UPDATE_JOB["id"] = ops.start_job("panel-rollback", do_rollback)
    flash(
        request,
        f"Откат панели на {tag} запущен (Xray не меняется). Сервис перезапустится — обновите страницу через минуту.",
        "info",
    )
    return go("/settings?tab=system")


@app.post("/panel/update/dismiss")
def panel_update_dismiss(request: Request):
    if redir := _require(request):
        return redir
    with mutate() as store:
        st = store.setdefault("panel_update_state", {})
        st["dismissed"] = st.get("latest") or ""
    return go(_next(request, "/"))


@app.post("/xray/update/check")
def xray_update_check(request: Request):
    if redir := _require(request):
        return redir
    st = check_xray_update(force=True)
    if st.get("error"):
        flash(request, f"Проверка обновлений: {st['error']}", "error")
    elif st.get("available"):
        flash(request, f"Доступна Xray {st['latest']} (установлена {st.get('current') or '?'})", "info")
    else:
        flash(request, f"Установлена последняя версия Xray {st.get('current') or ''}", "info")
    return go(_next(request))


@app.post("/xray/update/install")
def xray_update_install(request: Request, version: str = Form(...), confirm: str = Form("")):
    """Install the version shown in the update banner — only after explicit approval."""
    if redir := _require(request):
        return redir
    st = _load_store().get("xray_update_state") or {}
    if confirm != "yes" or version != st.get("latest"):
        flash(request, "Установка не подтверждена или версия устарела — проверьте обновления ещё раз", "error")
        return go("/xray?tab=core")
    running = XRAY_UPDATE_JOB.get("id")
    if running and ops.JOBS.get(running, {}).get("status") == "running":
        flash(request, "Установка Xray уже идёт", "info")
        return go("/xray?tab=core")

    def install_and_recheck(v: str) -> dict:
        res = ops.install_xray(v)
        try:
            check_xray_update(force=True)
        except Exception:
            pass
        return res

    XRAY_UPDATE_JOB["id"] = ops.start_job("xray-update", install_and_recheck, version)
    flash(request, f"Обновление Xray до {version} запущено. При ошибке будет возвращена прежняя версия.", "info")
    return go("/xray?tab=core")


@app.post("/xray/update/dismiss")
def xray_update_dismiss(request: Request):
    if redir := _require(request):
        return redir
    with mutate() as store:
        st = store.setdefault("xray_update_state", {})
        st["dismissed"] = st.get("latest") or ""
    flash(request, "Уведомление скрыто до следующего релиза Xray", "info")
    return go(_next(request, "/"))


@app.post("/xray/update/settings")
async def xray_update_settings(request: Request):
    if redir := _require(request):
        return redir
    form = await request.form()
    with mutate() as store:
        store["settings"]["xray_update"] = {
            "auto_check": form.get("auto_check") == "1",
            "interval_hours": max(1, min(168, _int(form.get("interval_hours"), 12))),
            "include_prerelease": form.get("include_prerelease") == "1",
        }
    _refresh_settings_cache()
    flash(request, "Настройки проверки обновлений сохранены", "info")
    return go("/xray?tab=core")


@app.post("/xray/geo/update")
def xray_geo_update(request: Request):
    if redir := _require(request):
        return redir
    nxt = _next(request, "/xray?tab=geo")

    def job():
        return _run_geo_update(reason="manual")

    ops.start_job("geo-update", job)
    flash(request, "Обновление geoip/geosite запущено (фоновая задача)", "info")
    return go(nxt)


@app.post("/xray/geo/settings")
async def xray_geo_settings(request: Request):
    if redir := _require(request):
        return redir
    form = await request.form()
    with mutate() as store:
        store["settings"]["geo_update"] = {
            "auto": form.get("auto") == "1",
            "interval_hours": max(6, min(720, _int(form.get("interval_hours"), 168))),
        }
    _refresh_settings_cache()
    flash(request, "Расписание обновления geo сохранено", "info")
    return go(_next(request, "/xray?tab=geo"))


@app.post("/xray/geo/ext-missing")
def xray_geo_ext_missing(request: Request):
    """Download ext:*.dat files that routing rules reference but are missing on disk."""
    if redir := _require(request):
        return redir
    res = _ensure_ext_geo(_load_store(), force=True)
    if res.get("started"):
        flash(request, f"Скачивание запущено: {', '.join(res['started'])}", "info")
    elif res.get("missing"):
        flash(request, "Загрузка уже идёт или нет источника: " + ", ".join(res["missing"]), "error")
    else:
        flash(request, "Все geo-файлы на месте", "info")
    return go(_next(request, "/routing"))


@app.post("/xray/geo/pack/{key}")
def xray_geo_pack(key: str, request: Request):
    """Add a known geo pack (Russia/Iran/all) to custom sources and download now."""
    if redir := _require(request):
        return redir
    keys = list(ops.GEO_PACKS.keys()) if key == "all" else [key]
    if key != "all" and key not in ops.GEO_PACKS:
        flash(request, "Неизвестный geo-пакет", "error")
        return go(_next(request, "/routing"))
    titles = []
    with mutate() as store:
        custom = store["settings"].setdefault("geo_custom", [])
        by_name = {str(x.get("name") or ""): x for x in custom if isinstance(x, dict)}
        for k in keys:
            pack = ops.GEO_PACKS[k]
            titles.append(pack["title"])
            for f in pack["files"]:
                by_name[f["name"]] = {"name": f["name"], "url": f["url"]}
        store["settings"]["geo_custom"] = list(by_name.values())
    _refresh_settings_cache()
    label = "все пакеты (IR+RU)" if key == "all" else titles[0]

    def job():
        return _run_geo_update(reason=f"pack-{key}")

    ops.start_job(f"geo-pack-{key}", job)
    flash(request, f"Пакет «{label}» добавлен, скачивание запущено (вместе с geoip/geosite Loyalsoldier)", "info")
    return go(_next(request, "/routing"))


# ================================================================ logs

@app.get("/logs", response_class=HTMLResponse)
def logs_page(request: Request):
    if redir := _require(request):
        return redir
    src = request.query_params.get("src") or "xray"
    lines = _int(request.query_params.get("n"), 300)
    grep = request.query_params.get("q") or ""
    if src == "access":
        text = ops.tail(str(xray.XRAY_LOG_DIR / "access.log"), lines)
        if grep:
            text = "\n".join(line for line in text.splitlines() if grep in line)
    else:
        text = ops.journal({"xray": "xray", "panel": "l2xpanel"}.get(src, "xray"), lines, grep)
    return page(request, "logs.html", active="logs", src=src, text=text, n=lines, q=grep)


# ================================================================ DoH (Pi-hole via nginx)
# Admin routes (/doh/install, /doh/save, …) MUST be registered before /doh/{token},
# otherwise Starlette matches «install» as a token and returns 403.

@app.get("/doh", response_class=HTMLResponse)
def doh_page(request: Request):
    if redir := _require(request):
        return redir
    store = _load_store()
    cfg = {**doh_mod.default_settings(), **(store["settings"].get("doh") or {})}
    st = doh_mod.status(cfg)
    dash = doh_mod.pihole_dashboard(cfg)
    clients = []
    for c in store.get("clients") or []:
        if not c.get("doh_enabled"):
            continue
        clients.append({
            "email": c["email"], "token": c.get("doh_token"), "in_tunnel": bool(c.get("doh_in_tunnel")),
            "url": doh_mod.public_url(store, c),
        })
    link = request.session.pop("pihole_link", None)
    until = request.session.get("pihole_until")
    try:
        until_f = float(until or 0)
    except (TypeError, ValueError):
        until_f = 0.0
    pihole_session = {
        "active": until_f > time.time(),
        "until": until_f,
        "left_sec": max(0, int(until_f - time.time())) if until_f else 0,
    }
    return page(request, "doh.html", active="doh", doh=cfg, status=st, doh_clients=clients,
                public_host=public_host(), pihole_link=link, pihole_session=pihole_session,
                pihole_open=f"{base_path()}/pihole/admin/", pihole_dash=dash)


@app.get("/doh/stats")
def doh_stats(request: Request):
    """JSON dashboard from Pi-hole API — used by the DoH tab auto-refresh."""
    if not _user(request):
        return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)
    store = _load_store()
    cfg = {**doh_mod.default_settings(), **(store["settings"].get("doh") or {})}
    return JSONResponse(doh_mod.pihole_dashboard(cfg))


@app.post("/doh/save")
async def doh_save(request: Request):
    if redir := _require(request):
        return redir
    form = await request.form()
    pwd = str(form.get("pihole_password") or "").strip()
    with mutate() as store:
        d = store["settings"].setdefault("doh", doh_mod.default_settings())
        d.update({
            "enabled": form.get("enabled") == "1",
            "path_prefix": doh_mod.normalize_prefix(str(form.get("path_prefix") or "doh")),
            "upstream": str(form.get("upstream") or "127.0.0.1").strip() or "127.0.0.1",
            "upstream_port": max(1, _int(form.get("upstream_port"), doh_mod.PIHOLE_DNS_HOST_PORT)),
            "pihole_web": str(form.get("pihole_web") or "127.0.0.1:8089").strip(),
            "timeout_sec": max(1, _float(form.get("timeout_sec"), 4)),
        })
        if pwd:
            d["pihole_password"] = pwd
    pwd_msg = ""
    if pwd:
        doh_mod.invalidate_pihole_session(_load_store()["settings"].get("doh") or {})
        sp = doh_mod.set_pihole_password(pwd)
        if sp.get("ok"):
            pwd_msg = " Пароль Pi-hole применён к контейнеру."
        else:
            flash(request, f"DoH сохранены, но пароль Pi-hole не применён: {sp.get('error')}", "error")
            return go("/doh")
    # Re-apply nginx so /doh/ location + reserved path update
    xr = _apply_xray(_load_store())
    on = "вкл" if form.get("enabled") == "1" else "выкл"
    _tg_change(
        f"🛡 DoH настройки сохранены ({on})",
        f"prefix=<code>{tgbot.escape(str(form.get('path_prefix') or 'doh'))}</code>"
        + (" · пароль Pi-hole обновлён" if pwd else ""),
    )
    # Soft front path remarks (e.g. grpc path occupied) are unrelated to DoH — don't flash them
    if not xr.get("ok"):
        flash(request, f"DoH сохранены.{pwd_msg} Ошибка front/Xray: {xr.get('error')}".strip(), "error")
    else:
        flash(request, f"DoH настройки сохранены.{pwd_msg}".rstrip(), "info")
    return go("/doh")


@app.post("/doh/install")
def doh_install(request: Request):
    if redir := _require(request):
        return redir
    store = _load_store()
    pwd = str((store["settings"].get("doh") or {}).get("pihole_password") or "") or secrets.token_urlsafe(12)
    res = doh_mod.install_pihole(password=pwd)
    if res.get("ok"):
        with mutate() as st:
            st["settings"].setdefault("doh", {})["pihole_password"] = pwd
            st["settings"]["doh"]["enabled"] = True
            st["settings"]["doh"]["upstream"] = "127.0.0.1"
            st["settings"]["doh"]["upstream_port"] = doh_mod.PIHOLE_DNS_HOST_PORT
        _apply_xray(_load_store())
        extra = " Docker установлен автоматически." if res.get("docker_installed") else ""
        _tg_change(f"🛡 Pi-hole установлен на этой панели. DoH включён.{extra}")
        flash(request, f"Pi-hole установлен (docker). DoH включён.{extra}", "info")
    else:
        _tg_change(f"❌ Pi-hole install: {tgbot.escape(res.get('error') or 'fail')}")
        flash(request, f"Pi-hole install: {res.get('error')}", "error")
    return go("/doh")


@app.post("/doh/stop")
def doh_stop(request: Request):
    if redir := _require(request):
        return redir
    res = doh_mod.stop_pihole()
    if res.get("ok"):
        _tg_change("🛡 Pi-hole остановлен")
    flash(request, "Pi-hole остановлен" if res.get("ok") else f"stop: {res.get('error')}",
          "info" if res.get("ok") else "error")
    return go("/doh")


@app.post("/doh/pihole-link")
def doh_pihole_link(request: Request):
    """Create a single-use link that opens Pi-hole admin via reverse proxy."""
    if redir := _require(request):
        return redir
    ticket = doh_mod.create_pihole_ticket(by=str(_user(request) or ""))
    abs_url = f"{public_https_base()}{base_path()}{ticket['url_path']}"
    request.session["pihole_link"] = {
        "url": abs_url,
        "exp": ticket["exp"],
        "ttl_sec": ticket["ttl_sec"],
    }
    flash(request, "Одноразовая ссылка создана. Откройте её один раз — действует 15 минут.", "info")
    return go("/doh")


@app.post("/doh/pihole-session-end")
def doh_pihole_session_end(request: Request):
    if redir := _require(request):
        return redir
    request.session.pop("pihole_until", None)
    flash(request, "Сессия доступа к Pi-hole закрыта", "info")
    return go("/doh")


@app.api_route("/doh/{token}", methods=["GET", "POST"])
@app.api_route("/doh/{token}/dns-query", methods=["GET", "POST"])  # legacy alias, never shown in UI
async def doh_dns_query(token: str, request: Request):
    """RFC 8484 DoH — public URL is /{prefix}/{token} (no /dns-query in links)."""
    if not doh_mod.TOKEN_RE.match(token or ""):
        return Response(status_code=404)
    store = _load_store()
    cfg = store["settings"].get("doh") or {}
    if not cfg.get("enabled"):
        return Response(status_code=404)
    client = doh_mod.client_by_token(store, token)
    if not client:
        return Response(status_code=403)
    try:
        if request.method == "GET":
            raw = str(request.query_params.get("dns") or "").strip()
            if not raw:
                return Response("missing dns=", status_code=400)
            query = doh_mod.b64url_decode(raw)
        else:
            ctype = (request.headers.get("content-type") or "").split(";")[0].strip().lower()
            body = await request.body()
            if ctype in ("application/dns-message", "application/dns-message; charset=utf-8", ""):
                query = body
            else:
                return Response("unsupported content-type", status_code=415)
        answer = doh_mod.resolve_wire(
            query,
            upstream=str(cfg.get("upstream") or "127.0.0.1"),
            port=int(cfg.get("upstream_port") or doh_mod.PIHOLE_DNS_HOST_PORT),
            timeout=float(cfg.get("timeout_sec") or 4),
        )
    except Exception as exc:  # noqa: BLE001
        return Response(str(exc), status_code=502)
    try:
        peer = ""
        try:
            if request.client:
                peer = str(request.client.host or "")
        except Exception:
            peer = ""
        rip = doh_mod.request_client_ip(dict(request.headers), fallback=peer)
        doh_mod.record_doh_client(doh_mod.doh_client_label(client, rip))
    except Exception:
        pass
    return Response(answer, media_type="application/dns-message",
                    headers={"cache-control": "no-store", "access-control-allow-origin": "*"})


def _pihole_session_ok(request: Request) -> bool:
    """Panel login OR redeemed one-time link grants proxy access."""
    if _user(request):
        exp = request.session.get("exp", 0)
        if not exp or time.time() <= float(exp):
            return True
    try:
        return float(request.session.get("pihole_until") or 0) > time.time()
    except (TypeError, ValueError):
        return False


_PIHOLE_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host", "content-length",
    "content-encoding",  # urllib decompresses; don't re-advertise gzip
}


def _pihole_mount() -> str:
    return f"{base_path()}/pihole"


def _rewrite_set_cookie(value: str, mount: str) -> str:
    """Point Pi-hole cookies at the proxied path prefix."""
    parts = []
    for part in value.split(";"):
        p = part.strip()
        low = p.lower()
        if low.startswith("path="):
            raw = p.split("=", 1)[1].strip() or "/"
            if raw == "/":
                parts.append(f"Path={mount}/")
            elif not raw.startswith(mount):
                parts.append(f"Path={mount}{raw if raw.startswith('/') else '/' + raw}")
            else:
                parts.append(p)
        else:
            parts.append(p)
    return "; ".join(parts)


def _rewrite_location(value: str, mount: str, upstream: str) -> str:
    v = (value or "").strip()
    if not v:
        return v
    for prefix in (f"http://{upstream}", f"https://{upstream}", "http://127.0.0.1:8089", "http://localhost:8089"):
        if v.startswith(prefix):
            v = v[len(prefix):] or "/"
            break
    if v.startswith("/") and not v.startswith(mount + "/") and v != mount:
        return mount + v
    return v


def _rewrite_pihole_body(body: bytes, content_type: str, mount: str) -> bytes:
    ct = (content_type or "").lower()
    if not any(x in ct for x in ("text/html", "javascript", "json", "css", "text/plain")):
        return body
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return body
    repl = (
        ('"/admin', f'"{mount}/admin'),
        ("'/admin", f"'{mount}/admin"),
        ('"/api', f'"{mount}/api'),
        ("'/api", f"'{mount}/api"),
        ("`/admin", f"`{mount}/admin"),
        ("`/api", f"`{mount}/api"),
        ("url(/admin", f"url({mount}/admin"),
        ("url(/api", f"url({mount}/api"),
        ("url('/admin", f"url('{mount}/admin"),
        ('url("/admin', f'url("{mount}/admin'),
    )
    for a, b in repl:
        text = text.replace(a, b)
    return text.encode("utf-8")


def _proxy_pihole(request: Request, path: str) -> Response:
    if not _pihole_session_ok(request):
        # No scary plaintext banner — send anonymous visitors to login; admins already pass above
        return RedirectResponse(base_path() + "/login?next=/pihole/admin/", status_code=303)
    store = _load_store()
    cfg = {**doh_mod.default_settings(), **(store["settings"].get("doh") or {})}
    host, port = doh_mod.pihole_upstream(cfg)
    upstream = f"{host}:{port}"
    mount = _pihole_mount()
    rel = (path or "").lstrip("/")
    qs = request.url.query
    target = f"http://{upstream}/{rel}" + (f"?{qs}" if qs else "")

    headers: dict[str, str] = {}
    for k, v in request.headers.items():
        lk = k.lower()
        if lk in _PIHOLE_HOP:
            continue
        if lk.startswith("x-forwarded") or lk == "forwarded":
            continue
        if lk == "cookie":
            headers["Cookie"] = v
            continue
        headers[k] = v
    headers["Host"] = upstream
    headers["X-Forwarded-Prefix"] = mount
    headers["Accept-Encoding"] = "identity"

    body = None
    if request.method not in ("GET", "HEAD"):
        # Starlette caches body on sync routes via run_in_threadpool when called from async;
        # read via request.stream consumed already — use _body if present.
        body = getattr(request, "_body", None)

    req = UrlRequest(target, data=body, method=request.method, headers=headers)
    try:
        with urlopen(req, timeout=float(cfg.get("timeout_sec") or 30)) as resp:
            raw = resp.read()
            status = resp.status
            resp_headers = list(resp.headers.items())
            content_type = resp.headers.get("Content-Type") or ""
    except HTTPError as exc:
        raw = exc.read() if exc.fp else b""
        status = exc.code
        resp_headers = list(exc.headers.items()) if exc.headers else []
        content_type = (exc.headers.get("Content-Type") if exc.headers else "") or ""
    except URLError as exc:
        return PlainTextResponse(f"Pi-hole недоступен: {exc.reason}", status_code=502)
    except Exception as exc:
        return PlainTextResponse(f"Pi-hole proxy error: {exc}", status_code=502)

    raw = _rewrite_pihole_body(raw, content_type, mount)
    out_headers: dict[str, str] = {}
    set_cookies: list[str] = []
    for k, v in resp_headers:
        lk = k.lower()
        if lk in _PIHOLE_HOP:
            continue
        if lk == "location":
            out_headers["Location"] = _rewrite_location(v, mount, upstream)
        elif lk == "set-cookie":
            set_cookies.append(_rewrite_set_cookie(v, mount))
        elif lk == "content-type":
            out_headers["Content-Type"] = v
        elif lk not in ("content-length", "content-encoding"):
            out_headers[k] = v
    response = Response(content=raw, status_code=status, headers=out_headers)
    for sc in set_cookies:
        response.headers.append("Set-Cookie", sc)
    return response


@app.get("/pihole-gate/{token}")
def pihole_gate(token: str, request: Request):
    """Redeem one-time link → session cookie → redirect into proxied admin."""
    res = doh_mod.redeem_pihole_ticket(token)
    if not res.get("ok"):
        return HTMLResponse(
            "<!doctype html><meta charset=utf-8><title>Pi-hole</title>"
            f"<body style='font-family:system-ui;padding:2rem'><h1>Доступ закрыт</h1>"
            f"<p>{res.get('error') or 'ссылка недействительна'}</p>"
            f"<p class=dim>Создайте новую одноразовую ссылку в панели (DoH / Pi-hole).</p></body>",
            status_code=403,
        )
    request.session["pihole_until"] = time.time() + int(res.get("session_ttl") or doh_mod.PIHOLE_SESSION_TTL_SEC)
    return RedirectResponse(base_path() + "/pihole/admin/", status_code=303)


@app.api_route("/pihole", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
@app.api_route("/pihole/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
async def pihole_proxy(request: Request, path: str = ""):
    # Read body before thread offload (sync urllib proxy uses request._body)
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        request._body = await request.body()  # type: ignore[attr-defined]
    else:
        request._body = None  # type: ignore[attr-defined]
    return await run_in_threadpool(_proxy_pihole, request, path)


# ================================================================ settings

@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request):
    if redir := _require(request):
        return redir
    store = _load_store()
    tab = request.query_params.get("tab") or "panel"
    s = store["settings"]
    ctx: dict[str, Any] = {}
    if tab == "security" and not s["security"].get("totp_enabled"):
        secret = request.session.get("totp_pending") or totp.new_secret()
        request.session["totp_pending"] = secret
        totp_user = _user(request) or _admin().get("username") or "admin"
        uri = totp.otpauth_uri(secret, totp_user, app_title())
        ctx.update(totp_secret=secret, totp_qr=qr_svg(uri, 5))
    if tab in ("certs", "panel", "sub"):
        ctx["certs"] = ops.list_certs()
    if tab == "system":
        ctx["bbr"] = ops.bbr_status()
        ctx["store"] = store
        ctx["panel_releases"] = ops.panel_releases(20)
    if tab == "masterdns":
        md = masterdns_mod.ensure_settings(store)
        pub = str((s.get("panel") or {}).get("public_host") or "")
        md_name = str((s.get("panel") or {}).get("title") or "MasterDNS")
        md_link = masterdns_mod.share_link(md, name=md_name) if md.get("domain") else ""
        ctx["md"] = md
        ctx["md_status"] = masterdns_mod.service_status()
        ctx["md_hints"] = masterdns_mod.dns_setup_hints(md, public_ip=pub if front._is_ip(pub) else "")
        ctx["md_methods"] = masterdns_mod.ENCRYPTION_METHODS
        ctx["md_link"] = md_link
        ctx["md_qr"] = qr_svg(md_link, 5) if md_link else ""
    if tab == "tg":
        # Outbounds suitable for Telegram proxy (skip balancers/direct/block)
        skip = {"direct", "block", "dns-out", "api"}
        ctx["tg_outbounds"] = [
            {"tag": t["tag"], "label": t["label"]}
            for t in xray.selectable_outbound_tags(store)
            if t.get("tag") and t["tag"] not in skip and t.get("kind") != "balancer"
        ]
    new_token = request.session.pop("new_api_token", None)
    me = _admin_record_for_user(_user(request))
    return page(request, "settings.html", active="settings", tab=tab, s=s, admin=me, admins=admins.public_rows(),
                session_user=_user(request), new_token=new_token,
                jobs=sorted(ops.JOBS.items(), key=lambda kv: -kv[1]["started"])[:5],
                sub_running=SUB_SERVER.running, sub_error=SUB_SERVER.error, panel_tls_running=PANEL_TLS.running,
                panel_tls_error=PANEL_TLS.error, **ctx)


@app.get("/settings/versions", response_class=HTMLResponse)
def settings_versions_page(request: Request):
    if redir := _require(request):
        return redir
    return page(request, "settings_versions.html", active="settings", tab="versions",
                versions=shist.list_versions(60), detail=None, vid="")


@app.get("/settings/versions/{vid}", response_class=HTMLResponse)
def settings_version_detail(vid: str, request: Request):
    if redir := _require(request):
        return redir
    detail = shist.version_detail(vid, _load_store())
    if not detail:
        flash(request, "Версия не найдена", "error")
        return go("/settings/versions")
    return page(request, "settings_versions.html", active="settings", tab="versions",
                versions=shist.list_versions(60), detail=detail, vid=vid)


@app.post("/settings/versions/{vid}/restore")
def settings_version_restore(vid: str, request: Request):
    if redir := _require(request):
        return redir
    try:
        with mutate(history_section="rollback", history_note=f"restore {vid}") as store:
            shist.apply_snapshot(store, vid)
        result = _apply_xray(_load_store())
        _refresh_settings_cache()
        _tg_change(f"⏪ Откат к версии <code>{tgbot.escape(vid)}</code>")
        flash(request, *_ok_msg(f"Откат к {vid}", result))
    except Exception as exc:  # noqa: BLE001
        flash(request, f"Откат: {exc}", "error")
    return go(f"/settings/versions/{vid}")


@app.post("/settings/masterdns/install")
def settings_masterdns_install(request: Request):
    if redir := _require(request):
        return redir
    with mutate(history_section="masterdns", history_note="install l2x-dnsd") as store:
        masterdns_mod.ensure_settings(store)
        res = masterdns_mod.apply(store, install_bin=True)
    if res.get("ok"):
        msg = f"l2x-dnsd установлен: {res.get('binary') or 'ok'}"
        if not res.get("enabled"):
            msg += " — включите чекбокс «Включить сервер» и сохраните / Start"
        flash(request, msg, "info")
    else:
        flash(request, f"Install: {res.get('error') or res}", "error")
    return go("/settings?tab=masterdns")


@app.post("/settings/masterdns/start")
def settings_masterdns_start(request: Request):
    if redir := _require(request):
        return redir
    with mutate(history_section="masterdns", history_note="start l2x-dnsd") as store:
        masterdns_mod.ensure_settings(store)
        res = masterdns_mod.apply(store, install_bin=False, force_start=True)
    if res.get("ok") and res.get("active"):
        flash(request, "l2x-dnsd запущен", "info")
    else:
        flash(request, f"Start: {res.get('error') or 'не запустился'}", "error")
    return go("/settings?tab=masterdns")


@app.get("/settings/masterdns/client.zip")
def settings_masterdns_client_zip(request: Request):
    if redir := _require(request):
        return redir
    store = _load_store()
    md = masterdns_mod.ensure_settings(store)
    if not md.get("domain"):
        flash(request, "Сначала укажите tunnel domain", "error")
        return go("/settings?tab=masterdns")
    title = str((store.get("settings") or {}).get("panel", {}).get("title") or "MasterDNS")
    data = masterdns_mod.build_client_zip(md, name=title)
    return Response(
        content=data,
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="masterdns-client.zip"'},
    )


@app.get("/settings/masterdns/link")
def settings_masterdns_link(request: Request):
    if redir := _require(request):
        return redir
    store = _load_store()
    md = masterdns_mod.ensure_settings(store)
    title = str((store.get("settings") or {}).get("panel", {}).get("title") or "MasterDNS")
    link = masterdns_mod.share_link(md, name=title)
    if not link:
        return PlainTextResponse("not configured", status_code=404)
    return PlainTextResponse(link, media_type="text/plain; charset=utf-8")


@app.get("/sub/{token}/masterdns.zip")
def sub_masterdns_zip(token: str, request: Request):
    """Public subscription download of MasterDNS client pack (shared key MVP)."""
    store = _load_store()
    client = next((c for c in store.get("clients") or [] if c.get("token") == token), None)
    if not client or not client.get("enable", True):
        return PlainTextResponse("not found", status_code=404)
    md = masterdns_mod.ensure_settings(store)
    if not md.get("enabled") or not md.get("domain"):
        return PlainTextResponse("masterdns disabled", status_code=404)
    data = masterdns_mod.build_client_zip(md, name=str(client.get("email") or "MasterDNS"))
    return Response(
        content=data,
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="masterdns-client.zip"'},
    )


@app.get("/sub/{token}/masterdns.txt")
def sub_masterdns_link(token: str, request: Request):
    """Plain masterdns:// share link for subscription clients."""
    store = _load_store()
    client = next((c for c in store.get("clients") or [] if c.get("token") == token), None)
    if not client or not client.get("enable", True):
        return PlainTextResponse("not found", status_code=404)
    md = masterdns_mod.ensure_settings(store)
    if not md.get("enabled") or not md.get("domain"):
        return PlainTextResponse("masterdns disabled", status_code=404)
    link = masterdns_mod.share_link(md, name=str(client.get("email") or "MasterDNS"))
    if not link:
        return PlainTextResponse("not configured", status_code=404)
    return PlainTextResponse(link + "\n", media_type="text/plain; charset=utf-8")


@app.post("/settings/save")
async def settings_save(request: Request):
    if redir := _require(request):
        return redir
    form = await request.form()
    section = str(form.get("section") or "")
    with mutate(history_section=section or "settings", history_note="settings/save") as store:
        s = store["settings"]
        if section == "panel":
            p = s["panel"]
            p["title"] = str(form.get("title") or APP_NAME_DEFAULT)
            p["session_hours"] = _float(form.get("session_hours"), 12)
            p["timezone"] = str(form.get("timezone") or "UTC")
            p["lang"] = "en" if form.get("lang") == "en" else "ru"
            p["theme"] = "light" if form.get("theme") == "light" else "dark"
            p["base_path"] = _clean_base_path(form.get("base_path") or "") or p.get("base_path") or _new_base_path()
            host = front.normalize_host(str(form.get("public_host") or ""))
            if host and not (front.is_domain(host) or front._is_ip(host)):
                flash(request, "Публичный домен: укажите домен (рекомендуется) или IP", "error")
                return go("/settings?tab=panel")
            p["public_host"] = host
            extras: list[str] = []
            seen_hosts = {host} if host else set()
            for line in _split_lines(str(form.get("extra_hosts") or "")):
                h = front.normalize_host(line)
                if not h or h in seen_hosts:
                    continue
                if not (front.is_domain(h) or front._is_ip(h)):
                    flash(request, f"Доп. домен «{line}»: нужен домен или IP", "error")
                    return go("/settings?tab=panel")
                seen_hosts.add(h)
                extras.append(h)
            p["extra_hosts"] = extras
            # Dedicated panel TLS port is unused — everything is on nginx :443
            p["extra_listen"] = {"enabled": False, "port": 2053, "cert_file": "", "key_file": ""}
            s["sub"]["domain"] = host if front.is_domain(host) else s["sub"].get("domain", "")
            s["sub"]["server_enabled"] = False
        elif section == "sub":
            sub = s["sub"]
            primary = re.sub(r"[^A-Za-z0-9_-]", "", str(form.get("path") or "sub")) or "sub"
            aliases = []
            for line in _split_lines(str(form.get("path_aliases") or "")):
                a = re.sub(r"[^A-Za-z0-9_-]", "", line)
                if a and a != primary and a not in aliases and a.lower() not in BASE_PATH_RESERVED:
                    aliases.append(a)
            leg_ports: list[int] = []
            for part in re.split(r"[\s,;]+", str(form.get("legacy_ports") or "")):
                if not part.strip():
                    continue
                pnum = _int(part, 0)
                if 1 <= pnum <= 65535 and pnum not in (80, 443) and pnum not in leg_ports:
                    leg_ports.append(pnum)
            leg_tls: list[int] = []
            for part in re.split(r"[\s,;]+", str(form.get("legacy_tls_ports") or "")):
                if not part.strip():
                    continue
                pnum = _int(part, 0)
                if 1 <= pnum <= 65535 and pnum not in (80, 443) and pnum not in leg_tls:
                    leg_tls.append(pnum)
            leg_ports = [x for x in leg_ports if x not in leg_tls]
            jwt_list: list[str] = []
            for line in _split_lines(str(form.get("legacy_jwt_secrets") or "")):
                key = line.strip()
                if re.fullmatch(r"[A-Za-z0-9_\-]{16,128}", key) and key not in jwt_list:
                    jwt_list.append(key)
            sub.update({
                "enabled": form.get("enabled") == "1", "server_enabled": False,
                "listen": "127.0.0.1", "port": 2096,
                "path": primary,
                "path_aliases": aliases,
                "legacy_ports": leg_ports,
                "legacy_tls_ports": leg_tls,
                "legacy_jwt_secrets": jwt_list,
                "domain": front.public_domain({"settings": s}) or front.normalize_host(str(form.get("domain") or "")),
                "cert_file": "", "key_file": "", "update_hours": _int(form.get("update_hours"), 1),
                "title": str(form.get("title") or ""), "support_url": str(form.get("support_url") or ""),
                "announce": str(form.get("announce") or ""), "show_page": form.get("show_page") == "1",
                "json_fragment": str(form.get("json_fragment") or "").strip(),
                "json_noise": str(form.get("json_noise") or "").strip(),
                "json_mux": str(form.get("json_mux") or "").strip(),
                "hwid_required": form.get("hwid_required") == "1", "migrate_url": form.get("migrate_url") == "1",
                "hwid_fallback": form.get("hwid_fallback") if form.get("hwid_fallback") in hwid.FALLBACK_MODES else "device",
                "happ_provider_id": str(form.get("happ_provider_id") or "").strip(),
                "hide_unhealthy": form.get("hide_unhealthy") == "1",
                "max_loss_pct": max(0, min(100, _int(form.get("max_loss_pct"), 20))),
            })
        elif section == "webhooks":
            wh = webhooks.ensure(s)
            wh["enabled"] = form.get("enabled") == "1"
            wh["secret"] = str(form.get("secret") or "").strip()
            safe_urls = []
            for u in _split_lines(str(form.get("urls") or "")):
                if not u.startswith("http"):
                    continue
                try:
                    safe_urls.append(sec.validate_outbound_url(u, allow_http=True))
                except ValueError as exc:
                    flash(request, f"Webhook URL отклонён: {exc}", "error")
                    return go("/settings?tab=webhooks")
            wh["urls"] = safe_urls
            wh["events"] = [e for e in webhooks.EVENTS if form.get(f"ev_{e}") == "1"] or list(webhooks.EVENTS)
        elif section == "nodes":
            ns = s.setdefault("nodes", {})
            ns["allow_master_manage"] = form.get("allow_master_manage") == "1"
            want_agent = form.get("agent_enabled") == "1"
            ns["agent_enabled"] = want_agent
            # Manual off is sticky: only an explicit uncheck turns Agent API off.
            # Enabling API must NEVER demote a master to agent (role stays).
            if want_agent:
                ns["agent_manual_off"] = False
                role = (ns.get("role") or "master").strip() or "master"
                if role != "master":
                    ns["role"] = "agent"
            else:
                ns["agent_manual_off"] = True
                if (ns.get("role") or "") == "agent":
                    ns["role"] = "master"
            if form.get("regen_token") == "1" or not ns.get("agent_token"):
                new_tok = secrets.token_urlsafe(32)
                _set_agent_token(ns, new_tok)
                request.session["_new_agent_token"] = new_tok
            elif not ns.get("agent_token_hash"):
                _set_agent_token(ns, ns["agent_token"])
        elif section == "tg":
            tg = s["tg"]
            new_token = str(form.get("token") or "").strip()
            # Password field: empty means "keep previous token"
            if not new_token:
                new_token = str(tg.get("token") or "")
            raw_admins = str(form.get("admin_ids") or "")
            admin_ids: list[str] = []
            seen: set[str] = set()
            for part in re.split(r"[\s,;]+", raw_admins):
                aid = part.strip().lstrip("@")
                if not aid or aid in seen:
                    continue
                seen.add(aid)
                admin_ids.append(aid)
            prev_proxy = dict(tg.get("proxy") or {})
            ptype = str(form.get("proxy_type") or "socks5").strip().lower()
            if ptype not in ("http", "socks5", "socks4", "outbound"):
                ptype = "socks5"
            new_proxy_pass = str(form.get("proxy_password") or "")
            # Empty password field keeps previous (same UX as bot token)
            if new_proxy_pass == "" and prev_proxy.get("password") and not str(form.get("proxy_url") or "").strip():
                new_proxy_pass = str(prev_proxy.get("password") or "")
            proxy = {
                "enabled": form.get("proxy_enabled") == "1",
                "type": ptype,
                "url": str(form.get("proxy_url") or "").strip(),
                "host": str(form.get("proxy_host") or "").strip(),
                "port": _int(form.get("proxy_port"), int(prev_proxy.get("port") or 1080)),
                "user": str(form.get("proxy_user") or "").strip(),
                "password": new_proxy_pass,
                "outbound": str(form.get("proxy_outbound") or "").strip(),
            }
            if proxy["url"] and ptype != "outbound":
                parsed = tgbot.parse_proxy_url(proxy["url"])
                if parsed.get("host"):
                    proxy["type"] = parsed.get("type") or ptype
                    proxy["host"] = parsed["host"]
                    proxy["port"] = int(parsed.get("port") or proxy["port"] or 1080)
                    if parsed.get("user"):
                        proxy["user"] = parsed["user"]
                    if parsed.get("password"):
                        proxy["password"] = parsed["password"]
            tg.update({
                "enabled": form.get("enabled") == "1", "token": new_token,
                "admin_ids": admin_ids,
                "receive_commands": form.get("receive_commands") == "1",
                "notify_login": form.get("notify_login") == "1", "notify_quota": form.get("notify_quota") == "1",
                "notify_iplimit": form.get("notify_iplimit") == "1",
                "notify_nodes": form.get("notify_nodes") == "1",
                "notify_changes": form.get("notify_changes") == "1",
                "notify_updates": form.get("notify_updates") == "1",
                "notify_expire_days": _float(form.get("notify_expire_days"), 3),
                "cpu_threshold": _float(form.get("cpu_threshold"), 85), "report_hours": _float(form.get("report_hours"), 24),
                "backup_hours": _float(form.get("backup_hours"), 24),
                "proxy": proxy,
            })
        elif section == "backup":
            # Schedule lives under settings.tg (same field as Telegram tab)
            tg = s.setdefault("tg", {})
            tg["backup_hours"] = _float(form.get("backup_hours"), float(tg.get("backup_hours") or 24))
        elif section == "iplimit":
            s["iplimit"]["ban_minutes"] = _int(form.get("ban_minutes"), 30)
        elif section == "masterdns":
            md = masterdns_mod.ensure_settings(store)
            md["enabled"] = form.get("enabled") == "1"
            md["domain"] = str(form.get("domain") or "").strip().lower().rstrip(".")
            md["ns_hostname"] = str(form.get("ns_hostname") or "").strip().lower().rstrip(".")
            md["ns_ip"] = str(form.get("ns_ip") or "").strip()
            md["listen"] = str(form.get("listen") or ":53").strip() or ":53"
            method = _int(form.get("encryption_method"), int(md.get("encryption_method") or 2))
            if method not in masterdns_mod.ENCRYPTION_METHODS:
                method = 2
            md["encryption_method"] = method
            if form.get("regen_key") == "1":
                md["encryption_key"] = masterdns_mod.generate_key(method)
            else:
                key = str(form.get("encryption_key") or "").strip()
                if key:
                    md["encryption_key"] = key
            resolvers = []
            for line in _split_lines(str(form.get("resolvers") or "")):
                line = line.strip()
                if line:
                    resolvers.append(line)
            md["resolvers"] = resolvers or list(masterdns_mod.DEFAULT_RESOLVERS)
            md["client_listen_ip"] = str(form.get("client_listen_ip") or "127.0.0.1").strip() or "127.0.0.1"
            md["client_listen_port"] = _int(form.get("client_listen_port"), 18000)
            md["protocol_type"] = "SOCKS5"
            apply_res = masterdns_mod.apply(store, install_bin=False)
            request.session["_masterdns_apply"] = apply_res
    _refresh_settings_cache()
    _sync_servers()
    if section == "tg":
        # Force restart so token/enabled/admin_ids/proxy take effect immediately
        BOT.restart()
    _tg_change(f"⚙️ Настройки: секция <b>{tgbot.escape(section)}</b> сохранена")
    if section in ("panel", "sub"):
        flash(request, *_ok_msg(
            "Настройки сохранены, nginx/front обновлён" if section == "sub" else "Настройки сохранены, HTTPS :443 обновлён",
            _apply_xray(_load_store()),
        ))
    elif section == "tg":
        # Always refresh Xray so l2x-tg-proxy SOCKS appears/disappears with outbound mode.
        flash(request, *_ok_msg("Настройки сохранены", _apply_xray(_load_store(), xray_only=True)))
    elif section == "nodes":
        shown = str(request.session.pop("_new_agent_token", "") or "")
        if shown:
            flash(request, f"Новый agent token (скопируйте сейчас): {shown}", "info")
        else:
            flash(request, "Настройки сохранены", "info")
    elif section == "masterdns":
        apply_res = request.session.pop("_masterdns_apply", {}) or {}
        if apply_res.get("ok"):
            flash(request, "MasterDNS сохранён и применён", "info")
        else:
            flash(request, f"MasterDNS сохранён, apply: {apply_res.get('error') or apply_res}", "warn")
    else:
        flash(request, "Настройки сохранены", "info")
    return go(f"/settings?tab={section}")


@app.post("/settings/admins/add")
def settings_admins_add(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    current: str = Form(...),
):
    if redir := _require(request):
        return redir
    if not _verify_current_password(request, current):
        flash(request, "Текущий пароль неверный", "error")
        return go("/settings?tab=security")
    ok, err = admins.add_admin(username.strip(), password)
    if not ok:
        flash(request, err or "Не удалось добавить", "error")
        return go("/settings?tab=security")
    _tg_change(f"➕ Администратор <b>{tgbot.escape(username.strip())}</b> добавлен")
    flash(request, f"Администратор {username.strip()} добавлен", "info")
    return go("/settings?tab=security")


@app.post("/settings/admins/{admin_id}/remove")
def settings_admins_remove(admin_id: str, request: Request, current: str = Form(...)):
    if redir := _require(request):
        return redir
    if not _verify_current_password(request, current):
        flash(request, "Текущий пароль неверный", "error")
        return go("/settings?tab=security")
    target = admins.get_by_id(admin_id)
    if not target:
        flash(request, "Администратор не найден", "error")
        return go("/settings?tab=security")
    me = _user(request)
    if me and secrets.compare_digest(str(me), target.get("username") or ""):
        flash(request, "Сначала смените пароль в «Моя учётная запись» или попросите другого админа удалить вас", "error")
        return go("/settings?tab=security")
    ok, err = admins.delete_admin(admin_id)
    if not ok:
        flash(request, err or "Не удалось удалить", "error")
        return go("/settings?tab=security")
    _tg_change(f"➖ Администратор <b>{tgbot.escape(target.get('username') or '?')}</b> удалён")
    flash(request, "Администратор удалён", "info")
    return go("/settings?tab=security")


@app.post("/settings/account")
def settings_account(request: Request, username: str = Form(...), current: str = Form(...), new_password: str = Form("")):
    if redir := _require(request):
        return redir
    rec = _admin_record_for_user(_user(request))
    if not rec or not rec.get("id"):
        flash(request, "Учётная запись не найдена", "error")
        return go("/settings?tab=security")
    if not _verify_current_password(request, current):
        flash(request, "Текущий пароль неверный", "error")
        return go("/settings?tab=security")
    old_user = rec["username"]
    username = username.strip() or old_user
    ok, err, updated = admins.update_account(
        rec["id"],
        username=username,
        new_password=new_password or None,
    )
    if not ok:
        flash(request, err or "Ошибка сохранения", "error")
        return go("/settings?tab=security")
    pwd_changed = bool(new_password)
    username = (updated or rec).get("username") or username
    request.session["user"] = username
    tgbot.bind_actor(username, _client_ip(request))
    bits = []
    if username != old_user:
        bits.append(f"логин {tgbot.escape(old_user)} → <b>{tgbot.escape(username)}</b>")
    if pwd_changed:
        bits.append("пароль изменён")
    _tg_change("🔑 Учётные данные панели обновлены", " · ".join(bits) or "без смены логина/пароля")
    flash(request, "Учётные данные обновлены", "info")
    return go("/settings?tab=security")


@app.post("/settings/totp/{action}")
def settings_totp(action: str, request: Request, code: str = Form("")):
    if redir := _require(request):
        return redir
    with mutate() as store:
        sec = store["settings"]["security"]
        if action == "enable":
            secret = request.session.get("totp_pending") or ""
            if not totp.verify(secret, code):
                flash(request, "Неверный код — 2FA не включена", "error")
                return go("/settings?tab=security")
            sec["totp_secret"], sec["totp_enabled"] = secret, True
            request.session.pop("totp_pending", None)
        elif action == "disable":
            if not totp.verify(sec.get("totp_secret") or "", code):
                flash(request, "Неверный код", "error")
                return go("/settings?tab=security")
            sec["totp_secret"], sec["totp_enabled"] = "", False
    _refresh_settings_cache()
    flash(request, f"2FA {'включена' if action == 'enable' else 'выключена'}", "info")
    return go("/settings?tab=security")


@app.post("/settings/api-token/{action}")
async def settings_api_token(action: str, request: Request):
    if redir := _require(request):
        return redir
    form = await request.form()
    name = str(form.get("name") or "")
    token_id = str(form.get("token_id") or "")
    with mutate() as store:
        tokens = store["settings"]["api_tokens"]
        if action == "create":
            scopes = []
            for key, _label in sec.API_SCOPE_CHOICES:
                if form.get(f"scope_{key}") == "1":
                    scopes.append(key)
            if not scopes:
                scopes = ["read", "clients"]
            if "admin" in scopes:
                scopes = ["admin"]
            raw = "l2x_" + secrets.token_urlsafe(32)
            tokens.append({
                "id": secrets.token_hex(4), "name": name.strip() or "token",
                "hash": _hash_token(raw), "last4": raw[-4:],
                "created": xray.now_utc().isoformat(),
                "scopes": scopes,
            })
            request.session["new_api_token"] = raw
        elif action == "delete":
            store["settings"]["api_tokens"] = [x for x in tokens if x["id"] != token_id]
    _refresh_settings_cache()
    return go("/settings?tab=api")


@app.post("/settings/cert")
def settings_cert(request: Request, domain: str = Form(...), email: str = Form("")):
    if redir := _require(request):
        return redir
    ops.start_job("acme", ops.issue_cert, domain, email)
    flash(request, f"Выпуск сертификата для {domain} запущен (1–2 мин)", "info")
    return go("/settings?tab=certs")


@app.post("/settings/bbr")
def settings_bbr(request: Request, enable: str = Form("1")):
    if redir := _require(request):
        return redir
    r = ops.bbr_set(enable == "1")
    flash(request, f"BBR: {r['congestion']} / {r['qdisc']}", "info" if r["ok"] else "error")
    return go("/settings?tab=system")


@app.post("/settings/speedtest")
def settings_speedtest(request: Request):
    if redir := _require(request):
        return redir
    r = ops.speedtest()
    flash(request, f"Speedtest: {r.get('mbps')} Mbit/s" if r["ok"] else f"Speedtest: {r.get('error')}", "info" if r["ok"] else "error")
    return go("/settings?tab=system")


@app.get("/backup/download")
def backup_download(request: Request):
    if redir := _require(request):
        return redir
    name, blob = _tg_backup()
    return Response(blob, media_type="application/zip", headers={"content-disposition": f'attachment; filename="{name}"'})


@app.post("/backup/telegram")
def backup_telegram(request: Request):
    if redir := _require(request):
        return redir
    res = _send_backup_to_telegram(caption="Бэкап L2X Panel", scheduled=False)
    if res.get("ok"):
        with mutate() as st:
            tg = st.setdefault("settings", {}).setdefault("tg", {})
            tg["last_backup_at"] = time.time()
            tg["last_backup_name"] = res.get("name") or ""
            tg["last_backup_ok"] = True
            tg["last_backup_error"] = ""
        _refresh_settings_cache()
        flash(request, f"Бэкап отправлен в Telegram и удалён с сервера ({res.get('name')})", "info")
    else:
        flash(request, f"Бэкап в Telegram: {res.get('error') or 'ошибка'}", "error")
    return go("/settings?tab=backup")


@app.post("/backup/restore")
async def backup_restore(request: Request, file: UploadFile = File(...)):
    if redir := _require(request):
        return redir
    blob = await file.read()
    with STORE_LOCK:
        res = ops.restore_backup(DATA, blob)
    if not res["ok"]:
        flash(request, f"Восстановление: {res['error']}", "error")
        return go("/settings?tab=backup")
    _refresh_settings_cache()
    xr = _apply_xray(_load_store())
    restored = res.get("restored") or {}
    detail = (
        f"data={restored.get('data', '?')}, certs={restored.get('certs', 0)}, "
        f"doh={restored.get('doh', 0)}"
    )
    msg = f"Бэкап восстановлен ({detail}; копия до: {res['safety_copy']})"
    if res.get("doh_warning"):
        msg += f". DoH: {res['doh_warning']}"
    flash(request, *_ok_msg(msg, xr))
    return go("/settings?tab=backup")


@app.get("/jobs/{job_id}")
def job_status(job_id: str, request: Request):
    if not _user(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return ops.JOBS.get(job_id) or {"status": "unknown"}


# ================================================================ REST API (/panel/api)

def _api_auth(request: Request) -> dict | None:
    """Return token record (or session stub) on success, else None."""
    if _user(request):
        return {"id": "session", "name": "session", "scopes": ["admin"]}
    auth = request.headers.get("authorization") or ""
    token = auth[7:].strip() if auth.lower().startswith("bearer ") else (request.headers.get("x-api-key") or "")
    if not token:
        return None
    h = _hash_token(token)
    for x in (SETTINGS_CACHE.get("api_tokens") or []):
        if sec.token_eq(h, x.get("hash") or ""):
            return x
    return None


def _api_err(msg: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "msg": msg}, status_code=code)


def _api_ok(obj: Any = None, msg: str = "") -> dict:
    return {"success": True, "msg": msg, "obj": obj}


def _public_client(store: dict, c: dict) -> dict:
    return {
        "email": c["email"], "uuid": c["uuid"], "enabled": c.get("enabled", True), "status": xray.client_status(c),
        "outbound": c.get("outbound"), "inbounds": [i["tag"] for i in xray.client_inbounds(store, c)],
        "limit_gb": c.get("limit_gb"), "daily_limit_gb": c.get("daily_limit_gb"),
        "expire_at": c.get("expire_at"), "limit_ip": c.get("limit_ip"),
        "limit_hwid": c.get("limit_hwid"), "hwid": hwid.status(c),
        "up": c["traffic"].get("up"), "down": c["traffic"].get("down"),
        "daily_used": xray.client_daily_used_bytes(c),
        "online": c["email"] in ONLINE,
        "last_online": c.get("last_online"), "comment": c.get("comment"), "tg_id": c.get("tg_id"),
        "tg_username": c.get("tg_username"), "tg_fio": c.get("tg_fio"),
        "tg_first_name": c.get("tg_first_name"), "tg_last_name": c.get("tg_last_name"),
        "sub_url": sub_url(c), "reset_period": c.get("reset_period"),
        "outbound_limits": c.get("outbound_limits"),
        "daily_outbound_limits": c.get("daily_outbound_limits"),
        "on_expire": c.get("on_expire"), "on_quota": c.get("on_quota"),
        "allowed_tags": c.get("allowed_tags"),
        "group_id": c.get("group_id") or "",
    }


API_CLIENT_FIELDS = (
    "outbound", "enabled", "limit_gb", "daily_limit_gb", "expire_at", "limit_ip", "limit_hwid", "comment", "tg_id",
    "inbounds", "reset_period", "renew_on_reset", "start_on_first_use", "duration_days", "allowed_tags",
    "outbound_limits", "daily_outbound_limits", "on_expire", "on_quota", "sub_enabled", "group_id",
)


def _api_apply_client(store: dict, c: dict, data: dict) -> str | None:
    for key in API_CLIENT_FIELDS:
        if key in data:
            c[key] = data[key]
    if c.get("outbound") not in _allowed_outbounds(store):
        return f"unknown outbound {c.get('outbound')}"
    if c.get("group_id") and not xray.get_group(store, c.get("group_id")):
        return f"unknown group_id {c.get('group_id')}"
    if c.get("expire_at") and not xray.parse_expire_at(c["expire_at"]):
        return "bad expire_at"
    if c.get("on_expire") not in xray.LIMIT_ACTIONS:
        c["on_expire"] = "block"
    if c.get("on_quota") not in xray.LIMIT_ACTIONS:
        c["on_quota"] = "block"
    return None


@app.api_route("/panel/api/{path:path}", methods=["GET", "POST", "DELETE"])
async def rest_api(path: str, request: Request):
    tok = _api_auth(request)
    if not tok:
        return _api_err("unauthorized", 401)
    ip = _client_ip(request)
    tid = str(tok.get("id") or "tok")
    if not sec.API_LIMITER.allow(f"api:{tid}:{ip}", limit=120, window_sec=60):
        return _api_err("rate limited", 429)
    try:
        data = await request.json() if request.method == "POST" and (request.headers.get("content-type") or "").startswith("application/json") else {}
    except ValueError:
        return _api_err("bad json")
    parts = [p for p in path.split("/") if p]
    scopes = tok.get("scopes")
    if not sec.scope_allows(scopes, parts):
        return _api_err(f"forbidden: need scope '{sec.required_scope(parts)}'", 403)
    store = _load_store()
    if parts == ["server", "status"]:
        return _api_ok({**sysmon.snapshot(), "xray": xray.xray_status(), "online": len(ONLINE)})
    if parts == ["inbounds", "list"]:
        return _api_ok([{**i, "used": xray.inbound_used_bytes(i)} for i in store["inbounds"]])
    if len(parts) == 3 and parts[:2] == ["inbounds", "get"]:
        ib = xray.inbound_by_id(store, _int(parts[2]))
        return _api_ok(ib) if ib else _api_err("not found", 404)
    if parts == ["inbounds", "onlines"]:
        return _api_ok(ONLINE)
    if parts == ["clients", "list"]:
        return _api_ok([_public_client(store, c) for c in store["clients"]])
    if len(parts) == 3 and parts[:2] == ["clients", "get"]:
        c = next((x for x in store["clients"] if x["email"] == parts[2]), None)
        return _api_ok(_public_client(store, c)) if c else _api_err("not found", 404)
    if parts == ["clients", "add"] and request.method == "POST":
        email = str(data.get("email") or "").strip()
        with mutate() as st:
            if not xray.EMAIL_RE.match(email) or any(x["email"] == email for x in st["clients"]):
                return _api_err("bad or duplicate email")
            c = xray.ensure_client({"email": email, "sub_token": secrets.token_urlsafe(18)})
            if data.get("uuid"):
                c["uuid"] = str(data["uuid"])
            err = _api_apply_client(st, c, data)
            if err:
                return _api_err(err)
            st["clients"].append(c)
            xray.ensure_wg_peer(st, c)
        res = _apply_xray(_load_store(), xray_only=True)
        return _api_ok(_public_client(_load_store(), c), res.get("error", ""))
    if len(parts) == 3 and parts[:2] == ["clients", "update"] and request.method == "POST":
        with mutate() as st:
            c = next((x for x in st["clients"] if x["email"] == parts[2]), None)
            if not c:
                return _api_err("not found", 404)
            err = _api_apply_client(st, c, data)
            if err:
                return _api_err(err)
        res = _apply_xray(_load_store(), xray_only=True)
        return _api_ok(_public_client(_load_store(), c), res.get("error", ""))
    if len(parts) == 3 and parts[0] == "clients" and parts[1] in ("delete", "reset") and request.method in ("POST", "DELETE"):
        with mutate() as st:
            c = next((x for x in st["clients"] if x["email"] == parts[2]), None)
            if not c:
                return _api_err("not found", 404)
            if parts[1] == "delete":
                st["clients"].remove(c)
            else:
                xray.reset_client_traffic(c)
        _apply_xray(_load_store(), xray_only=True)
        return _api_ok(None, f"{parts[1]} ok")
    if parts == ["clients", "resetAll"] and request.method == "POST":
        with mutate() as st:
            for c in st["clients"]:
                xray.reset_client_traffic(c)
        _apply_xray(_load_store(), xray_only=True)
        return _api_ok(None, "reset all")
    if parts == ["outbounds", "list"]:
        return _api_ok({"tags": xray.all_outbound_tags(store), "traffic": store.get("outbound_traffic") or {},
                        "rates": OB_STATS.rates, "summary_1h": OB_STATS.summary(60), "summary_24h": OB_STATS.summary(1440)})
    if parts == ["xray", "restart"] and request.method == "POST":
        return _api_ok(ops.xray_control("restart"))
    if parts == ["xray", "config"]:
        return _api_ok(xray.build_config(store))
    if parts == ["backup"]:
        name, blob = _tg_backup()
        return Response(blob, media_type="application/zip", headers={"content-disposition": f'attachment; filename="{name}"'})
    if len(parts) == 3 and parts[0] == "clients" and parts[2] == "hwids":
        c = next((x for x in store["clients"] if x["email"] == parts[1]), None)
        if not c:
            return _api_err("not found", 404)
        if request.method == "DELETE":
            with mutate() as st:
                cc = next((x for x in st["clients"] if x["email"] == parts[1]), None)
                n = hwid.clear(cc) if cc else 0
            return _api_ok({"cleared": n})
        return _api_ok(hwid.public_list(c))
    return _api_err("unknown endpoint", 404)


# ================================================================ nodes / agent

NODES_JOB: dict[str, str] = {}
NODES_SCHED_LOCK = threading.Lock()

# Serial panel-update queue: never update multiple nodes at once (avoids cluster-wide outage).
_NODE_UPD_LOCK = threading.Lock()
_NODE_UPD: dict[str, Any] = {
    "pending": [],       # [{id, name, via, ssh_password, enqueued_at}]
    "current": None,     # {id, name, via, started_at, status} or None
    "history": [],       # last ~20 [{id, name, ok, error, version, finished_at}]
    "worker": False,
}


def node_update_queue_snapshot() -> dict:
    with _NODE_UPD_LOCK:
        return {
            "pending": list(_NODE_UPD["pending"]),
            "current": dict(_NODE_UPD["current"]) if _NODE_UPD["current"] else None,
            "history": list(_NODE_UPD["history"][-12:]),
            "busy": bool(_NODE_UPD["current"]) or bool(_NODE_UPD["pending"]),
        }


def _node_upd_set_status(node_id: str, status: str, **extra) -> None:
    with mutate() as st:
        for n in nodes_mod.ensure_list(st):
            if n.get("id") != node_id:
                continue
            n["update_queue_status"] = status
            for k, v in extra.items():
                if v is not None:
                    n[k] = v
            break


def enqueue_node_update(
    node_id: str,
    *,
    name: str = "",
    ssh_password: str = "",
    via: str = "",
) -> dict:
    """Add node to serial update queue. Returns {ok, queued, position, error}."""
    with _NODE_UPD_LOCK:
        cur = _NODE_UPD["current"] or {}
        if cur.get("id") == node_id:
            return {"ok": True, "queued": False, "already": "running", "position": 0}
        for i, item in enumerate(_NODE_UPD["pending"]):
            if item.get("id") == node_id:
                return {"ok": True, "queued": True, "already": "pending", "position": i + 1}
        via = via or ("SSH" if ssh_password else "agent")
        _NODE_UPD["pending"].append({
            "id": node_id,
            "name": name or node_id[:8],
            "via": via,
            "ssh_password": ssh_password or "",
            "enqueued_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        })
        pos = len(_NODE_UPD["pending"])
        start_worker = not _NODE_UPD["worker"]
        if start_worker:
            _NODE_UPD["worker"] = True
    _node_upd_set_status(node_id, "queued")
    if start_worker:
        threading.Thread(target=_node_update_worker, daemon=True, name="node-upd-queue").start()
    return {"ok": True, "queued": True, "position": pos}


def enqueue_outdated_nodes(*, master_ver: str) -> dict:
    """Enqueue all enabled nodes whose panel_version differs from master."""
    store = _load_store()
    if not nodes_mod.is_master(store):
        return {"ok": False, "error": "not master", "added": 0}
    mv = str(master_ver or panel_version()).lstrip("vV")
    added = 0
    skipped = 0
    for n in nodes_mod.ensure_list(store):
        if not n.get("enabled", True):
            continue
        # Go tunnel-only agents have no panel /agent/pull — skip NAT update queue.
        if nodes_mod.is_tunnel_only_node(n):
            skipped += 1
            continue
        nv = str(n.get("panel_version") or "").lstrip("vV")
        if nv and mv and nv == mv:
            skipped += 1
            continue
        r = enqueue_node_update(n["id"], name=str(n.get("name") or ""), via="agent" if not n.get("nat") else "NAT-pull")
        if r.get("queued") and not r.get("already"):
            added += 1
        else:
            skipped += 1
    return {"ok": True, "added": added, "skipped": skipped}


def _run_one_node_update(item: dict) -> dict:
    """Execute a single node panel update and wait until version settles (or timeout)."""
    import time as _time
    node_id = item["id"]
    ssh_password = item.get("ssh_password") or ""
    store = _load_store()
    node = next((n for n in nodes_mod.ensure_list(store) if n.get("id") == node_id), None)
    if not node:
        return {"ok": False, "error": "node gone", "name": item.get("name")}
    name = node.get("name") or item.get("name") or node_id[:8]
    node_copy = dict(node)
    before = str(node_copy.get("panel_version") or "")

    # Pure Go L2X agent: no panel binary / no /agent/pull — cannot NAT-update.
    if nodes_mod.is_tunnel_only_node(node_copy):
        with mutate() as st:
            for n in nodes_mod.ensure_list(st):
                if n.get("id") != node_id:
                    continue
                n.pop("update_requested", None)
                n["update_queue_status"] = "ok"
                n["last_error"] = ""
                n["last_warning"] = "L2X tunnel-agent: панель не обновляется через NAT pull (бинарь отдельно)"
                n["panel_version"] = n.get("panel_version") or "l2x-tunnel-agent"
                nodes_mod.refresh_tunnel_only_health(st, [n])
                break
        return {
            "ok": True, "error": "", "version": before or "l2x-tunnel-agent",
            "name": name, "before": before, "skipped": True, "tunnel_only": True,
        }

    if node_copy.get("nat"):
        with mutate() as st:
            for n in nodes_mod.ensure_list(st):
                if n.get("id") == node_id:
                    n["update_requested"] = True
                    break
        # Wait until pull clears the flag / version changes (≤ ~3 min)
        last_ver = before
        ok = False
        err = ""
        for i in range(36):
            _time.sleep(5)
            st = _load_store()
            live = next((n for n in nodes_mod.ensure_list(st) if n.get("id") == node_id), None)
            if not live:
                err = "node removed"
                break
            if not live.get("update_requested"):
                last_ver = str(live.get("panel_version") or last_ver)
                ok = True
                break
            last_ver = str(live.get("panel_version") or last_ver)
            if last_ver and before and last_ver != before:
                ok = True
                break
        else:
            err = "таймаут ожидания NAT pull update"
        with mutate() as st:
            for n in nodes_mod.ensure_list(st):
                if n.get("id") != node_id:
                    continue
                if last_ver:
                    n["panel_version"] = last_ver
                n["update_queue_status"] = "ok" if ok else "failed"
                if ok:
                    n["last_update"] = nodes_mod.now_iso()
                    n["last_error"] = ""
                else:
                    n["last_error"] = err
                break
        return {"ok": ok, "error": err, "version": last_ver, "name": name, "before": before}

    # Reachable node: agent API or SSH
    if ssh_password:
        res = nodes_mod.update_via_ssh(node_copy, ssh_password=ssh_password)
    else:
        res = nodes_mod.trigger_update(node_copy)
        if res.get("ok") and (res.get("started") or res.get("already")):
            before = str(res.get("current") or before or "")
            last_ver = before
            for i in range(24):
                _time.sleep(5 if i else 12)
                probe = nodes_mod.probe_health(node_copy, timeout=8)
                if not probe.get("ok"):
                    continue
                last_ver = str(probe.get("version") or last_ver)
                if last_ver and last_ver != before:
                    break
            if last_ver:
                node_copy["panel_version"] = last_ver
            res = dict(res)
            res["version"] = last_ver or res.get("version") or ""
    ok = bool(res.get("ok"))
    ver = str(node_copy.get("panel_version") or res.get("version") or "")
    with mutate() as st:
        for n in nodes_mod.ensure_list(st):
            if n.get("id") != node_id:
                continue
            if ver:
                n["panel_version"] = ver
            if node_copy.get("last_update"):
                n["last_update"] = node_copy["last_update"]
            elif ok:
                n["last_update"] = nodes_mod.now_iso()
            n["update_queue_status"] = "ok" if ok else "failed"
            if ok:
                n["last_error"] = ""
                n["last_ok"] = True
            else:
                n["last_error"] = str(res.get("error") or node_copy.get("last_error") or "update failed")
            break
    return {
        "ok": ok,
        "error": "" if ok else (res.get("error") or "update failed"),
        "version": ver,
        "name": name,
        "before": before,
        "log": res.get("log") or "",
    }


def _node_update_worker() -> None:
    """Process `_NODE_UPD["pending"]` one-by-one."""
    try:
        while True:
            with _NODE_UPD_LOCK:
                if not _NODE_UPD["pending"]:
                    _NODE_UPD["current"] = None
                    _NODE_UPD["worker"] = False
                    return
                item = _NODE_UPD["pending"].pop(0)
                _NODE_UPD["current"] = {
                    "id": item["id"],
                    "name": item.get("name"),
                    "via": item.get("via"),
                    "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "status": "running",
                }
            _node_upd_set_status(item["id"], "running")
            try:
                result = _run_one_node_update(item)
            except Exception as exc:  # noqa: BLE001
                result = {"ok": False, "error": str(exc), "name": item.get("name"), "version": ""}
                _node_upd_set_status(item["id"], "failed", last_error=str(exc))
            finished = {
                "id": item["id"],
                "name": result.get("name") or item.get("name"),
                "ok": bool(result.get("ok")),
                "error": result.get("error") or "",
                "version": result.get("version") or "",
                "before": result.get("before") or "",
                "via": item.get("via"),
                "finished_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            }
            with _NODE_UPD_LOCK:
                _NODE_UPD["history"] = (_NODE_UPD["history"] + [finished])[-20:]
                _NODE_UPD["current"] = None
            name = finished["name"]
            if finished["ok"]:
                ver_s = f" → v{tgbot.escape(finished['version'])}" if finished["version"] else ""
                _tg_admin(
                    f"⬆️ Нода <b>{tgbot.escape(name)}</b>: обновление OK{ver_s}",
                    flag="notify_nodes",
                )
            else:
                _tg_admin(
                    f"❌ Нода <b>{tgbot.escape(name)}</b>: обновление — "
                    f"{tgbot.escape(finished['error'] or 'fail')}",
                    flag="notify_nodes",
                )
    finally:
        with _NODE_UPD_LOCK:
            _NODE_UPD["worker"] = False
            _NODE_UPD["current"] = None


def _nodes_health_cycle() -> None:
    """Probe all enabled nodes; persist reachability; Telegram on connect/disconnect/version."""
    store = _load_store()
    if not nodes_mod.is_master(store):
        return
    # Probe outside the lock (network I/O)
    snapshot = [dict(n) for n in nodes_mod.ensure_list(store) if n.get("enabled", True)]
    if not snapshot:
        return
    # probe_all_health already refreshes tunnel-only peers once
    events = nodes_mod.probe_all_health(snapshot, timeout=5, store=store)
    by_id = {n.get("id"): n for n in snapshot if n.get("id")}
    with mutate() as st:
        for n in nodes_mod.ensure_list(st):
            src = by_id.get(n.get("id"))
            if not src:
                continue
            for key in (
                "online", "fail_streak", "last_seen", "last_probe",
                "last_probe_error", "panel_version",
                "xray_version", "xray_active", "last_warning", "last_ok",
                "tunnel_transport",
            ):
                if key in src:
                    n[key] = src[key]
            if "rv_conns" in src:
                n["rv_conns"] = src["rv_conns"]
            elif not n.get("nat"):
                n.pop("rv_conns", None)
    _tg_node_events(events)


def _nodes_sync_loop() -> None:
    """Periodic health probes + per-node sync according to sync_interval_min."""
    if _stop.wait(45):
        return
    while True:
        try:
            _nodes_health_cycle()
        except Exception:
            pass
        try:
            store = _load_store()
            if nodes_mod.is_master(store):
                host = public_host()
                due_ids = [
                    n["id"] for n in nodes_mod.ensure_list(store)
                    if nodes_mod.node_sync_due(n)
                ]
                running = NODES_JOB.get("id")
                busy = bool(running and ops.JOBS.get(running, {}).get("status") == "running")
                # One due node per tick — avoid stacking multi-minute syncs in the health loop
                if due_ids and not busy and NODES_SCHED_LOCK.acquire(blocking=False):
                    try:
                        st = _load_store()
                        node = next(
                            (x for x in nodes_mod.ensure_list(st)
                             if x.get("id") in due_ids and nodes_mod.node_sync_due(x)),
                            None,
                        )
                        if node:
                            name = node.get("name") or str(node.get("id") or "")[:8]
                            _node_push_job(node["id"], f"{name}: schedule", host)
                    finally:
                        NODES_SCHED_LOCK.release()
        except Exception:
            pass
        if _stop.wait(60):
            return


_MASTER_XRAY_CACHE: dict[str, Any] = {"at": 0.0, "version": ""}


def _cached_master_xray(ttl: float = 30.0) -> str:
    """Avoid systemctl+xray version on every Nodes page render."""
    now = time.time()
    if now - float(_MASTER_XRAY_CACHE.get("at") or 0) < ttl and _MASTER_XRAY_CACHE.get("version") is not None:
        return str(_MASTER_XRAY_CACHE.get("version") or "")
    try:
        ver = str((xray.xray_status() or {}).get("version") or "")
    except Exception:
        ver = str(_MASTER_XRAY_CACHE.get("version") or "")
    _MASTER_XRAY_CACHE["at"] = now
    _MASTER_XRAY_CACHE["version"] = ver
    return ver


@app.get("/nodes", response_class=HTMLResponse)
def nodes_page(request: Request):
    if redir := _require(request):
        return redir
    # Fast render from store. Reachability / panel+xray versions come from the
    # background _nodes_health_cycle — do NOT probe every node on GET (was N×4s).
    with mutate() as store:
        nodes_mod.ensure_list(store)
        nodes_mod.agent_token(store)
    store = _load_store()
    running = NODES_JOB.get("id")
    return page(request, "nodes.html", active="nodes", items=store["nodes"],
                ns=store["settings"].get("nodes") or {},
                is_master=nodes_mod.is_master(store),
                master_version=panel_version(),
                master_xray=_cached_master_xray(),
                sync_intervals=nodes_mod.SYNC_INTERVAL_CHOICES,
                tunnel_profiles=nodes_mod.TUNNEL_PROFILES,
                update_queue=node_update_queue_snapshot(),
                jobs=sorted(ops.JOBS.items(), key=lambda kv: -kv[1]["started"])[:8],
                job_running=bool(running and ops.JOBS.get(running, {}).get("status") == "running"))


def _node_xray_check_one(node: dict) -> dict:
    """Check Xray version on one node (manage or NAT local+GitHub)."""
    if node.get("nat"):
        res = _master_node_xray_nat(node["id"], "check_xray", {})
    else:
        res = nodes_mod.manage_request(node, action="check_xray", timeout=60)
    if res.get("ok"):
        _persist_node_xray_info(node["id"], res)
    return res


def _node_xray_update_one(node: dict, version: str = "") -> dict:
    params = {"version": version} if version else {}
    if node.get("nat"):
        res = _master_node_xray_nat(node["id"], "update_xray", params)
    else:
        res = nodes_mod.manage_request(node, action="update_xray", params=params, timeout=60)
    if res.get("ok"):
        _persist_node_xray_info(node["id"], res)
    return res


@app.post("/nodes/xray-check-all")
def nodes_xray_check_all(request: Request):
    if redir := _require(request):
        return redir
    store = _load_store()
    if not nodes_mod.is_master(store):
        flash(request, "Только master", "error")
        return go("/nodes")
    ok = fail = avail = 0
    bits = []
    for n in nodes_mod.ensure_list(store):
        if not n.get("enabled", True):
            continue
        res = _node_xray_check_one(n)
        name = n.get("name") or n.get("id")
        if not res.get("ok"):
            fail += 1
            bits.append(f"{name}: {res.get('error') or 'fail'}")
            continue
        ok += 1
        if res.get("available"):
            avail += 1
            bits.append(f"{name}: {res.get('current')} → {res.get('latest')}")
        else:
            bits.append(f"{name}: {res.get('current') or '?'}")
    flash(
        request,
        f"Xray check: {ok} ok, {fail} err, обновлений {avail}"
        + (f" — {'; '.join(bits[:8])}" if bits else ""),
        "info" if fail == 0 else "error",
    )
    return go("/nodes")


@app.post("/nodes/{node_id}/xray-check")
def nodes_xray_check(node_id: str, request: Request):
    if redir := _require(request):
        return redir
    store = _load_store()
    if not nodes_mod.is_master(store):
        flash(request, "Только master", "error")
        return go("/nodes")
    node = next((n for n in nodes_mod.ensure_list(store) if n.get("id") == node_id), None)
    if not node:
        flash(request, "Нода не найдена", "error")
        return go("/nodes")
    res = _node_xray_check_one(node)
    name = node.get("name") or node_id
    if res.get("ok"):
        if res.get("available"):
            flash(request, f"{name}: Xray {res.get('current')} → доступна {res.get('latest')}", "info")
        else:
            flash(request, f"{name}: Xray {res.get('current') or '?'} актуальна"
                  + (f" ({res.get('error')})" if res.get("error") else ""), "info")
    else:
        flash(request, f"{name}: {res.get('error') or 'ошибка'}", "error")
    return go("/nodes")


@app.post("/nodes/{node_id}/xray-update")
async def nodes_xray_update(node_id: str, request: Request):
    if redir := _require(request):
        return redir
    store = _load_store()
    if not nodes_mod.is_master(store):
        flash(request, "Только master", "error")
        return go("/nodes")
    node = next((n for n in nodes_mod.ensure_list(store) if n.get("id") == node_id), None)
    if not node:
        flash(request, "Нода не найдена", "error")
        return go("/nodes")
    form = await request.form()
    version = str(form.get("version") or "").strip()
    res = _node_xray_update_one(node, version)
    name = node.get("name") or node_id
    if res.get("ok"):
        ver = res.get("version") or version or "latest"
        if res.get("queued"):
            flash(request, f"{name}: Xray {ver} в очереди agent pull", "info")
        elif res.get("already"):
            flash(request, f"{name}: установка Xray уже идёт", "info")
        else:
            flash(request, f"{name}: обновление Xray → {ver} запущено", "info")
        _tg_admin(
            f"⬆️ Xray на ноде <b>{tgbot.escape(name)}</b> → <code>{tgbot.escape(str(ver))}</code>",
            flag="notify_nodes",
        )
    else:
        flash(request, f"{name}: {res.get('error') or 'ошибка'}", "error")
    return go("/nodes")


@app.get("/settings-node", response_class=HTMLResponse)
def settings_node_page(request: Request):
    """Remote full control console for a registered node (Settings Node)."""
    if redir := _require(request):
        return redir
    store = _load_store()
    with mutate() as st:
        nodes_mod.ensure_list(st)
        nodes_mod.agent_token(st)
    store = _load_store()
    items = nodes_mod.ensure_list(store)
    is_master = nodes_mod.is_master(store)
    node_id = (request.query_params.get("id") or "").strip()
    tab = (request.query_params.get("tab") or "overview").strip() or "overview"
    node = next((n for n in items if n.get("id") == node_id), None) if node_id else None
    remote: dict = {}
    login_url = ""
    log_text = log_src = log_q = ""
    log_n = 300
    if is_master and node:
        login_url = nodes_mod.panel_login_url(node)
        # NAT has no inbound manage HTTP — use registry / last pull only (instant).
        if node.get("nat"):
            remote = {
                "ok": False, "error": "NAT: manage недоступен", "nat": True,
                "version": node.get("panel_version") or "",
                "xray": {
                    "version": node.get("xray_version") or "",
                    "active": node.get("xray_active"),
                },
            }
        elif tab == "logs":
            log_src = (request.query_params.get("src") or "xray").strip() or "xray"
            log_n = max(50, min(2000, _int(request.query_params.get("n"), 300)))
            log_q = request.query_params.get("q") or ""
            remote = nodes_mod.manage_request(
                node, action="get_logs",
                params={"src": log_src, "n": log_n, "q": log_q},
                timeout=12,
            )
            log_text = remote.get("text") or remote.get("error") or ""
            snap = nodes_mod.manage_request(node, timeout=8)
            if snap.get("ok"):
                remote = {**snap, **remote, "ok": True}
        else:
            # Short timeout so a dead node does not hang Settings Node for 30s
            remote = nodes_mod.manage_request(node, timeout=8)
            if remote.get("ok"):
                with mutate() as st:
                    for n in nodes_mod.ensure_list(st):
                        if n.get("id") != node["id"]:
                            continue
                        if remote.get("version"):
                            n["panel_version"] = str(remote.get("version") or "")
                        xs = remote.get("xray") if isinstance(remote.get("xray"), dict) else {}
                        if xs.get("version"):
                            n["xray_version"] = str(xs.get("version") or "")
                            n["xray_active"] = bool(xs.get("active"))
                        break
                node = dict(node)
                if remote.get("version"):
                    node["panel_version"] = str(remote.get("version") or "")
                xs = remote.get("xray") if isinstance(remote.get("xray"), dict) else {}
                if xs.get("version"):
                    node["xray_version"] = str(xs.get("version") or "")
            elif not remote.get("error"):
                remote = {"ok": False, "error": "нет ответа (timeout)"}
    return page(
        request, "settings_node.html", active="settings_node",
        items=items, node=node, remote=remote, is_master=is_master,
        tab=tab, login_url=login_url,
        log_text=log_text, log_src=log_src or "xray", log_n=log_n, log_q=log_q,
        xray_releases=ops.xray_releases(12) if tab == "system" else [],
        master_xray=_cached_master_xray(),
    )


def _persist_node_xray_info(node_id: str, info: dict) -> None:
    """Remember last known Xray version / update check on the node registry entry."""
    if not isinstance(info, dict):
        return
    with mutate() as st:
        for n in nodes_mod.ensure_list(st):
            if n.get("id") != node_id:
                continue
            cur = str(info.get("current") or (info.get("xray") or {}).get("version") or "").strip()
            if cur:
                n["xray_version"] = cur.lstrip("vV")
            if "active" in info:
                n["xray_active"] = bool(info.get("active"))
            elif isinstance(info.get("xray"), dict) and "active" in info["xray"]:
                n["xray_active"] = bool(info["xray"].get("active"))
            if info.get("latest"):
                n["xray_latest"] = str(info.get("latest") or "")
                n["xray_available"] = bool(info.get("available"))
                n["xray_checked_at"] = nodes_mod.now_iso()
            break


def _master_node_xray_nat(node_id: str, action: str, params: dict) -> dict:
    """NAT nodes are not reachable for /agent/manage — check locally / queue update via pull."""
    store = _load_store()
    node = next((n for n in nodes_mod.ensure_list(store) if n.get("id") == node_id), None)
    if not node:
        return {"ok": False, "error": "нода не найдена"}
    include_pre = str(params.get("include_prerelease") or "") in ("1", "true", "yes", "on")
    if action == "check_xray":
        current = str(node.get("xray_version") or "").strip()
        latest = ops.xray_latest(include_pre)
        tag = str(latest.get("tag") or "") if latest.get("ok") else ""
        available = bool(tag and current) and ops.version_tuple(tag) > ops.version_tuple(current)
        return {
            "ok": True,
            "error": "" if latest.get("ok") else (latest.get("error") or "github"),
            "current": current or "?",
            "latest": tag,
            "available": available,
            "url": latest.get("url") or "",
            "prerelease": bool(latest.get("prerelease")),
            "active": node.get("xray_active"),
            "nat": True,
        }
    if action == "update_xray":
        version = str(params.get("version") or "").strip()
        if not version:
            latest = ops.xray_latest(include_pre)
            if not latest.get("ok") or not latest.get("tag"):
                return {"ok": False, "error": latest.get("error") or "не удалось получить latest Xray"}
            version = str(latest["tag"])
        with mutate() as st:
            for n in nodes_mod.ensure_list(st):
                if n.get("id") != node_id:
                    continue
                n["xray_update_requested"] = version if version.startswith("v") else f"v{version}"
                break
        return {
            "ok": True, "queued": True, "version": version,
            "current": str(node.get("xray_version") or ""),
        }
    return {"ok": False, "error": f"unsupported nat action: {action}"}


@app.post("/settings-node/{node_id}/action")
async def settings_node_action(node_id: str, request: Request):
    if redir := _require(request):
        return redir
    store = _load_store()
    if not nodes_mod.is_master(store):
        flash(request, "Только master может управлять нодами", "error")
        return go("/settings-node")
    node = next((n for n in nodes_mod.ensure_list(store) if n.get("id") == node_id), None)
    if not node:
        flash(request, "Нода не найдена", "error")
        return go("/settings-node")
    form = await request.form()
    action = str(form.get("action") or "").strip()
    params = {k: str(v) for k, v in form.items() if k != "action"}
    if action in sec.MANAGE_ADMIN:
        params.setdefault("confirm", "yes")
    # Map form fields for save_panel / password
    tab = "overview"
    if action == "save_panel":
        tab = "settings"
    elif action == "set_admin_password":
        tab = "settings"
    elif action in ("update_panel", "rollback_panel", "restore_master", "restart_panel",
                    "check_xray", "update_xray", "rollback_xray", "restart_xray",
                    "iperf3_bench", "ensure_network_perf"):
        tab = "system"

    # iperf3 master↔node — background job (NAT wait can take ~40–55 s).
    if action == "iperf3_bench":
        seconds = max(3, min(20, _int(params.get("seconds"), 8)))
        name = str(node.get("name") or node_id)

        def _reload():
            with STORE_LOCK:
                return _load_store()

        def _save_node_fields(fields: dict) -> None:
            with mutate() as st:
                for n in nodes_mod.ensure_list(st):
                    if n.get("id") != node_id:
                        continue
                    for k, v in fields.items():
                        if v is None:
                            n.pop(k, None)
                        else:
                            n[k] = v
                    break

        def _job() -> dict:
            _save_node_fields({"iperf3_running": True, "iperf3_last": {
                "ok": None, "at": nodes_mod.now_iso(), "error": "running…",
            }})
            try:
                res = nodes_mod.iperf3_bench(
                    _reload(), node_id,
                    master_host=public_host(),
                    seconds=seconds,
                    reload_store=_reload,
                    persist=_save_node_fields,
                )
            except Exception as exc:  # noqa: BLE001
                res = {"ok": False, "error": str(exc)[:300], "at": nodes_mod.now_iso()}
            last = res.get("iperf3_last") or {
                k: res.get(k)
                for k in ("ok", "mode", "up_mbps", "down_mbps", "seconds", "host", "port", "error", "at")
            }
            _save_node_fields({
                "iperf3_last": last,
                "iperf3_requested": None,
                "iperf3_result": None,
                "iperf3_running": False,
            })
            if res.get("ok"):
                _tg_admin(
                    f"🖥 iperf3 <b>{tgbot.escape(name)}</b>: "
                    f"↓ <code>{res.get('down_mbps')}</code> · ↑ <code>{res.get('up_mbps')}</code> Mbps",
                    flag="notify_nodes",
                )
            else:
                _tg_admin(
                    f"🖥 iperf3 <b>{tgbot.escape(name)}</b>: ошибка — "
                    f"{tgbot.escape(str(res.get('error') or '')[:200])}",
                    flag="notify_nodes",
                )
            return res

        running = None
        for jid, meta in list(ops.JOBS.items()):
            if meta.get("name") == f"iperf3-{node_id[:8]}" and meta.get("status") == "running":
                running = jid
                break
        if running:
            flash(request, f"{name}: iperf3 уже выполняется", "info")
        else:
            ops.start_job(f"iperf3-{node_id[:8]}", _job)
            flash(
                request,
                f"{name}: iperf3 запущен (↓ master→node / ↑ node→master). "
                f"Обновите страницу через ~20–50 с.",
                "info",
            )
        return go(f"/settings-node?id={node_id}&tab={tab}")

    # Panel update on a node → serial queue (never parallel with other nodes)
    if action == "update_panel":
        via = "NAT-pull" if node.get("nat") else "agent"
        r = enqueue_node_update(node_id, name=str(node.get("name") or ""), via=via)
        if r.get("already") == "running":
            flash(request, f"{node.get('name')}: уже обновляется", "info")
        elif r.get("already") == "pending":
            flash(request, f"{node.get('name')}: уже в очереди #{r.get('position')}", "info")
        else:
            flash(request, f"{node.get('name')}: в очереди обновления #{r.get('position')}", "info")
        return go(f"/settings-node?id={node_id}&tab={tab}")

    # NAT has no inbound manage HTTP — queue Xray update / local check from last pull
    if action in ("check_xray", "update_xray") and node.get("nat"):
        res = _master_node_xray_nat(node_id, action, params)
    else:
        res = nodes_mod.manage_request(node, action=action, params=params, timeout=120)

    if res.get("ok"):
        msg = res.get("error") or f"{action}: ok"
        if action == "update_panel" and res.get("started"):
            msg = "Обновление панели на ноде запущено"
        elif action == "set_admin_password":
            msg = "Пароль админа на ноде обновлён"
        elif action == "check_xray":
            cur = res.get("current") or "?"
            latest = res.get("latest") or "?"
            if res.get("available"):
                msg = f"Xray {cur} → доступна {latest}"
            elif res.get("error"):
                msg = f"Xray {cur}; GitHub: {res.get('error')}"
            else:
                msg = f"Xray актуальна: {cur}"
            _persist_node_xray_info(node_id, res)
        elif action == "update_xray":
            if res.get("queued"):
                msg = f"Xray {res.get('version')}: в очереди agent pull (≤20 с)"
            elif res.get("started"):
                msg = f"Обновление Xray → {res.get('version')} запущено на ноде"
            elif res.get("already"):
                msg = f"Установка Xray уже идёт на ноде ({res.get('version')})"
            else:
                msg = f"Xray update: {res.get('version') or 'ok'}"
            _persist_node_xray_info(node_id, res)
        elif action == "save_panel":
            msg = "Настройки панели на ноде сохранены"
            # keep local registry base_path in sync if changed
            new_bp = str(params.get("base_path") or "").strip().strip("/")
            new_host = str(params.get("public_host") or "").strip()
            with mutate() as st:
                for n in nodes_mod.ensure_list(st):
                    if n.get("id") != node_id:
                        continue
                    if new_bp:
                        n["base_path"] = new_bp
                    if new_host:
                        n["domain"] = new_host
                        n["url"] = f"https://{new_host}"
                    break
        flash(request, msg if msg != f"{action}: ok" else f"Нода {node.get('name')}: {action} — ok", "info")
        detail = msg if msg != f"{action}: ok" else action
        _tg_admin(
            f"🖥 Нода <b>{tgbot.escape(node.get('name') or node_id)}</b>: "
            f"{tgbot.escape(detail)}",
            flag="notify_nodes",
        )
    else:
        flash(request, f"{node.get('name')}: {res.get('error') or 'ошибка'}", "error")
        _tg_admin(
            f"❌ Нода <b>{tgbot.escape(node.get('name') or node_id)}</b> / "
            f"{tgbot.escape(action or '?')}: {tgbot.escape(res.get('error') or 'ошибка')}",
            flag="notify_nodes",
        )
    return go(f"/settings-node?id={node_id}&tab={tab}")


@app.post("/nodes/add")
async def nodes_add(request: Request):
    """Manual add (URL + token) — kept for already-installed agents."""
    if redir := _require(request):
        return redir
    form = await request.form()
    name = str(form.get("name") or "").strip() or "node"
    url = str(form.get("url") or "").strip().rstrip("/")
    token = str(form.get("token") or "").strip()
    if not url.startswith("http"):
        flash(request, "URL ноды должен начинаться с http", "error")
        return go("/nodes")
    from urllib.parse import urlparse
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    # URL may include secret path: https://node.example.com/AbCdEfGh/
    path_parts = [p for p in (parsed.path or "").split("/") if p]
    base_path = path_parts[0] if path_parts else ""
    origin = f"{parsed.scheme}://{parsed.netloc}"
    self_err = nodes_mod.same_host_as_master(host, public_host()) if host else ""
    if self_err:
        flash(request, self_err, "error")
        return go("/nodes")
    with mutate() as store:
        mirror = form.get("mirror") == "1"
        direct_connect = form.get("direct_connect") == "1" and form.get("nat") != "1"
        node = {
            "id": str(uuid.uuid4()), "name": name, "url": origin, "token": token, "enabled": True,
            "user_title": str(form.get("user_title") or "").strip()[:80],
            "sync_clients": True if mirror or direct_connect else form.get("sync_clients") == "1",
            "sync_inbounds": True if mirror or direct_connect else form.get("sync_inbounds") == "1",
            "as_outbound": True if mirror or direct_connect or form.get("nat") == "1" else form.get("as_outbound") == "1",
            "direct_connect": direct_connect,
            "mirror": mirror and form.get("nat") != "1",
            "nat": form.get("nat") == "1",
            "domain": host, "base_path": base_path,
            "sync_interval_min": nodes_mod.normalize_sync_interval(form.get("sync_interval_min")),
            "ssh_user": "", "ssh_port": 22,
            "last_sync": "", "last_error": "", "last_ok": False, "role": "agent",
        }
        if node["nat"]:
            node["as_outbound"] = True
            node["mirror"] = False
            node["direct_connect"] = False
            node["sync_clients"] = False
            node["sync_inbounds"] = False
            node["tunnel_mode"] = "l2x_udp"
            node["tunnel_profile"] = "no_dpi"
            nodes_mod.tunnel_agent_id(node)
        elif node["as_outbound"]:
            nodes_mod.ensure_bridge(node)
        nodes_mod.ensure_list(store).append(node)
        nodes_mod.upsert_node_outbound(store, node)
    _tg_admin(
        f"➕ Нода <b>{tgbot.escape(name)}</b> добавлена\n<code>{tgbot.escape(host or url)}</code>",
        flag="notify_nodes",
    )
    flash(request, f"Нода {name} добавлена", "info")
    return go("/nodes")


@app.post("/nodes/provision")
async def nodes_provision(request: Request):
    """Install/configure a remote L2X node over SSH (domain + login + password)."""
    if redir := _require(request):
        return redir
    if not nodes_mod.is_master(_load_store()):
        flash(request, "Только мастер может добавлять ноды", "error")
        return go("/nodes")
    form = await request.form()
    domain = str(form.get("domain") or "").strip()
    login = str(form.get("login") or "root").strip()
    password = str(form.get("password") or "")
    name = str(form.get("name") or "").strip()
    user_title = str(form.get("user_title") or "").strip()[:80]
    port = _int(form.get("ssh_port"), 22)
    as_outbound = form.get("as_outbound") == "1"
    mirror = form.get("mirror") == "1"
    nat = form.get("nat") == "1"
    direct_connect = form.get("direct_connect") == "1" and not nat
    sync_interval_min = nodes_mod.normalize_sync_interval(form.get("sync_interval_min"))
    if nat:
        as_outbound = True
        mirror = False
        direct_connect = False
    if mirror or direct_connect:
        as_outbound = True
    if not domain or not password:
        flash(request, "Нужны domain и SSH-пароль", "error")
        return go("/nodes")
    self_err = nodes_mod.same_host_as_master(domain, public_host())
    if self_err:
        flash(request, self_err, "error")
        return go("/nodes")
    # Extra guard: refuse literal master public host even if DNS is broken
    if nodes_mod._normalize_domain(domain) == nodes_mod._normalize_domain(public_host() or ""):
        flash(request, f"нельзя провиженить сам master ({domain})", "error")
        return go("/nodes")
    running = NODES_JOB.get("id")
    if running and ops.JOBS.get(running, {}).get("status") == "running":
        flash(request, "Уже идёт операция с нодами", "info")
        return go("/nodes")

    master = _load_store()
    token = nodes_mod.agent_token(master)
    # Ensure master has a stable agent token even when not in agent mode (used on remotes)
    with mutate() as store:
        nodes_mod.agent_token(store)
        token = store["settings"]["nodes"]["agent_token"]
    master_url = f"https://{public_host()}" if public_host() else ""
    # NAT agent dials master under the secret panel path (same as admin UI)
    master_pull_url = f"{master_url}{base_path()}" if master_url else ""
    if nat and not master_pull_url:
        flash(request, "Для ноды за NAT задайте публичный домен мастера (Настройки → Панель)", "error")
        return go("/nodes")

    def job():
        res = nodes_mod.provision_via_ssh(
            domain=domain, ssh_user=login, ssh_password=password, ssh_port=port,
            name=name, master_url=master_url, master_token=token,
            master_host=public_host(), as_outbound=as_outbound, mirror=mirror,
            nat=nat, master_pull_url=master_pull_url if nat else "",
        )
        if not res.get("ok"):
            return {"ok": False, "error": res.get("error") or "provision failed", "log": res.get("log") or ""}
        node = res["node"]
        node["sync_interval_min"] = sync_interval_min
        if user_title:
            node["user_title"] = user_title
        if direct_connect and not nat:
            node["direct_connect"] = True
            node["as_outbound"] = True
            node["sync_clients"] = True
            node["sync_inbounds"] = True
        with mutate() as store:
            nodes = nodes_mod.ensure_list(store)
            # replace same domain if re-provisioning
            nodes[:] = [n for n in nodes if (n.get("domain") or "") != node["domain"] and n.get("url") != node["url"]]
            if nat:
                node["tunnel_mode"] = node.get("tunnel_mode") or "l2x_udp"
                node["direct_connect"] = False
            nodes.append(node)
            nodes_mod.upsert_node_outbound(store, node)
            payload = nodes_mod.build_payload(store, node, xray.build_config)
            push = nodes_mod.push(node, payload, master_host=public_host())
            xr = _apply_xray(store)
        log = (res.get("log") or "") + f"\npanel: {res.get('panel_url')}\nadmin pass: {res.get('admin_password')}\n"
        if nat:
            log += "mode: NAT + l2x_udp (egress через l2x-tunneld SOCKS; нода pull с мастера)\n"
            log += f"queued: {push.get('queued')} xray: {xr.get('ok')}"
        else:
            log += f"sync: {push.get('ok')} {push.get('error') or ''}\nxray: {xr.get('ok')}"
        return {"ok": True, "log": log}

    NODES_JOB["id"] = ops.start_job("node-provision", job)
    _tg_admin(f"🚀 Provision ноды <b>{tgbot.escape(domain)}</b> запущен", flag="notify_nodes")
    flash(request, f"Установка ноды {domain} по SSH запущена (несколько минут). Смотрите фоновые задачи.", "info")
    return go("/nodes")


def _node_push_job(node_id: str, label: str, host: str):
    """Push config to one node outside STORE_LOCK (avoids deadlock / hung panel)."""
    with mutate() as store:
        node = next((n for n in nodes_mod.ensure_list(store) if n.get("id") == node_id), None)
        if not node:
            return {"ok": False, "error": "нода не найдена", "log": ""}
        nodes_mod.ensure_tunnel_settings(store)
        nodes_mod.upsert_node_outbound(store, node)
        # Pure Go tunnel agent: no panel pull — just refresh SOCKS outbound + health
        if nodes_mod.is_tunnel_only_node(node):
            nodes_mod.refresh_tunnel_only_health(store, [node])
            name = node.get("name") or node_id
            online = bool(node.get("online"))
            node["last_ok"] = online
            node["last_error"] = "" if online else "tunneld peer offline"
            node["last_warning"] = ""
            node["last_sync"] = nodes_mod.now_iso()
            xr = _apply_xray(store)
            return {
                "ok": online and bool(xr.get("ok")),
                "log": (
                    f"{label}: L2X WSS tunnel {'online' if online else 'offline'}; "
                    f"xray={'ok' if xr.get('ok') else xr.get('error')}"
                ),
            }
        payload = nodes_mod.build_payload(store, node, xray.build_config)
        node_snap = dict(node)
        name = node.get("name") or node_id
        prev_ok = bool(node.get("last_ok"))
        doh_on = bool((store.get("settings") or {}).get("doh", {}).get("enabled"))
        is_mirror = bool(node.get("mirror"))
    # Network I/O must not hold mutate()/STORE_LOCK
    res = nodes_mod.push(node_snap, payload, master_host=host, timeout=120)
    warns = list(res.get("warnings") or [])
    # Master-side hint when DoH is on but this was a non-mirror push (settings not sent)
    if doh_on and not is_mirror and res.get("ok") and not node_snap.get("nat"):
        warns.append(
            "DoH включён на master, но нода без зеркала — настройки DoH/Pi-hole в sync не передаются. "
            "Включите «зеркало» или установите Pi-hole на ноде перед promote."
        )
        if not node_snap.get("last_warning"):
            node_snap["last_warning"] = "; ".join(warns)[:600]
    # Reachability from successful sync (skip for NAT — online = recent /agent/pull)
    reach_events: list[dict] = []
    if res.get("ok") and not res.get("queued") and not node_snap.get("nat"):
        reach_events = nodes_mod.apply_health_probe(node_snap, {
            "ok": True, "version": node_snap.get("panel_version") or "",
        })
    with mutate() as store:
        for n in nodes_mod.ensure_list(store):
            if n.get("id") != node_id:
                continue
            n["last_sync"] = nodes_mod.now_iso() if res.get("queued") else (node_snap.get("last_sync") or n.get("last_sync"))
            if res.get("queued"):
                n["last_ok"] = True
                n["last_error"] = ""
                if nodes_mod.is_tunnel_only_node(n):
                    n["last_warning"] = ""
                    nodes_mod.refresh_tunnel_only_health(store, [n])
                else:
                    n["last_warning"] = "NAT: конфиг в очереди — нода заберёт через /agent/pull"
            else:
                n["last_ok"] = bool(node_snap.get("last_ok"))
                n["last_error"] = node_snap.get("last_error") or ""
                n["last_warning"] = node_snap.get("last_warning") or ("; ".join(warns)[:600] if warns else "")
            if node_snap.get("panel_version"):
                n["panel_version"] = node_snap["panel_version"]
            for key in ("online", "fail_streak", "last_seen", "last_probe", "last_probe_error"):
                if key in node_snap and not node_snap.get("nat"):
                    n[key] = node_snap[key]
            break
        webhooks.fire(store["settings"], "node.sync", {
            "node": name, "ok": res.get("ok"), "error": res.get("error"),
            "label": label, "warnings": warns,
        })
        xr = _apply_xray(store)
    log = f"{label}: {'OK' if res.get('ok') else res.get('error') or 'fail'}"
    if warns:
        log += "\n⚠ " + " | ".join(warns)
    if not xr.get("ok"):
        log += f"\nxray: {xr.get('error') or 'fail'}"
    # Telegram: failures/warnings always; success when manual OR recovered after fail
    is_sched = "schedule" in (label or "").lower()
    recovered = bool(res.get("ok")) and not prev_ok
    if not res.get("ok"):
        _tg_admin(
            f"❌ Sync <b>{tgbot.escape(name)}</b>: {tgbot.escape(res.get('error') or 'fail')}\n"
            f"<i>{tgbot.escape(label)}</i>",
            flag="notify_nodes",
        )
    elif warns:
        _tg_admin(
            f"⚠️ <b>Sync {tgbot.escape(name)}</b> ({tgbot.escape(label)})\n"
            + "\n".join(f"• {tgbot.escape(w)}" for w in warns),
            flag="notify_nodes",
        )
    elif not is_sched or recovered:
        mark = "восстановлен · " if recovered and is_sched else ""
        _tg_admin(
            f"✅ Sync <b>{tgbot.escape(name)}</b>: {mark}OK ({tgbot.escape(label)})",
            flag="notify_nodes",
        )
    _tg_node_events(reach_events)
    return {
        "ok": bool(res.get("ok")), "log": log,
        "error": "" if res.get("ok") else (res.get("error") or "push failed"),
        "warnings": warns,
    }


@app.post("/nodes/{node_id}/tunnel-profile")
async def nodes_tunnel_profile(node_id: str, request: Request):
    """Switch L2X tunnel profile: no_dpi / dpi_lite / udp (NAT and +Reverse)."""
    if redir := _require(request):
        return redir
    form = await request.form()
    profile = nodes_mod.normalize_tunnel_profile(form.get("profile"))
    ssh_password = str(form.get("password") or "")
    with mutate() as store:
        if not nodes_mod.is_master(store):
            flash(request, "Только мастер может менять профиль туннеля", "error")
            return go("/nodes")
        node = next((n for n in nodes_mod.ensure_list(store) if n["id"] == node_id), None)
        if not node:
            flash(request, "Нода не найдена", "error")
            return go("/nodes")
        if not (node.get("nat") or node.get("rv_mode") or str(node.get("tunnel_mode") or "") == "l2x_udp"):
            flash(request, "Профиль туннеля доступен для NAT / +Reverse / L2X", "error")
            return go("/nodes")
        node["as_outbound"] = True
        node["tunnel_mode"] = "l2x_udp"
        node["tunnel_profile"] = profile
        nodes_mod.tunnel_agent_id(node)
        nodes_mod.upsert_node_outbound(store, node)
        tun_sync = nodes_mod.sync_tunneld_for_fleet(store)
        name = node.get("name") or node_id
        node_snap = dict(node)
    spec = nodes_mod.tunnel_profile_spec(profile=profile)
    tip = ""
    if profile == "udp" and tun_sync.get("udp"):
        tip = " (мастер слушает UDP :4443 — откройте порт в firewall)"
    # Tunnel-only: push yaml over SSH when password given
    if nodes_mod.is_tunnel_only_node(node_snap) and ssh_password:
        tac = nodes_mod.build_tunnel_agent_config(_load_store(), node_snap) or {}
        ret = nodes_mod.retarget_tunnel_agent_ssh(
            node_snap,
            ws_url=str(tac.get("ws_url") or ""),
            psk=str(tac.get("psk") or ""),
            token=str(tac.get("token") or ""),
            peer_udp=str(tac.get("peer_udp") or ""),
            transport=str(tac.get("transport") or ""),
            cipher=str(tac.get("cipher") or ""),
            agent_yaml=nodes_mod.render_agent_tunnel_yaml(tac) if tac else "",
            ssh_password=ssh_password,
        )
        if not ret.get("ok"):
            flash(request, f"{name}: профиль {spec['label']}, SSH retarget: {ret.get('error')}", "error")
            return go("/nodes")
    elif node_snap.get("nat") or node_snap.get("token"):
        # Panel agent: next /agent/pull or Sync pushes tunnel_agent block
        pass
    flash(
        request,
        f"{name}: туннель → {spec['label']}{tip}. "
        f"{'NAT: агент подхватит на ближайшем pull' if node_snap.get('nat') else 'Нажмите Sync (или SSH для tunnel-only)'}",
        "info",
    )
    _tg_admin(
        f"🔀 Нода <b>{tgbot.escape(name)}</b>: tunnel profile <code>{tgbot.escape(profile)}</code>",
        flag="notify_nodes",
    )
    # Non-NAT with panel: kick sync so tunnel_agent applies soon
    if node_snap.get("token") and not node_snap.get("nat"):
        running = NODES_JOB.get("id")
        if not (running and ops.JOBS.get(running, {}).get("status") == "running"):
            NODES_JOB["id"] = ops.start_job(
                f"node-tunnel-profile-{name}",
                _node_push_job, node_id, f"{name}: tunnel {profile}", public_host(),
            )
    return go("/nodes")


@app.post("/nodes/{node_id}/{action}")
async def nodes_action(node_id: str, action: str, request: Request):
    if redir := _require(request):
        return redir
    form = {}
    if request.method == "POST":
        try:
            form = await request.form()
        except Exception:
            form = {}

    # --- quick local mutations (no network) ---
    if action in ("delete", "toggle", "token", "schedule", "user_title"):
        with mutate() as store:
            nodes = nodes_mod.ensure_list(store)
            node = next((n for n in nodes if n["id"] == node_id), None)
            if not node:
                flash(request, "Нода не найдена", "error")
                return go("/nodes")
            if action == "delete":
                nm = node.get("name") or node_id
                nodes.remove(node)
                nodes_mod.sync_all_node_outbounds(store)
                _tg_admin(f"🗑 Нода <b>{tgbot.escape(nm)}</b> удалена", flag="notify_nodes")
                flash(request, "Нода удалена", "info")
            elif action == "toggle":
                node["enabled"] = not node.get("enabled", True)
                nodes_mod.upsert_node_outbound(store, node)
                state = "вкл" if node["enabled"] else "выкл"
                _tg_admin(f"🖥 Нода <b>{tgbot.escape(node['name'])}</b>: {state}", flag="notify_nodes")
                flash(request, f"{node['name']}: {state}", "info")
            elif action == "schedule":
                mins = nodes_mod.normalize_sync_interval(form.get("sync_interval_min"))
                node["sync_interval_min"] = mins
                label = nodes_mod.sync_interval_label(mins)
                _tg_admin(
                    f"⏱ Нода <b>{tgbot.escape(node['name'])}</b>: расписание sync — {tgbot.escape(label)}",
                    flag="notify_nodes",
                )
                flash(request, f"{node['name']}: расписание sync — {label}", "info")
            elif action == "user_title":
                title = str(form.get("user_title") or "").strip()[:80]
                node["user_title"] = title
                nodes_mod.upsert_node_outbound(store, node)
                shown = nodes_mod.node_user_title(node)
                flash(request, f"{node['name']}: название у пользователя — {shown}", "info")
            else:
                new_tok = str(form.get("token") or "").strip()
                if not new_tok:
                    flash(request, "Token не изменён (пустое поле)", "info")
                    return go("/nodes")
                if len(new_tok) < 8:
                    flash(request, "Token слишком короткий", "error")
                    return go("/nodes")
                node["token"] = new_tok
                _tg_admin(
                    f"🔑 Нода <b>{tgbot.escape(node['name'])}</b>: token обновлён",
                    flag="notify_nodes",
                )
                flash(request, f"{node['name']}: token обновлён — нажмите Sync", "info")
        if action == "delete":
            _apply_xray(_load_store())
        elif action == "user_title":
            _apply_xray(_load_store(), xray_only=True)
        return go("/nodes")

    # --- outbound / mirror / sync: flip flags under lock, push in background ---
    if action in ("outbound", "mirror", "sync", "reverse", "direct"):
        host = public_host()
        with mutate() as store:
            nodes = nodes_mod.ensure_list(store)
            node = next((n for n in nodes if n["id"] == node_id), None)
            if not node:
                flash(request, "Нода не найдена", "error")
                return go("/nodes")
            if action == "reverse":
                if node.get("nat"):
                    flash(request, "Нода за NAT: egress через L2X tunnel (профиль ниже)", "info")
                    return go("/nodes")
                if not nodes_mod.is_master(store):
                    flash(request, "Только мастер может менять режим outbound", "error")
                    return go("/nodes")
                node["rv_mode"] = not node.get("rv_mode")
                node.pop("rv_conns", None)
                node.pop("reverse_ok", None)
                if node["rv_mode"]:
                    node["as_outbound"] = True
                    node["direct_connect"] = False
                    # +Reverse → L2X agent tunnel (same profiles as NAT), not Xray reverse
                    node["tunnel_mode"] = "l2x_udp"
                    node["tunnel_profile"] = nodes_mod.normalize_tunnel_profile(
                        node.get("tunnel_profile") or "no_dpi"
                    )
                    nodes_mod.tunnel_agent_id(node)
                    nodes_mod.sync_tunneld_for_fleet(store)
                else:
                    node["tunnel_mode"] = ""
                    nodes_mod.ensure_bridge(node)
                    nodes_mod.sync_tunneld_for_fleet(store)
                label = f"reverse/L2X {'вкл' if node['rv_mode'] else 'выкл'}"
            elif action == "direct":
                if node.get("nat") or node.get("rv_mode") or nodes_mod.uses_l2x_tunnel(node):
                    flash(request, "Direct connect только для публичной ноды (не NAT / не Reverse)", "error")
                    return go("/nodes")
                if not nodes_mod.is_master(store):
                    flash(request, "Только мастер может включать direct connect", "error")
                    return go("/nodes")
                node["direct_connect"] = not node.get("direct_connect")
                if node["direct_connect"]:
                    node["as_outbound"] = True
                    node["sync_clients"] = True
                    node["sync_inbounds"] = True
                    nodes_mod.ensure_bridge(node)
                    self_err = nodes_mod.same_host_as_master(node.get("domain") or "", host)
                    if self_err:
                        node["direct_connect"] = False
                        flash(request, self_err, "error")
                        return go("/nodes")
                # Stale bridge-probe fail must not hide Direct entries until next probe
                for o in store.get("outbounds_custom") or []:
                    if o.get("node_id") == node.get("id") or o.get("tag") == nodes_mod.node_outbound_tag(node):
                        o.pop("last_test", None)
                label = f"direct connect {'вкл' if node['direct_connect'] else 'выкл'}"
            elif action == "outbound":
                node["as_outbound"] = not node.get("as_outbound")
                if node["as_outbound"]:
                    if node.get("nat") or node.get("rv_mode"):
                        # Preserve explicit mode; default reverse when rv identity exists
                        if not str(node.get("tunnel_mode") or "").strip():
                            node["tunnel_mode"] = (
                                "xray_reverse" if (node.get("rv_uuid") or node.get("rv_mode")) else "l2x_udp"
                            )
                    elif not nodes_mod.uses_l2x_tunnel(node):
                        nodes_mod.ensure_bridge(node)
                else:
                    node["direct_connect"] = False
                label = f"outbound {'вкл' if node['as_outbound'] else 'выкл'}"
            elif action == "mirror":
                if node.get("nat"):
                    flash(request, "Зеркало недоступно для ноды за NAT", "error")
                    return go("/nodes")
                node["mirror"] = not node.get("mirror")
                if node["mirror"]:
                    node["sync_clients"] = True
                    node["sync_inbounds"] = True
                    if not node.get("as_outbound"):
                        node["as_outbound"] = True
                        nodes_mod.ensure_bridge(node)
                    # Refuse self-host before we start a heavy push
                    self_err = nodes_mod.same_host_as_master(node.get("domain") or "", host)
                    if self_err:
                        node["mirror"] = False
                        flash(request, self_err, "error")
                        return go("/nodes")
                label = f"зеркало {'вкл' if node['mirror'] else 'выкл'}"
            else:
                label = "sync"
            nodes_mod.upsert_node_outbound(store, node)
            name = node["name"]
            if action in ("outbound", "mirror", "reverse", "direct"):
                _tg_admin(
                    f"🖥 Нода <b>{tgbot.escape(name)}</b>: {tgbot.escape(label)}",
                    flag="notify_nodes",
                )
            running = NODES_JOB.get("id")
            if running and ops.JOBS.get(running, {}).get("status") == "running":
                flash(request, "Уже идёт операция с нодами — флаг сохранён, Sync позже", "info")
                return go("/nodes")
        NODES_JOB["id"] = ops.start_job(
            f"node-{action}-{name}",
            _node_push_job, node_id, f"{name}: {label}", host,
        )
        flash(request, f"{name}: {label} — синхронизация в фоне", "info")
        return go("/nodes")

    if action == "update":
        store = _load_store()
        if not nodes_mod.is_master(store):
            flash(request, "Только мастер может обновлять ноды", "error")
            return go("/nodes")
        node = next((n for n in nodes_mod.ensure_list(store) if n["id"] == node_id), None)
        if not node:
            flash(request, "Нода не найдена", "error")
            return go("/nodes")
        if nodes_mod.is_tunnel_only_node(node):
            with mutate() as st:
                for n in nodes_mod.ensure_list(st):
                    if n.get("id") != node_id:
                        continue
                    n.pop("update_requested", None)
                    n["update_queue_status"] = "ok"
                    n["last_error"] = ""
                    n["last_warning"] = "L2X tunnel-agent обновляется бинарём, не через NAT pull"
                    nodes_mod.refresh_tunnel_only_health(st, [n])
                    break
            flash(
                request,
                f"{node.get('name')}: это Go L2X agent — нет panel pull. "
                "Обновите l2x-tunnel-agent с GitHub release, не кнопкой «Обновить».",
                "info",
            )
            return go("/nodes")
        ssh_password = str(form.get("password") or "")
        via = "NAT-pull" if node.get("nat") else ("SSH" if ssh_password else "agent")
        r = enqueue_node_update(
            node_id, name=str(node.get("name") or ""), ssh_password=ssh_password, via=via,
        )
        name = node.get("name") or node_id[:8]
        if r.get("already") == "running":
            flash(request, f"{name}: уже обновляется", "info")
        elif r.get("already") == "pending":
            flash(request, f"{name}: уже в очереди (#{r.get('position')})", "info")
        else:
            _tg_admin(
                f"⬆️ Нода <b>{tgbot.escape(name)}</b> в очереди обновления "
                f"(#{r.get('position')}, {tgbot.escape(via)}) — по одной, без параллели",
                flag="notify_nodes",
            )
            flash(
                request,
                f"{name}: в очереди обновления #{r.get('position')} ({via}). "
                "Ноды обновляются строго по одной.",
                "info",
            )
        return go("/nodes")

    if action == "promote":
        with mutate() as store:
            nodes = nodes_mod.ensure_list(store)
            node = next((n for n in nodes if n["id"] == node_id), None)
            if not node:
                flash(request, "Нода не найдена", "error")
                return go("/nodes")
            ssh_password = str(form.get("password") or "")
            if not ssh_password and not node.get("mirror"):
                flash(request, "Нужен SSH-пароль ноды (для зеркала можно без пароля — через API)", "error")
                return go("/nodes")
            running = NODES_JOB.get("id")
            if running and ops.JOBS.get(running, {}).get("status") == "running":
                flash(request, "Уже идёт операция с нодами", "info")
                return go("/nodes")
            old = {
                "id": str(uuid.uuid4()),
                "name": public_host() or "old-master",
                "url": f"https://{public_host()}" if public_host() else "",
                "domain": public_host() or "",
                "token": nodes_mod.agent_token(store),
                "enabled": True, "sync_clients": True, "sync_inbounds": True,
                "as_outbound": True, "mirror": bool(node.get("mirror")),
                "base_path": base_path().strip("/"), "role": "agent",
                "last_sync": "", "last_error": "", "last_ok": False,
            }
            nodes_mod.ensure_bridge(old)
            # Full master data → new master; outbound to THIS node remapped to direct
            snap = nodes_mod.promote_snapshot(store, node)
            peers = [nodes_mod._peer_node_export(n) for n in nodes if n.get("id") != node.get("id")]
            node_copy = dict(node)
            use_api = bool(node.get("mirror")) and not ssh_password
            name = node["name"]
            drop_tags = snap.get("drop_outbound_tags") or [nodes_mod.node_outbound_tag(node)]
            n_custom = int(snap.get("transferred_custom") or 0)

        def job():
            import time as _time
            log_lines = []
            # 1) Promote REMOTE first while we are still master (critical: never demote early)
            if use_api:
                body = nodes_mod.promote_payload(snap, old, extra_nodes=peers, for_api=True)
                res = nodes_mod.promote_via_api(node_copy, body)
            else:
                res = nodes_mod.promote_via_ssh(node_copy, ssh_password=ssh_password,
                                               master_store_snapshot=snap, old_master_node=old)
            log_lines.append(res.get("log") or "")
            if not res.get("ok"):
                # API body may be lost after remote already flipped (nginx/uvicorn close).
                soft = False
                for i in range(4):
                    _time.sleep(1 if i else 0)
                    probe0 = nodes_mod.probe_role(node_copy, timeout=10)
                    log_lines.append(
                        f"soft-probe[{i}]: ok={probe0.get('ok')} role={probe0.get('role')} "
                        f"after err={res.get('error')}"
                    )
                    if probe0.get("ok") and probe0.get("is_master"):
                        soft = True
                        res = {**res, "ok": True, "soft": True, "error": ""}
                        break
                if not soft:
                    _tg_admin(
                        f"❌ Promote → <b>{tgbot.escape(name)}</b>: {tgbot.escape(res.get('error') or 'fail')}",
                        flag="notify_nodes",
                    )
                    return {"ok": False, "error": res.get("error") or "promote failed",
                            "log": "\n".join(x for x in log_lines if x)}

            # 2) Verify new master is healthy and reports master role
            verified = False
            for i in range(8):
                _time.sleep(2 if i else 1)
                probe = nodes_mod.probe_role(node_copy, timeout=10)
                log_lines.append(f"probe[{i}]: ok={probe.get('ok')} role={probe.get('role')} ver={probe.get('version')}")
                if probe.get("ok") and probe.get("is_master"):
                    verified = True
                    break
            if not verified:
                _tg_admin(
                    f"❌ Promote → <b>{tgbot.escape(name)}</b> не подтверждён — старый master не трогали",
                    flag="notify_nodes",
                )
                return {
                    "ok": False,
                    "error": "новая нода не подтвердила роль master — старый master не трогали",
                    "log": "\n".join(x for x in log_lines if x),
                }

            # 3) Only now demote ourselves; preserve live Xray until new master pushes
            with mutate() as st:
                ns = st.setdefault("settings", {}).setdefault("nodes", {})
                ns["agent_enabled"] = True
                ns["role"] = "agent"
                ns["agent_manual_off"] = False
                ns["runtime_preserve"] = True
                # NAT agents still poll us — /agent/pull forwards them here
                ns["master_pull_url"] = nodes_mod.node_pull_base(node_copy)
                ns["upstream_master_url"] = nodes_mod.node_pull_base(node_copy)
                nodes_mod.agent_token(st)
                remaining = [n for n in nodes_mod.ensure_list(st) if n.get("id") != node_copy.get("id")]
                st["nodes"] = remaining
            # 4) L2X Go agents do not use /agent/pull — they keep dialing the old WSS until
            # agent.yaml ws_url is updated (retarget_tunnel_agent_ssh with THAT node's SSH).
            new_host = nodes_mod.node_public_domain(node_copy) or str(node_copy.get("domain") or "")
            ws_url = ""
            try:
                fake = {
                    "settings": {
                        "nodes": {"tunnel": snap.get("tunnel_settings") or {}},
                        "panel": {"public_host": new_host},
                    }
                }
                ws_url = nodes_mod.tunnel_public_ws_url(fake, new_host)
            except Exception:
                ws_url = ""
            retarget_logs = []
            for n in remaining:
                if not (nodes_mod.uses_l2x_tunnel(n) and nodes_mod.is_tunnel_only_node(n)):
                    continue
                tip = ws_url or f"wss://{new_host}:8000/…"
                msg = (
                    f"l2x-retarget REQUIRED for {n.get('name')}: "
                    f"set ws_url={tip} in /etc/l2x-tunnel/agent.yaml and restart l2x-tunnel-agent"
                )
                retarget_logs.append(msg)
                log_lines.append(msg)
            via = "API" if use_api else "SSH"
            _tg_admin(
                f"✅ Promote → <b>{tgbot.escape(name)}</b> OK ({via}). "
                f"certs={int(snap.get('transferred_certs') or 0)}, "
                f"doh_files={int(snap.get('transferred_doh_files') or 0)}, "
                f"custom={n_custom}",
                flag="notify_nodes",
            )
            return {
                "ok": True,
                "log": "\n".join(x for x in log_lines if x)
                + f"\n[{via}] Новый master: https://{node_copy.get('domain')}/ — откройте его панель."
                + f"\nOutbound {', '.join(drop_tags)} → direct;"
                + f" перенесено custom={n_custom}"
                + f", certs={int(snap.get('transferred_certs') or 0)}"
                + f", doh_files={int(snap.get('transferred_doh_files') or 0)}"
                + f", tunnel={bool(snap.get('transferred_tunnel'))}"
                + " (settings/DoH/Pi-hole включены)."
                + "\nСтарый master стал agent с runtime_preserve (трафик не срезается)."
                + ("\n" + "\n".join(retarget_logs) if retarget_logs else ""),
            }

        NODES_JOB["id"] = ops.start_job("node-promote", job)
        _tg_admin(
            f"👑 Promote master → <b>{tgbot.escape(name)}</b> запущен ({'API' if use_api else 'SSH'})",
            flag="notify_nodes",
        )
        flash(request, f"Передача роли master → {name} запущена ({'API' if use_api else 'SSH'}). Все outbound переносятся, {nodes_mod.node_outbound_tag(node_copy)} → direct.", "info")
        return go("/nodes")

    flash(request, "Неизвестное действие", "error")
    return go("/nodes")


@app.post("/nodes/restore-master")
def nodes_restore_master(request: Request):
    """Emergency: force this panel back to master if promote/failover left it as agent."""
    if redir := _require(request):
        return redir
    with mutate() as store:
        ns = store.setdefault("settings", {}).setdefault("nodes", {})
        if not ns.get("agent_manual_off"):
            ns["agent_enabled"] = True
        ns["role"] = "master"
        ns["runtime_preserve"] = False
        ns["mirror"] = False
        ns.pop("master_pull_url", None)
    xr = _apply_xray(_load_store())
    flash(request, *_ok_msg("Роль MASTER восстановлена на этой панели", xr))
    return go("/nodes")


@app.post("/nodes/update-all")
def nodes_update_all(request: Request):
    """Enqueue panel updates for all outdated nodes (serial queue)."""
    if redir := _require(request):
        return redir
    store = _load_store()
    if not nodes_mod.is_master(store):
        flash(request, "Только мастер", "error")
        return go("/nodes")
    r = enqueue_outdated_nodes(master_ver=panel_version())
    if not r.get("ok"):
        flash(request, r.get("error") or "ошибка", "error")
        return go("/nodes")
    _tg_admin(
        f"⬆️ В очередь обновления нод: <b>{r.get('added', 0)}</b> "
        f"(пропущено актуальных: {r.get('skipped', 0)})",
        flag="notify_nodes",
    )
    flash(
        request,
        f"В очередь: {r.get('added', 0)} нод (пропущено {r.get('skipped', 0)}). "
        "Обновление строго по одной — смотрите очередь на этой вкладке.",
        "info",
    )
    return go("/nodes")


@app.post("/nodes/update-queue/clear")
def nodes_update_queue_clear(request: Request):
    if redir := _require(request):
        return redir
    with _NODE_UPD_LOCK:
        cleared = len(_NODE_UPD["pending"])
        pending_ids = [x.get("id") for x in _NODE_UPD["pending"]]
        _NODE_UPD["pending"] = []
    for nid in pending_ids:
        if nid:
            _node_upd_set_status(str(nid), "")
    flash(request, f"Очередь очищена ({cleared}). Текущее обновление не прервано.", "info")
    return go("/nodes")


@app.post("/nodes/sync-all")
def nodes_sync_all(request: Request):
    if redir := _require(request):
        return redir
    host = public_host()
    running = NODES_JOB.get("id")
    if running and ops.JOBS.get(running, {}).get("status") == "running":
        flash(request, "Уже идёт операция с нодами", "info")
        return go("/nodes")

    def job():
        with mutate() as store:
            nodes_mod.sync_all_node_outbounds(store)
            payloads = [(n["id"], n.get("name") or n["id"],
                         nodes_mod.build_payload(store, n, xray.build_config), dict(n)) for n in
                        nodes_mod.ensure_list(store) if n.get("enabled", True)]
        ok = fail = 0
        logs = []
        for nid, name, payload, node_snap in payloads:
            res = nodes_mod.push(node_snap, payload, master_host=host, timeout=120)
            ok += 1 if res.get("ok") else 0
            fail += 0 if res.get("ok") else 1
            logs.append(f"{name}: {'OK' if res.get('ok') else res.get('error')}")
            with mutate() as store:
                for n in nodes_mod.ensure_list(store):
                    if n.get("id") != nid:
                        continue
                    n["last_sync"] = node_snap.get("last_sync") or n.get("last_sync")
                    n["last_ok"] = bool(node_snap.get("last_ok"))
                    n["last_error"] = node_snap.get("last_error") or ""
                    break
                webhooks.fire(store["settings"], "node.sync", {"node": name, "ok": res.get("ok")})
        with mutate() as store:
            _apply_xray(store)
        summary = f"OK {ok}, ошибок {fail}"
        if fail:
            _tg_admin(
                f"❌ Sync all: {summary}\n" + "\n".join(tgbot.escape(x) for x in logs[:12]),
                flag="notify_nodes",
            )
        else:
            _tg_admin(f"✅ Sync all: {summary}", flag="notify_nodes")
        return {"ok": fail == 0, "log": f"{summary}\n" + "\n".join(logs),
                "error": "" if fail == 0 else f"{fail} failed"}

    NODES_JOB["id"] = ops.start_job("nodes-sync-all", job)
    _tg_admin("🔄 Sync all нод запущен", flag="notify_nodes")
    flash(request, "Синхронизация всех нод запущена в фоне", "info")
    return go("/nodes")


def _agent_rate_ok(request: Request, bucket: str) -> JSONResponse | None:
    ip = _client_ip(request)
    if not sec.AGENT_LIMITER.allow(f"{bucket}:{ip}", limit=90, window_sec=60):
        return JSONResponse({"ok": False, "error": "rate limited"}, status_code=429)
    return None


def _agent_auth(request: Request) -> tuple[dict | None, JSONResponse | None]:
    """Validate Bearer agent_token. Returns (store, None) or (None, error response)."""
    if err := _agent_rate_ok(request, "agent"):
        return None, err
    store = _load_store()
    ns = store["settings"].get("nodes") or {}
    # Auto-heal on any role: Agent API stays on unless admin unchecked it
    if not ns.get("agent_manual_off") and not ns.get("agent_enabled"):
        with mutate() as st:
            n2 = st.setdefault("settings", {}).setdefault("nodes", {})
            n2["agent_enabled"] = True
        store = _load_store()
        ns = store["settings"].get("nodes") or {}
    if not ns.get("agent_enabled"):
        return None, JSONResponse({"ok": False, "error": "agent disabled"}, status_code=403)
    auth = request.headers.get("authorization") or ""
    token = auth.removeprefix("Bearer ").strip() if auth.startswith("Bearer ") else ""
    if not _agent_token_ok(ns, token):
        return None, JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)
    return store, None


def _agent_manage_auth(request: Request) -> tuple[dict | None, JSONResponse | None]:
    """Bearer agent_token auth for remote management — works even when this host is master."""
    if err := _agent_rate_ok(request, "manage"):
        return None, err
    store = _load_store()
    ns = store["settings"].get("nodes") or {}
    auth = request.headers.get("authorization") or ""
    token = auth.removeprefix("Bearer ").strip() if auth.startswith("Bearer ") else ""
    if not _agent_token_ok(ns, token):
        return None, JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)
    return store, None


def _manage_snapshot(store: dict) -> dict:
    """Compact remote state for Settings Node console."""
    store = json.loads(json.dumps(store))
    ns = (store.get("settings") or {}).get("nodes") or {}
    panel = (store.get("settings") or {}).get("panel") or {}
    xs = xray.xray_status()
    try:
        snap_sys = sysmon.snapshot()
    except Exception:
        snap_sys = {}
    bp = (panel.get("base_path") or "").strip().strip("/")
    host = (panel.get("public_host") or public_host() or "").strip()
    summary = (
        f"role={ns.get('role') or ('agent' if ns.get('agent_enabled') else 'master')} "
        f"ver={panel_version()} host={host} path=/{bp}/\n"
        f"clients={len(store.get('clients') or [])} "
        f"inbounds={len(store.get('inbounds') or [])} "
        f"custom={len(store.get('outbounds_custom') or [])} "
        f"routes={len(store.get('routes') or [])}"
    )
    return {
        "ok": True,
        "role": ns.get("role") or ("agent" if ns.get("agent_enabled") else "master"),
        "agent_enabled": bool(ns.get("agent_enabled")),
        "mirror": bool(ns.get("mirror")),
        "runtime_preserve": bool(ns.get("runtime_preserve")),
        "version": panel_version(),
        "panel": {
            "title": panel.get("title") or "",
            "public_host": host,
            "base_path": bp,
            "lang": panel.get("lang") or "ru",
            "theme": panel.get("theme") or "dark",
            "timezone": panel.get("timezone") or "",
        },
        "admin_user": (_admin() or {}).get("username") or "admin",
        "admin_count": len(admins.public_rows()),
        "counts": {
            "clients": len(store.get("clients") or []),
            "inbounds": len(store.get("inbounds") or []),
            "custom": len(store.get("outbounds_custom") or []),
            "routes": len(store.get("routes") or []),
        },
        "xray": xs,
        "sys": snap_sys,
        "summary": summary,
    }


def _manage_action(action: str, payload: dict) -> dict:
    """Execute a remote-management action on this host."""
    action = (action or "").strip()
    store0 = _load_store()
    ns0 = (store0.get("settings") or {}).get("nodes") or {}
    is_master = nodes_mod.is_master(store0)
    allow_mm = bool(ns0.get("allow_master_manage"))
    ok_act, why = sec.manage_action_allowed(
        action=action, is_master=is_master, allow_master_manage=allow_mm,
    )
    if not ok_act:
        return {"ok": False, "error": why}
    if action in sec.MANAGE_ADMIN and str(payload.get("confirm") or "") != "yes":
        return {"ok": False, "error": "confirm=yes required for this action"}
    if action in ("", "snapshot", "status"):
        return _manage_snapshot(store0)

    if action == "enable_agent":
        # Re-enable Agent API. Never demote a master; never overrides Settings → uncheck
        # (agent_manual_off): only the local admin can clear that flag by enabling the checkbox.
        with mutate() as st:
            ns = st.setdefault("settings", {}).setdefault("nodes", {})
            if ns.get("agent_manual_off"):
                return {"ok": False, "error": "agent выключен вручную на этой ноде", "manual_off": True}
            ns["agent_enabled"] = True
            ns["agent_manual_off"] = False
            # Keep master role; only force agent when already demoted / unset
            if (ns.get("role") or "master") != "master":
                ns["role"] = "agent"
            if not ns.get("agent_token"):
                _set_agent_token(ns, secrets.token_urlsafe(32))
            elif not ns.get("agent_token_hash"):
                _set_agent_token(ns, ns["agent_token"])
            role_out = ns.get("role") or "agent"
        return {"ok": True, "error": "", "agent_enabled": True, "role": role_out}

    if action == "demote_to_agent":
        # Explicit demotion of a former/stuck master so sync can proceed without reinstall.
        # Allowed on master without allow_master_manage (see manage_action_allowed).
        if str(payload.get("confirm") or "") != "yes":
            return {"ok": False, "error": "confirm=yes required"}
        with mutate() as st:
            out = nodes_mod.demote_store_to_agent(st)
        return out

    if action == "restart_xray":
        r = ops.xray_control("restart")
        return {"ok": bool(r.get("ok")), "error": "" if r.get("ok") else (r.get("stderr") or "restart failed"), "result": r}

    if action == "check_xray":
        xs = xray.xray_status()
        current = str(xs.get("version") or "")
        include_pre = str(payload.get("include_prerelease") or "") in ("1", "true", "yes", "on")
        latest = ops.xray_latest(include_pre)
        tag = str(latest.get("tag") or "") if latest.get("ok") else ""
        available = bool(tag) and ops.version_tuple(tag) > ops.version_tuple(current)
        return {
            "ok": True,
            "error": "" if latest.get("ok") else (latest.get("error") or "github"),
            "xray": xs,
            "current": current,
            "latest": tag,
            "available": available,
            "url": latest.get("url") or "",
            "prerelease": bool(latest.get("prerelease")),
            "published": latest.get("published") or "",
            "active": bool(xs.get("active")),
        }

    if action == "update_xray":
        version = str(payload.get("version") or "").strip()
        include_pre = str(payload.get("include_prerelease") or "") in ("1", "true", "yes", "on")
        if not version:
            latest = ops.xray_latest(include_pre)
            if not latest.get("ok") or not latest.get("tag"):
                return {"ok": False, "error": latest.get("error") or "не удалось получить latest Xray"}
            version = str(latest["tag"])
        current = str(xray.xray_status().get("version") or "")
        running = XRAY_UPDATE_JOB.get("id")
        if running and ops.JOBS.get(running, {}).get("status") == "running":
            return {"ok": True, "started": False, "already": True, "version": version, "current": current}

        def install_and_recheck(v: str) -> dict:
            res = ops.install_xray(v)
            try:
                check_xray_update(force=True)
            except Exception:
                pass
            return res

        XRAY_UPDATE_JOB["id"] = ops.start_job("xray-update-remote", install_and_recheck, version)
        return {"ok": True, "started": True, "version": version, "current": current}

    if action == "apply_xray":
        res = _apply_xray(_load_store())
        return {"ok": bool(res.get("ok")), "error": res.get("error") or ""}

    if action == "save_panel":
        with mutate() as st:
            p = st.setdefault("settings", {}).setdefault("panel", {})
            if "title" in payload:
                p["title"] = str(payload.get("title") or "").strip()
            if "public_host" in payload:
                host = str(payload.get("public_host") or "").strip()
                if host:
                    p["public_host"] = host
            if "lang" in payload:
                p["lang"] = str(payload.get("lang") or "ru")
            if "theme" in payload:
                p["theme"] = str(payload.get("theme") or "dark")
            if "timezone" in payload:
                p["timezone"] = str(payload.get("timezone") or "").strip()
            if "base_path" in payload:
                bp = str(payload.get("base_path") or "").strip().strip("/")
                if bp and SLUG_RE.match(bp):
                    p["base_path"] = bp
        _refresh_settings_cache()
        try:
            _sync_servers()
        except Exception:
            pass
        return {"ok": True, "error": "", **_manage_snapshot(_load_store())}

    if action == "set_admin_password":
        return {
            "ok": False,
            "error": "смена пароля через agent token отключена — смените локально в Settings → Admins",
        }

    if action == "update_panel":
        running = PANEL_UPDATE_JOB.get("id")
        if running and ops.JOBS.get(running, {}).get("status") == "running":
            return {"ok": True, "started": False, "already": True, "current": panel_version()}
        PANEL_UPDATE_JOB["id"] = ops.start_job("panel-update-remote", ops.update_panel)
        return {"ok": True, "started": True, "current": panel_version()}

    if action == "rollback_panel":
        tag = ops.normalize_tag(str(payload.get("version") or ""))
        if not tag:
            return {"ok": False, "error": "version required (e.g. v1.9.72)"}
        running = PANEL_UPDATE_JOB.get("id")
        if running and ops.JOBS.get(running, {}).get("status") == "running":
            return {"ok": True, "started": False, "already": True, "current": panel_version(), "version": tag}
        PANEL_UPDATE_JOB["id"] = ops.start_job("panel-rollback-remote", ops.rollback_panel, tag)
        return {"ok": True, "started": True, "current": panel_version(), "version": tag}

    if action == "rollback_xray":
        ver = str(payload.get("version") or "").strip()
        running = XRAY_UPDATE_JOB.get("id")
        if running and ops.JOBS.get(running, {}).get("status") == "running":
            return {"ok": True, "started": False, "already": True}
        XRAY_UPDATE_JOB["id"] = ops.start_job("xray-rollback-remote", ops.rollback_xray, ver)
        return {"ok": True, "started": True, "version": ver or "bak"}

    if action == "restore_master":
        with mutate() as st:
            ns = st.setdefault("settings", {}).setdefault("nodes", {})
            # Keep Agent API online on master (unless admin set agent_manual_off)
            if not ns.get("agent_manual_off"):
                ns["agent_enabled"] = True
            ns["role"] = "master"
            ns["runtime_preserve"] = False
            ns["mirror"] = False
            ns.pop("master_pull_url", None)
        xr = _apply_xray(_load_store())
        return {"ok": bool(xr.get("ok")), "error": xr.get("error") or "", "role": "master"}

    if action == "ensure_network_perf":
        return ops.ensure_network_perf()

    if action == "iperf3_ensure":
        return ops.ensure_iperf3()

    if action == "iperf3_serve":
        port = max(1024, min(65535, _int(payload.get("port"), 5201)))
        one_off = str(payload.get("one_off") or "1") not in ("0", "false", "no")
        return ops.iperf3_server_start(port, one_off=one_off)

    if action == "iperf3_client":
        host = str(payload.get("host") or "").strip()
        port = max(1024, min(65535, _int(payload.get("port"), 5201)))
        seconds = max(3, min(30, _int(payload.get("seconds"), 8)))
        reverse = str(payload.get("reverse") or "") in ("1", "true", "yes", "on")
        return ops.iperf3_client(host, port, seconds=seconds, reverse=reverse)

    if action == "restart_panel":
        # Delayed restart so the HTTP response can leave
        def _restart():
            import time as _t
            _t.sleep(1.5)
            return ops._run(["systemctl", "restart", ops.active_panel_unit()], 30)
        ops.start_job("panel-restart-remote", _restart)
        return {"ok": True, "error": "", "restarting": True}

    if action == "get_logs":
        src = str(payload.get("src") or "xray")
        lines = max(50, min(2000, _int(payload.get("n"), 300)))
        grep = str(payload.get("q") or "")
        if src == "access":
            text = ops.tail(str(xray.XRAY_LOG_DIR / "access.log"), lines)
            if grep:
                text = "\n".join(line for line in text.splitlines() if grep in line)
        else:
            text = ops.journal({"xray": "xray", "panel": "l2xpanel"}.get(src, "xray"), lines, grep)
        return {"ok": True, "text": text, "src": src, "n": lines, "q": grep}

    if action == "xray_debug":
        return ops.xray_debug_capture(
            _int(payload.get("seconds"), 20), str(payload.get("q") or ""), _int(payload.get("n"), 400),
        )

    if action == "xray_config":
        try:
            cfg = json.loads(Path("/etc/xray/config.json").read_text(encoding="utf-8"))
        except Exception as e:
            return {"ok": False, "error": str(e)}
        for ib in cfg.get("inbounds") or []:
            for c in (ib.get("settings") or {}).get("clients") or []:
                if c.get("id"):
                    c["id"] = str(c["id"])[:8] + "…"
        return {"ok": True, "config": cfg}

    if action == "nodes":
        rows = []
        for n in nodes_mod.ensure_list(_load_store()):
            rows.append({k: n.get(k) for k in (
                "id", "name", "domain", "nat", "as_outbound", "enabled", "online", "panel_version",
                "rv_tag", "last_pull", "last_sync", "last_warning", "last_error", "reverse_ok",
                "agent_diag", "agent_diag_at", "rv_conns",
            )})
            rows[-1]["rv_uuid"] = str(n.get("rv_uuid") or "")[:8]
        return {"ok": True, "nodes": rows}

    if action == "node_diag":
        node_id = str(payload.get("node_id") or "").strip()
        with mutate() as st:
            node = next((n for n in nodes_mod.ensure_list(st) if n.get("id") == node_id), None)
            if not node:
                return {"ok": False, "error": "unknown node"}
            node["diag_requested"] = {
                "seconds": max(5, min(90, _int(payload.get("seconds"), 25))),
                "q": str(payload.get("q") or ""),
            }
        return {"ok": True, "error": "", "queued": True}

    return {"ok": False, "error": f"unknown action: {action}"}


@app.api_route("/agent/manage", methods=["GET", "POST"])
async def agent_manage(request: Request):
    """Remote control channel for Settings Node (token auth, role-independent)."""
    store, err = _agent_manage_auth(request)
    if err:
        return err
    if request.method == "GET":
        return _manage_snapshot(store)
    try:
        payload = await request.json()
    except ValueError:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    action = str(payload.get("action") or "").strip()
    return _manage_action(action, payload)


@app.post("/agent/update")
async def agent_update(request: Request):
    """Master triggers panel self-update on this node (works even if agent mode is off)."""
    store, err = _agent_manage_auth(request)
    if err:
        return err
    try:
        payload = await request.json()
    except ValueError:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    if str(payload.get("confirm") or "") != "yes":
        return JSONResponse({"ok": False, "error": "confirm required"}, status_code=400)
    running = PANEL_UPDATE_JOB.get("id")
    if running and ops.JOBS.get(running, {}).get("status") == "running":
        return {"ok": True, "started": False, "already": True, "current": panel_version()}

    def do_update():
        return ops.update_panel()

    PANEL_UPDATE_JOB["id"] = ops.start_job("panel-update-agent", do_update)
    return {"ok": True, "started": True, "current": panel_version()}


@app.post("/agent/promote")
async def agent_promote(request: Request):
    """Flip this mirrored agent to master using already-synced (or final) store data.

    Role flips only after Xray apply succeeds; otherwise rolls back to agent.
    Heavy DoH docker recreate runs in background so the HTTP call does not time out.

    Auth is token-only (``_agent_manage_auth``): promote must work even when
    ``agent_enabled`` was flipped off by a bad sync/update — otherwise handoff
    dead-ends with ``agent disabled``.
    """
    store, err = _agent_manage_auth(request)
    if err:
        return err
    try:
        payload = await request.json()
    except ValueError:
        return JSONResponse({"ok": False, "error": "bad json"}, status_code=400)
    if not isinstance(payload, dict) or str(payload.get("confirm") or "") != "yes":
        return JSONResponse({"ok": False, "error": "confirm required"}, status_code=400)
    try:
        prev = {}
        with mutate() as st:
            ns = st.setdefault("settings", {}).setdefault("nodes", {})
            prev = {
                "agent_enabled": bool(ns.get("agent_enabled")),
                "role": ns.get("role") or "agent",
                "mirror": bool(ns.get("mirror")),
            }
            for key in ("clients", "inbounds", "routes", "balancers", "outbounds_custom", "dns", "xray_settings", "ip_bans"):
                if key in payload and payload[key] is not None:
                    st[key] = payload[key]
            if payload.get("settings"):
                nodes_mod.apply_promoted_settings(st, payload.get("settings"))
            if payload.get("nodes") is not None:
                st["nodes"] = payload["nodes"]
            elif payload.get("old_master"):
                nodes = nodes_mod.ensure_list(st)
                old = payload["old_master"]
                nodes[:] = [n for n in nodes if n.get("id") != old.get("id")]
                nodes.insert(0, old)
            # Subscription links must advertise THIS host, not the demoted master.
            new_host = ((st.get("settings") or {}).get("panel") or {}).get("public_host") or ""
            old_hosts: list[str] = []
            om = payload.get("old_master") or {}
            if om.get("domain"):
                old_hosts.append(str(om["domain"]))
            inc_host = ((payload.get("settings") or {}).get("panel") or {}).get("public_host") or ""
            if inc_host:
                old_hosts.append(str(inc_host))
            nodes_mod.remap_inbound_share_hosts(st, new_host=str(new_host or ""), old_hosts=old_hosts)
            ns = st.setdefault("settings", {}).setdefault("nodes", {})
            # Master keeps Agent API online so handoff/manage never hit «agent disabled»
            if not ns.get("agent_manual_off"):
                ns["agent_enabled"] = True
            ns["role"] = "master"
            ns["mirror"] = False
            ns["runtime_preserve"] = False
            ns.pop("master_pull_url", None)
            ns.pop("pull", None)
            ns.pop("reverse_bridge", None)
            ns.pop("upstream_master_url", None)
            tun = payload.get("tunnel_settings")
            if isinstance(tun, dict) and tun:
                ns["tunnel"] = tun
        if payload.get("tunnel_bundle"):
            try:
                nodes_mod.apply_tunnel_bundle(payload.get("tunnel_bundle"), payload.get("tunnel_settings"))
            except Exception:
                pass
        n_certs = ops.import_certs_bundle(payload.get("certs") or [])
        # Write DoH files now; recreate container in background (docker pull/up can exceed proxy timeouts)
        doh_res = ops.import_doh_bundle(payload.get("doh_bundle") or [], recreate=False)
        doh_files = int((doh_res or {}).get("files") or 0)
        if doh_files:
            def _bg_pihole():
                try:
                    ops.import_doh_bundle(payload.get("doh_bundle") or [], recreate=True)
                except Exception:
                    pass
            threading.Thread(target=_bg_pihole, name="promote-pihole", daemon=True).start()
        _refresh_settings_cache()
        res = _apply_xray(_load_store())
        if not res.get("ok"):
            with mutate() as st:
                ns = st.setdefault("settings", {}).setdefault("nodes", {})
                ns["agent_enabled"] = prev.get("agent_enabled", True)
                ns["role"] = prev.get("role") or "agent"
                ns["mirror"] = bool(prev.get("mirror"))
            err_txt = res.get("error") or "xray apply failed"
            try:
                err_txt = xray.clean_xray_error(err_txt) or err_txt
            except Exception:
                pass
            return JSONResponse({"ok": False, "error": err_txt, "rolled_back": True}, status_code=500)
        n_custom = len(payload.get("outbounds_custom") or [])
        return {
            "ok": True, "error": "", "role": "master", "version": panel_version(),
            "transferred_custom": n_custom,
            "transferred_certs": n_certs,
            "transferred_doh_files": doh_files,
            "doh_pihole_async": bool(doh_files),
            "assets_slimmed": bool(payload.get("assets_slimmed")),
            "doh_enabled": bool(((_load_store().get("settings") or {}).get("doh") or {}).get("enabled")),
        }
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"ok": False, "error": f"promote exception: {exc}"}, status_code=500)


def _agent_apply_payload(payload: dict, *, hold_front_commit: bool = False) -> dict:
    """Apply a master payload on this agent (push or pull). Returns {ok, error, warnings, mirror}.

    hold_front_commit: used by /agent/apply so nginx reload runs in BackgroundTasks
    after the HTTP response is sent (avoids "Remote end closed without response").
    """
    mirror = bool(payload.get("mirror"))
    keep_tags: set[str] = set()
    if payload.get("direct_connect"):
        keep_tags.add(nodes_mod.MASTER_EGRESS_TAG)
        dc_tag0 = str(payload.get("direct_connect_tag") or "").strip()
        if dc_tag0:
            keep_tags.add(dc_tag0)
    with mutate() as st:
        if payload.get("clients") is not None:
            st["clients"] = (
                list(payload["clients"]) if mirror
                else nodes_mod._agent_safe_clients(payload["clients"], keep_tags=keep_tags)
            )
        if payload.get("inbounds") is not None:
            inbounds = payload["inbounds"]
            local_host = front.public_domain(st) or (
                (st.get("settings") or {}).get("panel") or {}
            ).get("public_host") or ""
            local_host = nodes_mod._normalize_domain(str(local_host or ""))
            if local_host:
                old = {
                    nodes_mod._normalize_domain(ib.get("share_host") or "")
                    for ib in (inbounds or []) if isinstance(ib, dict)
                }
                old.discard("")
                old.discard(local_host)
                inbounds = nodes_mod.remap_inbounds_for_host(
                    inbounds, new_host=local_host, old_hosts=old,
                )
            st["inbounds"] = inbounds
        if payload.get("outbounds_custom") is not None:
            if mirror:
                st["outbounds_custom"] = list(payload["outbounds_custom"] or [])
            else:
                kept: list = []
                for o in (payload["outbounds_custom"] or []):
                    kind = o.get("kind")
                    tag = str(o.get("tag") or "")
                    if kind == "node":
                        continue
                    if kind in ("local_direct", "master_egress") or tag == nodes_mod.MASTER_EGRESS_TAG:
                        kept.append(o)
                        continue
                    if tag.startswith("node_"):
                        continue
                    kept.append(o)
                st["outbounds_custom"] = kept
        if payload.get("routes") is not None:
            if mirror and not payload.get("direct_connect"):
                st["routes"] = list(payload["routes"])
            else:
                routes = nodes_mod._agent_safe_routes(payload["routes"], keep_tags=keep_tags)
                if payload.get("direct_connect"):
                    try:
                        bals = set(xray.balancer_tags({"balancers": payload.get("balancers") or st.get("balancers") or {}}))
                    except Exception:
                        bals = set()
                    routes = nodes_mod.sanitize_direct_agent_routes(
                        routes,
                        self_tag=str(payload.get("direct_connect_tag") or "").strip(),
                        balancer_tags=bals,
                    )
                st["routes"] = routes
        if payload.get("balancers") is not None:
            st["balancers"] = (
                payload["balancers"] if mirror
                else nodes_mod._agent_safe_balancers(payload["balancers"], keep_tags=keep_tags)
            )
        if payload.get("dns") is not None:
            st["dns"] = payload["dns"]
        if payload.get("xray_settings") is not None:
            st["xray_settings"] = payload["xray_settings"]
        if mirror and payload.get("settings"):
            nodes_mod.apply_promoted_settings(st, payload.get("settings"))
        if mirror and payload.get("nodes") is not None:
            st["nodes"] = list(payload["nodes"] or [])
        ns = st.setdefault("settings", {}).setdefault("nodes", {})
        if not ns.get("agent_manual_off"):
            ns["agent_enabled"] = True
            ns["role"] = "agent"
        ns["mirror"] = mirror
        ns["runtime_preserve"] = False
        ns["direct_connect"] = bool(payload.get("direct_connect"))
        dc_tag = str(payload.get("direct_connect_tag") or "").strip()
        if dc_tag:
            ns["direct_connect_tag"] = dc_tag
        elif not ns.get("direct_connect"):
            ns.pop("direct_connect_tag", None)
        if payload.get("node_id"):
            ns["upstream_node_id"] = str(payload.get("node_id"))
        master_url = str(payload.get("master_url") or "").rstrip("/")
        if master_url:
            ns["upstream_master_url"] = master_url
            # Mirror/public agents keep an explicit pointer even without NAT pull cycle
            if not isinstance(ns.get("pull"), dict):
                ns["master_pull_url"] = master_url
        masters = payload.get("masters")
        if isinstance(masters, list) and isinstance(ns.get("pull"), dict):
            ns["pull"]["fallbacks"] = [str(m).rstrip("/") for m in masters if m][:8]
        # Only touch reverse_bridge when the key is present. Omitting it keeps the
        # agent's current bridge (avoids wiping reverse when master failed to build one).
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
    tunnel_agent_res = None
    if isinstance(payload.get("tunnel_agent"), dict):
        try:
            tunnel_agent_res = nodes_mod.apply_tunnel_agent_local(payload.get("tunnel_agent"))
        except Exception as exc:  # noqa: BLE001
            tunnel_agent_res = {"ok": False, "error": str(exc)}
    res = _apply_xray(_load_store(), hold_front_commit=hold_front_commit)
    err = res.get("error") or ""
    try:
        err = xray.clean_xray_error(err) or err
    except Exception:
        pass
    warnings: list[str] = []
    try:
        doh_cfg = (_load_store().get("settings") or {}).get("doh") or {}
        if doh_cfg.get("enabled"):
            ready = doh_mod.pihole_ready()
            if not ready.get("ok"):
                warnings.append(
                    "DoH/Pi-hole настройки переданы sync'ом, но на ноде Pi-hole не готов: "
                    f"{ready.get('reason') or 'не установлен'}. "
                    "Установите Pi-hole на этой ноде (DoH / Pi-hole → Установить), иначе DNS-over-HTTPS здесь не заработает."
                )
    except Exception:
        pass
    out = {"ok": bool(res.get("ok")), "error": err, "mirror": mirror, "warnings": warnings}
    if tunnel_agent_res is not None:
        out["tunnel_agent"] = tunnel_agent_res
        if not tunnel_agent_res.get("ok"):
            warnings.append(
                "L2X tunnel-agent: "
                + str(tunnel_agent_res.get("error") or "не применился — проверьте бинарь /usr/local/bin/l2x-tunnel-agent")
            )
            out["warnings"] = warnings
    if hold_front_commit and res.get("_front_staged") is not None:
        out["_front_staged"] = res["_front_staged"]
    return out


@app.post("/agent/apply")
async def agent_apply(request: Request, background_tasks: BackgroundTasks):
    """Remote node agent: accept pushed config from master panel."""
    store, err = _agent_auth(request)
    if err:
        return err
    try:
        payload = await request.json()
    except ValueError:
        return JSONResponse({"ok": False, "error": "bad json"}, status_code=400)
    if not isinstance(payload, dict):
        return JSONResponse({"ok": False, "error": "bad json"}, status_code=400)
    # Master keeps Agent API online. Plain apply is rejected (use /agent/promote to become
    # master). Sync payloads carry demote_to_agent so a former master can flip to agent
    # without SSH reinstall / manual store edits.
    if nodes_mod.is_master(store):
        if not nodes_mod.wants_demote_to_agent(payload):
            return JSONResponse(
                {"ok": False, "error": "master rejects apply (Agent API online; use /agent/promote)"},
                status_code=403,
            )

        def _demote() -> dict:
            with mutate() as st:
                return nodes_mod.demote_store_to_agent(st)

        demoted = await run_in_threadpool(_demote)
        if not demoted.get("ok"):
            return JSONResponse(
                {
                    "ok": False,
                    "error": demoted.get("error") or "demote failed",
                    "manual_off": bool(demoted.get("manual_off")),
                },
                status_code=403,
            )

    def _run() -> dict:
        return _agent_apply_payload(payload, hold_front_commit=True)

    out = await run_in_threadpool(_run)
    staged = out.pop("_front_staged", None)
    if staged is not None and out.get("ok"):
        # Reload nginx only after the response bytes are on the wire.
        background_tasks.add_task(_commit_front_safe, staged)
        background_tasks.add_task(lambda: _issue_front_certs(_load_store()))
    elif staged is not None:
        try:
            front.rollback(staged)
        except Exception:
            pass
    return out


@app.post("/agent/report")
async def agent_report(request: Request):
    """Direct-connect agent reports traffic/online to master (Bearer = node token)."""
    store = _load_store()
    try:
        body = await request.json()
    except ValueError:
        body = {}
    if not isinstance(body, dict):
        body = {}
    node_id = str(body.get("node_id") or "").strip()
    auth = request.headers.get("authorization") or ""
    token = auth.removeprefix("Bearer ").strip() if auth.startswith("Bearer ") else ""
    if err := _agent_rate_ok(request, "report"):
        return err
    if not nodes_mod.is_master(store):
        return JSONResponse({"ok": False, "error": "not master"}, status_code=403)
    if not node_id or not token:
        return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)
    err_code, err_msg = 0, ""
    changed = False
    with mutate() as st:
        node = next((n for n in nodes_mod.ensure_list(st) if n.get("id") == node_id), None)
        if not node or not node.get("enabled", True):
            err_code, err_msg = 404, "unknown node"
        elif not sec.any_token_eq(token, [node.get("token") or ""]):
            err_code, err_msg = 401, "unauthorized"
        elif not nodes_mod.uses_direct_connect(node):
            err_code, err_msg = 400, "direct_connect disabled"
        else:
            changed = nodes_mod.apply_agent_traffic_report(
                st, node,
                body.get("traffic") if isinstance(body.get("traffic"), dict) else {},
                body.get("online") if isinstance(body.get("online"), dict) else {},
            )
            node["last_ok"] = True
            node["last_seen"] = nodes_mod.now_iso()
    if err_code:
        return JSONResponse({"ok": False, "error": err_msg}, status_code=err_code)
    return {"ok": True, "changed": bool(changed)}


@app.post("/agent/pull")
async def agent_pull(request: Request):
    """NAT agent pulls config from master (Bearer = master agent_token, body.node_id)."""
    store = _load_store()
    try:
        body = await request.json()
    except ValueError:
        body = {}
    if not isinstance(body, dict):
        body = {}
    node_id = str(body.get("node_id") or "").strip()
    auth = request.headers.get("authorization") or ""
    token = auth.removeprefix("Bearer ").strip() if auth.startswith("Bearer ") else ""
    ns_local = (store.get("settings") or {}).get("nodes") or {}
    if err := _agent_rate_ok(request, "pull"):
        return err
    node_tokens = [
        n.get("token") or "" for n in (store.get("nodes") or [])
        if n.get("id") == node_id
    ]
    if not token or not (
        _agent_token_ok(ns_local, token) or sec.any_token_eq(token, node_tokens)
    ):
        return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)
    if not nodes_mod.is_master(store):
        # Demoted master: point the NAT agent at the new master. ok=True + update so agents
        # older than the moved-aware code still self-update instead of looping on 403.
        moved_to = str(ns_local.get("master_pull_url") or "").rstrip("/")
        if moved_to:
            agent_ver = str(body.get("version") or "")
            outdated = bool(agent_ver) and (
                nodes_mod.version_tuple(agent_ver) < nodes_mod.version_tuple(panel_version())
            )
            return {
                "ok": True, "unchanged": True, "moved": True, "master_url": moved_to,
                **({"update": True} if outdated else {}),
            }
        return JSONResponse({"ok": False, "error": "not master"}, status_code=403)
    have_ver = str(body.get("have") or "").strip()
    status = body.get("status") if isinstance(body.get("status"), dict) else {}
    events: list[dict] = []
    err_code = 0
    err_msg = ""
    payload: dict = {}
    ver = ""
    want_update = False
    diag_req = None
    iperf_req = None
    xray_upd = ""
    agent_ver = str(body.get("version") or "")
    master_ver = panel_version()
    with mutate() as st:
        node = next((n for n in nodes_mod.ensure_list(st) if n.get("id") == node_id), None)
        if not node or not node.get("enabled", True):
            err_code, err_msg = 404, "unknown node"
        elif not node.get("nat"):
            err_code, err_msg = 400, "node is not NAT mode"
        else:
            events = nodes_mod.apply_pull_seen(
                node, version=agent_ver, status=status, master_version=master_ver,
            )
            want_update = nodes_mod.pull_wants_update(node, agent_ver, master_ver)
            diag_text = body.get("diag")
            if isinstance(diag_text, str) and diag_text:
                node["agent_diag"] = diag_text[-60000:]
                node["agent_diag_at"] = nodes_mod.now_iso()
            diag_req = node.pop("diag_requested", None)
            # iperf3 result from NAT agent (after master queued iperf3_requested)
            iperf_body = body.get("iperf3") if isinstance(body.get("iperf3"), dict) else None
            if not iperf_body and isinstance(status.get("iperf3"), dict):
                iperf_body = status.get("iperf3")
            if isinstance(iperf_body, dict) and iperf_body.get("nonce"):
                node["iperf3_result"] = iperf_body
                if node.get("iperf3_requested") and (
                    (node["iperf3_requested"] or {}).get("nonce") == iperf_body.get("nonce")
                ):
                    node.pop("iperf3_requested", None)
            # Hand out pending bench request (do not pop until result arrives — re-send)
            pending_iperf = node.get("iperf3_requested")
            if isinstance(pending_iperf, dict) and pending_iperf.get("host"):
                iperf_req = dict(pending_iperf)
            # Remember Xray version reported by NAT agent pull status
            xv = str(status.get("xray_version") or "").strip()
            if xv:
                node["xray_version"] = xv.lstrip("vV")
            if "xray_active" in status:
                node["xray_active"] = bool(status.get("xray_active"))
            # Keep re-sending until agent reports matching/newer Xray (not one-shot pop)
            xray_upd = nodes_mod.pull_xray_update_tag(node, status)
            nodes_mod.upsert_node_outbound(st, node)
            payload = nodes_mod.build_payload(st, node, xray.build_config)
            self_url = f"https://{public_host()}{base_path()}" if public_host() else ""
            payload["masters"] = nodes_mod.master_candidates(
                st, self_url=self_url, exclude_id=node_id,
            )
            ver = nodes_mod.payload_version(payload)
            node["last_sync"] = nodes_mod.now_iso()
    if err_code:
        return JSONResponse({"ok": False, "error": err_msg}, status_code=err_code)
    if events:
        _tg_node_events(events)
    extra: dict = {}
    if isinstance(diag_req, dict):
        extra["diag"] = diag_req
    if isinstance(iperf_req, dict):
        extra["iperf3"] = iperf_req
    if want_update:
        extra["update"] = True
        if isinstance(payload, dict):
            payload = {**payload, "panel_update": True}
    if xray_upd:
        extra["xray_update"] = xray_upd if xray_upd.startswith("v") else f"v{xray_upd}"
        if isinstance(payload, dict):
            payload = {**payload, "xray_update": extra["xray_update"]}
    if have_ver and have_ver == ver:
        return {"ok": True, "unchanged": True, "version": ver, **extra}
    return {"ok": True, "unchanged": False, "version": ver, "payload": payload, **extra}


AGENT_DIAG: dict = {}
AGENT_IPERF: dict = {}  # {"running": bool, "result": dict|None}


def _run_agent_iperf3(req: dict) -> dict:
    """NAT agent: install iperf3 and measure both directions to master's server."""
    host = str(req.get("host") or "").strip()
    port = max(1024, min(65535, _int(req.get("port"), 5201)))
    seconds = max(3, min(20, _int(req.get("seconds"), 8)))
    nonce = str(req.get("nonce") or "")
    ens = ops.ensure_iperf3()
    if not ens.get("ok"):
        return {"ok": False, "nonce": nonce, "error": ens.get("error") or "iperf3 install failed"}
    up = ops.iperf3_client(host, port, seconds=seconds, reverse=False)
    down = ops.iperf3_client(host, port, seconds=seconds, reverse=True)
    ok = bool(up.get("ok") and down.get("ok"))
    return {
        "ok": ok,
        "nonce": nonce,
        "up_mbps": up.get("up_mbps") if up.get("ok") else None,
        "down_mbps": down.get("down_mbps") if down.get("ok") else None,
        "seconds": seconds,
        "host": host,
        "port": port,
        "error": "" if ok else (
            ("" if up.get("ok") else f"↑ {up.get('error')}; ")
            + ("" if down.get("ok") else f"↓ {down.get('error')}")
        ).strip("; "),
        "at": nodes_mod.now_iso(),
    }


def _reverse_conn_count(rb) -> int:
    """Established TCP connections from this agent to the master reverse endpoint.

    Prefers sockets owned by xray (avoids counting unrelated HTTPS to the same host).
    """
    if not isinstance(rb, dict) or not rb.get("master_host"):
        return -1
    import socket
    import subprocess as _sp
    try:
        ips = {a[4][0] for a in socket.getaddrinfo(rb["master_host"], None)}
        out = _sp.run(
            ["ss", "-Htnip", "state", "established"], capture_output=True, text=True, timeout=10,
        ).stdout
    except Exception:
        return -1
    port = str(int(rb.get("port") or 443))
    n = 0
    for line in out.splitlines():
        low = line.lower()
        # When -p is available, prefer xray-owned sockets only
        if "users:(" in low and "xray" not in low and "\"xray\"" not in low:
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        host, _, p = parts[3].rpartition(":")
        if p == port and host.strip("[]").removeprefix("::ffff:") in ips:
            n += 1
    return n


def _start_agent_diag(req: dict) -> None:
    def job():
        AGENT_DIAG["running"] = True
        try:
            cfg_txt = ""
            try:
                cfg = json.loads(Path("/etc/xray/config.json").read_text(encoding="utf-8"))
                cfg_txt = json.dumps({
                    "outbounds": [o for o in cfg.get("outbounds") or []
                                  if str(o.get("tag") or "").startswith("rv-")],
                    "rules": [r for r in (cfg.get("routing") or {}).get("rules") or []][:6],
                }, ensure_ascii=False)
            except Exception as e:
                cfg_txt = f"config: {e}"
            r = ops.xray_debug_capture(int(req.get("seconds") or 25), str(req.get("q") or ""), 1500)
            rb = (_load_store().get("settings") or {}).get("nodes", {}).get("reverse_bridge")
            AGENT_DIAG["text"] = (
                f"version={panel_version()} rv_conns_after={_reverse_conn_count(rb)}\n"
                f"{cfg_txt}\n----- xray debug -----\n{r.get('text') or r.get('error')}"
            )
        finally:
            AGENT_DIAG["running"] = False

    threading.Thread(target=job, daemon=True).start()


def _agent_pull_cycle() -> None:
    """On a NAT agent: poll master for config and apply when version changes."""
    store = _load_store()
    ns = (store.get("settings") or {}).get("nodes") or {}
    if (ns.get("role") or "") != "agent":
        return
    pull = ns.get("pull") if isinstance(ns.get("pull"), dict) else None
    if not pull or not pull.get("master_url") or not pull.get("node_id"):
        return
    token = ns.get("agent_token") or ""
    if not token:
        return
    have = str(ns.get("pull_version") or "")
    warnings: list[str] = []
    reverse_ok = False
    try:
        cfg_path = Path("/etc/xray/config.json")
        if cfg_path.is_file():
            cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
            tags = {o.get("tag") for o in (cfg.get("outbounds") or [])}
            has_up = any(str(t).startswith("rv-up") for t in tags)
            has_tags = has_up and "rv-direct" in tags
            xray_on = False
            try:
                import subprocess as _sp
                xray_on = _sp.run(
                    ["systemctl", "is-active", "--quiet", "xray"], check=False,
                ).returncode == 0
            except Exception:
                xray_on = True
            reverse_ok = bool(has_tags and xray_on)
            if ns.get("reverse_bridge") and not has_tags:
                warnings.append("reverse outbound не собран (нет rv-up/rv-direct)")
            elif ns.get("reverse_bridge") and not xray_on:
                warnings.append("Xray на ноде не запущен — reverse недоступен")
    except Exception:
        pass
    rv_conns = _reverse_conn_count(ns.get("reverse_bridge"))
    if ns.get("reverse_bridge") and rv_conns == 0:
        warnings.append("нет TCP-соединений reverse к мастеру")
    try:
        xs_local = xray.xray_status()
    except Exception:
        xs_local = {}
    body = {
        "node_id": pull["node_id"],
        "have": have,
        "version": panel_version(),
        "status": {
            "ok": True,
            "error": str(ns.get("last_apply_error") or ""),
            "warnings": warnings,
            "reverse_ok": reverse_ok,
            "rv_conns": rv_conns,
            "xray_version": str(xs_local.get("version") or ""),
            "xray_active": bool(xs_local.get("active")),
        },
    }
    diag_ready = AGENT_DIAG.pop("text", None)
    if diag_ready:
        body["diag"] = diag_ready
    iperf_ready = AGENT_IPERF.pop("result", None)
    if isinstance(iperf_ready, dict):
        body["iperf3"] = iperf_ready
        body["status"]["iperf3"] = iperf_ready
    current = str(pull["master_url"]).rstrip("/")
    res = nodes_mod.pull_request(current, token, body, timeout=45)
    if diag_ready and not res.get("ok"):
        AGENT_DIAG.setdefault("text", diag_ready)
    if isinstance(iperf_ready, dict) and not res.get("ok"):
        AGENT_IPERF.setdefault("result", iperf_ready)
    if isinstance(res.get("diag"), dict) and not AGENT_DIAG.get("running"):
        _start_agent_diag(res["diag"])
    if isinstance(res.get("iperf3"), dict) and not AGENT_IPERF.get("running"):
        def _iperf_job(req: dict) -> None:
            AGENT_IPERF["running"] = True
            try:
                AGENT_IPERF["result"] = _run_agent_iperf3(req)
            except Exception as exc:  # noqa: BLE001
                AGENT_IPERF["result"] = {
                    "ok": False,
                    "nonce": str(req.get("nonce") or ""),
                    "error": str(exc)[:300],
                }
            finally:
                AGENT_IPERF["running"] = False

        threading.Thread(
            target=_iperf_job, args=(res["iperf3"],), daemon=True, name="agent-iperf3",
        ).start()
    if res.get("moved") and res.get("master_url"):
        res = {**res, "ok": False}
    if not res.get("ok"):
        new_url = ""
        if res.get("moved") and res.get("master_url"):
            new_url = str(res["master_url"]).rstrip("/")
        else:
            fails = int(ns.get("pull_fail_streak") or 0) + 1
            with mutate() as st:
                st.setdefault("settings", {}).setdefault("nodes", {})["pull_fail_streak"] = fails
            # Master unreachable / demoted without forwarding — try known mirrors
            if fails >= 3 or res.get("status") == 403:
                for cand in pull.get("fallbacks") or []:
                    cand = str(cand or "").rstrip("/")
                    if not cand or cand == current:
                        continue
                    probe = nodes_mod.pull_request(cand, token, body, timeout=20)
                    if probe.get("moved") and probe.get("master_url"):
                        new_url = str(probe["master_url"]).rstrip("/")
                        break
                    if probe.get("ok"):
                        new_url = cand
                        break
        if new_url and new_url != current:
            with mutate() as st:
                n2 = st.setdefault("settings", {}).setdefault("nodes", {})
                p2 = n2.setdefault("pull", {})
                p2["master_url"] = new_url
                n2["pull_version"] = ""
                n2["pull_fail_streak"] = 0
            res = nodes_mod.pull_request(new_url, token, {**body, "have": ""}, timeout=45)
            if not res.get("ok"):
                return
        else:
            return
    if ns.get("pull_fail_streak"):
        with mutate() as st:
            st.setdefault("settings", {}).setdefault("nodes", {})["pull_fail_streak"] = 0
    payload = res.get("payload") if isinstance(res.get("payload"), dict) else {}
    # Xray update via pull MUST run even if panel update is also requested: master keeps
    # re-sending the tag until our reported xray_version catches up. Handle Xray first so a
    # panel-update early-return cannot starve the core upgrade forever.
    xray_upd = str(res.get("xray_update") or payload.get("xray_update") or "").strip()
    xray_job_started = False
    if xray_upd:
        cur = ""
        try:
            cur = str(xray.xray_status().get("version") or "")
        except Exception:
            cur = ""
        if cur and nodes_mod.version_tuple(cur) >= nodes_mod.version_tuple(xray_upd):
            xray_upd = ""  # already there — master clears on next status report
        else:
            running = XRAY_UPDATE_JOB.get("id")
            if not (running and ops.JOBS.get(running, {}).get("status") == "running"):
                def install_and_recheck(v: str) -> dict:
                    r = ops.install_xray(v)
                    try:
                        check_xray_update(force=True)
                    except Exception:
                        pass
                    return r
                XRAY_UPDATE_JOB["id"] = ops.start_job("xray-update-pull", install_and_recheck, xray_upd)
                xray_job_started = True
    want_update = bool(res.get("update") or payload.get("panel_update"))
    if want_update:
        running = PANEL_UPDATE_JOB.get("id")
        if not (running and ops.JOBS.get(running, {}).get("status") == "running"):
            PANEL_UPDATE_JOB["id"] = ops.start_job("panel-update-pull", ops.update_panel)
        # Prefer finishing the panel update; skip apply on this cycle
        return
    if xray_upd or xray_job_started:
        # Xray install restarts core — apply on next pull after job finishes
        if res.get("unchanged") or not payload:
            return
    if res.get("unchanged"):
        with mutate() as st:
            st.setdefault("settings", {}).setdefault("nodes", {})["pull_version"] = res.get("version") or have
        return
    if not payload:
        return
    applied = _agent_apply_payload(payload)
    with mutate() as st:
        n2 = st.setdefault("settings", {}).setdefault("nodes", {})
        n2["pull_version"] = res.get("version") or ""
        n2["last_apply_error"] = "" if applied.get("ok") else str(applied.get("error") or "")[:400]
        n2["last_pull_at"] = nodes_mod.now_iso()


def _agent_pull_loop() -> None:
    if _stop.wait(25):
        return
    while True:
        try:
            _agent_pull_cycle()
        except Exception:
            pass
        if _stop.wait(20):
            return


@app.get("/api-docs", response_class=HTMLResponse)
def api_docs(request: Request):
    if redir := _require(request):
        return redir
    return page(request, "api_docs.html", active="settings")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "8090")))
