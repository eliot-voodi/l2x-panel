#!/usr/bin/env python3
"""L2X Panel — multi-tunnel L2TP + Xray (multi-inbound) control panel."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import bcrypt
import yaml
from cryptography.fernet import Fernet
from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

import front
import hwid
import l2tp_runtime as l2tp
import nodes as nodes_mod
import ops
import protocols as P
import sysmon
import tgbot
import totp
import webhooks
import xray_runtime as xray

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
SECRETS_DIR = DATA / "l2tp_secrets"
SECRETS_DIR.mkdir(parents=True, exist_ok=True)
l2tp.ensure_runtime_dirs()

APP_NAME_DEFAULT = os.environ.get("APP_NAME", "L2X Panel")
ADMIN_USER_ENV = os.environ.get("PANEL_ADMIN_USER", "admin")
ADMIN_PASSWORD_ENV = os.environ.get("PANEL_ADMIN_PASSWORD", "").strip()
PUBLIC_HOST_ENV = os.environ.get("L2XPANEL_PUBLIC_HOST", "127.0.0.1")
STORE = DATA / "store.json"
ADMIN_FILE = DATA / "admin.json"
CREDS_FILE = DATA / "initial_credentials.txt"
STORE_LOCK = threading.RLock()
STARTED_AT = time.time()


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
            "extra_listen": {"enabled": False, "port": 2053, "cert_file": "", "key_file": ""},
        },
        "sub": {
            "enabled": True, "server_enabled": False, "listen": "0.0.0.0", "port": 2096, "path": "sub",
            "domain": "", "cert_file": "", "key_file": "", "update_hours": 1, "title": "",
            "support_url": "", "announce": "", "show_page": True,
            "json_fragment": "", "json_noise": "", "json_mux": "",
            "hwid_required": False, "migrate_url": False, "happ_provider_id": "",
        },
        "tg": tgbot.default_settings(),
        "webhooks": webhooks.default_settings(),
        "nodes": {"agent_enabled": False, "agent_token": ""},
        "iplimit": {"ban_minutes": 30},
        "security": {"totp_enabled": False, "totp_secret": ""},
        "api_tokens": [],
        "geo_custom": [],
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
    return s


def _load_store() -> dict:
    data: dict = {}
    if STORE.exists():
        try:
            data = json.loads(STORE.read_text(encoding="utf-8"))
        except ValueError:
            data = {}
    for key, default in (("l2tp", []), ("clients", []), ("routes", []), ("outbounds_custom", []), ("ip_bans", [])):
        data.setdefault(key, default)
    data.setdefault("reverse", {"bridges": [], "portals": []})
    xray.ensure_balancers(data)
    xray.ensure_inbounds(data)
    xray._ensure_section(data, "xray_settings", xray.default_xray_settings())
    xray._ensure_section(data, "dns", xray.default_dns())
    _ensure_settings(data)
    dirty = False
    for c in data["clients"]:
        xray.ensure_client(c)
        if not c.get("sub_token"):
            c["sub_token"] = secrets.token_urlsafe(18)
            dirty = True
    if dirty or "inbound" in data:
        data.pop("inbound", None)
        _save_store(data)
    return data


def _save_store(data: dict) -> None:
    tmp = STORE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, STORE)


@contextmanager
def mutate():
    with STORE_LOCK:
        store = _load_store()
        yield store
        _save_store(store)


FRONT_CERT_RETRY = 3600
_front_cert_tried: dict[str, float] = {}


def _apply_xray(store: dict) -> dict:
    """nginx front and Xray are verified before either is loaded; nothing is applied if a check fails."""
    with STORE_LOCK:
        xray.ensure_inbounds(store)
        staged = front.stage(store)
        if not staged["ok"]:
            return {"ok": False, "error": staged["error"], "verified": False}
        result = xray.apply_config(store)
        if not result.get("ok"):
            front.rollback(staged)
            _save_store(store)
            return result
        fr = front.commit(staged)
        if not fr["ok"]:
            result = {**result, "ok": False, "error": fr["error"]}
        elif staged.get("problems"):
            result = {**result, "warning": "; ".join(staged["problems"])}
        _save_store(store)
    _issue_front_certs(store)
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
BASE_PATH_RESERVED = {"sub", "panel", "health", "static", "login", "logout", "well-known"}


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


def _admin() -> dict:
    if ADMIN_FILE.exists():
        try:
            return json.loads(ADMIN_FILE.read_text(encoding="utf-8"))
        except ValueError:
            pass
    legacy = DATA / "admin.bcrypt"
    if legacy.exists():
        password = None
        pw_hash = legacy.read_bytes().decode()
    else:
        password = ADMIN_PASSWORD_ENV or secrets.token_urlsafe(16)
        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    admin = {"username": ADMIN_USER_ENV, "password_hash": pw_hash}
    _save_admin(admin)
    if password is not None and not ADMIN_PASSWORD_ENV:
        _write_initial_credentials(ADMIN_USER_ENV, password)
    return admin


def _save_admin(admin: dict) -> None:
    ADMIN_FILE.write_text(json.dumps(admin), encoding="utf-8")
    os.chmod(ADMIN_FILE, 0o600)


def _check_credentials(username: str, password: str) -> bool:
    admin = _admin()
    if not secrets.compare_digest(username, admin["username"]):
        return False
    try:
        return bcrypt.checkpw(password.encode(), admin["password_hash"].encode())
    except ValueError:
        return False


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# ================================================================ app + middleware

app = FastAPI(title=APP_NAME_DEFAULT, docs_url=None, redoc_url=None, openapi_url=None)


class BasePathMiddleware:
    """Serve the panel under a secret prefix; public sub/API paths stay reachable."""

    PUBLIC = ("/sub/", "/health", "/panel/api/", "/static/")

    def __init__(self, inner):
        self.inner = inner

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            bp = base_path()
            path = scope.get("path") or "/"
            if bp:
                if path == bp or path.startswith(bp + "/"):
                    scope = dict(scope)
                    scope["path"] = path[len(bp):] or "/"
                elif not path.startswith(self.PUBLIC):
                    resp = PlainTextResponse("404 page not found", status_code=404)
                    await resp(scope, receive, send)
                    return
        await self.inner(scope, receive, send)


app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, max_age=12 * 3600, same_site="lax")
app.add_middleware(BasePathMiddleware)
templates = Jinja2Templates(directory=str(ROOT / "ui"))

# ================================================================ i18n / template helpers

I18N_EN = {
    "Дашборд": "Dashboard", "Inbounds": "Inbounds", "Клиенты": "Clients", "L2TP": "L2TP",
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


def _require(request: Request):
    if not _user(request):
        return go("/login")
    exp = request.session.get("exp", 0)
    if exp and time.time() > exp:
        request.session.clear()
        return go("/login")
    return None


def page(request: Request, template: str, active: str = "", status_code: int = 200, **ctx) -> HTMLResponse:
    s = SETTINGS_CACHE or _refresh_settings_cache()
    base = {
        "request": request, "app_name": app_title(), "user": _user(request), "flash": pop_flash(request),
        "bp": base_path(), "active": active, "theme": (s.get("panel") or {}).get("theme") or "dark",
        "lang": (s.get("panel") or {}).get("lang") or "ru", "public_host": public_host(),
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


# ================================================================ L2TP helpers

def _save_l2tp_secrets(name: str, password: str, psk: str) -> None:
    path = SECRETS_DIR / f"{name}.json"
    payload = {"password": _enc(password) if password else "", "psk": _enc(psk) if psk else ""}
    if path.exists() and (not password or not psk):
        old = json.loads(path.read_text(encoding="utf-8"))
        if not password:
            payload["password"] = old.get("password", "")
        if not psk:
            payload["psk"] = old.get("psk", "")
    path.write_text(json.dumps(payload), encoding="utf-8")
    os.chmod(path, 0o600)


def _load_l2tp_secrets(name: str) -> tuple[str, str]:
    path = SECRETS_DIR / f"{name}.json"
    if not path.exists():
        return "", ""
    data = json.loads(path.read_text(encoding="utf-8"))
    return (_dec(data["password"]) if data.get("password") else "", _dec(data["psk"]) if data.get("psk") else "")


def _delete_l2tp_secrets(name: str) -> None:
    path = SECRETS_DIR / f"{name}.json"
    if path.exists():
        path.unlink()


def _l2tp_bindings(store: dict, item: dict) -> dict:
    outbound = item.get("outbound") or f"l2tp_{item['name']}"
    clients = [c["email"] for c in store.get("clients", []) if c.get("outbound") == outbound]
    routes = [r.get("name") or "?" for r in store.get("routes", []) if (r.get("outbound") or r.get("outbound_tag")) == outbound]
    inbounds = [i["tag"] for i in store.get("inbounds") or [] if i.get("outbound") == outbound]
    bals = [b.get("tag") or k for k, b in (store.get("balancers") or {}).items()
            if outbound in (b.get("members") or []) or (not b.get("members") and b.get("enabled", True))]
    return {"outbound": outbound, "clients": clients, "routes": routes, "inbounds": inbounds,
            "balancers": bals, "blocked": bool(clients or routes or inbounds)}


def _allowed_outbounds(store: dict) -> set[str]:
    return set(xray.all_outbound_tags(store))


def _probe_tunnel_alive(item: dict) -> tuple[bool, str]:
    name = item["name"]
    iface = l2tp.ifname_for(name)
    if not l2tp.is_connected(name):
        return False, "iface down"
    peer = item.get("peer_ip") or ""
    if not peer:
        local, peer = l2tp.parse_ppp_endpoints(iface)
        if local:
            item["local_ip"] = local
        if peer:
            item["peer_ip"] = peer
    r = l2tp._run(["ping", "-I", iface, "-c", "2", "-W", "2", peer or "1.1.1.1"], timeout=8)
    if r.get("exit_code") == 0:
        return True, "ok"
    pub = l2tp.probe_public_ip(iface, timeout=5)
    if pub:
        item["public_ip"] = pub
        return True, "ok"
    return False, "ping/egress failed"


def connect_l2tp(item: dict) -> dict:
    password, psk = _load_l2tp_secrets(item["name"])
    result = l2tp.connect_tunnel(item, password, psk)
    if result.get("ok"):
        item["ifname"] = result.get("ifname") or l2tp.ifname_for(item["name"])
        for key in ("addr", "local_ip", "peer_ip", "public_ip", "vrf"):
            item[key] = result.get(key) or ""
    return result


def disconnect_l2tp(item: dict, store: dict | None = None) -> dict:
    return l2tp.disconnect_tunnel(item, store_l2tp=(store or {}).get("l2tp"))


def refresh_statuses(store: dict) -> dict:
    changed = False
    for item in store.get("l2tp", []):
        active = l2tp.is_connected(item["name"])
        new_status = "connected" if active else ("error" if item.get("status") == "error" else "disconnected")
        iface = l2tp.ifname_for(item["name"])
        if item.get("ifname") != iface:
            item["ifname"] = iface
            changed = True
        if active and item.get("status") != "connected":
            item["status"] = "connected"
            changed = True
        elif not active and item.get("status") == "connected":
            item["status"] = new_status
            changed = True
        if active:
            addr = l2tp.iface_addrs(iface)
            local, peer = l2tp.parse_ppp_endpoints(iface)
            for key, val in (("addr", addr), ("local_ip", local), ("peer_ip", peer)):
                if val and item.get(key) != val:
                    item[key] = val
                    changed = True
            if item.get("last_error"):
                item["last_error"] = ""
                changed = True
        else:
            for key in ("addr", "local_ip", "peer_ip", "public_ip", "vrf"):
                if item.get(key):
                    item[key] = ""
                    changed = True
    if changed:
        with STORE_LOCK:
            fresh = _load_store()
            by_name = {i["name"]: i for i in store.get("l2tp", [])}
            for i in fresh["l2tp"]:
                src = by_name.get(i["name"])
                if src:
                    for key in ("status", "ifname", "addr", "local_ip", "peer_ip", "public_ip", "vrf", "last_error"):
                        if key in src:
                            i[key] = src[key]
            _save_store(fresh)
    return store


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
    connected = sum(1 for x in store["l2tp"] if x.get("status") == "connected")
    return (
        f"<b>{app_title()}</b>\n"
        f"CPU {snap['cpu']}% · RAM {xray.format_traffic(mem['used'])}/{xray.format_traffic(mem['total'])}\n"
        f"Uptime {fmt_uptime(snap['uptime'])} · Load {snap['load'][0]}\n"
        f"Xray {xs['version']} {'🟢' if xs['active'] else '🔴'}\n"
        f"Клиенты: {len(store['clients'])} (онлайн {len(ONLINE)})\n"
        f"L2TP: {connected}/{len(store['l2tp'])} connected\n"
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
    limit = f"{c['limit_gb']:g} ГБ" if c.get("limit_gb") else "∞"
    return (f"<b>{c['email']}</b> — {xray.client_status(c)}\n"
            f"Трафик: {xray.format_traffic(used)} / {limit}\n"
            f"Срок: {fmt_dt(c.get('expire_at'))}\n"
            f"Онлайн: {'да' if c['email'] in ONLINE else 'нет'} · последний {ago(c.get('last_online'))}")


def _tg_client_by_tg(chat_id: str) -> str:
    store = _load_store()
    c = next((x for x in store["clients"] if str(x.get("tg_id") or "") == chat_id), None)
    return _client_summary(c) if c else ""


def _tg_online() -> str:
    return "\n".join(f"🟢 {email}: {', '.join(ips)}" for email, ips in ONLINE.items())


def _tg_clients() -> str:
    store = _load_store()
    return "\n".join(f"{'🟢' if c['email'] in ONLINE else '⚪'} {c['email']} — {xray.client_status(c)} — "
                     f"{xray.format_traffic(xray.client_used_bytes(c))}" for c in store["clients"]) or "Нет клиентов"


def _tg_tunnels() -> str:
    store = _load_store()
    return "\n".join(f"{'🟢' if x.get('status') == 'connected' else '🔴'} {xray.flag_emoji(xray.country_code(x))} "
                     f"{x['name']} {x.get('public_ip') or ''}" for x in store["l2tp"]) or "Нет туннелей"


def _tg_backup() -> tuple[str, bytes]:
    return f"l2xpanel-{datetime.now().strftime('%Y%m%d-%H%M')}.zip", ops.make_backup(DATA)


def _tg_restart_xray() -> str:
    r = ops.xray_control("restart")
    return "Xray перезапущен" if r["ok"] else f"Ошибка: {r['stderr']}"


BOT = tgbot.Bot(_bot_settings, {
    "report": _tg_report, "usage": _tg_usage, "online": _tg_online, "clients": _tg_clients,
    "tunnels": _tg_tunnels, "backup": _tg_backup, "restart_xray": _tg_restart_xray,
    "cpu": sysmon.cpu_percent, "client_by_tg": _tg_client_by_tg,
})


def _notify_events(events: list[dict]) -> None:
    s = _bot_settings()
    for e in events:
        typ = e.get("type")
        if typ in ("expired", "quota_exceeded", "tag_exceeded", "auto_reset") and s.get("notify_quota"):
            text = {
                "expired": f"⏰ {e['email']}: срок истёк",
                "quota_exceeded": f"📛 {e['email']}: исчерпан общий лимит трафика",
                "tag_exceeded": f"📛 {e['email']}: исчерпан лимит на {e.get('tag')}",
                "auto_reset": f"🔄 {e['email']}: трафик сброшен по расписанию",
            }[typ]
            BOT.send(text)
        elif typ == "ip_ban" and s.get("notify_iplimit"):
            BOT.send(f"🚫 {e['email']}: превышен лимит IP, заблокирован {e['ip']}")
        elif typ == "tunnel_down" and s.get("notify_tunnel"):
            BOT.send(f"🔴 L2TP {e['name']}: {e.get('reason')}")


def _expiry_warnings(store: dict) -> None:
    s = _bot_settings()
    days = _float(s.get("notify_expire_days"), 0)
    if not days:
        return
    today = datetime.now(timezone.utc).date().isoformat()
    for c in store["clients"]:
        left = xray.days_left(c)
        if left is not None and 0 < left <= days and _expiry_notified.get(c["email"]) != today:
            _expiry_notified[c["email"]] = today
            BOT.send(f"⌛ {c['email']}: срок истекает через {left:.1f} дн ({fmt_dt(c['expire_at'])})")
            if c.get("tg_id"):
                BOT.send(f"⌛ Ваша подписка истекает {fmt_dt(c['expire_at'])}", c["tg_id"])


def _watchdog_cycle() -> None:
    global ONLINE
    # 1) L2TP health (slow; no lock)
    snapshot = _load_store()
    bad: dict[str, str] = {}
    for item in snapshot.get("l2tp") or []:
        if item.get("status") == "connected":
            ok, reason = _probe_tunnel_alive(item)
            if not ok:
                bad[item["name"]] = reason
    need_apply = False
    with STORE_LOCK:
        store = _load_store()
        events: list[dict] = []
        for item in store["l2tp"]:
            if item["name"] in bad:
                item["status"] = "error"
                item["last_error"] = f"watchdog: {bad[item['name']]}"
                for key in ("addr", "local_ip", "peer_ip", "public_ip", "vrf"):
                    item[key] = ""
                try:
                    disconnect_l2tp(item, store)
                except Exception:
                    pass
                events.append({"type": "tunnel_down", "name": item["name"], "reason": bad[item["name"]]})
                need_apply = True
        before = [(t["name"], t.get("status")) for t in store["l2tp"]]
        for item in store["l2tp"]:
            if item.get("status") == "connected" and not l2tp.is_connected(item["name"]):
                item["status"] = "disconnected"
        if before != [(t["name"], t.get("status")) for t in store["l2tp"]]:
            need_apply = True
        # 2) traffic + quotas
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
        _save_store(store)
        if need_apply:
            _apply_xray(store)
    _expiry_warnings(store)
    _notify_events(events)


def _watchdog_loop() -> None:
    while not _stop.wait(WATCHDOG_INTERVAL):
        try:
            _watchdog_cycle()
        except Exception:
            pass


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


@app.on_event("startup")
def _startup():
    _admin()
    _ensure_base_path()
    _refresh_settings_cache()
    for target in (_sync_xray_config, _watchdog_loop, _history_loop):
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
    return next((c for c in store["clients"] if c.get("sub_token") and secrets.compare_digest(c["sub_token"], token)), None)


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
        return templates.TemplateResponse("sub_page.html", {
            "request": request, "client": client, "links": list(zip(eps, links)), "sub_link": sub_url(client),
            "status": xray.client_status(client), "used": xray.client_used_bytes(client), "settings": s,
            "app_name": app_title(), "qr_svg": qr_svg, "format_traffic": xray.format_traffic, "fmt_dt": fmt_dt,
            "days_left": xray.days_left(client), "theme": "dark", "bp": "", "hwid": hwid.status(client),
        }, headers={"cache-control": "no-store"})
    if not xray.client_access_ok(client):
        return PlainTextResponse(xray.client_status(client), status_code=403, headers=headers)
    # HWID gate applies only to machine-readable subscription bodies
    req_headers = {k.lower(): v for k, v in request.headers.items()}
    gate = hwid.gate(client, req_headers, register=True, required=hwid_required)
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
    if gate["reason"] == "ok":
        with STORE_LOCK:
            st = _load_store()
            c = _find_by_token(st, token)
            if c:
                c["hwids"] = client.get("hwids") or []
                _save_store(st)
    filename = re.sub(r"[^A-Za-z0-9_.-]", "_", client["email"])
    extras = {"fragment": s.get("json_fragment"), "noise": s.get("json_noise"), "mux": s.get("json_mux")}
    if fmt == "json":
        body = json.dumps([P.xray_client_config(e, extras) for e in eps if e["protocol"] != "wireguard"],
                          ensure_ascii=False, indent=2)
        return Response(body, media_type="application/json", headers=headers)
    if fmt == "clash":
        body = yaml.safe_dump(P.clash_config(eps), allow_unicode=True, sort_keys=False)
        headers["content-disposition"] = f'attachment; filename="{filename}.yaml"'
        return Response(body, media_type="text/yaml; charset=utf-8", headers=headers)
    if fmt in ("singbox", "sing-box"):
        body = json.dumps(P.singbox_config(eps), ensure_ascii=False, indent=2)
        return Response(body, media_type="application/json", headers=headers)
    body = "\n".join(P.endpoint_to_link(e) for e in eps)
    if fmt != "plain":
        body = base64.b64encode(body.encode()).decode()
    headers["content-disposition"] = f'attachment; filename="{filename}.txt"'
    return PlainTextResponse(body, headers=headers)


@app.get("/sub/{token}")
def sub_main(token: str, request: Request):
    return _sub_response(request, token)


@sub_app.get("/{path}/{token}")
def sub_dedicated(path: str, token: str, request: Request):
    expected = ((SETTINGS_CACHE.get("sub") or {}).get("path") or "sub").strip("/")
    if path != expected:
        return PlainTextResponse("not found", status_code=404)
    return _sub_response(request, token)


@app.get("/health")
def health():
    return {"status": "ok", "app": app_title(), "time": datetime.now(timezone.utc).isoformat()}


# ================================================================ auth pages

_login_fail: dict[str, list[float]] = {}


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return page(request, "login.html", error=None, totp_enabled=SETTINGS_CACHE.get("security", {}).get("totp_enabled"))


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...), code: str = Form("")):
    ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip() or (request.client.host if request.client else "?")
    fails = [t_ for t_ in _login_fail.get(ip, []) if time.time() - t_ < 900]
    sec = _settings()["security"]
    if len(fails) >= 8:
        return page(request, "login.html", error="Слишком много попыток, подождите 15 минут",
                    totp_enabled=sec.get("totp_enabled"), status_code=429)
    ok = _check_credentials(username, password)
    if ok and sec.get("totp_enabled") and not totp.verify(sec.get("totp_secret") or "", code):
        ok = False
    if not ok:
        fails.append(time.time())
        _login_fail[ip] = fails
        if _bot_settings().get("notify_login"):
            BOT.send(f"⚠️ Неудачный вход в панель: {username} с {ip}")
        return page(request, "login.html", error="Неверный логин, пароль или код 2FA",
                    totp_enabled=sec.get("totp_enabled"), status_code=401)
    _login_fail.pop(ip, None)
    hours = _float(_settings()["panel"].get("session_hours"), 12) or 12
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
        "l2tp": len(store["l2tp"]),
        "l2tp_up": sum(1 for x in store["l2tp"] if x.get("status") == "connected"),
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
    for t_ in store.get("l2tp") or []:
        kinds[t_.get("outbound") or f"l2tp_{t_['name']}"] = ("l2tp", t_.get("status") or "")
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
    for path in ("/inbounds", "/clients", "/balancers", "/routing", "/outbounds", "/l2tp", "/xray", "/settings"):
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
    ib["listen"] = P.INBOUND_LISTEN
    ib["port"] = _int(form.get("port"), 0)
    if reason := xray.port_forbidden_reason(ib["port"]):
        return reason
    share = str(form.get("share_host") or "").strip().lower()
    share = re.sub(r"^[a-z]+://", "", share).split("/", 1)[0].split(":", 1)[0]
    ib["share_host"] = share
    ib["total_gb"] = _float(form.get("total_gb"))
    ib["expire_at"] = local_to_iso(str(form.get("expire_at") or ""))
    ib["outbound"] = str(form.get("outbound") or "direct")
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
        s["masquerade_dir"] = str(form.get("hy_mask_dir") or "")
    st = ib["stream"]
    st["network"] = str(form.get("network") or "raw")
    st["security"] = str(form.get("security") or "none")
    if proto == "hysteria":
        st["network"], st["security"] = "hysteria", "tls"
    elif proto not in ("vless", "vmess", "trojan") or (st["security"] == "reality" and proto == "vmess"):
        st["security"] = "none" if proto not in ("vmess",) else "tls"
    if st["network"] not in P.NETWORKS:
        st["network"] = "raw"
    # ws/grpc/httpupgrade/xhttp share the public HTTPS domain via nginx Path — TLS ends at nginx
    if st["network"] in P.FRONT_HTTP_NETWORKS:
        st["security"] = "none"
    st["accept_proxy_protocol"] = form.get("accept_proxy") == "1"
    st["raw"].update({
        "header": str(form.get("raw_header") or "none"),
        "http_host": str(form.get("raw_host") or ""),
        "http_path": str(form.get("raw_path") or "/"),
        "accept_proxy_protocol": form.get("accept_proxy") == "1",
    })
    st["ws"].update({
        "path": str(form.get("ws_path") or "/"), "host": str(form.get("ws_host") or ""),
        "accept_proxy_protocol": form.get("accept_proxy") == "1",
    })
    st["grpc"].update({
        "service_name": str(form.get("grpc_service") or "grpc"),
        "multi_mode": form.get("grpc_multi") == "1",
        "authority": str(form.get("grpc_authority") or ""),
    })
    st["httpupgrade"].update({
        "path": str(form.get("hu_path") or "/"), "host": str(form.get("hu_host") or ""),
        "accept_proxy_protocol": form.get("accept_proxy") == "1",
    })
    st["xhttp"].update({
        "path": str(form.get("xh_path") or "/"), "host": str(form.get("xh_host") or ""),
        "mode": str(form.get("xh_mode") or "auto"),
        "extra": str(form.get("xh_extra") or "").strip(),
    })
    st["kcp"].update({
        "mtu": _int(form.get("kcp_mtu"), 1350), "tti": _int(form.get("kcp_tti"), 20),
        "uplink": _int(form.get("kcp_up"), 5), "downlink": _int(form.get("kcp_down"), 20),
        "congestion": form.get("kcp_congestion") == "1",
        "header": str(form.get("kcp_header") or "none"),
        "seed": str(form.get("kcp_seed") or ""),
    })
    st["tls"].update({
        "server_name": str(form.get("tls_sni") or ""), "cert_file": str(form.get("tls_cert") or ""),
        "key_file": str(form.get("tls_key") or ""), "alpn": _split_lines(str(form.get("tls_alpn") or "h2,http/1.1")),
        "fingerprint": str(form.get("tls_fp") or "chrome"), "min_version": str(form.get("tls_min") or "1.2"),
        "allow_insecure": form.get("tls_insecure") == "1",
        "reject_unknown_sni": form.get("tls_reject_sni") == "1",
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
        "fingerprint": str(form.get("r_fp") or "chrome"),
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
        "mark": _int(form.get("so_mark"), 0),
        "tproxy": str(form.get("so_tproxy") or ""),
        "domain_strategy": str(form.get("so_ds") or "AsIs"),
        "dialer_proxy": str(form.get("so_dialer") or "").strip(),
        "penetrate": form.get("so_penetrate") == "1",
        "tcp_mptcp": form.get("so_mptcp") == "1",
        "tcp_no_delay": form.get("so_nodelay") == "1",
    })
    ib["sniffing"] = {
        "enabled": form.get("sniff") == "1",
        "dest": [d for d in ("http", "tls", "quic", "fakedns") if form.get(f"sniff_{d}") == "1"] or ["http", "tls", "quic"],
        "route_only": form.get("sniff_route_only") == "1",
        "metadata_only": form.get("sniff_meta") == "1",
    }
    fbs = []
    for line in str(form.get("fallbacks") or "").splitlines():
        parts = [p.strip() for p in line.split("|")]
        if not any(parts):
            continue
        parts += [""] * (5 - len(parts))
        fbs.append({"name": parts[0], "alpn": parts[1], "path": parts[2], "dest": parts[3], "xver": _int(parts[4])})
    ib["fallbacks"] = fbs
    xray.ensure_inbound_keys(ib)
    mode = P.front_mode(ib)
    share = ib["share_host"] or front.public_domain({"settings": SETTINGS_CACHE}) or public_host()
    if mode == "http" and not front.is_domain(share):
        return f"Для {st['network']} задайте публичный домен в Настройках или URL share"
    if mode == "http" and not front.PATH_RE.match(P.front_http_path(ib)):
        return "Путь/serviceName: только латиница, цифры и /_.~-"
    return None


@app.get("/inbounds", response_class=HTMLResponse)
def inbounds_page(request: Request):
    if redir := _require(request):
        return redir
    store = _load_store()
    rows = []
    for ib in store["inbounds"]:
        n_clients = sum(1 for c in store["clients"] if ib in xray.client_inbounds(store, c))
        rows.append({**ib, "n_clients": n_clients, "used": xray.inbound_used_bytes(ib), "ok": xray.inbound_access_ok(ib)})
    return page(request, "inbounds.html", active="inbounds", items=rows, store=store)


@app.get("/inbounds/new", response_class=HTMLResponse)
def inbound_new(request: Request):
    if redir := _require(request):
        return redir
    store = _load_store()
    proto = request.query_params.get("protocol") or "vless"
    port = xray.free_inbound_port(store)
    ib = P.default_inbound(proto, port, f"{proto}-{port}")
    xray.ensure_inbound_keys(ib)
    return page(request, "inbound_edit.html", active="inbounds", ib=ib, is_new=True, store=store,
                outbounds=xray.all_outbound_tags(store), certs=ops.list_certs())


@app.get("/inbounds/{ib_id}/edit", response_class=HTMLResponse)
def inbound_edit(ib_id: int, request: Request):
    if redir := _require(request):
        return redir
    store = _load_store()
    ib = xray.inbound_by_id(store, ib_id)
    if not ib:
        flash(request, "Inbound не найден", "error")
        return go("/inbounds")
    return page(request, "inbound_edit.html", active="inbounds", ib=ib, is_new=False, store=store,
                outbounds=xray.all_outbound_tags(store), certs=ops.list_certs())


@app.post("/inbounds/save")
async def inbound_save(request: Request):
    if redir := _require(request):
        return redir
    form = await request.form()
    ib_id = _int(form.get("id"))
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
        if err:
            flash(request, err, "error")
            return go(f"/inbounds/{ib_id}/edit" if ib_id else "/inbounds/new")
        if not ib_id:
            store["inbounds"].append(ib)
        elif old_tag != ib["tag"]:
            for c in store["clients"]:
                c["inbounds"] = [ib["tag"] if x == old_tag else x for x in c.get("inbounds") or []]
    result = _apply_xray(_load_store())
    flash(request, *_ok_msg(f"Inbound {ib['tag']} сохранён", result))
    return go("/inbounds")


@app.post("/inbounds/{ib_id}/{action}")
def inbound_action(ib_id: int, action: str, request: Request):
    if redir := _require(request):
        return redir
    with mutate() as store:
        ib = xray.inbound_by_id(store, ib_id)
        if not ib:
            flash(request, "Inbound не найден", "error")
            return go("/inbounds")
        if action == "toggle":
            ib["enabled"] = not ib.get("enabled", True)
        elif action == "reset":
            ib["traffic"].update({"up": 0, "down": 0})
        elif action == "delete":
            if len(store["inbounds"]) == 1:
                flash(request, "Нельзя удалить последний inbound", "error")
                return go("/inbounds")
            store["inbounds"] = [i for i in store["inbounds"] if i is not ib]
            for c in store["clients"]:
                c["inbounds"] = [x for x in c.get("inbounds") or [] if x != ib["tag"]]
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
        else:
            flash(request, "Неизвестное действие", "error")
            return go("/inbounds")
    result = _apply_xray(_load_store())
    flash(request, *_ok_msg(f"Inbound {ib['tag']}: {action}", result))
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
    return {
        **c, "used": used, "limit_bytes": limit, "pct": min(100, int(100 * used / limit)) if limit else 0,
        "status": xray.client_status(c), "online_ips": ONLINE.get(c["email"], []), "sub_url": sub_url(c),
        "inbound_tags": [i["tag"] for i in xray.client_inbounds(store, c)], "days_left": xray.days_left(c),
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
                total=len(store["clients"]))


def _client_form(form, store: dict, client: dict) -> str | None:
    email = str(form.get("email") or "").strip()
    if not xray.EMAIL_RE.match(email):
        return "Некорректный email (без пробелов и ~)"
    if email != client.get("email") and any(c["email"] == email for c in store["clients"]):
        return "Такой email уже есть"
    outbound = str(form.get("outbound") or "direct")
    if outbound not in _allowed_outbounds(store):
        return f"Неизвестный outbound {outbound}"
    old_email = client.get("email")
    client["email"] = email
    client["outbound"] = outbound
    client["enabled"] = form.get("enabled", "1") == "1"
    client["comment"] = str(form.get("comment") or "").strip()
    client["tg_id"] = str(form.get("tg_id") or "").strip()
    client["limit_gb"] = _float(form.get("limit_gb"))
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
    client["sub_enabled"] = form.get("sub_enabled", "1") == "1"
    known_ib = {i["tag"] for i in xray.client_capable_inbounds(store)}
    sel_ib = [str(x) for x in form.getlist("inbounds") if str(x) in known_ib]
    client["inbounds"] = [] if form.get("ib_mode", "all") == "all" or set(sel_ib) == known_ib else sel_ib
    known = {t_["tag"] for t_ in xray.selectable_outbound_tags(store)}
    selected = [str(x) for x in form.getlist("allowed_tags") if str(x) in known]
    client["allowed_tags"] = [] if form.get("select_mode", "all") == "all" or not selected else selected
    limits = {}
    for tag in known:
        gb = _float(form.get(f"limit_{tag}"))
        if gb > 0:
            limits[tag] = gb
    client["outbound_limits"] = limits
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
    return page(request, "client_edit.html", active="clients", c=c, row=None, is_new=True, store=store,
                tags=xray.selectable_outbound_tags(store), inbounds=xray.client_capable_inbounds(store),
                hwids=[], bans=[], links=[], wg_confs=[])


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
        tags.append({**tg, "used": xray.client_tag_used_bytes(c, tg["tag"]),
                     "limit": (c.get("outbound_limits") or {}).get(tg["tag"], ""),
                     "exceeded": xray.client_tag_exceeded(c, tg["tag"])})
    bans = [b for b in store.get("ip_bans") or [] if b.get("email") == email]
    eps = xray.client_endpoints(store, c, store["settings"]["sub"].get("domain") or None)
    links = [(e, P.endpoint_to_link(e)) for e in eps]
    wg_confs = [(e, P.wireguard_conf(e)) for e in eps if e["protocol"] == "wireguard"]
    return page(request, "client_edit.html", active="clients", c=c, row=_client_row(store, c), is_new=False,
                store=store, tags=tags, inbounds=xray.client_capable_inbounds(store), bans=bans, links=links,
                wg_confs=wg_confs, hwids=hwid.public_list(c))


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
    result = _apply_xray(_load_store())
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
                c = xray.ensure_client({"email": email, "sub_token": secrets.token_urlsafe(18),
                                        "limit_gb": _float(form.get("limit_gb")),
                                        "outbound": str(form.get("outbound") or "direct")})
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
    result = _apply_xray(_load_store())
    flash(request, *_ok_msg(msg, result))
    return go("/clients")


@app.post("/clients/{email}/{action}")
def client_action(email: str, action: str, request: Request):
    if redir := _require(request):
        return redir
    with mutate() as store:
        c = next((x for x in store["clients"] if x["email"] == email), None)
        if not c:
            flash(request, "Клиент не найден", "error")
            return go("/clients")
        if action == "toggle":
            c["enabled"] = not c.get("enabled", True)
        elif action == "reset":
            xray.reset_client_traffic(c)
        elif action == "regen_sub":
            c["sub_token"] = secrets.token_urlsafe(18)
        elif action == "regen_uuid":
            c["uuid"] = str(uuid.uuid4())
            c["password"] = secrets.token_hex(12)
        elif action == "delete":
            store["clients"].remove(c)
            for r in store.get("routes") or []:
                if isinstance(r.get("user"), list):
                    r["user"] = [u for u in r["user"] if u != email]
            webhooks.fire(store["settings"], "client.deleted", {"email": email})
        elif action == "clear_ips":
            c["ips"] = {}
        elif action == "clear_hwids":
            hwid.clear(c)
        else:
            flash(request, "Неизвестное действие", "error")
            return go("/clients")
    result = _apply_xray(_load_store()) if action not in ("regen_sub", "clear_ips", "clear_hwids") else {"ok": True}
    flash(request, *_ok_msg(f"{email}: {action}", result))
    if action == "delete":
        return go("/clients")
    nxt = request.query_params.get("next")
    return go(nxt or f"/clients/{email}/edit")


@app.post("/ipban/{ip}/unban")
def ip_unban(ip: str, request: Request):
    if redir := _require(request):
        return redir
    with mutate() as store:
        xray.unban_ip(store, ip)
    flash(request, f"{ip} разблокирован", "info")
    return go(request.query_params.get("next") or "/clients")


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


# ================================================================ L2TP

@app.get("/l2tp", response_class=HTMLResponse)
def l2tp_page(request: Request):
    if redir := _require(request):
        return redir
    store = refresh_statuses(_load_store())
    items = [{**item, "bindings": _l2tp_bindings(store, item),
              "traffic": (store.get("outbound_traffic") or {}).get(item.get("outbound") or f"l2tp_{item['name']}", {})}
             for item in store["l2tp"]]
    return page(request, "l2tp.html", active="l2tp", items=items)


@app.post("/l2tp")
def l2tp_add(request: Request, name: str = Form(...), server_host: str = Form(...), username: str = Form(...),
             password: str = Form(""), psk: str = Form(""), country: str = Form("")):
    if redir := _require(request):
        return redir
    name, country = name.strip(), country.strip().upper()
    if country and not re.fullmatch(r"[A-Z]{2}", country):
        flash(request, "Страна: двухбуквенный ISO-код", "error")
        return go("/l2tp")
    if not SLUG_RE.match(name):
        flash(request, "Имя: латиница/цифры/_/-, до 32 символов", "error")
        return go("/l2tp")
    if not password:
        flash(request, "Нужен пароль L2TP", "error")
        return go("/l2tp")
    with mutate() as store:
        if any(x["name"] == name for x in store["l2tp"]):
            flash(request, f"L2TP '{name}' уже существует", "error")
            return go("/l2tp")
        item = {"name": name, "server_host": server_host.strip(), "username": username.strip(), "password_set": True,
                "psk_set": bool(psk), "status": "disconnected", "outbound": f"l2tp_{name}",
                "ifname": l2tp.ifname_for(name), "addr": "", "last_error": ""}
        if country:
            item["country"] = country
        _save_l2tp_secrets(name, password, psk)
        store["l2tp"].append(item)
        prepared = l2tp.write_tunnel_configs(item, password, psk)
        if not prepared.get("ok"):
            item["last_error"] = prepared.get("error", "tunnel config failed")
    flash(request, f"L2TP '{name}' добавлен. Нажмите Connect." if not item["last_error"] else item["last_error"],
          "info" if not item["last_error"] else "error")
    return go("/l2tp")


@app.post("/l2tp/{name}/country")
def l2tp_set_country(name: str, request: Request, country: str = Form("")):
    if redir := _require(request):
        return redir
    country = country.strip().upper()
    if country and not re.fullmatch(r"[A-Z]{2}", country):
        flash(request, "Страна: двухбуквенный ISO-код", "error")
        return go("/l2tp")
    with mutate() as store:
        item = next((x for x in store["l2tp"] if x["name"] == name), None)
        if item:
            if country:
                item["country"] = country
            else:
                item.pop("country", None)
    return go("/l2tp")


@app.post("/l2tp/{name}/connect")
def l2tp_connect(name: str, request: Request):
    if redir := _require(request):
        return redir
    store = _load_store()
    item = next((x for x in store["l2tp"] if x["name"] == name), None)
    if not item:
        flash(request, "Не найдено", "error")
        return go("/l2tp")
    result = connect_l2tp(item)
    with mutate() as fresh:
        it = next(x for x in fresh["l2tp"] if x["name"] == name)
        if result["ok"]:
            it.update({k: item.get(k, "") for k in ("ifname", "addr", "local_ip", "peer_ip", "public_ip", "vrf")})
            it["status"], it["last_error"] = "connected", ""
        else:
            it["status"], it["last_error"] = "disconnected", result.get("error", "connect failed")
    if result["ok"]:
        xr = _apply_xray(_load_store())
        flash(request, *_ok_msg(f"{name}: connected, egress {item.get('public_ip') or '?'}", xr))
    else:
        flash(request, f"{name}: {result.get('error')}", "error")
    return go("/l2tp")


@app.post("/l2tp/{name}/disconnect")
def l2tp_disconnect(name: str, request: Request):
    if redir := _require(request):
        return redir
    with mutate() as store:
        item = next((x for x in store["l2tp"] if x["name"] == name), None)
        if not item:
            flash(request, "Не найдено", "error")
            return go("/l2tp")
        result = disconnect_l2tp(item, store)
        item["status"] = "disconnected"
        for key in ("addr", "local_ip", "peer_ip", "public_ip", "vrf"):
            item[key] = ""
        item["last_error"] = "" if result["ok"] else result.get("error", "")
    xr = _apply_xray(_load_store())
    flash(request, *_ok_msg(f"{name}: disconnected", xr))
    return go("/l2tp")


@app.post("/l2tp/{name}/delete")
def l2tp_delete(name: str, request: Request):
    if redir := _require(request):
        return redir
    with mutate() as store:
        item = next((x for x in store["l2tp"] if x["name"] == name), None)
        if not item:
            flash(request, "Не найдено", "error")
            return go("/l2tp")
        b = _l2tp_bindings(store, item)
        if b["blocked"]:
            flash(request, f"Нельзя удалить {name}: привязан к клиентам {b['clients']}, правилам {b['routes']}, inbounds {b['inbounds']}", "error")
            return go("/l2tp")
        l2tp.delete_tunnel(item, store_l2tp=store["l2tp"])
        _delete_l2tp_secrets(name)
        store["l2tp"] = [x for x in store["l2tp"] if x["name"] != name]
    xr = _apply_xray(_load_store())
    flash(request, *_ok_msg(f"L2TP {name} удалён", xr))
    return go("/l2tp")


# ================================================================ outbounds

@app.get("/outbounds", response_class=HTMLResponse)
def outbounds_page(request: Request):
    if redir := _require(request):
        return redir
    store = _load_store()
    ot = store.get("outbound_traffic") or {}
    rows = [{"tag": "direct", "kind": "system", "label": "🏠 Direct", "enabled": True, "status": "active"}]
    for t_ in store["l2tp"]:
        tag = t_.get("outbound") or f"l2tp_{t_['name']}"
        rows.append({"tag": tag, "kind": "l2tp", "label": xray.outbound_label(store, tag), "enabled": True,
                     "status": t_.get("status"), "info": t_.get("public_ip") or t_.get("server_host")})
    for o in store["outbounds_custom"]:
        rows.append({"tag": o["tag"], "kind": o.get("kind") or "custom", "label": xray.outbound_label(store, o["tag"]),
                     "enabled": o.get("enabled", True), "status": "active" if o.get("enabled", True) else "disabled",
                     "info": o.get("info") or (o.get("config") or {}).get("protocol"), "in_sub": o.get("in_sub", True),
                     "custom": True, "last_test": o.get("last_test")})
    for r in rows:
        tr = ot.get(r["tag"]) or {}
        r["up"], r["down"] = int(tr.get("up") or 0), int(tr.get("down") or 0)
    custom = {o["tag"]: {"config": o.get("config") or {}, "remark": o.get("remark") or "", "country": o.get("country") or ""}
              for o in store["outbounds_custom"]}
    return page(request, "outbounds.html", active="outbounds", items=rows, nord_countries=[], custom=custom,
                dialer_tags=[r["tag"] for r in rows], ss_methods=P.SS_METHODS, fingerprints=P.FINGERPRINTS)


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
            res = ops.warp_register()
            if not res.get("ok"):
                raise ValueError(res.get("error"))
            config, info, remark = res["config"], "Cloudflare WARP", remark or "Cloudflare WARP"
            tag = tag or "warp"
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
        else:
            raise ValueError("неизвестный режим")
    except Exception as exc:  # noqa: BLE001
        flash(request, f"Outbound: {exc}", "error")
        return go("/outbounds")
    with mutate() as store:
        previous = json.loads(json.dumps(store["outbounds_custom"]))
        if edit_tag:
            o = next((x for x in store["outbounds_custom"] if x["tag"] == edit_tag), None)
            if o:
                config.pop("tag", None)
                o.update({"config": config, "remark": remark or edit_tag, "country": country.upper(), "info": info})
                o.pop("last_test", None)
                err = None
            else:
                err = "Outbound не найден"
            tag = edit_tag
        else:
            err = _add_custom_outbound(store, tag, remark, config, "custom" if mode == "form" else mode, info, country)
    if err:
        flash(request, err, "error")
        return go("/outbounds")
    xr = _apply_xray(_load_store())
    if not xr.get("ok"):
        with mutate() as store:
            store["outbounds_custom"] = previous
        flash(request, f"Outbound {tag} не сохранён — Xray отклонил конфиг: {xr.get('error')}", "error")
        return go("/outbounds")
    flash(request, f"Outbound {tag} {'обновлён' if edit_tag else 'добавлен'}", "info")
    return go("/outbounds")


@app.get("/outbounds/nord/countries")
def nord_countries(request: Request):
    if not _user(request):
        return JSONResponse([], status_code=401)
    return ops.nord_countries()


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
    xr = _apply_xray(_load_store()) if action != "reset" else {"ok": True}
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
                l2tp=store["l2tp"], custom=store["outbounds_custom"], watchdog_sec=WATCHDOG_INTERVAL, store=store)


@app.post("/balancers/{key}")
async def balancers_save(key: str, request: Request):
    if redir := _require(request):
        return redir
    if key not in ("least_ping", "least_load"):
        return go("/balancers")
    form = await request.form()
    with mutate() as store:
        b = xray.ensure_balancers(store)[key]
        b["enabled"] = form.get("enabled") == "1"
        b["probe_url"] = str(form.get("probe_url") or b["probe_url"]).strip()
        b["probe_interval"] = str(form.get("probe_interval") or b["probe_interval"]).strip()
        b["fallback"] = str(form.get("fallback") or "direct")
        members = [str(x) for x in form.getlist("members")]
        all_l2tp = {t_.get("outbound") or f"l2tp_{t_['name']}" for t_ in store["l2tp"]}
        b["members"] = [] if members and set(members) == all_l2tp else members
        if key == "least_load":
            b["expected"] = max(1, _int(form.get("expected"), 1))
            b["max_rtt"] = str(form.get("max_rtt") or "1s")
            b["tolerance"] = _float(form.get("tolerance"), 0.15)
    xr = _apply_xray(_load_store())
    flash(request, *_ok_msg(f"{key} сохранён", xr))
    return go("/balancers")


# ================================================================ routing

@app.get("/routing", response_class=HTMLResponse)
def routing_page(request: Request):
    if redir := _require(request):
        return redir
    store = _load_store()
    return page(request, "routing.html", active="routing", routes=store["routes"], store=store,
                outbounds=xray.all_outbound_tags(store), presets=xray.ROUTE_PRESETS,
                inbound_tags=[i["tag"] for i in store["inbounds"]])


@app.post("/routing")
async def routing_add(request: Request):
    if redir := _require(request):
        return redir
    form = await request.form()
    name = str(form.get("name") or "").strip()
    with mutate() as store:
        if not name or any(r.get("name") == name for r in store["routes"]):
            flash(request, "Нужно уникальное имя правила", "error")
            return go("/routing")
        rule = {
            "name": name, "enabled": True, "outbound": str(form.get("outbound") or "direct"),
            "domain": _split_lines(str(form.get("domain") or "")), "ip": _split_lines(str(form.get("ip") or "")),
            "user": _split_lines(str(form.get("user") or "")), "source": _split_lines(str(form.get("source") or "")),
            "protocol": [p for p in ("http", "tls", "quic", "bittorrent") if form.get(f"proto_{p}") == "1"],
            "inbound_tags": [str(x) for x in form.getlist("inbound_tags")],
            "network": str(form.get("network") or ""), "port": str(form.get("port") or "").strip(),
        }
        if not any(rule[k] for k in ("domain", "ip", "user", "source", "protocol", "inbound_tags", "network", "port")):
            flash(request, "Нужно хотя бы одно условие", "error")
            return go("/routing")
        store["routes"].append(rule)
    xr = _apply_xray(_load_store())
    flash(request, *_ok_msg(f"Правило {name} добавлено", xr))
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
    xr = _apply_xray(_load_store())
    flash(request, *_ok_msg(f"Добавлено {preset['name']}", xr))
    return go("/routing")


@app.post("/routing/{name}/{action}")
def routing_action(name: str, action: str, request: Request):
    if redir := _require(request):
        return redir
    with mutate() as store:
        routes = store["routes"]
        idx = next((i for i, r in enumerate(routes) if r.get("name") == name), None)
        if idx is None:
            return go("/routing")
        if action == "delete":
            routes.pop(idx)
        elif action == "toggle":
            routes[idx]["enabled"] = not routes[idx].get("enabled", True)
        elif action == "up" and idx > 0:
            routes[idx - 1], routes[idx] = routes[idx], routes[idx - 1]
        elif action == "down" and idx < len(routes) - 1:
            routes[idx + 1], routes[idx] = routes[idx], routes[idx + 1]
    xr = _apply_xray(_load_store())
    flash(request, *_ok_msg(f"{name}: {action}", xr))
    return go("/routing")


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
    if tab == "template":
        ctx["final"] = json.dumps(xray.build_config(store), ensure_ascii=False, indent=2)
    if tab == "geo":
        ctx["geo"] = ops.geo_files()
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
                        items.append({"name": n, "url": u})
                store["settings"]["geo_custom"] = items
        except ValueError as exc:
            flash(request, f"Ошибка: {exc}", "error")
            return go(f"/xray?tab={section}")
    if section != "geo_custom":
        # apply_config always runs xray -test + live restart check; rejects/rolls back on failure
        xr = _apply_xray(_load_store())
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


@app.post("/xray/geo/update")
def xray_geo_update(request: Request):
    if redir := _require(request):
        return redir
    ops.start_job("geo-update", ops.update_geo, _settings().get("geo_custom") or [])
    flash(request, "Обновление geo-файлов запущено", "info")
    return go("/xray?tab=geo")


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
        text = ops.journal({"xray": "xray", "panel": "l2xpanel", "l2tp": "xl2tpd"}.get(src, "xray"), lines, grep)
    return page(request, "logs.html", active="logs", src=src, text=text, n=lines, q=grep)


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
        uri = totp.otpauth_uri(secret, _admin()["username"], app_title())
        ctx.update(totp_secret=secret, totp_qr=qr_svg(uri, 5))
    if tab in ("certs", "panel", "sub"):
        ctx["certs"] = ops.list_certs()
    if tab == "system":
        ctx["bbr"] = ops.bbr_status()
    new_token = request.session.pop("new_api_token", None)
    return page(request, "settings.html", active="settings", tab=tab, s=s, admin=_admin(), new_token=new_token,
                jobs=sorted(ops.JOBS.items(), key=lambda kv: -kv[1]["started"])[:5],
                sub_running=SUB_SERVER.running, sub_error=SUB_SERVER.error, panel_tls_running=PANEL_TLS.running,
                panel_tls_error=PANEL_TLS.error, **ctx)


@app.post("/settings/save")
async def settings_save(request: Request):
    if redir := _require(request):
        return redir
    form = await request.form()
    section = str(form.get("section") or "")
    with mutate() as store:
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
            # Dedicated panel TLS port is unused — everything is on nginx :443
            p["extra_listen"] = {"enabled": False, "port": 2053, "cert_file": "", "key_file": ""}
            s["sub"]["domain"] = host if front.is_domain(host) else s["sub"].get("domain", "")
            s["sub"]["server_enabled"] = False
        elif section == "sub":
            sub = s["sub"]
            sub.update({
                "enabled": form.get("enabled") == "1", "server_enabled": False,
                "listen": "127.0.0.1", "port": 2096,
                "path": re.sub(r"[^A-Za-z0-9_-]", "", str(form.get("path") or "sub")) or "sub",
                "domain": front.public_domain({"settings": s}) or front.normalize_host(str(form.get("domain") or "")),
                "cert_file": "", "key_file": "", "update_hours": _int(form.get("update_hours"), 1),
                "title": str(form.get("title") or ""), "support_url": str(form.get("support_url") or ""),
                "announce": str(form.get("announce") or ""), "show_page": form.get("show_page") == "1",
                "json_fragment": str(form.get("json_fragment") or "").strip(),
                "json_noise": str(form.get("json_noise") or "").strip(),
                "json_mux": str(form.get("json_mux") or "").strip(),
                "hwid_required": form.get("hwid_required") == "1", "migrate_url": form.get("migrate_url") == "1",
                "happ_provider_id": str(form.get("happ_provider_id") or "").strip(),
            })
        elif section == "webhooks":
            wh = webhooks.ensure(s)
            wh["enabled"] = form.get("enabled") == "1"
            wh["secret"] = str(form.get("secret") or "").strip()
            wh["urls"] = [u for u in _split_lines(str(form.get("urls") or "")) if u.startswith("http")]
            wh["events"] = [e for e in webhooks.EVENTS if form.get(f"ev_{e}") == "1"] or list(webhooks.EVENTS)
        elif section == "nodes":
            ns = s.setdefault("nodes", {})
            ns["agent_enabled"] = form.get("agent_enabled") == "1"
            if form.get("regen_token") == "1" or not ns.get("agent_token"):
                ns["agent_token"] = secrets.token_urlsafe(32)
        elif section == "tg":
            tg = s["tg"]
            tg.update({
                "enabled": form.get("enabled") == "1", "token": str(form.get("token") or "").strip(),
                "admin_ids": [x for x in _split_lines(str(form.get("admin_ids") or "").replace(" ", "\n"))],
                "notify_login": form.get("notify_login") == "1", "notify_quota": form.get("notify_quota") == "1",
                "notify_iplimit": form.get("notify_iplimit") == "1", "notify_tunnel": form.get("notify_tunnel") == "1",
                "notify_expire_days": _float(form.get("notify_expire_days"), 3),
                "cpu_threshold": _float(form.get("cpu_threshold"), 85), "report_hours": _float(form.get("report_hours"), 24),
                "backup_hours": _float(form.get("backup_hours"), 24),
            })
        elif section == "iplimit":
            s["iplimit"]["ban_minutes"] = _int(form.get("ban_minutes"), 30)
    _refresh_settings_cache()
    _sync_servers()
    if section == "tg":
        BOT.start()
    if section == "panel":
        flash(request, *_ok_msg("Настройки сохранены, HTTPS :443 обновлён", _apply_xray(_load_store())))
    else:
        flash(request, "Настройки сохранены", "info")
    return go(f"/settings?tab={section}")


@app.post("/settings/account")
def settings_account(request: Request, username: str = Form(...), current: str = Form(...), new_password: str = Form("")):
    if redir := _require(request):
        return redir
    admin = _admin()
    if not _check_credentials(admin["username"], current):
        flash(request, "Текущий пароль неверный", "error")
        return go("/settings?tab=security")
    username = username.strip() or admin["username"]
    admin["username"] = username
    if new_password:
        if len(new_password) < 8:
            flash(request, "Пароль минимум 8 символов", "error")
            return go("/settings?tab=security")
        admin["password_hash"] = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
    _save_admin(admin)
    request.session["user"] = username
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
def settings_api_token(action: str, request: Request, name: str = Form(""), token_id: str = Form("")):
    if redir := _require(request):
        return redir
    with mutate() as store:
        tokens = store["settings"]["api_tokens"]
        if action == "create":
            raw = "l2x_" + secrets.token_urlsafe(32)
            tokens.append({"id": secrets.token_hex(4), "name": name.strip() or "token", "hash": _hash_token(raw),
                           "last4": raw[-4:], "created": xray.now_utc().isoformat()})
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
    name, blob = _tg_backup()
    BOT.send_document(name, blob, "Бэкап L2X Panel")
    flash(request, "Бэкап отправлен в Telegram", "info")
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
    flash(request, *_ok_msg(f"Бэкап восстановлен (копия до: {res['safety_copy']})", xr))
    return go("/settings?tab=backup")


@app.get("/jobs/{job_id}")
def job_status(job_id: str, request: Request):
    if not _user(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return ops.JOBS.get(job_id) or {"status": "unknown"}


# ================================================================ REST API (/panel/api)

def _api_auth(request: Request) -> bool:
    if _user(request):
        return True
    auth = request.headers.get("authorization") or ""
    token = auth[7:].strip() if auth.lower().startswith("bearer ") else request.headers.get("x-api-key", "")
    if not token:
        return False
    h = _hash_token(token)
    return any(secrets.compare_digest(h, x["hash"]) for x in (SETTINGS_CACHE.get("api_tokens") or []))


def _api_err(msg: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "msg": msg}, status_code=code)


def _api_ok(obj: Any = None, msg: str = "") -> dict:
    return {"success": True, "msg": msg, "obj": obj}


def _public_client(store: dict, c: dict) -> dict:
    return {
        "email": c["email"], "uuid": c["uuid"], "enabled": c.get("enabled", True), "status": xray.client_status(c),
        "outbound": c.get("outbound"), "inbounds": [i["tag"] for i in xray.client_inbounds(store, c)],
        "limit_gb": c.get("limit_gb"), "expire_at": c.get("expire_at"), "limit_ip": c.get("limit_ip"),
        "limit_hwid": c.get("limit_hwid"), "hwid": hwid.status(c),
        "up": c["traffic"].get("up"), "down": c["traffic"].get("down"), "online": c["email"] in ONLINE,
        "last_online": c.get("last_online"), "comment": c.get("comment"), "tg_id": c.get("tg_id"),
        "sub_url": sub_url(c), "reset_period": c.get("reset_period"), "outbound_limits": c.get("outbound_limits"),
        "allowed_tags": c.get("allowed_tags"),
    }


API_CLIENT_FIELDS = ("outbound", "enabled", "limit_gb", "expire_at", "limit_ip", "limit_hwid", "comment", "tg_id", "inbounds",
                     "reset_period", "renew_on_reset", "start_on_first_use", "duration_days", "allowed_tags",
                     "outbound_limits", "sub_enabled")


def _api_apply_client(store: dict, c: dict, data: dict) -> str | None:
    for key in API_CLIENT_FIELDS:
        if key in data:
            c[key] = data[key]
    if c.get("outbound") not in _allowed_outbounds(store):
        return f"unknown outbound {c.get('outbound')}"
    if c.get("expire_at") and not xray.parse_expire_at(c["expire_at"]):
        return "bad expire_at"
    return None


@app.api_route("/panel/api/{path:path}", methods=["GET", "POST", "DELETE"])
async def rest_api(path: str, request: Request):
    if not _api_auth(request):
        return _api_err("unauthorized", 401)
    try:
        data = await request.json() if request.method == "POST" and (request.headers.get("content-type") or "").startswith("application/json") else {}
    except ValueError:
        return _api_err("bad json")
    parts = [p for p in path.split("/") if p]
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
        res = _apply_xray(_load_store())
        return _api_ok(_public_client(_load_store(), c), res.get("error", ""))
    if len(parts) == 3 and parts[:2] == ["clients", "update"] and request.method == "POST":
        with mutate() as st:
            c = next((x for x in st["clients"] if x["email"] == parts[2]), None)
            if not c:
                return _api_err("not found", 404)
            err = _api_apply_client(st, c, data)
            if err:
                return _api_err(err)
        res = _apply_xray(_load_store())
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
        _apply_xray(_load_store())
        return _api_ok(None, f"{parts[1]} ok")
    if parts == ["clients", "resetAll"] and request.method == "POST":
        with mutate() as st:
            for c in st["clients"]:
                xray.reset_client_traffic(c)
        _apply_xray(_load_store())
        return _api_ok(None, "reset all")
    if parts == ["l2tp", "list"]:
        return _api_ok([{k: v for k, v in x.items() if k not in ("password",)} for x in store["l2tp"]])
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

@app.get("/nodes", response_class=HTMLResponse)
def nodes_page(request: Request):
    if redir := _require(request):
        return redir
    with mutate() as store:
        nodes_mod.ensure_list(store)
        nodes_mod.agent_token(store)
    store = _load_store()
    return page(request, "nodes.html", active="nodes", items=store["nodes"], ns=store["settings"].get("nodes") or {})


@app.post("/nodes/add")
async def nodes_add(request: Request):
    if redir := _require(request):
        return redir
    form = await request.form()
    name = str(form.get("name") or "").strip() or "node"
    url = str(form.get("url") or "").strip().rstrip("/")
    token = str(form.get("token") or "").strip()
    if not url.startswith("http"):
        flash(request, "URL ноды должен начинаться с http", "error")
        return go("/nodes")
    with mutate() as store:
        nodes_mod.ensure_list(store).append({
            "id": str(uuid.uuid4()), "name": name, "url": url, "token": token, "enabled": True,
            "sync_clients": form.get("sync_clients") == "1", "sync_inbounds": form.get("sync_inbounds") == "1",
            "last_sync": "", "last_error": "", "last_ok": False,
        })
    flash(request, f"Нода {name} добавлена", "info")
    return go("/nodes")


@app.post("/nodes/{node_id}/{action}")
def nodes_action(node_id: str, action: str, request: Request):
    if redir := _require(request):
        return redir
    with mutate() as store:
        nodes = nodes_mod.ensure_list(store)
        node = next((n for n in nodes if n["id"] == node_id), None)
        if not node:
            flash(request, "Нода не найдена", "error")
            return go("/nodes")
        if action == "delete":
            nodes.remove(node)
            flash(request, "Нода удалена", "info")
            return go("/nodes")
        if action == "toggle":
            node["enabled"] = not node.get("enabled", True)
            flash(request, f"{node['name']}: {'вкл' if node['enabled'] else 'выкл'}", "info")
            return go("/nodes")
        if action == "sync":
            payload = nodes_mod.build_payload(store, node, xray.build_config)
            res = nodes_mod.push(node, payload)
            webhooks.fire(store["settings"], "node.sync", {"node": node["name"], "ok": res.get("ok"), "error": res.get("error")})
            flash(request, f"{node['name']}: {'OK' if res.get('ok') else res.get('error') or 'ошибка'}",
                  "info" if res.get("ok") else "error")
            return go("/nodes")
    flash(request, "Неизвестное действие", "error")
    return go("/nodes")


@app.post("/nodes/sync-all")
def nodes_sync_all(request: Request):
    if redir := _require(request):
        return redir
    ok = fail = 0
    with mutate() as store:
        for node in nodes_mod.ensure_list(store):
            if not node.get("enabled", True):
                continue
            payload = nodes_mod.build_payload(store, node, xray.build_config)
            res = nodes_mod.push(node, payload)
            ok += 1 if res.get("ok") else 0
            fail += 0 if res.get("ok") else 1
            webhooks.fire(store["settings"], "node.sync", {"node": node["name"], "ok": res.get("ok")})
    flash(request, f"Синхронизация: OK {ok}, ошибок {fail}", "info" if not fail else "error")
    return go("/nodes")


@app.post("/agent/apply")
async def agent_apply(request: Request):
    """Remote node agent: accept pushed config from master panel."""
    store = _load_store()
    ns = store["settings"].get("nodes") or {}
    if not ns.get("agent_enabled"):
        return JSONResponse({"ok": False, "error": "agent disabled"}, status_code=403)
    auth = request.headers.get("authorization") or ""
    token = auth.removeprefix("Bearer ").strip() if auth.startswith("Bearer ") else ""
    expected = ns.get("agent_token") or ""
    if not expected or not token or not secrets.compare_digest(token, expected):
        return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)
    try:
        payload = await request.json()
    except ValueError:
        return JSONResponse({"ok": False, "error": "bad json"}, status_code=400)
    with mutate() as st:
        if payload.get("clients") is not None:
            st["clients"] = payload["clients"]
        if payload.get("inbounds") is not None:
            st["inbounds"] = payload["inbounds"]
        if payload.get("outbounds_custom") is not None:
            st["outbounds_custom"] = payload["outbounds_custom"]
        if payload.get("routes") is not None:
            st["routes"] = payload["routes"]
        if payload.get("balancers") is not None:
            st["balancers"] = payload["balancers"]
        if payload.get("dns") is not None:
            st["dns"] = payload["dns"]
        if payload.get("xray_settings") is not None:
            st["xray_settings"] = payload["xray_settings"]
    res = _apply_xray(_load_store())
    return {"ok": bool(res.get("ok")), "error": res.get("error") or ""}


@app.get("/api-docs", response_class=HTMLResponse)
def api_docs(request: Request):
    if redir := _require(request):
        return redir
    return page(request, "api_docs.html", active="settings")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "8090")))
