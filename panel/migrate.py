"""Import users from 3x-ui, PasarGuard, or Remnawave (API or backup file).

Preserves subscription tokens, traffic counters, limits, and expiry so clients
can keep their existing subscription URLs after DNS points at L2X.
"""
from __future__ import annotations

import gzip
import io
import json
import re
import sqlite3
import ssl
import tarfile
import tempfile
import zipfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit
from urllib.request import Request, build_opener, HTTPCookieProcessor, HTTPSHandler
from http.cookiejar import CookieJar

import xray_runtime as xray

SOURCES = ("3xui", "pasarguard", "remnawave")
SOURCE_LABELS = {
    "3xui": "3x-ui",
    "pasarguard": "PasarGuard",
    "remnawave": "Remnawave",
}

# Filled by fetch/parse when source exposes sub path/port (3x-ui settings).
LAST_SOURCE_META: dict[str, Any] = {}


@dataclass
class NormalizedUser:
    email: str
    uuid: str = ""
    password: str = ""
    sub_token: str = ""
    limit_gb: float = 0.0
    expire_at: str = ""
    enabled: bool = True
    comment: str = ""
    tg_id: str = ""
    up: int = 0
    down: int = 0
    source: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("extra", None)
        return d


# ---------------------------------------------------------------- helpers

def _safe_int(v: Any, default: int = 0) -> int:
    try:
        if v is None or v == "":
            return default
        return int(float(v))
    except (TypeError, ValueError):
        return default


def _safe_float(v: Any, default: float = 0.0) -> float:
    try:
        if v is None or v == "":
            return default
        return float(v)
    except (TypeError, ValueError):
        return default


def bytes_to_limit_gb(n: Any) -> float:
    b = _safe_int(n, 0)
    if b <= 0:
        return 0.0
    return round(b / xray.GB, 6)


def token_from_url(url: str) -> str:
    """Last non-empty path segment of a subscription URL."""
    raw = str(url or "").strip()
    if not raw:
        return ""
    if "://" not in raw and "/" not in raw:
        return raw
    path = urlsplit(raw).path if "://" in raw else raw
    parts = [p for p in path.split("/") if p]
    return parts[-1] if parts else ""


def expire_from_ms(ms: Any) -> str:
    """3x-ui expiryTime is ms since epoch; 0 = unlimited."""
    n = _safe_int(ms, 0)
    if n <= 0:
        return ""
    # Heuristic: seconds vs milliseconds
    if n < 10_000_000_000:
        n *= 1000
    try:
        return datetime.fromtimestamp(n / 1000, tz=timezone.utc).isoformat(timespec="seconds")
    except (OSError, OverflowError, ValueError):
        return ""


def expire_from_unix(sec: Any) -> str:
    n = _safe_int(sec, 0)
    if n <= 0:
        return ""
    if n > 10_000_000_000:  # ms
        n //= 1000
    try:
        return datetime.fromtimestamp(n, tz=timezone.utc).isoformat(timespec="seconds")
    except (OSError, OverflowError, ValueError):
        return ""


def expire_from_iso(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    dt = xray.parse_expire_at(raw)
    if not dt:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def _norm_email(email: str) -> str:
    return str(email or "").strip()


# ---------------------------------------------------------------- HTTP

class HttpClient:
    def __init__(self, base_url: str, *, insecure: bool = False, timeout: int = 60):
        base = str(base_url or "").strip().rstrip("/")
        if not base.startswith("http"):
            raise ValueError("URL панели должен начинаться с http:// или https://")
        self.base = base
        self.timeout = timeout
        self.jar = CookieJar()
        ctx = ssl._create_unverified_context() if insecure else ssl.create_default_context()
        self.opener = build_opener(HTTPCookieProcessor(self.jar), HTTPSHandler(context=ctx))
        self.headers: dict[str, str] = {"User-Agent": "l2xpanel-migrate/1.0", "Accept": "application/json"}

    def url(self, path: str) -> str:
        if path.startswith("http"):
            return path
        return urljoin(self.base + "/", path.lstrip("/"))

    def request(
        self,
        method: str,
        path: str,
        *,
        data: bytes | None = None,
        headers: dict | None = None,
        form: dict | None = None,
        json_body: Any = None,
    ) -> tuple[int, bytes, dict[str, str]]:
        hdrs = {**self.headers, **(headers or {})}
        body = data
        if json_body is not None:
            body = json.dumps(json_body).encode()
            hdrs.setdefault("Content-Type", "application/json")
        elif form is not None:
            from urllib.parse import urlencode
            body = urlencode(form).encode()
            hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
        req = Request(self.url(path), data=body, headers=hdrs, method=method.upper())
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                raw = resp.read()
                rh = {k.lower(): v for k, v in resp.headers.items()}
                return int(resp.status), raw, rh
        except HTTPError as exc:
            raw = exc.read() if exc.fp else b""
            rh = {k.lower(): v for k, v in (exc.headers.items() if exc.headers else [])}
            return int(exc.code), raw, rh
        except URLError as exc:
            raise RuntimeError(f"Не удалось подключиться к панели: {exc.reason}") from exc

    def json(self, method: str, path: str, **kw) -> Any:
        code, raw, _ = self.request(method, path, **kw)
        if code >= 400:
            snippet = raw[:300].decode("utf-8", "replace")
            raise RuntimeError(f"HTTP {code} {path}: {snippet}")
        if not raw:
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except ValueError as exc:
            raise RuntimeError(f"Ответ не JSON ({path})") from exc


# ---------------------------------------------------------------- preview / apply

def preview(store: dict, users: list[NormalizedUser]) -> dict[str, Any]:
    existing = {str(c.get("email") or "") for c in store.get("clients") or []}
    create, skip, conflicts = [], [], []
    for u in users:
        email = _norm_email(u.email)
        if not email:
            continue
        if email in existing:
            skip.append(email)
            conflicts.append(email)
        else:
            create.append(email)
    return {
        "total": len(users),
        "create": len(create),
        "skip": len(skip),
        "conflicts": conflicts[:50],
        "sample": [u.to_dict() for u in users[:5]],
    }


def _set_imported_traffic(client: dict, up: int, down: int) -> None:
    """Write migrated counters into both top-level traffic and by_email.

    harvest_traffic rebuilds traffic.up/down from by_email sums. An empty
    by_email would wipe imported usage on the next watchdog cycle.
    """
    up_i = max(0, int(up or 0))
    down_i = max(0, int(down or 0))
    t = client.setdefault("traffic", {})
    t["up"] = up_i
    t["down"] = down_i
    by = t.setdefault("by_email", {})
    email = str(client.get("email") or "").strip()
    if not email:
        return
    row = by.setdefault(email, {"up": 0, "down": 0, "last_up": 0, "last_down": 0})
    row["up"] = up_i
    row["down"] = down_i
    # last_* stay 0 so live Xray deltas accumulate on top of imported totals


def apply(
    store: dict,
    users: list[NormalizedUser],
    inbound_tags: list[str],
    *,
    update_existing: bool = False,
) -> dict[str, Any]:
    """Mutate store clients in-place. Caller holds mutate() lock."""
    capable = {i["tag"] for i in xray.client_capable_inbounds(store)}
    tags = [t for t in inbound_tags if t in capable] if inbound_tags else list(capable)
    by_email = {str(c.get("email") or ""): c for c in store.get("clients") or []}
    created = updated = skipped = traffic_fixed = 0
    traffic_bytes = 0
    errors: list[str] = []

    for u in users:
        email = _norm_email(u.email)
        if not email:
            skipped += 1
            continue
        existing = by_email.get(email)
        up_i, down_i = int(u.up or 0), int(u.down or 0)
        if existing and not update_existing:
            # Re-run after a buggy import: fill traffic if panel still shows 0
            if (up_i or down_i) and xray.client_used_bytes(existing) <= 0:
                try:
                    xray.ensure_client(existing)
                    _set_imported_traffic(existing, up_i, down_i)
                    traffic_fixed += 1
                    traffic_bytes += up_i + down_i
                except Exception as exc:  # noqa: BLE001
                    errors.append(f"{email}: {exc}")
            else:
                skipped += 1
            continue
        try:
            if existing and update_existing:
                c = existing
                if u.sub_token:
                    c["sub_token"] = u.sub_token
                if u.uuid:
                    c["uuid"] = u.uuid
                if u.password:
                    c["password"] = u.password
                if u.limit_gb:
                    c["limit_gb"] = u.limit_gb
                if u.expire_at:
                    c["expire_at"] = u.expire_at
                c["enabled"] = bool(u.enabled)
                if u.comment:
                    c["comment"] = u.comment
                if u.tg_id:
                    c["tg_id"] = str(u.tg_id)
                if tags:
                    c["inbounds"] = list(tags)
                xray.ensure_client(c)
                _set_imported_traffic(c, up_i, down_i)
                traffic_bytes += up_i + down_i
                xray.ensure_wg_peer(store, c)
                updated += 1
            else:
                payload: dict[str, Any] = {
                    "email": email,
                    "enabled": bool(u.enabled),
                    "inbounds": list(tags),
                    "limit_gb": float(u.limit_gb or 0),
                    "expire_at": u.expire_at or "",
                    "comment": u.comment or "",
                    "tg_id": str(u.tg_id or ""),
                    "sub_enabled": True,
                }
                if u.sub_token:
                    payload["sub_token"] = u.sub_token
                if u.uuid:
                    payload["uuid"] = u.uuid
                if u.password:
                    payload["password"] = u.password
                c = xray.ensure_client(payload)
                _set_imported_traffic(c, up_i, down_i)
                traffic_bytes += up_i + down_i
                if not c.get("sub_token"):
                    import secrets
                    c["sub_token"] = secrets.token_urlsafe(18)
                store.setdefault("clients", []).append(c)
                by_email[email] = c
                xray.ensure_wg_peer(store, c)
                created += 1
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{email}: {exc}")

    return {
        "ok": not errors,
        "created": created,
        "updated": updated,
        "skipped": skipped,
        "traffic_fixed": traffic_fixed,
        "traffic_bytes": traffic_bytes,
        "errors": errors[:30],
        "inbounds": tags,
    }


# ---------------------------------------------------------------- 3x-ui

def _row_dict(row: sqlite3.Row | dict) -> dict[str, Any]:
    """SQLite row → dict with lowercase keys (GORM may use email/up/down or mixed)."""
    if isinstance(row, dict):
        return {str(k).lower(): row[k] for k in row}
    return {str(k).lower(): row[k] for k in row.keys()}


def _x3_pick_uuid(c: dict) -> str:
    for key in ("uuid", "id"):
        raw = str(c.get(key) or "").strip()
        if not raw:
            continue
        # clients.id is often an autoincrement int — skip those
        if raw.isdigit():
            continue
        return raw
    return ""


def _x3_client_from_dict(c: dict, traffic: dict | None = None, *, source: str = "3xui") -> NormalizedUser | None:
    email = _norm_email(c.get("email") or c.get("Email") or "")
    if not email:
        return None
    tr = traffic or {}
    # Prefer client_traffics counters; fall back to fields on the client object
    up = _safe_int(tr.get("up", tr.get("upload", c.get("up", c.get("upload")))), 0)
    down = _safe_int(tr.get("down", tr.get("download", c.get("down", c.get("download")))), 0)
    # Limit: totalGB (GB) on client, else total bytes from traffic/client
    if c.get("totalGB") not in (None, "") or c.get("total_gb") not in (None, ""):
        limit_gb = _safe_float(c.get("totalGB", c.get("total_gb")), 0)
    else:
        total = _safe_int(tr.get("total", c.get("total")), 0)
        limit_gb = bytes_to_limit_gb(total) if total > 1024 else _safe_float(total, 0)
    exp = expire_from_ms(
        c.get("expiryTime") or c.get("expiry_time") or tr.get("expirytime") or tr.get("expiry_time")
    )
    enabled = c.get("enable", True)
    if isinstance(enabled, str):
        enabled = enabled.lower() not in ("0", "false", "no")
    elif "enable" in tr and c.get("enable") is None:
        enabled = bool(tr.get("enable"))
    sub = str(c.get("subId") or c.get("sub_id") or tr.get("subid") or "").strip()
    uid = _x3_pick_uuid(c)
    password = str(c.get("password") or c.get("passwd") or "").strip()
    return NormalizedUser(
        email=email,
        uuid=uid,
        password=password,
        sub_token=sub,
        limit_gb=limit_gb,
        expire_at=exp,
        enabled=bool(enabled),
        comment=str(c.get("comment") or "") or (f"tg:{c.get('tgId')}" if c.get("tgId") else ""),
        tg_id=str(c.get("tgId") or c.get("tg_id") or c.get("telegramId") or ""),
        up=up,
        down=down,
        source=source,
    )


def parse_3xui_json(raw: bytes | str) -> list[NormalizedUser]:
    data = json.loads(raw if isinstance(raw, str) else raw.decode("utf-8"))
    # Portable export: [{client, inboundIds, traffic}]
    if isinstance(data, dict) and "obj" in data:
        data = data["obj"]
    if isinstance(data, dict) and "data" in data:
        inner = data["data"]
        if isinstance(inner, str):
            data = json.loads(inner)
        else:
            data = inner
    out: list[NormalizedUser] = []
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and "client" in item:
                u = _x3_client_from_dict(item.get("client") or {}, item.get("traffic") or {})
            elif isinstance(item, dict):
                u = _x3_client_from_dict(item, item.get("traffic") if isinstance(item.get("traffic"), dict) else None)
            else:
                u = None
            if u:
                out.append(u)
    return out


def read_3xui_sub_meta(path: Path | str) -> dict[str, Any]:
    """Read subPath / subPort from a 3x-ui SQLite backup (settings table)."""
    meta: dict[str, Any] = {"path": "", "port": 0}
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    try:
        try:
            rows = conn.execute("SELECT key, value FROM settings")
        except sqlite3.Error:
            try:
                rows = conn.execute('SELECT "key", value FROM settings')
            except sqlite3.Error:
                return meta
        kv = {}
        for row in rows:
            try:
                kv[str(row["key"])] = row["value"]
            except (KeyError, IndexError):
                keys = list(row.keys())
                if len(keys) >= 2:
                    kv[str(row[keys[0]])] = row[keys[1]]
        for k in ("subPath", "sub_path"):
            if kv.get(k):
                raw = str(kv[k]).strip().strip("/")
                meta["path"] = re.sub(r"[^A-Za-z0-9_-]", "", raw.split("/")[0])
                if meta["path"]:
                    break
        if not meta["path"]:
            for k in ("subURI", "subUri", "sub_uri"):
                if not kv.get(k):
                    continue
                raw = str(kv[k]).strip()
                parts = [p for p in urlsplit(raw).path.split("/") if p] if "://" in raw else [p for p in raw.split("/") if p]
                if parts:
                    meta["path"] = re.sub(r"[^A-Za-z0-9_-]", "", parts[0])
                if meta["path"]:
                    break
        for k in ("subPort", "sub_port"):
            if kv.get(k) not in (None, ""):
                try:
                    meta["port"] = int(kv[k])
                except (TypeError, ValueError):
                    pass
                if meta["port"]:
                    break
    finally:
        conn.close()
    return meta


def _load_3xui_traffics(conn: sqlite3.Connection) -> dict[str, dict]:
    """email(lower) → {up, down, total, enable, expiryTime} from client_traffics."""
    traffics: dict[str, dict] = {}
    try:
        rows = conn.execute("SELECT * FROM client_traffics")
    except sqlite3.Error:
        return traffics
    for row in rows:
        d = _row_dict(row)
        email = _norm_email(d.get("email") or "")
        if not email:
            continue
        key = email.lower()
        up = _safe_int(d.get("up"), 0)
        down = _safe_int(d.get("down"), 0)
        # After a traffic reset 3x-ui keeps lifetime in allTime / all_time
        all_time = _safe_int(d.get("all_time", d.get("alltime")), 0)
        if up + down <= 0 and all_time > 0:
            down = all_time
        prev = traffics.get(key)
        if prev:
            # Same email on multiple rows (shouldn't happen) — sum usage
            up += _safe_int(prev.get("up"), 0)
            down += _safe_int(prev.get("down"), 0)
        traffics[key] = {
            "up": up,
            "down": down,
            "total": _safe_int(d.get("total"), 0),
            "enable": d.get("enable", True),
            "expiryTime": d.get("expiry_time", d.get("expirytime")),
            "subId": d.get("sub_id") or d.get("subid") or "",
            "_email": email,
        }
    return traffics


def parse_3xui_sqlite(path: Path | str) -> list[NormalizedUser]:
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    try:
        traffics = _load_3xui_traffics(conn)

        # Collect client defs from modern `clients` table AND classic inbounds.settings
        by_email: dict[str, dict] = {}

        try:
            for row in conn.execute("SELECT * FROM clients"):
                d = _row_dict(row)
                email = _norm_email(d.get("email") or "")
                if not email:
                    continue
                mapped = {
                    "email": email,
                    "uuid": d.get("uuid") or "",
                    "id": d.get("uuid") or d.get("id") or "",
                    "password": d.get("password") or "",
                    "subId": d.get("sub_id") or d.get("subid") or "",
                    "totalGB": d.get("total_gb") if d.get("total_gb") not in (None, "") else d.get("totalgb"),
                    "expiryTime": d.get("expiry_time") or d.get("expirytime"),
                    "enable": d.get("enable", True),
                    "comment": d.get("comment") or "",
                    "tgId": d.get("tg_id") or d.get("tgid") or "",
                }
                by_email[email.lower()] = mapped
        except sqlite3.Error:
            pass

        try:
            for row in conn.execute("SELECT settings FROM inbounds"):
                try:
                    settings = json.loads(row["settings"] or "{}")
                except (ValueError, TypeError, KeyError):
                    continue
                for c in settings.get("clients") or []:
                    if not isinstance(c, dict):
                        continue
                    email = _norm_email(c.get("email") or "")
                    if not email:
                        continue
                    key = email.lower()
                    # Inbound JSON is the classic source of uuid/subId; don't wipe modern row
                    if key not in by_email:
                        by_email[key] = dict(c)
                    else:
                        cur = by_email[key]
                        if not cur.get("uuid") and not _x3_pick_uuid(cur):
                            if c.get("id") or c.get("uuid"):
                                cur["id"] = c.get("id") or c.get("uuid")
                                cur["uuid"] = c.get("uuid") or c.get("id") or cur.get("uuid")
                        if not cur.get("subId") and (c.get("subId") or c.get("sub_id")):
                            cur["subId"] = c.get("subId") or c.get("sub_id")
                        if cur.get("totalGB") in (None, "", 0) and c.get("totalGB") not in (None, ""):
                            cur["totalGB"] = c.get("totalGB")
                        if not cur.get("password") and c.get("password"):
                            cur["password"] = c.get("password")
        except sqlite3.Error:
            pass

        # Traffic-only rows still become users (email from client_traffics)
        for key, tr in traffics.items():
            if key not in by_email:
                by_email[key] = {"email": tr.get("_email") or key, "enable": tr.get("enable", True)}

        out: list[NormalizedUser] = []
        for key, c in by_email.items():
            tr = traffics.get(key) or {}
            u = _x3_client_from_dict(c, tr)
            if u:
                out.append(u)

        global LAST_SOURCE_META
        used = sum(int(u.up) + int(u.down) for u in out)
        LAST_SOURCE_META = {
            **(LAST_SOURCE_META or {}),
            "source": "3xui",
            "traffic_rows": len(traffics),
            "clients": len(out),
            "traffic_bytes": used,
        }
        return out
    finally:
        conn.close()


def fetch_3xui_api(
    base_url: str,
    username: str,
    password: str,
    *,
    insecure: bool = False,
    web_base: str = "",
) -> list[NormalizedUser]:
    """Login + prefer getDb; fallback to inbounds list."""
    http = HttpClient(base_url, insecure=insecure)
    # webBasePath may be /panel/ or custom — try login at root and under path
    paths = ["/login"]
    wb = str(web_base or "").strip().strip("/")
    if wb:
        paths.insert(0, f"/{wb}/login")
        paths.append(f"/{wb}/login")
    last_err = None
    logged = False
    for p in paths:
        try:
            code, raw, _ = http.request(
                "POST", p, json_body={"username": username, "password": password},
            )
            if code < 400:
                try:
                    obj = json.loads(raw.decode() or "{}")
                except ValueError:
                    obj = {}
                if obj.get("success") is False:
                    last_err = obj.get("msg") or "login failed"
                    continue
                logged = True
                break
            last_err = f"HTTP {code}"
        except Exception as exc:  # noqa: BLE001
            last_err = str(exc)
    if not logged:
        raise RuntimeError(f"3x-ui login failed: {last_err or 'unknown'}")

    prefix = f"/{wb}" if wb else ""
    # Try DB download first
    for db_path in (f"{prefix}/panel/api/server/getDb", f"{prefix}/panel/api/server/getdb", "/panel/api/server/getDb"):
        try:
            code, raw, hdrs = http.request("GET", db_path)
            if code < 400 and raw[:15].startswith(b"SQLite format 3"):
                with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
                    tmp.write(raw)
                    tmp_path = Path(tmp.name)
                try:
                    users = parse_3xui_sqlite(tmp_path)
                    meta = read_3xui_sub_meta(tmp_path)
                    global LAST_SOURCE_META
                    LAST_SOURCE_META = {**(LAST_SOURCE_META or {}), "source": "3xui", **meta}
                    return users
                finally:
                    tmp_path.unlink(missing_ok=True)
            # Sometimes wrapped — ignore
        except Exception:
            continue

    # Fallback: list inbounds
    for list_path in (f"{prefix}/panel/api/inbounds/list", "/panel/api/inbounds/list"):
        try:
            data = http.json("GET", list_path)
        except Exception:
            continue
        obj = data.get("obj") if isinstance(data, dict) else data
        if not isinstance(obj, list):
            continue
        out: list[NormalizedUser] = []
        seen: set[str] = set()
        for ib in obj:
            settings = ib.get("settings")
            if isinstance(settings, str):
                try:
                    settings = json.loads(settings)
                except ValueError:
                    settings = {}
            stats = {str(s.get("email")): s for s in (ib.get("clientStats") or []) if isinstance(s, dict)}
            for c in (settings or {}).get("clients") or []:
                if not isinstance(c, dict):
                    continue
                email = _norm_email(c.get("email"))
                u = _x3_client_from_dict(c, stats.get(email))
                if u and u.email not in seen:
                    seen.add(u.email)
                    out.append(u)
        if out:
            return out
    raise RuntimeError("3x-ui: не удалось получить клиентов (getDb / inbounds/list)")


# ---------------------------------------------------------------- PasarGuard / Marzban-like

def _pg_as_dict(value: Any) -> dict:
    """proxies / proxy_settings may arrive as dict or JSON string (sqlite/sql dumps)."""
    if isinstance(value, dict):
        return value
    if isinstance(value, (bytes, bytearray)):
        try:
            value = value.decode("utf-8")
        except Exception:
            return {}
    if isinstance(value, str):
        s = value.strip()
        if not s or s.upper() == "NULL":
            return {}
        try:
            data = json.loads(s)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}
    return {}


def _pg_proxy_blob(u: dict) -> dict:
    """Modern PasarGuard uses proxy_settings; Marzban used proxies."""
    blob = _pg_as_dict(u.get("proxy_settings"))
    if blob:
        return blob
    return _pg_as_dict(u.get("proxies"))


def _pg_uuid_password(u: dict) -> tuple[str, str]:
    proxies = _pg_proxy_blob(u)
    vless = proxies.get("vless") if isinstance(proxies.get("vless"), dict) else {}
    vmess = proxies.get("vmess") if isinstance(proxies.get("vmess"), dict) else {}
    trojan = proxies.get("trojan") if isinstance(proxies.get("trojan"), dict) else {}
    ss = proxies.get("shadowsocks") if isinstance(proxies.get("shadowsocks"), dict) else {}
    uuid = str(
        u.get("uuid")
        or vless.get("id")
        or vless.get("uuid")
        or vmess.get("id")
        or vmess.get("uuid")
        or ""
    ).strip()
    password = str(
        u.get("password")
        or trojan.get("password")
        or ss.get("password")
        or ""
    ).strip()
    return uuid, password


def _pg_expire_at(u: dict) -> str:
    """PasarGuard expire is DateTime; older Marzban used unix seconds."""
    for key in ("expire_at", "expireAt", "expire"):
        raw = u.get(key)
        if raw in (None, "", 0, "0"):
            continue
        if isinstance(raw, datetime):
            return expire_from_iso(raw.isoformat())
        s = str(raw).strip()
        if not s or s.upper() == "NULL":
            continue
        # Numeric unix / ms
        if re.fullmatch(r"-?\d+(\.\d+)?", s):
            exp = expire_from_unix(s)
            if exp:
                return exp
            continue
        exp = expire_from_iso(s)
        if exp:
            return exp
    return ""


def _pg_user_from_dict(u: dict, *, source: str = "pasarguard") -> NormalizedUser | None:
    email = _norm_email(u.get("username") or u.get("email") or u.get("name") or "")
    if not email:
        return None
    sub = (
        str(u.get("subscription_token") or "").strip()
        or token_from_url(str(u.get("subscription_url") or u.get("subscriptionUrl") or ""))
    )
    used = _safe_int(
        u.get("lifetime_used_traffic")
        or u.get("lifetimeUsedTraffic")
        or u.get("used_traffic")
        or u.get("usedTraffic"),
        0,
    )
    limit = _safe_int(u.get("data_limit") or u.get("dataLimit") or 0, 0)
    status = str(u.get("status") or "active").lower()
    enabled = status not in ("disabled", "on_hold", "expired") and status != "false"
    if "enabled" in u:
        enabled = bool(u["enabled"])
    uuid, password = _pg_uuid_password(u)
    # File dumps often have no subscription_url (it is computed by PasarGuard).
    # Fall back to a stable token from username so import still creates usable clients;
    # for exact old links prefer API import.
    if not sub:
        sub = re.sub(r"[^A-Za-z0-9_-]", "", email)[:64] or email
    return NormalizedUser(
        email=email,
        uuid=uuid,
        password=password,
        sub_token=sub,
        limit_gb=bytes_to_limit_gb(limit),
        expire_at=_pg_expire_at(u),
        enabled=enabled,
        comment=str(u.get("note") or u.get("comment") or ""),
        tg_id=str(u.get("telegram_id") or u.get("telegramId") or ""),
        up=0,
        down=used,
        source=source,
        extra={"status": status, "id": u.get("id")},
    )


def parse_pasarguard_json(raw: bytes | str) -> list[NormalizedUser]:
    data = json.loads(raw if isinstance(raw, str) else raw.decode("utf-8"))
    users = data
    if isinstance(data, dict):
        users = data.get("users") or data.get("items") or data.get("data") or []
    out = []
    if isinstance(users, list):
        for u in users:
            if isinstance(u, dict):
                nu = _pg_user_from_dict(u)
                if nu:
                    out.append(nu)
    return out


def _extract_archive_members(raw: bytes) -> list[tuple[str, bytes]]:
    found: list[tuple[str, bytes]] = []
    # zip
    if raw[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            for name in zf.namelist():
                if name.endswith("/"):
                    continue
                found.append((name, zf.read(name)))
        return found
    # tar / tar.gz
    bio = io.BytesIO(raw)
    try:
        with tarfile.open(fileobj=bio, mode="r:*") as tf:
            for m in tf.getmembers():
                if not m.isfile():
                    continue
                f = tf.extractfile(m)
                if f:
                    found.append((m.name, f.read()))
        return found
    except tarfile.TarError:
        pass
    # bare gzip
    try:
        return [("data", gzip.decompress(raw))]
    except OSError:
        pass
    return [("upload", raw)]


def _sql_unquote(v: Any) -> Any:
    if v is None:
        return None
    s = str(v).strip()
    if s.upper() == "NULL":
        return None
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
        return s[1:-1].replace("''", "'").replace('\\"', '"')
    return s


def _split_sql_values(row: str) -> list[str]:
    parts: list[str] = []
    cur = []
    in_q = False
    qch = ""
    i = 0
    while i < len(row):
        ch = row[i]
        if in_q:
            if ch == qch:
                if i + 1 < len(row) and row[i + 1] == qch:
                    cur.append(qch)
                    i += 2
                    continue
                in_q = False
                cur.append(ch)
            else:
                cur.append(ch)
        else:
            if ch in ("'", '"'):
                in_q = True
                qch = ch
                cur.append(ch)
            elif ch == ",":
                parts.append("".join(cur).strip())
                cur = []
            else:
                cur.append(ch)
        i += 1
    if cur:
        parts.append("".join(cur).strip())
    return parts


def _pg_rec_from_sql_cols(cols: list[str], fields: list[Any]) -> dict:
    rec_raw = {cols[i]: fields[i] for i in range(min(len(cols), len(fields)))}
    return {
        "id": _sql_unquote(rec_raw.get("id")),
        "username": _sql_unquote(rec_raw.get("username")),
        "uuid": _sql_unquote(rec_raw.get("uuid")),
        "used_traffic": _sql_unquote(rec_raw.get("used_traffic")),
        "lifetime_used_traffic": _sql_unquote(rec_raw.get("lifetime_used_traffic")),
        "data_limit": _sql_unquote(rec_raw.get("data_limit")),
        "expire": _sql_unquote(rec_raw.get("expire")),
        "status": _sql_unquote(rec_raw.get("status")),
        "note": _sql_unquote(rec_raw.get("note")),
        "telegram_id": _sql_unquote(rec_raw.get("telegram_id")),
        "proxy_settings": _sql_unquote(rec_raw.get("proxy_settings")),
        "proxies": _sql_unquote(rec_raw.get("proxies")),
        "subscription_url": _sql_unquote(rec_raw.get("subscription_url") or ""),
    }


def _parse_users_sql_insert(text: str) -> list[NormalizedUser]:
    """Parse INSERT INTO users (...) VALUES (...); dumps (MySQL / some Postgres)."""
    out: list[NormalizedUser] = []
    for block in re.finditer(
        r"INSERT\s+INTO\s+(?:[\"`]?[\w]+[\"`]?\.)?[\"`]?users[\"`]?\s*\(([^)]+)\)\s*VALUES\s*(.+?);",
        text,
        re.I | re.S,
    ):
        cols = [c.strip().strip('`"') for c in block.group(1).split(",")]
        vals_blob = block.group(2)
        rows = re.findall(r"\(([^()]*(?:\([^()]*\)[^()]*)*)\)", vals_blob)
        for row in rows:
            fields = _split_sql_values(row)
            if len(fields) < len(cols):
                continue
            nu = _pg_user_from_dict(_pg_rec_from_sql_cols(cols, fields))
            if nu:
                out.append(nu)
    return out


def _parse_pg_copy_field(raw: str) -> Any:
    """One Postgres COPY text field (tab-separated, \\N = NULL, escapes \\t \\n \\\\)."""
    if raw == r"\N":
        return None
    out: list[str] = []
    i = 0
    while i < len(raw):
        ch = raw[i]
        if ch == "\\" and i + 1 < len(raw):
            nxt = raw[i + 1]
            out.append({"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "\\": "\\"}.get(nxt, nxt))
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _parse_users_sql_copy(text: str) -> list[NormalizedUser]:
    """Parse Postgres/Timescale ``COPY ... users (...) FROM stdin;`` blocks from pg_dump."""
    out: list[NormalizedUser] = []
    for block in re.finditer(
        r"COPY\s+(?:(?P<schema>[\"\w]+)\.)?(?P<table>[\"\w]+)\s*\((?P<cols>[^)]+)\)\s+FROM\s+stdin\s*;\r?\n(?P<body>.*?)(?<!\S)\\\.\s*(?:\r?\n|$)",
        text,
        re.I | re.S,
    ):
        table = block.group("table").strip().strip('"')
        if table.lower() != "users":
            continue
        cols = [c.strip().strip('"') for c in block.group("cols").split(",")]
        body = block.group("body") or ""
        for line in body.splitlines():
            if not line or line == r"\.":
                continue
            # COPY text format: fields separated by tab
            raw_fields = line.split("\t")
            if len(raw_fields) < len(cols):
                continue
            fields = [_parse_pg_copy_field(f) for f in raw_fields[: len(cols)]]
            nu = _pg_user_from_dict(_pg_rec_from_sql_cols(cols, fields))
            if nu:
                out.append(nu)
    return out


def _parse_users_sql_dump(text: str) -> list[NormalizedUser]:
    """Best-effort parse users from SQL dumps (INSERT and Postgres COPY)."""
    users = _parse_users_sql_insert(text)
    if users:
        return users
    return _parse_users_sql_copy(text)


def _pg_looks_like_sql(content: bytes) -> bool:
    head = content[:24000].upper()
    return (
        (b"COPY " in head and b"USERS" in head)
        or (b"INSERT INTO" in head and b"USERS" in head)
        or (b"CREATE TABLE" in head and b"USERS" in head)
    )


def _pg_member_priority(name: str, content: bytes) -> int:
    """Lower = try earlier. Prefer real DB dumps over random JSON configs in the zip."""
    low = name.lower().replace("\\", "/")
    base = low.rsplit("/", 1)[-1]
    if content[:15] == b"SQLite format 3" or base in ("db.sqlite3", "db.sqlite", "x-ui.db"):
        return 0
    if base.endswith((".sqlite3", ".sqlite", ".db")):
        return 1
    if "db_dump/" in low or "pg_dump/" in low or (base.startswith("db-") and base.endswith(".sql")):
        return 2
    if base in ("db_backup.sql", "dump.sql", "backup.sql") or base.endswith(".sql") or _pg_looks_like_sql(content):
        return 3
    if base.endswith(".json") and (b'"users"' in content[:8000] or b'"username"' in content[:4000]):
        return 4
    if b'"username"' in content[:4000]:
        return 5
    return 100


def parse_pasarguard_backup(raw: bytes) -> list[NormalizedUser]:
    members = _extract_archive_members(raw)
    ordered = sorted(members, key=lambda it: (_pg_member_priority(it[0], it[1]), it[0].lower()))
    errors: list[str] = []
    for name, content in ordered:
        if _pg_member_priority(name, content) >= 100:
            continue
        low = name.lower()
        try:
            if content[:15] == b"SQLite format 3" or low.endswith((".db", ".sqlite", ".sqlite3")):
                with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
                    tmp.write(content)
                    path = Path(tmp.name)
                try:
                    users = _parse_pg_sqlite(path)
                finally:
                    path.unlink(missing_ok=True)
                if users:
                    return users
                continue
            if low.endswith(".sql") or _pg_looks_like_sql(content):
                text = content.decode("utf-8", "replace")
                users = _parse_users_sql_dump(text)
                if users:
                    return users
                continue
            if low.endswith(".json") or b'"username"' in content[:4000]:
                users = parse_pasarguard_json(content)
                if users:
                    return users
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{name}: {exc}")
            continue
    hint = ("; ".join(errors[:3]) + " — ") if errors else ""
    raise RuntimeError(
        "PasarGuard: не удалось разобрать бэкап. "
        f"{hint}"
        "Нужен zip/tar.gz с db.sqlite3 или SQL dump (pg_dump/mysqldump), "
        "либо JSON users. Для сохранения старых ссылок подписки лучше API."
    )


def _parse_pg_sqlite(path: Path) -> list[NormalizedUser]:
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    try:
        tables = {
            r[0].lower()
            for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
        if "users" not in tables:
            return []
        # lifetime = current used_traffic + sum of reset logs (PasarGuard hybrid property)
        has_reset = "user_usage_reset_logs" in tables
        if has_reset:
            sql = (
                "SELECT u.*, "
                "COALESCE(u.used_traffic,0) + COALESCE(("
                "  SELECT SUM(r.used_traffic_at_reset) FROM user_usage_reset_logs r "
                "  WHERE r.user_id = u.id"
                "), 0) AS lifetime_used_traffic "
                "FROM users u"
            )
        else:
            sql = "SELECT * FROM users"
        out: list[NormalizedUser] = []
        for row in conn.execute(sql):
            rec = {k: row[k] for k in row.keys()}
            try:
                nu = _pg_user_from_dict(rec)
            except Exception:
                continue
            if nu:
                out.append(nu)
        return out
    finally:
        conn.close()


def fetch_pasarguard_api(
    base_url: str,
    username: str = "",
    password: str = "",
    *,
    api_key: str = "",
    insecure: bool = False,
) -> list[NormalizedUser]:
    http = HttpClient(base_url, insecure=insecure)
    if api_key:
        http.headers["X-Api-Key"] = api_key
        http.headers["Authorization"] = f"apikey {api_key}"
    elif username and password:
        data = http.json("POST", "/api/admin/token", form={"username": username, "password": password, "grant_type": "password"})
        token = (data or {}).get("access_token") or (data or {}).get("accessToken")
        if not token:
            raise RuntimeError("PasarGuard: не получен access_token")
        http.headers["Authorization"] = f"Bearer {token}"
    else:
        raise RuntimeError("Укажите логин/пароль или API key")

    out: list[NormalizedUser] = []
    offset = 0
    limit = 100
    while True:
        # Try several list shapes
        tried = False
        for path in (
            f"/api/users?offset={offset}&limit={limit}",
            f"/api/users?skip={offset}&limit={limit}",
            f"/api/users?page={offset // limit + 1}&size={limit}",
        ):
            try:
                data = http.json("GET", path)
                tried = True
                break
            except Exception:
                data = None
                continue
        if not tried or data is None:
            if offset == 0:
                raise RuntimeError("PasarGuard: /api/users недоступен")
            break
        batch: list = []
        if isinstance(data, list):
            batch = data
        elif isinstance(data, dict):
            batch = data.get("users") or data.get("items") or data.get("data") or []
            if isinstance(batch, dict):
                batch = batch.get("users") or []
        for u in batch:
            if isinstance(u, dict):
                nu = _pg_user_from_dict(u)
                if nu:
                    out.append(nu)
        if len(batch) < limit:
            break
        offset += limit
        if offset > 100_000:
            break
    return out


# ---------------------------------------------------------------- Remnawave

def _rw_unwrap(data: Any) -> Any:
    if isinstance(data, dict) and "response" in data:
        return data["response"]
    return data


def _rw_user_from_dict(u: dict) -> NormalizedUser | None:
    email = _norm_email(u.get("username") or u.get("email") or "")
    if not email:
        return None
    traffic = u.get("userTraffic") or u.get("user_traffic") or {}
    used = _safe_int(
        traffic.get("lifetimeUsedTrafficBytes")
        or traffic.get("lifetime_used_traffic_bytes")
        or traffic.get("usedTrafficBytes")
        or traffic.get("used_traffic_bytes")
        or u.get("lifetimeUsedTrafficBytes")
        or u.get("usedTrafficBytes"),
        0,
    )
    status = str(u.get("status") or "ACTIVE").upper()
    enabled = status in ("ACTIVE", "LIMITED", "EXPIRED")  # import expired too but disabled if DISABLED
    if status == "DISABLED":
        enabled = False
    sub = str(u.get("shortUuid") or u.get("short_uuid") or "").strip()
    if not sub:
        sub = token_from_url(str(u.get("subscriptionUrl") or u.get("subscription_url") or ""))
    return NormalizedUser(
        email=email,
        uuid=str(u.get("vlessUuid") or u.get("vless_uuid") or "").strip(),
        password=str(
            u.get("trojanPassword") or u.get("trojan_password")
            or u.get("ssPassword") or u.get("ss_password") or ""
        ).strip(),
        sub_token=sub,
        limit_gb=bytes_to_limit_gb(u.get("trafficLimitBytes") or u.get("traffic_limit_bytes")),
        expire_at=expire_from_iso(u.get("expireAt") or u.get("expire_at")),
        enabled=enabled,
        comment=str(u.get("description") or u.get("tag") or ""),
        tg_id=str(u.get("telegramId") or u.get("telegram_id") or ""),
        up=0,
        down=used,
        source="remnawave",
        extra={"status": status},
    )


def parse_remnawave_json(raw: bytes | str) -> list[NormalizedUser]:
    data = json.loads(raw if isinstance(raw, str) else raw.decode("utf-8"))
    data = _rw_unwrap(data)
    users = data
    if isinstance(data, dict):
        users = data.get("users") or data.get("items") or data.get("data") or []
        if isinstance(users, dict):
            users = users.get("users") or users.get("items") or []
    out = []
    if isinstance(users, list):
        for u in users:
            if isinstance(u, dict):
                # nested response.user
                if "username" not in u and isinstance(u.get("response"), dict):
                    u = u["response"]
                nu = _rw_user_from_dict(u)
                if nu:
                    out.append(nu)
    elif isinstance(data, dict) and data.get("username"):
        nu = _rw_user_from_dict(data)
        if nu:
            out.append(nu)
    return out


def fetch_remnawave_api(
    base_url: str,
    username: str = "",
    password: str = "",
    *,
    api_token: str = "",
    insecure: bool = False,
) -> list[NormalizedUser]:
    http = HttpClient(base_url, insecure=insecure)
    if api_token:
        http.headers["Authorization"] = f"Bearer {api_token}"
    elif username and password:
        http.headers["X-Remnawave-Client-Type"] = "browser"
        data = http.json("POST", "/api/auth/login", json_body={"username": username, "password": password})
        resp = _rw_unwrap(data) or {}
        token = resp.get("accessToken") or resp.get("access_token") or (data or {}).get("accessToken")
        if not token:
            raise RuntimeError("Remnawave: не получен accessToken")
        http.headers["Authorization"] = f"Bearer {token}"
    else:
        raise RuntimeError("Укажите логин/пароль или API token")

    out: list[NormalizedUser] = []
    size = 250
    cursor = None
    start = 0
    for _ in range(500):
        if cursor:
            path = f"/api/users?size={size}&cursor={cursor}"
        else:
            path = f"/api/users?size={size}&start={start}"
        try:
            data = http.json("GET", path)
        except Exception:
            if start == 0 and not cursor:
                data = http.json("GET", "/api/users")
            else:
                break
        resp = _rw_unwrap(data) or data
        batch: list = []
        next_cursor = None
        if isinstance(resp, list):
            batch = resp
        elif isinstance(resp, dict):
            batch = resp.get("users") or resp.get("items") or resp.get("data") or []
            next_cursor = resp.get("nextCursor") or resp.get("next_cursor")
            if isinstance(batch, dict):
                batch = batch.get("users") or []
        if not batch:
            break
        for u in batch:
            if isinstance(u, dict):
                nu = _rw_user_from_dict(u)
                if nu:
                    out.append(nu)
        if next_cursor:
            cursor = next_cursor
            continue
        if len(batch) < size:
            break
        start += len(batch)
        cursor = None
    return out


# ---------------------------------------------------------------- dispatch

def _extract_3xui_db_bytes(raw: bytes, filename: str = "") -> bytes | None:
    """Return SQLite db bytes from raw upload or from zip/tar that contains a .db."""
    if raw[:15] == b"SQLite format 3":
        return raw
    name = (filename or "").lower()
    if name.endswith(".db") and raw[:15] == b"SQLite format 3":
        return raw
    # zip / tar backup wrapping x-ui.db
    try:
        for member_name, content in _extract_archive_members(raw):
            low = member_name.lower()
            if content[:15] == b"SQLite format 3" or low.endswith(".db"):
                if content[:15] == b"SQLite format 3":
                    return content
    except Exception:
        pass
    return None


def parse_backup(source: str, raw: bytes, filename: str = "") -> list[NormalizedUser]:
    global LAST_SOURCE_META
    LAST_SOURCE_META = {}
    src = (source or "").lower().strip()
    name = (filename or "").lower()
    if src == "3xui":
        db_bytes = _extract_3xui_db_bytes(raw, filename)
        if db_bytes:
            with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
                tmp.write(db_bytes)
                path = Path(tmp.name)
            try:
                users = parse_3xui_sqlite(path)
                meta = read_3xui_sub_meta(path)
                LAST_SOURCE_META = {**(LAST_SOURCE_META or {}), "source": "3xui", **meta}
                return users
            finally:
                path.unlink(missing_ok=True)
        users = parse_3xui_json(raw)
        used = sum(int(u.up) + int(u.down) for u in users)
        LAST_SOURCE_META = {
            "source": "3xui", "clients": len(users), "traffic_bytes": used,
            "note": "JSON export — traffic only if present in file; prefer x-ui.db backup",
        }
        return users
    if src == "pasarguard":
        if name.endswith(".json") or (raw[:1] in (b"{", b"[") and b"username" in raw[:2000]):
            try:
                return parse_pasarguard_json(raw)
            except Exception:
                pass
        return parse_pasarguard_backup(raw)
    if src == "remnawave":
        return parse_remnawave_json(raw)
    raise ValueError(f"Неизвестный источник: {source}")


def fetch_api(
    source: str,
    base_url: str,
    *,
    username: str = "",
    password: str = "",
    api_token: str = "",
    insecure: bool = False,
    web_base: str = "",
) -> list[NormalizedUser]:
    global LAST_SOURCE_META
    LAST_SOURCE_META = {}
    src = (source or "").lower().strip()
    if src == "3xui":
        if not username or not password:
            raise RuntimeError("3x-ui: нужны логин и пароль")
        return fetch_3xui_api(base_url, username, password, insecure=insecure, web_base=web_base)
    if src == "pasarguard":
        return fetch_pasarguard_api(
            base_url, username, password, api_key=api_token, insecure=insecure,
        )
    if src == "remnawave":
        return fetch_remnawave_api(
            base_url, username, password, api_token=api_token, insecure=insecure,
        )
    raise ValueError(f"Неизвестный источник: {source}")
