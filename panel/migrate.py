"""Import users from X-UI, PasarGuard, or Remnawave (API or backup file).

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

import protocols as P
import xray_runtime as xray

SOURCES = ("3xui", "pasarguard", "remnawave")
SOURCE_LABELS = {
    "3xui": "X-UI",
    "pasarguard": "PasarGuard",
    "remnawave": "Remnawave",
}

# Filled by fetch/parse when source exposes sub path/port (x-ui settings).
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
    # PasarGuard/Marzban numeric user id — needed to resolve signed v2/v3 sub tokens
    source_id: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        extra = d.pop("extra", None) or {}
        # Keep inbound tags from the backup so import-from-cache still maps clients
        ibs = extra.get("inbounds")
        if ibs:
            d["inbounds"] = list(ibs)
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


# ---------------------------------------------------------------- PasarGuard / Marzban subscription tokens
# Tokens are NOT stored in the users table — they are HMAC/JWT signed with jwt.secret_key.
# File imports must recover the secret and either mint a stable token or accept any valid
# signature at lookup time (see app._find_by_token).

def _b64url_encode(raw: bytes) -> str:
    from base64 import b64encode
    return b64encode(raw, altchars=b"-_").decode("utf-8").rstrip("=")


def _b64url_decode(raw: str) -> bytes | None:
    from base64 import b64decode
    try:
        s = raw.encode("utf-8")
        return b64decode(s + b"=" * (-len(s) % 4), altchars=b"-_", validate=True)
    except Exception:
        return None


def create_pasarguard_sub_token(user_id: int | str, secret: str, *, issued_at: int | None = None) -> str:
    """Mint a modern PasarGuard v3 subscription token (HMAC-SHA256, full signature)."""
    import hmac
    import time
    from hashlib import sha256
    from math import ceil

    uid = int(user_id)
    ts = int(issued_at) if issued_at is not None else ceil(time.time())
    data_b64 = _b64url_encode(f"v3,{uid},{ts}".encode("utf-8"))
    sig = _b64url_encode(hmac.new(secret.encode("utf-8"), data_b64.encode("utf-8"), sha256).digest())
    return f"{data_b64}.{sig}"


def parse_pasarguard_sub_token(token: str, secrets: list[str]) -> dict[str, Any] | None:
    """Decode Marzban/PasarGuard subscription token with any of the given jwt secrets.

    Returns {"username": str} and/or {"user_id": int, "created_at": datetime}.
    """
    import hmac
    from datetime import datetime, timezone
    from hashlib import sha256

    tok = str(token or "").strip()
    if len(tok) < 15 or not secrets:
        return None

    def _parse_data(data_str: str) -> dict[str, Any] | None:
        parts = data_str.split(",")
        if len(parts) == 3 and parts[0] in ("v2", "v3"):
            try:
                uid = int(parts[1])
                created = int(parts[2])
            except ValueError:
                return None
            return {
                "user_id": uid,
                "created_at": datetime.fromtimestamp(created, tz=timezone.utc),
            }
        if len(parts) == 2:
            try:
                created = int(parts[1])
            except ValueError:
                return None
            return {
                "username": parts[0],
                "created_at": datetime.fromtimestamp(created, tz=timezone.utc),
            }
        return None

    # JWT form (older Marzban)
    if tok.startswith("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."):
        try:
            import jwt as pyjwt  # PyJWT optional
        except Exception:
            pyjwt = None
        if pyjwt is not None:
            for secret in secrets:
                if not secret:
                    continue
                try:
                    payload = pyjwt.decode(tok, secret, algorithms=["HS256"], leeway=5)
                except Exception:
                    continue
                if payload.get("access") != "subscription":
                    continue
                username = payload.get("sub")
                if not username:
                    continue
                try:
                    created = datetime.fromtimestamp(payload["iat"], tz=timezone.utc)
                except Exception:
                    created = None
                return {"username": str(username), "created_at": created}

    # New HMAC format: payload.signature ("." never appears in legacy tokens)
    if "." in tok:
        data_b64, _, signature = tok.rpartition(".")
        for secret in secrets:
            if not secret:
                continue
            expected = _b64url_encode(
                hmac.new(secret.encode("utf-8"), data_b64.encode("utf-8"), sha256).digest()
            )
            if not hmac.compare_digest(signature.encode("utf-8"), expected.encode("utf-8")):
                continue
            decoded = _b64url_decode(data_b64)
            if decoded is None:
                return None
            try:
                return _parse_data(decoded.decode("utf-8"))
            except Exception:
                return None
        return None

    # Legacy truncated sha256(data+secret) signature (last 10 chars)
    data_b64, signature = tok[:-10], tok[-10:]
    decoded = _b64url_decode(data_b64)
    if decoded is None:
        return None
    try:
        data_str = decoded.decode("utf-8")
    except Exception:
        return None
    for secret in secrets:
        if not secret:
            continue
        resign_b64 = _b64url_encode(sha256((data_b64 + secret).encode("utf-8")).digest())[:10]
        resign_hex = sha256((data_b64 + secret).encode("utf-8")).hexdigest()[:10]
        sig = signature.encode("utf-8")
        if hmac.compare_digest(sig, resign_b64.encode("utf-8")) or hmac.compare_digest(
            sig, resign_hex.encode("utf-8")
        ):
            return _parse_data(data_str)
    return None


def _created_at_unix(raw: Any) -> int | None:
    """Best-effort unix seconds from PasarGuard created_at / datetime / unix."""
    from math import ceil

    if raw in (None, "", 0, "0"):
        return None
    if isinstance(raw, datetime):
        return ceil(raw.timestamp())
    s = str(raw).strip()
    if not s or s.upper() == "NULL":
        return None
    if re.fullmatch(r"-?\d+(\.\d+)?", s):
        n = float(s)
        if n > 1e12:
            n /= 1000.0
        return ceil(n) if n > 0 else None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return ceil(dt.timestamp())
    except Exception:
        return None


def _assign_pg_sub_tokens(users: list[NormalizedUser], secrets: list[str]) -> None:
    """Fill missing sub_token from JWT secret (stable v3 mint using created_at)."""
    secret = next((s for s in secrets if s), "")
    if not secret:
        return
    for u in users:
        if u.sub_token:
            continue
        sid = str(u.source_id or (u.extra or {}).get("id") or "").strip()
        if not sid:
            continue
        issued = _created_at_unix((u.extra or {}).get("created_at"))
        try:
            u.sub_token = create_pasarguard_sub_token(sid, secret, issued_at=issued)
        except Exception:
            continue


def expire_from_ms(ms: Any) -> str:
    """X-UI expiryTime is ms since epoch; 0 = unlimited."""
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
        # Prefer inbound tags recorded from x-ui inbound.settings.clients
        user_tags = [t for t in ((u.extra or {}).get("inbounds") or []) if t in capable]
        use_tags = user_tags or tags
        existing = by_email.get(email)
        up_i, down_i = int(u.up or 0), int(u.down or 0)
        if existing and not update_existing:
            repaired = False
            # Re-run after a buggy import: fill traffic if panel still shows 0
            if (up_i or down_i) and xray.client_used_bytes(existing) <= 0:
                try:
                    xray.ensure_client(existing)
                    _set_imported_traffic(existing, up_i, down_i)
                    traffic_fixed += 1
                    traffic_bytes += up_i + down_i
                    repaired = True
                except Exception as exc:  # noqa: BLE001
                    errors.append(f"{email}: {exc}")
            # Always attach PasarGuard source_id so legacy signed sub tokens resolve
            if u.source_id and not existing.get("source_id"):
                existing["source_id"] = str(u.source_id)
                if u.source:
                    existing["source"] = str(u.source)
                repaired = True
            # Replace username-fallback tokens with minted PasarGuard tokens when available
            if (
                u.sub_token
                and ("." in u.sub_token or len(u.sub_token) > 40)
                and (
                    not existing.get("sub_token")
                    or str(existing.get("sub_token")) == email
                    or str(existing.get("sub_token")) == re.sub(r"[^A-Za-z0-9_-]", "", email)[:64]
                )
            ):
                existing["sub_token"] = u.sub_token
                repaired = True
            if not repaired:
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
                if u.source_id:
                    c["source_id"] = str(u.source_id)
                if u.source:
                    c["source"] = str(u.source)
                if use_tags:
                    c["inbounds"] = list(use_tags)
                xray.ensure_client(c)
                _set_imported_traffic(c, up_i, down_i)
                traffic_bytes += up_i + down_i
                xray.ensure_wg_peer(store, c)
                updated += 1
            else:
                payload: dict[str, Any] = {
                    "email": email,
                    "enabled": bool(u.enabled),
                    "inbounds": list(use_tags),
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
                if u.source_id:
                    payload["source_id"] = str(u.source_id)
                if u.source:
                    payload["source"] = str(u.source)
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
        "client_inbound_map": sum(
            1 for u in users if (u.extra or {}).get("inbounds")
        ),
    }


# ---------------------------------------------------------------- X-UI

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
    """Read subPath / subPort from an x-ui SQLite backup (settings table)."""
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
        # After a traffic reset X-UI keeps lifetime in allTime / all_time
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
            for row in conn.execute("SELECT tag, settings FROM inbounds"):
                try:
                    ib_tag = str(row["tag"] or "").strip()
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
                    if ib_tag:
                        tags = by_email[key].setdefault("_inbounds", [])
                        if ib_tag not in tags:
                            tags.append(ib_tag)
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
                ibs = [t for t in (c.get("_inbounds") or []) if t]
                if ibs:
                    u.extra["inbounds"] = ibs
                out.append(u)

        global LAST_SOURCE_META
        used = sum(int(u.up) + int(u.down) for u in out)
        structure = load_3xui_structure(conn)
        LAST_SOURCE_META = {
            **(LAST_SOURCE_META or {}),
            "source": "3xui",
            "traffic_rows": len(traffics),
            "clients": len(out),
            "traffic_bytes": used,
            "structure": structure,
            "inbounds": len(structure.get("inbound_rows") or []),
            "outbounds": len(structure.get("outbounds") or []),
            "routes": len(structure.get("routes") or []),
        }
        return out
    finally:
        conn.close()


# ---------------------------------------------------------------- X-UI structure (inbounds / outbounds / routes)

_SYSTEM_OUTBOUND_TAGS = frozenset({"direct", "block", "blocked", "blackhole", "api", "dns-out", "dns", "freedom"})
_SKIP_ROUTE_OUTBOUNDS = frozenset({"api"})


def _json_obj(raw: Any, default: Any = None) -> Any:
    if raw is None or raw == "":
        return default if default is not None else {}
    if isinstance(raw, (dict, list)):
        return raw
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8", "replace")
    try:
        return json.loads(str(raw))
    except (ValueError, TypeError):
        return default if default is not None else {}


def _headers_to_lines(headers: Any) -> str:
    if not isinstance(headers, dict):
        return ""
    lines = []
    for k, v in headers.items():
        if isinstance(v, list):
            for item in v:
                lines.append(f"{k}: {item}")
        elif v is not None and str(v) != "":
            lines.append(f"{k}: {v}")
    return "\n".join(lines)


def stream_from_xray(ss: dict | None) -> dict:
    """Convert Xray streamSettings JSON into L2X stream model."""
    ss = ss if isinstance(ss, dict) else {}
    net = str(ss.get("network") or "tcp").lower()
    if net in ("tcp", "raw", ""):
        net = "raw"
    sec = str(ss.get("security") or "none").lower() or "none"
    if sec not in ("none", "tls", "reality"):
        sec = "none"
    st = P.default_stream("none")
    st["network"] = net if net in P.NETWORKS else "raw"
    st["security"] = sec
    tcp_or_raw = ss.get("tcpSettings") if isinstance(ss.get("tcpSettings"), dict) else (
        ss.get("rawSettings") if isinstance(ss.get("rawSettings"), dict) else {}
    )
    sock = ss.get("sockopt") if isinstance(ss.get("sockopt"), dict) else {}
    st["accept_proxy_protocol"] = bool(sock.get("acceptProxyProtocol") or tcp_or_raw.get("acceptProxyProtocol"))

    # --- transports
    if net == "raw":
        raw_ss = ss.get("rawSettings") or ss.get("tcpSettings") or {}
        if not isinstance(raw_ss, dict):
            raw_ss = {}
        header = raw_ss.get("header") if isinstance(raw_ss.get("header"), dict) else {}
        htype = str(header.get("type") or "none")
        req = header.get("request") if isinstance(header.get("request"), dict) else {}
        path = req.get("path") or ["/"]
        if isinstance(path, list):
            path = path[0] if path else "/"
        hosts = (req.get("headers") or {}).get("Host") if isinstance(req.get("headers"), dict) else []
        if isinstance(hosts, str):
            hosts = [hosts]
        st["raw"].update({
            "header": "http" if htype == "http" else "none",
            "http_method": str(req.get("method") or "GET"),
            "http_path": str(path or "/"),
            "http_host": ",".join(str(h) for h in (hosts or [])),
            "http_headers": _headers_to_lines({
                k: v for k, v in (req.get("headers") or {}).items() if str(k).lower() != "host"
            }) if isinstance(req.get("headers"), dict) else "",
            "accept_proxy_protocol": bool(raw_ss.get("acceptProxyProtocol")),
        })
    elif net == "ws":
        ws = ss.get("wsSettings") or {}
        if isinstance(ws, dict):
            st["ws"].update({
                "path": str(ws.get("path") or "/"),
                "host": str(ws.get("host") or ""),
                "headers": _headers_to_lines(ws.get("headers")),
                "heartbeat": int(ws.get("heartbeatPeriod") or P.DEFAULT_WS_HEARTBEAT),
                "accept_proxy_protocol": bool(ws.get("acceptProxyProtocol")),
            })
    elif net == "grpc":
        g = ss.get("grpcSettings") or {}
        if isinstance(g, dict):
            st["grpc"].update({
                "service_name": str(g.get("serviceName") or "grpc"),
                "multi_mode": bool(g.get("multiMode")),
                "authority": str(g.get("authority") or ""),
                "idle_timeout": int(g.get("idle_timeout") or 0),
                "health_check_timeout": int(g.get("health_check_timeout") or 0),
                "permit_without_stream": bool(g.get("permit_without_stream")),
                "initial_windows_size": int(g.get("initial_windows_size") or 0),
            })
    elif net == "httpupgrade":
        h = ss.get("httpupgradeSettings") or {}
        if isinstance(h, dict):
            st["httpupgrade"].update({
                "path": str(h.get("path") or "/"),
                "host": str(h.get("host") or ""),
                "headers": _headers_to_lines(h.get("headers")),
                "accept_proxy_protocol": bool(h.get("acceptProxyProtocol")),
            })
    elif net == "xhttp":
        x = ss.get("xhttpSettings") or ss.get("splithttpSettings") or {}
        if isinstance(x, dict):
            xm = x.get("xmux") if isinstance(x.get("xmux"), dict) else {}
            st["xhttp"].update({
                "path": str(x.get("path") or "/"),
                "host": str(x.get("host") or ""),
                "mode": str(x.get("mode") or "auto"),
                "headers": _headers_to_lines(x.get("headers")),
                "x_padding_bytes": str(x.get("xPaddingBytes") or "100-1000"),
                "sc_max_buffered_posts": int(x.get("scMaxBufferedPosts") or 30),
                "sc_max_each_post_bytes": str(x.get("scMaxEachPostBytes") or "1000000"),
                "sc_min_each_post_bytes": str(x.get("scMinEachPostBytes") or "1"),
                "sc_stream_up_server_secs": str(x.get("scStreamUpServerSecs") or "20-80"),
                "sc_min_posts_interval_ms": int(x.get("scMinPostsIntervalMs") or 30),
                "no_sse_header": bool(x.get("noSSEHeader")),
                "no_grpc_header": bool(x.get("noGRPCHeader")),
                "extra": json.dumps(x.get("extra"), ensure_ascii=False) if isinstance(x.get("extra"), (dict, list)) else str(x.get("extra") or ""),
                "xmux": {
                    "enabled": bool(xm),
                    "max_concurrency": str(xm.get("maxConcurrency") or "16-32"),
                    "max_connections": int(xm.get("maxConnections") or 0),
                    "c_max_reuse_times": str(xm.get("cMaxReuseTimes") or "0"),
                    "c_max_lifetime_ms": str(xm.get("cMaxLifetimeMs") or "0"),
                    "h_max_request_times": str(xm.get("hMaxRequestTimes") or "0"),
                    "h_max_reusable_secs": str(xm.get("hMaxReusableSecs") or "0"),
                },
            })
    elif net == "kcp":
        k = ss.get("kcpSettings") or {}
        if isinstance(k, dict):
            hdr = k.get("header") if isinstance(k.get("header"), dict) else {}
            st["kcp"].update({
                "mtu": int(k.get("mtu") or 1350),
                "tti": int(k.get("tti") or 20),
                "uplink": int(k.get("uplinkCapacity") or 5),
                "downlink": int(k.get("downlinkCapacity") or 20),
                "congestion": bool(k.get("congestion")),
                "header": str(hdr.get("type") or "none"),
                "seed": str(k.get("seed") or ""),
                "read_buffer": int(k.get("readBufferSize") or 2),
                "write_buffer": int(k.get("writeBufferSize") or 2),
            })

    # --- security
    fp = "firefox"
    if sec == "tls":
        t = ss.get("tlsSettings") or {}
        if isinstance(t, dict):
            certs = t.get("certificates") or []
            cert = certs[0] if isinstance(certs, list) and certs and isinstance(certs[0], dict) else {}
            alpn = t.get("alpn") or ["h2", "http/1.1"]
            if isinstance(alpn, str):
                alpn = [a.strip() for a in alpn.split(",") if a.strip()]
            fp = str(t.get("fingerprint") or fp)
            st["tls"].update({
                "server_name": str(t.get("serverName") or ""),
                "cert_file": str(cert.get("certificateFile") or ""),
                "key_file": str(cert.get("keyFile") or ""),
                "alpn": alpn,
                "fingerprint": fp,
                "min_version": str(t.get("minVersion") or "1.2"),
                "max_version": str(t.get("maxVersion") or "1.3"),
                "cipher_suites": str(t.get("cipherSuites") or ""),
                "allow_insecure": bool(t.get("allowInsecure")),
                "reject_unknown_sni": bool(t.get("rejectUnknownSni")),
                "disable_system_root": bool(t.get("disableSystemRoot")),
                "ech_server_keys": str(t.get("echServerKeys") or ""),
            })
    elif sec == "reality":
        r = ss.get("realitySettings") or {}
        if isinstance(r, dict):
            names = r.get("serverNames") or []
            if isinstance(names, str):
                names = [n.strip() for n in names.split(",") if n.strip()]
            sids = r.get("shortIds") or [""]
            if isinstance(sids, str):
                sids = [sids]
            fp = str(r.get("fingerprint") or fp)
            priv = str(r.get("privateKey") or "")
            pub = str(r.get("publicKey") or r.get("password") or "")
            if priv and not pub:
                derived = xray.reality_public_from_private(priv)
                if derived.get("ok"):
                    pub = derived["public_key"]
            st["reality"].update({
                "show": bool(r.get("show")),
                "dest": str(r.get("dest") or r.get("target") or "www.cloudflare.com:443"),
                "xver": int(r.get("xver") or 0),
                "server_names": names or ["www.cloudflare.com"],
                "private_key": priv,
                "public_key": pub,
                "short_ids": [str(s) for s in sids] or [""],
                "fingerprint": fp,
                "spider_x": str(r.get("spiderX") or r.get("spider_x") or "/"),
                "max_time_diff": int(r.get("maxTimeDiff") or 0),
                "min_client_ver": str(r.get("minClientVer") or ""),
                "max_client_ver": str(r.get("maxClientVer") or ""),
                "mldsa65_seed": str(r.get("mldsa65Seed") or ""),
                "mldsa65_verify": str(r.get("mldsa65Verify") or ""),
            })
    st["fingerprint"] = fp

    so = ss.get("sockopt") if isinstance(ss.get("sockopt"), dict) else {}
    if so:
        st["sockopt"].update({
            "enabled": True,
            "tcp_fast_open": bool(so.get("tcpFastOpen")),
            "tcp_keep_alive_interval": int(so.get("tcpKeepAliveInterval") or 0),
            "tcp_keep_alive_idle": int(so.get("tcpKeepAliveIdle") or 0),
            "tcp_user_timeout": int(so.get("tcpUserTimeout") or 0),
            "tcp_congestion": str(so.get("tcpCongestion") or so.get("tcpcongestion") or ""),
            "tcp_window_clamp": int(so.get("tcpWindowClamp") or 0),
            "tcp_max_seg": int(so.get("tcpMaxSeg") or 0),
            "mark": int(so.get("mark") or 0),
            "tproxy": str(so.get("tproxy") or ""),
            "domain_strategy": str(so.get("domainStrategy") or "AsIs"),
            "dialer_proxy": str(so.get("dialerProxy") or ""),
            "interface": str(so.get("interface") or so.get("interfaceName") or ""),
            "penetrate": bool(so.get("penetrate")),
            "tcp_mptcp": bool(so.get("tcpMptcp")),
            "tcp_no_delay": bool(so.get("tcpNoDelay")),
            "v6only": bool(so.get("V6Only") or so.get("v6only")),
        })
    return st


def sniffing_from_xray(raw: Any) -> dict:
    sn = _json_obj(raw, {})
    if not isinstance(sn, dict):
        sn = {}
    dest = sn.get("destOverride") or sn.get("dest") or ["http", "tls", "quic"]
    if isinstance(dest, str):
        dest = [d.strip() for d in dest.split(",") if d.strip()]
    return {
        "enabled": bool(sn.get("enabled", True)),
        "dest": [str(d) for d in dest],
        "route_only": bool(sn.get("routeOnly") or sn.get("route_only")),
        "metadata_only": bool(sn.get("metadataOnly") or sn.get("metadata_only")),
        "excluded_domains": [str(d) for d in (sn.get("domainsExcluded") or sn.get("excluded_domains") or []) if d],
    }


def inbound_from_3xui_row(row: dict, *, next_id: int, used_ports: set[int]) -> tuple[dict | None, str]:
    """Build L2X inbound from an x-ui inbounds table row. Returns (ib, warning)."""
    proto = str(row.get("protocol") or "").lower().strip()
    if proto == "dokodemo":
        proto = "dokodemo-door"
    if proto not in P.ALL_PROTOCOLS:
        return None, f"протокол {proto or '?'} не поддерживается"
    tag = str(row.get("tag") or "").strip() or f"{proto}-{next_id}"
    if not xray.TAG_RE.match(tag):
        tag = re.sub(r"[^A-Za-z0-9_.-]", "_", tag)[:40] or f"{proto}-{next_id}"
    settings_raw = _json_obj(row.get("settings"), {})
    if not isinstance(settings_raw, dict):
        settings_raw = {}
    stream_raw = _json_obj(row.get("stream_settings") or row.get("streamsettings") or row.get("streamSettings"), {})
    if not isinstance(stream_raw, dict):
        stream_raw = {}

    ib = P.default_inbound(proto, 10000, tag)
    ib["id"] = next_id
    ib["remark"] = str(row.get("remark") or tag)
    ib["enabled"] = bool(row.get("enable", row.get("enabled", True)))
    if isinstance(ib["enabled"], str):
        ib["enabled"] = ib["enabled"].lower() not in ("0", "false", "no")
    ib["expire_at"] = expire_from_ms(row.get("expiry_time") or row.get("expirytime") or row.get("expiryTime"))
    total = _safe_int(row.get("total"), 0)
    ib["total_gb"] = bytes_to_limit_gb(total) if total > 1024 else _safe_float(total, 0)
    reset = str(row.get("traffic_reset") or row.get("trafficreset") or "never")
    ib["traffic_reset"] = reset if reset in P.TRAFFIC_RESETS else "never"
    up = _safe_int(row.get("up"), 0)
    down = _safe_int(row.get("down"), 0)
    ib["traffic"] = {"up": up, "down": down, "last_up": 0, "last_down": 0}

    listen = str(row.get("listen") or "").strip()
    port = _safe_int(row.get("port"), 0)
    # Source public ports → L2X: reserved 22/80/443 or taken → free internal + nginx/direct remap
    want_direct = listen in ("", "0.0.0.0", "::", "[::]")
    warn = ""
    if port <= 0 or xray.port_forbidden_reason(port) or port in used_ports:
        new_port = next(
            (p for p in range(10000, 65535) if p not in used_ports and not xray.port_forbidden_reason(p)),
            0,
        )
        if not new_port:
            return None, f"нет свободного порта для {tag}"
        if port:
            warn = f"{tag}: порт {port} занят/запрещён → {new_port}"
        port = new_port
        # Keep reachable via nginx :443 when possible
        want_direct = False
    ib["port"] = port
    ib["direct"] = want_direct
    ib["listen"] = P.inbound_listen(ib)
    used_ports.add(port)

    # Protocol settings (without clients — they live in store.clients)
    s = ib["settings"]
    if proto == "vless":
        s["decryption"] = str(settings_raw.get("decryption") or "none")
        s["encryption"] = str(settings_raw.get("encryption") or "none")
        clients = settings_raw.get("clients") or []
        flow = ""
        if isinstance(clients, list):
            for c in clients:
                if isinstance(c, dict) and c.get("flow"):
                    flow = str(c["flow"])
                    break
        s["flow"] = flow
    elif proto == "shadowsocks":
        s["method"] = str(settings_raw.get("method") or s.get("method") or "2022-blake3-aes-256-gcm")
        s["password"] = str(settings_raw.get("password") or s.get("password") or "")
        s["network"] = str(settings_raw.get("network") or "tcp,udp")
    elif proto == "wireguard":
        s["secret_key"] = str(settings_raw.get("secretKey") or "")
        s["mtu"] = int(settings_raw.get("mtu") or 1420)
    elif proto in ("socks", "http"):
        s["auth"] = "noauth" if settings_raw.get("auth") == "noauth" else "password"
        s["udp"] = bool(settings_raw.get("udp", True))
    elif proto == "dokodemo-door":
        s["address"] = str(settings_raw.get("address") or "1.1.1.1")
        s["port"] = int(settings_raw.get("port") or 53)
        s["network"] = str(settings_raw.get("network") or "tcp,udp")
        s["follow_redirect"] = bool(settings_raw.get("followRedirect"))

    fbs = []
    for fb in settings_raw.get("fallbacks") or []:
        if not isinstance(fb, dict):
            continue
        dest = str(fb.get("dest") or "").strip()
        if not dest:
            continue
        fbs.append({
            "name": str(fb.get("name") or ""),
            "alpn": str(fb.get("alpn") or ""),
            "path": str(fb.get("path") or ""),
            "dest": dest,
            "xver": _safe_int(fb.get("xver"), 0),
        })
    ib["fallbacks"] = fbs

    ib["stream"] = stream_from_xray(stream_raw)
    ib["sniffing"] = sniffing_from_xray(row.get("sniffing"))
    # SNI / share host for nginx front
    if not want_direct:
        names = P.front_snis(ib)
        if names and not _is_ip_like(names[0]):
            ib["share_host"] = names[0]
    P.ensure_inbound_shape(ib)
    xray.ensure_inbound_keys(ib)
    return ib, warn


def _is_ip_like(value: str) -> bool:
    v = (value or "").strip().strip("[]")
    if not v:
        return False
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", v):
        return True
    return ":" in v and all(c in "0123456789abcdefABCDEF:" for c in v)


def outbound_from_xray(ob: dict) -> dict | None:
    """Map a non-system Xray outbound into outbounds_custom entry."""
    if not isinstance(ob, dict):
        return None
    tag = str(ob.get("tag") or "").strip()
    proto = str(ob.get("protocol") or "").strip().lower()
    if not tag or not proto:
        return None
    if tag.lower() in _SYSTEM_OUTBOUND_TAGS or proto in ("freedom", "blackhole", "dns", "dokodemo-door"):
        return None
    if not xray.TAG_RE.match(tag):
        tag = re.sub(r"[^A-Za-z0-9_.-]", "_", tag)[:40]
    cfg = json.loads(json.dumps(ob))
    cfg["tag"] = tag
    return {
        "tag": tag,
        "enabled": True,
        "kind": proto,
        "remark": tag,
        "country": "",
        "info": _outbound_info_simple(cfg),
        "in_sub": True,
        "config": cfg,
    }


def _outbound_info_simple(config: dict) -> str:
    proto = config.get("protocol") or "?"
    s = config.get("settings") or {}
    srv = (s.get("vnext") or s.get("servers") or [None])[0]
    if isinstance(srv, dict) and srv.get("address"):
        return f"{proto} {srv['address']}:{srv.get('port', '')}"
    return proto


def route_from_xray_rule(rule: dict, *, idx: int) -> dict | None:
    if not isinstance(rule, dict):
        return None
    if rule.get("type") and rule.get("type") != "field":
        return None
    inbound = rule.get("inboundTag") or []
    if isinstance(inbound, str):
        inbound = [inbound]
    inbound = [str(x) for x in inbound if x]
    if inbound and set(inbound) <= _SKIP_ROUTE_OUTBOUNDS:
        return None
    outbound = str(rule.get("outboundTag") or rule.get("balancerTag") or "").strip()
    if not outbound or outbound.lower() in ("api",):
        return None
    # Skip the universal final catch-all — L2X already appends network→direct
    domain = rule.get("domain") or []
    ip = rule.get("ip") or []
    user = rule.get("user") or []
    source = rule.get("source") or []
    protocol = rule.get("protocol") or []
    network = str(rule.get("network") or "")
    port = str(rule.get("port") or "")
    if isinstance(domain, str):
        domain = [domain]
    if isinstance(ip, str):
        ip = [ip]
    if isinstance(user, str):
        user = [user]
    if isinstance(source, str):
        source = [source]
    if isinstance(protocol, str):
        protocol = [protocol]
    if (
        not domain and not ip and not user and not source and not protocol
        and not inbound and not port
        and network in ("tcp,udp", "tcp", "udp", "")
        and outbound in ("direct", "block")
    ):
        return None
    name = str(rule.get("ruleTag") or f"x3-{idx}")
    name = re.sub(r"[^A-Za-z0-9_.-]", "_", name)[:64] or f"x3-{idx}"
    return {
        "name": name,
        "enabled": True,
        "outbound": outbound,
        "domain": [str(x) for x in domain if x],
        "ip": [str(x) for x in ip if x],
        "user": [str(x) for x in user if x],
        "source": [str(x) for x in source if x],
        "protocol": [str(x) for x in protocol if x],
        "inbound_tags": inbound,
        "network": network if network not in ("tcp,udp",) else "",
        "port": port,
    }


def _read_xray_template(conn: sqlite3.Connection) -> dict:
    """Unwrap x-ui xrayTemplateConfig (raw or nested xraySetting)."""
    try:
        rows = conn.execute("SELECT key, value FROM settings")
    except sqlite3.Error:
        try:
            rows = conn.execute('SELECT "key", value FROM settings')
        except sqlite3.Error:
            return {}
    kv = {}
    for row in rows:
        try:
            kv[str(row["key"])] = row["value"]
        except (KeyError, IndexError):
            keys = list(row.keys())
            if len(keys) >= 2:
                kv[str(row[keys[0]])] = row[keys[1]]
    raw = kv.get("xrayTemplateConfig") or kv.get("xray_template_config") or ""
    data = _json_obj(raw, {})
    if not isinstance(data, dict):
        return {}
    if isinstance(data.get("xraySetting"), dict):
        return data["xraySetting"]
    if isinstance(data.get("xraySettings"), dict):
        return data["xraySettings"]
    return data


def load_3xui_structure(conn: sqlite3.Connection) -> dict[str, Any]:
    """Parse inbounds + template outbounds/routes from an open x-ui SQLite connection."""
    inbounds_rows: list[dict] = []
    try:
        for row in conn.execute("SELECT * FROM inbounds"):
            inbounds_rows.append(_row_dict(row))
    except sqlite3.Error:
        pass
    tmpl = _read_xray_template(conn)
    outbounds = []
    for ob in tmpl.get("outbounds") or []:
        mapped = outbound_from_xray(ob)
        if mapped:
            outbounds.append(mapped)
    routes = []
    routing = tmpl.get("routing") if isinstance(tmpl.get("routing"), dict) else {}
    for i, rule in enumerate(routing.get("rules") or []):
        mapped = route_from_xray_rule(rule, idx=i + 1)
        if mapped:
            routes.append(mapped)
    return {
        "inbound_rows": inbounds_rows,
        "outbounds": outbounds,
        "routes": routes,
        "routing_domain_strategy": str(routing.get("domainStrategy") or ""),
    }


def apply_3xui_structure(
    store: dict,
    structure: dict | None,
    *,
    restore_inbounds: bool = True,
    restore_outbounds: bool = True,
    restore_routes: bool = True,
) -> dict[str, Any]:
    """Create/update L2X inbounds, custom outbounds and routes from x-ui backup data."""
    structure = structure or {}
    report: dict[str, Any] = {
        "inbounds_created": 0, "inbounds_updated": 0, "inbounds_skipped": 0,
        "outbounds_created": 0, "outbounds_updated": 0, "outbounds_skipped": 0,
        "routes_created": 0, "routes_updated": 0, "routes_skipped": 0,
        "warnings": [], "inbound_tags": [],
    }
    xray.ensure_inbounds(store)
    used_ports = {int(i.get("port") or 0) for i in store.get("inbounds") or []}
    next_id = max([int(i.get("id") or 0) for i in store.get("inbounds") or []] + [0]) + 1
    tag_map: dict[str, str] = {}  # original → final tag (usually same)

    if restore_inbounds:
        for row in structure.get("inbound_rows") or []:
            tag = str(row.get("tag") or "").strip()
            existing = xray.inbound_by_tag(store, tag) if tag else None
            if existing and existing.get("_system"):
                report["inbounds_skipped"] += 1
                report["warnings"].append(f"{tag}: систем inbound — пропуск")
                continue
            ib, warn = inbound_from_3xui_row(
                row,
                next_id=(int(existing["id"]) if existing else next_id),
                used_ports=used_ports - ({int(existing.get("port") or 0)} if existing else set()),
            )
            if warn:
                report["warnings"].append(warn)
            if not ib:
                report["inbounds_skipped"] += 1
                continue
            used_ports.add(int(ib["port"]))
            tag_map[str(row.get("tag") or ib["tag"])] = ib["tag"]
            report["inbound_tags"].append(ib["tag"])
            if existing:
                # Keep id; replace config fields
                keep_id = existing["id"]
                existing.clear()
                existing.update(ib)
                existing["id"] = keep_id
                report["inbounds_updated"] += 1
            else:
                store.setdefault("inbounds", []).append(ib)
                next_id = max(next_id, int(ib["id"]) + 1)
                report["inbounds_created"] += 1

    if restore_outbounds:
        customs = store.setdefault("outbounds_custom", [])
        by_tag = {str(o.get("tag") or ""): o for o in customs}
        for ob in structure.get("outbounds") or []:
            tag = ob["tag"]
            if tag in ("direct", "block"):
                report["outbounds_skipped"] += 1
                continue
            if tag in by_tag:
                cur = by_tag[tag]
                if cur.get("kind") == "node":
                    report["outbounds_skipped"] += 1
                    report["warnings"].append(f"{tag}: node outbound — не перезаписываем")
                    continue
                cur.update({k: v for k, v in ob.items() if k != "tag"})
                cur["tag"] = tag
                report["outbounds_updated"] += 1
            else:
                customs.append(ob)
                by_tag[tag] = ob
                report["outbounds_created"] += 1

    if restore_routes:
        routes = store.setdefault("routes", [])
        by_name = {str(r.get("name") or ""): r for r in routes}
        for rule in structure.get("routes") or []:
            # Remap inbound tags if needed
            rule = dict(rule)
            rule["inbound_tags"] = [tag_map.get(t, t) for t in (rule.get("inbound_tags") or [])]
            name = rule["name"]
            if name in by_name:
                by_name[name].update(rule)
                report["routes_updated"] += 1
            else:
                # ensure unique name
                base = name
                n = 2
                while name in by_name:
                    name = f"{base}-{n}"
                    n += 1
                rule["name"] = name
                routes.append(rule)
                by_name[name] = rule
                report["routes_created"] += 1

    return report


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
        raise RuntimeError(f"X-UI login failed: {last_err or 'unknown'}")

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
    raise RuntimeError("X-UI: не удалось получить клиентов (getDb / inbounds/list)")


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
    source_id = str(u.get("id") if u.get("id") is not None else "").strip()
    created_raw = u.get("created_at") or u.get("createdAt")
    # File dumps have no subscription_url (signed URL is computed by PasarGuard).
    # Leave sub_token empty here — parse_pasarguard_backup mints a v3 token from jwt secret.
    # Username fallback only if minting is impossible (no secret / no id).
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
        source_id=source_id,
        extra={"status": status, "id": u.get("id"), "created_at": created_raw},
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
        "expire": _sql_unquote(rec_raw.get("expire") or rec_raw.get("expire_at")),
        "expire_at": _sql_unquote(rec_raw.get("expire_at") or rec_raw.get("expire")),
        "created_at": _sql_unquote(rec_raw.get("created_at")),
        "status": _sql_unquote(rec_raw.get("status")),
        "note": _sql_unquote(rec_raw.get("note")),
        "telegram_id": _sql_unquote(rec_raw.get("telegram_id")),
        "proxy_settings": _sql_unquote(rec_raw.get("proxy_settings")),
        "proxies": _sql_unquote(rec_raw.get("proxies")),
        "subscription_url": _sql_unquote(rec_raw.get("subscription_url") or ""),
        "subscription_token": _sql_unquote(rec_raw.get("subscription_token") or ""),
    }


_COPY_BLOCK_RE = re.compile(
    r"COPY\s+(?:(?P<schema>[\"\w]+)\.)?(?P<table>[\"\w]+)\s*\((?P<cols>[^)]+)\)\s+FROM\s+stdin\s*;\r?\n"
    r"(?P<body>.*?)(?<!\S)\\\.\s*(?:\r?\n|$)",
    re.I | re.S,
)


def _iter_sql_copy_tables(text: str):
    for block in _COPY_BLOCK_RE.finditer(text):
        table = block.group("table").strip().strip('"')
        cols = [c.strip().strip('"') for c in block.group("cols").split(",")]
        body = block.group("body") or ""
        yield table, cols, body


def extract_pasarguard_meta_from_sql(text: str) -> dict[str, Any]:
    """Pull jwt.secret_key (+ optional sub path hints) from a PasarGuard/Marzban SQL dump."""
    secrets: list[str] = []
    path = ""
    for table, cols, body in _iter_sql_copy_tables(text):
        low = table.lower()
        if low == "jwt":
            for line in body.splitlines():
                if not line or line == r"\.":
                    continue
                raw_fields = line.split("\t")
                if len(raw_fields) < len(cols):
                    continue
                fields = [_parse_pg_copy_field(f) for f in raw_fields[: len(cols)]]
                rec = {cols[i]: fields[i] for i in range(len(cols))}
                key = str(rec.get("secret_key") or "").strip()
                if key and key not in secrets:
                    secrets.append(key)
        elif low == "settings" and not path:
            for line in body.splitlines():
                if not line or line == r"\.":
                    continue
                raw_fields = line.split("\t")
                if len(raw_fields) < len(cols):
                    continue
                fields = [_parse_pg_copy_field(f) for f in raw_fields[: len(cols)]]
                rec = {cols[i]: fields[i] for i in range(len(cols))}
                blob = rec.get("subscription")
                if isinstance(blob, str) and blob.strip().startswith("{"):
                    try:
                        sub = json.loads(blob)
                    except Exception:
                        sub = {}
                elif isinstance(blob, dict):
                    sub = blob
                else:
                    sub = {}
                # url_prefix may be full URL; path segment after host is rarely useful.
                # Default PasarGuard path is "sub" (same as L2X) — leave empty unless obvious.
                prefix = str(sub.get("url_prefix") or "").strip()
                if prefix and "://" not in prefix:
                    path = re.sub(r"[^A-Za-z0-9_-]", "", prefix.strip("/").split("/")[0] or "")
                break
    return {"jwt_secrets": secrets, "path": path}


def extract_pasarguard_meta_from_sqlite(path: Path) -> dict[str, Any]:
    secrets: list[str] = []
    conn = sqlite3.connect(str(path))
    try:
        tables = {
            r[0].lower()
            for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
        if "jwt" in tables:
            cols = {r[1].lower() for r in conn.execute("PRAGMA table_info(jwt)").fetchall()}
            if "secret_key" in cols:
                for row in conn.execute("SELECT secret_key FROM jwt"):
                    key = str(row[0] or "").strip()
                    if key and key not in secrets:
                        secrets.append(key)
    finally:
        conn.close()
    return {"jwt_secrets": secrets}


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
    for table, cols, body in _iter_sql_copy_tables(text):
        if table.lower() != "users":
            continue
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


def _finalize_pasarguard_users(
    users: list[NormalizedUser],
    *,
    jwt_secrets: list[str] | None = None,
    path: str = "",
    note: str = "",
    port: int = 0,
    tls: bool = False,
) -> list[NormalizedUser]:
    global LAST_SOURCE_META
    secrets = [s for s in (jwt_secrets or []) if s]
    _assign_pg_sub_tokens(users, secrets)
    # Last resort: username-shaped token so the client is still reachable somehow
    for u in users:
        if not u.sub_token:
            u.sub_token = re.sub(r"[^A-Za-z0-9_-]", "", u.email)[:64] or u.email
    LAST_SOURCE_META = {
        **(LAST_SOURCE_META or {}),
        "source": "pasarguard",
        "clients": len(users),
        "jwt_secrets": secrets,
        "path": path or "",
        "port": int(port or 0) or None,
        "tls": bool(tls),
        "sub_tokens_minted": sum(1 for u in users if u.sub_token and "." in u.sub_token),
        "note": note or (
            "JWT secret imported — старые PasarGuard-ссылки принимаются панелью"
            if secrets else
            "JWT secret не найден в бэкапе — токены подписки не восстановить из файла; используйте API"
        ),
    }
    return users


def parse_pasarguard_backup(raw: bytes) -> list[NormalizedUser]:
    members = _extract_archive_members(raw)
    ordered = sorted(members, key=lambda it: (_pg_member_priority(it[0], it[1]), it[0].lower()))
    # Collect jwt secrets from any dump member (may live in a different file than users)
    all_secrets: list[str] = []
    path_hint = ""
    port_hint = 0
    tls_hint = False
    for name, content in ordered:
        low = name.lower()
        try:
            if content[:15] == b"SQLite format 3" or low.endswith((".db", ".sqlite", ".sqlite3")):
                with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
                    tmp.write(content)
                    path = Path(tmp.name)
                try:
                    meta = extract_pasarguard_meta_from_sqlite(path)
                finally:
                    path.unlink(missing_ok=True)
                for s in meta.get("jwt_secrets") or []:
                    if s not in all_secrets:
                        all_secrets.append(s)
            elif low.endswith(".sql") or _pg_looks_like_sql(content):
                meta = extract_pasarguard_meta_from_sql(content.decode("utf-8", "replace"))
                for s in meta.get("jwt_secrets") or []:
                    if s not in all_secrets:
                        all_secrets.append(s)
                if not path_hint and meta.get("path"):
                    path_hint = str(meta["path"])
            elif low.endswith(".env") or low.rsplit("/", 1)[-1] == ".env":
                # SUBSCRIPTION_PATH / XRAY_SUBSCRIPTION_PATH hints
                text = content.decode("utf-8", "replace")
                for key in ("XRAY_SUBSCRIPTION_PATH", "SUBSCRIPTION_PATH"):
                    m = re.search(rf"(?m)^\s*{key}\s*=\s*[\"']?([^\"'\s#]+)", text)
                    if m and not path_hint:
                        path_hint = re.sub(r"[^A-Za-z0-9_-]", "", m.group(1).strip("/"))
                if not port_hint:
                    m = re.search(r"(?m)^\s*UVICORN_PORT\s*=\s*[\"']?(\d+)", text)
                    if m:
                        port_hint = int(m.group(1))
                        tls_hint = bool(re.search(r"(?m)^\s*UVICORN_SSL_CERTFILE\s*=\s*[\"']?\S", text))
        except Exception:
            continue

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
                    if not all_secrets:
                        meta = extract_pasarguard_meta_from_sqlite(path)
                        all_secrets.extend(meta.get("jwt_secrets") or [])
                    users = _parse_pg_sqlite(path)
                finally:
                    path.unlink(missing_ok=True)
                if users:
                    return _finalize_pasarguard_users(
                        users, jwt_secrets=all_secrets, path=path_hint, port=port_hint, tls=tls_hint
                    )
                continue
            if low.endswith(".sql") or _pg_looks_like_sql(content):
                text = content.decode("utf-8", "replace")
                if not all_secrets:
                    meta = extract_pasarguard_meta_from_sql(text)
                    all_secrets.extend(meta.get("jwt_secrets") or [])
                    if not path_hint and meta.get("path"):
                        path_hint = str(meta["path"])
                users = _parse_users_sql_dump(text)
                if users:
                    return _finalize_pasarguard_users(
                        users, jwt_secrets=all_secrets, path=path_hint, port=port_hint, tls=tls_hint
                    )
                continue
            if low.endswith(".json") or b'"username"' in content[:4000]:
                users = parse_pasarguard_json(content)
                if users:
                    return _finalize_pasarguard_users(
                        users, jwt_secrets=all_secrets, path=path_hint, port=port_hint, tls=tls_hint
                    )
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{name}: {exc}")
            continue
    hint = ("; ".join(errors[:3]) + " — ") if errors else ""
    raise RuntimeError(
        "PasarGuard: не удалось разобрать бэкап. "
        f"{hint}"
        "Нужен zip/tar.gz с db.sqlite3 или SQL dump (pg_dump/mysqldump), "
        "либо JSON users."
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
            raise RuntimeError("X-UI: нужны логин и пароль")
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
