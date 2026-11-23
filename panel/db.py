"""PostgreSQL persistence for L2X panel store.

Env: ``L2XPANEL_DATABASE_URL`` = ``postgresql://user:pass@host:5432/l2xpanel``

When unset or unreachable, callers fall back to store.json.
Schema:
  - panel_store(id, data jsonb) — full document (primary)
  - groups / clients / client_hwids / client_traffic — relational hot path
  - settings_versions — history snapshots (replaces files over time)
"""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse, unquote

DATABASE_URL = (os.environ.get("L2XPANEL_DATABASE_URL") or "").strip()
# blob = only panel_store jsonb (cheap); full = also rewrite clients/groups tables (heavy);
# off = ignore DATABASE_URL entirely.
PG_MODE = (os.environ.get("L2XPANEL_PG_MODE") or "blob").strip().lower()
_LOCK = threading.RLock()
_INIT_DONE = False
_ENABLED: bool | None = None
_LAST_ERR = ""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def enabled() -> bool:
    """True when DATABASE_URL is set, mode != off, and connection/schema are ready."""
    global _ENABLED, _LAST_ERR
    if not DATABASE_URL or PG_MODE in ("off", "0", "false", "no"):
        _ENABLED = False
        return False
    if _ENABLED is True:
        return True
    try:
        init_schema()
        _ENABLED = True
        _LAST_ERR = ""
        return True
    except Exception as exc:  # noqa: BLE001
        _ENABLED = False
        _LAST_ERR = str(exc)
        return False


def relational_sync_enabled() -> bool:
    """Full clients/groups table rewrite — expensive; only for large dedicated DB hosts."""
    return enabled() and PG_MODE in ("full", "relational", "all")


def last_error() -> str:
    return _LAST_ERR


def _connect():
    """Open a psycopg connection (v3 preferred, v2 fallback)."""
    try:
        import psycopg
        from psycopg.rows import dict_row
        conn = psycopg.connect(DATABASE_URL, row_factory=dict_row, autocommit=False)
        return conn, "psycopg3"
    except ImportError:
        pass
    import psycopg2
    import psycopg2.extras
    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = False
    return conn, "psycopg2"


def _execute(conn, flavor: str, sql: str, params: tuple | dict | None = None):
    cur = conn.cursor()
    cur.execute(sql, params)
    return cur


def _json_dump(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), default=str)


def init_schema() -> None:
    global _INIT_DONE
    with _LOCK:
        if _INIT_DONE and _ENABLED:
            return
        conn, flavor = _connect()
        try:
            stmts = [
                """
                CREATE TABLE IF NOT EXISTS panel_store (
                    id INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
                    data JSONB NOT NULL DEFAULT '{}'::jsonb,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS groups (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL DEFAULT '',
                    comment TEXT NOT NULL DEFAULT '',
                    core_mode TEXT NOT NULL DEFAULT 'all',
                    cores JSONB NOT NULL DEFAULT '[]'::jsonb,
                    ib_mode TEXT NOT NULL DEFAULT 'all',
                    inbounds JSONB NOT NULL DEFAULT '[]'::jsonb,
                    extra JSONB NOT NULL DEFAULT '{}'::jsonb,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS clients (
                    email TEXT PRIMARY KEY,
                    uuid TEXT NOT NULL DEFAULT '',
                    password TEXT NOT NULL DEFAULT '',
                    sub_token TEXT NOT NULL DEFAULT '',
                    enabled BOOLEAN NOT NULL DEFAULT TRUE,
                    group_id TEXT NOT NULL DEFAULT '',
                    comment TEXT NOT NULL DEFAULT '',
                    admin TEXT NOT NULL DEFAULT '',
                    limit_gb DOUBLE PRECISION NOT NULL DEFAULT 0,
                    daily_limit_gb DOUBLE PRECISION NOT NULL DEFAULT 0,
                    limit_ip INT NOT NULL DEFAULT 0,
                    limit_hwid INT NOT NULL DEFAULT 0,
                    expire_at TEXT NOT NULL DEFAULT '',
                    start_on_first_use BOOLEAN NOT NULL DEFAULT FALSE,
                    duration_days INT NOT NULL DEFAULT 0,
                    reset_period TEXT NOT NULL DEFAULT '',
                    renew_on_reset BOOLEAN NOT NULL DEFAULT FALSE,
                    on_expire TEXT NOT NULL DEFAULT 'block',
                    on_quota TEXT NOT NULL DEFAULT 'block',
                    sub_enabled BOOLEAN NOT NULL DEFAULT TRUE,
                    tg_id TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL DEFAULT '',
                    last_online TEXT NOT NULL DEFAULT '',
                    data JSONB NOT NULL DEFAULT '{}'::jsonb
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS client_hwids (
                    email TEXT NOT NULL REFERENCES clients(email) ON DELETE CASCADE,
                    hash TEXT NOT NULL,
                    first_seen TEXT NOT NULL DEFAULT '',
                    last_seen TEXT NOT NULL DEFAULT '',
                    os TEXT NOT NULL DEFAULT '',
                    os_ver TEXT NOT NULL DEFAULT '',
                    model TEXT NOT NULL DEFAULT '',
                    kind TEXT NOT NULL DEFAULT '',
                    raw JSONB NOT NULL DEFAULT '{}'::jsonb,
                    PRIMARY KEY (email, hash)
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS client_traffic (
                    email TEXT PRIMARY KEY REFERENCES clients(email) ON DELETE CASCADE,
                    up BIGINT NOT NULL DEFAULT 0,
                    down BIGINT NOT NULL DEFAULT 0,
                    by_email JSONB NOT NULL DEFAULT '{}'::jsonb,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS settings_versions (
                    id TEXT PRIMARY KEY,
                    at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    username TEXT NOT NULL DEFAULT '',
                    ip TEXT NOT NULL DEFAULT '',
                    section TEXT NOT NULL DEFAULT '',
                    note TEXT NOT NULL DEFAULT '',
                    changes INT NOT NULL DEFAULT 0,
                    summary TEXT NOT NULL DEFAULT '',
                    state JSONB NOT NULL DEFAULT '{}'::jsonb
                )
                """,
                "CREATE INDEX IF NOT EXISTS idx_clients_group ON clients(group_id)",
                "CREATE INDEX IF NOT EXISTS idx_clients_enabled ON clients(enabled)",
                "CREATE INDEX IF NOT EXISTS idx_clients_expire ON clients(expire_at)",
                "CREATE INDEX IF NOT EXISTS idx_hwids_hash ON client_hwids(hash)",
                "CREATE INDEX IF NOT EXISTS idx_settings_versions_at ON settings_versions(at DESC)",
            ]
            cur = conn.cursor()
            for sql in stmts:
                cur.execute(sql)
            cur.execute(
                "INSERT INTO panel_store (id, data) VALUES (1, '{}'::jsonb) "
                "ON CONFLICT (id) DO NOTHING"
            )
            conn.commit()
            _INIT_DONE = True
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


def load_store_blob() -> dict | None:
    """Return full store document from panel_store, or None if empty/missing."""
    if not DATABASE_URL:
        return None
    init_schema()
    conn, _flavor = _connect()
    try:
        cur = conn.cursor()
        cur.execute("SELECT data FROM panel_store WHERE id = 1")
        row = cur.fetchone()
        if not row:
            return None
        data = row["data"] if isinstance(row, dict) else row[0]
        if isinstance(data, str):
            data = json.loads(data)
        if not isinstance(data, dict) or not data:
            return None
        # Relational overlay only in full mode (blob is enough for light VPS)
        if relational_sync_enabled():
            try:
                rel_clients = _fetch_clients(conn)
                rel_groups = _fetch_groups(conn)
                if rel_clients:
                    data["clients"] = rel_clients
                if rel_groups:
                    data["groups"] = rel_groups
            except Exception:
                pass
        return data
    finally:
        conn.close()


def save_store_blob(data: dict) -> None:
    if not DATABASE_URL:
        raise RuntimeError("L2XPANEL_DATABASE_URL not set")
    init_schema()
    conn, _flavor = _connect()
    try:
        cur = conn.cursor()
        payload = _json_dump(data)
        cur.execute(
            "INSERT INTO panel_store (id, data, updated_at) VALUES (1, %s::jsonb, NOW()) "
            "ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, updated_at = NOW()",
            (payload,),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _fetch_groups(conn) -> list[dict]:
    cur = conn.cursor()
    cur.execute(
        "SELECT id, name, comment, core_mode, cores, ib_mode, inbounds, extra FROM groups ORDER BY name"
    )
    out = []
    for row in cur.fetchall() or []:
        r = dict(row) if not isinstance(row, dict) else row
        g = {
            "id": str(r.get("id") or ""),
            "name": str(r.get("name") or ""),
            "comment": str(r.get("comment") or ""),
            "core_mode": str(r.get("core_mode") or "all"),
            "cores": _as_list(r.get("cores")),
            "ib_mode": str(r.get("ib_mode") or "all"),
            "inbounds": _as_list(r.get("inbounds")),
        }
        extra = _as_dict(r.get("extra"))
        for k, v in extra.items():
            if k not in g:
                g[k] = v
        out.append(g)
    return out


def _fetch_clients(conn) -> list[dict]:
    cur = conn.cursor()
    cur.execute("SELECT * FROM clients")
    rows = cur.fetchall() or []
    # hwids
    cur.execute("SELECT * FROM client_hwids")
    hw_rows = cur.fetchall() or []
    hw_by: dict[str, list] = {}
    for h in hw_rows:
        hh = dict(h) if not isinstance(h, dict) else h
        email = str(hh.get("email") or "")
        entry = {
            "hash": str(hh.get("hash") or ""),
            "first_seen": str(hh.get("first_seen") or ""),
            "last_seen": str(hh.get("last_seen") or ""),
            "os": str(hh.get("os") or ""),
            "os_ver": str(hh.get("os_ver") or ""),
            "model": str(hh.get("model") or ""),
            "kind": str(hh.get("kind") or ""),
        }
        raw = _as_dict(hh.get("raw"))
        if raw:
            entry["raw"] = raw
            entry.update({k: v for k, v in raw.items() if k not in entry})
        hw_by.setdefault(email, []).append(entry)
    # traffic
    cur.execute("SELECT * FROM client_traffic")
    tr_rows = cur.fetchall() or []
    tr_by: dict[str, dict] = {}
    for t in tr_rows:
        tt = dict(t) if not isinstance(t, dict) else t
        tr_by[str(tt.get("email") or "")] = {
            "up": int(tt.get("up") or 0),
            "down": int(tt.get("down") or 0),
            "by_email": _as_dict(tt.get("by_email")),
        }
    out = []
    for row in rows:
        r = dict(row) if not isinstance(row, dict) else row
        email = str(r.get("email") or "")
        c = _as_dict(r.get("data"))
        # overlay columns
        c["email"] = email
        c["uuid"] = str(r.get("uuid") or c.get("uuid") or "")
        c["password"] = str(r.get("password") or c.get("password") or "")
        c["sub_token"] = str(r.get("sub_token") or c.get("sub_token") or "")
        c["enabled"] = bool(r.get("enabled") if r.get("enabled") is not None else c.get("enabled", True))
        c["group_id"] = str(r.get("group_id") or c.get("group_id") or "")
        c["comment"] = str(r.get("comment") or c.get("comment") or "")
        c["admin"] = str(r.get("admin") or c.get("admin") or "")
        c["limit_gb"] = float(r.get("limit_gb") or c.get("limit_gb") or 0)
        c["daily_limit_gb"] = float(r.get("daily_limit_gb") or c.get("daily_limit_gb") or 0)
        c["limit_ip"] = int(r.get("limit_ip") or c.get("limit_ip") or 0)
        c["limit_hwid"] = int(r.get("limit_hwid") or c.get("limit_hwid") or 0)
        c["expire_at"] = str(r.get("expire_at") or c.get("expire_at") or "")
        c["start_on_first_use"] = bool(r.get("start_on_first_use") or c.get("start_on_first_use"))
        c["duration_days"] = int(r.get("duration_days") or c.get("duration_days") or 0)
        c["reset_period"] = str(r.get("reset_period") or c.get("reset_period") or "")
        c["renew_on_reset"] = bool(r.get("renew_on_reset") or c.get("renew_on_reset"))
        c["on_expire"] = str(r.get("on_expire") or c.get("on_expire") or "block")
        c["on_quota"] = str(r.get("on_quota") or c.get("on_quota") or "block")
        c["sub_enabled"] = bool(
            r.get("sub_enabled") if r.get("sub_enabled") is not None else c.get("sub_enabled", True)
        )
        c["tg_id"] = str(r.get("tg_id") or c.get("tg_id") or "")
        c["created_at"] = str(r.get("created_at") or c.get("created_at") or "")
        c["updated_at"] = str(r.get("updated_at") or c.get("updated_at") or "")
        c["last_online"] = str(r.get("last_online") or c.get("last_online") or "")
        if email in hw_by:
            c["hwids"] = hw_by[email]
        if email in tr_by:
            c.setdefault("traffic", {})
            if isinstance(c["traffic"], dict):
                c["traffic"]["up"] = tr_by[email]["up"]
                c["traffic"]["down"] = tr_by[email]["down"]
                if tr_by[email]["by_email"]:
                    c["traffic"]["by_email"] = tr_by[email]["by_email"]
        out.append(c)
    return out


def _as_list(v: Any) -> list:
    if isinstance(v, list):
        return v
    if isinstance(v, str):
        try:
            x = json.loads(v)
            return x if isinstance(x, list) else []
        except Exception:
            return []
    return list(v) if v else []


def _as_dict(v: Any) -> dict:
    if isinstance(v, dict):
        return dict(v)
    if isinstance(v, str):
        try:
            x = json.loads(v)
            return x if isinstance(x, dict) else {}
        except Exception:
            return {}
    return {}


def sync_clients_groups(store: dict) -> None:
    """Replace relational clients/groups from in-memory store (full sync)."""
    if not DATABASE_URL:
        return
    init_schema()
    conn, _flavor = _connect()
    try:
        cur = conn.cursor()
        # groups
        cur.execute("DELETE FROM groups")
        for g in store.get("groups") or []:
            if not isinstance(g, dict) or not g.get("id"):
                continue
            known = {"id", "name", "comment", "core_mode", "cores", "ib_mode", "inbounds"}
            extra = {k: v for k, v in g.items() if k not in known}
            cur.execute(
                """
                INSERT INTO groups (id, name, comment, core_mode, cores, ib_mode, inbounds, extra, updated_at)
                VALUES (%s,%s,%s,%s,%s::jsonb,%s,%s::jsonb,%s::jsonb,NOW())
                """,
                (
                    str(g.get("id")),
                    str(g.get("name") or ""),
                    str(g.get("comment") or ""),
                    str(g.get("core_mode") or "all"),
                    _json_dump(list(g.get("cores") or [])),
                    str(g.get("ib_mode") or "all"),
                    _json_dump(list(g.get("inbounds") or [])),
                    _json_dump(extra),
                ),
            )
        # clients — wipe children first
        cur.execute("DELETE FROM client_hwids")
        cur.execute("DELETE FROM client_traffic")
        cur.execute("DELETE FROM clients")
        for c in store.get("clients") or []:
            if not isinstance(c, dict):
                continue
            email = str(c.get("email") or "").strip()
            if not email:
                continue
            cols = {
                "email", "uuid", "password", "sub_token", "enabled", "group_id", "comment",
                "admin", "limit_gb", "daily_limit_gb", "limit_ip", "limit_hwid", "expire_at",
                "start_on_first_use", "duration_days", "reset_period", "renew_on_reset",
                "on_expire", "on_quota", "sub_enabled", "tg_id", "created_at", "updated_at",
                "last_online", "hwids", "traffic",
            }
            data = {k: v for k, v in c.items() if k not in cols}
            cur.execute(
                """
                INSERT INTO clients (
                    email, uuid, password, sub_token, enabled, group_id, comment, admin,
                    limit_gb, daily_limit_gb, limit_ip, limit_hwid, expire_at,
                    start_on_first_use, duration_days, reset_period, renew_on_reset,
                    on_expire, on_quota, sub_enabled, tg_id, created_at, updated_at,
                    last_online, data
                ) VALUES (
                    %s,%s,%s,%s,%s,%s,%s,%s,
                    %s,%s,%s,%s,%s,
                    %s,%s,%s,%s,
                    %s,%s,%s,%s,%s,%s,
                    %s,%s::jsonb
                )
                """,
                (
                    email,
                    str(c.get("uuid") or ""),
                    str(c.get("password") or ""),
                    str(c.get("sub_token") or ""),
                    bool(c.get("enabled", True)),
                    str(c.get("group_id") or ""),
                    str(c.get("comment") or ""),
                    str(c.get("admin") or ""),
                    float(c.get("limit_gb") or 0),
                    float(c.get("daily_limit_gb") or 0),
                    int(c.get("limit_ip") or 0),
                    int(c.get("limit_hwid") or 0),
                    str(c.get("expire_at") or ""),
                    bool(c.get("start_on_first_use")),
                    int(c.get("duration_days") or 0),
                    str(c.get("reset_period") or ""),
                    bool(c.get("renew_on_reset")),
                    str(c.get("on_expire") or "block"),
                    str(c.get("on_quota") or "block"),
                    bool(c.get("sub_enabled", True)),
                    str(c.get("tg_id") or ""),
                    str(c.get("created_at") or ""),
                    str(c.get("updated_at") or ""),
                    str(c.get("last_online") or ""),
                    _json_dump(data),
                ),
            )
            traffic = c.get("traffic") if isinstance(c.get("traffic"), dict) else {}
            cur.execute(
                """
                INSERT INTO client_traffic (email, up, down, by_email, updated_at)
                VALUES (%s,%s,%s,%s::jsonb,NOW())
                """,
                (
                    email,
                    int(traffic.get("up") or 0),
                    int(traffic.get("down") or 0),
                    _json_dump(traffic.get("by_email") or {}),
                ),
            )
            for h in c.get("hwids") or []:
                if not isinstance(h, dict) or not h.get("hash"):
                    continue
                raw = {k: v for k, v in h.items() if k not in (
                    "hash", "first_seen", "last_seen", "os", "os_ver", "model", "kind", "raw"
                )}
                if isinstance(h.get("raw"), dict):
                    raw.update(h["raw"])
                cur.execute(
                    """
                    INSERT INTO client_hwids
                      (email, hash, first_seen, last_seen, os, os_ver, model, kind, raw)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)
                    ON CONFLICT (email, hash) DO UPDATE SET
                      last_seen = EXCLUDED.last_seen,
                      os = EXCLUDED.os, os_ver = EXCLUDED.os_ver,
                      model = EXCLUDED.model, kind = EXCLUDED.kind, raw = EXCLUDED.raw
                    """,
                    (
                        email,
                        str(h.get("hash")),
                        str(h.get("first_seen") or ""),
                        str(h.get("last_seen") or ""),
                        str(h.get("os") or ""),
                        str(h.get("os_ver") or ""),
                        str(h.get("model") or ""),
                        str(h.get("kind") or ""),
                        _json_dump(raw),
                    ),
                )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def import_store_if_empty(store: dict) -> bool:
    """If panel_store is empty, write ``store`` and sync relational tables. Returns True if imported."""
    if not DATABASE_URL or not isinstance(store, dict) or not store:
        return False
    init_schema()
    conn, _flavor = _connect()
    try:
        cur = conn.cursor()
        cur.execute("SELECT data FROM panel_store WHERE id = 1")
        row = cur.fetchone()
        data = None
        if row:
            data = row["data"] if isinstance(row, dict) else row[0]
            if isinstance(data, str):
                data = json.loads(data)
        if isinstance(data, dict) and data.get("clients"):
            return False
        conn.close()
    except Exception:
        try:
            conn.close()
        except Exception:
            pass
        return False
    save_store_blob(store)
    sync_clients_groups(store)
    return True


def save_history_version(
    vid: str,
    *,
    user: str = "",
    ip: str = "",
    section: str = "",
    note: str = "",
    changes: int = 0,
    summary: str = "",
    state: dict | None = None,
) -> None:
    if not DATABASE_URL:
        return
    try:
        init_schema()
        conn, _ = _connect()
        try:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO settings_versions
                  (id, at, username, ip, section, note, changes, summary, state)
                VALUES (%s, NOW(), %s, %s, %s, %s, %s, %s, %s::jsonb)
                ON CONFLICT (id) DO UPDATE SET
                  summary = EXCLUDED.summary, state = EXCLUDED.state, changes = EXCLUDED.changes
                """,
                (
                    vid, user, ip, section, note, int(changes or 0), summary,
                    _json_dump(state or {}),
                ),
            )
            # Keep last 30
            cur.execute(
                """
                DELETE FROM settings_versions WHERE id IN (
                  SELECT id FROM settings_versions ORDER BY at DESC OFFSET 30
                )
                """
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    except Exception:
        pass


def status() -> dict[str, Any]:
    ok = enabled()
    info: dict[str, Any] = {
        "enabled": ok,
        "url_set": bool(DATABASE_URL),
        "error": _LAST_ERR,
    }
    if not ok:
        return info
    try:
        conn, _ = _connect()
        try:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) AS n FROM clients")
            row = cur.fetchone()
            info["clients"] = int((row["n"] if isinstance(row, dict) else row[0]) or 0)
            cur.execute("SELECT COUNT(*) AS n FROM groups")
            row = cur.fetchone()
            info["groups"] = int((row["n"] if isinstance(row, dict) else row[0]) or 0)
            cur.execute("SELECT updated_at FROM panel_store WHERE id = 1")
            row = cur.fetchone()
            if row:
                info["updated_at"] = str(row["updated_at"] if isinstance(row, dict) else row[0])
        finally:
            conn.close()
    except Exception as exc:  # noqa: BLE001
        info["error"] = str(exc)
    return info


def parse_url_safe() -> str:
    """Redacted DSN for UI."""
    if not DATABASE_URL:
        return ""
    try:
        u = urlparse(DATABASE_URL)
        user = unquote(u.username or "")
        host = u.hostname or ""
        port = u.port or 5432
        db = (u.path or "/").lstrip("/")
        return f"postgresql://{user}@***@{host}:{port}/{db}"
    except Exception:
        return "postgresql://***"
