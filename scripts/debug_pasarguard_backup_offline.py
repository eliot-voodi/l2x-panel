#!/usr/bin/env python3
"""Offline checks for PasarGuard backup file import (sqlite / COPY sql / zip)."""
from __future__ import annotations

import io
import json
import sqlite3
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PANEL = ROOT / "panel"
sys.path.insert(0, str(PANEL))

import migrate as m  # noqa: E402


def ok(name: str) -> None:
    print(f"  OK  {name}")


def fail(name: str, msg: str) -> None:
    print(f" FAIL {name}: {msg}")
    raise SystemExit(1)


def _sqlite_bytes() -> bytes:
    import os
    import tempfile
    from pathlib import Path as P

    fd, name = tempfile.mkstemp(suffix=".sqlite3")
    os.close(fd)
    path = P(name)
    try:
        conn = sqlite3.connect(str(path))
        conn.executescript(
            """
            CREATE TABLE users (
              id INTEGER PRIMARY KEY,
              username TEXT,
              status TEXT,
              used_traffic INTEGER,
              data_limit INTEGER,
              expire TEXT,
              note TEXT,
              proxy_settings TEXT
            );
            CREATE TABLE user_usage_reset_logs (
              id INTEGER PRIMARY KEY,
              user_id INTEGER,
              used_traffic_at_reset INTEGER
            );
            INSERT INTO users VALUES (
              1, 'alice', 'active', 1000, 10737418240,
              '2027-06-01 12:00:00+00:00', 'note-a',
              '{"vless":{"id":"11111111-1111-1111-1111-111111111111"},"trojan":{"password":"trj-secret"}}'
            );
            INSERT INTO users VALUES (
              2, 'bob', 'disabled', 50, 0, NULL, '',
              '{"vless":{"id":"22222222-2222-2222-2222-222222222222"}}'
            );
            INSERT INTO user_usage_reset_logs VALUES (1, 1, 5000);
            """
        )
        conn.commit()
        conn.close()
        return path.read_bytes()
    finally:
        path.unlink(missing_ok=True)


def test_sqlite_modern_schema():
    users = m.parse_pasarguard_backup(_sqlite_bytes())
    by = {u.email: u for u in users}
    if set(by) != {"alice", "bob"}:
        fail("sqlite", f"users={list(by)}")
    alice = by["alice"]
    if alice.uuid != "11111111-1111-1111-1111-111111111111":
        fail("sqlite", f"uuid={alice.uuid}")
    if alice.password != "trj-secret":
        fail("sqlite", f"password={alice.password}")
    if alice.down != 6000:
        fail("sqlite", f"lifetime traffic expected 6000 got {alice.down}")
    if not alice.expire_at.startswith("2027-06-01"):
        fail("sqlite", f"expire={alice.expire_at}")
    if by["bob"].enabled:
        fail("sqlite", "bob should be disabled")
    ok("modern sqlite proxy_settings + datetime expire + lifetime")


def test_zip_with_sqlite():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("docker-compose.yml", "services:\n  panel:\n    image: x\n")
        zf.writestr(".env", "SQLALCHEMY_DATABASE_URL=sqlite\nADMIN_USERNAME=admin\n")
        zf.writestr("db_dump/db.sqlite3", _sqlite_bytes())
    users = m.parse_backup("pasarguard", buf.getvalue(), "backup_20260101.zip")
    if len(users) != 2:
        fail("zip", f"len={len(users)}")
    ok("zip backup prefers db.sqlite3 over junk JSON-ish files")


def test_postgres_copy_dump():
    dump = """
--
-- PostgreSQL database dump
--
COPY public.users (id, username, status, used_traffic, data_limit, expire, note, proxy_settings) FROM stdin;
1	carol	active	42	2147483648	2028-01-15 00:00:00+00	hi	{"vless": {"id": "33333333-3333-3333-3333-333333333333"}}
2	dave	on_hold	0	\\N	\\N	\\N	{"vless": {"id": "44444444-4444-4444-4444-444444444444"}, "trojan": {"password": "pw"}}
\\.
COPY public.admins (id, username) FROM stdin;
1	root
\\.
"""
    users = m.parse_pasarguard_backup(dump.encode())
    by = {u.email: u for u in users}
    if set(by) != {"carol", "dave"}:
        fail("copy", f"users={list(by)}")
    if by["carol"].uuid != "33333333-3333-3333-3333-333333333333":
        fail("copy", f"carol uuid={by['carol'].uuid}")
    if by["dave"].password != "pw" or by["dave"].enabled:
        fail("copy", f"dave={by['dave']}")
    if not by["carol"].expire_at.startswith("2028-01-15"):
        fail("copy", f"expire={by['carol'].expire_at}")
    ok("postgres COPY users dump")


def test_json_still_works():
    raw = json.dumps({
        "users": [{
            "username": "eve",
            "status": "active",
            "data_limit": 0,
            "used_traffic": 9,
            "subscription_url": "https://pg.example/sub/tokEVE",
            "proxies": {"vless": {"id": "55555555-5555-5555-5555-555555555555"}},
        }],
    }).encode()
    users = m.parse_backup("pasarguard", raw, "users.json")
    if len(users) != 1 or users[0].sub_token != "tokEVE":
        fail("json", users)
    ok("JSON users export")


def test_proxies_string_no_crash():
    # Marzban-style: proxies stored as JSON text
    u = m._pg_user_from_dict({
        "username": "frank",
        "status": "active",
        "used_traffic": 1,
        "proxies": json.dumps({"vless": {"id": "66666666-6666-6666-6666-666666666666"}, "trojan": {"password": "x"}}),
        "expire": 1893456000,  # unix
    })
    if not u or u.uuid != "66666666-6666-6666-6666-666666666666" or u.password != "x":
        fail("proxies-string", u)
    if not u.expire_at:
        fail("proxies-string", f"expire empty: {u.expire_at}")
    ok("proxies JSON-string does not crash")


def main():
    print("== L2X PasarGuard backup offline debug ==")
    test_sqlite_modern_schema()
    test_zip_with_sqlite()
    test_postgres_copy_dump()
    test_json_still_works()
    test_proxies_string_no_crash()
    print("ALL PASSED")


if __name__ == "__main__":
    main()
