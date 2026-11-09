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


SECRET = "9ce6f9af210241a11af1f82d51c1ad82ea03318859a40ce34fcfb7c212950d9a"


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
            f"""
            CREATE TABLE jwt (
              id INTEGER PRIMARY KEY,
              secret_key TEXT NOT NULL
            );
            CREATE TABLE users (
              id INTEGER PRIMARY KEY,
              username TEXT,
              status TEXT,
              used_traffic INTEGER,
              data_limit INTEGER,
              expire TEXT,
              created_at TEXT,
              note TEXT,
              proxy_settings TEXT
            );
            CREATE TABLE user_usage_reset_logs (
              id INTEGER PRIMARY KEY,
              user_id INTEGER,
              used_traffic_at_reset INTEGER
            );
            INSERT INTO jwt VALUES (1, '{SECRET}');
            INSERT INTO users VALUES (
              1, 'alice', 'active', 1000, 10737418240,
              '2027-06-01 12:00:00+00:00', '2026-01-01 00:00:00+00:00', 'note-a',
              '{{"vless":{{"id":"11111111-1111-1111-1111-111111111111"}},"trojan":{{"password":"trj-secret"}}}}'
            );
            INSERT INTO users VALUES (
              2, 'bob', 'disabled', 50, 0, NULL, '2026-02-01 00:00:00+00:00', '',
              '{{"vless":{{"id":"22222222-2222-2222-2222-222222222222"}}}}'
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
    if alice.source_id != "1" or by["bob"].source_id != "2":
        fail("sqlite", f"source_id alice={alice.source_id} bob={by['bob'].source_id}")
    if "." not in alice.sub_token:
        fail("sqlite", f"expected minted v3 token, got {alice.sub_token}")
    meta = m.LAST_SOURCE_META or {}
    if SECRET not in (meta.get("jwt_secrets") or []):
        fail("sqlite", f"jwt meta={meta}")
    ok("modern sqlite proxy_settings + datetime expire + lifetime + jwt mint")


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
    dump = f"""
--
-- PostgreSQL database dump
--
COPY public.jwt (id, secret_key) FROM stdin;
1	{SECRET}
\\.
COPY public.users (id, username, status, used_traffic, data_limit, expire, created_at, note, proxy_settings) FROM stdin;
1	carol	active	42	2147483648	2028-01-15 00:00:00+00	2026-03-01 00:00:00+00	hi	{{"vless": {{"id": "33333333-3333-3333-3333-333333333333"}}}}
2	dave	on_hold	0	\\N	\\N	2026-03-02 00:00:00+00	\\N	{{"vless": {{"id": "44444444-4444-4444-4444-444444444444"}}, "trojan": {{"password": "pw"}}}}
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
    if "." not in by["carol"].sub_token or by["carol"].source_id != "1":
        fail("copy", f"carol token/source={by['carol'].sub_token}/{by['carol'].source_id}")
    ok("postgres COPY users dump + jwt")


def test_legacy_token_resolve():
    """Any validly signed PG token for user_id must resolve — not only the minted one."""
    users = m.parse_pasarguard_backup(_sqlite_bytes())
    alice = next(u for u in users if u.email == "alice")
    # Mint a *different* issued_at token (what an old client app would still hold)
    other = m.create_pasarguard_sub_token(1, SECRET, issued_at=1_700_000_000)
    if other == alice.sub_token:
        fail("resolve", "tokens unexpectedly equal")
    payload = m.parse_pasarguard_sub_token(other, [SECRET])
    if not payload or payload.get("user_id") != 1:
        fail("resolve", f"payload={payload}")
    # Legacy username form
    from base64 import b64encode
    from hashlib import sha256

    data = "alice,1700000000"
    data_b64 = b64encode(data.encode(), altchars=b"-_").decode().rstrip("=")
    sig = b64encode(sha256((data_b64 + SECRET).encode()).digest(), altchars=b"-_").decode()[:10]
    legacy = data_b64 + sig
    payload2 = m.parse_pasarguard_sub_token(legacy, [SECRET])
    if not payload2 or payload2.get("username") != "alice":
        fail("resolve", f"legacy payload={payload2}")
    ok("legacy + alternate v3 tokens decode")


def test_real_zip_if_present():
    from pathlib import Path

    candidates = [
        Path(r"C:\Users\eliot\Downloads\Telegram Desktop\pasarguard-backup_20261014000043.zip"),
    ]
    path = next((p for p in candidates if p.exists()), None)
    if not path:
        ok("real zip skipped (not found)")
        return
    users = m.parse_backup("pasarguard", path.read_bytes(), path.name)
    meta = m.LAST_SOURCE_META or {}
    if len(users) < 10:
        fail("real", f"users={len(users)}")
    if not meta.get("jwt_secrets"):
        fail("real", f"no jwt in meta={meta}")
    minted = sum(1 for u in users if u.sub_token and "." in u.sub_token)
    with_id = sum(1 for u in users if u.source_id)
    if minted < 10 or with_id < 10:
        fail("real", f"minted={minted} with_id={with_id} total={len(users)}")
    # Spot-check: alternate token for first user resolves to same user_id
    u0 = users[0]
    alt = m.create_pasarguard_sub_token(u0.source_id, meta["jwt_secrets"][0], issued_at=1_650_000_000)
    got = m.parse_pasarguard_sub_token(alt, meta["jwt_secrets"])
    if not got or str(got.get("user_id")) != str(u0.source_id):
        fail("real", f"alt resolve {got} vs {u0.source_id}")
    ok(f"real zip ({len(users)} users, jwt ok)")


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
    test_legacy_token_resolve()
    test_real_zip_if_present()
    print("ALL PASSED")


if __name__ == "__main__":
    main()
