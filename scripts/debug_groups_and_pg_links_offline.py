#!/usr/bin/env python3
"""Offline checks: client groups, PasarGuard legacy token resolve, HTTPS legacy ports."""
from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PANEL = ROOT / "panel"
sys.path.insert(0, str(PANEL))

import front  # noqa: E402
import migrate as m  # noqa: E402
import xray_runtime as xray  # noqa: E402

SECRET = "9ce6f9af210241a11af1f82d51c1ad82ea03318859a40ce34fcfb7c212950d9a"
OLD = "djMsMiwxNzkyNjEzMDky.i-qLohDh_EhwwUXjz5fAYh9jScavspGm-57z5k-mv68"
NEW = "djMsMiwxNzcyODg1OTMw.Kt1mkUJRayyulGUp-X6VuriXV9c3AgBapvUZB56agYs"


def ok(name: str) -> None:
    print(f"  OK  {name}")


def fail(name: str, msg: object) -> None:
    print(f" FAIL {name}: {msg}")
    raise SystemExit(1)


def _store() -> dict:
    store = {
        "settings": {"sub": {}},
        "l2tp": [{"name": "de", "status": "connected"}, {"name": "nl", "status": "connected"}],
        "outbounds_custom": [{"tag": "vless-fi", "enabled": True, "in_sub": True}],
        "inbounds": [],
        "clients": [],
        "groups": [],
    }
    xray.ensure_balancers(store)
    xray.ensure_inbounds(store)
    return store


def test_group_overrides_client():
    store = _store()
    tags = [t["tag"] for t in xray.selectable_outbound_tags(store)]
    l2_de = next(t for t in tags if "de" in t)
    g = xray.new_group(name="Premium")
    g["allowed_tags"] = [l2_de]
    store["groups"].append(g)
    c = xray.ensure_client({"email": "u1", "sub_token": "t1", "allowed_tags": [], "group_id": g["id"]})
    store["clients"].append(c)
    if xray.client_effective_allowed_tags(store, c) != [l2_de]:
        fail("group", xray.client_effective_allowed_tags(store, c))
    if not xray.tag_allowed_for_client(store, c, l2_de):
        fail("group", "de should be allowed")
    other = next(t for t in tags if t != l2_de)
    if xray.tag_allowed_for_client(store, c, other):
        fail("group", f"{other} must be filtered by group")
    # No group → personal list (empty = all)
    c2 = xray.ensure_client({"email": "u2", "sub_token": "t2"})
    if not xray.tag_allowed_for_client(store, c2, other):
        fail("group", "client without group should see all")
    # Group outbound overrides client default
    g["outbound"] = l2_de
    c["outbound"] = "direct"
    if xray.client_default_outbound(store, c) != l2_de:
        fail("group", "group outbound not applied")
    ok("group allowed_tags + outbound override")


def test_pg_old_token_resolves():
    payload = m.parse_pasarguard_sub_token(OLD, [SECRET])
    if not payload or payload.get("user_id") != 2:
        fail("pg", payload)
    p2 = m.parse_pasarguard_sub_token(NEW, [SECRET])
    if not p2 or p2.get("user_id") != 2:
        fail("pg", p2)
    if m.parse_pasarguard_sub_token(OLD, ["wrong" * 8]):
        fail("pg", "must not verify with wrong secret")
    ok("old/new PasarGuard tokens decode to same user_id")


def test_tls_legacy_ports_split():
    store = {"settings": {"sub": {"legacy_ports": [2096, 8000], "legacy_tls_ports": [8000]}}}
    if front.legacy_sub_plain_ports(store) != [2096]:
        fail("ports", front.legacy_sub_plain_ports(store))
    if front.legacy_sub_tls_ports(store) != [8000]:
        fail("ports", front.legacy_sub_tls_ports(store))
    if set(front.legacy_sub_ports(store)) != {2096, 8000}:
        fail("ports", front.legacy_sub_ports(store))
    ok("legacy HTTP vs HTTPS ports")


def test_app_find_by_token_wiring():
    src = (PANEL / "app.py").read_text(encoding="utf-8")
    ast.parse(src)
    for needle in (
        "legacy_jwt_secrets",
        "parse_pasarguard_sub_token",
        '"meta": dict(migrate_mod.LAST_SOURCE_META',
        "legacy_tls_ports",
        "/groups/save",
        "set_group",
    ):
        if needle not in src:
            fail("app", f"missing {needle}")
    for name in ("groups.html", "group_edit.html"):
        if not (PANEL / "ui" / name).exists():
            fail("ui", name)
    ok("app wiring (cache meta, jwt, tls ports, groups)")


def test_env_port_detect():
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(".env", 'UVICORN_PORT = 8000\nUVICORN_SSL_CERTFILE = "/x/cert.pem"\n')
        zf.writestr(
            "pg_dump/db-001.sql",
            f"COPY public.jwt (id, secret_key) FROM stdin;\n1\t{SECRET}\n\\.\n"
            "COPY public.users (id, username, status, used_traffic, created_at, proxy_settings) FROM stdin;\n"
            '2\tdenis\tactive\t0\t2026-03-07 12:18:49+00\t{"vless": {"id": "11111111-1111-1111-1111-111111111111"}}\n'
            "\\.\n",
        )
    users = m.parse_backup("pasarguard", buf.getvalue(), "b.zip")
    meta = m.LAST_SOURCE_META or {}
    if meta.get("port") != 8000 or not meta.get("tls"):
        fail("env", meta)
    if not users or users[0].source_id != "2":
        fail("env", users)
    ok("PasarGuard .env port 8000 + TLS detected")


def main():
    print("== L2X groups + PasarGuard links offline debug ==")
    test_group_overrides_client()
    test_pg_old_token_resolves()
    test_tls_legacy_ports_split()
    test_app_find_by_token_wiring()
    test_env_port_detect()
    print("ALL PASSED")


if __name__ == "__main__":
    main()
