#!/usr/bin/env python3
"""Offline tests for multi-admin accounts (no network)."""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PANEL = ROOT / "panel"
sys.path.insert(0, str(PANEL))


def ok(name: str) -> None:
    print(f"  OK  {name}")


def fail(name: str, msg: str) -> None:
    print(f" FAIL {name}: {msg}")
    raise SystemExit(1)


def fresh_data() -> Path:
    d = Path(tempfile.mkdtemp(prefix="l2x-adm-"))
    os.environ["L2XPANEL_DATA"] = str(d)
    return d


def test_bootstrap_and_login():
    d = fresh_data()
    import admins as ad  # noqa: WPS433

    ad.ensure(default_user="root", default_password_env="secretpass8")
    assert ad.check_credentials("root", "secretpass8")
    assert not ad.check_credentials("root", "nope")
    assert len(ad.public_rows()) == 1
    ok("bootstrap + login")

    ok_add, _ = ad.add_admin("second", "password99")
    assert ok_add
    assert ad.check_credentials("second", "password99")
    assert len(ad.public_rows()) == 2
    ok("add second admin")

    bad, msg = ad.add_admin("second", "password99")
    assert not bad and "уже" in msg.lower()
    ok("reject duplicate username")

    sec = ad.get_by_username("second")
    assert sec
    ok_u, err, _ = ad.update_account(sec["id"], new_password="newpass888")
    assert ok_u and not err
    assert ad.check_credentials("second", "newpass888")
    ok("update password")

    ok_d, err_d = ad.delete_admin(sec["id"])
    assert ok_d and not err_d
    assert len(ad.public_rows()) == 1
    ok("delete admin")

    last = ad.public_rows()[0]
    bad_last, _ = ad.delete_admin(last["id"])
    assert not bad_last
    ok("cannot delete last admin")

    shutil.rmtree(d, ignore_errors=True)


def test_legacy_migration():
    d = fresh_data()
    import bcrypt
    import json

    leg = d / "admin.json"
    h = bcrypt.hashpw(b"legacypass8", bcrypt.gensalt()).decode()
    leg.write_text(json.dumps({"username": "legacy", "password_hash": h}), encoding="utf-8")

    import admins as ad  # noqa: WPS433

    ad.ensure()
    assert ad.check_credentials("legacy", "legacypass8")
    assert (d / "admins.json").exists()
    ok("migrate legacy admin.json")

    shutil.rmtree(d, ignore_errors=True)


def test_syntax():
    import ast

    ast.parse((PANEL / "admins.py").read_text(encoding="utf-8"))
    ok("AST admins.py")


def test_settings_routes_source():
    text = (PANEL / "app.py").read_text(encoding="utf-8")
    for needle in (
        '"/settings/admins/add"',
        '"/settings/admins/{admin_id}/remove"',
        "admins.public_rows()",
    ):
        if needle not in text:
            fail("app routes", f"missing {needle}")
    ok("app.py admin routes")


def main():
    print("== L2X admins offline debug ==")
    test_syntax()
    test_settings_routes_source()
    test_bootstrap_and_login()
    test_legacy_migration()
    print("ALL PASSED")


if __name__ == "__main__":
    main()
