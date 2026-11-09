#!/usr/bin/env python3
"""Offline checks for Pi-hole password apply path (no docker required)."""
from __future__ import annotations

import ast
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PANEL = ROOT / "panel"
sys.path.insert(0, str(PANEL))
os.environ["L2XPANEL_DOH_DIR"] = tempfile.mkdtemp(prefix="l2x-doh-")


def ok(name: str) -> None:
    print(f"  OK  {name}")


def fail(name: str, msg: str) -> None:
    print(f" FAIL {name}: {msg}")
    raise SystemExit(1)


def test_ftlconf_yaml_escapes_dollar():
    import doh as d

    assert d._ftlconf_password_yaml("abc") == "'abc'"
    assert d._ftlconf_password_yaml("a$b") == "'a$$b'"
    assert d._ftlconf_password_yaml("x${y}z") == "'x$${y}z'"
    assert d._ftlconf_password_yaml("it's") == "'it''s'"
    ok("FTLCONF yaml $$ escape")


def test_compose_embeds_password_not_env_ref():
    import doh as d

    d.write_compose(password="sec$ret#1")
    yml = (d.COMPOSE_DIR / "docker-compose.yml").read_text(encoding="utf-8")
    if "FTLCONF_webserver_api_password:" not in yml:
        fail("compose", "missing FTLCONF_webserver_api_password")
    if "${PIHOLE_PASSWORD}" in yml:
        fail("compose", "must not reference ${PIHOLE_PASSWORD}")
    if "sec$$ret#1" not in yml and "'sec$$ret#1'" not in yml:
        # embedded as 'sec$$ret#1'
        if "sec$$ret" not in yml:
            fail("compose", f"$ not doubled in yml: {yml}")
    env = (d.COMPOSE_DIR / ".env").read_text(encoding="utf-8")
    if "sec$ret" not in env:
        fail("env", "backup .env lost password")
    ok("compose embeds escaped password; no env interpolation ref")


def test_source_force_recreate():
    text = (PANEL / "doh.py").read_text(encoding="utf-8")
    assert "--force-recreate" in text
    assert "verify_pihole_password" in text
    assert "_ftlconf_password_yaml" in text
    ast.parse(text)
    ok("force-recreate + verify in doh.py")


def main():
    print("== L2X pihole password offline debug ==")
    test_ftlconf_yaml_escapes_dollar()
    test_compose_embeds_password_not_env_ref()
    test_source_force_recreate()
    print("ALL PASSED")


if __name__ == "__main__":
    main()
