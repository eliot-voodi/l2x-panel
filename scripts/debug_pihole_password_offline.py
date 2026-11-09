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


def test_env_quote():
    import doh as d

    assert d._env_quote("simple") == "simple"
    q = d._env_quote("a$b#c 'x'")
    assert q.startswith("'") and q.endswith("'")
    assert "$" in q
    ok("env quote special chars")


def test_compose_no_ftlconf_password():
    import doh as d

    d.write_compose(password="sec$ret#1")
    yml = (d.COMPOSE_DIR / "docker-compose.yml").read_text(encoding="utf-8")
    env = (d.COMPOSE_DIR / ".env").read_text(encoding="utf-8")
    if "FTLCONF_webserver_api_password:" in yml or 'FTLCONF_webserver_api_password"' in yml:
        fail("compose", "FTLCONF_webserver_api_password must not be an env assignment")
    if "PIHOLE_PASSWORD=" not in env:
        fail("env", "missing PIHOLE_PASSWORD")
    if "sec$ret" not in env:
        fail("env", "password mangled in .env")
    ok("compose without FTLCONF password; .env keeps $")


def test_detect_old_compose():
    import doh as d

    d.COMPOSE_DIR.mkdir(parents=True, exist_ok=True)
    (d.COMPOSE_DIR / "docker-compose.yml").write_text(
        "environment:\n  FTLCONF_webserver_api_password: \"${PIHOLE_PASSWORD}\"\n",
        encoding="utf-8",
    )
    assert d._compose_has_env_password() is True
    d.write_compose(password="x")
    assert d._compose_has_env_password() is False
    ok("migrate detection for old FTLCONF compose")


def test_source_uses_setpassword():
    text = (PANEL / "doh.py").read_text(encoding="utf-8")
    assert 'pihole", "setpassword"' in text or "pihole\", \"setpassword\"" in text
    assert "verify_pihole_password" in text
    assert "wait_pihole_http" in text
    ast.parse(text)
    ok("setpassword + verify in doh.py")


def main():
    print("== L2X pihole password offline debug ==")
    test_env_quote()
    test_compose_no_ftlconf_password()
    test_detect_old_compose()
    test_source_uses_setpassword()
    print("ALL PASSED")


if __name__ == "__main__":
    main()
