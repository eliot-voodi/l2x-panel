#!/usr/bin/env python3
"""Offline checks: Pi-hole password via docker exec setpassword only."""
from __future__ import annotations

import ast
import os
import sys
import tempfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
PANEL = ROOT / "panel"
sys.path.insert(0, str(PANEL))
os.environ["L2XPANEL_DOH_DIR"] = tempfile.mkdtemp(prefix="l2x-doh-")


def ok(name: str) -> None:
    print(f"  OK  {name}")


def fail(name: str, msg: str) -> None:
    print(f" FAIL {name}: {msg}")
    raise SystemExit(1)


def test_compose_no_ftlconf_assignment():
    import doh as d

    d.write_compose(password="sec$ret")
    yml = (d.COMPOSE_DIR / "docker-compose.yml").read_text(encoding="utf-8")
    if "FTLCONF_webserver_api_password:" in yml:
        fail("compose", "must not pin FTLCONF_webserver_api_password")
    if "setpassword" not in yml:
        fail("compose", "comment should mention setpassword")
    ok("compose without FTLCONF password pin")


def test_detect_old_pin():
    import doh as d

    d.COMPOSE_DIR.mkdir(parents=True, exist_ok=True)
    (d.COMPOSE_DIR / "docker-compose.yml").write_text(
        "environment:\n  FTLCONF_webserver_api_password: 'x'\n",
        encoding="utf-8",
    )
    assert d._compose_pins_ftlconf_password() is True
    d.write_compose(password="y")
    assert d._compose_pins_ftlconf_password() is False
    ok("detect/migrate old FTLCONF pin")


def test_source_uses_docker_exec_setpassword():
    text = (PANEL / "doh.py").read_text(encoding="utf-8")
    assert '"pihole", "setpassword"' in text
    assert '"-u", "0"' in text
    assert "def _pihole_setpassword_cli" in text
    assert "def verify_pihole_password" not in text
    assert "def _ftlconf_password_yaml" not in text
    ast.parse(text)
    ok("docker exec -u 0 setpassword")


def test_live_container_skips_compose_up():
    import doh as d

    d.write_compose(password="abc")
    calls: list[list[str]] = []

    def fake_run(cmd, **_kwargs):
        calls.append(list(cmd))
        joined = " ".join(str(x) for x in cmd)
        if "inspect" in joined:
            return {"ok": True, "stdout": "true\n", "stderr": ""}
        if "setpassword" in joined:
            return {"ok": True, "stdout": "Password set\n", "stderr": ""}
        return {"ok": True, "stdout": "", "stderr": ""}

    with mock.patch.object(d, "_run", side_effect=fake_run), \
            mock.patch.object(d, "shutil") as sh:
        sh.which.return_value = "/usr/bin/docker"
        res = d.set_pihole_password("new-secret")
    if not res.get("ok"):
        fail("live-cli", res)
    if res.get("via") != "pihole setpassword":
        fail("via", res)
    if any("compose" in " ".join(c) or c[:1] == ["docker-compose"] for c in calls
           if "up" in c):
        # compose up should not run when container already running and no FTLCONF pin
        ups = [c for c in calls if "up" in c]
        if ups:
            fail("compose-up", ups)
    if not any("setpassword" in c for c in calls):
        fail("setpassword", calls)
    ok("live container -> setpassword only")


def test_tg_admin_mentions_node():
    text = (PANEL / "app.py").read_text(encoding="utf-8")
    if "def _local_node_label" not in text:
        fail("tg-node", "missing _local_node_label")
    if "🖥" not in text:
        fail("tg-node", "missing node footer marker")
    ok("tg admin node footer")


def main():
    print("== L2X pihole setpassword offline debug ==")
    test_compose_no_ftlconf_assignment()
    test_detect_old_pin()
    test_source_uses_docker_exec_setpassword()
    test_live_container_skips_compose_up()
    test_tg_admin_mentions_node()
    print("ALL PASSED")


if __name__ == "__main__":
    main()
