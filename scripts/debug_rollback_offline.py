#!/usr/bin/env python3
"""Offline debug for panel/Xray rollback helpers."""
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
os.environ.setdefault("L2XPANEL_DATA", tempfile.mkdtemp(prefix="l2x-rb-"))

import ops  # noqa: E402
import security as sec  # noqa: E402


def ok(name: str) -> None:
    print(f"  OK  {name}")


def fail(name: str, msg: str) -> None:
    print(f" FAIL {name}: {msg}")
    raise SystemExit(1)


def test_normalize_tag():
    assert ops.normalize_tag("1.9.72") == "v1.9.72"
    assert ops.normalize_tag("v1.9.72") == "v1.9.72"
    assert ops.normalize_tag("") == ""
    ok("normalize_tag")


def test_manage_scopes():
    assert "rollback_panel" in sec.MANAGE_ADMIN
    assert "rollback_xray" in sec.MANAGE_WRITE
    bad, why = sec.manage_action_allowed(
        action="rollback_panel", is_master=True, allow_master_manage=False,
    )
    assert not bad and "allow_master_manage" in why
    good, _ = sec.manage_action_allowed(
        action="rollback_xray", is_master=False, allow_master_manage=False,
    )
    assert good
    ok("manage scopes for rollback_*")


def test_xray_backup_and_rollback_local():
    tmp = Path(tempfile.mkdtemp(prefix="l2x-xray-"))
    live = tmp / "xray"
    bak = tmp / "xray.bak"
    # Opaque binary blobs (not executed — _run is mocked)
    live.write_bytes(b"LIVE-BIN-99")
    bak.write_bytes(b"BAK-BIN-88")
    os.chmod(live, 0o755)
    os.chmod(bak, 0o755)
    meta = tmp / "xray.bak.version"
    meta.write_text("88.0.0", encoding="utf-8")

    old_bin = ops.XRAY_BIN
    try:
        ops.XRAY_BIN = live
        info = ops.xray_backup_info()
        assert info["exists"] and info["version"] == "88.0.0"

        def fake_run(cmd, timeout=120, shell=False, env=None, cwd=None):
            joined = " ".join(cmd) if isinstance(cmd, list) else str(cmd)
            path0 = Path(cmd[0]) if isinstance(cmd, list) and cmd else Path("")
            if "version" in joined:
                # Identify which binary by content
                try:
                    blob = path0.read_bytes()
                except OSError:
                    blob = b""
                if b"88" in blob or b"BAK" in blob:
                    return {"ok": True, "code": 0, "stdout": "Xray 88.0.0 (fake)\n", "stderr": ""}
                return {"ok": True, "code": 0, "stdout": "Xray 99.0.0 (fake)\n", "stderr": ""}
            if "-test" in joined:
                return {"ok": True, "code": 0, "stdout": "ok", "stderr": ""}
            if "systemctl" in joined or "is-active" in joined:
                return {"ok": True, "code": 0, "stdout": "active\n", "stderr": ""}
            return {"ok": True, "code": 0, "stdout": "", "stderr": ""}

        with mock.patch.object(ops, "_run", side_effect=fake_run):
            with mock.patch.object(ops.time, "sleep", lambda *_a, **_k: None):
                res = ops.rollback_xray("")
        assert res.get("ok"), res
        assert live.read_bytes() == b"BAK-BIN-88"
        assert bak.read_bytes() == b"LIVE-BIN-99"
        ok("xray_backup_info + rollback_xray(.bak)")
    finally:
        ops.XRAY_BIN = old_bin


def test_rollback_panel_requires_version():
    r = ops.rollback_panel("")
    assert not r.get("ok")
    ok("rollback_panel empty version rejected")


def test_update_panel_passes_env():
    calls = []

    def fake_run(cmd, timeout=120, shell=False, env=None, cwd=None):
        calls.append({"cmd": cmd, "env": env})
        return {"ok": True, "code": 0, "stdout": "done", "stderr": ""}

    with mock.patch.object(ops, "_run", side_effect=fake_run):
        with mock.patch.object(Path, "exists", return_value=True):
            # Path.exists is too broad — patch only l2x path via mock on Path
            pass

    # Narrower: patch Path.exists for the l2x binary check inside update_panel
    real_exists = Path.exists

    def exists_patched(self):
        if str(self).replace("\\", "/").endswith("/usr/local/bin/l2x"):
            return True
        if str(self).replace("\\", "/").endswith("/opt/l2xpanel/VERSION"):
            return False
        return real_exists(self)

    with mock.patch.object(ops, "_run", side_effect=fake_run), \
            mock.patch.object(Path, "exists", exists_patched):
        res = ops.update_panel("1.9.70")
    assert res.get("ok")
    assert calls, "update_panel did not call _run"
    env = calls[0]["env"] or {}
    assert env.get("L2X_BRANCH") == "v1.9.70"
    assert env.get("SKIP_XRAY") == "1"
    cmd = calls[0]["cmd"]
    assert "v1.9.70" in cmd
    ok("update_panel(version) sets L2X_BRANCH + SKIP_XRAY")


def test_install_sh_has_tag_urls():
    text = (ROOT / "install.sh").read_text(encoding="utf-8")
    assert "refs/tags/${BRANCH}" in text
    assert "SKIP_XRAY" in text
    assert '--update) [ -f "$ENV_FILE"' not in text  # old single-arg parser gone
    assert "SKIP_XRAY=${SKIP_XRAY:-1}" in text or "SKIP_XRAY=${SKIP_XRAY:-1}" in text.replace(" ", "")
    ok("install.sh supports tags + SKIP_XRAY")


def test_routes_present():
    text = (PANEL / "app.py").read_text(encoding="utf-8")
    assert '@app.post("/panel/update/rollback")' in text
    assert '@app.post("/xray/rollback")' in text
    assert 'action == "rollback_panel"' in text
    assert 'action == "rollback_xray"' in text
    for name in ("app.py", "ops.py", "security.py"):
        ast.parse((PANEL / name).read_text(encoding="utf-8"))
    ok("routes + AST")


def test_ui_hooks():
    s = (PANEL / "ui" / "settings.html").read_text(encoding="utf-8")
    assert "/panel/update/rollback" in s
    x = (PANEL / "ui" / "xray.html").read_text(encoding="utf-8")
    assert "/xray/rollback" in x
    ok("UI rollback forms")


def main():
    print("== L2X rollback offline debug ==")
    test_normalize_tag()
    test_manage_scopes()
    test_xray_backup_and_rollback_local()
    test_rollback_panel_requires_version()
    test_update_panel_passes_env()
    test_install_sh_has_tag_urls()
    test_routes_present()
    test_ui_hooks()
    print("ALL PASSED")


if __name__ == "__main__":
    main()
