#!/usr/bin/env python3
"""Offline checks for fast update + serial node update queue."""
from __future__ import annotations

import ast
import os
import sys
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PANEL = ROOT / "panel"
sys.path.insert(0, str(PANEL))
os.environ.setdefault("L2XPANEL_COOKIE_INSECURE", "1")
os.environ.setdefault("L2XPANEL_DATA", tempfile.mkdtemp(prefix="l2x-fu-"))


def ok(name: str) -> None:
    print(f"  OK  {name}")


def test_install_sh():
    text = (ROOT / "install.sh").read_text(encoding="utf-8")
    assert "update_fast" not in text or "Быстрое обновление" in text
    assert "snapshot_panel" in text
    assert "restore_panel_snapshot" in text
    assert "wait_panel_health" in text
    assert "--update-full" in text
    assert "SKIP_XRAY=${SKIP_XRAY:-1}" in text or 'SKIP_XRAY=${SKIP_XRAY:-1}' in text
    # default update is fast
    assert "Быстрое обновление" in text
    ok("install.sh fast update + snapshot/rollback")


def test_ops_update_panel_flags():
    import ops
    from unittest import mock

    calls = []

    def fake_run(cmd, timeout=120, shell=False, env=None, cwd=None):
        calls.append({"cmd": list(cmd) if isinstance(cmd, list) else cmd, "env": env})
        return {"ok": True, "code": 0, "stdout": "Панель: v1 → v2 (fast", "stderr": ""}

    real_exists = Path.exists

    def exists_patched(self):
        s = str(self).replace("\\", "/")
        if s.endswith("/usr/local/bin/l2x"):
            return True
        if s.endswith("/opt/l2xpanel/VERSION"):
            return False
        return real_exists(self)

    with mock.patch.object(ops, "_run", side_effect=fake_run), \
            mock.patch.object(Path, "exists", exists_patched):
        r = ops.update_panel("1.9.70")
        assert r.get("ok")
        assert "--full" not in calls[-1]["cmd"]
        assert calls[-1]["env"].get("SKIP_XRAY") == "1"
        calls.clear()
        r2 = ops.update_panel(full=True)
        assert "--full" in calls[-1]["cmd"]
    ok("ops.update_panel fast vs --full")


def test_queue_serial():
    # Import app with temp data
    import app as panel_app

    with panel_app.mutate() as st:
        st["nodes"] = [
            {"id": "n1", "name": "alpha", "enabled": True, "panel_version": "1.0.0", "token": "t1", "url": "https://a.example"},
            {"id": "n2", "name": "beta", "enabled": True, "panel_version": "1.0.0", "token": "t2", "url": "https://b.example"},
        ]
        st.setdefault("settings", {}).setdefault("nodes", {})["role"] = "master"
        st["settings"]["nodes"]["agent_enabled"] = False

    # Stub the actual updater so worker finishes instantly
    results = []
    lock = threading.Lock()

    def fake_run(item):
        import time
        time.sleep(0.08)  # keep item "running" long enough for duplicate checks
        with lock:
            results.append(item["id"])
        return {"ok": True, "name": item["name"], "version": "9.9.9", "before": "1.0.0"}

    panel_app._run_one_node_update = fake_run  # type: ignore
    r1 = panel_app.enqueue_node_update("n1", name="alpha", via="agent")
    r2 = panel_app.enqueue_node_update("n2", name="beta", via="agent")
    assert r1.get("queued") and r2.get("queued")
    # n2 should still be pending while n1 runs
    r3 = panel_app.enqueue_node_update("n2", name="beta")
    assert r3.get("already") in ("pending", "running"), r3
    r4 = panel_app.enqueue_node_update("n1", name="alpha")
    assert r4.get("already") in ("pending", "running"), r4

    # wait for worker
    import time
    for _ in range(80):
        snap = panel_app.node_update_queue_snapshot()
        if not snap["busy"] and len(results) >= 2:
            break
        time.sleep(0.05)
    assert results == ["n1", "n2"], results
    ok("node update queue is serial")


def test_ast():
    for name in ("app.py", "ops.py"):
        ast.parse((PANEL / name).read_text(encoding="utf-8"))
    ok("AST")


def test_ui():
    t = (PANEL / "ui" / "nodes.html").read_text(encoding="utf-8")
    assert "Очередь обновления нод" in t
    assert "/nodes/update-all" in t
    assert "/nodes/update-queue/clear" in t
    ok("nodes UI queue")


def main():
    print("== L2X fast-update / node-queue offline debug ==")
    test_install_sh()
    test_ops_update_panel_flags()
    test_queue_serial()
    test_ast()
    test_ui()
    print("ALL PASSED")


if __name__ == "__main__":
    main()
