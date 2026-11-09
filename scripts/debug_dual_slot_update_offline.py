#!/usr/bin/env python3
"""Offline checks for dual-slot zero-downtime panel updates."""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PANEL = ROOT / "panel"


def ok(name: str) -> None:
    print(f"  OK  {name}")


def fail(name: str, msg: str) -> None:
    print(f" FAIL {name}: {msg}")
    raise SystemExit(1)


def test_install_sh_dual_slot():
    text = (ROOT / "install.sh").read_text(encoding="utf-8")
    for needle in (
        "LIVE_DIR=/opt/l2xpanel-live",
        "NEXT_DIR=/opt/l2xpanel-next",
        "PANEL_SLOT_FILE=",
        "ensure_slot_layout",
        "prepare_inactive_slot",
        "inactive_unit",
        "active_unit",
        "write_panel_slot",
        "enable_active_unit",
        "единственный flip",
        "Dual-slot",
    ):
        if needle not in text:
            fail("install.sh dual-slot markers", f"missing {needle!r}")
    # Must NOT promote + flip back (that caused panel downtime).
    if "promote_stage_to_app" in text:
        fail("install.sh", "promote_stage_to_app still present — dual-slot must not promote")
    # Cutover must stop the OLD unit only after nginx flip.
    cut = re.search(r"cutover_blue_green\(\) \{.*?^\}", text, re.S | re.M)
    if not cut:
        fail("install.sh", "cutover_blue_green not found")
    body = cut.group(0)
    flip_at = body.find("единственный flip")
    stop_old_at = body.find("Остановка старой службы")
    if flip_at < 0 or stop_old_at < 0 or stop_old_at < flip_at:
        fail("install.sh cutover order", "old unit must stop AFTER nginx flip")
    if "flip_panel_upstream \"$PANEL_LIVE_ADDR\"" in body and body.count("flip_panel_upstream") > 3:
        # Allow flip-back only on failure paths; success path must keep traffic on new slot.
        success_tail = body[stop_old_at:]
        if 'flip_panel_upstream "$PANEL_LIVE_ADDR"' in success_tail.split("die")[0]:
            fail("install.sh", "success path still flips back to PANEL_LIVE_ADDR")
    ok("install.sh dual-slot cutover (one flip, stop old after)")


def test_unit_files():
    live = (ROOT / "deploy" / "l2xpanel.service").read_text(encoding="utf-8")
    nxt = (ROOT / "deploy" / "l2xpanel-next.service").read_text(encoding="utf-8")
    if "WorkingDirectory=/opt/l2xpanel-live" not in live:
        fail("l2xpanel.service", "expected WorkingDirectory=/opt/l2xpanel-live")
    if "WorkingDirectory=/opt/l2xpanel-next" not in nxt:
        fail("l2xpanel-next.service", "expected WorkingDirectory=/opt/l2xpanel-next")
    if "PORT=8091" not in nxt:
        fail("l2xpanel-next.service", "expected PORT=8091")
    if "/opt/l2xpanel.stage" in nxt:
        fail("l2xpanel-next.service", "still references .stage")
    ok("systemd unit paths")


def test_l2x_cli():
    text = (ROOT / "scripts" / "l2x.sh").read_text(encoding="utf-8")
    for needle in ("panel_unit", "panel_slot", "panel_port", "l2xpanel-next"):
        if needle not in text:
            fail("l2x.sh", f"missing {needle}")
    if 'systemctl restart l2xpanel &&' in text or 'systemctl restart l2xpanel xray' in text:
        fail("l2x.sh", "hardcoded restart l2xpanel — must use panel_unit")
    ok("l2x.sh active unit helpers")


def test_ops_doc():
    text = (PANEL / "ops.py").read_text(encoding="utf-8")
    if "dual-slot" not in text:
        fail("ops.py", "update_panel docstring should mention dual-slot")
    if "promote, flip back" in text:
        fail("ops.py", "stale promote/flip-back wording")
    ok("ops.update_panel dual-slot docs")


def test_ast():
    for name in ("app.py", "ops.py", "nodes.py", "front.py"):
        ast.parse((PANEL / name).read_text(encoding="utf-8"))
    ok("AST")


def test_front_preserves_upstream():
    text = (PANEL / "front.py").read_text(encoding="utf-8")
    if "panel_upstream_addr" not in text or "PANEL_UPSTREAM_STATE" not in text:
        fail("front.py", "upstream state helpers missing")
    # ensure_panel_upstream_conf must default to state, not hard reset to 8090 when state exists
    if "addr = (addr or panel_upstream_addr())" not in text:
        fail("front.py", "ensure_panel_upstream_conf must preserve active upstream")
    ok("front.py preserves upstream across panel start")


def test_detach_from_panel_cgroup():
    text = (ROOT / "install.sh").read_text(encoding="utf-8")
    if "detach_from_panel_cgroup" not in text or "L2X_DETACHED" not in text:
        fail("install.sh", "missing self-detach from panel cgroup")
    call = text.find('detach_from_panel_cgroup "$@"')
    parse = text.find("_args=(\"$@\")")
    if call < 0 or parse < 0 or call > parse:
        fail("install.sh", "detach must run before argument parsing / update")

    sys.path.insert(0, str(PANEL))
    import ops
    from unittest import mock

    calls: list = []

    def fake_run(cmd, timeout=120, shell=False, env=None, cwd=None):
        calls.append(cmd)
        return {"ok": True, "code": 0, "stdout": "", "stderr": ""}

    # Inside panel cgroup → transient unit via systemd-run, rc file read back.
    with mock.patch.object(ops, "_in_panel_cgroup", return_value=True), \
            mock.patch.object(ops.shutil, "which", return_value="/usr/bin/systemd-run"), \
            mock.patch.object(ops, "_run", side_effect=fake_run), \
            mock.patch.object(ops, "UPDATE_RC") as rc, \
            mock.patch.object(ops, "UPDATE_LOG") as lg, \
            mock.patch.object(ops.time, "sleep", lambda *_: None):
        rc.is_file.return_value = True
        rc.read_text.return_value = "0\n"
        lg.read_text.return_value = "Панель: v1 → v2 (dual-slot live→next, без простоя)"
        r = ops.update_panel()
    if not calls or calls[0][0] != "systemd-run":
        fail("ops.update_panel", f"expected systemd-run, got {calls[:1]}")
    if not any(str(a).startswith("--unit=") for a in calls[0]):
        fail("ops.update_panel", "systemd-run without --unit")
    if not r.get("ok"):
        fail("ops.update_panel", f"detached update result not ok: {r}")

    calls.clear()
    with mock.patch.object(ops, "_in_panel_cgroup", return_value=False), \
            mock.patch.object(ops, "_run", side_effect=fake_run):
        ops.update_panel()
    if calls and calls[0][0] == "systemd-run":
        fail("ops.update_panel", "must not detach outside the panel cgroup")

    if "systemctl restart l2xpanel\"" in (PANEL / "ops.py").read_text(encoding="utf-8"):
        fail("ops.py", "hard-coded restart l2xpanel")
    if '"restart", "l2xpanel"]' in (PANEL / "app.py").read_text(encoding="utf-8"):
        fail("app.py", "hard-coded restart l2xpanel")
    ok("update survives panel unit stop (systemd-run detach)")


def main():
    print("== L2X dual-slot update offline debug ==")
    test_detach_from_panel_cgroup()
    test_install_sh_dual_slot()
    test_unit_files()
    test_l2x_cli()
    test_ops_doc()
    test_front_preserves_upstream()
    test_ast()
    print("ALL PASSED")


if __name__ == "__main__":
    main()
