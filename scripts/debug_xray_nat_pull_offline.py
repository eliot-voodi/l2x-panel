#!/usr/bin/env python3
"""Offline tests: NAT Xray update must go through agent pull and survive retries."""
from __future__ import annotations

import ast
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PANEL = ROOT / "panel"
sys.path.insert(0, str(PANEL))
os.environ.setdefault("L2XPANEL_DATA", tempfile.mkdtemp(prefix="l2x-xray-nat-"))


def ok(name: str) -> None:
    print(f"  OK  {name}")


def fail(name: str, msg: str) -> None:
    print(f" FAIL {name}: {msg}")
    raise SystemExit(1)


def test_pull_xray_update_tag_persists():
    import nodes as n

    node = {"id": "n1", "xray_update_requested": "v26.11.9", "xray_version": "26.10.31"}
    tag = n.pull_xray_update_tag(node, {"xray_version": "26.10.31"})
    assert tag == "v26.11.9", tag
    assert node.get("xray_update_requested") == "v26.11.9"
    # second pull still sends (not one-shot)
    tag2 = n.pull_xray_update_tag(node, {"xray_version": "26.10.31"})
    assert tag2 == "v26.11.9"
    ok("re-send until installed")

    # clear when agent reports matching/newer
    tag3 = n.pull_xray_update_tag(node, {"xray_version": "26.11.9"})
    assert tag3 == ""
    assert "xray_update_requested" not in node
    ok("clear when version caught up")


def test_normalize_without_v():
    import nodes as n

    node = {"xray_update_requested": "26.11.9"}
    assert n.pull_xray_update_tag(node, {}) == "v26.11.9"
    ok("normalize tag with v prefix")


def test_source_no_one_shot_pop():
    text = (PANEL / "app.py").read_text(encoding="utf-8")
    if 'node.pop("xray_update_requested"' in text:
        fail("one-shot pop", "agent_pull still pops xray_update_requested")
    if "pull_xray_update_tag" not in text:
        fail("helper", "pull_xray_update_tag not used in app.py")
    # agent must handle xray before panel-update early return
    idx_xray = text.find('xray_upd = str(res.get("xray_update")')
    idx_want = text.find("want_update = bool(res.get(\"update\")", idx_xray)
    if idx_xray < 0 or idx_want < 0 or idx_xray > idx_want:
        fail("order", "xray_update must be handled before panel want_update return")
    ok("app.py: no one-shot pop; xray before panel update")


def test_ast():
    for name in ("app.py", "nodes.py"):
        ast.parse((PANEL / name).read_text(encoding="utf-8"))
    ok("AST app.py / nodes.py")


def main():
    print("== L2X NAT xray-pull offline debug ==")
    test_ast()
    test_pull_xray_update_tag_persists()
    test_normalize_without_v()
    test_source_no_one_shot_pop()
    print("ALL PASSED")


if __name__ == "__main__":
    main()
