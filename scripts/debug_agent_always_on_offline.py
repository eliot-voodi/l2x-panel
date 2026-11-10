#!/usr/bin/env python3
"""Offline checks: Agent API stays on for master; User=root in units; apply rejected on master."""
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


def test_sticky_any_role():
    text = (PANEL / "app.py").read_text(encoding="utf-8")
    if "Master keeps Agent API online" not in text and "Keep Agent API on after restarts" not in text:
        fail("sticky", "missing sticky/promote keep-agent comments")
    # promote/restore must not force agent_enabled=False anymore
    if re.search(r'ns\["agent_enabled"\]\s*=\s*False', text):
        fail("promote", "app.py still sets agent_enabled=False literally")
    if "master rejects apply" not in text:
        fail("apply", "master must reject /agent/apply")
    ast.parse(text)
    ok("sticky + promote keep agent + master rejects apply")


def test_nodes_promote_ssh():
    text = (PANEL / "nodes.py").read_text(encoding="utf-8")
    if "ns['agent_enabled'] = False" in text or 'ns["agent_enabled"] = False' in text:
        fail("nodes-promote", "SSH promote still disables agent")
    if 's.setdefault("agent_enabled", True)' not in text:
        fail("default", "default agent_enabled should be True")
    ok("nodes promote keeps agent")


def test_units_root():
    for rel in (
        "deploy/l2xpanel.service",
        "deploy/l2xpanel-next.service",
        "tunnel/deploy/l2x-tunneld.service",
        "tunnel/deploy/l2x-tunnel-agent.service",
    ):
        body = (ROOT / rel).read_text(encoding="utf-8")
        if "User=root" not in body:
            fail(rel, "missing User=root")
        if "Group=root" not in body:
            fail(rel, "missing Group=root")
    ok("systemd User=root")


def main():
    print("== L2X agent always-on offline debug ==")
    test_sticky_any_role()
    test_nodes_promote_ssh()
    test_units_root()
    print("ALL PASSED")


if __name__ == "__main__":
    main()
