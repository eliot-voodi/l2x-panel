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
        fail("apply", "master must reject /agent/apply without demote flag")
    if "demote_to_agent" not in text:
        fail("demote", "app.py missing demote_to_agent apply/manage path")
    if "wants_demote_to_agent" not in text:
        fail("demote", "app.py must gate master apply on wants_demote_to_agent")
    ast.parse(text)
    ok("sticky + promote keep agent + master rejects apply + demote")


def test_nodes_promote_ssh():
    text = (PANEL / "nodes.py").read_text(encoding="utf-8")
    if "ns['agent_enabled'] = False" in text or 'ns["agent_enabled"] = False' in text:
        fail("nodes-promote", "SSH promote still disables agent")
    if 's.setdefault("agent_enabled", True)' not in text:
        fail("default", "default agent_enabled should be True")
    if "demote_store_to_agent" not in text:
        fail("demote", "nodes.py missing demote_store_to_agent")
    if '"demote_to_agent": True' not in text and "'demote_to_agent': True" not in text:
        fail("demote", "build_payload must send demote_to_agent")
    if "master rejects apply" not in text:
        fail("demote", "push() must auto-heal master rejects apply")
    ok("nodes promote keeps agent + demote sync heal")


def test_demote_helpers():
    sys.path.insert(0, str(PANEL))
    import nodes as nodes_mod  # noqa: WPS433

    assert nodes_mod.wants_demote_to_agent({"demote_to_agent": True})
    assert nodes_mod.wants_demote_to_agent({"demote_to_agent": "yes"})
    assert not nodes_mod.wants_demote_to_agent({})
    assert not nodes_mod.wants_demote_to_agent({"demote_to_agent": False})

    st = {"settings": {"nodes": {"role": "master", "agent_enabled": True, "agent_token": "t"}}}
    r = nodes_mod.demote_store_to_agent(st)
    assert r["ok"] and r["demoted"] and st["settings"]["nodes"]["role"] == "agent"
    assert st["settings"]["nodes"]["runtime_preserve"] is True

    blocked = {"settings": {"nodes": {"role": "master", "agent_manual_off": True}}}
    r2 = nodes_mod.demote_store_to_agent(blocked)
    assert not r2["ok"] and r2.get("manual_off")
    ok("demote helpers")


def test_security_demote_allowed_on_master():
    sys.path.insert(0, str(PANEL))
    import security as sec  # noqa: WPS433

    ok_act, why = sec.manage_action_allowed(
        action="demote_to_agent", is_master=True, allow_master_manage=False,
    )
    if not ok_act:
        fail("security", f"demote_to_agent must work on master: {why}")
    ok("security demote on master")


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
    test_demote_helpers()
    test_security_demote_allowed_on_master()
    test_units_root()
    print("ALL PASSED")


if __name__ == "__main__":
    main()
