#!/usr/bin/env python3
"""Offline checks: reverse toggle, health role, tunnel health gate, parallel probes."""
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


def test_reverse_toggle_xray_reverse():
    text = (PANEL / "app.py").read_text(encoding="utf-8")
    if 'node["tunnel_mode"] = "l2x_udp"' in text and "rv_mode" in text:
        # find reverse-on block
        m = re.search(
            r'if node\["rv_mode"\]:\s*node\["as_outbound"\] = True\s*node\["tunnel_mode"\] = "([^"]+)"',
            text,
            re.S,
        )
        if not m:
            # alternate formatting
            if 'node["tunnel_mode"] = "xray_reverse"' not in text:
                fail("reverse", "rv_mode on must set xray_reverse")
        elif m.group(1) != "xray_reverse":
            fail("reverse", f"got {m.group(1)}")
    if "ensure_reverse(node)" not in text:
        fail("reverse", "must call ensure_reverse when enabling")
    ok("reverse toggle -> xray_reverse")


def test_health_role_independent():
    text = (PANEL / "app.py").read_text(encoding="utf-8")
    if 'role = "agent" if (ns.get("agent_enabled") and (ns.get("role") or "") == "agent")' in text:
        fail("health", "role still gated on agent_enabled")
    if 'role = "agent" if (ns.get("role") or "master") == "agent"' not in text:
        fail("health", "expected role from ns[role]")
    ok("health role from ns.role")


def test_tunnel_health_tunnel_only():
    text = (PANEL / "nodes.py").read_text(encoding="utf-8")
    if "if not is_tunnel_only_node(n):" not in text:
        fail("tunnel-health", "refresh must gate on is_tunnel_only_node")
    if "if bool(health.get(\"online\")) and not agents:" in text or "if bool(health.get('online')) and not agents:" in text:
        fail("tunnel-health", "legacy all-online branch still present")
    ok("tunnel health tunnel-only + no legacy")


def test_reverse_member_nat_only_pull():
    text = (PANEL / "xray_runtime.py").read_text(encoding="utf-8")
    if "if node.get(\"nat\") or nodes_mod.uses_reverse(node):" in text:
        # old combined branch
        idx = text.find("_reverse_portal_member_ok")
        chunk = text[idx:idx + 1200]
        if "if node.get(\"nat\") or nodes_mod.uses_reverse(node):" in chunk:
            fail("member-ok", "reachable reverse still requires pull_fresh via OR")
    if "Reachable reverse: push-synced" not in text:
        fail("member-ok", "missing reachable reverse branch")
    ok("reverse member_ok NAT-only pull_fresh")


def test_parallel_probes():
    app = (PANEL / "app.py").read_text(encoding="utf-8")
    nodes = (PANEL / "nodes.py").read_text(encoding="utf-8")
    if "ThreadPoolExecutor" not in app or "ThreadPoolExecutor" not in nodes:
        fail("parallel", "missing ThreadPoolExecutor")
    if "def _outbounds_probe_loop" not in app:
        fail("parallel", "missing outbound probe loop")
    chunk = app.split("def _outbounds_probe_loop")[1][:400]
    if "_stop.wait(90)" in chunk:
        fail("parallel", "outbound probe still waits 90s at start")
    if "_stop.wait(25)" not in chunk:
        fail("parallel", "expected faster outbound probe startup")
    ok("parallel outbound + node probes")


def test_enable_agent_keeps_master():
    text = (PANEL / "app.py").read_text(encoding="utf-8")
    chunk = text[text.find('if action == "enable_agent"'):text.find('if action == "enable_agent"') + 900]
    if 'ns["role"] = "agent"' in chunk and "!= \"master\"" not in chunk and "!= 'master'" not in chunk:
        fail("enable_agent", "still always sets role=agent")
    ok("enable_agent preserves master")


def test_ast():
    for name in ("app.py", "nodes.py", "xray_runtime.py", "doh.py"):
        ast.parse((PANEL / name).read_text(encoding="utf-8"))
    ok("AST")


def main():
    print("== L2X promote/speed offline debug ==")
    test_reverse_toggle_xray_reverse()
    test_health_role_independent()
    test_tunnel_health_tunnel_only()
    test_reverse_member_nat_only_pull()
    test_parallel_probes()
    test_enable_agent_keeps_master()
    test_ast()
    print("ALL PASSED")


if __name__ == "__main__":
    main()
