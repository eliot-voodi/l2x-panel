#!/usr/bin/env python3
"""Offline checks for lb_random (distribute across live outbounds)."""
from __future__ import annotations

import ast
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PANEL = ROOT / "panel"
sys.path.insert(0, str(PANEL))
os.environ.setdefault("L2XPANEL_DATA", tempfile.mkdtemp(prefix="l2x-bal-"))
os.environ.setdefault("L2XPANEL_COOKIE_INSECURE", "1")

import xray_runtime as xray  # noqa: E402


def ok(name: str) -> None:
    print(f"  OK  {name}")


def fail(name: str, msg: str) -> None:
    print(f" FAIL {name}: {msg}")
    raise SystemExit(1)


def test_defaults():
    bals = xray.default_balancers()
    if "random" not in bals:
        fail("defaults", "missing random balancer")
    b = bals["random"]
    if b.get("tag") != xray.BALANCER_RANDOM or b.get("strategy") != "random":
        fail("defaults", f"bad random defaults: {b}")
    if xray.BALANCER_RANDOM not in xray.BALANCER_LABELS:
        fail("defaults", "missing label")
    ok("default_balancers has random / lb_random")


def test_ensure_migrates():
    store: dict = {"balancers": {}, "l2tp": [], "outbounds_custom": []}
    bals = xray.ensure_balancers(store)
    if "random" not in bals or bals["random"]["tag"] != "lb_random":
        fail("ensure", bals)
    ok("ensure_balancers migrates random")


def test_cfg_emits_random_live_only():
    store = {
        "balancers": {},
        "l2tp": [
            {"name": "de", "status": "connected", "outbound": "l2tp_de", "metrics": {"loss_pct": 1}},
            {"name": "us", "status": "disconnected", "outbound": "l2tp_us"},
            {"name": "bad", "status": "connected", "outbound": "l2tp_bad", "metrics": {"loss_pct": 90}},
        ],
        "outbounds_custom": [
            {"tag": "warp1", "enabled": True, "remark": "WARP"},
            {"tag": "off1", "enabled": False, "remark": "off"},
        ],
        "settings": {"sub": {"hide_unhealthy": True, "max_loss_pct": 20}},
    }
    xray.ensure_balancers(store)
    store["balancers"]["random"]["enabled"] = True
    store["balancers"]["least_ping"]["enabled"] = False
    store["balancers"]["least_load"]["enabled"] = False
    cfg, obs, burst = xray._balancers_cfg(store)
    tags = {e["tag"]: e for e in cfg}
    if "lb_random" not in tags:
        fail("cfg", f"lb_random missing: {cfg}")
    entry = tags["lb_random"]
    if entry["strategy"]["type"] != "random":
        fail("cfg", f"strategy={entry['strategy']}")
    sel = set(entry["selector"])
    if sel != {"l2tp_de", "warp1"}:
        fail("cfg", f"selector should be live only, got {sorted(sel)}")
    if "l2tp_us" in sel or "l2tp_bad" in sel or "off1" in sel:
        fail("cfg", f"dead/disabled leaked into selector: {sorted(sel)}")
    if burst is not None:
        fail("cfg", "burstObservatory should be off when least_load disabled")
    if not obs or "l2tp_de" not in obs.get("subjectSelector", []):
        fail("cfg", f"observatory subjects for probes: {obs}")
    ok("random cfg = live members only")


def test_empty_pool_no_emit():
    store = {"balancers": {}, "l2tp": [], "outbounds_custom": []}
    xray.ensure_balancers(store)
    store["balancers"]["least_ping"]["enabled"] = False
    store["balancers"]["least_load"]["enabled"] = False
    cfg, obs, burst = xray._balancers_cfg(store)
    if any(e.get("tag") == "lb_random" for e in cfg):
        fail("empty", f"should not emit empty random: {cfg}")
    target = xray._route_target(store, "lb_random")
    if target.get("outboundTag") != "direct":
        fail("empty", f"empty random should fall back via _route_target, got {target}")
    ok("empty pool → no balancer emit, route→fallback")


def test_fallback_none_emits_block():
    store = {
        "balancers": {},
        "l2tp": [{"name": "de", "status": "connected", "outbound": "l2tp_de"}],
        "outbounds_custom": [],
        "settings": {"sub": {"hide_unhealthy": True}},
    }
    xray.ensure_balancers(store)
    for key in ("least_ping", "least_load", "random"):
        store["balancers"][key]["fallback"] = "none"
        store["balancers"][key]["enabled"] = True
    cfg, _, _ = xray._balancers_cfg(store)
    by_tag = {e["tag"]: e for e in cfg}
    for tag in ("lb_least_ping", "lb_least_load", "lb_random"):
        if tag not in by_tag:
            fail("fallback_none", f"missing {tag}: {cfg}")
        if by_tag[tag].get("fallbackTag") != "block":
            fail("fallback_none", f"{tag} fallbackTag={by_tag[tag].get('fallbackTag')}")
    store["l2tp"] = []
    if xray._route_target(store, "lb_least_ping") != {"outboundTag": "block"}:
        fail("fallback_none", f"empty pool route={xray._route_target(store, 'lb_least_ping')}")
    if xray.balancer_fallback_tag({"fallback": "none"}) != "block":
        fail("fallback_none", "balancer_fallback_tag(none) != block")
    ok("fallback none → fallbackTag=block")


def test_offline_nat_excluded_from_selector():
    from datetime import datetime, timedelta, timezone

    stale = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
    store = {
        "balancers": {},
        "l2tp": [],
        "nodes": [{
            "id": 1, "name": "root", "enabled": True, "nat": True, "as_outbound": True,
            "online": False, "last_pull": stale, "rv_conns": 0, "role": "agent",
        }],
        "outbounds_custom": [{
            "tag": "node_root", "enabled": True, "kind": "node", "reverse": True,
            "node_id": 1, "config": {},
        }],
        "settings": {"sub": {"hide_unhealthy": True}},
    }
    xray.ensure_balancers(store)
    store["balancers"]["random"]["members"] = ["node_root"]
    store["balancers"]["least_ping"]["enabled"] = False
    store["balancers"]["least_load"]["enabled"] = False
    members = xray.balancer_member_tags(store, store["balancers"]["random"], healthy_only=True)
    if members:
        fail("nat_offline", f"dead NAT still in pool: {members}")
    cfg, _, _ = xray._balancers_cfg(store)
    if any(e.get("tag") == "lb_random" for e in cfg):
        fail("nat_offline", f"should not emit random with dead NAT: {cfg}")
    ok("offline NAT excluded from balancer selector")


def test_ui_and_route():
    html = (PANEL / "ui" / "balancers.html").read_text(encoding="utf-8")
    if "lb_random" not in html and "random" not in html:
        fail("ui", "balancers.html missing random hints")
    if "fallbackTag=block" not in html:
        fail("ui", "balancers.html must document fallbackTag=block")
    app = (PANEL / "app.py").read_text(encoding="utf-8")
    if '"random"' not in app.split("balancers_save")[1][:800]:
        fail("app", "balancers_save must allow key=random")
    ok("UI + save route accept random")


def test_ast():
    for name in ("xray_runtime.py", "app.py"):
        ast.parse((PANEL / name).read_text(encoding="utf-8"))
    ok("AST")


def main():
    print("== L2X lb_random offline debug ==")
    test_defaults()
    test_ensure_migrates()
    test_cfg_emits_random_live_only()
    test_empty_pool_no_emit()
    test_fallback_none_emits_block()
    test_offline_nat_excluded_from_selector()
    test_ui_and_route()
    test_ast()
    print("ALL PASSED")


if __name__ == "__main__":
    main()
