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
    store: dict = {"balancers": {}, "outbounds_custom": []}
    bals = xray.ensure_balancers(store)
    if "random" not in bals or bals["random"]["tag"] != "lb_random":
        fail("ensure", bals)
    ok("ensure_balancers migrates random")


def test_cfg_emits_random_enabled_customs():
    store = {
        "balancers": {},
        "outbounds_custom": [
            {"tag": "warp1", "enabled": True, "remark": "WARP", "last_test": {"ok": True}},
            {"tag": "de1", "enabled": True, "remark": "DE", "last_test": {"ok": False}},
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
    # healthy_only=False for routing stability — enabled customs stay in selector
    if sel != {"warp1", "de1"}:
        fail("cfg", f"selector should be enabled customs, got {sorted(sel)}")
    if "off1" in sel:
        fail("cfg", f"disabled leaked into selector: {sorted(sel)}")
    if burst is not None:
        fail("cfg", "burstObservatory should be off when least_load disabled")
    if not obs or "warp1" not in obs.get("subjectSelector", []):
        fail("cfg", f"observatory subjects for probes: {obs}")
    ok("random cfg = enabled customs")


def test_empty_pool_no_emit():
    store = {"balancers": {}, "outbounds_custom": []}
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
        "outbounds_custom": [{"tag": "de1", "enabled": True, "remark": "DE"}],
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
    store["outbounds_custom"] = []
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
    # reverse portal with no dial config is not in _custom_outbounds; auto pool may be empty
    pool = xray.balancer_auto_pool(store)
    # node reverse without config is skipped from custom outbounds list
    if "node_root" in pool:
        # if present, health gate should exclude offline
        if xray.outbound_member_ok(store, "node_root"):
            fail("nat", "offline NAT should not be member_ok")
    ok("offline NAT handling")


def test_syntax():
    src = (PANEL / "xray_runtime.py").read_text(encoding="utf-8")
    ast.parse(src)
    ok("xray_runtime syntax")


def main() -> None:
    print("== balancer random offline ==")
    test_syntax()
    test_defaults()
    test_ensure_migrates()
    test_cfg_emits_random_enabled_customs()
    test_empty_pool_no_emit()
    test_fallback_none_emits_block()
    test_offline_nat_excluded_from_selector()
    print("all passed")


if __name__ == "__main__":
    main()
