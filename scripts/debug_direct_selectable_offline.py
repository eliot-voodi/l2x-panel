#!/usr/bin/env python3
"""direct appears in selectable outbound tags (opt-in for subscription extras)."""
from __future__ import annotations

import copy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "panel"))

import xray_runtime as xray  # noqa: E402


def fail(msg: str) -> None:
    print("FAIL", msg)
    raise SystemExit(1)


def ok(msg: str) -> None:
    print("OK", msg)


def main() -> None:
    store = {
        "settings": {},
        "inbounds": [],
        "clients": [],
        "groups": [],
        "balancers": {},
        "outbounds_custom": [
            {"tag": "node_buh", "remark": "buh", "enabled": True, "in_sub": True, "kind": "node"},
        ],
        "nodes": [],
    }
    xray.ensure_balancers(store)
    tags = xray.selectable_outbound_tags(store)
    kinds = {t["tag"]: t["kind"] for t in tags}
    if kinds.get("direct") != "system":
        fail(f"direct missing/wrong kind: {kinds}")
    ok("direct in selectable")

    no_sys = {t["tag"] for t in xray.selectable_outbound_tags(store, include_system=False)}
    if "direct" in no_sys:
        fail("include_system=False still has direct")
    ok("include_system=False excludes direct")

    c = xray.ensure_client({"email": "u1", "uuid": "11111111-1111-1111-1111-111111111111",
                           "sub_token": "t", "outbound": "lb_least_ping", "allowed_tags": [],
                           "select_mode": "all"})
    store["clients"].append(c)
    # mode «все» → empty allowed → direct must NOT appear as extra
    extras = [e["tag"] for e in xray.subscription_entries(store, c, ignore_quota=True)]
    if "direct" in extras:
        fail(f"direct leaked into all-mode extras: {extras}")
    ok("all-mode skips direct extra")

    c2 = copy.deepcopy(c)
    c2["email"] = "u2"
    c2["select_mode"] = "select"
    c2["allowed_tags"] = ["direct", "node_buh"]
    c2["outbound"] = "lb_least_ping"
    store["clients"].append(c2)
    extras2 = [e["tag"] for e in xray.subscription_entries(store, c2, ignore_quota=True)]
    if "direct" not in extras2:
        fail(f"direct not in select-mode extras: {extras2}")
    ok("select-mode includes direct extra")

    c3 = copy.deepcopy(c)
    c3["email"] = "u3"
    c3["outbound"] = "direct"
    c3["allowed_tags"] = ["node_buh"]
    c3["select_mode"] = "select"
    extras3 = [e["tag"] for e in xray.subscription_entries(store, c3, ignore_quota=True)]
    if "direct" in extras3:
        fail("direct duplicated when it is main")
    ok("main=direct not duplicated in extras")

    print("ALL OK")


if __name__ == "__main__":
    main()
