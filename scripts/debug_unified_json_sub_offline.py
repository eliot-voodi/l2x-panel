#!/usr/bin/env python3
"""Unified ?format=json builds Ascella-style cascade."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "panel"))

import protocols as P  # noqa: E402


def fail(msg: str) -> None:
    print("FAIL", msg)
    raise SystemExit(1)


def ok(msg: str) -> None:
    print("OK", msg)


def main() -> None:
    eps = [
        {"protocol": "vless", "address": "msk.ro0t.dev", "port": 8443, "net": "raw", "security": "reality",
         "uuid": "u1", "flow": "xtls-rprx-vision", "sni": "static.ascl.dev", "pbk": "pbk", "sid": "sid",
         "fp": "firefox", "spx": "/", "remark": "rv1"},
        {"protocol": "hysteria", "address": "msk.ro0t.dev", "port": 443, "net": "hysteria", "security": "tls",
         "password": "pwd", "sni": "msk.ro0t.dev", "fp": "firefox", "brutal_up": "100mbps",
         "brutal_down": "300mbps", "remark": "hy2"},
        {"protocol": "vless", "address": "msk.ro0t.dev", "port": 443, "net": "xhttp", "security": "tls",
         "uuid": "u1", "path": "/download", "host": "msk.ro0t.dev", "mode": "packet-up", "sni": "msk.ro0t.dev",
         "fp": "firefox", "remark": "xh"},
        # duplicate transport (different remark) — must dedupe
        {"protocol": "vless", "address": "msk.ro0t.dev", "port": 443, "net": "xhttp", "security": "tls",
         "uuid": "u2", "path": "/download", "host": "msk.ro0t.dev", "mode": "packet-up", "sni": "msk.ro0t.dev",
         "fp": "firefox", "remark": "xh-dup"},
    ]
    cfg = P.xray_unified_client_config(eps, remarks="Test")
    tags = [o["tag"] for o in cfg["outbounds"]]
    if "direct" not in tags or "block" not in tags:
        fail(f"missing system outs: {tags}")
    proxy = [t for t in tags if t not in ("direct", "block", "dns-out") and not t.startswith("LOOP-")]
    if len(proxy) != 3:
        fail(f"expected 3 proxy hops after dedupe, got {proxy}")
    bals = cfg["routing"]["balancers"]
    if len(bals) != 3:
        fail(f"balancers {bals}")
    if bals[0]["fallbackTag"] != "LOOP-1":
        fail(f"cascade fallback {bals[0]}")
    rules = cfg["routing"]["rules"]
    if not any(r.get("balancerTag") == "BAL-1" for r in rules):
        fail("no default BAL-1 rule")
    if not any(r.get("outboundTag") == "direct" and "geoip:ru" in (r.get("ip") or []) for r in rules):
        fail("no RU direct rule")
    # Reality hop uses tcp not raw
    reality = next(o for o in cfg["outbounds"] if "REALITY" in o["tag"])
    if (reality.get("streamSettings") or {}).get("network") != "tcp":
        fail(f"reality net {reality.get('streamSettings')}")
    ok("cascade + routing")

    one = P.xray_unified_client_config(eps[:1], remarks="One")
    if not any(o.get("tag") == "proxy" for o in one["outbounds"]):
        fail("single-ep should keep proxy tag")
    ok("single endpoint")
    print("ALL OK")


if __name__ == "__main__":
    main()
