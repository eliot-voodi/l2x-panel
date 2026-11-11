#!/usr/bin/env python3
"""Offline checks for inbound_lint field mapping + Vision/Reality rules."""
from __future__ import annotations

import sys
from pathlib import Path

PANEL = Path(__file__).resolve().parents[1] / "panel"
sys.path.insert(0, str(PANEL))

import inbound_lint as L  # noqa: E402
import protocols as P  # noqa: E402


def ok(name: str) -> None:
    print(f"  OK  {name}")


def fail(name: str, msg: str) -> None:
    print(f" FAIL {name}: {msg}")
    raise SystemExit(1)


def _store() -> dict:
    return {
        "settings": {"panel": {"public_host": "panel.example.com"}, "nodes": {"role": "master"}},
        "inbounds": [],
        "clients": [],
        "l2tp": [],
        "outbounds_custom": [],
    }


def test_vision_on_ws():
    store = _store()
    ib = P.default_inbound("vless", 10001, "bad-vision")
    ib["stream"]["network"] = "ws"
    ib["stream"]["security"] = "none"
    ib["stream"]["ws"]["path"] = "/ws"
    ib["settings"]["flow"] = "xtls-rprx-vision"
    ib["direct"] = True
    issues = L.inbound_issues(store, ib)
    fields = {i["field"] for i in issues if i["level"] == L.ERROR}
    if "flow" not in fields:
        fail("vision-ws", f"expected flow error, got {issues}")
    ok("vision on ws -> flow error")


def test_reality_pub_domain():
    store = _store()
    ib = P.default_inbound("vless", 10002, "bad-reality")
    ib["stream"]["security"] = "reality"
    ib["stream"]["network"] = "raw"
    ib["stream"]["reality"]["server_names"] = ["panel.example.com"]
    ib["stream"]["reality"]["dest"] = "panel.example.com:443"
    ib["stream"]["reality"]["private_key"] = "x"
    ib["stream"]["reality"]["public_key"] = "y"
    ib["direct"] = False
    issues = L.inbound_issues(store, ib)
    msgs = " ".join(i["msg"] for i in issues if i["field"] == "r_names")
    if "панели" not in msgs and "панел" not in msgs.lower():
        fail("reality-sni", f"expected public-domain SNI error, got {issues}")
    ok("reality SNI = panel domain -> error")


def test_none_outbound_ok():
    store = _store()
    ib = P.default_inbound("vless", 10003, "ok")
    ib["outbound"] = ""
    ib["direct"] = True
    ib["stream"]["security"] = "reality"
    ib["stream"]["reality"]["private_key"] = "x"
    ib["stream"]["reality"]["public_key"] = "y"
    ib["stream"]["reality"]["server_names"] = ["www.cloudflare.com"]
    ib["stream"]["reality"]["dest"] = "www.cloudflare.com:443"
    issues = [i for i in L.inbound_issues(store, ib) if i["level"] == L.ERROR]
    if issues:
        fail("none-ob", f"unexpected errors: {issues}")
    ok("max-speed-like inbound clean")


def test_summarize():
    s = L.summarize([{"field": "a", "level": "error", "msg": "e"}, {"field": "b", "level": "warn", "msg": "w"}])
    if s["errors"] != 1 or s["warnings"] != 1:
        fail("summary", str(s))
    ok("summarize counts")


def test_fallbacks_with_decryption():
    store = _store()
    ib = P.default_inbound("vless", 10004, "vless")
    ib["direct"] = False
    ib["stream"]["network"] = "raw"
    ib["stream"]["security"] = "none"
    ib["settings"]["flow"] = "xtls-rprx-vision"
    ib["settings"]["decryption"] = "mlkem768x25519plus.500s..."
    ib["settings"]["encryption"] = "mlkem768x25519plus.500s..."
    ib["fallbacks"] = [{"name": "", "alpn": "", "path": "//ms", "dest": "127.0.0.1:8881", "xver": 0}]
    issues = L.inbound_issues(store, ib)
    fields = {i["field"] for i in issues if i["level"] == L.ERROR}
    if "fallbacks" not in fields or "vless_decryption" not in fields:
        fail("fb+dec", f"expected fallbacks+decryption highlights, got {issues}")
    mapped = L.map_xray_error_fields(
        ib,
        'VLESS settings: "fallbacks" can not be used together with "decryption"',
    )
    mfields = {i["field"] for i in mapped}
    if "fallbacks" not in mfields:
        fail("map-xray", str(mapped))
    ok("fallbacks + decryption -> highlight")


def main():
    print("== inbound_lint offline ==")
    test_vision_on_ws()
    test_reality_pub_domain()
    test_none_outbound_ok()
    test_summarize()
    test_fallbacks_with_decryption()
    print("ALL PASSED")


if __name__ == "__main__":
    main()
