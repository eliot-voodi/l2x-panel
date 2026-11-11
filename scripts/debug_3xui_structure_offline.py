#!/usr/bin/env python3
"""Offline checks: x-ui backup restores inbounds, outbounds, routes + client tags."""
from __future__ import annotations

import json
import sqlite3
import sys
import tempfile
from pathlib import Path

PANEL = Path(__file__).resolve().parents[1] / "panel"
sys.path.insert(0, str(PANEL))

import migrate as M  # noqa: E402
import protocols as P  # noqa: E402
import xray_runtime as xray  # noqa: E402


def ok(name: str) -> None:
    print(f"  OK  {name}")


def fail(name: str, msg: str) -> None:
    print(f" FAIL {name}: {msg}")
    raise SystemExit(1)


def _empty_store() -> dict:
    return {
        "settings": {"panel": {"public_host": "panel.example.com"}, "nodes": {"role": "master"}},
        "inbounds": [],
        "clients": [],
        "l2tp": [],
        "outbounds_custom": [],
        "routes": [],
    }


def _mk_db(path: Path) -> None:
    conn = sqlite3.connect(str(path))
    conn.execute(
        "CREATE TABLE inbounds ("
        "id INTEGER PRIMARY KEY, user_id INTEGER, up INTEGER, down INTEGER, total INTEGER,"
        "remark TEXT, enable INTEGER, expiry_time INTEGER, listen TEXT, port INTEGER,"
        "protocol TEXT, settings TEXT, stream_settings TEXT, tag TEXT, sniffing TEXT,"
        "traffic_reset TEXT)"
    )
    conn.execute("CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT)")
    settings = {
        "clients": [
            {
                "id": "11111111-1111-1111-1111-111111111111",
                "email": "alice@example.com",
                "enable": True,
                "flow": "xtls-rprx-vision",
                "subId": "alice-sub-token",
            }
        ],
        "decryption": "none",
    }
    stream = {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
            "dest": "www.microsoft.com:443",
            "serverNames": ["www.microsoft.com"],
            "privateKey": "aGVsbG8tdGVzdC1wcml2YXRlLWtleS0xMjM0NTY",  # may fail derive; still stored
            "shortIds": ["abcd"],
            "fingerprint": "chrome",
        },
    }
    sniffing = {"enabled": True, "destOverride": ["http", "tls", "quic"]}
    conn.execute(
        "INSERT INTO inbounds VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            1, 0, 1000, 2000, 0, "VLESS Reality", 1, 0, "", 443, "vless",
            json.dumps(settings), json.dumps(stream), "vless-reality",
            json.dumps(sniffing), "never",
        ),
    )
    tmpl = {
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
            {
                "tag": "proxy-warp",
                "protocol": "wireguard",
                "settings": {"secretKey": "x", "address": ["10.0.0.1/32"], "peers": []},
            },
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {"type": "field", "inboundTag": ["api"], "outboundTag": "api"},
                {
                    "type": "field",
                    "ruleTag": "block-ads",
                    "domain": ["geosite:category-ads-all"],
                    "outboundTag": "block",
                },
                {
                    "type": "field",
                    "inboundTag": ["vless-reality"],
                    "outboundTag": "proxy-warp",
                },
                {"type": "field", "network": "tcp,udp", "outboundTag": "direct"},
            ],
        },
    }
    conn.execute(
        "INSERT INTO settings(key, value) VALUES (?, ?)",
        ("xrayTemplateConfig", json.dumps(tmpl)),
    )
    conn.execute(
        "INSERT INTO settings(key, value) VALUES (?, ?)",
        ("subPath", "oldpath"),
    )
    conn.commit()
    conn.close()


def test_stream_and_route_converters():
    st = M.stream_from_xray({
        "network": "ws",
        "security": "tls",
        "wsSettings": {"path": "/ws", "host": "a.example", "heartbeatPeriod": 15},
        "tlsSettings": {"serverName": "a.example", "alpn": ["h2"], "certificates": []},
    })
    if st["network"] != "ws" or st["security"] != "tls":
        fail("stream_from_xray", f"got {st['network']}/{st['security']}")
    if st["ws"]["path"] != "/ws" or st["ws"]["heartbeat"] != 15:
        fail("stream_from_xray ws", str(st["ws"]))
    rule = M.route_from_xray_rule(
        {"type": "field", "domain": ["geosite:cn"], "outboundTag": "direct", "ruleTag": "cn"},
        idx=1,
    )
    if not rule or rule["outbound"] != "direct" or rule["domain"] != ["geosite:cn"]:
        fail("route_from_xray_rule", str(rule))
    skipped = M.route_from_xray_rule(
        {"type": "field", "network": "tcp,udp", "outboundTag": "direct"},
        idx=2,
    )
    if skipped is not None:
        fail("route catch-all skip", str(skipped))
    ok("converters")


def test_parse_and_apply():
    with tempfile.TemporaryDirectory() as td:
        db = Path(td) / "x-ui.db"
        _mk_db(db)
        users = M.parse_3xui_sqlite(db)
        if len(users) != 1 or users[0].email != "alice@example.com":
            fail("parse users", str(users))
        if users[0].extra.get("inbounds") != ["vless-reality"]:
            fail("client inbound tag", str(users[0].extra))
        meta = M.LAST_SOURCE_META or {}
        if meta.get("inbounds", 0) < 1 or meta.get("outbounds", 0) < 1:
            fail("meta structure counts", str(meta))
        structure = meta.get("structure") or {}
        store = _empty_store()
        # seed a system-like empty ensure
        xray.ensure_inbounds(store)
        rep = M.apply_3xui_structure(store, structure)
        if rep["inbounds_created"] < 1:
            fail("inbounds_created", str(rep))
        ib = xray.inbound_by_tag(store, "vless-reality")
        if not ib or ib["protocol"] != "vless":
            fail("inbound present", str(ib))
        if ib["stream"]["security"] != "reality":
            fail("reality security", str(ib.get("stream")))
        if rep["outbounds_created"] < 1:
            fail("outbounds_created", str(rep))
        tags = {o["tag"] for o in store["outbounds_custom"]}
        if "proxy-warp" not in tags:
            fail("outbound tag", tags)
        if rep["routes_created"] < 1:
            fail("routes_created", str(rep))
        names = {r["name"] for r in store["routes"]}
        if "block-ads" not in names:
            fail("route names", names)
        # apply clients onto restored tags
        arep = M.apply(store, users, inbound_tags=[], update_existing=True)
        if arep["created"] != 1:
            fail("client created", str(arep))
        c = store["clients"][0]
        if "vless-reality" not in (c.get("inbounds") or []):
            fail("client bound to restored inbound", str(c.get("inbounds")))
        ok("parse+apply structure")


def test_to_dict_keeps_inbounds():
    u = M.NormalizedUser(email="a@b.c", extra={"inbounds": ["t1", "t2"]})
    d = u.to_dict()
    if d.get("inbounds") != ["t1", "t2"]:
        fail("to_dict inbounds", str(d))
    ok("to_dict inbounds")


def test_missing_ext_geo_skipped():
    store = _empty_store()
    with tempfile.TemporaryDirectory() as td:
        old_dir = xray.GEO_DIR
        xray.GEO_DIR = Path(td)
        try:
            only_ext = {"name": "x3-6", "enabled": True, "outbound": "direct",
                        "domain": ["ext:geosite_RU.dat:ru-available-only-inside"],
                        "inbound_tags": ["vless"]}
            mixed = {"name": "mix", "enabled": True, "outbound": "direct",
                     "domain": ["ext:geosite_RU.dat:ru", "regexp:.*\\.ru$"]}
            if xray._rule_from_route(store, only_ext) is not None:
                fail("ext skip", "rule with only missing ext domains must be skipped")
            rule = xray._rule_from_route(store, mixed)
            if not rule or rule.get("domain") != ["regexp:.*\\.ru$"]:
                fail("ext partial", str(rule))
            store["routes"] = [only_ext, mixed]
            if xray.missing_ext_geo(store) != ["geosite_RU.dat"]:
                fail("missing list", str(xray.missing_ext_geo(store)))
            (Path(td) / "geosite_RU.dat").write_bytes(b"x" * 2048)
            rule = xray._rule_from_route(store, only_ext)
            if not rule or rule.get("domain") != only_ext["domain"]:
                fail("ext present", str(rule))
            if xray.missing_ext_geo(store):
                fail("missing after download", str(xray.missing_ext_geo(store)))
        finally:
            xray.GEO_DIR = old_dir
    ok("missing ext geo skipped until downloaded")


def main() -> None:
    print("== x-ui structure offline ==")
    test_stream_and_route_converters()
    test_to_dict_keeps_inbounds()
    test_parse_and_apply()
    test_missing_ext_geo_skipped()
    print("all passed")


if __name__ == "__main__":
    main()
