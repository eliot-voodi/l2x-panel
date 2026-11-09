#!/usr/bin/env python3
"""Offline checks for WARP / WARP+ outbound registration helpers."""
from __future__ import annotations

import ast
import sys
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
PANEL = ROOT / "panel"
sys.path.insert(0, str(PANEL))


def ok(name: str) -> None:
    print(f"  OK  {name}")


def fail(name: str, msg: str) -> None:
    print(f" FAIL {name}: {msg}")
    raise SystemExit(1)


def test_source():
    text = (PANEL / "ops.py").read_text(encoding="utf-8")
    assert "def warp_register(license_key" in text
    assert "/account" in text
    assert '"license"' in text
    app = (PANEL / "app.py").read_text(encoding="utf-8")
    assert "warp_license" in app
    ui = (PANEL / "ui" / "outbounds.html").read_text(encoding="utf-8")
    assert 'name="warp_license"' in ui
    for name in ("ops.py", "app.py"):
        ast.parse((PANEL / name).read_text(encoding="utf-8"))
    ok("source + AST")


def test_warp_register_applies_license():
    import ops

    calls: list[tuple] = []

    def fake_run(cmd, *a, **k):
        return {"ok": True, "stdout": "PrivateKey: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=\nPublicKey: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=\n", "stderr": ""}

    def fake_http(url, timeout=30, data=None, headers=None, method=None):
        calls.append((method or ("POST" if data else "GET"), url, data, headers))
        if url.endswith("/reg") and (method or "POST") == "POST":
            import json
            return json.dumps({
                "id": "dev-1",
                "token": "tok-1",
                "account": {"warp_plus": False, "account_type": "free"},
                "config": {
                    "client_id": "AAAA",
                    "interface": {"addresses": {"v4": "172.16.0.2"}},
                    "peers": [{"public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                               "endpoint": {"host": "engage.cloudflareclient.com:2408"}}],
                },
            }).encode()
        if "/account" in url and method == "PUT":
            import json
            body = json.loads(data.decode())
            assert body.get("license") == "KEY-1234-PLUS"
            return json.dumps({
                "warp_plus": True, "account_type": "unlimited", "premium_data": 10_000_000_000, "quota": 0,
            }).encode()
        raise AssertionError(f"unexpected {method} {url}")

    with mock.patch.object(ops, "_run", side_effect=fake_run), mock.patch.object(ops, "_http", side_effect=fake_http):
        res = ops.warp_register("KEY-1234-PLUS")
    assert res.get("ok"), res
    assert res.get("warp_plus") is True
    assert res["config"]["protocol"] == "wireguard"
    assert any(c[0] == "PUT" and "/account" in c[1] for c in calls)
    ok("warp_register applies license via PUT")


def test_warp_register_free_no_put():
    import ops

    calls: list[str] = []

    def fake_run(cmd, *a, **k):
        return {"ok": True, "stdout": "PrivateKey: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=\nPublicKey: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=\n", "stderr": ""}

    def fake_http(url, timeout=30, data=None, headers=None, method=None):
        calls.append(method or "GET")
        import json
        return json.dumps({
            "id": "dev-2", "token": "tok-2", "account": {"warp_plus": False},
            "config": {"interface": {"addresses": {"v4": "172.16.0.2"}}, "peers": [{}]},
        }).encode()

    with mock.patch.object(ops, "_run", side_effect=fake_run), mock.patch.object(ops, "_http", side_effect=fake_http):
        res = ops.warp_register("")
    assert res.get("ok")
    assert res.get("warp_plus") is False
    assert "PUT" not in calls
    ok("free WARP skips license PUT")


def main():
    print("== L2X WARP+ offline debug ==")
    test_source()
    test_warp_register_applies_license()
    test_warp_register_free_no_put()
    print("ALL PASSED")


if __name__ == "__main__":
    main()
