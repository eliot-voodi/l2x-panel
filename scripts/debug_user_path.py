#!/usr/bin/env python3
"""Offline checks for per-user cosmetic WS paths."""
from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PANEL = ROOT / "panel"
sys.path.insert(0, str(PANEL))


def ok(name: str) -> None:
    print(f"  OK  {name}")


def main() -> None:
    for name in ("xray_runtime.py", "front.py"):
        ast.parse((PANEL / name).read_text(encoding="utf-8"))
    ok("AST")

    import front
    import xray_runtime as x

    c = x.ensure_client({"email": "a@b.c", "sub_token": "tok"})
    assert c["link_token"]
    store = {
        "inbounds": [
            {
                "tag": "ws1",
                "enabled": True,
                "protocol": "vless",
                "share_host": "ex.com",
                "port": 1001,
                "listen": "127.0.0.1",
                "stream": {"network": "ws", "security": "none", "ws": {"path": "/ws"}},
            }
        ],
        "clients": [c],
        "settings": {"panel": {"public_host": "ex.com"}, "doh": {}},
    }
    path = x.client_cosmetic_path(store, c, store["inbounds"][0])
    assert path == f"/u-{c['link_token']}", path
    plan = front.plan(store)
    loc = (plan.get("sites") or {}).get("ex.com") or []
    assert loc and loc[0].get("user_path_re") == r"^/u-[A-Za-z0-9_-]+$"
    gate = front._location_user_path(loc[0])
    assert "rewrite ^ /ws break" in gate
    assert f"location ~ {loc[0]['user_path_re']}" in gate
    ok("single inbound gate")

    store["inbounds"].append(
        {
            "tag": "xh1",
            "enabled": True,
            "protocol": "vless",
            "share_host": "ex.com",
            "port": 1002,
            "listen": "127.0.0.1",
            "stream": {"network": "xhttp", "security": "none", "xhttp": {"path": "/xh"}},
        }
    )
    p2 = x.client_cosmetic_path(store, c, store["inbounds"][0])
    assert p2.startswith("/u-ws1-"), p2
    plan2 = front.plan(store)
    locs = plan2["sites"]["ex.com"]
    assert any("u-ws1-" in (l.get("user_path_re") or "") for l in locs)
    ok("multi inbound prefix")
    print("ALL PASSED")


if __name__ == "__main__":
    main()
