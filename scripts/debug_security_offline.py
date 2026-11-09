#!/usr/bin/env python3
"""Offline debug suite for security hardening (no network, no root)."""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PANEL = ROOT / "panel"
sys.path.insert(0, str(PANEL))
os.environ.setdefault("L2XPANEL_COOKIE_INSECURE", "1")
os.environ.setdefault("L2XPANEL_DATA", tempfile.mkdtemp(prefix="l2x-sec-"))

import security as sec  # noqa: E402


def ok(name: str) -> None:
    print(f"  OK  {name}")


def fail(name: str, msg: str) -> None:
    print(f" FAIL {name}: {msg}")
    raise SystemExit(1)


def test_token_eq():
    assert sec.token_eq("abc", "abc")
    assert not sec.token_eq("abc", "abd")
    assert not sec.token_eq("abc", "ab")  # length mismatch must not raise
    assert not sec.token_eq("", "x")
    assert sec.any_token_eq("t1", ["", "t1", "t2"])
    assert not sec.any_token_eq("nope", ["a", "b"])
    ok("token_eq / any_token_eq")


def test_ssrf():
    try:
        sec.validate_outbound_url("http://127.0.0.1/x", allow_http=True)
        fail("ssrf-loopback", "should reject 127.0.0.1")
    except ValueError:
        pass
    try:
        sec.validate_outbound_url("https://169.254.169.254/latest", allow_http=False)
        fail("ssrf-meta", "should reject link-local")
    except ValueError:
        pass
    try:
        sec.validate_outbound_url("ftp://example.com/x")
        fail("ssrf-scheme", "should reject ftp")
    except ValueError:
        pass
    # public https without resolve for speed
    u = sec.validate_outbound_url("https://example.com/geo.dat", allow_http=False, resolve=False)
    assert u.startswith("https://")
    ok("SSRF validate_outbound_url")


def test_scopes():
    assert sec.scope_allows(["admin"], ["backup"])
    assert sec.scope_allows(["backup"], ["backup"])
    assert not sec.scope_allows(["read"], ["backup"])
    assert not sec.scope_allows(["read"], ["xray", "config"])
    assert sec.scope_allows(["xray"], ["xray", "config"])
    assert sec.scope_allows(["clients"], ["clients", "list"])
    assert not sec.scope_allows(["read"], ["clients", "add"])
    assert sec.normalize_scopes(None) == ["admin"]  # legacy
    assert "read" in sec.normalize_scopes([])
    ok("API scopes")


def test_manage_policy():
    ok_a, _ = sec.manage_action_allowed(action="snapshot", is_master=True, allow_master_manage=False)
    assert ok_a
    bad, why = sec.manage_action_allowed(action="set_admin_password", is_master=True, allow_master_manage=False)
    assert not bad and "allow_master_manage" in why
    ok_b, _ = sec.manage_action_allowed(action="set_admin_password", is_master=False, allow_master_manage=False)
    assert ok_b
    ok_c, _ = sec.manage_action_allowed(action="restart_xray", is_master=False, allow_master_manage=False)
    assert ok_c
    ok("manage action policy")


def test_rate_limiter():
    lim = sec.RateLimiter()
    assert lim.allow("k", limit=2, window_sec=60)
    assert lim.allow("k", limit=2, window_sec=60)
    assert not lim.allow("k", limit=2, window_sec=60)
    ok("RateLimiter")


def test_client_ip():
    class R:
        def __init__(self, host, headers):
            self.client = type("C", (), {"host": host})()
            self.headers = headers

    # untrusted peer → ignore XFF
    ip = sec.client_ip(R("8.8.8.8", {"x-forwarded-for": "1.2.3.4"}), ["127.0.0.1"])
    assert ip == "8.8.8.8"
    # trusted peer → honor XFF
    ip2 = sec.client_ip(R("127.0.0.1", {"x-forwarded-for": "1.2.3.4"}), ["127.0.0.1"])
    assert ip2 == "1.2.3.4"
    ok("client_ip trusted proxies")


def test_imports_and_syntax():
    import ast
    for name in ("app.py", "security.py", "webhooks.py", "ops.py", "nodes.py", "front.py"):
        src = (PANEL / name).read_text(encoding="utf-8")
        ast.parse(src)
    ok("AST parse core modules")


def test_front_no_root_api():
    text = (PANEL / "front.py").read_text(encoding="utf-8")
    # location for /panel/api/ at root should be gone
    assert 'location ^~ /panel/api/' not in text
    ok("nginx: no root /panel/api/")


def test_basepath_public():
    # Importing app needs many deps; check source instead if import fails
    text = (PANEL / "app.py").read_text(encoding="utf-8")
    assert 'PUBLIC = ("/sub/", "/api/sub/", "/health", "/static/")' in text
    assert 'https_only=not _COOKIE_INSECURE' in text
    assert "import security as sec" in text
    assert "allow_master_manage" in text
    ok("app.py BasePath/PUBLIC + cookie + security import")


def test_fastapi_smoke():
    """Boot FastAPI app with TestClient if deps present."""
    try:
        from fastapi.testclient import TestClient
    except Exception as exc:
        print(f"  SKIP TestClient ({exc})")
        return
    # Avoid systemd / xray side effects as much as possible
    os.environ["L2XPANEL_COOKIE_INSECURE"] = "1"
    try:
        import app as panel_app
    except Exception as exc:
        print(f"  SKIP app import ({exc})")
        return
    client = TestClient(panel_app.app)
    # public health is minimal
    r = client.get("/health")
    assert r.status_code == 200, r.text
    data = r.json()
    assert data.get("status") == "ok"
    assert "version" not in data and "role" not in data
    ok("GET /health minimal")

    # login page sets csrf
    r = client.get("/login")
    # may 404 without base_path middleware if path required — base_path is auto-created
    # After import, base_path should exist; login is under base path rewrite
    # Without bp in URL, BasePath returns 404 for /login
    store = panel_app._load_store()
    bp = ((store.get("settings") or {}).get("panel") or {}).get("base_path") or ""
    login_path = f"/{bp}/login" if bp else "/login"
    r = client.get(login_path)
    assert r.status_code == 200, r.text
    assert "csrf-token" in r.text
    ok("login page has csrf meta")

    # POST without csrf → 403
    r = client.post(login_path, data={"username": "x", "password": "y"})
    assert r.status_code == 403, r.text
    ok("login POST without csrf → 403")

    # Force secret path and ensure root /panel/api/ is hidden
    with panel_app.mutate() as st:
        st.setdefault("settings", {}).setdefault("panel", {})["base_path"] = "SecTestPath99"
    panel_app._refresh_settings_cache()
    r = client.get("/panel/api/server/status")
    assert r.status_code == 404, r.text
    r = client.get("/SecTestPath99/panel/api/server/status")
    assert r.status_code in (401, 403), r.text  # reachable under bp, needs token
    ok("root /panel/api/ blocked; under base_path requires auth")

    # manage admin blocked on master by default
    with panel_app.mutate() as st:
        ns = st.setdefault("settings", {}).setdefault("nodes", {})
        ns["agent_token"] = "test-agent-token-aaaaaaaa"
        ns["role"] = "master"
        ns["agent_enabled"] = False
        ns["allow_master_manage"] = False
    panel_app._refresh_settings_cache()
    r = client.post(
        "/SecTestPath99/agent/manage",
        headers={"Authorization": "Bearer test-agent-token-aaaaaaaa"},
        json={"action": "set_admin_password", "password": "12345678", "confirm": "yes"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body.get("ok") is False and "allow_master_manage" in (body.get("error") or "")
    ok("master manage admin action blocked")


def main():
    print("== L2X security offline debug ==")
    test_token_eq()
    test_ssrf()
    test_scopes()
    test_manage_policy()
    test_rate_limiter()
    test_client_ip()
    test_imports_and_syntax()
    test_front_no_root_api()
    test_basepath_public()
    test_fastapi_smoke()
    print("ALL PASSED")


if __name__ == "__main__":
    main()
