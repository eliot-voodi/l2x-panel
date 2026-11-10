"""Shared security helpers: token compare, SSRF guards, CSRF, rate limits, API scopes."""
from __future__ import annotations

import hmac
import ipaddress
import secrets
import socket
import threading
import time
from typing import Iterable
from urllib.parse import urlparse

# ---------------------------------------------------------------- token compare

def token_eq(a: str | None, b: str | None) -> bool:
    """Constant-time equality that never raises on length mismatch."""
    x = (a or "").encode("utf-8")
    y = (b or "").encode("utf-8")
    if len(x) != len(y):
        # still burn a compare so timing stays similar for empty/wrong length
        hmac.compare_digest(x, x)
        return False
    return hmac.compare_digest(x, y)


def any_token_eq(got: str | None, candidates: Iterable[str | None]) -> bool:
    return any(token_eq(got, c) for c in candidates if c)


# ---------------------------------------------------------------- client IP / trusted proxies

DEFAULT_TRUSTED_PROXIES = ("127.0.0.1", "::1")


def _ip_in_list(ip: str, allowed: Iterable[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for item in allowed:
        item = (item or "").strip()
        if not item:
            continue
        try:
            if "/" in item:
                if addr in ipaddress.ip_network(item, strict=False):
                    return True
            elif addr == ipaddress.ip_address(item):
                return True
        except ValueError:
            continue
    return False


def client_ip(request, trusted_proxies: Iterable[str] | None = None) -> str:
    """Peer IP; honor X-Forwarded-For only when the direct peer is a trusted proxy."""
    peer = ""
    try:
        if request.client and request.client.host:
            peer = str(request.client.host)
    except Exception:
        peer = ""
    trusted = list(trusted_proxies) if trusted_proxies is not None else list(DEFAULT_TRUSTED_PROXIES)
    if peer and _ip_in_list(peer, trusted):
        xf = (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
        if xf:
            return xf
        xr = (request.headers.get("x-real-ip") or "").strip()
        if xr:
            return xr
    return peer or "?"


# ---------------------------------------------------------------- rate limit

class RateLimiter:
    """Simple sliding-window counter (process-local)."""

    def __init__(self):
        self._lock = threading.Lock()
        self._hits: dict[str, list[float]] = {}

    def allow(self, key: str, *, limit: int, window_sec: float) -> bool:
        now = time.time()
        with self._lock:
            bucket = [t for t in self._hits.get(key, []) if now - t < window_sec]
            if len(bucket) >= limit:
                self._hits[key] = bucket
                return False
            bucket.append(now)
            self._hits[key] = bucket
            # opportunistic prune
            if len(self._hits) > 5000:
                stale = [k for k, v in self._hits.items() if not v or now - v[-1] > window_sec * 2]
                for k in stale[:500]:
                    self._hits.pop(k, None)
            return True


LOGIN_LIMITER = RateLimiter()
API_LIMITER = RateLimiter()
AGENT_LIMITER = RateLimiter()


# ---------------------------------------------------------------- CSRF

def ensure_csrf(session: dict) -> str:
    tok = session.get("csrf_token")
    if not tok or not isinstance(tok, str) or len(tok) < 16:
        tok = secrets.token_urlsafe(32)
        session["csrf_token"] = tok
    return tok


def csrf_ok(session: dict, got: str | None) -> bool:
    expected = session.get("csrf_token") or ""
    return bool(expected) and token_eq(str(got or ""), str(expected))


# ---------------------------------------------------------------- API scopes

API_SCOPE_CHOICES = (
    ("read", "Чтение (status, списки)"),
    ("clients", "Клиенты (CRUD)"),
    ("inbounds", "Inbounds"),
    ("xray", "Xray config / restart"),
    ("backup", "Скачивание backup"),
    ("admin", "Полный доступ"),
)

# path prefix → required scope (admin always allowed)
_API_SCOPE_RULES: list[tuple[tuple[str, ...], str]] = [
    (("backup",), "backup"),
    (("xray", "restart"), "xray"),
    (("xray", "config"), "xray"),
    (("clients",), "clients"),
    (("inbounds",), "inbounds"),
    (("l2tp",), "read"),
    (("outbounds",), "read"),
    (("server",), "read"),
]


def normalize_scopes(raw) -> list[str]:
    if raw is None:
        return ["admin"]  # legacy tokens without scopes
    if isinstance(raw, str):
        items = [x.strip() for x in raw.replace(",", " ").split() if x.strip()]
    elif isinstance(raw, (list, tuple, set)):
        items = [str(x).strip() for x in raw if str(x).strip()]
    else:
        items = []
    known = {k for k, _ in API_SCOPE_CHOICES}
    out = []
    for s in items:
        if s in known and s not in out:
            out.append(s)
    return out or ["read"]


def scope_allows(scopes: list[str] | None, parts: list[str]) -> bool:
    sc = normalize_scopes(scopes if scopes is not None else ["admin"])
    if "admin" in sc or "*" in sc:
        return True
    need = "read"
    for prefix, scope in _API_SCOPE_RULES:
        if tuple(parts[: len(prefix)]) == prefix:
            need = scope
            break
    return need in sc


def required_scope(parts: list[str]) -> str:
    for prefix, scope in _API_SCOPE_RULES:
        if tuple(parts[: len(prefix)]) == prefix:
            return scope
    return "read"


# ---------------------------------------------------------------- agent manage scopes

# Read-ish actions always allowed with valid agent token
MANAGE_READ = frozenset({
    "", "snapshot", "status", "check_xray", "get_logs", "xray_config", "xray_debug",
    "nodes", "refresh_l2tp",
})
# Mutating ops OK on agents; blocked on master unless allow_master_manage
MANAGE_WRITE = frozenset({
    "restart_xray", "update_xray", "rollback_xray", "apply_xray", "l2tp_connect", "l2tp_disconnect",
    "select_best_l2tp", "save_panel", "enable_agent", "node_diag", "ensure_network_perf",
})
# High-impact: need confirm + blocked on master by default
MANAGE_ADMIN = frozenset({
    "set_admin_password", "update_panel", "rollback_panel", "restart_panel", "restore_master",
})


def manage_action_allowed(*, action: str, is_master: bool, allow_master_manage: bool) -> tuple[bool, str]:
    a = (action or "").strip()
    if a in MANAGE_READ:
        return True, ""
    if a in MANAGE_ADMIN or a in MANAGE_WRITE:
        if is_master and not allow_master_manage:
            return False, "remote manage на master отключён (nodes.allow_master_manage)"
        return True, ""
    # unknown actions: allow only if master manage enabled (compat) else deny write-unknown on master
    if is_master and not allow_master_manage:
        return False, f"unknown/blocked action on master: {a}"
    return True, ""


# ---------------------------------------------------------------- SSRF / URL allow

_BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def _is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved:
        return False
    for net in _BLOCKED_NETWORKS:
        if addr in net:
            return False
    return True


def validate_outbound_url(
    url: str,
    *,
    allow_http: bool = False,
    resolve: bool = True,
) -> str:
    """Return cleaned URL or raise ValueError if unsafe (SSRF)."""
    raw = (url or "").strip()
    if not raw or len(raw) > 2048:
        raise ValueError("пустой или слишком длинный URL")
    parsed = urlparse(raw)
    scheme = (parsed.scheme or "").lower()
    if scheme not in (("http", "https") if allow_http else ("https",)):
        raise ValueError("разрешён только HTTPS URL" if not allow_http else "нужен http(s) URL")
    host = (parsed.hostname or "").strip().lower()
    if not host:
        raise ValueError("нет hostname в URL")
    if host in ("localhost", "metadata.google.internal"):
        raise ValueError(f"запрещённый host: {host}")
    # literal IP in URL
    try:
        ipaddress.ip_address(host)
        is_literal_ip = True
    except ValueError:
        is_literal_ip = False
    if is_literal_ip:
        if not _is_public_ip(host):
            raise ValueError(f"запрещённый IP: {host}")
        return raw

    if not resolve:
        return raw
    try:
        infos = socket.getaddrinfo(host, parsed.port or (443 if scheme == "https" else 80), type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ValueError(f"DNS {host}: {exc}") from exc
    ips = {info[4][0] for info in infos}
    if not ips:
        raise ValueError(f"DNS {host}: нет адресов")
    for ip in ips:
        if not _is_public_ip(ip):
            raise ValueError(f"URL резолвится в приватный/запрещённый адрес {ip}")
    return raw


# ---------------------------------------------------------------- SSH host key pin

def ssh_key_fingerprint(key) -> str:
    """SHA256 fingerprint in OpenSSH style: SHA256:<base64>."""
    import base64
    import hashlib
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")
