"""Subscription HWID device limits.

Apps without X-HWID can still be counted by a fallback fingerprint built from the
subscription request headers (the client token is implicit: devices live on the client):
    device — app name + X-Device-OS + X-Device-Model (needs OS or model);
    ua     — like device, but app name alone is enough (weak: same app on two phones = one device).
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any

FALLBACK_MODES = ("off", "device", "ua")
KIND_LABELS = {"hwid": "HWID", "device": "ОС + модель", "ua": "только приложение"}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def hash_hwid(raw: str) -> str:
    return hashlib.sha256(raw.strip().encode()).hexdigest()


def _trim(value: str, n: int = 512) -> str:
    return (value or "").strip()[:n]


LINK_PREVIEW_BOTS = ("bot", "facebookexternalhit", "whatsapp", "skypeuripreview", "vkshare", "embedly")


def app_name(user_agent: str) -> str:
    """Client app without version: 'v2rayNG/1.9.16' → 'v2rayng', 'Happ/3.2 (iOS)' → 'happ'.

    Real browsers get the HTML page (Accept: text/html) before the gate, so a 'Mozilla/…' UA here
    is an app posing as a browser (V2Box, Shadowrocket…): it is identified by its platform part.
    """
    ua = (user_agent or "").strip()
    low = ua.lower()
    if any(b in low for b in LINK_PREVIEW_BOTS):
        return ""
    m = re.match(r"\s*([A-Za-z][A-Za-z0-9._-]*)", ua)
    if not m:
        return ""
    name = m.group(1).lower()
    if name == "mozilla":
        platform = re.search(r"\(([^)]*)\)", ua)
        return f"mozilla[{platform.group(1).strip().lower()[:96]}]" if platform else ""
    # Generic HTTP libraries say nothing about the device
    return "" if name in ("curl", "wget", "python-requests", "go-http-client", "okhttp") else name


def fallback_fingerprint(request_headers: dict[str, str], mode: str) -> tuple[str, str]:
    """(raw, kind) for requests without X-HWID; ("", "") when headers are not enough for `mode`."""
    if mode not in ("device", "ua"):
        return "", ""
    app = app_name(request_headers.get("user-agent") or "")
    os_name = _trim(request_headers.get("x-device-os") or "", 64).lower()
    model = _trim(request_headers.get("x-device-model") or "", 128).lower()
    if not app:
        return "", ""
    if os_name or model:
        return f"fp:{app}|{os_name}|{model}", "device"
    if mode == "ua":
        return f"fp:{app}||", "ua"
    return "", ""


def ensure(client: dict) -> dict:
    client.setdefault("limit_hwid", 0)
    client.setdefault("hwids", [])
    return client


def devices(client: dict) -> list[dict]:
    return list(ensure(client).get("hwids") or [])


def clear(client: dict) -> int:
    n = len(ensure(client).get("hwids") or [])
    client["hwids"] = []
    return n


def status(client: dict) -> dict:
    ensure(client)
    limit = int(client.get("limit_hwid") or 0)
    registered = len(client.get("hwids") or [])
    remaining = max(0, limit - registered) if limit > 0 else None
    return {
        "active": limit > 0,
        "limit": limit,
        "registered": registered,
        "remaining": remaining,
        "full": limit > 0 and registered >= limit,
    }


def gate(client: dict, request_headers: dict[str, str], *, register: bool = True, required: bool = False,
         fallback: str = "off") -> dict[str, Any]:
    """Evaluate HWID for a subscription body request.

    required=True rejects requests without X-HWID even when the client has no device limit
    (a fallback fingerprint never satisfies it).
    fallback: off | device | ua — how to count apps that send no X-HWID (see module doc).
    Without a limit and without `required` nothing is blocked, but devices are still recorded
    (reason "inactive", recorded=True) so the admin sees them before setting a limit.
    Returns {allowed, reason, headers, limit, registered, kind, recorded}.
    reason: ok | inactive | missing | short | full
    """
    request_headers = {k.lower(): v for k, v in request_headers.items()}
    ensure(client)
    limit = int(client.get("limit_hwid") or 0)
    active = limit > 0 or required
    headers = {"X-Hwid-Active": "true" if active else "false"}

    def result(allowed: bool, reason: str, kind: str = "", recorded: bool = False) -> dict[str, Any]:
        return {"allowed": allowed, "reason": reason, "headers": headers, "limit": limit,
                "registered": len(client["hwids"]), "kind": kind, "recorded": recorded}

    raw = (request_headers.get("x-hwid") or "").strip()
    kind = "hwid"
    if limit > 0:
        headers["X-Hwid-Limit"] = str(limit)
    if raw and len(raw) < 6:
        if active:
            headers["X-Hwid-Not-Supported"] = "true"
            return result(False, "short")
        raw = ""
    if not raw and not required:
        # Without a limit we only observe, so even an app-only fingerprint is worth listing
        raw, kind = fallback_fingerprint(request_headers, fallback if active else "ua")
    if not raw:
        if not active:
            return result(True, "inactive")
        headers["X-Hwid-Not-Supported"] = "true"
        return result(False, "missing")
    ok_reason = "ok" if active else "inactive"

    digest = hash_hwid(raw)
    now = now_iso()
    meta = {
        "ua": _trim(request_headers.get("user-agent") or ""),
        "os": _trim(request_headers.get("x-device-os") or ""),
        "os_ver": _trim(request_headers.get("x-ver-os") or ""),
        "model": _trim(request_headers.get("x-device-model") or ""),
    }
    for d in client["hwids"]:
        if d.get("hash") == digest:
            if register:
                d["last_seen"] = now
                for k, v in meta.items():
                    if v:
                        d[k] = v
            return result(True, ok_reason, kind, recorded=register)

    if limit > 0 and len(client["hwids"]) >= limit:
        headers["X-Hwid-Max-Devices-Reached"] = "true"
        headers["X-Hwid-Limit"] = "true"
        return result(False, "full", kind)

    if register:
        client["hwids"].append({
            "hash": digest, "first_seen": now, "last_seen": now, "kind": kind,
            "ua": meta["ua"], "os": meta["os"], "os_ver": meta["os_ver"], "model": meta["model"],
            "fp": digest[:12],
        })
        if limit <= 0 and len(client["hwids"]) > 50:
            client["hwids"] = sorted(client["hwids"], key=lambda d: d.get("last_seen") or "")[-50:]
    return result(True, ok_reason, kind, recorded=register)


def public_list(client: dict) -> list[dict]:
    """Admin-safe device list (no full hash)."""
    out = []
    for d in devices(client):
        out.append({
            "fp": d.get("fp") or (d.get("hash") or "")[:12],
            "kind": d.get("kind") or "hwid",
            "first_seen": d.get("first_seen") or "",
            "last_seen": d.get("last_seen") or "",
            "ua": d.get("ua") or "",
            "os": d.get("os") or "",
            "os_ver": d.get("os_ver") or "",
            "model": d.get("model") or "",
        })
    return out
