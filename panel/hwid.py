"""Subscription HWID device limits."""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def hash_hwid(raw: str) -> str:
    return hashlib.sha256(raw.strip().encode()).hexdigest()


def _trim(value: str, n: int = 512) -> str:
    return (value or "").strip()[:n]


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


def gate(client: dict, request_headers: dict[str, str], *, register: bool = True, required: bool = False) -> dict[str, Any]:
    """Evaluate HWID for a subscription body request.

    required=True rejects requests without X-HWID even when the client has no device limit.
    Returns {allowed, reason, headers, limit, registered}.
    reason: ok | inactive | missing | short | full
    """
    ensure(client)
    limit = int(client.get("limit_hwid") or 0)
    headers = {"X-Hwid-Active": "true" if limit > 0 or required else "false"}
    if limit <= 0 and not required:
        return {"allowed": True, "reason": "inactive", "headers": headers, "limit": 0, "registered": len(client.get("hwids") or [])}

    raw = (request_headers.get("x-hwid") or request_headers.get("X-HWID") or "").strip()
    if limit > 0:
        headers["X-Hwid-Limit"] = str(limit)
    if not raw:
        headers["X-Hwid-Not-Supported"] = "true"
        return {"allowed": False, "reason": "missing", "headers": headers, "limit": limit, "registered": len(client["hwids"])}
    if len(raw) < 6:
        headers["X-Hwid-Not-Supported"] = "true"
        return {"allowed": False, "reason": "short", "headers": headers, "limit": limit, "registered": len(client["hwids"])}

    digest = hash_hwid(raw)
    now = now_iso()
    meta = {
        "ua": _trim(request_headers.get("user-agent") or request_headers.get("User-Agent") or ""),
        "os": _trim(request_headers.get("x-device-os") or request_headers.get("X-Device-OS") or ""),
        "os_ver": _trim(request_headers.get("x-ver-os") or request_headers.get("X-Ver-OS") or ""),
        "model": _trim(request_headers.get("x-device-model") or request_headers.get("X-Device-Model") or ""),
    }
    for d in client["hwids"]:
        if d.get("hash") == digest:
            if register:
                d["last_seen"] = now
                for k, v in meta.items():
                    if v:
                        d[k] = v
            return {"allowed": True, "reason": "ok", "headers": headers, "limit": limit, "registered": len(client["hwids"])}

    if limit > 0 and len(client["hwids"]) >= limit:
        headers["X-Hwid-Max-Devices-Reached"] = "true"
        headers["X-Hwid-Limit"] = "true"
        return {"allowed": False, "reason": "full", "headers": headers, "limit": limit, "registered": len(client["hwids"])}

    if register:
        client["hwids"].append({
            "hash": digest, "first_seen": now, "last_seen": now,
            "ua": meta["ua"], "os": meta["os"], "os_ver": meta["os_ver"], "model": meta["model"],
            "fp": digest[:12],
        })
        if limit <= 0 and len(client["hwids"]) > 50:
            client["hwids"] = sorted(client["hwids"], key=lambda d: d.get("last_seen") or "")[-50:]
    return {"allowed": True, "reason": "ok", "headers": headers, "limit": limit, "registered": len(client["hwids"])}


def public_list(client: dict) -> list[dict]:
    """Admin-safe device list (no full hash)."""
    out = []
    for d in devices(client):
        out.append({
            "fp": d.get("fp") or (d.get("hash") or "")[:12],
            "first_seen": d.get("first_seen") or "",
            "last_seen": d.get("last_seen") or "",
            "ua": d.get("ua") or "",
            "os": d.get("os") or "",
            "os_ver": d.get("os_ver") or "",
            "model": d.get("model") or "",
        })
    return out
