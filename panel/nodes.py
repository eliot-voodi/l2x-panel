"""Multi-node registry: push Xray config / clients to remote L2X agents."""
from __future__ import annotations

import json
import secrets
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from typing import Any


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def ensure_list(store: dict) -> list[dict]:
    nodes = store.setdefault("nodes", [])
    for n in nodes:
        n.setdefault("id", str(uuid.uuid4()))
        n.setdefault("name", n.get("url") or "node")
        n.setdefault("url", "")
        n.setdefault("token", "")
        n.setdefault("enabled", True)
        n.setdefault("sync_clients", True)
        n.setdefault("sync_inbounds", True)
        n.setdefault("last_sync", "")
        n.setdefault("last_error", "")
        n.setdefault("last_ok", False)
    return nodes


def agent_token(store: dict) -> str:
    s = store.setdefault("settings", {}).setdefault("nodes", {})
    if not s.get("agent_token"):
        s["agent_token"] = secrets.token_urlsafe(32)
    s.setdefault("agent_enabled", False)
    return s["agent_token"]


def build_payload(store: dict, node: dict, build_config) -> dict:
    """Subset for a remote agent: clients + inbounds + xray config without local L2TP ifaces."""
    clients = store.get("clients") or []
    inbounds = store.get("inbounds") or []
    # Build config then strip L2TP sockopt outbounds → freedom (remote has no l2x-* ifaces)
    cfg = build_config(store)
    outbounds = []
    for o in cfg.get("outbounds") or []:
        tag = o.get("tag") or ""
        sock = ((o.get("streamSettings") or {}).get("sockopt") or {})
        if tag.startswith("l2tp_") or sock.get("interface", "").startswith("l2x-"):
            outbounds.append({"tag": tag, "protocol": "freedom", "settings": {"domainStrategy": "UseIPv4"}})
        else:
            outbounds.append(o)
    cfg["outbounds"] = outbounds
    return {
        "clients": clients if node.get("sync_clients", True) else [],
        "inbounds": inbounds if node.get("sync_inbounds", True) else [],
        "outbounds_custom": store.get("outbounds_custom") or [],
        "routes": store.get("routes") or [],
        "balancers": store.get("balancers") or {},
        "dns": store.get("dns") or {},
        "xray_settings": store.get("xray_settings") or {},
        "config": cfg,
        "pushed_at": now_iso(),
        "node_id": node.get("id"),
    }


def push(node: dict, payload: dict, timeout: int = 60) -> dict:
    url = (node.get("url") or "").rstrip("/") + "/agent/apply"
    token = node.get("token") or ""
    data = json.dumps(payload, ensure_ascii=False).encode()
    req = urllib.request.Request(url, data=data, method="POST", headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
        "User-Agent": "L2XPanel-NodeSync/1.0",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode()
            try:
                parsed = json.loads(body)
            except json.JSONDecodeError:
                parsed = {"ok": resp.status < 300, "raw": body[:500]}
            ok = bool(parsed.get("ok", resp.status < 300))
            node["last_sync"] = now_iso()
            node["last_ok"] = ok
            node["last_error"] = "" if ok else str(parsed.get("error") or body[:300])
            return parsed if isinstance(parsed, dict) else {"ok": ok}
    except Exception as exc:  # noqa: BLE001
        node["last_sync"] = now_iso()
        node["last_ok"] = False
        node["last_error"] = str(exc)
        return {"ok": False, "error": str(exc)}


def apply_agent_payload(store: dict, payload: dict, apply_config) -> dict:
    """Merge pushed payload into local store and apply Xray."""
    if payload.get("clients") is not None:
        store["clients"] = payload["clients"]
    if payload.get("inbounds") is not None:
        store["inbounds"] = payload["inbounds"]
    if payload.get("outbounds_custom") is not None:
        store["outbounds_custom"] = payload["outbounds_custom"]
    if payload.get("routes") is not None:
        store["routes"] = payload["routes"]
    if payload.get("balancers") is not None:
        store["balancers"] = payload["balancers"]
    if payload.get("dns") is not None:
        store["dns"] = payload["dns"]
    if payload.get("xray_settings") is not None:
        store["xray_settings"] = payload["xray_settings"]
    # Prefer applying the remote-built config if present and valid; else rebuild locally
    if payload.get("config"):
        # write via apply_config path by temporarily setting store and calling apply
        pass
    result = apply_config(store)
    return result
