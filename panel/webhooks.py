"""Outbound webhooks for panel events."""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Callable


EVENTS = (
    "client.created", "client.updated", "client.deleted", "client.expired", "client.limited",
    "client.hwid_full", "tunnel.down", "tunnel.up", "login", "backup", "node.sync",
)


def default_settings() -> dict:
    return {"enabled": False, "urls": [], "secret": "", "events": list(EVENTS)}


def ensure(settings: dict) -> dict:
    wh = settings.setdefault("webhooks", default_settings())
    wh.setdefault("enabled", False)
    wh.setdefault("urls", [])
    wh.setdefault("secret", "")
    wh.setdefault("events", list(EVENTS))
    return wh


def _post(url: str, payload: dict, secret: str, timeout: int = 8) -> None:
    data = json.dumps(payload, ensure_ascii=False).encode()
    req = urllib.request.Request(url, data=data, method="POST", headers={
        "Content-Type": "application/json",
        "User-Agent": "L2XPanel-Webhook/1.0",
        **({"X-L2X-Secret": secret} if secret else {}),
    })
    try:
        urllib.request.urlopen(req, timeout=timeout).read()
    except (urllib.error.URLError, TimeoutError, OSError):
        pass


def fire(settings: dict, event: str, data: dict[str, Any] | None = None) -> None:
    wh = ensure(settings)
    if not wh.get("enabled"):
        return
    if event not in (wh.get("events") or EVENTS):
        return
    urls = [u for u in (wh.get("urls") or []) if isinstance(u, str) and u.startswith("http")]
    if not urls:
        return
    payload = {
        "event": event,
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "data": data or {},
    }
    secret = str(wh.get("secret") or "")

    def run():
        for url in urls:
            _post(url, payload, secret)

    threading.Thread(target=run, daemon=True).start()


def fire_store(get_settings: Callable[[], dict], event: str, data: dict | None = None) -> None:
    try:
        fire(get_settings(), event, data)
    except Exception:
        pass
