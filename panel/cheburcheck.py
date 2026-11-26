"""Cheburcheck.ru — list + optional dynamic TSPU probe for node domains.

Free:  GET /api/v1/check?target=…
Probe: GET /api/v1/probe/?id=…  (Bearer API token; SSE verdicts include tspu_block)
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

API_BASE = "https://cheburcheck.ru/api/v1"
CHECK_PAGE = "https://cheburcheck.ru/check"

# Minutes between automatic checks (0 = off)
INTERVAL_CHOICES: list[tuple[int, str]] = [
    (0, "выкл"),
    (15, "15 мин"),
    (30, "30 мин"),
    (60, "1 ч"),
    (180, "3 ч"),
    (360, "6 ч"),
    (720, "12 ч"),
    (1440, "24 ч"),
]

# Dynamic probe verdicts that mean «blocked for users in RU»
BLOCK_VERDICTS = frozenset({"tspu_block", "sni_block", "dns_spoofing", "cdn_block"})


def default_settings() -> dict:
    return {
        "enabled": True,
        "interval_min": 60,
        # Optional Cheburcheck API token — enables SSE /probe for real TSPU/SNI
        "api_token": "",
        "use_probe": True,
        "last_run_at": "",
        "last_error": "",
    }


def ensure_settings(store: dict) -> dict:
    s = store.setdefault("settings", {})
    cfg = s.setdefault("tspu", {})
    for k, v in default_settings().items():
        cfg.setdefault(k, v)
    return cfg


def normalize_interval(raw) -> int:
    try:
        v = int(raw or 0)
    except (TypeError, ValueError):
        return 0
    allowed = {m for m, _ in INTERVAL_CHOICES}
    return v if v in allowed else 0


def interval_label(minutes: int) -> str:
    for m, label in INTERVAL_CHOICES:
        if m == int(minutes or 0):
            return label
    return "выкл"


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def check_url(domain: str) -> str:
    d = (domain or "").strip().lower().rstrip(".")
    return f"{CHECK_PAGE}?target={quote(d)}" if d else CHECK_PAGE


def node_domain(node: dict) -> str:
    """Hostname to check for a node (domain field, else URL host)."""
    d = str(node.get("domain") or "").strip().lower().rstrip(".")
    if d:
        # strip scheme/path if pasted as URL
        if "://" in d:
            try:
                from urllib.parse import urlparse
                d = (urlparse(d).hostname or d).lower().rstrip(".")
            except Exception:
                pass
        return d
    url = str(node.get("url") or "").strip()
    if not url:
        return ""
    try:
        from urllib.parse import urlparse
        return (urlparse(url if "://" in url else f"https://{url}").hostname or "").lower().rstrip(".")
    except Exception:
        return ""


def ensure_node_fields(node: dict) -> None:
    node.setdefault("tspu_status", "")       # ok | blocked | error | ""
    node.setdefault("tspu_blocked", None)    # True/False/None
    node.setdefault("tspu_detail", "")
    node.setdefault("tspu_checked_at", "")
    node.setdefault("tspu_error", "")
    node.setdefault("tspu_verdicts", [])


def _http_json(url: str, *, headers: dict | None = None, timeout: float = 25.0) -> dict:
    req = Request(url, headers={"Accept": "application/json", "User-Agent": "L2XPanel-TSPU/1.0", **(headers or {})})
    with urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8", "replace")
    data = json.loads(raw) if raw else {}
    if not isinstance(data, dict):
        raise ValueError("unexpected JSON root")
    return data


def _http_sse(url: str, *, headers: dict | None = None, timeout: float = 90.0) -> list[tuple[str, dict]]:
    """Read named SSE events until event=done or stream ends."""
    req = Request(
        url,
        headers={
            "Accept": "text/event-stream",
            "User-Agent": "L2XPanel-TSPU/1.0",
            **(headers or {}),
        },
    )
    events: list[tuple[str, dict]] = []
    with urlopen(req, timeout=timeout) as resp:
        event_name = "message"
        data_lines: list[str] = []
        while True:
            line = resp.readline()
            if not line:
                break
            try:
                text = line.decode("utf-8", "replace").rstrip("\r\n")
            except Exception:
                continue
            if text.startswith(":"):
                continue
            if text.startswith("event:"):
                event_name = text[6:].strip() or "message"
                continue
            if text.startswith("data:"):
                data_lines.append(text[5:].lstrip())
                continue
            if text == "" and data_lines:
                payload = "\n".join(data_lines)
                data_lines = []
                try:
                    obj = json.loads(payload) if payload else {}
                except json.JSONDecodeError:
                    obj = {"raw": payload}
                if not isinstance(obj, dict):
                    obj = {"value": obj}
                events.append((event_name, obj))
                if event_name == "done":
                    break
                event_name = "message"
    return events


def check_lists(target: str, *, timeout: float = 25.0) -> dict[str, Any]:
    """GET /check — no auth. Returns API JSON (+ normalized helpers)."""
    t = (target or "").strip()
    if not t:
        return {"ok": False, "error": "empty target"}
    url = f"{API_BASE}/check?{urlencode({'target': t})}"
    try:
        data = _http_json(url, timeout=timeout)
    except HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8", "replace")[:300]
        except Exception:
            pass
        return {"ok": False, "error": f"HTTP {exc.code}: {body or exc.reason}"}
    except (URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as exc:
        return {"ok": False, "error": str(exc)[:300]}
    blocked = bool(data.get("blocked"))
    subnets = data.get("blocked_subnets") or []
    if isinstance(subnets, list) and subnets:
        blocked = True
    if data.get("rkn_domain"):
        blocked = True
    return {
        "ok": True,
        "id": data.get("id"),
        "target": data.get("target") or t,
        "blocked": blocked,
        "lists_blocked": bool(data.get("blocked") or data.get("rkn_domain") or subnets),
        "ips": list(data.get("ips") or []),
        "geo": data.get("geo") or {},
        "raw": data,
    }


def probe_dynamic(check_id: str, api_token: str, *, timeout: float = 90.0) -> dict[str, Any]:
    """GET /probe/?id=… — needs Bearer token. Aggregates SSE verdicts."""
    token = (api_token or "").strip()
    cid = (check_id or "").strip()
    if not token:
        return {"ok": False, "error": "no api_token", "skipped": True}
    if not cid:
        return {"ok": False, "error": "no check id", "skipped": True}
    url = f"{API_BASE}/probe/?{urlencode({'id': cid})}"
    try:
        events = _http_sse(
            url,
            headers={"Authorization": f"Bearer {token}"},
            timeout=timeout,
        )
    except HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8", "replace")[:300]
        except Exception:
            pass
        return {"ok": False, "error": f"probe HTTP {exc.code}: {body or exc.reason}"}
    except (URLError, TimeoutError, OSError, ValueError) as exc:
        return {"ok": False, "error": f"probe: {exc}"[:300]}

    verdicts: list[str] = []
    results = 0
    for name, obj in events:
        if name != "result":
            continue
        results += 1
        for v in obj.get("verdicts") or []:
            vs = str(v or "").strip().lower()
            if vs and vs not in verdicts:
                verdicts.append(vs)
    block_hits = [v for v in verdicts if v in BLOCK_VERDICTS]
    return {
        "ok": True,
        "results": results,
        "verdicts": verdicts,
        "blocked": bool(block_hits),
        "block_hits": block_hits,
        "tspu": "tspu_block" in verdicts,
        "sni": "sni_block" in verdicts,
    }


def check_target(target: str, *, api_token: str = "", use_probe: bool = True) -> dict[str, Any]:
    """Full check: lists always; dynamic probe when token present."""
    lists = check_lists(target)
    if not lists.get("ok"):
        return {
            "ok": False,
            "status": "error",
            "blocked": None,
            "detail": lists.get("error") or "check failed",
            "verdicts": [],
            "lists": lists,
            "probe": None,
        }

    probe = None
    token = (api_token or "").strip()
    if use_probe and token and lists.get("id"):
        probe = probe_dynamic(str(lists["id"]), token)
        if not probe.get("ok") and not probe.get("skipped"):
            # lists ok but probe failed — still report lists; mark soft error in detail
            blocked = bool(lists.get("blocked"))
            detail = "список" if blocked else "ок"
            if probe.get("error"):
                detail = f"{detail}; probe: {probe['error']}"
            return {
                "ok": True,
                "status": "blocked" if blocked else "ok",
                "blocked": blocked,
                "detail": detail,
                "verdicts": [],
                "lists": lists,
                "probe": probe,
            }

    blocked = bool(lists.get("blocked"))
    verdicts: list[str] = []
    reasons: list[str] = []
    if blocked:
        reasons.append("список")
    if probe and probe.get("ok"):
        verdicts = list(probe.get("verdicts") or [])
        if probe.get("blocked"):
            blocked = True
            if probe.get("tspu"):
                reasons.append("ТСПУ")
            if probe.get("sni"):
                reasons.append("SNI")
            for h in probe.get("block_hits") or []:
                if h not in ("tspu_block", "sni_block") and h not in reasons:
                    reasons.append(h.replace("_", " "))
    detail = ", ".join(reasons) if reasons else ("ок" if not blocked else "блок")
    return {
        "ok": True,
        "status": "blocked" if blocked else "ok",
        "blocked": blocked,
        "detail": detail,
        "verdicts": verdicts,
        "lists": lists,
        "probe": probe,
    }


def apply_result(node: dict, result: dict) -> dict | None:
    """Write result onto node. Returns a change event dict if blocked flipped, else None."""
    ensure_node_fields(node)
    prev = node.get("tspu_blocked")
    if not result.get("ok") and result.get("status") == "error":
        node["tspu_status"] = "error"
        node["tspu_error"] = str(result.get("detail") or "error")[:400]
        node["tspu_checked_at"] = now_iso()
        # do not flip tspu_blocked on hard errors — avoid false TG spam
        return None

    blocked = bool(result.get("blocked"))
    node["tspu_status"] = "blocked" if blocked else "ok"
    node["tspu_blocked"] = blocked
    node["tspu_detail"] = str(result.get("detail") or "")[:200]
    node["tspu_verdicts"] = list(result.get("verdicts") or [])[:20]
    node["tspu_error"] = ""
    node["tspu_checked_at"] = now_iso()

    if prev is None:
        return None  # first baseline — no notify
    if bool(prev) == blocked:
        return None
    return {
        "type": "tspu_blocked" if blocked else "tspu_unblocked",
        "name": node.get("name") or node.get("id") or "node",
        "domain": node_domain(node),
        "detail": node.get("tspu_detail") or "",
        "node_id": node.get("id") or "",
    }


def due(cfg: dict, now: float | None = None) -> bool:
    """True if automatic cycle should run."""
    if not cfg.get("enabled", True):
        return False
    interval = normalize_interval(cfg.get("interval_min"))
    if interval <= 0:
        return False
    last = str(cfg.get("last_run_at") or "").strip()
    if not last:
        return True
    try:
        ts = datetime.fromisoformat(last.replace("Z", "+00:00"))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - ts).total_seconds()
        return age >= interval * 60
    except Exception:
        return True


def run_cycle(store: dict, *, force: bool = False) -> list[dict]:
    """Check all node domains. Mutates store nodes + settings.tspu. Returns change events."""
    cfg = ensure_settings(store)
    if not force and not due(cfg):
        return []
    token = str(cfg.get("api_token") or "")
    use_probe = bool(cfg.get("use_probe", True))
    events: list[dict] = []
    nodes = store.get("nodes") or []
    if not isinstance(nodes, list):
        return []
    errors: list[str] = []
    for n in nodes:
        if not isinstance(n, dict):
            continue
        ensure_node_fields(n)
        domain = node_domain(n)
        if not domain:
            n["tspu_status"] = ""
            n["tspu_blocked"] = None
            n["tspu_detail"] = ""
            continue
        result = check_target(domain, api_token=token, use_probe=use_probe)
        ev = apply_result(n, result)
        if ev:
            events.append(ev)
        if result.get("status") == "error":
            errors.append(f"{n.get('name') or domain}: {result.get('detail')}")
        # polite spacing vs cheburcheck rate limits
        time.sleep(0.35)
    cfg["last_run_at"] = now_iso()
    cfg["last_error"] = "; ".join(errors)[:500] if errors else ""
    return events
