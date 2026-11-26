"""Dashboard connection analytics: OS / client apps / city × inbound.

Sources
-------
- ``client.hwids`` — subscription devices (UA, X-Device-OS) → OS & apps pie
- Online IPs (``client.ips`` / live ONLINE) + GeoIP → cities
- Client inbound assignment + online/sub hits → city × inbound matrix
- Optional Xray ``access.log`` accepted lines → visit-based city × inbound

Geo resolution uses a local JSON cache; lookups go to ip-api.com (free, no key)
with rate limiting. Private IPs are labeled «LAN».
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

DATA = Path(os.environ.get("L2XPANEL_DATA", "/var/lib/l2xpanel"))
ANALYTICS_FILE = Path(os.environ.get(
    "L2XPANEL_CONN_ANALYTICS",
    str(DATA / "conn_analytics.json"),
))
GEO_CACHE_FILE = Path(os.environ.get(
    "L2XPANEL_IP_GEO_CACHE",
    str(DATA / "ip_geo_cache.json"),
))
XRAY_ACCESS_LOG = Path(os.environ.get("L2XPANEL_XRAY_ACCESS", "/var/log/xray/access.log"))

_LOCK = threading.RLock()
_GEO_MEM: dict[str, dict] = {}
_GEO_LAST_HTTP = 0.0
_STATE: dict[str, Any] | None = None

# ip-api.com free: 45 req/min
_GEO_MIN_INTERVAL = 1.5

_PRIVATE_RE = re.compile(
    r"^(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|::1|fc|fd|fe80)",
    re.I,
)

# access.log: from 1.2.3.4:12345 accepted … [inbound -> outbound] email: user
_ACCESS_RE = re.compile(
    r"from\s+(\d{1,3}(?:\.\d{1,3}){3}|\[?[0-9a-fA-F:]+\]?):\d+\s+accepted\s+"
    r".*?\[([^\]]*)\].*?email:\s*([^\s\]]+)",
    re.I,
)
_ACCESS_RE_ALT = re.compile(
    r"from\s+(\d{1,3}(?:\.\d{1,3}){3}):\d+.*?email:\s*([^\s\]]+)",
    re.I,
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _empty_day() -> dict:
    return {
        "os": {},
        "apps": {},
        "cities": {},
        "inbounds": {},
        "nodes": {},
        "city_inbound": {},  # "City|||inbound_tag" → count
        "city_node": {},  # "City|||host" → count
        "visits_city_inbound": {},
        "sub_hits": 0,
        "online_hits": 0,
    }


def _load_state() -> dict:
    global _STATE
    with _LOCK:
        if _STATE is not None:
            return _STATE
        data: dict = {"version": 1, "days": {}, "access_offset": 0}
        try:
            if ANALYTICS_FILE.is_file():
                raw = json.loads(ANALYTICS_FILE.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    data.update(raw)
                    data.setdefault("days", {})
                    data.setdefault("access_offset", 0)
        except Exception:
            pass
        _STATE = data
        return _STATE


def _save_state() -> None:
    with _LOCK:
        st = _load_state()
        try:
            DATA.mkdir(parents=True, exist_ok=True)
            tmp = ANALYTICS_FILE.with_suffix(".tmp")
            tmp.write_text(json.dumps(st, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
            tmp.replace(ANALYTICS_FILE)
        except Exception:
            pass


def _day_bucket(st: dict, day: str | None = None) -> dict:
    day = day or _today()
    days = st.setdefault("days", {})
    if day not in days or not isinstance(days[day], dict):
        days[day] = _empty_day()
    b = days[day]
    for k, v in _empty_day().items():
        b.setdefault(k, v if not isinstance(v, dict) else {})
    # prune > 45 days
    if len(days) > 50:
        for old in sorted(days.keys())[:-45]:
            days.pop(old, None)
    return b


def _bump(counter: dict, key: str, n: int = 1) -> None:
    key = str(key or "").strip() or "?"
    if len(key) > 120:
        key = key[:120]
    counter[key] = int(counter.get(key) or 0) + max(1, int(n))


# ---------------------------------------------------------------- geo

def _load_geo_cache() -> dict:
    with _LOCK:
        if _GEO_MEM:
            return _GEO_MEM
        try:
            if GEO_CACHE_FILE.is_file():
                raw = json.loads(GEO_CACHE_FILE.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    _GEO_MEM.update({str(k): v for k, v in raw.items() if isinstance(v, dict)})
        except Exception:
            pass
        return _GEO_MEM


def _save_geo_cache() -> None:
    with _LOCK:
        try:
            DATA.mkdir(parents=True, exist_ok=True)
            # keep last 20k entries
            items = list(_GEO_MEM.items())
            if len(items) > 20000:
                items = items[-20000:]
                _GEO_MEM.clear()
                _GEO_MEM.update(items)
            tmp = GEO_CACHE_FILE.with_suffix(".tmp")
            tmp.write_text(json.dumps(dict(items), ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
            tmp.replace(GEO_CACHE_FILE)
        except Exception:
            pass


def _is_private_ip(ip: str) -> bool:
    ip = (ip or "").strip().strip("[]")
    if not ip or ip in ("0.0.0.0", "::"):
        return True
    return bool(_PRIVATE_RE.match(ip))


def lookup_city(ip: str, *, allow_http: bool = True) -> dict:
    """Return {city, region, cc, label} for an IP (cached)."""
    ip = (ip or "").strip().strip("[]")
    if not ip or _is_private_ip(ip):
        return {"city": "LAN", "region": "", "cc": "", "label": "LAN", "cached": True}
    cache = _load_geo_cache()
    hit = cache.get(ip)
    if isinstance(hit, dict) and hit.get("label"):
        # refresh after 30 days
        if time.time() - float(hit.get("at") or 0) < 30 * 86400:
            return hit
    if not allow_http:
        return {"city": "?", "region": "", "cc": "", "label": "?", "cached": False}

    global _GEO_LAST_HTTP
    with _LOCK:
        wait = _GEO_MIN_INTERVAL - (time.time() - _GEO_LAST_HTTP)
    if wait > 0:
        time.sleep(min(wait, 3))

    row = {"city": "?", "region": "", "cc": "", "label": "?", "cached": False, "at": time.time()}
    try:
        url = f"http://ip-api.com/json/{quote(ip)}?fields=status,country,countryCode,regionName,city,query"
        req = urllib.request.Request(url, headers={"User-Agent": "L2XPanel-Geo/1.0"})
        with urllib.request.urlopen(req, timeout=4) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        _GEO_LAST_HTTP = time.time()
        if isinstance(data, dict) and data.get("status") == "success":
            city = str(data.get("city") or "").strip() or str(data.get("regionName") or "").strip() or "?"
            region = str(data.get("regionName") or "").strip()
            cc = str(data.get("countryCode") or "").strip().upper()
            label = city if not cc else f"{city}, {cc}"
            row = {
                "city": city,
                "region": region,
                "cc": cc,
                "country": str(data.get("country") or ""),
                "label": label,
                "cached": False,
                "at": time.time(),
            }
    except Exception as exc:  # noqa: BLE001
        row["error"] = str(exc)[:120]
        _GEO_LAST_HTTP = time.time()

    with _LOCK:
        cache[ip] = row
    # Persist occasionally
    if int(time.time()) % 17 == 0:
        _save_geo_cache()
    return row


# ---------------------------------------------------------------- normalize OS / app

def normalize_os(os_name: str = "", ua: str = "") -> str:
    raw = f"{os_name} {ua}".lower()
    if "android" in raw:
        return "Android"
    if "iphone" in raw or "ipad" in raw or "ios" in raw or "cfnetwork" in raw or "darwin" in raw:
        # Happ/INCY often send os=iOS; Darwin alone usually means Apple
        if "windows" in raw:
            return "Windows"
        if "android" in raw:
            return "Android"
        return "iOS"
    if "mac os" in raw or "macintosh" in raw or "macos" in raw:
        return "macOS"
    if "windows" in raw or "win64" in raw or "win32" in raw:
        return "Windows"
    if "linux" in raw:
        return "Linux"
    o = (os_name or "").strip()
    if o:
        return o[:32]
    return "Other"


def normalize_app(ua: str = "") -> str:
    """Keep Remnawave-style labels: Happ/4.7.4/ios, v2raytun/android, …"""
    ua = (ua or "").strip()
    if not ua:
        return "Unknown"
    low = ua.lower()
    if any(b in low for b in ("bot", "facebookexternalhit", "whatsapp", "skypeuripreview")):
        return "Preview/Bot"
    # Prefer first product token with version path
    m = re.match(r"\s*([A-Za-z][A-Za-z0-9._-]*/[^\s]+)", ua)
    if m:
        token = m.group(1)
        # Trim CFNetwork/Dalvik noise after first product
        if " " in token:
            token = token.split(" ", 1)[0]
        if not token.lower().startswith("mozilla"):
            return token[:80]
    # Mozilla disguised apps — use platform blob
    if low.startswith("mozilla"):
        plat = re.search(r"\(([^)]*)\)", ua)
        if plat:
            return f"Browser/{plat.group(1).strip()[:48]}"
        return "Browser"
    m2 = re.match(r"\s*([A-Za-z][A-Za-z0-9._-]*)", ua)
    return (m2.group(1) if m2 else ua)[:64]


def _client_inbound_tags(store: dict, client: dict) -> list[str]:
    """Enabled inbound tags assigned to the client (for city×inbound)."""
    try:
        import xray_runtime as xray
        tags = []
        for ib in xray.client_inbounds(store, client):
            if not isinstance(ib, dict) or not ib.get("enabled", True):
                continue
            tag = str(ib.get("tag") or "").strip()
            if tag:
                tags.append(tag)
        return tags
    except Exception:
        # Fallback: raw client.inbounds list
        raw = client.get("inbounds") or []
        if isinstance(raw, list):
            return [str(t).strip() for t in raw if str(t).strip()]
        return []


def _inbound_traffic_map(store: dict) -> dict[str, int]:
    out: dict[str, int] = {}
    for ib in store.get("inbounds") or []:
        if not isinstance(ib, dict):
            continue
        tag = str(ib.get("tag") or "").strip()
        if not tag:
            continue
        tr = ib.get("traffic") or {}
        out[tag] = int(tr.get("up") or 0) + int(tr.get("down") or 0)
    return out


def _likely_inbound_tag(store: dict, client: dict) -> str:
    """Best-effort inbound for routing analytics when access.log is off.

    Among the client's assigned inbounds, pick the one with the most panel traffic
    (proxy for «what clients actually use»). Falls back to first tag / (unassigned).
    """
    tags = _client_inbound_tags(store, client)
    if not tags:
        return "(unassigned)"
    traffic = _inbound_traffic_map(store)
    best = max(tags, key=lambda t: (int(traffic.get(t) or 0), -tags.index(t)))
    return best


def _client_node_hosts(store: dict, client: dict) -> list[str]:
    """Unique dial hosts from subscription endpoints (node side of the route)."""
    hosts: list[str] = []
    seen: set[str] = set()
    try:
        import xray_runtime as xray
        for e in xray.client_endpoints(store, client, None) or []:
            if not isinstance(e, dict):
                continue
            host = str(e.get("address") or e.get("host") or "").strip().lower()
            if not host or host in seen:
                continue
            seen.add(host)
            hosts.append(host)
            if len(hosts) >= 8:
                break
    except Exception:
        pass
    return hosts


# ---------------------------------------------------------------- record

def record_online_sample(store: dict, online: dict[str, list[str]] | None = None) -> None:
    """Watchdog hook: attribute current online IPs → city × likely inbound."""
    online = online or {}
    st = _load_state()
    day = _day_bucket(st)
    clients_by_email = {
        str(c.get("email") or ""): c
        for c in (store.get("clients") or [])
        if isinstance(c, dict) and c.get("email")
    }
    # Dedup IPs already counted this process-minute via day key set
    seen_key = f"_online_seen_{_today()}"
    seen: set[str] = set(st.get(seen_key) or [])
    dirty = False
    geo_budget = 8  # max HTTP lookups per watchdog tick

    def _attr(client: dict, ip: str, *, allow_http: bool) -> bool:
        nonlocal geo_budget, dirty
        ip = str(ip or "").strip()
        if not ip or _is_private_ip(ip):
            return False
        email = str(client.get("email") or "")
        mark = f"{email}|{ip}"
        if mark in seen:
            return False
        seen.add(mark)
        use_http = allow_http and geo_budget > 0
        geo = lookup_city(ip, allow_http=use_http)
        if use_http and not geo.get("cached") and geo.get("label") not in ("?", "LAN"):
            geo_budget -= 1
        city = geo.get("label") or geo.get("city") or "?"
        if city == "?":
            pend = st.setdefault("_pending_geo", [])
            if ip not in pend:
                pend.append(ip)
            return True
        tag = _likely_inbound_tag(store, client)
        _bump(day["cities"], city)
        _bump(day["inbounds"], tag)
        _bump(day["city_inbound"], f"{city}|||{tag}")
        for host in _client_node_hosts(store, client)[:4]:
            _bump(day.setdefault("nodes", {}), host)
            _bump(day.setdefault("city_node", {}), f"{city}|||{host}")
        day["online_hits"] = int(day.get("online_hits") or 0) + 1
        dirty = True
        return True

    for email, ips in online.items():
        client = clients_by_email.get(str(email) or "")
        if not client or not ips:
            continue
        for ip in ips:
            _attr(client, ip, allow_http=True)

    # Seed from stored client.ips when today's city bucket is still empty
    if not day["cities"]:
        for client in clients_by_email.values():
            for ip in list((client.get("ips") or {}) or {})[:12]:
                _attr(client, str(ip), allow_http=geo_budget > 0)

    st[seen_key] = list(seen)[-5000:]
    for k in list(st.keys()):
        if k.startswith("_online_seen_") and k != seen_key:
            st.pop(k, None)

    if dirty:
        _save_state()
        _save_geo_cache()


def record_sub_hit(
    store: dict,
    client: dict,
    *,
    ip: str = "",
    ua: str = "",
    os_name: str = "",
) -> None:
    """Successful machine-readable subscription fetch."""
    st = _load_state()
    day = _day_bucket(st)
    ua = ua or ""
    os_label = normalize_os(os_name, ua)
    app_label = normalize_app(ua)
    _bump(day["os"], os_label)
    _bump(day["apps"], app_label)
    day["sub_hits"] = int(day.get("sub_hits") or 0) + 1

    ip = (ip or "").strip()
    if ip and not _is_private_ip(ip):
        # Cache-only on the request path (no HTTP) so sub responses stay fast.
        geo = lookup_city(ip, allow_http=False)
        city = geo.get("label") or ""
        tag = _likely_inbound_tag(store, client)
        _bump(day["inbounds"], tag)
        if city and city != "?":
            _bump(day["cities"], city)
            _bump(day["city_inbound"], f"{city}|||{tag}")
            for host in _client_node_hosts(store, client)[:4]:
                _bump(day.setdefault("nodes", {}), host)
                _bump(day.setdefault("city_node", {}), f"{city}|||{host}")
        else:
            # Watchdog / history loop will resolve pending IPs via ip-api.
            pend = st.setdefault("_pending_geo", [])
            if ip not in pend:
                pend.append(ip)
                if len(pend) > 500:
                    del pend[:-400]
    _save_state()


def resolve_pending_geo(budget: int = 10) -> int:
    """Background: resolve IPs queued from sub hits / online without blocking HTTP requests."""
    st = _load_state()
    pend = list(st.get("_pending_geo") or [])
    if not pend:
        return 0
    n = 0
    left: list[str] = []
    for ip in pend:
        if n >= budget:
            left.append(ip)
            continue
        geo = lookup_city(ip, allow_http=True)
        if geo.get("label") and geo.get("label") not in ("?",):
            n += 1
        else:
            left.append(ip)
    st["_pending_geo"] = left[-400:]
    if n:
        _save_geo_cache()
    _save_state()
    return n


def ingest_access_log(*, max_lines: int = 4000) -> int:
    """Parse new access.log lines → visits_city_inbound. Returns new events count."""
    if not XRAY_ACCESS_LOG.is_file():
        return 0
    st = _load_state()
    day = _day_bucket(st)
    try:
        size = XRAY_ACCESS_LOG.stat().st_size
    except OSError:
        return 0
    offset = int(st.get("access_offset") or 0)
    if offset > size:
        offset = 0
    try:
        with XRAY_ACCESS_LOG.open("rb") as f:
            f.seek(offset)
            chunk = f.read()
            st["access_offset"] = f.tell()
    except OSError:
        return 0
    if not chunk:
        return 0
    text = chunk.decode("utf-8", "replace")
    lines = text.splitlines()[-max_lines:]
    n = 0
    geo_budget = 12
    for line in lines:
        if "accepted" not in line.lower():
            continue
        ip = ""
        inbound = ""
        email = ""
        m = _ACCESS_RE.search(line)
        if m:
            ip, bracket, email = m.group(1), m.group(2), m.group(3)
            # bracket like "am-ws -> proxy" or "am-ws >> proxy"
            inbound = re.split(r"\s*(?:->|>>|>)\s*", bracket.strip())[0].strip()
        else:
            m2 = _ACCESS_RE_ALT.search(line)
            if not m2:
                continue
            ip, email = m2.group(1), m2.group(2)
        ip = ip.strip("[]")
        email = email.strip()
        if not ip or _is_private_ip(ip):
            continue
        geo = lookup_city(ip, allow_http=geo_budget > 0)
        if geo_budget > 0 and not geo.get("cached"):
            geo_budget -= 1
        city = geo.get("label") or "?"
        tag = inbound or "(access)"
        _bump(day["visits_city_inbound"], f"{city}|||{tag}")
        _bump(day["cities"], city)
        if inbound:
            _bump(day["inbounds"], inbound)
            _bump(day["city_inbound"], f"{city}|||{tag}")
        n += 1
    if n:
        _save_state()
        _save_geo_cache()
    else:
        _save_state()
    return n


# ---------------------------------------------------------------- snapshot for UI

def _sum_days(st: dict, days: int = 7) -> dict:
    out = _empty_day()
    keys = sorted((st.get("days") or {}).keys())[-max(1, days):]
    for d in keys:
        b = st["days"].get(d) or {}
        for section in (
            "os", "apps", "cities", "inbounds", "nodes",
            "city_inbound", "city_node", "visits_city_inbound",
        ):
            src = b.get(section) or {}
            if not isinstance(src, dict):
                continue
            for k, v in src.items():
                _bump(out[section], str(k), int(v or 0))
        out["sub_hits"] = int(out.get("sub_hits") or 0) + int(b.get("sub_hits") or 0)
        out["online_hits"] = int(out.get("online_hits") or 0) + int(b.get("online_hits") or 0)
    return out


def _from_hwids(store: dict) -> tuple[Counter, Counter, int]:
    """Inventory of registered devices → OS / app counters.

    Apps without a User-Agent (common after HWID-only migrations) are skipped in
    the apps pie so «Unknown» does not drown real clients; OS still counts them.
    """
    os_c: Counter = Counter()
    app_c: Counter = Counter()
    skipped_ua = 0
    for client in store.get("clients") or []:
        if not isinstance(client, dict):
            continue
        for d in client.get("hwids") or []:
            if not isinstance(d, dict):
                continue
            ua = str(d.get("ua") or "").strip()
            if not ua:
                raw = d.get("raw") if isinstance(d.get("raw"), dict) else {}
                ua = str((raw or {}).get("ua") or "").strip()
            os_c[normalize_os(str(d.get("os") or ""), ua)] += 1
            if ua:
                app_c[normalize_app(ua)] += 1
            else:
                skipped_ua += 1
    return os_c, app_c, skipped_ua


def _top_rows(counter: dict | Counter, *, limit: int = 12) -> list[dict]:
    items = sorted(
        ((str(k), int(v or 0)) for k, v in dict(counter).items() if int(v or 0) > 0),
        key=lambda kv: (-kv[1], kv[0].lower()),
    )[:limit]
    total = sum(v for _, v in items) or 1
    return [
        {"name": name, "count": count, "pct": round(100.0 * count / total, 1)}
        for name, count in items
    ]


def _city_inbound_rows(counter: dict, *, limit: int = 40) -> list[dict]:
    rows = []
    for key, count in (counter or {}).items():
        parts = str(key).split("|||", 1)
        city = parts[0] if parts else "?"
        inbound = parts[1] if len(parts) > 1 else "?"
        rows.append({"city": city, "inbound": inbound, "count": int(count or 0)})
    rows.sort(key=lambda r: (-r["count"], r["city"], r["inbound"]))
    total = sum(r["count"] for r in rows) or 1
    for r in rows[:limit]:
        r["pct"] = round(100.0 * r["count"] / total, 1)
    return rows[:limit]


def dashboard_snapshot(store: dict, *, days: int = 7) -> dict:
    """Build pie/table payload for the Dashboard page."""
    st = _load_state()
    # Opportunistic access.log ingest (cheap if file missing)
    try:
        ingest_access_log(max_lines=2000)
    except Exception:
        pass
    summed = _sum_days(st, days)
    hw_os, hw_apps, apps_no_ua = _from_hwids(store)

    # Prefer live HWID inventory for OS; apps = devices with UA + recent sub hits.
    os_rows = _top_rows(hw_os or summed["os"], limit=10)
    merged_apps: Counter = Counter(hw_apps)
    for k, v in (summed.get("apps") or {}).items():
        if str(k) not in ("Unknown", "?"):
            merged_apps[str(k)] += int(v or 0)
    app_rows = _top_rows(merged_apps, limit=14)

    city_rows = _top_rows(summed["cities"], limit=12)
    inbound_rows = _top_rows(summed["inbounds"], limit=12)
    matrix = _city_inbound_rows(summed["city_inbound"], limit=50)
    visits_matrix = _city_inbound_rows(summed["visits_city_inbound"], limit=30)
    node_rows = _top_rows(summed.get("nodes") or {}, limit=12)
    city_node = _city_inbound_rows(summed.get("city_node") or {}, limit=40)
    # city_node rows use inbound key name — remap for UI
    for r in city_node:
        r["node"] = r.pop("inbound", "?")

    # Live rebuild from client.ips (cache-only) when history is empty or still
    # polluted by the old «all inbounds» fan-out (many equal inbound counts).
    need_live = not city_rows
    if matrix and len({r["inbound"] for r in matrix[:12]}) >= 6:
        # Heuristic: old fan-out made every inbound look equal — rebuild.
        counts = [r["count"] for r in matrix[:8]]
        if counts and max(counts) == min(counts):
            need_live = True

    if need_live:
        live_cities: Counter = Counter()
        live_matrix: Counter = Counter()
        live_inbounds: Counter = Counter()
        live_nodes: Counter = Counter()
        live_city_node: Counter = Counter()
        for c in store.get("clients") or []:
            if not isinstance(c, dict):
                continue
            tag = _likely_inbound_tag(store, c)
            hosts = _client_node_hosts(store, c)
            for ip in list((c.get("ips") or {}) or {})[:15]:
                geo = lookup_city(str(ip), allow_http=False)
                city = geo.get("label") or "?"
                if city == "?":
                    continue
                live_cities[city] += 1
                live_inbounds[tag] += 1
                live_matrix[f"{city}|||{tag}"] += 1
                for host in hosts[:4]:
                    live_nodes[host] += 1
                    live_city_node[f"{city}|||{host}"] += 1
        if live_cities:
            city_rows = _top_rows(live_cities, limit=12)
            matrix = _city_inbound_rows(dict(live_matrix), limit=50)
            inbound_rows = _top_rows(live_inbounds, limit=12)
            node_rows = _top_rows(live_nodes, limit=12)
            city_node = _city_inbound_rows(dict(live_city_node), limit=40)
            for r in city_node:
                r["node"] = r.pop("inbound", "?")

    access_on = False
    try:
        access_on = bool((store.get("xray_settings") or {}).get("access_log"))
    except Exception:
        pass

    return {
        "days": days,
        "os": os_rows,
        "apps": app_rows,
        "cities": city_rows,
        "inbounds": inbound_rows,
        "nodes": node_rows,
        "city_inbound": matrix,
        "city_node": city_node,
        "visits_city_inbound": visits_matrix,
        "sub_hits": int(summed.get("sub_hits") or 0),
        "online_hits": int(summed.get("online_hits") or 0),
        "hwid_devices": sum(hw_os.values()),
        "apps_without_ua": apps_no_ua,
        "access_log": access_on,
        "access_log_path": str(XRAY_ACCESS_LOG),
        "updated_at": _now_iso(),
    }
