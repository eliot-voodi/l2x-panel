"""Version history for panel store — snapshot, readable diff, rollback."""
from __future__ import annotations

import json
import os
import re
import secrets
import threading
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

HISTORY_DIR = Path(os.environ.get("L2XPANEL_DATA", "/var/lib/l2xpanel")) / "settings_versions"
INDEX_FILE = HISTORY_DIR / "index.json"
MAX_VERSIONS = 80
_LOCK = threading.RLock()
FORMAT_V2 = 2

TRACKED_KEYS = (
    "clients",
    "inbounds",
    "routes",
    "balancers",
    "outbounds_custom",
    "dns",
    "xray_settings",
    "settings",
    "l2tp",
    "certs",
    "doh_bundle",
    "ip_bans",
    "reverse",
)

_VOLATILE_CLIENT = {
    "traffic", "last_online", "ips", "tg_notify_expire_on", "tg_notify_low_gb",
}
_VOLATILE_INBOUND = {"traffic"}
_VOLATILE_L2TP = {
    "status", "last_error", "addr", "local_ip", "peer_ip", "public_ip", "vrf",
    "metrics", "connected_at", "latency_ms",
}
_VOLATILE_NODE = {"last_seen", "last_update", "online", "version", "error", "health"}

_REDACT_SEGMENTS = {
    "token", "password", "password_hash", "secret", "api_token", "agent_token",
    "pihole_password", "totp_secret", "private_key", "privatekey", "mldsa65_seed",
    "login_secret", "webhook_secret", "cert_key", "key_file", "sub_token",
    "doh_token", "uuid", "wg_private", "wg_public",
}

_KIND_LABEL = {
    "client": "Клиент",
    "inbound": "Inbound",
    "l2tp": "L2TP",
    "route": "Маршрут",
    "balancer": "Balancer",
    "outbound": "Outbound",
    "cert": "Сертификат",
    "doh": "DoH",
    "ban": "IP ban",
    "settings": "Настройки",
    "dns": "DNS",
    "xray_settings": "Xray",
    "reverse": "Reverse",
    "other": "Прочее",
}

_FIELD_LABELS = {
    "enabled": "вкл",
    "email": "email",
    "limit_gb": "лимит ГБ",
    "expire_at": "срок",
    "limit_ip": "лимит IP",
    "limit_hwid": "лимит HWID",
    "comment": "комментарий",
    "outbound": "outbound",
    "inbounds": "inbounds",
    "sub_enabled": "подписка",
    "tg_id": "TG id",
    "tg_username": "TG username",
    "port": "порт",
    "tag": "tag",
    "protocol": "протокол",
    "listen": "listen",
    "remark": "имя",
    "name": "имя",
    "host": "хост",
    "username": "логин",
    "fingerprint": "fingerprint",
    "network": "сеть",
    "security": "security",
    "sniffing": "sniffing",
    "title": "название",
    "theme": "тема",
    "lang": "язык",
    "timezone": "часовой пояс",
    "base_path": "base path",
    "session_hours": "сессия (ч)",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _ensure_dir() -> None:
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)


def _load_index() -> list[dict]:
    _ensure_dir()
    if not INDEX_FILE.exists():
        return []
    try:
        data = json.loads(INDEX_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except ValueError:
        return []


def _save_index(items: list[dict]) -> None:
    _ensure_dir()
    tmp = INDEX_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, INDEX_FILE)


def _redact_value(path: str, value: Any) -> Any:
    parts = {p.lower() for p in re.split(r"[.\[]", path) if p and p != "]"}
    if parts & _REDACT_SEGMENTS:
        if value in (None, "", [], {}):
            return value
        return "•••"
    return value


def _fmt_val(value: Any) -> str:
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "да" if value else "нет"
    if isinstance(value, float):
        return str(int(value)) if value.is_integer() else f"{value:g}"
    if isinstance(value, (list, dict)):
        try:
            text = json.dumps(value, ensure_ascii=False, sort_keys=True)
        except TypeError:
            text = str(value)
        return text if len(text) <= 120 else text[:117] + "…"
    text = str(value)
    return text if len(text) <= 120 else text[:117] + "…"


def _label_field(key: str) -> str:
    return _FIELD_LABELS.get(key, key)


class _Missing:
    pass


_MISSING = _Missing()


def flatten(obj: Any, prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    if isinstance(obj, dict):
        if not obj and prefix:
            out[prefix] = {}
            return out
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            out.update(flatten(v, key))
    elif isinstance(obj, list):
        if not obj and prefix:
            out[prefix] = []
            return out
        for i, v in enumerate(obj):
            out.update(flatten(v, f"{prefix}[{i}]"))
    else:
        out[prefix or "(root)"] = obj
    return out


def diff_maps(before: dict[str, Any], after: dict[str, Any]) -> list[dict[str, Any]]:
    keys = sorted(set(before) | set(after), key=lambda x: x.lower())
    rows = []
    for path in keys:
        a = before.get(path, _MISSING)
        b = after.get(path, _MISSING)
        if a == b:
            continue
        rows.append({
            "path": path,
            "before": None if a is _MISSING else _redact_value(path, a),
            "after": None if b is _MISSING else _redact_value(path, b),
            "op": "add" if a is _MISSING else ("remove" if b is _MISSING else "change"),
        })
    return rows


def diff_settings(a: dict | None, b: dict | None) -> list[dict[str, Any]]:
    return diff_maps(flatten(a or {}), flatten(b or {}))


def _strip_client(c: dict) -> dict:
    return {k: deepcopy(v) for k, v in c.items() if k not in _VOLATILE_CLIENT}


def _strip_inbound(ib: dict) -> dict:
    return {k: deepcopy(v) for k, v in ib.items() if k not in _VOLATILE_INBOUND}


def _strip_l2tp(item: dict) -> dict:
    return {k: deepcopy(v) for k, v in item.items() if k not in _VOLATILE_L2TP}


def _strip_settings(s: dict) -> dict:
    s = deepcopy(s or {})
    nodes = s.get("nodes")
    if isinstance(nodes, dict):
        for list_key in ("peers", "list"):
            peers = nodes.get(list_key)
            if isinstance(peers, list):
                nodes[list_key] = [
                    {k: v for k, v in p.items() if k not in _VOLATILE_NODE}
                    if isinstance(p, dict) else p
                    for p in peers
                ]
    return s


def canonical_state(store: dict | None) -> dict:
    """Stable subset of the panel store for history compare/snapshot."""
    store = store or {}
    out: dict[str, Any] = {}
    for key in TRACKED_KEYS:
        if key not in store:
            continue
        val = store[key]
        if key == "clients" and isinstance(val, list):
            out[key] = [_strip_client(c) for c in val if isinstance(c, dict)]
        elif key == "inbounds" and isinstance(val, list):
            out[key] = [_strip_inbound(i) for i in val if isinstance(i, dict)]
        elif key == "l2tp" and isinstance(val, list):
            out[key] = [_strip_l2tp(i) for i in val if isinstance(i, dict)]
        elif key == "settings" and isinstance(val, dict):
            out[key] = _strip_settings(val)
        else:
            out[key] = deepcopy(val)
    return out


def _is_v2_snapshot(data: dict) -> bool:
    return int(data.get("_format") or 0) == FORMAT_V2 and isinstance(data.get("state"), dict)


def _unwrap_snapshot(data: dict | None) -> dict:
    if not data:
        return {}
    if _is_v2_snapshot(data):
        return data["state"] if isinstance(data["state"], dict) else {}
    return {"settings": data}


def _index_list(items: list, id_keys: tuple[str, ...]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for i, item in enumerate(items or []):
        if not isinstance(item, dict):
            continue
        key = ""
        for k in id_keys:
            if item.get(k) not in (None, ""):
                key = str(item[k])
                break
        if not key:
            key = f"#{i}"
        out[key] = item
    return out


def _field_changes(before: dict, after: dict, *, skip: set[str] | None = None) -> list[dict]:
    skip = skip or set()
    keys = sorted((set(before) | set(after)) - skip, key=lambda x: x.lower())
    rows = []
    for key in keys:
        a = before.get(key, _MISSING)
        b = after.get(key, _MISSING)
        if a == b:
            continue
        path = key
        av = None if a is _MISSING else _redact_value(path, a)
        bv = None if b is _MISSING else _redact_value(path, b)
        if av == "•••" and bv == "•••":
            rows.append({
                "key": key, "label": _label_field(key),
                "before": "•••", "after": "••• (изменён)", "op": "change",
            })
            continue
        rows.append({
            "key": key, "label": _label_field(key),
            "before": None if a is _MISSING else av,
            "after": None if b is _MISSING else bv,
            "op": "add" if a is _MISSING else ("remove" if b is _MISSING else "change"),
        })
    return rows


def _entity_title(kind: str, item: dict, key: str) -> str:
    label = _KIND_LABEL.get(kind, kind)
    if kind == "client":
        name = item.get("email") or item.get("comment") or key
        return f"{label} «{name}»"
    if kind == "inbound":
        name = item.get("tag") or item.get("remark") or key
        proto = item.get("protocol") or ""
        return f"{label} «{name}»" + (f" ({proto})" if proto else "")
    if kind == "l2tp":
        return f"{label} «{item.get('name') or key}»"
    if kind in ("balancer", "outbound"):
        return f"{label} «{item.get('tag') or key}»"
    if kind == "cert":
        return f"{label} «{item.get('domain') or item.get('name') or key}»"
    if kind == "ban":
        return f"{label} «{item.get('ip') or key}»"
    if kind == "route":
        return f"{label} #{key.lstrip('#')}"
    return f"{label} «{key}»"


def _diff_entities(
    before_list: list,
    after_list: list,
    *,
    kind: str,
    id_keys: tuple[str, ...],
    skip_fields: set[str] | None = None,
) -> list[dict]:
    before_map = _index_list(before_list if isinstance(before_list, list) else [], id_keys)
    after_map = _index_list(after_list if isinstance(after_list, list) else [], id_keys)
    events: list[dict] = []
    for key in sorted(set(before_map) | set(after_map), key=lambda x: x.lower()):
        a = before_map.get(key)
        b = after_map.get(key)
        if a is None and b is not None:
            events.append({
                "op": "add", "kind": kind, "id": key,
                "title": _entity_title(kind, b, key), "text": "создан", "fields": [],
            })
        elif a is not None and b is None:
            events.append({
                "op": "remove", "kind": kind, "id": key,
                "title": _entity_title(kind, a, key), "text": "удалён", "fields": [],
            })
        else:
            fields = _field_changes(a or {}, b or {}, skip=skip_fields)
            if not fields:
                continue
            parts = []
            for f in fields[:8]:
                if f["op"] == "add":
                    parts.append(f"{f['label']}: {_fmt_val(f['after'])}")
                elif f["op"] == "remove":
                    parts.append(f"{f['label']}: удалено ({_fmt_val(f['before'])})")
                else:
                    parts.append(f"{f['label']}: {_fmt_val(f['before'])} → {_fmt_val(f['after'])}")
            extra = f" …+{len(fields) - 8}" if len(fields) > 8 else ""
            events.append({
                "op": "change", "kind": kind, "id": key,
                "title": _entity_title(kind, b or a or {}, key),
                "text": "; ".join(parts) + extra,
                "fields": [{
                    **f,
                    "before_fmt": _fmt_val(f["before"]) if f["before"] is not None else "—",
                    "after_fmt": _fmt_val(f["after"]) if f["after"] is not None else "—",
                } for f in fields],
            })
    return events


def _diff_dict_section(before: dict, after: dict, *, kind: str) -> list[dict]:
    before = before if isinstance(before, dict) else {}
    after = after if isinstance(after, dict) else {}
    if kind == "balancer" and (before or after) and all(
        isinstance(v, dict) for v in list(before.values()) + list(after.values())
    ):
        return _diff_entities(
            [{"tag": k, **v} for k, v in before.items()],
            [{"tag": k, **v} for k, v in after.items()],
            kind=kind, id_keys=("tag",),
        )
    rows = diff_settings(before, after)
    if not rows:
        return []
    fields = []
    parts = []
    for r in rows[:12]:
        label = r["path"]
        bits = [p for p in label.replace("[", ".").replace("]", "").split(".") if p]
        short = " · ".join(_label_field(p) if not p.isdigit() else p for p in bits)
        fields.append({
            "key": r["path"], "label": short or r["path"],
            "before": r["before"], "after": r["after"], "op": r["op"],
            "before_fmt": "—" if r["op"] == "add" else _fmt_val(r["before"]),
            "after_fmt": "—" if r["op"] == "remove" else _fmt_val(r["after"]),
        })
        if r["op"] == "add":
            parts.append(f"{short}: {_fmt_val(r['after'])}")
        elif r["op"] == "remove":
            parts.append(f"{short}: удалено")
        else:
            parts.append(f"{short}: {_fmt_val(r['before'])} → {_fmt_val(r['after'])}")
    extra = f" …+{len(rows) - 12}" if len(rows) > 12 else ""
    return [{
        "op": "change", "kind": kind, "id": kind,
        "title": _KIND_LABEL.get(kind, kind),
        "text": "; ".join(parts) + extra,
        "fields": fields,
    }]


def describe_changes(before: dict | None, after: dict | None) -> list[dict]:
    before = before or {}
    after = after or {}
    events: list[dict] = []
    events += _diff_entities(
        before.get("clients") or [], after.get("clients") or [],
        kind="client", id_keys=("uuid", "email"), skip_fields={"created_at"},
    )
    events += _diff_entities(
        before.get("inbounds") or [], after.get("inbounds") or [],
        kind="inbound", id_keys=("tag", "id"),
    )
    events += _diff_entities(
        before.get("l2tp") or [], after.get("l2tp") or [],
        kind="l2tp", id_keys=("name",), skip_fields={"password", "secret"},
    )
    events += _diff_entities(
        before.get("outbounds_custom") or [], after.get("outbounds_custom") or [],
        kind="outbound", id_keys=("tag",),
    )
    events += _diff_entities(
        before.get("certs") or [], after.get("certs") or [],
        kind="cert", id_keys=("domain", "id", "name"),
        skip_fields={"cert_pem", "key_pem", "fullchain"},
    )
    events += _diff_entities(
        before.get("doh_bundle") or [], after.get("doh_bundle") or [],
        kind="doh", id_keys=("id", "name", "domain"),
    )
    events += _diff_entities(
        before.get("ip_bans") or [], after.get("ip_bans") or [],
        kind="ban", id_keys=("ip",),
    )
    events += _diff_entities(
        [{"_i": str(i), **(r if isinstance(r, dict) else {"value": r})}
         for i, r in enumerate(before.get("routes") or [])],
        [{"_i": str(i), **(r if isinstance(r, dict) else {"value": r})}
         for i, r in enumerate(after.get("routes") or [])],
        kind="route", id_keys=("_i",),
    )
    events += _diff_dict_section(before.get("balancers") or {}, after.get("balancers") or {}, kind="balancer")
    events += _diff_dict_section(before.get("dns") or {}, after.get("dns") or {}, kind="dns")
    events += _diff_dict_section(
        before.get("xray_settings") or {}, after.get("xray_settings") or {}, kind="xray_settings",
    )
    events += _diff_dict_section(before.get("reverse") or {}, after.get("reverse") or {}, kind="reverse")
    events += _diff_dict_section(before.get("settings") or {}, after.get("settings") or {}, kind="settings")
    return events


def summarize_events(events: list[dict], limit: int = 5) -> str:
    if not events:
        return "без изменений"
    parts = []
    for e in events[:limit]:
        op = {"add": "+", "remove": "−", "change": "~"}.get(e.get("op"), "·")
        text = e.get("text") or ""
        if e.get("op") in ("add", "remove"):
            parts.append(f"{op} {e.get('title')} {text}")
        else:
            short = text if len(text) <= 80 else text[:77] + "…"
            parts.append(f"{op} {e.get('title')}: {short}" if short else f"{op} {e.get('title')}")
    extra = f" …+{len(events) - limit}" if len(events) > limit else ""
    return " · ".join(parts) + extra


def infer_section(events: list[dict]) -> str:
    kinds = []
    for e in events:
        k = e.get("kind") or ""
        if k and k not in kinds:
            kinds.append(k)
    labels = [_KIND_LABEL.get(k, k) for k in kinds[:4]]
    if not labels:
        return ""
    extra = f" +{len(kinds) - 4}" if len(kinds) > 4 else ""
    return ", ".join(labels) + extra


def _snapshot_path(vid: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9_-]", "", vid)
    return HISTORY_DIR / f"{safe}.json"


def read_snapshot(vid: str) -> dict | None:
    path = _snapshot_path(vid)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except ValueError:
        return None


def list_versions(limit: int = 50) -> list[dict]:
    with _LOCK:
        items = _load_index()
    return items[: max(1, min(limit, MAX_VERSIONS))]


def get_version(vid: str) -> dict | None:
    with _LOCK:
        for item in _load_index():
            if item.get("id") == vid:
                return item
    return None


def previous_version(vid: str) -> dict | None:
    with _LOCK:
        items = _load_index()
    for i, item in enumerate(items):
        if item.get("id") == vid:
            return items[i + 1] if i + 1 < len(items) else None
    return None


def _normalize_input(data: dict | None) -> dict:
    """Accept full store, canonical state, or legacy flat settings dict."""
    if not isinstance(data, dict) or not data:
        return {}
    if any(k in data for k in TRACKED_KEYS):
        return canonical_state(data)
    # Legacy: settings object saved without wrapper
    return {"settings": deepcopy(data)}


def record(
    before: dict,
    after: dict,
    *,
    user: str = "",
    ip: str = "",
    section: str = "",
    note: str = "",
) -> dict | None:
    """Save after-state. `before`/`after` may be full store or canonical state."""
    before_c = _normalize_input(before)
    after_c = _normalize_input(after)
    events = describe_changes(before_c, after_c)
    if not events:
        return None
    vid = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(3)
    entry = {
        "id": vid,
        "at": _now(),
        "user": str(user or ""),
        "ip": str(ip or ""),
        "section": str(section or infer_section(events)),
        "note": str(note or ""),
        "changes": len(events),
        "summary": summarize_events(events),
        "format": FORMAT_V2,
    }
    payload = {"_format": FORMAT_V2, "state": after_c}
    with _LOCK:
        _ensure_dir()
        path = _snapshot_path(vid)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        items = _load_index()
        items.insert(0, entry)
        while len(items) > MAX_VERSIONS:
            old = items.pop()
            _snapshot_path(str(old.get("id") or "")).unlink(missing_ok=True)
        _save_index(items)
    return entry


def version_detail(vid: str, current_store: dict) -> dict | None:
    meta = get_version(vid)
    if not meta:
        return None
    raw_after = read_snapshot(vid)
    if raw_after is None:
        return None
    after = _unwrap_snapshot(raw_after)
    prev_meta = previous_version(vid)
    if prev_meta:
        raw_before = read_snapshot(prev_meta["id"])
        before = _unwrap_snapshot(raw_before) if raw_before is not None else {}
    else:
        before = {}
    current = canonical_state(current_store)
    return {
        "meta": meta,
        "prev_meta": prev_meta,
        "before": before,
        "after": after,
        "current": current,
        "events_prev_after": describe_changes(before, after),
        "events_after_current": describe_changes(after, current),
        "events_prev_current": describe_changes(before, current),
        "diff_prev_after": diff_settings(before, after),
        "diff_after_current": diff_settings(after, current),
        "diff_prev_current": diff_settings(before, current),
    }


def apply_snapshot(store: dict, vid: str) -> dict:
    """Restore tracked keys from snapshot. Caller holds mutate lock & saves."""
    raw = read_snapshot(vid)
    if raw is None:
        raise FileNotFoundError(f"версия {vid} не найдена")
    state = _unwrap_snapshot(raw)
    before = canonical_state(store)
    if _is_v2_snapshot(raw):
        for key in TRACKED_KEYS:
            if key in state:
                store[key] = deepcopy(state[key])
    else:
        store["settings"] = deepcopy(state.get("settings") or raw)
    after = canonical_state(store)
    return {"before": before, "after": after, "from": vid}
