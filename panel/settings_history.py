"""Version history for panel settings — snapshot, flat diff, rollback."""
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

# Keys (any path segment) whose values are redacted in diffs / listings
_REDACT_SEGMENTS = {
    "token", "password", "password_hash", "secret", "api_token", "agent_token",
    "pihole_password", "totp_secret", "private_key", "privatekey", "mldsa65_seed",
    "login_secret", "webhook_secret", "cert_key", "key_file",
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
    parts = {p.lower() for p in path.split(".") if p}
    if parts & _REDACT_SEGMENTS:
        if value in (None, "", [], {}):
            return value
        return "•••"
    return value


def flatten(obj: Any, prefix: str = "") -> dict[str, Any]:
    """Flatten nested dict/list into dotted paths → values."""
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
    """List of {path, before, after} for changed/added/removed keys."""
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


class _Missing:
    pass


_MISSING = _Missing()


def diff_settings(a: dict | None, b: dict | None) -> list[dict[str, Any]]:
    return diff_maps(flatten(a or {}), flatten(b or {}))


def summarize_diff(rows: list[dict], limit: int = 6) -> str:
    if not rows:
        return "без изменений"
    parts = []
    for r in rows[:limit]:
        parts.append(r["path"])
    extra = f" …+{len(rows) - limit}" if len(rows) > limit else ""
    return ", ".join(parts) + extra


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


def record(
    before: dict,
    after: dict,
    *,
    user: str = "",
    ip: str = "",
    section: str = "",
    note: str = "",
) -> dict | None:
    """Save a new version (after-state). No-op if nothing changed. Returns index entry."""
    rows = diff_settings(before, after)
    if not rows:
        return None
    vid = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(3)
    entry = {
        "id": vid,
        "at": _now(),
        "user": str(user or ""),
        "ip": str(ip or ""),
        "section": str(section or ""),
        "note": str(note or ""),
        "changes": len(rows),
        "summary": summarize_diff(rows),
    }
    with _LOCK:
        _ensure_dir()
        path = _snapshot_path(vid)
        path.write_text(json.dumps(after, ensure_ascii=False, indent=2), encoding="utf-8")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        items = _load_index()
        items.insert(0, entry)
        # prune
        while len(items) > MAX_VERSIONS:
            old = items.pop()
            _snapshot_path(str(old.get("id") or "")).unlink(missing_ok=True)
        _save_index(items)
    return entry


def version_detail(vid: str, current: dict) -> dict | None:
    """Build three-way view: previous | this (after) | current."""
    meta = get_version(vid)
    if not meta:
        return None
    after = read_snapshot(vid)
    if after is None:
        return None
    prev_meta = previous_version(vid)
    before = read_snapshot(prev_meta["id"]) if prev_meta else {}
    if before is None:
        before = {}
    return {
        "meta": meta,
        "prev_meta": prev_meta,
        "before": before,
        "after": after,
        "current": current or {},
        "diff_prev_after": diff_settings(before, after),
        "diff_after_current": diff_settings(after, current or {}),
        "diff_prev_current": diff_settings(before, current or {}),
    }


def apply_snapshot(store: dict, vid: str) -> dict:
    """Replace store['settings'] with snapshot. Caller holds mutate lock & saves."""
    snap = read_snapshot(vid)
    if snap is None:
        raise FileNotFoundError(f"версия {vid} не найдена")
    before = deepcopy(store.get("settings") or {})
    store["settings"] = deepcopy(snap)
    return {"before": before, "after": store["settings"], "from": vid}
