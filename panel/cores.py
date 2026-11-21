"""Node core profiles (Pasarguard-style «Ядра»).

A core is a named Xray config profile (inbounds / outbounds / routes / balancers / DNS).
Nodes keep auto-provision via master, but sync/push apply the assigned core's settings.
"""
from __future__ import annotations

import copy
import secrets
from datetime import datetime, timezone
from typing import Any

CORE_SLICES = (
    "inbounds",
    "outbounds_custom",
    "routes",
    "balancers",
    "dns",
    "xray_settings",
)

_SYSTEM_INBOUND_TAGS = frozenset({"master-backhaul", "rv-in", "node-bridge", "api"})


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _new_id() -> str:
    return "core_" + secrets.token_urlsafe(9).replace("-", "").replace("_", "")[:12]


def _filter_inbounds(inbounds: list | None) -> list[dict]:
    out = []
    for i in inbounds or []:
        if not isinstance(i, dict):
            continue
        tag = str(i.get("tag") or "")
        if i.get("_system") or tag in _SYSTEM_INBOUND_TAGS:
            continue
        out.append(copy.deepcopy(i))
    return out


def _filter_outbounds(customs: list | None) -> list[dict]:
    """Keep user/custom outbounds; drop live node/bridge stubs (rebuilt per node on push)."""
    out = []
    for o in customs or []:
        if not isinstance(o, dict):
            continue
        kind = str(o.get("kind") or "")
        tag = str(o.get("tag") or "")
        if kind in ("node", "local_direct", "master_egress"):
            continue
        if tag.startswith("node_") or tag in ("master", "master-backhaul"):
            continue
        out.append(copy.deepcopy(o))
    return out


def snapshot_from_master(store: dict, *, name: str = "Default", remark: str = "") -> dict:
    """Capture current master slices into a new core profile."""
    try:
        import xray_runtime as xray
        bals = copy.deepcopy(xray.ensure_balancers(store) if hasattr(xray, "ensure_balancers") else (store.get("balancers") or {}))
    except Exception:
        bals = copy.deepcopy(store.get("balancers") or {})
    return {
        "id": _new_id(),
        "name": (name or "Default").strip() or "Default",
        "remark": (remark or "").strip(),
        "engine": "xray",
        # When True, push uses live master slices (core is only a label/assignment)
        "inherit_master": False,
        "inbounds": _filter_inbounds(store.get("inbounds")),
        "outbounds_custom": _filter_outbounds(store.get("outbounds_custom")),
        "routes": copy.deepcopy(store.get("routes") or []),
        "balancers": bals if isinstance(bals, dict) else {},
        "dns": copy.deepcopy(store.get("dns") or {}),
        "xray_settings": copy.deepcopy(store.get("xray_settings") or {}),
        "created_at": now_iso(),
        "updated_at": now_iso(),
    }


def refresh_core_from_master(store: dict, core: dict) -> dict:
    """Replace core slices with a fresh master snapshot (keeps id/name)."""
    snap = snapshot_from_master(store, name=str(core.get("name") or "Default"), remark=str(core.get("remark") or ""))
    for key in CORE_SLICES:
        core[key] = snap[key]
    core["inherit_master"] = False
    core["engine"] = snap.get("engine") or "xray"
    core["updated_at"] = now_iso()
    return core


def ensure_cores(store: dict) -> list[dict]:
    """Ensure cores list exists; migrate legacy installs to one Default core."""
    cores = store.setdefault("cores", [])
    if not isinstance(cores, list):
        cores = []
        store["cores"] = cores
    for c in cores:
        if not isinstance(c, dict):
            continue
        c.setdefault("id", _new_id())
        c.setdefault("name", "Core")
        c.setdefault("remark", "")
        c.setdefault("engine", "xray")
        c.setdefault("inherit_master", False)
        for key in CORE_SLICES:
            c.setdefault(key, [] if key != "balancers" and key != "dns" and key != "xray_settings" else {})
        if key_needs_list(c, "inbounds"):
            c["inbounds"] = list(c.get("inbounds") or [])
        if key_needs_list(c, "outbounds_custom"):
            c["outbounds_custom"] = list(c.get("outbounds_custom") or [])
        if key_needs_list(c, "routes"):
            c["routes"] = list(c.get("routes") or [])
        if not isinstance(c.get("balancers"), dict):
            c["balancers"] = {}
        if not isinstance(c.get("dns"), dict):
            c["dns"] = {}
        if not isinstance(c.get("xray_settings"), dict):
            c["xray_settings"] = {}
        c.setdefault("created_at", now_iso())
        c.setdefault("updated_at", c.get("created_at") or now_iso())

    if not cores:
        default = snapshot_from_master(store, name="Default", remark="Авто: снимок настроек мастера")
        # First core inherits master until admin customizes (seamless upgrade)
        default["inherit_master"] = True
        cores.append(default)
        for n in store.get("nodes") or []:
            if isinstance(n, dict):
                n.setdefault("core_id", default["id"])
    else:
        default_id = cores[0].get("id")
        for n in store.get("nodes") or []:
            if not isinstance(n, dict):
                continue
            n.setdefault("core_id", "")
            if not n.get("core_id"):
                n["core_id"] = default_id
    return cores


def key_needs_list(core: dict, key: str) -> bool:
    return not isinstance(core.get(key), list)


def core_by_id(store: dict, core_id: str | None) -> dict | None:
    cid = str(core_id or "").strip()
    if not cid:
        return None
    for c in ensure_cores(store):
        if c.get("id") == cid:
            return c
    return None


def default_core(store: dict) -> dict:
    cores = ensure_cores(store)
    return cores[0]


def core_for_node(store: dict, node: dict | None) -> dict:
    """Resolve the core assigned to a node (fallback: default)."""
    ensure_cores(store)
    if isinstance(node, dict):
        c = core_by_id(store, node.get("core_id"))
        if c:
            return c
    return default_core(store)


def cores_usage(store: dict) -> dict[str, int]:
    """core_id → number of nodes using it."""
    ensure_cores(store)
    counts: dict[str, int] = {c["id"]: 0 for c in store.get("cores") or [] if c.get("id")}
    for n in store.get("nodes") or []:
        cid = str((n or {}).get("core_id") or "")
        if cid in counts:
            counts[cid] += 1
    return counts


def store_view_for_node(store: dict, node: dict) -> dict:
    """Deep-ish view of store with config slices taken from the node's core.

    Clients / groups / nodes registry stay from master. Used by ``build_payload``.
    """
    core = core_for_node(store, node)
    view = store  # shallow — we only override keys below via a wrapper dict
    out = dict(store)
    if core.get("inherit_master"):
        return out
    out["inbounds"] = copy.deepcopy(core.get("inbounds") or [])
    out["outbounds_custom"] = copy.deepcopy(core.get("outbounds_custom") or [])
    out["routes"] = copy.deepcopy(core.get("routes") or [])
    out["balancers"] = copy.deepcopy(core.get("balancers") or {})
    out["dns"] = copy.deepcopy(core.get("dns") or {})
    out["xray_settings"] = copy.deepcopy(core.get("xray_settings") or {})
    return out


def create_core(store: dict, *, name: str, remark: str = "", clone_master: bool = True) -> dict:
    ensure_cores(store)
    if clone_master:
        core = snapshot_from_master(store, name=name or "Core", remark=remark)
    else:
        core = {
            "id": _new_id(),
            "name": (name or "Core").strip() or "Core",
            "remark": (remark or "").strip(),
            "engine": "xray",
            "inherit_master": True,
            "inbounds": [],
            "outbounds_custom": [],
            "routes": [],
            "balancers": {},
            "dns": {},
            "xray_settings": {},
            "created_at": now_iso(),
            "updated_at": now_iso(),
        }
    store.setdefault("cores", []).append(core)
    return core


def delete_core(store: dict, core_id: str) -> str | None:
    """Delete core; reassign nodes to default. Returns error or None."""
    cores = ensure_cores(store)
    if len(cores) <= 1:
        return "Нельзя удалить последнее ядро"
    core = core_by_id(store, core_id)
    if not core:
        return "Ядро не найдено"
    fallback = next(c for c in cores if c.get("id") != core_id)
    store["cores"] = [c for c in cores if c.get("id") != core_id]
    for n in store.get("nodes") or []:
        if n.get("core_id") == core_id:
            n["core_id"] = fallback["id"]
    return None


def rename_core(core: dict, name: str, remark: str | None = None) -> None:
    core["name"] = (name or core.get("name") or "Core").strip() or "Core"
    if remark is not None:
        core["remark"] = remark.strip()
    core["updated_at"] = now_iso()


def set_inherit(core: dict, inherit: bool) -> None:
    core["inherit_master"] = bool(inherit)
    core["updated_at"] = now_iso()


def core_summary(core: dict) -> dict:
    """Counts for UI badges."""
    bals = core.get("balancers") or {}
    return {
        "inbounds": len(core.get("inbounds") or []),
        "outbounds": len(core.get("outbounds_custom") or []),
        "routes": len(core.get("routes") or []),
        "balancers": len(bals) if isinstance(bals, dict) else 0,
        "inherit_master": bool(core.get("inherit_master")),
    }


def resolve_core_id(store: dict, raw: str | None) -> str:
    """Validate form core_id; fallback to default."""
    ensure_cores(store)
    cid = str(raw or "").strip()
    if cid and core_by_id(store, cid):
        return cid
    return default_core(store)["id"]
