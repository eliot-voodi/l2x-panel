"""Node core profiles (PasarGuard-style «Ядра»).

PasarGuard CoreConfig fields mirrored here:
  name, type/engine, config (JSON overlay), exclude_inbound_tags,
  fallbacks_inbound_tags, sort_order (+ L2X slices + inherit_master).

Nodes keep SSH auto-provision via master; Sync applies the assigned core.
"""
from __future__ import annotations

import copy
import json
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CORE_SLICES = (
    "inbounds",
    "outbounds_custom",
    "routes",
    "balancers",
    "dns",
    "xray_settings",
)

CORE_ENGINES = ("xray",)  # WireGuard/sing-box reserved; panel is Xray-first

_SYSTEM_INBOUND_TAGS = frozenset({"master-backhaul", "rv-in", "node-bridge", "api"})

# Session / context key for «edit this core's slices» mode
EDIT_CORE_SESSION = "edit_core_id"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _new_id() -> str:
    return "core_" + secrets.token_urlsafe(9).replace("-", "").replace("_", "")[:12]


def parse_tag_set(raw: Any) -> list[str]:
    """PasarGuard-style tag list: spaces, commas, or newlines."""
    if isinstance(raw, (list, set, tuple)):
        items = [str(x).strip() for x in raw]
    else:
        text = str(raw or "").replace(",", " ").replace("\n", " ").replace("\t", " ")
        items = text.split()
    out: list[str] = []
    seen: set[str] = set()
    for t in items:
        if not t or t in seen:
            continue
        seen.add(t)
        out.append(t)
    return out


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


def _empty_slices() -> dict:
    return {
        "inbounds": [],
        "outbounds_custom": [],
        "routes": [],
        "balancers": {},
        "dns": {},
        "xray_settings": {},
    }


def _normalize_engine(raw: Any) -> str:
    eng = str(raw or "xray").strip().lower()
    if eng in ("wg", "wireguard"):
        return "xray"  # not supported yet — keep xray
    if eng in CORE_ENGINES:
        return eng
    return "xray"


def snapshot_from_master(store: dict, *, name: str = "Default", remark: str = "") -> dict:
    """Capture current master slices into a new core profile."""
    try:
        import xray_runtime as xray
        bals = copy.deepcopy(
            xray.ensure_balancers(store) if hasattr(xray, "ensure_balancers") else (store.get("balancers") or {})
        )
    except Exception:
        bals = copy.deepcopy(store.get("balancers") or {})
    xs = copy.deepcopy(store.get("xray_settings") or {})
    return {
        "id": _new_id(),
        "name": (name or "Default").strip() or "Default",
        "remark": (remark or "").strip(),
        "engine": "xray",
        "type": "xray",
        "inherit_master": False,
        "is_default": False,
        "sort_order": 0,
        "exclude_inbound_tags": [],
        "fallbacks_inbound_tags": [],
        # PasarGuard ``config`` — advanced Xray JSON overlay (merged as template_patch)
        "config": {},
        "sub_custom_json": False,
        "sub_custom_json_template": "",
        "cascade": True,
        "inbounds": _filter_inbounds(store.get("inbounds")),
        "outbounds_custom": _filter_outbounds(store.get("outbounds_custom")),
        "routes": copy.deepcopy(store.get("routes") or []),
        "balancers": bals if isinstance(bals, dict) else {},
        "dns": copy.deepcopy(store.get("dns") or {}),
        "xray_settings": xs if isinstance(xs, dict) else {},
        "created_at": now_iso(),
        "updated_at": now_iso(),
    }


def refresh_core_from_master(store: dict, core: dict) -> dict:
    """Replace core slices with a fresh master snapshot (keeps id/name/tags)."""
    snap = snapshot_from_master(store, name=str(core.get("name") or "Default"), remark=str(core.get("remark") or ""))
    for key in CORE_SLICES:
        core[key] = snap[key]
    core["inherit_master"] = False
    core["engine"] = "xray"
    core["type"] = "xray"
    core["updated_at"] = now_iso()
    return core


def ensure_cores(store: dict) -> list[dict]:
    """Ensure cores list exists; migrate legacy installs to one Default core."""
    cores = store.setdefault("cores", [])
    if not isinstance(cores, list):
        cores = []
        store["cores"] = cores
    for idx, c in enumerate(cores):
        if not isinstance(c, dict):
            continue
        c.setdefault("id", _new_id())
        c.setdefault("name", "Core")
        c.setdefault("remark", "")
        c["engine"] = _normalize_engine(c.get("engine") or c.get("type") or "xray")
        c["type"] = c["engine"]
        c.setdefault("inherit_master", False)
        c.setdefault("is_default", False)
        c.setdefault("sort_order", idx)
        c.setdefault("sub_custom_json", False)
        if not isinstance(c.get("sub_custom_json_template"), str):
            c["sub_custom_json_template"] = str(c.get("sub_custom_json_template") or "")
        c["sub_custom_json"] = bool(c.get("sub_custom_json"))
        if "cascade" not in c:
            c["cascade"] = True
        else:
            c["cascade"] = bool(c.get("cascade"))
        c["exclude_inbound_tags"] = parse_tag_set(c.get("exclude_inbound_tags"))
        c["fallbacks_inbound_tags"] = parse_tag_set(c.get("fallbacks_inbound_tags"))
        if not isinstance(c.get("config"), dict):
            c["config"] = {}
        for key in CORE_SLICES:
            c.setdefault(key, [] if key not in ("balancers", "dns", "xray_settings") else {})
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
        # PasarGuard policy.statsUserOnline
        xs = c["xray_settings"]
        xs.setdefault("stats_user_online", True)
        xs.setdefault("log_level", xs.get("log_level") or "warning")
        xs.setdefault("access_log", bool(xs.get("access_log")))
        xs.setdefault("dns_log", bool(xs.get("dns_log")))
        if not isinstance(xs.get("template_patch"), dict):
            xs["template_patch"] = {}
        # Merge legacy config overlay into template_patch once
        if c.get("config") and isinstance(c["config"], dict) and c["config"]:
            # keep both: config is the PasarGuard field; also feed template_patch
            pass
        c.setdefault("created_at", now_iso())
        c.setdefault("updated_at", c.get("created_at") or now_iso())

    if not cores:
        default = snapshot_from_master(store, name="Default", remark="Авто: снимок настроек мастера")
        default["inherit_master"] = True
        default["is_default"] = True
        default["sort_order"] = 0
        cores.append(default)
        for n in store.get("nodes") or []:
            if isinstance(n, dict):
                n.setdefault("core_id", default["id"])
    else:
        # Exactly one default — first by sort_order
        cores.sort(key=lambda x: (int(x.get("sort_order") or 0), str(x.get("name") or "")))
        if not any(c.get("is_default") for c in cores if isinstance(c, dict)):
            cores[0]["is_default"] = True
        default_id = next((c["id"] for c in cores if c.get("is_default")), cores[0].get("id"))
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
    for c in cores:
        if c.get("is_default"):
            return c
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


def apply_exclude_inbounds(inbounds: list, core: dict | None) -> list:
    """Drop tags listed in core.exclude_inbound_tags (PasarGuard XRAY_EXCLUDE_INBOUND_TAGS)."""
    if not core:
        return list(inbounds or [])
    excl = set(parse_tag_set(core.get("exclude_inbound_tags")))
    if not excl:
        return list(inbounds or [])
    return [i for i in (inbounds or []) if isinstance(i, dict) and str(i.get("tag") or "") not in excl]


def mark_fallback_inbounds(inbounds: list, core: dict | None) -> list:
    """Annotate inbounds whose tags are in fallbacks_inbound_tags."""
    if not core:
        return list(inbounds or [])
    fb = set(parse_tag_set(core.get("fallbacks_inbound_tags")))
    if not fb:
        return list(inbounds or [])
    out = []
    for i in inbounds or []:
        if not isinstance(i, dict):
            continue
        ib = dict(i)
        if str(ib.get("tag") or "") in fb:
            ib["is_fallback"] = True
        out.append(ib)
    return out


def merge_core_xray_settings(core: dict) -> dict:
    """xray_settings for push: slices + PasarGuard config overlay + policy flag."""
    xs = copy.deepcopy(core.get("xray_settings") or {})
    if not isinstance(xs, dict):
        xs = {}
    patch = xs.get("template_patch") if isinstance(xs.get("template_patch"), dict) else {}
    cfg = core.get("config") if isinstance(core.get("config"), dict) else {}
    if cfg:
        # Deep-merge PasarGuard config into template_patch (config wins on conflict)
        try:
            import xray_runtime as xray
            patch = xray.deep_merge(patch, cfg)
        except Exception:
            merged = dict(patch)
            merged.update(cfg)
            patch = merged
    xs["template_patch"] = patch
    # Ensure policy.statsUserOnline from core setting
    online = xs.get("stats_user_online", True)
    policy = patch.setdefault("policy", {})
    if not isinstance(policy, dict):
        policy = {}
        patch["policy"] = policy
    levels = policy.setdefault("levels", {})
    if not isinstance(levels, dict):
        levels = {}
        policy["levels"] = levels
    lvl0 = levels.setdefault("0", {})
    if not isinstance(lvl0, dict):
        lvl0 = {}
        levels["0"] = lvl0
    lvl0["statsUserOnline"] = bool(online)
    xs["template_patch"] = patch
    return xs


def store_view_for_node(store: dict, node: dict) -> dict:
    """View of store with config slices from the node's core (for build_payload)."""
    core = core_for_node(store, node)
    out = dict(store)
    if core.get("inherit_master"):
        # Still apply exclude/fallback filters on live master slices
        out["inbounds"] = mark_fallback_inbounds(
            apply_exclude_inbounds(list(store.get("inbounds") or []), core), core
        )
        xs = copy.deepcopy(store.get("xray_settings") or {})
        # Apply online stats preference from core even when inheriting
        if isinstance(core.get("xray_settings"), dict) and "stats_user_online" in (core.get("xray_settings") or {}):
            xs["stats_user_online"] = core["xray_settings"].get("stats_user_online", True)
        # Always merge so policy.statsUserOnline follows the core flag (even without
        # PasarGuard config overlay). Skipping merge left agents on whatever default
        # was last pushed — and a False flag never reached policy.
        out["xray_settings"] = merge_core_xray_settings({**core, "xray_settings": xs})
        return out
    out["inbounds"] = mark_fallback_inbounds(
        apply_exclude_inbounds(copy.deepcopy(core.get("inbounds") or []), core), core
    )
    # Core customs + enabled master outbounds (node_* / custom) so routes can
    # target server-side exits that live on the master list.
    outs = copy.deepcopy(core.get("outbounds_custom") or [])
    seen = {str(o.get("tag") or "") for o in outs if isinstance(o, dict) and o.get("tag")}
    for o in store.get("outbounds_custom") or []:
        if not isinstance(o, dict):
            continue
        tag = str(o.get("tag") or "")
        if not tag or tag in seen:
            continue
        if not o.get("enabled", True):
            continue
        outs.append(copy.deepcopy(o))
        seen.add(tag)
    out["outbounds_custom"] = outs
    out["routes"] = copy.deepcopy(core.get("routes") or [])
    out["balancers"] = copy.deepcopy(core.get("balancers") or {})
    out["dns"] = copy.deepcopy(core.get("dns") or {})
    out["xray_settings"] = merge_core_xray_settings(core)
    return out


def store_view_for_core_edit(store: dict, core_id: str) -> dict:
    """Shallow store view for UI while editing a non-inherit core."""
    core = core_by_id(store, core_id)
    if not core or core.get("inherit_master"):
        return store
    out = dict(store)
    for key in CORE_SLICES:
        out[key] = core.get(key) if key in ("balancers", "dns", "xray_settings") else list(core.get(key) or [])
        if key in ("balancers", "dns", "xray_settings"):
            out[key] = core.get(key) if isinstance(core.get(key), dict) else {}
    return out


def create_core(
    store: dict,
    *,
    name: str,
    remark: str = "",
    clone_master: bool = True,
    clone_from: str | None = None,
) -> dict:
    ensure_cores(store)
    if clone_from:
        src = core_by_id(store, clone_from)
        if src:
            core = copy.deepcopy(src)
            core["id"] = _new_id()
            core["name"] = (name or f"{src.get('name')} copy").strip() or "Core"
            core["remark"] = (remark if remark is not None else src.get("remark") or "").strip()
            core["is_default"] = False
            core["created_at"] = now_iso()
            core["updated_at"] = now_iso()
            store.setdefault("cores", []).append(core)
            return core
    if clone_master:
        core = snapshot_from_master(store, name=name or "Core", remark=remark)
    else:
        core = {
            "id": _new_id(),
            "name": (name or "Core").strip() or "Core",
            "remark": (remark or "").strip(),
            "engine": "xray",
            "type": "xray",
            "inherit_master": True,
            "is_default": False,
            "sort_order": len(store.get("cores") or []),
            "exclude_inbound_tags": [],
            "fallbacks_inbound_tags": [],
            "config": {},
            "sub_custom_json": False,
            "sub_custom_json_template": "",
            "cascade": True,
            **_empty_slices(),
            "created_at": now_iso(),
            "updated_at": now_iso(),
        }
        core["xray_settings"] = {"stats_user_online": True, "log_level": "warning", "access_log": False, "dns_log": False, "template_patch": {}}
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
    if core.get("is_default"):
        return "Нельзя удалить ядро по умолчанию (как в PasarGuard)"
    fallback = default_core(store)
    if fallback.get("id") == core_id:
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


def update_core_settings(core: dict, form: dict) -> list[str]:
    """Apply PasarGuard-like settings from a form. Returns validation errors."""
    errors: list[str] = []
    if "name" in form:
        rename_core(core, str(form.get("name") or core.get("name") or "Core"), str(form.get("remark") or ""))
    elif "remark" in form:
        core["remark"] = str(form.get("remark") or "").strip()

    if "engine" in form or "type" in form:
        core["engine"] = _normalize_engine(form.get("engine") or form.get("type"))
        core["type"] = core["engine"]

    if "exclude_inbound_tags" in form:
        core["exclude_inbound_tags"] = parse_tag_set(form.get("exclude_inbound_tags"))
    if "fallbacks_inbound_tags" in form:
        core["fallbacks_inbound_tags"] = parse_tag_set(form.get("fallbacks_inbound_tags"))

    if "inherit_master" in form:
        core["inherit_master"] = str(form.get("inherit_master")) in ("1", "true", "on", "yes")

    xs = core.setdefault("xray_settings", {})
    if not isinstance(xs, dict):
        xs = {}
        core["xray_settings"] = xs
    if "stats_user_online" in form:
        xs["stats_user_online"] = str(form.get("stats_user_online")) in ("1", "true", "on", "yes")
    if "log_level" in form:
        lvl = str(form.get("log_level") or "warning").strip().lower()
        if lvl in ("debug", "info", "warning", "error", "none"):
            xs["log_level"] = lvl
    if "access_log" in form:
        xs["access_log"] = str(form.get("access_log")) in ("1", "true", "on", "yes")
    if "dns_log" in form:
        xs["dns_log"] = str(form.get("dns_log")) in ("1", "true", "on", "yes")

    if "config_json" in form:
        raw = str(form.get("config_json") or "").strip()
        if not raw:
            core["config"] = {}
        else:
            try:
                parsed = json.loads(raw)
                if not isinstance(parsed, dict):
                    errors.append("config JSON должен быть объектом {}")
                else:
                    verr = validate_core_config(parsed, require_io=False)
                    errors.extend(verr)
                    if not verr:
                        core["config"] = parsed
            except json.JSONDecodeError as exc:
                errors.append(f"Некорректный JSON: {exc}")

    # Client subscription Custom JSON (per-core template → ?format=json profiles)
    if "sub_custom_json_form" in form or "sub_custom_json_template" in form:
        core["sub_custom_json"] = str(form.get("sub_custom_json") or "") in ("1", "true", "on", "yes")
        core["sub_custom_json_template"] = str(form.get("sub_custom_json_template") or "")
        if core["sub_custom_json"] and core["sub_custom_json_template"].strip():
            try:
                import protocols as P
                probe = P.render_sub_custom_json(
                    core["sub_custom_json_template"],
                    client={
                        "uuid": "00000000-0000-0000-0000-000000000001",
                        "email": "probe",
                        "password": "probe",
                    },
                    host="example.com",
                    remark="probe",
                )
                if probe is None:
                    errors.append("Custom JSON: невалидный JSON после подстановки плейсхолдеров")
            except Exception as exc:
                errors.append(f"Custom JSON: {exc}")

    # Validate exclude/fallback tags against known inbounds when not inheriting
    if not core.get("inherit_master"):
        known = {str(i.get("tag") or "") for i in (core.get("inbounds") or []) if isinstance(i, dict)}
        for t in core.get("exclude_inbound_tags") or []:
            if known and t not in known:
                # soft warning — tags may be planned; don't block
                pass
        tag_err = validate_core_slices(core)
        errors.extend(tag_err)

    if not errors:
        core["updated_at"] = now_iso()
    return errors


def validate_core_config(cfg: dict, *, require_io: bool = True) -> list[str]:
    """PasarGuard XRayConfig-style validation for a raw JSON config object."""
    errs: list[str] = []
    if not isinstance(cfg, dict):
        return ["config must be a dict"]
    inbounds = cfg.get("inbounds")
    outbounds = cfg.get("outbounds")
    if require_io:
        if not inbounds:
            errs.append("config doesn't have inbounds")
        if not outbounds:
            errs.append("config doesn't have outbounds")
    if isinstance(inbounds, list):
        tags: set[str] = set()
        for ib in inbounds:
            if not isinstance(ib, dict):
                continue
            tag = str(ib.get("tag") or "")
            if not tag:
                errs.append("all inbounds must have a unique tag")
                continue
            if "," in tag or "<=>" in tag:
                errs.append(f"character «,» / «<=>» is not allowed in inbound tag «{tag}»")
            if tag in tags:
                errs.append(f"duplicate inbound tag «{tag}»")
            tags.add(tag)
            proto = str(ib.get("protocol") or "")
            if require_io and not proto:
                errs.append(f"inbound «{tag}» missing protocol")
            # Port required unless fallbacks
            has_fb = bool((ib.get("settings") or {}).get("fallbacks")) if isinstance(ib.get("settings"), dict) else bool(ib.get("fallbacks"))
            if require_io and ib.get("port") is None and not has_fb and not ib.get("is_fallback"):
                errs.append(f"{tag} inbound doesn't have port")
            # Reality checks
            stream = ib.get("streamSettings") or {}
            if isinstance(stream, dict) and stream.get("security") == "reality":
                rs = stream.get("realitySettings") or {}
                if not isinstance(rs, dict) or not rs.get("privateKey"):
                    errs.append(f"You need to provide privateKey in realitySettings ({tag})")
                sids = rs.get("shortIds") if isinstance(rs, dict) else None
                if not isinstance(sids, list) or len(sids) < 1:
                    errs.append(f"You need to define at least one shortID in realitySettings ({tag})")
    if isinstance(outbounds, list):
        otags: set[str] = set()
        for ob in outbounds:
            if not isinstance(ob, dict):
                continue
            tag = str(ob.get("tag") or "")
            if not tag:
                errs.append("all outbounds must have a unique tag")
                continue
            if tag in otags:
                errs.append(f"duplicate outbound tag «{tag}»")
            otags.add(tag)
    return errs


def validate_core_slices(core: dict) -> list[str]:
    """Validate panel-format slices on a core."""
    errs: list[str] = []
    tags: set[str] = set()
    for ib in core.get("inbounds") or []:
        if not isinstance(ib, dict):
            continue
        tag = str(ib.get("tag") or "")
        if not tag:
            errs.append("inbound без tag")
            continue
        if "," in tag or "<=>" in tag:
            errs.append(f"недопустимые символы в tag «{tag}»")
        if tag in tags:
            errs.append(f"дубликат inbound tag «{tag}»")
        tags.add(tag)
    otags: set[str] = set()
    for ob in core.get("outbounds_custom") or []:
        if not isinstance(ob, dict):
            continue
        tag = str(ob.get("tag") or "")
        if not tag:
            continue
        if tag in otags:
            errs.append(f"дубликат outbound tag «{tag}»")
        otags.add(tag)
    return errs


def core_summary(core: dict) -> dict:
    """Counts for UI badges."""
    bals = core.get("balancers") or {}
    return {
        "inbounds": len(core.get("inbounds") or []),
        "outbounds": len(core.get("outbounds_custom") or []),
        "routes": len(core.get("routes") or []),
        "balancers": len(bals) if isinstance(bals, dict) else 0,
        "inherit_master": bool(core.get("inherit_master")),
        "exclude": len(core.get("exclude_inbound_tags") or []),
        "fallbacks": len(core.get("fallbacks_inbound_tags") or []),
        "has_config": bool(core.get("config")),
        "stats_user_online": bool((core.get("xray_settings") or {}).get("stats_user_online", True)),
        "is_default": bool(core.get("is_default")),
        "engine": core.get("engine") or "xray",
    }


def resolve_core_id(store: dict, raw: str | None) -> str:
    """Validate form core_id; fallback to default."""
    ensure_cores(store)
    cid = str(raw or "").strip()
    if cid and core_by_id(store, cid):
        return cid
    return default_core(store)["id"]


def set_default_core(store: dict, core_id: str) -> str | None:
    cores = ensure_cores(store)
    core = core_by_id(store, core_id)
    if not core:
        return "Ядро не найдено"
    for c in cores:
        c["is_default"] = c.get("id") == core_id
    return None


def nodes_for_core(store: dict, core_id: str) -> list[dict]:
    cid = str(core_id or "")
    return [n for n in (store.get("nodes") or []) if isinstance(n, dict) and n.get("core_id") == cid]


def config_json_text(core: dict) -> str:
    cfg = core.get("config") if isinstance(core.get("config"), dict) else {}
    if not cfg:
        return "{\n}\n"
    return json.dumps(cfg, ensure_ascii=False, indent=2) + "\n"


def preview_inbound_tags(store: dict, core: dict) -> list[str]:
    if core.get("inherit_master"):
        src = store.get("inbounds") or []
    else:
        src = core.get("inbounds") or []
    return [str(i.get("tag") or "") for i in src if isinstance(i, dict) and i.get("tag")]


def snapshot_slices(store: dict, core: dict) -> dict:
    """Deep copy of config slices for this core (master live if inherit)."""
    src = store if core.get("inherit_master") else core
    out: dict[str, Any] = {}
    for key in CORE_SLICES:
        out[key] = copy.deepcopy(src.get(key))
    out["exclude_inbound_tags"] = list(core.get("exclude_inbound_tags") or [])
    out["fallbacks_inbound_tags"] = list(core.get("fallbacks_inbound_tags") or [])
    out["config"] = copy.deepcopy(core.get("config") or {})
    out["inherit_master"] = bool(core.get("inherit_master"))
    return out


def restore_slices(store: dict, core: dict, snap: dict | None) -> None:
    """Restore slices from a previous apply snapshot."""
    if not isinstance(snap, dict):
        return
    inherit = bool(snap.get("inherit_master", core.get("inherit_master")))
    core["inherit_master"] = inherit
    target = store if inherit else core
    for key in CORE_SLICES:
        if key not in snap:
            continue
        val = copy.deepcopy(snap[key])
        if key in ("balancers", "dns", "xray_settings"):
            target[key] = val if isinstance(val, dict) else {}
        else:
            target[key] = val if isinstance(val, list) else []
    if "exclude_inbound_tags" in snap:
        core["exclude_inbound_tags"] = list(snap.get("exclude_inbound_tags") or [])
    if "fallbacks_inbound_tags" in snap:
        core["fallbacks_inbound_tags"] = list(snap.get("fallbacks_inbound_tags") or [])
    if "config" in snap:
        core["config"] = copy.deepcopy(snap.get("config") or {})
    core["updated_at"] = now_iso()


def remember_applied(core: dict, snap: dict) -> None:
    core["applied_snapshot"] = copy.deepcopy(snap)
    core["applied_at"] = now_iso()


def validate_and_build(store: dict, core: dict) -> dict:
    """Build Xray JSON for this core and run ``xray run -test``.

    Returns ``{ok, error, cfg?, sni_notes?}``. Does not touch live master config file on failure.
    """
    sni_notes: list[str] = []
    if not core.get("inherit_master"):
        try:
            import protocols as P
            for ib in core.get("inbounds") or []:
                if isinstance(ib, dict):
                    P.ensure_inbound_shape(ib)
                    fixed = P.fix_http_front_path(ib)
                    if fixed:
                        sni_notes.append(f"{ib.get('tag')}: Path → {fixed}")
            sni_notes.extend(P.resolve_reality_sni_conflicts(core.get("inbounds") or []))
        except Exception:
            sni_notes = []
    errs = validate_core_slices(core if not core.get("inherit_master") else {
        **core,
        "inbounds": store.get("inbounds") or [],
        "outbounds_custom": store.get("outbounds_custom") or [],
    })
    if errs:
        return {"ok": False, "error": "; ".join(errs[:6]), "sni_notes": sni_notes}
    try:
        import xray_runtime as xray
    except Exception as exc:
        return {"ok": False, "error": f"xray_runtime: {exc}", "sni_notes": sni_notes}
    # Fake node view so build uses core slices
    view = store_view_for_node(store, {"core_id": core.get("id"), "id": "_validate"})
    try:
        cfg = xray.build_config(view)
    except Exception as exc:
        return {"ok": False, "error": f"build_config: {exc}", "sni_notes": sni_notes}
    test = xray.test_config(cfg)
    # Drop temp file if any
    try:
        tmp = test.get("tmp")
        if tmp is not None:
            Path(tmp).unlink(missing_ok=True)
    except Exception:
        pass
    if not test.get("ok"):
        return {"ok": False, "error": test.get("error") or "xray -test failed", "cfg": cfg, "sni_notes": sni_notes}
    return {"ok": True, "error": "", "cfg": cfg, "sni_notes": sni_notes}
