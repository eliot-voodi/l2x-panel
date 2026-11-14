"""Routing rule lint: unknown targets, empty selectors, balancer/dialer loops."""
from __future__ import annotations

from typing import Any

import xray_runtime as xray

ERROR = "error"
WARN = "warn"


def _issue(out: list[dict], *, name: str, level: str, msg: str, field: str = "") -> None:
    out.append({"name": name, "level": level, "msg": msg, "field": field})


def _has_selector(r: dict) -> bool:
    if r.get("inbound_all"):
        return True
    for key in ("domain", "ip", "user", "source", "protocol", "inbound_tags", "network", "port", "sourcePort"):
        val = r.get(key)
        if isinstance(val, list) and any(str(x).strip() for x in val):
            return True
        if isinstance(val, str) and val.strip():
            return True
    return False


def _balancer_cycle(store: dict, start: str, *, _stack: list[str] | None = None) -> list[str] | None:
    """Return cycle path if balancer members eventually reference a balancer on the stack."""
    stack = list(_stack or [])
    if start in stack:
        return stack[stack.index(start):] + [start]
    bals = xray.ensure_balancers(store)
    bal_tags = {b.get("tag") for b in bals.values() if b.get("tag")}
    if start not in bal_tags:
        return None
    b = next(x for x in bals.values() if x.get("tag") == start)
    stack.append(start)
    for tag in xray.balancer_member_tags(store, b, healthy_only=False):
        if tag in bal_tags:
            nested = _balancer_cycle(store, tag, _stack=stack)
            if nested:
                return nested
        elif tag == start:
            return [start, tag]
    return None


def _outbound_dialer_tag(store: dict, tag: str) -> str:
    for o in store.get("outbounds_custom") or []:
        if o.get("tag") != tag:
            continue
        cfg = o.get("config") or {}
        # dialerProxy on stream sockopt
        sock = ((cfg.get("streamSettings") or {}).get("sockopt")) or {}
        dialer = str(sock.get("dialerProxy") or "").strip()
        if dialer:
            return dialer
        # panel wrap via
        via = str(o.get("via") or o.get("wrap_via") or "").strip()
        if via:
            return via
    return ""


def lint_routes(store: dict) -> list[dict]:
    """Return issues for panel routes (and related balancer/dialer loops)."""
    out: list[dict] = []
    known = set(xray.all_outbound_tags(store)) | {"direct", "block", "blackhole", "api"}
    bals = xray.ensure_balancers(store)
    bal_tags = {b.get("tag") for b in bals.values() if b.get("tag")}
    known |= bal_tags

    routes = list(store.get("routes") or [])
    # Duplicate selector signatures
    seen_sig: dict[str, str] = {}
    for r in routes:
        name = str(r.get("name") or "?")
        if not r.get("enabled", True):
            continue
        if not _has_selector(r):
            _issue(out, name=name, level=ERROR, msg="Пустое правило — нет условий (domain/ip/user/source/inbound/…).")
        target = str(r.get("outbound") or r.get("outbound_tag") or "direct").strip() or "direct"
        if target not in known:
            _issue(out, name=name, level=ERROR, msg=f"Неизвестный outbound/balancer «{target}».", field="outbound")
        if target in bal_tags:
            cyc = _balancer_cycle(store, target)
            if cyc and len(cyc) > 1:
                _issue(
                    out, name=name, level=ERROR,
                    msg="Петля balancer: " + " → ".join(cyc),
                    field="outbound",
                )
        dialer = _outbound_dialer_tag(store, target)
        if dialer and dialer == target:
            _issue(out, name=name, level=ERROR, msg=f"Dialer proxy «{dialer}» совпадает с outbound — петля.")
        # inbound → outbound that dials back through same inbound tag (best-effort)
        ib_tags = [str(x) for x in (r.get("inbound_tags") or []) if str(x).strip()]
        if ib_tags and dialer:
            for ib in store.get("inbounds") or []:
                if ib.get("tag") in ib_tags and str(ib.get("outbound") or "") == dialer:
                    _issue(
                        out, name=name, level=ERROR,
                        msg=f"Петля: inbound {ib.get('tag')} → {target} dialer→{dialer} снова на этот inbound.",
                    )
        sig = json_sig(r)
        if sig in seen_sig:
            _issue(
                out, name=name, level=WARN,
                msg=f"Дублирует селекторы правила «{seen_sig[sig]}».",
            )
        else:
            seen_sig[sig] = name
        missing = xray.route_missing_geo(r)
        if missing:
            _issue(out, name=name, level=WARN, msg="Нет geo-файлов: " + ", ".join(missing))

    for b in bals.values():
        if not b.get("enabled", True):
            continue
        tag = str(b.get("tag") or "")
        if not tag:
            continue
        members = xray.balancer_member_tags(store, b, healthy_only=False)
        if not members:
            _issue(out, name=tag, level=WARN, msg="Balancer без members — пустой пул.")
        cyc = _balancer_cycle(store, tag)
        if cyc and len(set(cyc)) < len(cyc):
            _issue(out, name=tag, level=ERROR, msg="Петля balancer: " + " → ".join(cyc))

    return out


def json_sig(r: dict) -> str:
    keys = ("domain", "ip", "user", "source", "protocol", "inbound_tags", "network", "port", "sourcePort", "inbound_all")
    parts: dict[str, Any] = {}
    for k in keys:
        v = r.get(k)
        if isinstance(v, list):
            parts[k] = sorted(str(x) for x in v)
        elif v:
            parts[k] = v
    return repr(sorted(parts.items()))


def lint_blocks_apply(issues: list[dict]) -> bool:
    return any(i.get("level") == ERROR for i in issues)


def format_issues(issues: list[dict], *, limit: int = 8) -> str:
    lines = []
    for i in issues[:limit]:
        lvl = "ERR" if i.get("level") == ERROR else "WARN"
        lines.append(f"[{lvl}] {i.get('name')}: {i.get('msg')}")
    if len(issues) > limit:
        lines.append(f"… ещё {len(issues) - limit}")
    return "\n".join(lines)
