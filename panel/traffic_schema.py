"""Traffic schema: visual path client → inbound → filters → rules → exit + destination checker."""
from __future__ import annotations

import ipaddress
import re
from typing import Any

import protocols as P
import xray_runtime as xray

_FILTER_HINTS = (
    ("ads", ("ads", "adblock", "реклам", "telemetry", "телеметр")),
    ("torrent", ("torrent", "bittorrent", "торрент")),
    ("porn", ("porn", "adult", "nsfw")),
    ("private", ("private", "lan", "local")),
    ("quic", ("quic",)),
)


def _host_from_dest(dest: str) -> tuple[str, str]:
    """Return (kind, value) where kind is 'domain' | 'ip'."""
    raw = (dest or "").strip().lower()
    raw = raw.split("/")[0].split(":")[0].strip(".")
    if not raw:
        return "domain", ""
    try:
        ipaddress.ip_address(raw)
        return "ip", raw
    except ValueError:
        return "domain", raw


def _match_domain_entry(entry: str, host: str) -> bool | None:
    """True/False definitive; None = geosite/ext unknown without .dat."""
    e = str(entry or "").strip()
    if not e or not host:
        return False
    low = e.lower()
    if low.startswith("regexp:"):
        try:
            return bool(re.search(e[7:], host, re.I))
        except re.error:
            return False
    if low.startswith("full:"):
        return host == e[5:].lower().lstrip()
    if low.startswith("domain:"):
        d = e[7:].lower().lstrip()
        return host == d or host.endswith("." + d)
    if low.startswith("keyword:"):
        return e[8:].lower() in host
    if low.startswith("geosite:") or low.startswith("ext:"):
        return None
    d = low
    return host == d or host.endswith("." + d)


def _match_ip_entry(entry: str, ip: str) -> bool | None:
    e = str(entry or "").strip()
    if not e or not ip:
        return False
    low = e.lower()
    if low.startswith("geoip:"):
        tag = low[6:]
        if tag == "private":
            try:
                return ipaddress.ip_address(ip).is_private
            except ValueError:
                return False
        return None
    if low.startswith("ext:"):
        return None
    try:
        net = ipaddress.ip_network(e, strict=False)
        return ipaddress.ip_address(ip) in net
    except ValueError:
        return False


def _rule_matches(rule: dict, *, kind: str, value: str, email: str, inbound_tag: str) -> tuple[bool, str]:
    """Whether panel route matches this flow. Returns (matched, reason)."""
    if not rule.get("enabled", True):
        return False, "выключено"

    users = [str(u).strip() for u in (rule.get("user") or []) if str(u).strip()]
    if users and email not in users and not any(email.startswith(u + "~") for u in users):
        return False, "другой user"

    ibs = [str(t).strip() for t in (rule.get("inbound_tags") or []) if str(t).strip()]
    if ibs and inbound_tag not in ibs:
        return False, "другой inbound"

    # Domain / IP arms are OR (same as build)
    domain = [str(x) for x in (rule.get("domain") or []) if str(x).strip()]
    ips = [str(x) for x in (rule.get("ip") or []) if str(x).strip()]
    proto = [str(x) for x in (rule.get("protocol") or []) if str(x).strip()]

    hit = False
    reason_bits: list[str] = []
    ambiguous = False

    if kind == "domain" and domain:
        for entry in domain:
            m = _match_domain_entry(entry, value)
            if m is True:
                hit = True
                reason_bits.append(entry)
                break
            if m is None:
                ambiguous = True
        if not hit and not ambiguous and domain and not ips and not proto:
            return False, "domain не совпал"
    elif kind == "ip" and ips:
        for entry in ips:
            m = _match_ip_entry(entry, value)
            if m is True:
                hit = True
                reason_bits.append(entry)
                break
            if m is None:
                ambiguous = True
        if not hit and not ambiguous and ips and not domain and not proto:
            return False, "ip не совпал"
    elif kind == "domain" and ips and not domain:
        # Domain dest vs IP-only rule: need DNS — treat as possible via IPIfNonMatch legacy note
        ambiguous = True
    elif kind == "ip" and domain and not ips:
        ambiguous = True

    if proto and not hit and not domain and not ips:
        # Destination checker only knows domain/IP — L7 sniff (bittorrent/…) is runtime-only.
        # Never treat protocol-only rules as a match for youtube.com etc.
        return False, "protocol " + ",".join(proto) + " (только sniff в Xray)"

    if hit:
        return True, "совпало: " + ", ".join(reason_bits[:3])
    if ambiguous and (domain or ips) and not hit:
        # Do not pretend geosite/geoip matched — that made every check look blocked by ads lists
        return False, "geosite/geoip (нужен Xray .dat)"
    if not domain and not ips and not proto and not users and not ibs and not rule.get("port") and not rule.get("network"):
        return False, "пустое правило"
    if not domain and not ips and not proto:
        return True, "условия port/network/source"
    return False, "нет совпадения"


def _filter_kind(rule: dict) -> str | None:
    if xray.normalize_outbound_tag(rule.get("outbound") or "") != "block":
        return None
    blob = " ".join(
        [
            str(rule.get("name") or ""),
            " ".join(str(x) for x in (rule.get("domain") or [])),
            " ".join(str(x) for x in (rule.get("protocol") or [])),
            " ".join(str(x) for x in (rule.get("ip") or [])),
        ]
    ).lower()
    for kind, keys in _FILTER_HINTS:
        if any(k in blob for k in keys):
            return kind
    return "block"


def _exit_meta(store: dict, tag: str) -> dict:
    tag = xray.normalize_outbound_tag(tag)
    label = xray.outbound_label(store, tag)
    kind = "direct" if tag == "direct" else ("block" if tag == "block" else "outbound")
    if tag.startswith("lb_") or any(
        (b.get("tag") == tag) for b in xray.ensure_balancers(store).values()
    ):
        kind = "pool"
        members = []
        for b in xray.ensure_balancers(store).values():
            if b.get("tag") == tag:
                members = xray.balancer_member_tags(store, b, healthy_only=False)
                break
        return {"tag": tag, "label": label, "kind": kind, "members": members, "fallback": "block"}
    status = ""
    for o in store.get("outbounds_custom") or []:
        if o.get("tag") == tag:
            status = xray.custom_outbound_status(o)
            break
    return {"tag": tag, "label": label, "kind": kind, "status": status}


def build_schema(store: dict, *, online: dict | None = None) -> dict:
    online = online or {}
    clients = [xray.ensure_client(c) for c in store.get("clients") or []]
    active_clients = [c for c in clients if xray.client_access_ok(c)]
    inbounds = [i for i in xray.client_capable_inbounds(store) if i.get("enabled", True)]
    routes = [r for r in (store.get("routes") or [])]
    filters = []
    rules = []
    for r in routes:
        fk = _filter_kind(r)
        item = {
            "name": r.get("name") or "",
            "enabled": bool(r.get("enabled", True)),
            "outbound": xray.normalize_outbound_tag(r.get("outbound") or "direct"),
            "domain": list(r.get("domain") or []),
            "ip": list(r.get("ip") or []),
            "protocol": list(r.get("protocol") or []),
            "filter_kind": fk,
            "label": xray.outbound_label(store, xray.normalize_outbound_tag(r.get("outbound") or "direct")),
        }
        if fk:
            filters.append(item)
        else:
            rules.append(item)

    client_rows = []
    online_n = 0
    for c in active_clients:
        email = c.get("email") or ""
        raw = online.get(email)
        if isinstance(raw, list):
            ips = [str(x) for x in raw]
        elif isinstance(raw, dict):
            ips = [str(x) for x in (raw.get("ips") or list(raw.keys()))]
        else:
            ips = []
        on = bool(ips) or email in online
        if on:
            online_n += 1
        client_rows.append({
            "email": email,
            "remark": c.get("remark") or email,
            "outbound": xray.client_default_outbound(store, c),
            "outbound_label": xray.outbound_label(store, xray.client_default_outbound(store, c)),
            "inbounds": [i["tag"] for i in xray.client_inbounds(store, c)],
            "online": on,
            "ips": ips[:5],
            "group_id": c.get("group_id") or "",
        })

    ib_rows = []
    for ib in inbounds:
        proto = ib.get("protocol") or ""
        st = ib.get("stream") or {}
        ib_rows.append({
            "tag": ib.get("tag") or "",
            "remark": ib.get("remark") or ib.get("tag") or "",
            "protocol": proto,
            "network": st.get("network") or ("hysteria" if proto == "hysteria" else "raw"),
            "security": st.get("security") or "",
            "port": ib.get("port"),
            "direct": P.is_direct(ib),
            "enabled": bool(ib.get("enabled", True)),
        })

    exits = []
    seen = set()
    for tag in ("direct", "block"):
        exits.append(_exit_meta(store, tag))
        seen.add(tag)
    for b in xray.ensure_balancers(store).values():
        if not b.get("enabled", True):
            continue
        t = b.get("tag") or ""
        if t and t not in seen:
            exits.append(_exit_meta(store, t))
            seen.add(t)
    for o in store.get("outbounds_custom") or []:
        if not o.get("enabled", True):
            continue
        t = o.get("tag") or ""
        if t and t not in seen:
            exits.append(_exit_meta(store, t))
            seen.add(t)

    working = sum(1 for e in exits if e["kind"] != "block" and e.get("status") in ("", "connected", "ok", None))
    # count non-block exits that look up
    up = 0
    total_exits = 0
    for e in exits:
        if e["kind"] in ("direct", "block"):
            continue
        total_exits += 1
        st = str(e.get("status") or "")
        if e["kind"] == "pool" or st in ("", "connected") or st == "ok" or not st:
            if st not in ("disconnected", "error", "down"):
                up += 1

    return {
        "clients": client_rows,
        "inbounds": ib_rows,
        "filters": filters,
        "rules": rules,
        "exits": exits,
        "stats": {
            "clients_online": online_n,
            "clients_total": len(client_rows),
            "inbounds": len(ib_rows),
            "exits_up": up,
            "exits_total": total_exits,
        },
    }


def check_destination(
    store: dict,
    *,
    email: str,
    inbound_tag: str,
    dest: str,
) -> dict:
    kind, value = _host_from_dest(dest)
    if not value:
        return {"ok": False, "error": "Укажите домен или IP"}

    client = next((c for c in store.get("clients") or [] if c.get("email") == email), None)
    if not client:
        return {"ok": False, "error": "Клиент не найден"}
    client = xray.ensure_client(client)
    if not xray.client_access_ok(client):
        return {"ok": False, "error": "Клиент отключён / лимит"}

    capable = {i["tag"]: i for i in xray.client_capable_inbounds(store)}
    if inbound_tag not in capable:
        return {"ok": False, "error": "Inbound недоступен"}
    allowed_ibs = {i["tag"] for i in xray.client_inbounds(store, client)}
    if allowed_ibs and inbound_tag not in allowed_ibs:
        return {"ok": False, "error": "Этот inbound не назначен клиенту"}

    ib = capable[inbound_tag]
    ib_st = ib.get("stream") or {}
    ib_proto = ib.get("protocol") or ""
    ib_net = ib_st.get("network") or ("hysteria" if ib_proto == "hysteria" else "raw")
    ib_sec = ib_st.get("security") or "none"
    client_ob = xray.client_default_outbound(store, client)
    path: list[dict[str, Any]] = [
        {
            "col": "client",
            "id": email,
            "title": client.get("remark") or email,
            "meta": email,
            "badges": [
                {"text": xray.outbound_label(store, client_ob), "kind": ""},
            ],
        },
        {
            "col": "inbound",
            "id": inbound_tag,
            "title": ib.get("remark") or inbound_tag,
            "meta": f"{ib_proto} · {ib_net}/{ib_sec} · :{ib.get('port')}",
            "badges": [{"text": inbound_tag, "kind": "mono"}],
        },
    ]

    matched_filters: list[dict] = []
    matched_rule: dict | None = None
    target = ""
    detail = ""

    for r in store.get("routes") or []:
        if not r.get("enabled", True):
            continue
        ok, why = _rule_matches(
            r, kind=kind, value=value, email=email, inbound_tag=inbound_tag,
        )
        if not ok:
            continue
        # Prefer definitive matches over geosite "возможно"
        definitive = not why.startswith("возможно")
        item = {
            "name": r.get("name") or "",
            "outbound": xray.normalize_outbound_tag(r.get("outbound") or "direct"),
            "why": why,
            "filter_kind": _filter_kind(r),
            "definitive": definitive,
        }
        if item["filter_kind"]:
            if not definitive:
                continue
            matched_filters.append(item)
            if item["outbound"] == "block":
                target = "block"
                detail = why
                matched_rule = item
                break
            continue
        if not definitive:
            continue
        matched_rule = item
        target = item["outbound"]
        detail = why
        break

    if not target:
        # subscription identity catch-alls are per email~tag — main email uses client outbound
        if client_ob == xray.NONE_TAG:
            target = "block"
            detail = "outbound клиента = none"
        else:
            target = xray.normalize_outbound_tag(client_ob)
            detail = "outbound по умолчанию клиента"

    for f in matched_filters:
        fk = f.get("filter_kind") or "block"
        path.append({
            "col": "filter",
            "id": f["name"],
            "title": f["name"],
            "meta": f["why"],
            "badges": [{"text": fk, "kind": "warn" if fk != "block" else "err"}],
        })
    if matched_rule and matched_rule.get("filter_kind") and target == "block":
        # block filter already in path; still show exit below
        pass
    elif matched_rule and not matched_rule.get("filter_kind"):
        path.append({
            "col": "rule",
            "id": matched_rule["name"],
            "title": matched_rule["name"],
            "meta": matched_rule["why"],
            "badges": [{"text": "→ " + xray.outbound_label(store, matched_rule["outbound"]), "kind": ""}],
        })
    elif not matched_rule:
        path.append({
            "col": "rule",
            "id": "default",
            "title": "По умолчанию",
            "meta": detail,
            "badges": [{"text": "client outbound", "kind": ""}],
        })

    exit_info = _exit_meta(store, target)
    route_title = {
        "direct": "Напрямую", "block": "Блок", "pool": "Пул выходов",
    }.get(exit_info["kind"], "Выход")
    path.append({
        "col": "exit",
        "id": exit_info["tag"],
        "title": exit_info["label"] if exit_info["kind"] != "direct" else route_title,
        "meta": {
            "direct": "С адреса сервера",
            "block": "blackhole — трафик отбрасывается",
            "pool": "Пул: " + (", ".join((exit_info.get("members") or [])[:6]) or "—"),
        }.get(exit_info["kind"], exit_info.get("status") or exit_info["tag"]),
        "badges": [
            {"text": exit_info["tag"], "kind": "mono"},
            *(
                [{"text": "up", "kind": "ok"}]
                if exit_info.get("status") in ("", "connected", "ok", None) and exit_info["kind"] != "block"
                else ([{"text": "block", "kind": "err"}] if exit_info["kind"] == "block" else [])
            ),
        ],
    })

    summary = ""
    if exit_info["kind"] == "block":
        summary = f"Трафик к {value} блокируется (blackhole)"
    elif exit_info["kind"] == "direct":
        summary = f"Напрямую с адреса сервера → {value}"
    elif exit_info["kind"] == "pool":
        members = ", ".join(exit_info.get("members") or []) or "—"
        summary = f"Через пул {exit_info['tag']} ({members})"
    else:
        summary = f"Через outbound {exit_info['label']}"

    return {
        "ok": True,
        "dest": value,
        "kind": kind,
        "email": email,
        "inbound": inbound_tag,
        "target": target,
        "exit": exit_info,
        "matched_rule": matched_rule,
        "matched_filters": matched_filters,
        "detail": detail,
        "summary": summary,
        "path": path,
    }
