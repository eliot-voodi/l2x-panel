"""Protocol layer: inbound/stream builders, share links, link parsing, client config formats.

Everything client-facing is expressed as an *endpoint* dict so that share links,
Xray JSON, Clash/Mihomo and sing-box exports are generated from one source:

    {"protocol", "address", "port", "remark",
     "uuid" | "password" | "method" | "user",
     "flow", "net", "security", "sni", "fp", "alpn", "pbk", "sid", "spx",
     "path", "host", "service_name", "mode", "header", "allow_insecure",
     wireguard: "private_key", "peer_public_key", "local_address", "mtu"}
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import uuid as uuidlib
from typing import Any
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit

USER_PROTOCOLS = ("vless", "vmess", "trojan", "shadowsocks", "hysteria")
ALL_PROTOCOLS = ("vless", "vmess", "trojan", "shadowsocks", "hysteria", "wireguard", "socks", "http", "dokodemo-door")
NETWORKS = ("raw", "ws", "grpc", "httpupgrade", "xhttp", "kcp", "hysteria")
SECURITIES = ("none", "tls", "reality")
SS_METHODS = (
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "aes-256-gcm",
    "aes-128-gcm",
    "chacha20-poly1305",
)
FINGERPRINTS = ("chrome", "firefox", "safari", "ios", "android", "edge", "random", "randomized")


# ---------------------------------------------------------------- defaults

def default_stream(security: str = "reality") -> dict:
    return {
        "network": "raw",
        "security": security,
        "tls": {
            "server_name": "",
            "cert_file": "",
            "key_file": "",
            "alpn": ["h2", "http/1.1"],
            "fingerprint": "chrome",
            "min_version": "1.2",
            "allow_insecure": False,
        },
        "reality": {
            "dest": "www.cloudflare.com:443",
            "server_names": ["www.cloudflare.com"],
            "private_key": "",
            "public_key": "",
            "short_ids": [secrets.token_hex(4)],
            "fingerprint": "chrome",
            "spider_x": "/",
        },
        "raw": {"header": "none", "http_host": "", "http_path": "/"},
        "ws": {"path": "/ws", "host": ""},
        "grpc": {"service_name": "grpc", "multi_mode": False},
        "httpupgrade": {"path": "/up", "host": ""},
        "xhttp": {"path": "/xh", "host": "", "mode": "auto"},
        "kcp": {"mtu": 1350, "tti": 20, "uplink": 5, "downlink": 20, "congestion": False},
    }


def default_settings(protocol: str) -> dict:
    if protocol == "vless":
        return {"flow": "xtls-rprx-vision"}
    if protocol == "shadowsocks":
        return {"method": "2022-blake3-aes-256-gcm", "password": ss_server_key("2022-blake3-aes-256-gcm"), "network": "tcp,udp"}
    if protocol == "hysteria":
        return {"version": 2, "udp_idle": 60, "brutal_up": "100mbps", "brutal_down": "300mbps",
                "masquerade_type": "string", "masquerade_content": "OK", "masquerade_url": "", "masquerade_dir": ""}
    if protocol == "wireguard":
        return {"secret_key": "", "public_key": "", "mtu": 1420, "address_pool": "10.66.0.0/24"}
    if protocol == "socks":
        return {"auth": "password", "udp": True}
    if protocol == "http":
        return {"auth": "password"}
    if protocol == "dokodemo-door":
        return {"address": "1.1.1.1", "port": 53, "network": "tcp,udp", "follow_redirect": False}
    return {}


def default_inbound(protocol: str = "vless", port: int = 443, tag: str = "vless-in") -> dict:
    if protocol == "hysteria":
        sec = "tls"
    else:
        sec = "reality" if protocol == "vless" else ("none" if protocol in ("shadowsocks", "wireguard", "socks", "http", "dokodemo-door") else "tls")
    return {
        "id": 0,
        "tag": tag,
        "remark": tag,
        "enabled": True,
        "listen": "0.0.0.0",
        "port": port,
        "protocol": protocol,
        "settings": default_settings(protocol),
        "stream": default_stream(sec),
        "sniffing": {"enabled": True, "dest": ["http", "tls", "quic"], "route_only": False, "metadata_only": False},
        "fallbacks": [],
        "outbound": "direct",
        "share_host": "",
        "total_gb": 0,
        "expire_at": "",
        "traffic": {"up": 0, "down": 0, "last_up": 0, "last_down": 0},
    }


def ensure_inbound_shape(ib: dict) -> dict:
    proto = ib.get("protocol") or "vless"
    base = default_inbound(proto, int(ib.get("port") or 443), ib.get("tag") or f"{proto}-in")
    for k, v in base.items():
        ib.setdefault(k, v)
    for k, v in default_settings(proto).items():
        ib["settings"].setdefault(k, v)
    st = ib["stream"]
    for k, v in default_stream(st.get("security") or "none").items():
        if isinstance(v, dict):
            cur = st.setdefault(k, {})
            for kk, vv in v.items():
                cur.setdefault(kk, vv)
        else:
            st.setdefault(k, v)
    if st.get("network") == "tcp":
        st["network"] = "raw"
    for k, v in base["sniffing"].items():
        ib["sniffing"].setdefault(k, v)
    for k, v in base["traffic"].items():
        ib["traffic"].setdefault(k, v)
    return ib


# ---------------------------------------------------------------- keys / secrets

def ss_key_len(method: str) -> int:
    return 16 if "128" in method else 32


def ss_server_key(method: str) -> str:
    if method.startswith("2022-"):
        return base64.b64encode(secrets.token_bytes(ss_key_len(method))).decode()
    return secrets.token_urlsafe(16)


def ss_user_key(seed: str, method: str) -> str:
    """Deterministic per-identity SS key (base64 key for 2022, password otherwise)."""
    digest = hashlib.sha256(f"l2x-ss:{seed}".encode()).digest()
    if method.startswith("2022-"):
        return base64.b64encode(digest[: ss_key_len(method)]).decode()
    return base64.urlsafe_b64encode(digest[:18]).decode().rstrip("=")


def derived_password(seed: str) -> str:
    return hashlib.sha256(f"l2x-pw:{seed}".encode()).hexdigest()[:24]


def identity_uuid(client_uuid: str, tag: str) -> str:
    return str(uuidlib.uuid5(uuidlib.NAMESPACE_URL, f"l2x-sub:{client_uuid}:{tag}"))


# ---------------------------------------------------------------- server side builders

def build_stream_settings(stream: dict) -> dict:
    net = stream.get("network") or "raw"
    sec = stream.get("security") or "none"
    out: dict[str, Any] = {"network": net, "security": sec}
    if net == "raw":
        raw = stream.get("raw") or {}
        if raw.get("header") == "http":
            out["rawSettings"] = {
                "header": {
                    "type": "http",
                    "request": {
                        "path": [raw.get("http_path") or "/"],
                        "headers": {"Host": [h.strip() for h in (raw.get("http_host") or "").split(",") if h.strip()]},
                    },
                }
            }
    elif net == "ws":
        ws = stream.get("ws") or {}
        out["wsSettings"] = {"path": ws.get("path") or "/", **({"host": ws["host"]} if ws.get("host") else {})}
    elif net == "grpc":
        g = stream.get("grpc") or {}
        out["grpcSettings"] = {"serviceName": g.get("service_name") or "grpc", "multiMode": bool(g.get("multi_mode"))}
    elif net == "httpupgrade":
        h = stream.get("httpupgrade") or {}
        out["httpupgradeSettings"] = {"path": h.get("path") or "/", **({"host": h["host"]} if h.get("host") else {})}
    elif net == "xhttp":
        x = stream.get("xhttp") or {}
        out["xhttpSettings"] = {
            "path": x.get("path") or "/",
            "mode": x.get("mode") or "auto",
            **({"host": x["host"]} if x.get("host") else {}),
        }
    elif net == "kcp":
        k = stream.get("kcp") or {}
        out["kcpSettings"] = {
            "mtu": int(k.get("mtu") or 1350),
            "tti": int(k.get("tti") or 20),
            "uplinkCapacity": int(k.get("uplink") or 5),
            "downlinkCapacity": int(k.get("downlink") or 20),
            "congestion": bool(k.get("congestion")),
        }
    if sec == "tls":
        t = stream.get("tls") or {}
        tls: dict[str, Any] = {
            "serverName": t.get("server_name") or "",
            "alpn": t.get("alpn") or ["h2", "http/1.1"],
            "minVersion": t.get("min_version") or "1.2",
        }
        if t.get("cert_file") and t.get("key_file"):
            tls["certificates"] = [{"certificateFile": t["cert_file"], "keyFile": t["key_file"]}]
        out["tlsSettings"] = tls
    elif sec == "reality":
        r = stream.get("reality") or {}
        out["realitySettings"] = {
            "show": False,
            "dest": r.get("dest") or "www.cloudflare.com:443",
            "xver": 0,
            "serverNames": r.get("server_names") or ["www.cloudflare.com"],
            "privateKey": r.get("private_key") or "",
            "shortIds": r.get("short_ids") or [""],
        }
    return out


def _fallbacks(ib: dict) -> list[dict]:
    out = []
    for fb in ib.get("fallbacks") or []:
        dest = str(fb.get("dest") or "").strip()
        if not dest:
            continue
        item: dict[str, Any] = {"dest": int(dest) if dest.isdigit() else dest}
        for k in ("name", "alpn", "path"):
            if fb.get(k):
                item[k] = fb[k]
        if fb.get("xver"):
            item["xver"] = int(fb["xver"])
        out.append(item)
    return out


def supports_flow(ib: dict) -> bool:
    st = ib.get("stream") or {}
    return ib.get("protocol") == "vless" and (st.get("network") or "raw") == "raw" and st.get("security") in ("tls", "reality")


def build_inbound(ib: dict, identities: list[dict]) -> dict:
    """identities: [{uuid, email, password, wg_public, wg_ip, main}]"""
    proto = ib["protocol"]
    s = ib.get("settings") or {}
    settings: dict[str, Any] = {}
    if proto == "vless":
        flow = s.get("flow") if supports_flow(ib) else ""
        settings = {
            "clients": [{"id": i["uuid"], "email": i["email"], **({"flow": flow} if flow else {})} for i in identities],
            "decryption": "none",
        }
        if fb := _fallbacks(ib):
            settings["fallbacks"] = fb
    elif proto == "vmess":
        settings = {"clients": [{"id": i["uuid"], "email": i["email"]} for i in identities]}
    elif proto == "trojan":
        settings = {"clients": [{"password": i["password"], "email": i["email"]} for i in identities]}
        if fb := _fallbacks(ib):
            settings["fallbacks"] = fb
    elif proto == "shadowsocks":
        method = s.get("method") or "2022-blake3-aes-256-gcm"
        if method.startswith("2022-"):
            settings = {
                "method": method,
                "password": s.get("password") or "",
                "network": s.get("network") or "tcp,udp",
                "clients": [{"password": ss_user_key(i["password"], method), "email": i["email"]} for i in identities],
            }
        else:
            settings = {
                "network": s.get("network") or "tcp,udp",
                "clients": [{"method": method, "password": ss_user_key(i["password"], method), "email": i["email"]} for i in identities],
            }
    elif proto == "wireguard":
        settings = {
            "secretKey": s.get("secret_key") or "",
            "mtu": int(s.get("mtu") or 1420),
            "peers": [
                {"publicKey": i["wg_public"], "allowedIPs": [f"{i['wg_ip']}/32"]}
                for i in identities
                if i.get("wg_public") and i.get("wg_ip")
            ],
        }
    elif proto in ("socks", "http"):
        accounts = [{"user": i["email"], "pass": i["password"]} for i in identities if i.get("main")]
        if proto == "socks":
            settings = {"auth": "password" if accounts and s.get("auth") != "noauth" else "noauth", "udp": bool(s.get("udp", True))}
            if settings["auth"] == "password":
                settings["accounts"] = accounts
        else:
            settings = {"accounts": accounts} if s.get("auth") != "noauth" else {}
    elif proto == "dokodemo-door":
        settings = {
            "address": s.get("address") or "1.1.1.1",
            "port": int(s.get("port") or 53),
            "network": s.get("network") or "tcp,udp",
            "followRedirect": bool(s.get("follow_redirect")),
        }
    elif proto == "hysteria":
        settings = {
            "version": 2,
            "clients": [{"auth": i["password"], "email": i["email"]} for i in identities],
        }
    out: dict[str, Any] = {
        "tag": ib["tag"],
        "listen": ib.get("listen") or "0.0.0.0",
        "port": int(ib["port"]),
        "protocol": proto,
        "settings": settings,
    }
    if proto == "hysteria":
        out["streamSettings"] = _hysteria_stream(ib)
    elif proto in USER_PROTOCOLS:
        out["streamSettings"] = build_stream_settings(ib.get("stream") or {})
    sn = ib.get("sniffing") or {}
    if sn.get("enabled"):
        out["sniffing"] = {
            "enabled": True,
            "destOverride": sn.get("dest") or ["http", "tls", "quic"],
            "routeOnly": bool(sn.get("route_only")),
            "metadataOnly": bool(sn.get("metadata_only")),
        }
    return out


def _hysteria_stream(ib: dict) -> dict:
    s = ib.get("settings") or {}
    st = ib.get("stream") or {}
    tls = (st.get("tls") or {})
    hy: dict[str, Any] = {
        "network": "hysteria",
        "security": "tls",
        "tlsSettings": {
            "certificates": [{
                "certificateFile": tls.get("cert_file") or "",
                "keyFile": tls.get("key_file") or "",
            }],
        },
        "hysteriaSettings": {
            "version": 2,
            "udpIdleTimeout": int(s.get("udp_idle") or 60),
        },
        "finalmask": {
            "quicParams": {
                "brutalUp": s.get("brutal_up") or "100mbps",
                "brutalDown": s.get("brutal_down") or "300mbps",
            },
        },
    }
    mtype = s.get("masquerade_type") or "string"
    if mtype == "proxy" and s.get("masquerade_url"):
        hy["hysteriaSettings"]["masquerade"] = {"type": "proxy", "url": s["masquerade_url"], "rewriteHost": True}
    elif mtype == "file" and s.get("masquerade_dir"):
        hy["hysteriaSettings"]["masquerade"] = {"type": "file", "dir": s["masquerade_dir"]}
    else:
        hy["hysteriaSettings"]["masquerade"] = {
            "type": "string", "content": s.get("masquerade_content") or "OK", "statusCode": 200,
        }
    return hy


# ---------------------------------------------------------------- endpoints

def endpoint_for(ib: dict, ident: dict, host: str, remark: str) -> dict | None:
    proto = ib["protocol"]
    if proto not in USER_PROTOCOLS + ("wireguard", "socks", "http"):
        return None
    st = ib.get("stream") or {}
    net = st.get("network") or "raw"
    sec = st.get("security") or "none"
    ep: dict[str, Any] = {
        "protocol": proto,
        "address": ib.get("share_host") or host,
        "port": int(ib["port"]),
        "remark": remark,
        "net": net,
        "security": sec,
    }
    if proto in ("vless", "vmess"):
        ep["uuid"] = ident["uuid"]
    if proto == "vless" and supports_flow(ib):
        ep["flow"] = (ib.get("settings") or {}).get("flow") or ""
    if proto == "trojan":
        ep["password"] = ident["password"]
    if proto == "shadowsocks":
        s = ib.get("settings") or {}
        method = s.get("method") or "2022-blake3-aes-256-gcm"
        ep["method"] = method
        user_key = ss_user_key(ident["password"], method)
        ep["password"] = f"{s.get('password')}:{user_key}" if method.startswith("2022-") else user_key
    if proto in ("socks", "http"):
        if not ident.get("main"):
            return None
        ep["user"] = ident["email"]
        ep["password"] = ident["password"]
    if proto == "wireguard":
        if not ident.get("main") or not ident.get("wg_private"):
            return None
        s = ib.get("settings") or {}
        ep.update(
            {
                "private_key": ident["wg_private"],
                "peer_public_key": s.get("public_key") or "",
                "local_address": f"{ident['wg_ip']}/32",
                "mtu": int(s.get("mtu") or 1420),
            }
        )
        return ep
    if proto == "hysteria":
        s = ib.get("settings") or {}
        t = st.get("tls") or {}
        ep.update({
            "password": ident["password"],
            "net": "hysteria",
            "security": "tls",
            "sni": t.get("server_name") or (ib.get("share_host") or host),
            "allow_insecure": bool(t.get("allow_insecure")),
            "brutal_up": s.get("brutal_up") or "100mbps",
            "brutal_down": s.get("brutal_down") or "300mbps",
        })
        return ep
    if net == "raw":
        raw = st.get("raw") or {}
        if raw.get("header") == "http":
            ep["header"] = "http"
            ep["host"] = raw.get("http_host") or ""
            ep["path"] = raw.get("http_path") or "/"
    elif net in ("ws", "httpupgrade", "xhttp"):
        cfg = st.get(net) or {}
        ep["path"] = cfg.get("path") or "/"
        ep["host"] = cfg.get("host") or ""
        if net == "xhttp":
            ep["mode"] = cfg.get("mode") or "auto"
    elif net == "grpc":
        g = st.get("grpc") or {}
        ep["service_name"] = g.get("service_name") or "grpc"
        ep["mode"] = "multi" if g.get("multi_mode") else "gun"
    if sec == "tls":
        t = st.get("tls") or {}
        ep["sni"] = t.get("server_name") or ""
        ep["fp"] = t.get("fingerprint") or "chrome"
        ep["alpn"] = ",".join(t.get("alpn") or [])
        ep["allow_insecure"] = bool(t.get("allow_insecure"))
    elif sec == "reality":
        r = st.get("reality") or {}
        names = r.get("server_names") or []
        ep["sni"] = names[0] if names else str(r.get("dest") or "").split(":")[0]
        ep["fp"] = r.get("fingerprint") or "chrome"
        ep["pbk"] = r.get("public_key") or ""
        sids = r.get("short_ids") or []
        ep["sid"] = sids[0] if sids else ""
        ep["spx"] = r.get("spider_x") or "/"
    return ep


def _link_net(net: str) -> str:
    return "tcp" if net == "raw" else net


def endpoint_to_link(ep: dict) -> str:
    proto = ep["protocol"]
    remark = quote(ep.get("remark") or proto)
    addr = ep["address"]
    port = ep["port"]
    if proto in ("socks", "http"):
        cred = base64.b64encode(f"{ep['user']}:{ep['password']}".encode()).decode()
        return f"{proto}://{cred}@{addr}:{port}#{remark}"
    if proto == "hysteria":
        q = urlencode({
            "insecure": "1" if ep.get("allow_insecure") else "0",
            "sni": ep.get("sni") or "",
            "obfs": "none",
        }, doseq=True)
        return f"hy2://{quote(ep['password'], safe='')}@{addr}:{port}?{q}#{remark}"
    if proto == "wireguard":
        q = urlencode(
            {
                "publickey": ep["peer_public_key"],
                "address": ep["local_address"],
                "mtu": ep.get("mtu") or 1420,
            },
            quote_via=quote,
            safe="",
        )
        return f"wireguard://{quote(ep['private_key'], safe='')}@{addr}:{port}?{q}#{remark}"
    if proto == "shadowsocks":
        user = base64.urlsafe_b64encode(f"{ep['method']}:{ep['password']}".encode()).decode().rstrip("=")
        q = ""
        if ep.get("net") not in (None, "raw") or ep.get("security") not in (None, "none"):
            q = urlencode(_stream_params(ep), quote_via=quote, safe="")
        return f"ss://{user}@{addr}:{port}{'?' + q if q else ''}#{remark}"
    if proto == "vmess":
        data = {
            "v": "2",
            "ps": ep.get("remark") or "",
            "add": addr,
            "port": str(port),
            "id": ep["uuid"],
            "aid": "0",
            "scy": "auto",
            "net": _link_net(ep.get("net") or "raw"),
            "type": ep.get("header") or "none",
            "host": ep.get("host") or "",
            "path": ep.get("service_name") if ep.get("net") == "grpc" else (ep.get("path") or ""),
            "tls": "tls" if ep.get("security") == "tls" else "",
            "sni": ep.get("sni") or "",
            "alpn": ep.get("alpn") or "",
            "fp": ep.get("fp") or "",
        }
        return "vmess://" + base64.b64encode(json.dumps(data, ensure_ascii=False).encode()).decode()
    params = _stream_params(ep)
    if proto == "vless":
        params = {"encryption": "none", **params}
        if ep.get("flow"):
            params["flow"] = ep["flow"]
        cred = ep["uuid"]
    else:  # trojan
        cred = quote(ep["password"], safe="")
    q = urlencode(params, quote_via=quote, safe="")
    return f"{proto}://{cred}@{addr}:{port}?{q}#{remark}"


def _stream_params(ep: dict) -> dict:
    net = ep.get("net") or "raw"
    p: dict[str, str] = {"type": _link_net(net), "security": ep.get("security") or "none"}
    if net == "raw" and ep.get("header") == "http":
        p["headerType"] = "http"
    if ep.get("path") and net in ("ws", "httpupgrade", "xhttp", "raw"):
        p["path"] = ep["path"]
    if ep.get("host"):
        p["host"] = ep["host"]
    if net == "grpc":
        p["serviceName"] = ep.get("service_name") or "grpc"
        p["mode"] = ep.get("mode") or "gun"
    if net == "xhttp" and ep.get("mode"):
        p["mode"] = ep["mode"]
    sec = ep.get("security")
    if sec in ("tls", "reality"):
        if ep.get("sni"):
            p["sni"] = ep["sni"]
        p["fp"] = ep.get("fp") or "chrome"
    if sec == "tls":
        if ep.get("alpn"):
            p["alpn"] = ep["alpn"]
        if ep.get("allow_insecure"):
            p["allowInsecure"] = "1"
    if sec == "reality":
        p["pbk"] = ep.get("pbk") or ""
        if ep.get("sid"):
            p["sid"] = ep["sid"]
        p["spx"] = ep.get("spx") or "/"
    return p


def wireguard_conf(ep: dict, dns: str = "1.1.1.1") -> str:
    return (
        "[Interface]\n"
        f"PrivateKey = {ep['private_key']}\n"
        f"Address = {ep['local_address']}\n"
        f"DNS = {dns}\n"
        f"MTU = {ep.get('mtu') or 1420}\n\n"
        "[Peer]\n"
        f"PublicKey = {ep['peer_public_key']}\n"
        "AllowedIPs = 0.0.0.0/0, ::/0\n"
        f"Endpoint = {ep['address']}:{ep['port']}\n"
        "PersistentKeepalive = 25\n"
    )


# ---------------------------------------------------------------- link parsing (outbound import)

def _b64decode(s: str) -> str:
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s).decode("utf-8", errors="replace")


def link_to_endpoint(link: str) -> dict:
    link = link.strip()
    scheme = link.split("://", 1)[0].lower()
    if scheme == "vmess":
        data = json.loads(_b64decode(link[8:]))
        net = data.get("net") or "tcp"
        ep = {
            "protocol": "vmess",
            "address": data.get("add"),
            "port": int(data.get("port") or 443),
            "uuid": data.get("id"),
            "remark": data.get("ps") or "",
            "net": "raw" if net == "tcp" else net,
            "security": "tls" if data.get("tls") == "tls" else "none",
            "sni": data.get("sni") or "",
            "alpn": data.get("alpn") or "",
            "fp": data.get("fp") or "",
            "host": data.get("host") or "",
            "header": data.get("type") if data.get("type") == "http" else "",
        }
        if ep["net"] == "grpc":
            ep["service_name"] = data.get("path") or ""
        else:
            ep["path"] = data.get("path") or ""
        return ep
    u = urlsplit(link)
    q = dict(parse_qsl(u.query))
    remark = unquote(u.fragment or "")
    if scheme == "ss":
        userinfo = unquote(u.username or "")
        if u.password is None and ":" not in userinfo:
            try:
                userinfo = _b64decode(userinfo)
            except Exception:
                pass
        elif u.password is not None:
            userinfo = f"{userinfo}:{unquote(u.password)}"
        method, _, password = userinfo.partition(":")
        if not u.hostname:  # legacy ss://base64(method:pass@host:port)
            raw = _b64decode(link[5:].split("#")[0])
            creds, _, hp = raw.rpartition("@")
            method, _, password = creds.partition(":")
            host, _, port = hp.rpartition(":")
            return {"protocol": "shadowsocks", "address": host, "port": int(port), "method": method,
                    "password": password, "remark": remark, "net": "raw", "security": "none"}
        return {"protocol": "shadowsocks", "address": u.hostname, "port": u.port or 443, "method": method,
                "password": password, "remark": remark, "net": "raw", "security": "none"}
    if scheme in ("socks", "socks5", "http", "https"):
        user = unquote(u.username or "")
        pw = unquote(u.password or "")
        if user and not pw:
            try:
                user, _, pw = _b64decode(user).partition(":")
            except Exception:
                pass
        return {"protocol": "socks" if scheme.startswith("socks") else "http", "address": u.hostname,
                "port": u.port or 1080, "user": user, "password": pw, "remark": remark,
                "net": "raw", "security": "tls" if scheme == "https" else "none"}
    if scheme in ("wireguard", "wg"):
        return {"protocol": "wireguard", "address": u.hostname, "port": u.port or 51820,
                "private_key": unquote(u.username or ""), "peer_public_key": q.get("publickey") or q.get("publicKey") or "",
                "local_address": q.get("address") or "172.16.0.2/32", "mtu": int(q.get("mtu") or 1280),
                "reserved": q.get("reserved") or "", "remark": remark}
    if scheme in ("vless", "trojan"):
        net = q.get("type") or "tcp"
        ep = {
            "protocol": scheme,
            "address": u.hostname,
            "port": u.port or 443,
            "remark": remark,
            "net": "raw" if net == "tcp" else net,
            "security": q.get("security") or ("tls" if scheme == "trojan" else "none"),
            "sni": q.get("sni") or q.get("peer") or "",
            "fp": q.get("fp") or "",
            "alpn": q.get("alpn") or "",
            "pbk": q.get("pbk") or "",
            "sid": q.get("sid") or "",
            "spx": q.get("spx") or "",
            "path": q.get("path") or "",
            "host": q.get("host") or "",
            "service_name": q.get("serviceName") or "",
            "mode": q.get("mode") or "",
            "header": q.get("headerType") or "",
            "flow": q.get("flow") or "",
            "allow_insecure": q.get("allowInsecure") in ("1", "true"),
        }
        if scheme == "vless":
            ep["uuid"] = unquote(u.username or "")
        else:
            ep["password"] = unquote(u.username or "")
        return ep
    raise ValueError(f"неподдерживаемая ссылка: {scheme}")


# ---------------------------------------------------------------- client-side Xray outbound

def endpoint_to_xray_outbound(ep: dict, tag: str = "proxy") -> dict:
    proto = ep["protocol"]
    out: dict[str, Any] = {"tag": tag, "protocol": proto}
    if proto == "vless":
        user = {"id": ep["uuid"], "encryption": "none"}
        if ep.get("flow"):
            user["flow"] = ep["flow"]
        out["settings"] = {"vnext": [{"address": ep["address"], "port": ep["port"], "users": [user]}]}
    elif proto == "vmess":
        out["settings"] = {"vnext": [{"address": ep["address"], "port": ep["port"], "users": [{"id": ep["uuid"], "security": "auto"}]}]}
    elif proto == "trojan":
        out["settings"] = {"servers": [{"address": ep["address"], "port": ep["port"], "password": ep["password"]}]}
    elif proto == "shadowsocks":
        out["settings"] = {"servers": [{"address": ep["address"], "port": ep["port"], "method": ep["method"], "password": ep["password"]}]}
    elif proto in ("socks", "http"):
        srv: dict[str, Any] = {"address": ep["address"], "port": ep["port"]}
        if ep.get("user"):
            srv["users"] = [{"user": ep["user"], "pass": ep.get("password") or ""}]
        out["settings"] = {"servers": [srv]}
    elif proto == "wireguard":
        reserved = ep.get("reserved")
        if isinstance(reserved, str) and reserved:
            try:
                reserved = [int(x) for x in reserved.split(",")]
            except ValueError:
                reserved = None
        peer = {"publicKey": ep["peer_public_key"], "endpoint": f"{ep['address']}:{ep['port']}", "allowedIPs": ["0.0.0.0/0", "::/0"]}
        out["settings"] = {
            "secretKey": ep["private_key"],
            "address": [a.strip() for a in str(ep.get("local_address") or "").split(",") if a.strip()],
            "peers": [peer],
            "mtu": int(ep.get("mtu") or 1280),
            **({"reserved": reserved} if reserved else {}),
        }
        return out
    stream = _client_stream(ep)
    if stream:
        out["streamSettings"] = stream
    return out


def _client_stream(ep: dict) -> dict:
    net = ep.get("net") or "raw"
    sec = ep.get("security") or "none"
    st: dict[str, Any] = {"network": net, "security": sec}
    if net == "raw" and ep.get("header") == "http":
        st["rawSettings"] = {"header": {"type": "http", "request": {"path": [ep.get("path") or "/"], "headers": {"Host": [ep.get("host") or ""]}}}}
    elif net == "ws":
        st["wsSettings"] = {"path": ep.get("path") or "/", **({"host": ep["host"]} if ep.get("host") else {})}
    elif net == "grpc":
        st["grpcSettings"] = {"serviceName": ep.get("service_name") or "", "multiMode": ep.get("mode") == "multi"}
    elif net == "httpupgrade":
        st["httpupgradeSettings"] = {"path": ep.get("path") or "/", **({"host": ep["host"]} if ep.get("host") else {})}
    elif net == "xhttp":
        st["xhttpSettings"] = {"path": ep.get("path") or "/", "mode": ep.get("mode") or "auto", **({"host": ep["host"]} if ep.get("host") else {})}
    if sec == "tls":
        tls: dict[str, Any] = {"serverName": ep.get("sni") or ep["address"], "fingerprint": ep.get("fp") or "chrome"}
        if ep.get("alpn"):
            tls["alpn"] = [a for a in ep["alpn"].split(",") if a]
        if ep.get("allow_insecure"):
            tls["allowInsecure"] = True
        st["tlsSettings"] = tls
    elif sec == "reality":
        st["realitySettings"] = {
            "serverName": ep.get("sni") or "",
            "fingerprint": ep.get("fp") or "chrome",
            "publicKey": ep.get("pbk") or "",
            "shortId": ep.get("sid") or "",
            "spiderX": ep.get("spx") or "/",
        }
    return st


def _parse_json_blob(value: Any) -> Any:
    if value is None or value == "":
        return None
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(str(value))
    except (json.JSONDecodeError, TypeError):
        return None


def apply_sub_json_extras(cfg: dict, extras: dict | None) -> dict:
    """Inject Fragment / Noise / Mux into a JSON subscription client config."""
    if not extras:
        return cfg
    outs = cfg.get("outbounds") or []
    proxy = next((o for o in outs if o.get("tag") == "proxy"), outs[0] if outs else None)
    if not proxy:
        return cfg
    frag = _parse_json_blob(extras.get("fragment"))
    noise = _parse_json_blob(extras.get("noise"))
    mux = _parse_json_blob(extras.get("mux"))
    if frag:
        # Freedom dialer with fragment; chain the proxy outbound through it
        if isinstance(frag, dict) and frag.get("packets"):
            dialer = {"tag": "fragment", "protocol": "freedom", "settings": {"fragment": frag}}
            so = (proxy.setdefault("streamSettings", {})).setdefault("sockopt", {})
            so["dialerProxy"] = "fragment"
            outs.append(dialer)
        elif isinstance(frag, dict):
            proxy.setdefault("streamSettings", {}).setdefault("sockopt", {}).update(frag)
    if noise and isinstance(noise, (dict, list)):
        st = proxy.setdefault("streamSettings", {})
        st["finalmask"] = {"udp": noise if isinstance(noise, list) else [noise]}
    if mux and isinstance(mux, dict):
        proxy["mux"] = {"enabled": True, **mux}
    cfg["outbounds"] = outs
    return cfg


def xray_client_config(ep: dict, extras: dict | None = None) -> dict:
    """Full client config for a JSON subscription item."""
    if ep.get("protocol") == "hysteria":
        proxy = {
            "tag": "proxy", "protocol": "hysteria",
            "settings": {"version": 2, "address": ep["address"], "port": ep["port"]},
            "streamSettings": {
                "network": "hysteria", "security": "tls",
                "tlsSettings": {"serverName": ep.get("sni") or ep["address"], "allowInsecure": bool(ep.get("allow_insecure"))},
                "hysteriaSettings": {"version": 2, "auth": ep["password"]},
                "finalmask": {"quicParams": {
                    "brutalUp": ep.get("brutal_up") or "100mbps",
                    "brutalDown": ep.get("brutal_down") or "300mbps",
                }},
            },
        }
    else:
        proxy = endpoint_to_xray_outbound(ep, "proxy")
    cfg = {
        "remarks": ep.get("remark") or "",
        "log": {"loglevel": "warning"},
        "dns": {"servers": ["1.1.1.1", "8.8.8.8"]},
        "inbounds": [
            {"tag": "socks", "listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": {"udp": True},
             "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True}},
            {"tag": "http", "listen": "127.0.0.1", "port": 10809, "protocol": "http"},
        ],
        "outbounds": [
            proxy,
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"},
                {"type": "field", "network": "tcp,udp", "outboundTag": "proxy"},
            ],
        },
    }
    return apply_sub_json_extras(cfg, extras)


# ---------------------------------------------------------------- Clash / Mihomo

def endpoint_to_clash(ep: dict) -> dict | None:
    proto = ep["protocol"]
    p: dict[str, Any] = {"name": ep.get("remark") or proto, "server": ep["address"], "port": ep["port"], "udp": True}
    if proto == "vless":
        p.update({"type": "vless", "uuid": ep["uuid"]})
        if ep.get("flow"):
            p["flow"] = ep["flow"]
    elif proto == "vmess":
        p.update({"type": "vmess", "uuid": ep["uuid"], "alterId": 0, "cipher": "auto"})
    elif proto == "trojan":
        p.update({"type": "trojan", "password": ep["password"]})
    elif proto == "shadowsocks":
        p.update({"type": "ss", "cipher": ep["method"], "password": ep["password"]})
        return p
    elif proto == "socks":
        p.update({"type": "socks5", "username": ep.get("user"), "password": ep.get("password")})
        return p
    elif proto == "http":
        p.update({"type": "http", "username": ep.get("user"), "password": ep.get("password")})
        return p
    elif proto == "wireguard":
        p.update({"type": "wireguard", "private-key": ep["private_key"], "public-key": ep["peer_public_key"],
                  "ip": ep["local_address"].split("/")[0], "mtu": ep.get("mtu") or 1420})
        return p
    else:
        return None
    net = ep.get("net") or "raw"
    if net == "xhttp" or net == "kcp":
        return None  # not supported by Mihomo
    p["network"] = {"raw": "tcp", "httpupgrade": "ws"}.get(net, net)
    if net == "ws" or net == "httpupgrade":
        opts: dict[str, Any] = {"path": ep.get("path") or "/"}
        if ep.get("host"):
            opts["headers"] = {"Host": ep["host"]}
        if net == "httpupgrade":
            opts["v2ray-http-upgrade"] = True
        p["ws-opts"] = opts
    elif net == "grpc":
        p["grpc-opts"] = {"grpc-service-name": ep.get("service_name") or ""}
    sec = ep.get("security")
    if sec in ("tls", "reality"):
        p["tls"] = True
        if ep.get("sni"):
            p["servername" if proto != "trojan" else "sni"] = ep["sni"]
        p["client-fingerprint"] = ep.get("fp") or "chrome"
        if ep.get("alpn"):
            p["alpn"] = ep["alpn"].split(",")
        if ep.get("allow_insecure"):
            p["skip-cert-verify"] = True
    if sec == "reality":
        p["reality-opts"] = {"public-key": ep.get("pbk") or "", "short-id": ep.get("sid") or ""}
    return p


def clash_config(endpoints: list[dict]) -> dict:
    proxies = [c for c in (endpoint_to_clash(e) for e in endpoints) if c]
    # names must be unique in Clash
    seen: dict[str, int] = {}
    for p in proxies:
        n = p["name"]
        if n in seen:
            seen[n] += 1
            p["name"] = f"{n} #{seen[n]}"
        else:
            seen[n] = 1
    names = [p["name"] for p in proxies]
    return {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "warning",
        "proxies": proxies,
        "proxy-groups": [
            {"name": "PROXY", "type": "select", "proxies": ["AUTO", *names]},
            {"name": "AUTO", "type": "url-test", "url": "https://www.gstatic.com/generate_204", "interval": 300, "proxies": names or ["DIRECT"]},
        ],
        "rules": ["GEOIP,private,DIRECT,no-resolve", "MATCH,PROXY"],
    }


# ---------------------------------------------------------------- sing-box

def endpoint_to_singbox(ep: dict) -> dict | None:
    proto = ep["protocol"]
    o: dict[str, Any] = {"tag": ep.get("remark") or proto, "server": ep["address"], "server_port": ep["port"]}
    if proto == "vless":
        o.update({"type": "vless", "uuid": ep["uuid"]})
        if ep.get("flow"):
            o["flow"] = ep["flow"]
    elif proto == "vmess":
        o.update({"type": "vmess", "uuid": ep["uuid"], "security": "auto", "alter_id": 0})
    elif proto == "trojan":
        o.update({"type": "trojan", "password": ep["password"]})
    elif proto == "shadowsocks":
        o.update({"type": "shadowsocks", "method": ep["method"], "password": ep["password"]})
        return o
    elif proto == "socks":
        o.update({"type": "socks", "username": ep.get("user"), "password": ep.get("password")})
        return o
    elif proto == "http":
        o.update({"type": "http", "username": ep.get("user"), "password": ep.get("password")})
        return o
    else:
        return None
    net = ep.get("net") or "raw"
    if net in ("xhttp", "kcp"):
        return None
    if net == "ws":
        t: dict[str, Any] = {"type": "ws", "path": ep.get("path") or "/"}
        if ep.get("host"):
            t["headers"] = {"Host": ep["host"]}
        o["transport"] = t
    elif net == "httpupgrade":
        o["transport"] = {"type": "httpupgrade", "path": ep.get("path") or "/", **({"host": ep["host"]} if ep.get("host") else {})}
    elif net == "grpc":
        o["transport"] = {"type": "grpc", "service_name": ep.get("service_name") or ""}
    sec = ep.get("security")
    if sec in ("tls", "reality"):
        tls: dict[str, Any] = {"enabled": True, "server_name": ep.get("sni") or ep["address"],
                               "utls": {"enabled": True, "fingerprint": ep.get("fp") or "chrome"}}
        if ep.get("alpn"):
            tls["alpn"] = ep["alpn"].split(",")
        if ep.get("allow_insecure"):
            tls["insecure"] = True
        if sec == "reality":
            tls["reality"] = {"enabled": True, "public_key": ep.get("pbk") or "", "short_id": ep.get("sid") or ""}
        o["tls"] = tls
    return o


def singbox_config(endpoints: list[dict]) -> dict:
    outs = [o for o in (endpoint_to_singbox(e) for e in endpoints) if o]
    seen: dict[str, int] = {}
    for o in outs:
        n = o["tag"]
        if n in seen:
            seen[n] += 1
            o["tag"] = f"{n} #{seen[n]}"
        else:
            seen[n] = 1
    tags = [o["tag"] for o in outs]
    return {
        "log": {"level": "warn"},
        "dns": {"servers": [{"tag": "remote", "address": "https://1.1.1.1/dns-query", "detour": "proxy"},
                            {"tag": "local", "address": "local", "detour": "direct"}],
                "final": "remote"},
        "inbounds": [
            {"type": "tun", "tag": "tun-in", "address": ["172.19.0.1/30"], "auto_route": True, "strict_route": True, "stack": "mixed"},
            {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080},
        ],
        "outbounds": [
            {"type": "selector", "tag": "proxy", "outbounds": ["auto", *tags]},
            {"type": "urltest", "tag": "auto", "outbounds": tags or ["direct"], "url": "https://www.gstatic.com/generate_204", "interval": "5m"},
            *outs,
            {"type": "direct", "tag": "direct"},
        ],
        "route": {"rules": [{"ip_is_private": True, "outbound": "direct"}], "final": "proxy", "auto_detect_interface": True},
    }
