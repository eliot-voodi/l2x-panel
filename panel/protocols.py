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
# uTLS client fingerprints for share links / Reality+TLS (aligned with 3x-ui / Xray)
FINGERPRINTS = (
    "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq",
    "random", "randomized", "randomizednoalpn", "unsafe",
)
FINGERPRINT_LABELS = {
    "chrome": "Chrome",
    "firefox": "Firefox",
    "safari": "Safari",
    "ios": "iOS",
    "android": "Android",
    "edge": "Edge",
    "360": "360 Browser",
    "qq": "QQ Browser",
    "random": "Random",
    "randomized": "Randomized",
    "randomizednoalpn": "Randomized (no ALPN)",
    "unsafe": "unsafe (без uTLS)",
}
KCP_HEADERS = ("none", "srtp", "utp", "wechat-video", "dtls", "wireguard")
TRAFFIC_RESETS = ("never", "hourly", "daily", "weekly", "monthly")
SOCKOPT_DOMAIN = ("AsIs", "UseIP", "UseIPv4", "UseIPv6", "ForceIP", "ForceIPv4", "ForceIPv6", "ForceIPv4v6", "ForceIPv6v4")
TPROXY_MODES = ("", "off", "redirect", "tproxy")
TCP_CONGESTION = ("", "bbr", "cubic", "reno")
XH_MODES = ("auto", "packet-up", "stream-up", "stream-one")
TLS_VERSIONS = ("1.0", "1.1", "1.2", "1.3")

# Inbounds are published only through the nginx front on :443; Xray itself never binds a public address.
FRONT_PORT = 443
FRONT_INTERNAL_PORT = 7443
# Plain-HTTP nginx listeners that Xray (TLS terminator for RAW on the public domain) falls back to
FRONT_FALLBACK_H1_PORT = 7444
FRONT_FALLBACK_H2_PORT = 7445
FRONT_RAW_PROTOCOLS = ("vless", "trojan")
INBOUND_LISTEN = "127.0.0.1"
RESERVED_PORTS = frozenset({22, 80, 443})
FRONT_HTTP_NETWORKS = ("ws", "grpc", "httpupgrade", "xhttp")
FRONT_PROTOCOLS = ("vless", "vmess", "trojan")

# WS without Mux opens a new WebSocket per app connection → nginx/Xray flood.
# Mux.Cool keeps ~concurrency streams on a few long-lived WS sessions (client-side).
MUX_NETWORKS = frozenset({"ws", "httpupgrade"})
DEFAULT_WS_HEARTBEAT = 10  # seconds; Ping frames keep the long WS alive through nginx
# Opt-in only via Settings → Sub → json_mux. Auto-Mux.Cool caps multi-thread and
# upload throughput (often ~10–30 Mbps up while download looks fine).
DEFAULT_SUB_MUX = {
    "enabled": False,
    "concurrency": 8,
    "xudpConcurrency": 16,
    "xudpProxyUDP443": "reject",
}


# ---------------------------------------------------------------- defaults


def default_stream(security: str = "reality") -> dict:
    return {
        "network": "raw",
        "security": security,
        # Client uTLS fingerprint for share links (all inbounds that emit TLS/Reality/CDN links)
        "fingerprint": "firefox",
        "accept_proxy_protocol": False,
        "tls": {
            "server_name": "",
            "cert_file": "",
            "key_file": "",
            "alpn": ["h2", "http/1.1"],
            "fingerprint": "firefox",
            "min_version": "1.2",
            "max_version": "1.3",
            "cipher_suites": "",
            "allow_insecure": False,
            "reject_unknown_sni": False,
            "disable_system_root": False,
            "ech_server_keys": "",
        },
        "reality": {
            "show": False,
            "dest": "www.cloudflare.com:443",
            "xver": 0,
            "server_names": ["www.cloudflare.com"],
            "private_key": "",
            "public_key": "",
            "short_ids": [secrets.token_hex(4)],
            "fingerprint": "firefox",
            "spider_x": "/",
            "max_time_diff": 0,
            "min_client_ver": "",
            "max_client_ver": "",
            "mldsa65_seed": "",
            "mldsa65_verify": "",
        },
        "raw": {
            "header": "none", "http_host": "", "http_path": "/",
            "http_method": "GET", "http_headers": "",
            "accept_proxy_protocol": False,
        },
        "ws": {
            "path": "/ws", "host": "", "headers": "", "heartbeat": DEFAULT_WS_HEARTBEAT,
            "accept_proxy_protocol": False,
        },
        "grpc": {
            "service_name": "grpc", "multi_mode": False, "authority": "",
            "idle_timeout": 0, "health_check_timeout": 0,
            "permit_without_stream": False, "initial_windows_size": 0,
        },
        "httpupgrade": {
            "path": "/up", "host": "", "headers": "",
            "accept_proxy_protocol": False,
        },
        "xhttp": {
            "path": "/xh", "host": "", "mode": "auto", "extra": "",
            "x_padding_bytes": "100-1000",
            "sc_max_buffered_posts": 30,
            "sc_max_each_post_bytes": "1000000",
            "sc_min_each_post_bytes": "1",
            "sc_stream_up_server_secs": "20-80",
            "sc_min_posts_interval_ms": 30,
            "no_sse_header": False,
            "no_grpc_header": False,
            "headers": "",
            "xmux": {
                "enabled": False,
                "max_concurrency": "16-32",
                "max_connections": 0,
                "c_max_reuse_times": "0",
                "c_max_lifetime_ms": "0",
                "h_max_request_times": "0",
                "h_max_reusable_secs": "0",
            },
        },
        "kcp": {
            "mtu": 1350, "tti": 20, "uplink": 5, "downlink": 20, "congestion": False,
            "header": "none", "seed": "",
            "read_buffer": 2, "write_buffer": 2,
        },
        "sockopt": {
            "enabled": False,
            "tcp_fast_open": False,
            "tcp_keep_alive_interval": 0,
            "tcp_keep_alive_idle": 0,
            "tcp_user_timeout": 0,
            "tcp_congestion": "",
            "tcp_window_clamp": 0,
            "tcp_max_seg": 0,
            "mark": 0,
            "tproxy": "",
            "domain_strategy": "AsIs",
            "dialer_proxy": "",
            "interface": "",
            "penetrate": False,
            "tcp_mptcp": False,
            "tcp_no_delay": False,
            "v6only": False,
        },
    }


def default_settings(protocol: str) -> dict:
    if protocol == "vless":
        return {"flow": "xtls-rprx-vision", "decryption": "none", "encryption": "none"}
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


def default_inbound(protocol: str = "vless", port: int = 10443, tag: str = "vless-in") -> dict:
    if protocol == "hysteria":
        sec = "tls"
    else:
        sec = "reality" if protocol == "vless" else ("none" if protocol in ("shadowsocks", "wireguard", "socks", "http", "dokodemo-door") else "tls")
    return {
        "id": 0,
        "tag": tag,
        "remark": tag,
        "enabled": True,
        "listen": INBOUND_LISTEN,
        "port": port,
        "protocol": protocol,
        "settings": default_settings(protocol),
        "stream": default_stream(sec),
        "sniffing": {
            "enabled": True, "dest": ["http", "tls", "quic"],
            "route_only": False, "metadata_only": False, "excluded_domains": [],
        },
        "fallbacks": [],
        "outbound": "direct",
        "share_host": "",
        "external_proxies": [],
        "total_gb": 0,
        "expire_at": "",
        "traffic_reset": "never",
        "traffic": {"up": 0, "down": 0, "last_up": 0, "last_down": 0},
    }


def ensure_inbound_shape(ib: dict) -> dict:
    proto = ib.get("protocol") or "vless"
    base = default_inbound(proto, int(ib.get("port") or 10443), ib.get("tag") or f"{proto}-in")
    for k, v in base.items():
        ib.setdefault(k, v)
    for k, v in default_settings(proto).items():
        ib["settings"].setdefault(k, v)
    st = ib["stream"]
    for k, v in default_stream(st.get("security") or "none").items():
        if isinstance(v, dict):
            cur = st.setdefault(k, {})
            for kk, vv in v.items():
                if isinstance(vv, dict):
                    sub = cur.setdefault(kk, {})
                    for k3, v3 in vv.items():
                        sub.setdefault(k3, v3)
                else:
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

def parse_header_lines(raw: str) -> dict[str, list[str]]:
    """Parse `Key: Value` lines (or JSON object) into Xray header map."""
    text = str(raw or "").strip()
    if not text:
        return {}
    if text.startswith("{"):
        try:
            data = json.loads(text)
        except ValueError:
            data = None
        if isinstance(data, dict):
            out: dict[str, list[str]] = {}
            for k, v in data.items():
                if isinstance(v, list):
                    out[str(k)] = [str(x) for x in v]
                elif v is not None and str(v) != "":
                    out[str(k)] = [str(v)]
            return out
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        key, _, val = line.partition(":")
        key, val = key.strip(), val.strip()
        if not key:
            continue
        out.setdefault(key, []).append(val)
    return out


def _maybe_range(value) -> Any:
    """Keep dash-ranges as strings; coerce plain ints."""
    s = str(value if value is not None else "").strip()
    if not s:
        return None
    if "-" in s:
        return s
    try:
        return int(s)
    except ValueError:
        return s


def build_stream_settings(stream: dict) -> dict:
    net = stream.get("network") or "raw"
    sec = stream.get("security") or "none"
    out: dict[str, Any] = {"network": net, "security": sec}
    if net == "raw":
        raw = stream.get("raw") or {}
        raw_settings: dict[str, Any] = {}
        if raw.get("header") == "http":
            headers = parse_header_lines(raw.get("http_headers") or "")
            hosts = [h.strip() for h in (raw.get("http_host") or "").split(",") if h.strip()]
            if hosts:
                headers["Host"] = hosts
            raw_settings["header"] = {
                "type": "http",
                "request": {
                    "version": "1.1",
                    "method": raw.get("http_method") or "GET",
                    "path": [raw.get("http_path") or "/"],
                    **({"headers": headers} if headers else {}),
                },
            }
        if raw.get("accept_proxy_protocol") or stream.get("accept_proxy_protocol"):
            raw_settings["acceptProxyProtocol"] = True
        if raw_settings:
            out["rawSettings"] = raw_settings
    elif net == "ws":
        ws = stream.get("ws") or {}
        ws_settings: dict[str, Any] = {"path": ws.get("path") or "/", **({"host": ws["host"]} if ws.get("host") else {})}
        headers = parse_header_lines(ws.get("headers") or "")
        if headers:
            # ws headers are flat string map in Xray
            ws_settings["headers"] = {k: (v[0] if isinstance(v, list) and v else str(v)) for k, v in headers.items()}
        # Keep long-lived WS alive through nginx idle timeouts (0 / empty → default)
        try:
            hb = int(ws.get("heartbeat") or 0)
        except (TypeError, ValueError):
            hb = 0
        ws_settings["heartbeatPeriod"] = hb if hb > 0 else DEFAULT_WS_HEARTBEAT
        if ws.get("accept_proxy_protocol") or stream.get("accept_proxy_protocol"):
            ws_settings["acceptProxyProtocol"] = True
        out["wsSettings"] = ws_settings
    elif net == "grpc":
        g = stream.get("grpc") or {}
        grpc: dict[str, Any] = {"serviceName": g.get("service_name") or "grpc", "multiMode": bool(g.get("multi_mode"))}
        if g.get("authority"):
            grpc["authority"] = g["authority"]
        if int(g.get("idle_timeout") or 0) > 0:
            grpc["idle_timeout"] = int(g["idle_timeout"])
        if int(g.get("health_check_timeout") or 0) > 0:
            grpc["health_check_timeout"] = int(g["health_check_timeout"])
        if g.get("permit_without_stream"):
            grpc["permit_without_stream"] = True
        if int(g.get("initial_windows_size") or 0) > 0:
            grpc["initial_windows_size"] = int(g["initial_windows_size"])
        out["grpcSettings"] = grpc
    elif net == "httpupgrade":
        h = stream.get("httpupgrade") or {}
        hu: dict[str, Any] = {"path": h.get("path") or "/", **({"host": h["host"]} if h.get("host") else {})}
        headers = parse_header_lines(h.get("headers") or "")
        if headers:
            hu["headers"] = {k: (v[0] if isinstance(v, list) and v else str(v)) for k, v in headers.items()}
        if h.get("accept_proxy_protocol") or stream.get("accept_proxy_protocol"):
            hu["acceptProxyProtocol"] = True
        out["httpupgradeSettings"] = hu
    elif net == "xhttp":
        x = stream.get("xhttp") or {}
        xh: dict[str, Any] = {
            "path": x.get("path") or "/",
            "mode": x.get("mode") or "auto",
            **({"host": x["host"]} if x.get("host") else {}),
        }
        headers = parse_header_lines(x.get("headers") or "")
        if headers:
            xh["headers"] = {k: (v[0] if isinstance(v, list) and v else str(v)) for k, v in headers.items()}
        pad = _maybe_range(x.get("x_padding_bytes"))
        if pad is not None:
            xh["xPaddingBytes"] = pad
        for src, dst in (
            ("sc_max_buffered_posts", "scMaxBufferedPosts"),
            ("sc_min_posts_interval_ms", "scMinPostsIntervalMs"),
        ):
            val = int(x.get(src) or 0)
            if val > 0:
                xh[dst] = val
        for src, dst in (
            ("sc_max_each_post_bytes", "scMaxEachPostBytes"),
            ("sc_min_each_post_bytes", "scMinEachPostBytes"),
            ("sc_stream_up_server_secs", "scStreamUpServerSecs"),
        ):
            val = _maybe_range(x.get(src))
            if val is not None:
                xh[dst] = val
        if x.get("no_sse_header"):
            xh["noSSEHeader"] = True
        if x.get("no_grpc_header"):
            xh["noGRPCHeader"] = True
        xm = x.get("xmux") or {}
        if xm.get("enabled"):
            xmux: dict[str, Any] = {}
            for src, dst in (
                ("max_concurrency", "maxConcurrency"),
                ("c_max_reuse_times", "cMaxReuseTimes"),
                ("c_max_lifetime_ms", "cMaxLifetimeMs"),
                ("h_max_request_times", "hMaxRequestTimes"),
                ("h_max_reusable_secs", "hMaxReusableSecs"),
            ):
                val = _maybe_range(xm.get(src))
                if val is not None and val != 0 and val != "0":
                    xmux[dst] = val
            max_conn = int(xm.get("max_connections") or 0)
            if max_conn > 0:
                xmux["maxConnections"] = max_conn
            if xmux:
                xh["xmux"] = xmux
        # Advanced JSON overlay (wins on conflicts)
        extra = str(x.get("extra") or "").strip()
        if extra:
            try:
                parsed = json.loads(extra)
                if isinstance(parsed, dict):
                    # Prefer nesting under extra for splitHTTP extras, else merge
                    if any(k in parsed for k in ("xmux", "headers", "xPaddingBytes", "mode", "path")):
                        for k, v in parsed.items():
                            if k == "xmux" and isinstance(v, dict) and isinstance(xh.get("xmux"), dict):
                                xh["xmux"] = {**xh["xmux"], **v}
                            else:
                                xh[k] = v
                    else:
                        xh["extra"] = parsed
                else:
                    xh["extra"] = parsed
            except ValueError:
                xh["extra"] = extra
        out["xhttpSettings"] = xh
    elif net == "kcp":
        k = stream.get("kcp") or {}
        kcp: dict[str, Any] = {
            "mtu": int(k.get("mtu") or 1350),
            "tti": int(k.get("tti") or 20),
            "uplinkCapacity": int(k.get("uplink") or 5),
            "downlinkCapacity": int(k.get("downlink") or 20),
            "congestion": bool(k.get("congestion")),
            "header": {"type": k.get("header") or "none"},
            "readBufferSize": int(k.get("read_buffer") or 2),
            "writeBufferSize": int(k.get("write_buffer") or 2),
        }
        if k.get("seed"):
            kcp["seed"] = k["seed"]
        out["kcpSettings"] = kcp
    if sec == "tls":
        t = stream.get("tls") or {}
        tls: dict[str, Any] = {
            "serverName": t.get("server_name") or "",
            "alpn": t.get("alpn") or ["h2", "http/1.1"],
            "minVersion": t.get("min_version") or "1.2",
            "rejectUnknownSni": bool(t.get("reject_unknown_sni")),
        }
        if t.get("max_version"):
            tls["maxVersion"] = t["max_version"]
        if t.get("cipher_suites"):
            tls["cipherSuites"] = str(t["cipher_suites"]).strip()
        if t.get("disable_system_root"):
            tls["disableSystemRoot"] = True
        if t.get("cert_file") and t.get("key_file"):
            tls["certificates"] = [{"certificateFile": t["cert_file"], "keyFile": t["key_file"]}]
        if t.get("ech_server_keys"):
            tls["echServerKeys"] = t["ech_server_keys"]
        out["tlsSettings"] = tls
    elif sec == "reality":
        r = stream.get("reality") or {}
        reality: dict[str, Any] = {
            "show": bool(r.get("show")),
            "dest": r.get("dest") or "www.cloudflare.com:443",
            "xver": int(r.get("xver") or 0),
            "serverNames": r.get("server_names") or ["www.cloudflare.com"],
            "privateKey": r.get("private_key") or "",
            "shortIds": r.get("short_ids") or [""],
        }
        if r.get("max_time_diff"):
            reality["maxTimeDiff"] = int(r["max_time_diff"])
        if r.get("min_client_ver"):
            reality["minClientVer"] = r["min_client_ver"]
        if r.get("max_client_ver"):
            reality["maxClientVer"] = r["max_client_ver"]
        if r.get("mldsa65_seed"):
            reality["mldsa65Seed"] = r["mldsa65_seed"]
        out["realitySettings"] = reality
    so = stream.get("sockopt") or {}
    if so.get("enabled"):
        sock: dict[str, Any] = {}
        if so.get("tcp_fast_open"):
            sock["tcpFastOpen"] = True
        if so.get("tcp_keep_alive_interval"):
            sock["tcpKeepAliveInterval"] = int(so["tcp_keep_alive_interval"])
        if so.get("tcp_keep_alive_idle"):
            sock["tcpKeepAliveIdle"] = int(so["tcp_keep_alive_idle"])
        if so.get("tcp_user_timeout"):
            sock["tcpUserTimeout"] = int(so["tcp_user_timeout"])
        if so.get("tcp_congestion"):
            sock["tcpcongestion"] = so["tcp_congestion"]
        if int(so.get("tcp_window_clamp") or 0) > 0:
            sock["tcpWindowClamp"] = int(so["tcp_window_clamp"])
        if int(so.get("tcp_max_seg") or 0) > 0:
            sock["tcpMaxSeg"] = int(so["tcp_max_seg"])
        if so.get("mark"):
            sock["mark"] = int(so["mark"])
        if so.get("tproxy") and so["tproxy"] != "off":
            sock["tproxy"] = so["tproxy"]
        if so.get("domain_strategy") and so["domain_strategy"] != "AsIs":
            sock["domainStrategy"] = so["domain_strategy"]
        if so.get("dialer_proxy"):
            sock["dialerProxy"] = so["dialer_proxy"]
        if so.get("interface"):
            sock["interface"] = so["interface"]
        if so.get("penetrate"):
            sock["penetrate"] = True
        if so.get("tcp_mptcp"):
            sock["tcpMptcp"] = True
        if so.get("tcp_no_delay"):
            sock["tcpNoDelay"] = True
        if so.get("v6only"):
            sock["V6Only"] = True
        if sock:
            out["sockopt"] = sock
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


DIRECT_LISTEN = "0.0.0.0"


def is_direct(ib: dict) -> bool:
    """Inbound listens on its own public port, bypassing the nginx :443 front."""
    return bool(ib.get("direct"))


def inbound_listen(ib: dict) -> str:
    return DIRECT_LISTEN if is_direct(ib) else INBOUND_LISTEN


def front_mode(ib: dict) -> str | None:
    """How the nginx front publishes this inbound on :443.

    "http" — nginx terminates TLS on the share/public domain and proxies by Path
             (ws / grpc / httpupgrade / xhttp). Several inbounds share one domain.
    "sni"  — TLS passthrough by SNI (Reality, or TLS terminated by Xray) for a
             *different* hostname than the public panel domain;
    "raw"  — plain VLESS/Trojan RAW on the public domain: Xray terminates TLS with the
             public certificate and falls back to nginx for everything that is not a proxy client;
    None   — not behind nginx (local only, or direct on its own port).
    """
    if is_direct(ib) or ib.get("protocol") not in FRONT_PROTOCOLS:
        return None
    st = ib.get("stream") or {}
    net = st.get("network") or "raw"
    sec = st.get("security") or "none"
    # Reality/TLS on path transports (esp. XHTTP/gRPC) use SNI passthrough like 3x-ui
    if sec in ("reality", "tls"):
        return "sni"
    if net in FRONT_HTTP_NETWORKS:
        return "http"
    if (
        net == "raw"
        and ib.get("protocol") in FRONT_RAW_PROTOCOLS
        and (st.get("raw") or {}).get("header") != "http"
    ):
        return "raw"
    return None


def front_snis(ib: dict) -> list[str]:
    st = ib.get("stream") or {}
    if (st.get("security") or "none") == "reality":
        return [n for n in ((st.get("reality") or {}).get("server_names") or []) if n]
    name = (st.get("tls") or {}).get("server_name") or ib.get("share_host") or ""
    return [name] if name else []


def normalize_http_inbound(ib: dict) -> None:
    """nginx terminates TLS for path inbounds — Xray must speak plain HTTP on localhost."""
    if front_mode(ib) != "http":
        return
    st = ib.setdefault("stream", {})
    st["security"] = "none"
    st.pop("accept_proxy_protocol", None)


def front_http_path(ib: dict) -> str:
    st = ib.get("stream") or {}
    net = st.get("network") or "raw"
    if net == "grpc":
        return "/" + ((st.get("grpc") or {}).get("service_name") or "grpc").strip("/") + "/"
    return ((st.get(net) or {}).get("path") or "/").split("?", 1)[0]


def _vless_enc_on(settings: dict | None) -> bool:
    s = settings or {}
    for key in ("encryption", "decryption"):
        val = str(s.get(key) or "").strip().lower()
        if val and val != "none":
            return True
    return False


def supports_flow(ib: dict) -> bool:
    """XTLS-Vision: classic raw+tls/reality, or any transport when VLESS encryption is on (3x-ui)."""
    if ib.get("protocol") != "vless":
        return False
    st = ib.get("stream") or {}
    net = st.get("network") or "raw"
    sec = st.get("security") or "none"
    if net == "raw" and sec in ("tls", "reality"):
        return True
    if front_mode(ib) == "raw":
        return True  # TLS is terminated by Xray itself on :443
    return _vless_enc_on(ib.get("settings"))


def build_inbound(ib: dict, identities: list[dict]) -> dict:
    """identities: [{uuid, email, password, wg_public, wg_ip, main}]"""
    proto = ib["protocol"]
    s = ib.get("settings") or {}
    settings: dict[str, Any] = {}
    if proto == "vless":
        flow = s.get("flow") if supports_flow(ib) else ""
        settings = {
            "clients": [{"id": i["uuid"], "email": i["email"], **({"flow": flow} if flow else {})} for i in identities],
            "decryption": s.get("decryption") or "none",
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
        "listen": inbound_listen(ib),
        "port": int(ib["port"]),
        "protocol": proto,
        "settings": settings,
    }
    if proto == "hysteria":
        out["streamSettings"] = _hysteria_stream(ib)
    elif proto in USER_PROTOCOLS:
        out["streamSettings"] = build_stream_settings(ib.get("stream") or {})
        mode = front_mode(ib)
        if mode in ("sni", "raw"):
            # nginx stream sends PROXY protocol so Xray sees the real client IP
            out["streamSettings"].setdefault("sockopt", {})["acceptProxyProtocol"] = True
        elif mode == "http":
            # nginx already matched the domain; a Host check in Xray only turns typos into 404
            for key in ("wsSettings", "httpupgradeSettings", "xhttpSettings"):
                out["streamSettings"].get(key, {}).pop("host", None)
            out["streamSettings"].get("grpcSettings", {}).pop("authority", None)
            # Every request arrives from nginx (127.0.0.1); the real client IP is in the header nginx sets.
            # Without it online-IP stats stay empty (Xray skips localhost) and IP limits never fire.
            out["streamSettings"].setdefault("sockopt", {})["trustedXForwardedFor"] = ["X-Forwarded-For", "X-Real-IP"]
    sn = ib.get("sniffing") or {}
    if sn.get("enabled"):
        sniff: dict[str, Any] = {
            "enabled": True,
            "destOverride": sn.get("dest") or ["http", "tls", "quic"],
            "routeOnly": bool(sn.get("route_only")),
            "metadataOnly": bool(sn.get("metadata_only")),
        }
        excl = [d for d in (sn.get("excluded_domains") or []) if str(d).strip()]
        if excl:
            sniff["domainsExcluded"] = excl
        out["sniffing"] = sniff
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

def _apply_external_proxy(ep: dict, ib: dict) -> list[dict]:
    """Return one endpoint per external proxy; if none configured, just the direct ep."""
    proxies = [p for p in (ib.get("external_proxies") or []) if (p.get("address") or p.get("dest"))]
    if not proxies:
        return [ep]
    out = []
    for i, p in enumerate(proxies):
        item = dict(ep)
        addr = str(p.get("address") or p.get("dest") or "").strip()
        if addr:
            item["address"] = addr
        if p.get("port"):
            item["port"] = int(p["port"])
        force = str(p.get("force_tls") or p.get("forceTls") or "").lower()
        if force in ("tls", "reality"):
            item["security"] = force
        remark = str(p.get("remark") or "").strip()
        if remark:
            item["remark"] = remark
        elif len(proxies) > 1:
            item["remark"] = f"{ep.get('remark') or ib.get('remark') or ib.get('tag')}-{i + 1}"
        out.append(item)
    return out


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
    if proto == "vless":
        s = ib.get("settings") or {}
        if supports_flow(ib):
            ep["flow"] = s.get("flow") or ""
        enc = s.get("encryption") or "none"
        if enc and enc != "none":
            ep["encryption"] = enc
        r = st.get("reality") or {}
        if sec == "reality" and r.get("mldsa65_verify"):
            ep["pqv"] = r["mldsa65_verify"]
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
            "fp": st.get("fingerprint") or t.get("fingerprint") or "firefox",
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
        if net == "ws":
            try:
                ep["heartbeat"] = max(0, int(cfg.get("heartbeat") if cfg.get("heartbeat") not in (None, "") else DEFAULT_WS_HEARTBEAT))
            except (TypeError, ValueError):
                ep["heartbeat"] = DEFAULT_WS_HEARTBEAT
        if net == "xhttp":
            ep["mode"] = cfg.get("mode") or "auto"
    elif net == "grpc":
        g = st.get("grpc") or {}
        ep["service_name"] = g.get("service_name") or "grpc"
        ep["mode"] = "multi" if g.get("multi_mode") else "gun"
    # Canonical client fingerprint (stream-level); tls/reality copies kept in sync for legacy
    fp = (
        st.get("fingerprint")
        or (st.get("tls") or {}).get("fingerprint")
        or (st.get("reality") or {}).get("fingerprint")
        or "firefox"
    )
    if sec == "tls":
        t = st.get("tls") or {}
        ep["sni"] = t.get("server_name") or ""
        ep["fp"] = fp
        ep["alpn"] = ",".join(t.get("alpn") or [])
        ep["allow_insecure"] = bool(t.get("allow_insecure"))
    elif sec == "reality":
        r = st.get("reality") or {}
        names = r.get("server_names") or []
        ep["sni"] = names[0] if names else str(r.get("dest") or "").split(":")[0]
        ep["fp"] = fp
        ep["pbk"] = r.get("public_key") or ""
        sids = r.get("short_ids") or []
        ep["sid"] = sids[0] if sids else ""
        ep["spx"] = r.get("spider_x") or "/"
    else:
        ep["fp"] = fp
    mode = front_mode(ib)
    if mode:
        ep["port"] = FRONT_PORT
    elif is_direct(ib) and sec == "tls" and not ep.get("sni"):
        ep["sni"] = ep["address"]
    if mode == "sni" and sec == "tls" and not ep.get("sni"):
        ep["sni"] = ib.get("share_host") or ""
    elif mode == "raw":
        # Certificate is the public domain's — share_host of path inbounds may differ
        domain = host or ib.get("share_host") or ""
        ep.update({
            "address": domain,
            "security": "tls",
            "sni": domain,
            "fp": fp,
            "alpn": "h2,http/1.1",
            "allow_insecure": False,
        })
    elif mode == "http":
        domain = ib.get("share_host") or host
        ep.update({
            "address": domain,
            "security": "tls",
            "sni": domain,
            "host": domain,
            "fp": fp,
            "alpn": "h2,http/1.1" if net in ("grpc", "xhttp") else "http/1.1",
            "allow_insecure": False,
        })
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
        params = {"encryption": ep.get("encryption") or "none", **params}
        if ep.get("pqv"):
            params["pqv"] = ep["pqv"]
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
        p["fp"] = ep.get("fp") or "firefox"
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
        user = {"id": ep["uuid"], "encryption": ep.get("encryption") or "none"}
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
        ws: dict[str, Any] = {"path": ep.get("path") or "/", **({"host": ep["host"]} if ep.get("host") else {})}
        # Client-side Ping keeps the muxed WS from being dropped by idle timeouts
        ws["heartbeatPeriod"] = int(ep.get("heartbeat") or DEFAULT_WS_HEARTBEAT) or DEFAULT_WS_HEARTBEAT
        st["wsSettings"] = ws
    elif net == "grpc":
        st["grpcSettings"] = {"serviceName": ep.get("service_name") or "", "multiMode": ep.get("mode") == "multi"}
    elif net == "httpupgrade":
        st["httpupgradeSettings"] = {"path": ep.get("path") or "/", **({"host": ep["host"]} if ep.get("host") else {})}
    elif net == "xhttp":
        st["xhttpSettings"] = {"path": ep.get("path") or "/", "mode": ep.get("mode") or "auto", **({"host": ep["host"]} if ep.get("host") else {})}
    if sec == "tls":
        tls: dict[str, Any] = {"serverName": ep.get("sni") or ep["address"], "fingerprint": ep.get("fp") or "firefox"}
        if ep.get("alpn"):
            tls["alpn"] = [a for a in ep["alpn"].split(",") if a]
        if ep.get("allow_insecure"):
            tls["allowInsecure"] = True
        st["tlsSettings"] = tls
    elif sec == "reality":
        st["realitySettings"] = {
            "serverName": ep.get("sni") or "",
            "fingerprint": ep.get("fp") or "firefox",
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


def _mux_compatible(ep: dict | None, proxy: dict | None = None) -> bool:
    """Mux.Cool is for WS/httpupgrade; Vision flow ignores Mux."""
    if ep and ep.get("flow"):
        return False
    net = (ep or {}).get("net") or ""
    if not net and proxy:
        net = ((proxy.get("streamSettings") or {}).get("network") or "")
    return net in MUX_NETWORKS


def apply_sub_json_extras(cfg: dict, extras: dict | None, *, ep: dict | None = None) -> dict:
    """Inject Fragment / Noise / Mux into a JSON subscription client config.

    Mux is OFF by default (throughput). Enable explicitly via Settings → Sub →
    json_mux, e.g. {"enabled": true, "concurrency": 8}.
    """
    outs = cfg.get("outbounds") or []
    proxy = next((o for o in outs if o.get("tag") == "proxy"), outs[0] if outs else None)
    if not proxy:
        return cfg
    extras = extras or {}
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
    # Only enable Mux when admin JSON explicitly asks for it (and network allows)
    if isinstance(mux, dict) and mux.get("enabled", True) is not False and _mux_compatible(ep, proxy):
        body = {k: v for k, v in mux.items() if k != "enabled"}
        proxy["mux"] = {"enabled": True, **body}
    cfg["outbounds"] = outs
    return cfg


def xray_client_config(ep: dict, extras: dict | None = None, *, doh_url: str = "", doh_in_tunnel: bool = False) -> dict:
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
    if doh_url and doh_in_tunnel:
        # Resolve DoH host via proxy (inside tunnel)
        dns_servers: list = [{"address": doh_url, "domains": ["geosite:geolocation-!cn"]}, "1.1.1.1"]
        # Xray DoH as string URL uses system dial — prefer https+local for out-of-tunnel;
        # for in-tunnel put DoH first as plain https URL (client dials through routing if supported).
        dns_servers = [doh_url, "localhost"]
    elif doh_url:
        dns_servers = [doh_url.replace("https://", "https+local://", 1), "localhost"]
    else:
        dns_servers = ["1.1.1.1", "8.8.8.8"]
    cfg = {
        "remarks": ep.get("remark") or "",
        "log": {"loglevel": "warning"},
        "dns": {"servers": dns_servers},
        "inbounds": [
            {"tag": "socks", "listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": {"udp": True},
             "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True}},
            {"tag": "http", "listen": "127.0.0.1", "port": 10809, "protocol": "http"},
        ],
        "outbounds": [
            proxy,
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
            {"tag": "dns-out", "protocol": "dns"},
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {"type": "field", "inboundTag": ["socks", "http"], "port": 53, "outboundTag": "dns-out"},
                {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"},
                {"type": "field", "network": "tcp,udp", "outboundTag": "proxy"},
            ],
        },
    }
    return apply_sub_json_extras(cfg, extras, ep=ep)


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
        p["client-fingerprint"] = ep.get("fp") or "firefox"
        if ep.get("alpn"):
            p["alpn"] = ep["alpn"].split(",")
        if ep.get("allow_insecure"):
            p["skip-cert-verify"] = True
    if sec == "reality":
        p["reality-opts"] = {"public-key": ep.get("pbk") or "", "short-id": ep.get("sid") or ""}
    return p


def clash_config(endpoints: list[dict], *, doh_url: str = "", doh_in_tunnel: bool = False) -> dict:
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
    cfg: dict[str, Any] = {
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
    if doh_url:
        # Mihomo: `#PROXY` dials DoH through the PROXY group (inside tunnel)
        ns = f"{doh_url}#PROXY" if doh_in_tunnel else doh_url
        cfg["dns"] = {
            "enable": True,
            "enhanced-mode": "fake-ip",
            "nameserver": [ns],
            "fallback": ["1.1.1.1", "8.8.8.8"],
            "proxy-server-nameserver": ["1.1.1.1"],
        }
    return cfg


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
                               "utls": {"enabled": True, "fingerprint": ep.get("fp") or "firefox"}}
        if ep.get("alpn"):
            tls["alpn"] = ep["alpn"].split(",")
        if ep.get("allow_insecure"):
            tls["insecure"] = True
        if sec == "reality":
            tls["reality"] = {"enabled": True, "public_key": ep.get("pbk") or "", "short_id": ep.get("sid") or ""}
        o["tls"] = tls
    return o


def singbox_config(endpoints: list[dict], *, doh_url: str = "", doh_in_tunnel: bool = False) -> dict:
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
    remote: dict[str, Any] = {
        "tag": "remote",
        "address": doh_url or "https://1.1.1.1/dns-query",
    }
    if doh_in_tunnel or not doh_url:
        remote["detour"] = "proxy"
    return {
        "log": {"level": "warn"},
        "dns": {"servers": [remote, {"tag": "local", "address": "local", "detour": "direct"}],
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
