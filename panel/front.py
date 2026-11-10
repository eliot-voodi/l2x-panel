"""nginx front: the only public entry (panel, subscriptions, inbounds) — clients only need :443.

    client ──:443──> nginx stream (ssl_preread)
                       ├─ SNI of a Reality / Xray-TLS inbound ──PROXY──> Xray 127.0.0.1:<port>
                       └─ public domain (and other HTTPS) ──PROXY──> nginx https 127.0.0.1:7443
                            ├─ /sub/…  → panel (subscriptions)
                            ├─ /       → panel
                            └─ path    → Xray (ws/grpc/httpupgrade/xhttp)

Generated files are verified with `nginx -t` before nginx ever loads them; a failed test or a failed
reload restores the previous files. There is no switch to skip that.
"""
from __future__ import annotations

import ipaddress
import os
import re
import shutil
import socket
import subprocess
import threading
import time
from pathlib import Path

import protocols as P

NGINX_CONF = Path("/etc/nginx/nginx.conf")
FRONT_DIR = Path("/etc/nginx/l2x")
STREAM_CONF = FRONT_DIR / "stream.conf"
HTTP_CONF = FRONT_DIR / "http.conf"
HTTP_INCLUDE = Path("/etc/nginx/conf.d/l2x-front.conf")
NGINX_SYSTEMD_DROPIN_DIR = Path("/etc/systemd/system/nginx.service.d")
NGINX_SYSTEMD_DROPIN = NGINX_SYSTEMD_DROPIN_DIR / "l2x-nofile.conf"
CERT_DIR = Path(os.environ.get("L2XPANEL_CERT_DIR", "/etc/l2xpanel/certs"))
SELF_SIGNED_DIR = CERT_DIR / "self-signed"
# Named upstream — dual-slot updates flip /etc/nginx/conf.d/l2x-panel-upstream.conf
# without rewriting the whole front (zero-downtime cutover).
PANEL_UPSTREAM = "l2x_panel_backend"
PANEL_UPSTREAM_CONF = Path("/etc/nginx/conf.d/l2x-panel-upstream.conf")
PANEL_UPSTREAM_STATE = Path("/etc/l2xpanel/panel_upstream")
MARK = "# managed by l2x-panel — generated, edits are overwritten"
STREAM_INCLUDE_LINE = f"include {STREAM_CONF};"

# WS without Mux ≈ 2 FDs per app connection; stock worker_connections 768/1024 → EMFILE (errno 24).
WORKER_CONNECTIONS = 16384
WORKER_RLIMIT_NOFILE = 1048576
NGINX_SYSTEMD_DROPIN_BODY = (
    "# managed by l2x-panel — nginx needs high FD for WS/gRPC (each session ≈ 2 sockets)\n"
    "[Service]\n"
    f"LimitNOFILE={WORKER_RLIMIT_NOFILE}\n"
)

HOST_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")
PATH_RE = re.compile(r"^/[A-Za-z0-9/_.~-]*$")


def _clean_sub_segment(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]", "", str(value or "")).strip("_-")


def sub_uri_paths(store: dict | None = None) -> list[str]:
    """Primary subscription path + aliases (e.g. old 3x-ui subPath)."""
    sub = (((store or {}).get("settings") or {}).get("sub") or {})
    out: list[str] = []
    for raw in [sub.get("path") or "sub", *(sub.get("path_aliases") or [])]:
        p = _clean_sub_segment(raw)
        if p and p not in out and p.lower() not in ("api", "panel", "health", "static", "login"):
            out.append(p)
    if "sub" not in out:
        out.append("sub")
    return out


def _legacy_port_list(sub: dict, key: str) -> list[int]:
    ports: list[int] = []
    for raw in sub.get(key) or []:
        try:
            p = int(raw)
        except (TypeError, ValueError):
            continue
        if 1 <= p <= 65535 and p not in (80, 443, P.FRONT_PORT, P.FRONT_INTERNAL_PORT) and p not in ports:
            ports.append(p)
    return ports


def legacy_sub_tls_ports(store: dict | None = None) -> list[int]:
    """Extra HTTPS ports for old subscription URLs (e.g. PasarGuard https://host:8000/sub/…)."""
    sub = (((store or {}).get("settings") or {}).get("sub") or {})
    return _legacy_port_list(sub, "legacy_tls_ports")


def legacy_sub_ports(store: dict | None = None) -> list[int]:
    """All extra ports nginx listens on for old subscription URLs (HTTP + HTTPS)."""
    sub = (((store or {}).get("settings") or {}).get("sub") or {})
    tls = set(_legacy_port_list(sub, "legacy_tls_ports"))
    plain = [p for p in _legacy_port_list(sub, "legacy_ports") if p not in tls]
    return plain + sorted(tls)


def legacy_sub_plain_ports(store: dict | None = None) -> list[int]:
    sub = (((store or {}).get("settings") or {}).get("sub") or {})
    tls = set(_legacy_port_list(sub, "legacy_tls_ports"))
    return [p for p in _legacy_port_list(sub, "legacy_ports") if p not in tls]


def _run(cmd: list[str], timeout: int = 60) -> dict:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "stdout": "", "stderr": str(exc)}
    return {"ok": p.returncode == 0, "stdout": p.stdout, "stderr": p.stderr}


def available() -> bool:
    return bool(shutil.which("nginx")) and NGINX_CONF.is_file()


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


def is_domain(value: str) -> bool:
    return not _is_ip(value or "") and bool(HOST_RE.match(value or ""))


def normalize_host(value: str) -> str:
    v = (value or "").strip().lower()
    v = re.sub(r"^[a-z][a-z0-9+.-]*://", "", v)
    return v.split("/", 1)[0].split(":", 1)[0].strip("[]")


def public_domain(store: dict) -> str:
    """Single changeable HTTPS domain for panel, subscriptions and share links (port 443 only)."""
    panel = ((store.get("settings") or {}).get("panel") or {})
    sub = ((store.get("settings") or {}).get("sub") or {})
    for cand in (panel.get("public_host"), sub.get("domain"), os.environ.get("L2XPANEL_PUBLIC_HOST", "")):
        host = normalize_host(str(cand or ""))
        if is_domain(host):
            return host
    return ""


def _nginx_version() -> tuple[int, ...]:
    out = _run(["nginx", "-v"])
    m = re.search(r"nginx/(\d+)\.(\d+)\.(\d+)", out["stderr"] + out["stdout"])
    return tuple(int(x) for x in m.groups()) if m else (0, 0, 0)


def _ipv6() -> bool:
    return Path("/proc/net/if_inet6").is_file() and Path("/proc/net/if_inet6").read_text().strip() != ""


# ---------------------------------------------------------------- plan

def raw_front_inbound(store: dict) -> dict | None:
    """The one plain VLESS/Trojan RAW inbound served on the public domain :443 (Xray terminates TLS)."""
    if not public_domain(store):
        return None
    for ib in store.get("inbounds") or []:
        if ib.get("enabled", True) and not ib.get("_system") and P.front_mode(ib) == "raw":
            return ib
    return None


def plan(store: dict) -> dict:
    """Routing table: SNI → Xray, HTTPS sites → panel/paths. Public domain always gets a panel site."""
    pub = public_domain(store)
    sni: dict[str, int] = {}
    sites: dict[str, list[dict]] = {}
    problems: list[str] = []
    if not pub:
        problems.append("задайте публичный домен в Настройки → Панель (HTTPS :443 для панели, подписок и ссылок)")
    else:
        sites.setdefault(pub, [])

    base = re.sub(r"[^A-Za-z0-9_-]", "", str((((store.get("settings") or {}).get("panel") or {}).get("base_path") or ""))).strip("/")
    doh_prefix = re.sub(
        r"[^A-Za-z0-9_-]", "",
        str((((store.get("settings") or {}).get("doh") or {}).get("path_prefix") or "doh")),
    ).strip("_-") or "doh"
    reserved_paths = {"/sub/", "/api/sub/", "/panel/", "/health", "/.well-known/", f"/{doh_prefix}/"}
    for sp in sub_uri_paths(store):
        reserved_paths.add(f"/{sp}/")
    if base:
        reserved_paths.add(f"/{base}/")

    for ib in store.get("inbounds") or []:
        if not ib.get("enabled", True):
            continue
        P.normalize_http_inbound(ib)
        mode = P.front_mode(ib)
        tag, port = ib.get("tag") or "?", int(ib.get("port") or 0)
        if tag == "rv-in" and ib.get("_system"):
            rv = ((store.get("settings") or {}).get("nodes") or {}).get("rv") or {}
            port = int(rv.get("port") or port)
            # Keep panel inbound path in sync with settings.nodes.rv (xhttp or legacy ws)
            if rv.get("path"):
                net = ((ib.get("stream") or {}).get("network") or rv.get("network") or "xhttp").lower()
                st = ib.setdefault("stream", {})
                st["network"] = net if net in ("xhttp", "ws") else "xhttp"
                if st["network"] == "xhttp":
                    st.setdefault("xhttp", {})["path"] = rv["path"]
                    st.setdefault("xhttp", {}).setdefault("mode", "auto")
                else:
                    st.setdefault("ws", {})["path"] = rv["path"]
                # front_mode uses security=none path transports
                st["security"] = "none"
        if mode == "sni":
            names = P.front_snis(ib)
            if not names:
                problems.append(f"{tag}: нет SNI (serverNames / TLS server name / URL share)")
            kept = 0
            for name in names:
                name = name.lower()
                if _is_ip(name) and (ib["stream"].get("security") == "tls"):
                    name = '""'  # clients send no SNI for an IP address
                # Public domain always terminates at nginx (panel + Path inbounds).
                # TLS whose cert/SNI is that domain is published as empty-SNI (IP connect);
                # Reality must use a *different* camouflage SNI (ya.ru, …).
                if name == pub:
                    if (ib.get("stream") or {}).get("security") == "tls":
                        name = '""'
                    else:
                        problems.append(
                            f"{tag}: Reality SNI «{pub}» = публичный домен — этот SNI отдаётся nginx "
                            f"(панель и Path). Укажите другой serverName (например ya.ru)"
                        )
                        continue
                if name != '""' and not is_domain(name):
                    problems.append(f"{tag}: SNI «{name}» — нужен домен")
                    continue
                if sni.get(name, port) != port:
                    what = "приём без SNI (TLS на IP)" if name == '""' else f"SNI {name}"
                    problems.append(f"{tag}: {what} уже занят другим inbound")
                    continue
                sni[name] = port
                kept += 1
            if names and kept == 0 and (ib.get("stream") or {}).get("security") == "reality":
                problems.append(f"{tag}: нет рабочего Reality SNI после исключения публичного домена")
        elif mode == "http":
            domain = normalize_host(ib.get("share_host") or "") or pub
            if not is_domain(domain):
                problems.append(f"{tag}: для {ib['stream'].get('network')} нужен публичный домен или URL share")
                continue
            path = P.front_http_path(ib)
            if not PATH_RE.match(path):
                problems.append(f"{tag}: путь «{path}» — допустимы латиница, цифры и /_.~-")
                continue
            if path in ("/", "") or any(path == r.rstrip("/") or path.startswith(r) for r in reserved_paths):
                problems.append(f"{tag}: путь «{path}» занят панелью/подписками — выберите другой Path/serviceName")
                continue
            locs = sites.setdefault(domain, [])
            if any(loc["path"] == path for loc in locs):
                problems.append(f"{tag}: путь {path} на {domain} уже занят")
                continue
            locs.append({"path": path, "port": port, "net": ib["stream"].get("network"), "tag": tag})
    # Same hostname cannot be both stream-SNI passthrough and an HTTPS site.
    # Public domain is always an HTTPS site; never steal it for Reality/TLS SNI.
    for domain in list(sites):
        if domain == pub:
            continue
        if domain in sni:
            problems.append(f"{domain}: домен используется и как SNI Reality/TLS, и для HTTPS Path — разведите их")
            del sites[domain]
    if pub and pub in sni:
        del sni[pub]
    raw_ib = raw_front_inbound(store)
    raw = {"tag": raw_ib.get("tag"), "port": int(raw_ib.get("port") or 0)} if raw_ib else None
    for ib in store.get("inbounds") or []:
        if not ib.get("enabled", True) or P.front_mode(ib) != "raw" or ib is raw_ib:
            continue
        if not pub:
            problems.append(f"{ib.get('tag')}: RAW на :443 требует публичный домен")
        else:
            problems.append(
                f"{ib.get('tag')}: на :443 публикуется только один RAW-inbound "
                f"({raw['tag'] if raw else '—'}) — этот доступен только локально"
            )
    return {"sni": sni, "sites": sites, "problems": problems, "public_domain": pub, "raw": raw}


# ---------------------------------------------------------------- certificates

def cert_for(domain: str) -> tuple[str, str, bool]:
    """(cert, key, is_real). Falls back to a self-signed pair so nginx can start before Let's Encrypt."""
    crt, key = CERT_DIR / f"{domain}.crt", CERT_DIR / f"{domain}.key"
    if crt.is_file() and key.is_file():
        return str(crt), str(key), True
    SELF_SIGNED_DIR.mkdir(parents=True, exist_ok=True)
    crt, key = SELF_SIGNED_DIR / f"{domain}.crt", SELF_SIGNED_DIR / f"{domain}.key"
    if not (crt.is_file() and key.is_file()):
        _run(["openssl", "req", "-x509", "-nodes", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
              "-days", "3650", "-subj", f"/CN={domain}", "-addext", f"subjectAltName=DNS:{domain}",
              "-keyout", str(key), "-out", str(crt)])
        try:
            os.chmod(key, 0o600)
        except OSError:
            pass
    return str(crt), str(key), False


def domains_without_cert(store: dict) -> list[str]:
    p = plan(store)
    domains = set(p["sites"])
    if p.get("public_domain"):
        domains.add(p["public_domain"])
    return [d for d in sorted(domains) if not cert_for(d)[2]]


# ---------------------------------------------------------------- render

CAMOUFLAGE_URL = "https://ya.ru/"


def _sub_location(path_seg: str, proxy: str) -> str:
    """Proxy subscription path; non-/sub/ aliases are rewritten to /sub/… so panel routes stay unique."""
    sp = _clean_sub_segment(path_seg) or "sub"
    if sp == "sub":
        return f"    location ^~ /sub/ {{\n{proxy}    }}"
    # Old 3x-ui style /{subPath}/{token} → panel /sub/{token} (avoids FastAPI /{path}/{token} catching /clients/…)
    return (
        f"    location ^~ /{sp}/ {{\n"
        f"        rewrite ^/{sp}/(.*)$ /sub/$1 break;\n"
        f"{proxy}    }}"
    )


def _panel_locations(store: dict | None = None) -> list[str]:
    """Public HTTPS site: correct links work; bare / goes to ya.ru, unknown paths are 404."""
    common = (
        "        proxy_http_version 1.1;\n"
        "        proxy_set_header Host $host;\n"
        "        proxy_set_header X-Real-IP $remote_addr;\n"
        "        proxy_set_header X-Forwarded-For $remote_addr;\n"
        "        proxy_set_header X-Forwarded-Proto https;\n"
        "        proxy_set_header Upgrade $http_upgrade;\n"
        "        proxy_set_header Connection $l2x_connection_upgrade;\n"
        "        proxy_read_timeout 300s;\n"
        "        client_max_body_size 64m;\n"
    )
    proxy = f"        proxy_pass http://{PANEL_UPSTREAM};\n{common}"
    base = (((store or {}).get("settings") or {}).get("panel") or {}).get("base_path") or ""
    base = re.sub(r"[^A-Za-z0-9_-]", "", str(base)).strip("/")
    doh_prefix = re.sub(
        r"[^A-Za-z0-9_-]", "",
        str((((store or {}).get("settings") or {}).get("doh") or {}).get("path_prefix") or "doh"),
    ).strip("_-") or "doh"
    # DoH (Pi-hole frontend): client → nginx :443 → panel → Pi-hole UDP/53
    doh_loc = (
        f"    location ^~ /{doh_prefix}/ {{\n"
        f"        proxy_pass http://{PANEL_UPSTREAM};\n"
        f"{common}"
        "        proxy_buffering off;\n"
        "        proxy_request_buffering off;\n"
        "    }"
    )
    out = [
        "    location ^~ /.well-known/acme-challenge/ {\n"
        "        root /var/www/l2x-acme;\n"
        "        default_type text/plain;\n"
        "        try_files $uri =404;\n"
        "    }",
        *[_sub_location(sp, proxy) for sp in sub_uri_paths(store)],
        f"    location ^~ /api/sub/ {{\n{proxy}    }}",
        doh_loc,
        # REST API only under secret base_path (not at site root)
        f"    location = /health {{\n{proxy}    }}",
    ]
    if base:
        out.append(f"    location = /{base} {{\n        return 302 https://$host/{base}/;\n    }}")
        out.append(f"    location ^~ /{base}/ {{\n{proxy}    }}")
        out.append("    location / {\n        return 404;\n    }")
    else:
        # No secret path yet: only bare / is camouflaged; /login and the rest still reach the panel
        out.append(f"    location / {{\n{proxy}    }}")
    # L2X Go tunnel camouflage: WSS over :443 (looks like normal web, not VPN UDP)
    try:
        import nodes as nodes_mod
        tun = nodes_mod.ensure_tunnel_settings(store or {})
        ws_path = str(tun.get("ws_path") or "").strip()
        ws_listen = str(tun.get("ws_listen") or "127.0.0.1:11081").strip()
        if ws_path.startswith("/") and ":" in ws_listen:
            ws_port = ws_listen.rsplit(":", 1)[-1]
            out.insert(
                -1 if out else 0,
                (
                    f"    location = {ws_path} {{\n"
                    f"        proxy_pass http://127.0.0.1:{ws_port};\n"
                    "        proxy_http_version 1.1;\n"
                    "        proxy_set_header Upgrade $http_upgrade;\n"
                    "        proxy_set_header Connection $l2x_connection_upgrade;\n"
                    "        proxy_set_header Host $host;\n"
                    "        proxy_set_header X-Real-IP $remote_addr;\n"
                    "        proxy_set_header X-Forwarded-For $remote_addr;\n"
                    "        proxy_read_timeout 1d;\n"
                    "        proxy_send_timeout 1d;\n"
                    "        proxy_buffering off;\n"
                    "        proxy_request_buffering off;\n"
                    "        tcp_nodelay on;\n"
                    "    }"
                ),
            )
    except Exception:
        pass
    # The only camouflage redirect in the whole config; kept as the last block of the server
    out.append(f"    location = / {{\n        return 302 {CAMOUFLAGE_URL};\n    }}")
    return out


def render(store: dict) -> tuple[str, str, list[str]]:
    p = plan(store)
    pub = p.get("public_domain") or ""
    internal = f"127.0.0.1:{P.FRONT_INTERNAL_PORT}"
    listen6 = "        listen [::]:443;\n" if _ipv6() else ""
    sni_lines = "".join(f"        {name} 127.0.0.1:{port};\n" for name, port in sorted(p["sni"].items()))
    raw = p.get("raw") if pub else None
    raw_upstream = ""
    if raw:
        # Xray terminates TLS for the public domain (RAW + fallbacks to nginx). If Xray is down,
        # the backup keeps the panel reachable via nginx TLS as before.
        sni_lines += f"        {pub} l2x_pub_raw;\n"
        raw_upstream = (
            "    upstream l2x_pub_raw {\n"
            f"        server 127.0.0.1:{raw['port']};\n"
            f"        server {internal} backup;\n"
            "    }\n"
        )
    stream = (
        f"{MARK}\n"
        "stream {\n"
        f"{raw_upstream}"
        "    map $ssl_preread_server_name $l2x_front_upstream {\n"
        "        hostnames;\n"
        f"        default {internal};\n"
        f"{sni_lines}"
        "    }\n"
        "    server {\n"
        "        listen 443;\n"
        f"{listen6}"
        "        ssl_preread on;\n"
        "        proxy_pass $l2x_front_upstream;\n"
        "        proxy_protocol on;\n"
        "        proxy_connect_timeout 5s;\n"
        "        proxy_timeout 1h;\n"
        "    }\n"
        "}\n"
    )

    new_http2 = _nginx_version() >= (1, 25, 1)
    listen = f"listen {internal} ssl proxy_protocol" + ("" if new_http2 else " http2")
    blocks = [
        MARK,
        "map $http_upgrade $l2x_connection_upgrade {\n    default upgrade;\n    ''      close;\n}",
        f"server {{\n    listen {internal} ssl proxy_protocol default_server;\n    ssl_reject_handshake on;\n}}",
    ]
    for domain, locs in sorted(p["sites"].items()):
        crt, key, _ = cert_for(domain)
        body = [
            f"    {listen};",
            *(["    http2 on;"] if new_http2 else []),
            f"    server_name {domain};",
            "    server_tokens off;",
            "    tcp_nodelay on;",
            f"    ssl_certificate {crt};",
            f"    ssl_certificate_key {key};",
            "    ssl_protocols TLSv1.2 TLSv1.3;",
            "    set_real_ip_from 127.0.0.1;",
            "    real_ip_header proxy_protocol;",
        ]
        for loc in sorted(locs, key=lambda x: x["path"]):
            body.append(_location(loc))
        if domain == pub:
            body.extend(_panel_locations(store))
        else:
            body.append("    location / {\n        return 404;\n    }")
        blocks.append("server {\n" + "\n".join(body) + "\n}")
        if raw and domain == pub:
            # Plain-HTTP twins of the public site for Xray fallbacks (TLS already terminated by Xray)
            content = [
                ln for ln in body
                if not ln.lstrip().startswith(("listen ", "http2 ", "ssl_"))
            ]
            h1 = f"    listen 127.0.0.1:{P.FRONT_FALLBACK_H1_PORT} proxy_protocol;"
            if new_http2:
                h2 = [f"    listen 127.0.0.1:{P.FRONT_FALLBACK_H2_PORT} proxy_protocol;", "    http2 on;"]
            else:
                h2 = [f"    listen 127.0.0.1:{P.FRONT_FALLBACK_H2_PORT} proxy_protocol http2;"]
            blocks.append("server {\n" + "\n".join([h1, *content]) + "\n}")
            blocks.append("server {\n" + "\n".join([*h2, *content]) + "\n}")
    # Legacy subscription ports (HTTP): 3x-ui style http://host:2096/<path>/<token>
    # Cannot iptables-REDIRECT to :443 (TLS stream) — dedicated plain-HTTP listeners.
    plain_ports = legacy_sub_plain_ports(store)
    tls_ports = legacy_sub_tls_ports(store)
    if (plain_ports or tls_ports) and pub:
        common = (
            "        proxy_http_version 1.1;\n"
            "        proxy_set_header Host $host;\n"
            "        proxy_set_header X-Real-IP $remote_addr;\n"
            "        proxy_set_header X-Forwarded-For $remote_addr;\n"
            "        proxy_set_header X-Forwarded-Proto $scheme;\n"
            "        proxy_read_timeout 300s;\n"
            "        client_max_body_size 16m;\n"
        )
        proxy = f"        proxy_pass http://{PANEL_UPSTREAM};\n{common}"
        sub_locs = "\n".join(_sub_location(sp, proxy) for sp in sub_uri_paths(store))
        sub_locs += f"\n    location ^~ /api/sub/ {{\n{proxy}    }}"
        for port in plain_ports:
            listen_lines = f"    listen {port};\n"
            if _ipv6():
                listen_lines += f"    listen [::]:{port};\n"
            blocks.append(
                "server {\n"
                f"{listen_lines}"
                f"    server_name {pub} _;\n"
                "    server_tokens off;\n"
                f"{sub_locs}\n"
                "    location / { return 404; }\n"
                "}"
            )
        if tls_ports:
            crt, key, _ = cert_for(pub)
            tunnel_ws = ""
            try:
                import nodes as nodes_mod
                tun = nodes_mod.ensure_tunnel_settings(store)
                ws_path = str(tun.get("ws_path") or "").strip()
                ws_listen = str(tun.get("ws_listen") or "127.0.0.1:11081").strip()
                if ws_path.startswith("/") and ":" in ws_listen:
                    ws_port = ws_listen.rsplit(":", 1)[-1]
                    # Prefer these ports for Go tunnel WSS: nginx terminates TLS directly
                    # (public :443 is Xray RAW + fallbacks — WS upgrade is unreliable there).
                    # No nginx `if` on Upgrade — it breaks intermittent WSS handshakes.
                    tunnel_ws = (
                        f"    location = {ws_path} {{\n"
                        f"        proxy_pass http://127.0.0.1:{ws_port};\n"
                        "        proxy_http_version 1.1;\n"
                        "        proxy_set_header Upgrade $http_upgrade;\n"
                        "        proxy_set_header Connection $l2x_connection_upgrade;\n"
                        "        proxy_set_header Host $host;\n"
                        "        proxy_set_header X-Real-IP $remote_addr;\n"
                        "        proxy_set_header X-Forwarded-For $remote_addr;\n"
                        "        proxy_read_timeout 1d;\n"
                        "        proxy_send_timeout 1d;\n"
                        "        proxy_buffering off;\n"
                        "        proxy_request_buffering off;\n"
                        "        tcp_nodelay on;\n"
                        "    }\n"
                        "    location = /l2x-tunnel-agent {\n"
                        "        default_type application/octet-stream;\n"
                        "        alias /var/www/l2x-public/l2x-tunnel-agent;\n"
                        "    }\n"
                        "    location = /install-l2x-agent.sh {\n"
                        "        default_type application/octet-stream;\n"
                        "        alias /var/www/l2x-public/install-l2x-agent.sh;\n"
                        "    }\n"
                    )
                    tun["ws_public_port"] = int(tls_ports[0])
            except Exception:
                tunnel_ws = ""
            for port in tls_ports:
                listen_lines = f"    listen {port} ssl;\n"
                if _ipv6():
                    listen_lines += f"    listen [::]:{port} ssl;\n"
                blocks.append(
                    "server {\n"
                    f"{listen_lines}"
                    f"    server_name {pub} _;\n"
                    "    server_tokens off;\n"
                    f"    ssl_certificate {crt};\n"
                    f"    ssl_certificate_key {key};\n"
                    "    ssl_protocols TLSv1.2 TLSv1.3;\n"
                    # Plain HTTP on the TLS port → redirect to https on same port
                    "    error_page 497 =301 https://$host:$server_port$request_uri;\n"
                    f"{sub_locs}\n"
                    f"{tunnel_ws}"
                    "    location / { return 404; }\n"
                    "}"
                )
    return stream, "\n\n".join(blocks) + "\n", p["problems"]


def _location(loc: dict) -> str:
    path, port, net = loc["path"], loc["port"], loc["net"]
    if net == "grpc":
        return (
            f"    location ^~ {path} {{\n"
            "        if ($content_type !~ \"application/grpc\") { return 404; }\n"
            "        client_max_body_size 0;\n"
            "        client_body_buffer_size 1m;\n"
            "        client_body_timeout 52w;\n"
            "        grpc_socket_keepalive on;\n"
            "        grpc_buffer_size 4m;\n"
            f"        grpc_pass grpc://127.0.0.1:{port};\n"
            "        grpc_read_timeout 52w;\n"
            "        grpc_send_timeout 52w;\n"
            "        grpc_set_header X-Real-IP $remote_addr;\n"
            "        grpc_set_header X-Forwarded-For $remote_addr;\n"
            "    }"
        )
    if net == "xhttp":
        # Official XHTTP-behind-nginx setup uses grpc_pass (stream-up/one speak gRPC-framed H2).
        # plain proxy_pass HTTP/1.1 breaks bidirectional reverse mux while TCP still looks "up".
        return (
            f"    location ^~ {path} {{\n"
            "        client_max_body_size 0;\n"
            "        client_body_buffer_size 1m;\n"
            "        client_body_timeout 52w;\n"
            "        grpc_socket_keepalive on;\n"
            "        grpc_buffer_size 4m;\n"
            f"        grpc_pass grpc://127.0.0.1:{port};\n"
            "        grpc_read_timeout 52w;\n"
            "        grpc_send_timeout 52w;\n"
            "        grpc_set_header Host $host;\n"
            "        grpc_set_header X-Real-IP $remote_addr;\n"
            "        grpc_set_header X-Forwarded-For $remote_addr;\n"
            "    }"
        )
    # ws / httpupgrade
    return (
        f"    location = {path} {{\n"
        "        if ($http_upgrade = \"\") { return 404; }\n"
        f"        proxy_pass http://127.0.0.1:{port};\n"
        "        proxy_http_version 1.1;\n"
        "        proxy_set_header Upgrade $http_upgrade;\n"
        "        proxy_set_header Connection $l2x_connection_upgrade;\n"
        "        proxy_set_header Host $host;\n"
        "        proxy_set_header X-Real-IP $remote_addr;\n"
        "        proxy_set_header X-Forwarded-For $remote_addr;\n"
        "        proxy_read_timeout 1d;\n"
        "        proxy_send_timeout 1d;\n"
        "        proxy_buffering off;\n"
        "        proxy_request_buffering off;\n"
        "        tcp_nodelay on;\n"
        "    }"
    )


# ---------------------------------------------------------------- apply (verify → swap → reload → rollback)

def _patch_nginx_fd_limits(main: str) -> tuple[str, bool]:
    """Raise worker_connections / worker_rlimit_nofile; never lower an already higher value."""
    changed = False
    m_conn = re.search(r"worker_connections\s+(\d+)\s*;", main)
    if m_conn:
        if int(m_conn.group(1)) < WORKER_CONNECTIONS:
            main = re.sub(
                r"worker_connections\s+\d+\s*;",
                f"worker_connections {WORKER_CONNECTIONS};",
                main,
                count=1,
            )
            changed = True
    else:
        if re.search(r"events\s*\{", main):
            main = re.sub(
                r"(events\s*\{)",
                rf"\1\n    worker_connections {WORKER_CONNECTIONS};",
                main,
                count=1,
            )
            changed = True

    m_rl = re.search(r"(?m)^\s*worker_rlimit_nofile\s+(\d+)\s*;", main)
    if m_rl:
        if int(m_rl.group(1)) < WORKER_RLIMIT_NOFILE:
            main = re.sub(
                r"(?m)^\s*worker_rlimit_nofile\s+\d+\s*;",
                f"worker_rlimit_nofile {WORKER_RLIMIT_NOFILE};",
                main,
                count=1,
            )
            changed = True
    else:
        if re.search(r"(?m)^\s*worker_processes\s+", main):
            main = re.sub(
                r"(?m)^(\s*worker_processes\s+[^;]+;)",
                rf"\1\nworker_rlimit_nofile {WORKER_RLIMIT_NOFILE};",
                main,
                count=1,
            )
        else:
            main = f"worker_rlimit_nofile {WORKER_RLIMIT_NOFILE};\n" + main
        changed = True
    return main, changed


def _ensure_nginx_systemd_nofile() -> tuple[str | None, bool]:
    """Install LimitNOFILE drop-in. Returns (previous contents or None if new, changed?)."""
    prev: str | None = None
    if NGINX_SYSTEMD_DROPIN.is_file():
        prev = NGINX_SYSTEMD_DROPIN.read_text(encoding="utf-8")
        if prev.strip() == NGINX_SYSTEMD_DROPIN_BODY.strip():
            return prev, False
    NGINX_SYSTEMD_DROPIN_DIR.mkdir(parents=True, exist_ok=True)
    NGINX_SYSTEMD_DROPIN.write_text(NGINX_SYSTEMD_DROPIN_BODY, encoding="utf-8")
    return prev, True


def panel_upstream_addr(default: str = "127.0.0.1:8090") -> str:
    """Active panel backend host:port (dual-slot cutover state)."""
    try:
        if PANEL_UPSTREAM_STATE.is_file():
            addr = PANEL_UPSTREAM_STATE.read_text(encoding="utf-8").strip().splitlines()[0].strip()
            if addr and ":" in addr:
                return addr
    except (OSError, IndexError):
        pass
    return default


def ensure_panel_upstream_conf(addr: str | None = None) -> bool:
    """Ensure nginx upstream for the panel exists. Returns True if file changed."""
    addr = (addr or panel_upstream_addr()).strip() or "127.0.0.1:8090"
    body = (
        f"{MARK}\n"
        f"upstream {PANEL_UPSTREAM} {{\n"
        f"    server {addr};\n"
        f"    keepalive 32;\n"
        f"}}\n"
    )
    changed = False
    try:
        PANEL_UPSTREAM_CONF.parent.mkdir(parents=True, exist_ok=True)
        prev = PANEL_UPSTREAM_CONF.read_text(encoding="utf-8") if PANEL_UPSTREAM_CONF.is_file() else None
        if prev != body:
            PANEL_UPSTREAM_CONF.write_text(body, encoding="utf-8")
            changed = True
        PANEL_UPSTREAM_STATE.parent.mkdir(parents=True, exist_ok=True)
        if not PANEL_UPSTREAM_STATE.is_file() or PANEL_UPSTREAM_STATE.read_text(encoding="utf-8").strip() != addr:
            PANEL_UPSTREAM_STATE.write_text(addr + "\n", encoding="utf-8")
    except OSError:
        pass
    return changed


def _ensure_includes() -> tuple[dict[Path, str | None], bool]:
    """Hook generated files + FD limits into nginx.

    Returns (touched files snapshot, need_systemd_restart).
    LimitNOFILE only applies after daemon-reload + restart of the nginx master.
    """
    touched: dict[Path, str | None] = {}
    need_restart = False
    # Upstream must exist before nginx -t (blue-green cutover owns the live target)
    try:
        prev_up = PANEL_UPSTREAM_CONF.read_text(encoding="utf-8") if PANEL_UPSTREAM_CONF.is_file() else None
    except OSError:
        prev_up = None
    if ensure_panel_upstream_conf():
        touched[PANEL_UPSTREAM_CONF] = prev_up
    main = NGINX_CONF.read_text(encoding="utf-8")
    orig_main = main
    if STREAM_INCLUDE_LINE not in main:
        main = main.rstrip("\n") + f"\n\n# l2x-panel: public :443 front\n{STREAM_INCLUDE_LINE}\n"
    main, fd_changed = _patch_nginx_fd_limits(main)
    if main != orig_main:
        touched[NGINX_CONF] = orig_main
        NGINX_CONF.write_text(main, encoding="utf-8")
        if fd_changed:
            need_restart = True  # workers keep old RLIMIT until master restarts
    want = f"{MARK}\ninclude {HTTP_CONF};\n"
    cur = HTTP_INCLUDE.read_text(encoding="utf-8") if HTTP_INCLUDE.is_file() else None
    if cur != want:
        touched[HTTP_INCLUDE] = cur
        HTTP_INCLUDE.parent.mkdir(parents=True, exist_ok=True)
        HTTP_INCLUDE.write_text(want, encoding="utf-8")
    try:
        prev_dropin, dropin_changed = _ensure_nginx_systemd_nofile()
        if dropin_changed:
            touched[NGINX_SYSTEMD_DROPIN] = prev_dropin
            need_restart = True
    except OSError:
        pass
    return touched, need_restart


def _restore(snapshot: dict[Path, str | None]) -> None:
    for path, content in snapshot.items():
        try:
            if content is None:
                path.unlink(missing_ok=True)
            else:
                path.write_text(content, encoding="utf-8")
        except OSError:
            pass


def _includes_already_ready() -> bool:
    """True when nginx main/includes/FD drop-in already match what _ensure_includes would write."""
    try:
        main = NGINX_CONF.read_text(encoding="utf-8")
        if STREAM_INCLUDE_LINE not in main:
            return False
        if _patch_nginx_fd_limits(main)[0] != main:
            return False
        want = f"{MARK}\ninclude {HTTP_CONF};\n"
        cur = HTTP_INCLUDE.read_text(encoding="utf-8") if HTTP_INCLUDE.is_file() else None
        if cur != want:
            return False
        if not NGINX_SYSTEMD_DROPIN.is_file():
            return False
        if NGINX_SYSTEMD_DROPIN.read_text(encoding="utf-8").strip() != NGINX_SYSTEMD_DROPIN_BODY.strip():
            return False
    except OSError:
        return False
    return True


def stage(store: dict) -> dict:
    """Write candidate config and run `nginx -t`. Nginx keeps serving the old config until commit()."""
    if not available():
        return {"ok": True, "skipped": True, "snapshot": {}, "problems": [], "error": "", "restart": False}
    # Inbounds with routing problems are left out of nginx (and reported); they never block the others.
    stream, http, problems = render(store)
    FRONT_DIR.mkdir(parents=True, exist_ok=True)
    # Fast path: generated front configs + includes already match → skip write/nginx -t
    try:
        cur_stream = STREAM_CONF.read_text(encoding="utf-8") if STREAM_CONF.is_file() else None
        cur_http = HTTP_CONF.read_text(encoding="utf-8") if HTTP_CONF.is_file() else None
    except OSError:
        cur_stream = cur_http = None
    if cur_stream == stream and cur_http == http and _includes_already_ready():
        return {
            "ok": True,
            "snapshot": {},
            "changed": False,
            "problems": problems,
            "error": "",
            "restart": False,
        }
    snapshot: dict[Path, str | None] = {}
    need_restart = False
    for path in (STREAM_CONF, HTTP_CONF):
        snapshot[path] = path.read_text(encoding="utf-8") if path.is_file() else None
    try:
        includes, need_restart = _ensure_includes()
        snapshot.update({k: v for k, v in includes.items() if k not in snapshot})
        STREAM_CONF.write_text(stream, encoding="utf-8")
        HTTP_CONF.write_text(http, encoding="utf-8")
    except OSError as exc:
        _restore(snapshot)
        return {"ok": False, "snapshot": {}, "problems": [], "error": f"nginx: запись конфига: {exc}", "restart": False}
    test = _run(["nginx", "-t"])
    if not test["ok"]:
        _restore(snapshot)
        return {"ok": False, "snapshot": {}, "problems": [], "error": "nginx -t: " + (test["stderr"] or test["stdout"])[-800:], "restart": False}
    changed = any((path.read_text(encoding="utf-8") if path.is_file() else None) != old for path, old in snapshot.items())
    return {
        "ok": True,
        "snapshot": snapshot,
        "changed": changed or need_restart,
        "problems": problems,
        "error": "",
        "restart": need_restart,
    }


def rollback(staged: dict) -> None:
    _restore(staged.get("snapshot") or {})


def _listening(port: int, timeout: float = 5.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.3)
    return False


def _reload(*, restart: bool = False) -> dict:
    active = _run(["systemctl", "is-active", "nginx"])["stdout"].strip() == "active"
    if restart:
        _run(["systemctl", "daemon-reload"])
        _run(["systemctl", "enable", "nginx"])
        r = _run(["systemctl", "restart", "nginx"])
    elif active:
        r = _run(["systemctl", "reload", "nginx"])
    else:
        _run(["systemctl", "enable", "nginx"])
        r = _run(["systemctl", "restart", "nginx"])
    ok = r["ok"] and _listening(P.FRONT_PORT) and _listening(P.FRONT_INTERNAL_PORT)
    return {"ok": ok, "error": "" if ok else (r["stderr"] or r["stdout"] or "nginx не слушает :443")}


def commit(staged: dict, *, defer_reload_sec: float = 0) -> dict:
    """Load the verified config; restore the previous one if nginx does not come up on :443.

    defer_reload_sec > 0: schedule reload shortly after returning so an in-flight
    HTTP response (e.g. /agent/apply through this same nginx) can flush first.
    nginx -t already passed in stage(), so a deferred reload almost always succeeds.
    """
    if staged.get("skipped"):
        return {"ok": True, "skipped": True}
    if not staged.get("changed") and _listening(P.FRONT_PORT, 1) and _listening(P.FRONT_INTERNAL_PORT, 1):
        return {"ok": True}
    restart = bool(staged.get("restart"))
    if defer_reload_sec and defer_reload_sec > 0:
        snap = staged  # keep snapshot for possible late rollback

        def _later() -> None:
            try:
                r = _reload(restart=restart)
                if not r.get("ok"):
                    rollback(snap)
                    _reload(restart=restart)
            except Exception:
                try:
                    rollback(snap)
                    _reload(restart=restart)
                except Exception:
                    pass

        t = threading.Timer(float(defer_reload_sec), _later)
        t.daemon = True
        t.start()
        return {"ok": True, "deferred_reload": True}
    r = _reload(restart=restart)
    if r["ok"]:
        return r
    rollback(staged)
    _reload(restart=restart)
    return {"ok": False, "error": f"nginx: {r['error']}; предыдущий конфиг восстановлен"}


def status(store: dict) -> dict:
    p = plan(store)
    return {
        "available": available(),
        "listening": _listening(P.FRONT_PORT, 0.5) if available() else False,
        "sni": p["sni"],
        "sites": {d: {"locations": locs, "real_cert": cert_for(d)[2]} for d, locs in p["sites"].items()},
        "problems": p["problems"],
    }
