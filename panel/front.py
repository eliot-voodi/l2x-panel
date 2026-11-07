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
import time
from pathlib import Path

import protocols as P

NGINX_CONF = Path("/etc/nginx/nginx.conf")
FRONT_DIR = Path("/etc/nginx/l2x")
STREAM_CONF = FRONT_DIR / "stream.conf"
HTTP_CONF = FRONT_DIR / "http.conf"
HTTP_INCLUDE = Path("/etc/nginx/conf.d/l2x-front.conf")
CERT_DIR = Path(os.environ.get("L2XPANEL_CERT_DIR", "/etc/l2xpanel/certs"))
SELF_SIGNED_DIR = CERT_DIR / "self-signed"
PANEL_UPSTREAM = "127.0.0.1:8090"
MARK = "# managed by l2x-panel — generated, edits are overwritten"
STREAM_INCLUDE_LINE = f"include {STREAM_CONF};"

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


def legacy_sub_ports(store: dict | None = None) -> list[int]:
    """Extra HTTP ports nginx should listen on for old panel subscription URLs (e.g. 2096)."""
    sub = (((store or {}).get("settings") or {}).get("sub") or {})
    ports: list[int] = []
    for raw in sub.get("legacy_ports") or []:
        try:
            p = int(raw)
        except (TypeError, ValueError):
            continue
        if 1 <= p <= 65535 and p not in (80, 443, P.FRONT_PORT, P.FRONT_INTERNAL_PORT) and p not in ports:
            ports.append(p)
    return ports


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
    return {"sni": sni, "sites": sites, "problems": problems, "public_domain": pub}


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
        *[f"    location ^~ /{sp}/ {{\n{proxy}    }}" for sp in sub_uri_paths(store)],
        f"    location ^~ /api/sub/ {{\n{proxy}    }}",
        doh_loc,
        f"    location ^~ /panel/api/ {{\n{proxy}    }}",
        f"    location = /health {{\n{proxy}    }}",
    ]
    if base:
        out.append(f"    location = /{base} {{\n        return 302 https://$host/{base}/;\n    }}")
        out.append(f"    location ^~ /{base}/ {{\n{proxy}    }}")
        out.append("    location / {\n        return 404;\n    }")
    else:
        # No secret path yet: only bare / is camouflaged; /login and the rest still reach the panel
        out.append(f"    location / {{\n{proxy}    }}")
    # The only camouflage redirect in the whole config; kept as the last block of the server
    out.append(f"    location = / {{\n        return 302 {CAMOUFLAGE_URL};\n    }}")
    return out


def render(store: dict) -> tuple[str, str, list[str]]:
    p = plan(store)
    pub = p.get("public_domain") or ""
    internal = f"127.0.0.1:{P.FRONT_INTERNAL_PORT}"
    listen6 = "        listen [::]:443;\n" if _ipv6() else ""
    sni_lines = "".join(f"        {name} 127.0.0.1:{port};\n" for name, port in sorted(p["sni"].items()))
    stream = (
        f"{MARK}\n"
        "stream {\n"
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
    # Legacy subscription ports (HTTP): 3x-ui style http://host:2096/<path>/<token>
    # Cannot iptables-REDIRECT to :443 (TLS stream) — dedicated plain-HTTP listeners.
    leg_ports = legacy_sub_ports(store)
    if leg_ports and pub:
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
        sub_locs = "\n".join(
            f"    location ^~ /{sp}/ {{\n{proxy}    }}" for sp in sub_uri_paths(store)
        )
        sub_locs += f"\n    location ^~ /api/sub/ {{\n{proxy}    }}"
        for port in leg_ports:
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
    return stream, "\n\n".join(blocks) + "\n", p["problems"]


def _location(loc: dict) -> str:
    path, port, net = loc["path"], loc["port"], loc["net"]
    if net == "grpc":
        return (
            f"    location ^~ {path} {{\n"
            "        if ($content_type !~ \"application/grpc\") { return 404; }\n"
            "        client_max_body_size 0;\n"
            "        client_body_buffer_size 512k;\n"
            "        client_body_timeout 52w;\n"
            f"        grpc_pass grpc://127.0.0.1:{port};\n"
            "        grpc_read_timeout 52w;\n"
            "        grpc_send_timeout 52w;\n"
            "        grpc_set_header X-Real-IP $remote_addr;\n"
            "        grpc_set_header X-Forwarded-For $remote_addr;\n"
            "    }"
        )
    if net == "xhttp":
        return (
            f"    location ^~ {path} {{\n"
            "        client_max_body_size 0;\n"
            "        client_body_timeout 1h;\n"
            f"        proxy_pass http://127.0.0.1:{port};\n"
            "        proxy_http_version 1.1;\n"
            "        proxy_set_header Host $host;\n"
            "        proxy_set_header X-Real-IP $remote_addr;\n"
            "        proxy_set_header X-Forwarded-For $remote_addr;\n"
            "        proxy_buffering off;\n"
            "        proxy_request_buffering off;\n"
            "        proxy_read_timeout 1h;\n"
            "        proxy_send_timeout 1h;\n"
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
        "    }"
    )


# ---------------------------------------------------------------- apply (verify → swap → reload → rollback)

def _ensure_includes() -> dict[Path, str | None]:
    """Hook generated files into nginx. Returns previous contents of every touched file."""
    touched: dict[Path, str | None] = {}
    main = NGINX_CONF.read_text(encoding="utf-8")
    if STREAM_INCLUDE_LINE not in main:
        touched[NGINX_CONF] = main
        NGINX_CONF.write_text(main.rstrip("\n") + f"\n\n# l2x-panel: public :443 front\n{STREAM_INCLUDE_LINE}\n",
                              encoding="utf-8")
    want = f"{MARK}\ninclude {HTTP_CONF};\n"
    cur = HTTP_INCLUDE.read_text(encoding="utf-8") if HTTP_INCLUDE.is_file() else None
    if cur != want:
        touched[HTTP_INCLUDE] = cur
        HTTP_INCLUDE.parent.mkdir(parents=True, exist_ok=True)
        HTTP_INCLUDE.write_text(want, encoding="utf-8")
    return touched


def _restore(snapshot: dict[Path, str | None]) -> None:
    for path, content in snapshot.items():
        try:
            if content is None:
                path.unlink(missing_ok=True)
            else:
                path.write_text(content, encoding="utf-8")
        except OSError:
            pass


def stage(store: dict) -> dict:
    """Write candidate config and run `nginx -t`. Nginx keeps serving the old config until commit()."""
    if not available():
        return {"ok": True, "skipped": True, "snapshot": {}, "problems": [], "error": ""}
    # Inbounds with routing problems are left out of nginx (and reported); they never block the others.
    stream, http, problems = render(store)
    FRONT_DIR.mkdir(parents=True, exist_ok=True)
    snapshot: dict[Path, str | None] = {}
    for path in (STREAM_CONF, HTTP_CONF):
        snapshot[path] = path.read_text(encoding="utf-8") if path.is_file() else None
    try:
        snapshot.update({k: v for k, v in _ensure_includes().items() if k not in snapshot})
        STREAM_CONF.write_text(stream, encoding="utf-8")
        HTTP_CONF.write_text(http, encoding="utf-8")
    except OSError as exc:
        _restore(snapshot)
        return {"ok": False, "snapshot": {}, "problems": [], "error": f"nginx: запись конфига: {exc}"}
    test = _run(["nginx", "-t"])
    if not test["ok"]:
        _restore(snapshot)
        return {"ok": False, "snapshot": {}, "problems": [], "error": "nginx -t: " + (test["stderr"] or test["stdout"])[-800:]}
    changed = any((path.read_text(encoding="utf-8") if path.is_file() else None) != old for path, old in snapshot.items())
    return {"ok": True, "snapshot": snapshot, "changed": changed, "problems": problems, "error": ""}


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


def _reload() -> dict:
    if _run(["systemctl", "is-active", "nginx"])["stdout"].strip() == "active":
        r = _run(["systemctl", "reload", "nginx"])
    else:
        _run(["systemctl", "enable", "nginx"])
        r = _run(["systemctl", "restart", "nginx"])
    ok = r["ok"] and _listening(P.FRONT_PORT) and _listening(P.FRONT_INTERNAL_PORT)
    return {"ok": ok, "error": "" if ok else (r["stderr"] or r["stdout"] or "nginx не слушает :443")}


def commit(staged: dict) -> dict:
    """Load the verified config; restore the previous one if nginx does not come up on :443."""
    if staged.get("skipped"):
        return {"ok": True, "skipped": True}
    if not staged.get("changed") and _listening(P.FRONT_PORT, 1) and _listening(P.FRONT_INTERNAL_PORT, 1):
        return {"ok": True}
    r = _reload()
    if r["ok"]:
        return r
    rollback(staged)
    _reload()
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
