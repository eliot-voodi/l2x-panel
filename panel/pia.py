"""Private Internet Access (PIA) WireGuard outbound helper.

Login → signed server list → /addKey on selected host → Xray userspace WireGuard outbound.
"""
from __future__ import annotations

import base64
import http.client
import json
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
CA_PEM = (HERE / "pia_ca.rsa.4096.crt").read_bytes()
SERVERLIST_PUBKEY_PEM = (HERE / "pia_serverlist_public_key.pem").read_bytes()

TOKEN_URL = "https://www.privateinternetaccess.com/api/client/v2/token"
SERVERLIST_URL = "https://serverlist.piaservers.net/vpninfo/servers/v6"
ADDKEY_PORT = 1337
UA = "l2xpanel-pia/1.0"
# PIA tokens are typically valid ~24h; refresh earlier to avoid edge expiry.
TOKEN_TTL_SECONDS = 20 * 3600
TOKEN_REFRESH_SKEW_SECONDS = 2 * 3600

_REGION_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_COUNTRY_RE = re.compile(r"^[A-Za-z]{2}$")
_HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")


def _tag_part(value: str, *, strip_domain: bool = False) -> str:
    s = (value or "").strip().lower().replace("_", "-")
    if strip_domain and "." in s:
        s = s.split(".", 1)[0]
    return re.sub(r"[^a-z0-9.-]+", "-", s).strip("-")


def outbound_tag(region_id: str, hostname: str) -> str:
    region = _tag_part(region_id)
    server = _tag_part(hostname, strip_domain=True)
    if not region:
        return f"pia-{server}" if server else "pia"
    return f"pia-{region}-{server}" if server else f"pia-{region}"


def authenticate(username: str, password: str) -> dict:
    user = (username or "").strip()
    pwd = password or ""
    if not user or not pwd:
        return {"ok": False, "error": "укажите PIA username и password"}
    boundary = "----l2xpia" + base64.urlsafe_b64encode(user.encode()).decode()[:12]
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="username"\r\n\r\n{user}\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="password"\r\n\r\n{pwd}\r\n'
        f"--{boundary}--\r\n"
    ).encode()
    req = urllib.request.Request(
        TOKEN_URL,
        data=body,
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Accept": "application/json",
            "User-Agent": UA,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            raw = resp.read()
            data = json.loads(raw)
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            return {"ok": False, "error": "PIA: неверный username/password"}
        return {"ok": False, "error": f"PIA auth HTTP {exc.code}"}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"PIA auth: {exc}"}
    token = str(data.get("token") or "").strip()
    if len(token) < 16:
        return {"ok": False, "error": "PIA auth: пустой token"}
    return {"ok": True, "token": token, "username": user}


def _split_signed_list(raw: bytes) -> tuple[bytes, bytes]:
    if not raw or raw[:1] != b"{":
        raise ValueError("server list: нет JSON")
    end = raw.rfind(b"}")
    if end < 0 or end == len(raw) - 1:
        raise ValueError("server list: нет подписи")
    body = raw[: end + 1]
    encoded = re.sub(rb"\s+", b"", raw[end + 1 :])
    if not encoded:
        raise ValueError("server list: пустая подпись")
    return body, base64.b64decode(encoded)


def _verify_server_list(raw: bytes) -> bytes:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    body, signature = _split_signed_list(raw)
    pub = serialization.load_pem_public_key(SERVERLIST_PUBKEY_PEM)
    pub.verify(signature, body, padding.PKCS1v15(), hashes.SHA256())
    return body


def _parse_regions(payload: bytes) -> list[dict]:
    data = json.loads(payload)
    regions_out: list[dict] = []
    seen: set[str] = set()
    for raw in data.get("regions") or []:
        rid = str(raw.get("id") or "").strip()
        name = str(raw.get("name") or "").strip()
        country = str(raw.get("country") or "").strip().upper()
        if not _REGION_ID_RE.match(rid) or not name or not _COUNTRY_RE.match(country):
            continue
        key = rid.lower()
        if key in seen:
            continue
        if raw.get("offline") is True:
            continue
        seen.add(key)
        servers = []
        for s in ((raw.get("servers") or {}).get("wg") or []):
            ip = str(s.get("ip") or "").strip()
            host = str(s.get("cn") or s.get("hostname") or "").strip()
            if not ip or not host or not _HOST_RE.match(host):
                continue
            try:
                socket.inet_aton(ip)
            except OSError:
                continue
            servers.append({"hostname": host, "ip": ip})
        if not servers:
            continue
        regions_out.append({
            "id": rid,
            "name": name,
            "country": country,
            "geo": bool(raw.get("geo")),
            "port_forward": bool(raw.get("port_forward") or raw.get("port_forwarding")),
            "servers": servers,
        })
    regions_out.sort(key=lambda r: (r["country"], r["name"].lower()))
    return regions_out


def list_regions() -> dict:
    req = urllib.request.Request(
        SERVERLIST_URL,
        headers={"Accept": "application/json, text/plain;q=0.9", "User-Agent": UA},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read()
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"PIA server list: {exc}", "regions": []}
    try:
        try:
            payload = _verify_server_list(raw)
        except ImportError:
            payload, _sig = _split_signed_list(raw)
        regions = _parse_regions(payload)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"PIA server list: {exc}", "regions": []}
    if not regions:
        return {"ok": False, "error": "PIA: нет WireGuard регионов", "regions": []}
    return {"ok": True, "regions": regions}


def countries_from_regions(regions: list[dict]) -> list[dict]:
    by: dict[str, dict] = {}
    for r in regions:
        code = r["country"]
        item = by.setdefault(code, {"code": code, "name": code, "regions": []})
        item["regions"].append({
            "id": r["id"],
            "name": r["name"],
            "port_forward": r.get("port_forward"),
            "servers": r.get("servers") or [],
        })
    return sorted(by.values(), key=lambda c: c["code"])


def find_server(regions: list[dict], *, region_id: str = "", hostname: str = "") -> dict | None:
    host = (hostname or "").strip().lower()
    rid = (region_id or "").strip().lower()
    for r in regions:
        if rid and r["id"].lower() != rid:
            continue
        for s in r.get("servers") or []:
            hn = (s.get("hostname") or "").lower()
            if host and host not in (hn, hn.split(".", 1)[0], outbound_tag(r["id"], hn).lower()):
                continue
            return {"region": r, "server": s}
        if host:
            continue
        if r.get("servers"):
            return {"region": r, "server": r["servers"][0]}
    return None


def _wg_keys(xray_bin: Path) -> dict:
    import subprocess

    try:
        p = subprocess.run([str(xray_bin), "wg"], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "error": str(exc)}
    priv = pub = ""
    for line in (p.stdout or "").splitlines():
        low = line.lower()
        if "private" in low and ":" in line:
            priv = line.split(":", 1)[1].strip()
        elif "public" in low and ":" in line:
            pub = line.split(":", 1)[1].strip()
    if not priv or not pub:
        return {"ok": False, "error": "xray wg: нет ключей"}
    return {"ok": True, "private_key": priv, "public_key": pub}


def register_key(token: str, server: dict) -> dict:
    host = str(server.get("hostname") or "").strip()
    ip = str(server.get("ip") or "").strip()
    pubkey = str(server.get("public_key") or "").strip()
    if not host or not ip or not pubkey or not token:
        return {"ok": False, "error": "PIA addKey: неполные параметры"}
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_verify_locations(cadata=CA_PEM.decode())
    try:
        raw_sock = socket.create_connection((ip, ADDKEY_PORT), timeout=20)
        ssock = ctx.wrap_socket(raw_sock, server_hostname=host)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"PIA TLS {host}: {exc}"}
    path = "/addKey?" + urllib.parse.urlencode({"pt": token, "pubkey": pubkey})
    try:
        conn = http.client.HTTPSConnection(host, ADDKEY_PORT, timeout=25, context=ctx)
        conn.sock = ssock
        conn.request("GET", path, headers={"Accept": "application/json", "User-Agent": UA})
        resp = conn.getresponse()
        body = resp.read()
        status = resp.status
        conn.close()
    except Exception as exc:  # noqa: BLE001
        try:
            ssock.close()
        except Exception:
            pass
        return {"ok": False, "error": f"PIA addKey: {exc}"}
    if status in (401, 403):
        return {"ok": False, "error": "PIA token отклонён — войдите снова"}
    if status != 200:
        return {"ok": False, "error": f"PIA addKey HTTP {status}"}
    try:
        data = json.loads(body)
    except Exception:
        return {"ok": False, "error": "PIA addKey: не JSON"}
    if str(data.get("status") or "") != "OK":
        return {"ok": False, "error": "PIA addKey: сервер отклонил ключ"}
    peer_ip = str(data.get("peer_ip") or "").strip()
    server_key = str(data.get("server_key") or "").strip()
    server_ip = str(data.get("server_ip") or "").strip()
    server_port = int(data.get("server_port") or 0)
    if not peer_ip or not server_key or not server_ip or not (1 <= server_port <= 65535):
        return {"ok": False, "error": "PIA addKey: неполный ответ"}
    if "/" not in peer_ip:
        peer_ip = f"{peer_ip}/32"
    return {
        "ok": True,
        "peer_ip": peer_ip,
        "server_key": server_key,
        "server_ip": server_ip,
        "server_port": server_port,
        "dns_servers": list(data.get("dns_servers") or []),
    }


def build_outbound(*, secret_key: str, peer_ip: str, server_key: str, endpoint: str, hostname: str = "") -> dict:
    cfg = {
        "protocol": "wireguard",
        "settings": {
            "secretKey": secret_key,
            "address": [peer_ip],
            "mtu": 1420,
            "noKernelTun": True,
            "domainStrategy": "ForceIPv4",
            "peers": [{
                "publicKey": server_key,
                "endpoint": endpoint,
                "allowedIPs": ["0.0.0.0/0"],
                "keepAlive": 25,
            }],
        },
    }
    if hostname:
        cfg["piaHostname"] = hostname
    return cfg


def provision_outbound(token: str, *, region_id: str = "", hostname: str = "",
                       xray_bin: Path | None = None, regions: list[dict] | None = None) -> dict:
    """Register a fresh WireGuard peer for a PIA server using an auth token."""
    if not (token or "").strip():
        return {"ok": False, "error": "PIA: нет token"}
    if regions is None:
        catalog = list_regions()
        if not catalog.get("ok"):
            return catalog
        regions = catalog["regions"]
    hit = find_server(regions, region_id=region_id, hostname=hostname)
    if not hit:
        return {"ok": False, "error": "PIA: сервер не найден (region/hostname)"}
    region, server = hit["region"], hit["server"]
    keys = _wg_keys(xray_bin or Path("/usr/local/bin/xray"))
    if not keys.get("ok"):
        return keys
    reg = register_key(token, {**server, "public_key": keys["public_key"]})
    if not reg.get("ok"):
        return reg
    tag = outbound_tag(region["id"], server["hostname"])
    endpoint = f"{reg['server_ip']}:{reg['server_port']}"
    config = build_outbound(
        secret_key=keys["private_key"],
        peer_ip=reg["peer_ip"],
        server_key=reg["server_key"],
        endpoint=endpoint,
        hostname=server["hostname"],
    )
    return {
        "ok": True,
        "tag": tag,
        "config": config,
        "region": region,
        "server": server,
        "region_id": region["id"],
        "hostname": server["hostname"],
        "info": f"PIA {region['name']} {server['hostname']} {endpoint}",
        "remark": f"PIA {region['name']}",
        "country": region["country"],
    }


def create_outbound(username: str, password: str, *, region_id: str = "", hostname: str = "",
                    xray_bin: Path | None = None, token: str = "") -> dict:
    """Auth (unless token given) → pick server → WG keys → addKey → outbound config."""
    tok = (token or "").strip()
    if not tok:
        auth = authenticate(username, password)
        if not auth.get("ok"):
            return auth
        tok = auth["token"]
        auth_meta = {"token": tok, "username": auth.get("username") or username}
    else:
        auth_meta = {"token": tok}
    res = provision_outbound(tok, region_id=region_id, hostname=hostname, xray_bin=xray_bin)
    if not res.get("ok"):
        # Token may have expired mid-flight — one retry with fresh login
        if username and password and "token" in str(res.get("error") or "").lower():
            auth = authenticate(username, password)
            if auth.get("ok"):
                res = provision_outbound(auth["token"], region_id=region_id, hostname=hostname, xray_bin=xray_bin)
                if res.get("ok"):
                    auth_meta = {"token": auth["token"], "username": auth.get("username") or username}
        if not res.get("ok"):
            return res
    res.update(auth_meta)
    return res
