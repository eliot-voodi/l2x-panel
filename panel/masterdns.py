"""MasterDNS (l2x-dnsd) management: config, systemd, client TOML download."""
from __future__ import annotations

import io
import json
import os
import secrets
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Any

import ops as ops_mod

DNSD_BIN = Path("/usr/local/bin/l2x-dnsd")
DNSD_DIR = Path("/etc/l2x-dnsd")
DNSD_CFG = DNSD_DIR / "dnsd.yaml"
DNSD_KEY = DNSD_DIR / "encrypt_key.txt"
DNSD_UNIT = Path("/etc/systemd/system/l2x-dnsd.service")
DNSD_HEALTH = "http://127.0.0.1:9111/health"

DEFAULT_RESOLVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "8.8.4.4", "1.0.0.1"]

ENCRYPTION_METHODS = {
    0: "None",
    1: "XOR",
    2: "ChaCha20",
    3: "AES-128-GCM",
    4: "AES-192-GCM",
    5: "AES-256-GCM",
}


def default_settings() -> dict:
    return {
        "enabled": False,
        "domain": "",
        "ns_hostname": "",
        "ns_ip": "",
        "listen": ":53",
        "encryption_method": 2,
        "encryption_key": "",
        "resolvers": list(DEFAULT_RESOLVERS),
        "client_listen_ip": "127.0.0.1",
        "client_listen_port": 18000,
        "protocol_type": "SOCKS5",
    }


def ensure_settings(store: dict) -> dict:
    s = store.setdefault("settings", {})
    md = s.setdefault("masterdns", {})
    for k, v in default_settings().items():
        md.setdefault(k, v if not isinstance(v, list) else list(v))
    if not isinstance(md.get("resolvers"), list):
        md["resolvers"] = list(DEFAULT_RESOLVERS)
    method = int(md.get("encryption_method") or 2)
    if method not in ENCRYPTION_METHODS:
        method = 2
    md["encryption_method"] = method
    if not str(md.get("encryption_key") or "").strip():
        md["encryption_key"] = generate_key(method)
    return md


def required_key_length(method: int) -> int:
    if method == 3:
        return 16
    if method == 4:
        return 24
    return 32


def generate_key(method: int = 2) -> str:
    n = required_key_length(method)
    return secrets.token_hex((n + 1) // 2)[:n]


def _run(cmd: list[str], timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)


def systemd_available() -> bool:
    return shutil.which("systemctl") is not None and Path("/run/systemd/system").exists()


def unit_body() -> str:
    return """[Unit]
Description=L2X MasterDNS tunnel server (l2x-dnsd)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/l2x-dnsd -config /etc/l2x-dnsd/dnsd.yaml
Restart=always
RestartSec=2
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
"""


def render_server_yaml(md: dict) -> str:
    domain = str(md.get("domain") or "").strip().lower().rstrip(".")
    listen = str(md.get("listen") or ":53").strip() or ":53"
    method = int(md.get("encryption_method") or 2)
    ns_host = str(md.get("ns_hostname") or "").strip().lower().rstrip(".")
    ns_ip = str(md.get("ns_ip") or "").strip()
    if not ns_host and domain:
        # ns.<parent of v.example.com>  →  ns.example.com if domain is v.example.com
        parts = domain.split(".")
        ns_host = "ns." + ".".join(parts[1:]) if len(parts) > 2 else f"ns.{domain}"
    lines = [
        f"domain: {domain}",
        "domains:",
        f"  - {domain}",
        f'listen_udp: "{listen}"',
        f'listen_tcp: "{listen}"',
        f"encryption_method: {method}",
        f"encryption_key_file: {DNSD_KEY}",
        "protocol_type: SOCKS5",
        'health_listen: "127.0.0.1:9111"',
        f'ns_hostname: "{ns_host}"',
        f'ns_ip: "{ns_ip}"',
        "connect_timeout_sec: 30",
        "session_timeout_sec: 300",
        "max_sessions: 255",
        "max_streams_per_session: 2000",
    ]
    return "\n".join(lines) + "\n"


def write_config(md: dict) -> None:
    DNSD_DIR.mkdir(parents=True, exist_ok=True)
    key = str(md.get("encryption_key") or "").strip()
    if not key:
        key = generate_key(int(md.get("encryption_method") or 2))
        md["encryption_key"] = key
    DNSD_KEY.write_text(key + "\n", encoding="utf-8")
    try:
        os.chmod(DNSD_KEY, 0o600)
    except OSError:
        pass
    DNSD_CFG.write_text(render_server_yaml(md), encoding="utf-8")
    try:
        os.chmod(DNSD_CFG, 0o600)
    except OSError:
        pass
    if not DNSD_UNIT.exists() or "l2x-dnsd" in DNSD_UNIT.read_text(encoding="utf-8", errors="ignore"):
        DNSD_UNIT.write_text(unit_body(), encoding="utf-8")


def dnsd_release_urls(tag: str = "") -> list[str]:
    tag = ops_mod.normalize_tag(tag)
    if not tag:
        try:
            tag = ops_mod.normalize_tag(
                Path("/opt/l2xpanel/VERSION").read_text(encoding="utf-8").strip().splitlines()[0]
            )
        except OSError:
            tag = ""
    if not tag:
        return []
    arch = ops_mod.tunnel_goarch()
    base = f"https://github.com/{ops_mod.PANEL_REPO}/releases/download/{tag}"
    return [
        f"{base}/l2x-dnsd-linux-{arch}",
        f"{base}/l2x-dnsd",
    ]


def install_binary_from_github(tag: str = "") -> dict:
    tag = ops_mod.normalize_tag(tag)
    if not tag:
        try:
            tag = ops_mod.normalize_tag(
                Path("/opt/l2xpanel/VERSION").read_text(encoding="utf-8").strip().splitlines()[0]
            )
        except OSError:
            tag = ""
    if not tag:
        return {"ok": False, "error": "no VERSION/tag"}

    tags_try = [tag]
    try:
        for r in ops_mod.panel_releases(8):
            t = ops_mod.normalize_tag(r.get("tag") or "")
            if t and t not in tags_try:
                tags_try.append(t)
            if len(tags_try) >= 4:
                break
    except Exception:
        pass

    blob = b""
    used = ""
    errors: list[str] = []
    for try_tag in tags_try:
        for url in dnsd_release_urls(try_tag):
            try:
                blob = ops_mod._http(url, 180)
                if blob and len(blob) > 1000:
                    used = url
                    break
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{url}: {exc}")
                blob = b""
        if blob:
            break
    if not blob:
        local = _try_local_build()
        if local.get("ok"):
            return local
        return {"ok": False, "error": "; ".join(errors[-4:]) or "l2x-dnsd asset missing", "tag": tag}

    Path("/usr/local/bin").mkdir(parents=True, exist_ok=True)
    tmp = Path(str(DNSD_BIN) + ".new")
    tmp.write_bytes(blob)
    os.chmod(tmp, 0o755)
    os.replace(tmp, DNSD_BIN)
    return {"ok": True, "tag": tag, "installed": f"l2x-dnsd←{used}"}


def _try_local_build() -> dict:
    """Fallback: build from /opt/l2xpanel/tunnel or repo tunnel/ next to panel."""
    candidates = [
        Path("/opt/l2xpanel/tunnel"),
        Path(__file__).resolve().parents[1] / "tunnel",
    ]
    src = next((p for p in candidates if (p / "cmd/l2x-dnsd").is_dir()), None)
    if src is None or not shutil.which("go"):
        return {"ok": False, "error": "no binary and no local go build"}
    env = {**os.environ, "CGO_ENABLED": "0", "GOOS": "linux"}
    out = Path("/usr/local/bin/l2x-dnsd")
    r = subprocess.run(
        ["go", "build", "-ldflags=-s -w", "-o", str(out), "./cmd/l2x-dnsd"],
        cwd=str(src),
        capture_output=True,
        text=True,
        timeout=180,
        env=env,
        check=False,
    )
    if r.returncode != 0 or not out.exists():
        return {"ok": False, "error": (r.stderr or r.stdout or "go build failed")[-400:]}
    os.chmod(out, 0o755)
    return {"ok": True, "installed": "l2x-dnsd←local-build"}


def apply(store: dict, *, install_bin: bool = False) -> dict:
    md = ensure_settings(store)
    out: dict[str, Any] = {"ok": True, "enabled": bool(md.get("enabled"))}
    if install_bin or (md.get("enabled") and not DNSD_BIN.exists()):
        bin_res = install_binary_from_github()
        out["binary"] = bin_res
        if not bin_res.get("ok") and md.get("enabled"):
            out["ok"] = False
            out["error"] = bin_res.get("error") or "binary install failed"
            return out

    try:
        write_config(md)
    except OSError as exc:
        return {"ok": False, "error": str(exc)}

    if not systemd_available():
        out["systemd"] = "unavailable"
        return out

    _run(["systemctl", "daemon-reload"])
    if md.get("enabled"):
        _run(["systemctl", "enable", "l2x-dnsd"])
        r = _run(["systemctl", "restart", "l2x-dnsd"])
        out["restart"] = (r.stderr or r.stdout or "")[-200:]
        out["active"] = service_active()
    else:
        _run(["systemctl", "stop", "l2x-dnsd"])
        _run(["systemctl", "disable", "l2x-dnsd"])
        out["active"] = False
    return out


def service_active() -> bool:
    if not systemd_available():
        return False
    r = _run(["systemctl", "is-active", "l2x-dnsd"])
    return (r.stdout or "").strip() == "active"


def service_status() -> dict:
    st: dict[str, Any] = {
        "binary": DNSD_BIN.exists(),
        "config": DNSD_CFG.exists(),
        "active": service_active(),
        "health": None,
        "resolved_conflict": False,
        "listen_hint": "",
    }
    try:
        raw = ops_mod._http(DNSD_HEALTH, 2).decode("utf-8", "replace")
        st["health"] = json.dumps(json.loads(raw), indent=2, ensure_ascii=False)
    except Exception as exc:  # noqa: BLE001
        st["health_error"] = str(exc)[:200]

    # systemd-resolved often owns :53
    try:
        r = _run(["ss", "-ulnp"])
        text = r.stdout or ""
        if ":53 " in text and "systemd-resolved" in text:
            st["resolved_conflict"] = True
            st["listen_hint"] = (
                "Порт 53 занят systemd-resolved. Отключите DNSStubListener "
                "(DNSStubListener=no в resolved.conf) или слушайте другой порт + DNAT."
            )
    except Exception:
        pass

    if systemd_available():
        r = _run(["systemctl", "status", "l2x-dnsd", "--no-pager", "-l"])
        st["status_text"] = ((r.stdout or "") + (r.stderr or ""))[-1500:]
    return st


def dns_setup_hints(md: dict, public_ip: str = "") -> list[str]:
    domain = str(md.get("domain") or "").strip().lower().rstrip(".")
    if not domain:
        return ["Укажите tunnel domain, например v.example.com"]
    parts = domain.split(".")
    parent = ".".join(parts[1:]) if len(parts) > 1 else domain
    ns = str(md.get("ns_hostname") or "").strip() or (f"ns.{parent}" if parent else f"ns.{domain}")
    ip = str(md.get("ns_ip") or public_ip or "<SERVER_IP>").strip()
    return [
        f"A  {ns}  →  {ip}",
        f"NS {domain}  →  {ns}",
        "Только DNS-делегирование (без Cloudflare proxy / orange cloud).",
        "Клиент ходит на публичные резолверы; они должны видеть NS делегирование.",
    ]


def client_resolvers_text(md: dict) -> str:
    resolvers = [str(x).strip() for x in (md.get("resolvers") or []) if str(x).strip()]
    if not resolvers:
        resolvers = list(DEFAULT_RESOLVERS)
    # MasterDnsVPN client_resolvers.txt: one IP per line (optionally host:port)
    lines = []
    for r in resolvers:
        if ":" not in r:
            lines.append(f"{r}:53")
        else:
            lines.append(r)
    return "\n".join(lines) + "\n"


def client_config_toml(md: dict) -> str:
    domain = str(md.get("domain") or "").strip().lower().rstrip(".")
    method = int(md.get("encryption_method") or 2)
    key = str(md.get("encryption_key") or "").strip()
    listen_ip = str(md.get("client_listen_ip") or "127.0.0.1").strip() or "127.0.0.1"
    listen_port = int(md.get("client_listen_port") or 18000)
    proto = str(md.get("protocol_type") or "SOCKS5").strip() or "SOCKS5"
    # Lossy-friendly defaults aligned with upstream sample
    return f'''# Generated by L2X Panel for MasterDnsVPN Client (wire-compatible)
DOMAINS = ["{domain}"]
DATA_ENCRYPTION_METHOD = {method}
ENCRYPTION_KEY = "{key}"
PROTOCOL_TYPE = "{proto}"
LISTEN_IP = "{listen_ip}"
LISTEN_PORT = {listen_port}
SOCKS5_AUTH = false
SOCKS5_USER = "master_dns_vpn"
SOCKS5_PASS = "master_dns_vpn"
LOCAL_DNS_ENABLED = false
RESOLVER_BALANCING_STRATEGY = 3
PACKET_DUPLICATION_COUNT = 3
SETUP_PACKET_DUPLICATION_COUNT = 4
STREAM_RESOLVER_FAILOVER_RESEND_THRESHOLD = 2
STREAM_RESOLVER_FAILOVER_COOLDOWN = 2.5
RECHECK_INACTIVE_SERVERS_ENABLED = true
AUTO_DISABLE_TIMEOUT_SERVERS = true
AUTO_DISABLE_TIMEOUT_WINDOW_SECONDS = 30.0
BASE_ENCODE_DATA = false
UPLOAD_COMPRESSION_TYPE = 0
DOWNLOAD_COMPRESSION_TYPE = 0
COMPRESSION_MIN_SIZE = 120
MIN_UPLOAD_MTU = 38
MIN_DOWNLOAD_MTU = 200
MAX_UPLOAD_MTU = 150
MAX_DOWNLOAD_MTU = 4000
AUTO_REMOVE_LOW_MTU_SERVERS = true
MTU_TEST_RETRIES = 2
MTU_TEST_TIMEOUT = 2.0
MTU_TEST_PARALLELISM = 32
RX_TX_WORKERS = 4
TUNNEL_PROCESS_WORKERS = 6
TUNNEL_PACKET_TIMEOUT_SECONDS = 10.0
SESSION_INIT_RACING_COUNT = 3
ARQ_WINDOW_SIZE = 1000
ARQ_INITIAL_RTO_SECONDS = 0.5
ARQ_MAX_RTO_SECONDS = 3.0
ARQ_CONTROL_INITIAL_RTO_SECONDS = 0.5
ARQ_CONTROL_MAX_RTO_SECONDS = 2.0
ARQ_MAX_CONTROL_RETRIES = 126
ARQ_INACTIVITY_TIMEOUT_SECONDS = 1800.0
ARQ_DATA_PACKET_TTL_SECONDS = 2400.0
ARQ_CONTROL_PACKET_TTL_SECONDS = 1200.0
ARQ_MAX_DATA_RETRIES = 126
ARQ_DATA_NACK_MAX_GAP = 32
LOG_LEVEL = "INFO"
'''


def build_client_zip(md: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("client_config.toml", client_config_toml(md))
        zf.writestr("client_resolvers.txt", client_resolvers_text(md))
        zf.writestr(
            "README.txt",
            "L2X MasterDNS client pack\n"
            "1. Install official MasterDnsVPN Client\n"
            "2. Place client_config.toml and client_resolvers.txt next to the client binary\n"
            "3. Ensure DNS NS delegation for DOMAINS points to this server\n",
        )
    return buf.getvalue()
