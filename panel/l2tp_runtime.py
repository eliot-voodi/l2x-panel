"""Multi-tunnel L2TP client via strongSwan + xl2tpd (not NetworkManager-l2tp).

Each tunnel gets its own PPP iface (l2x-<name>). Connect/disconnect/delete
must never restart NetworkManager or touch the host default route NIC.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import time
from pathlib import Path

DATA = Path(os.environ.get("L2XPANEL_DATA", "/var/lib/l2xpanel"))
TUN_DIR = DATA / "l2tp"
IPSEC_DIR = DATA / "ipsec"
CONTROL = "/var/run/xl2tpd/l2tp-control"

SLUG_SAFE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$")


def _run(cmd: list[str], timeout: int = 60) -> dict:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {
            "cmd": " ".join(cmd),
            "exit_code": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }
    except FileNotFoundError as exc:
        return {
            "cmd": " ".join(cmd),
            "exit_code": 127,
            "stdout": "",
            "stderr": f"not found: {exc.filename or cmd[0]}",
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "cmd": " ".join(cmd),
            "exit_code": 124,
            "stdout": (exc.stdout or "") if isinstance(exc.stdout, str) else "",
            "stderr": f"timeout after {timeout}s",
        }


def lac_name(name: str) -> str:
    return f"l2x-{name}"


def ifname_for(name: str) -> str:
    # IFNAMSIZ=16 incl. NUL → max 15 chars
    return f"l2x-{name}"[:15]


def vrf_name(name: str) -> str:
    return f"vrf-{name}"[:15]


def tunnel_table_id(name: str) -> int:
    """Stable routing-table / VRF table id in 1100..1999."""
    digest = hashlib.sha256(name.encode()).hexdigest()
    return 1100 + (int(digest[:6], 16) % 900)


def gw_conn_name(server_host: str) -> str:
    digest = hashlib.sha256(server_host.strip().lower().encode()).hexdigest()[:10]
    return f"l2xgw-{digest}"


def tunnel_dir(name: str) -> Path:
    path = TUN_DIR / name
    path.mkdir(parents=True, exist_ok=True)
    return path


def ensure_runtime_dirs() -> None:
    TUN_DIR.mkdir(parents=True, exist_ok=True)
    IPSEC_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(TUN_DIR, 0o700)
        os.chmod(IPSEC_DIR, 0o700)
    except OSError:
        pass


def ensure_services() -> dict:
    """Start ipsec/xl2tpd if needed — never restart NetworkManager."""
    ensure_runtime_dirs()
    out = {}
    # Debian 13 metapackage may leave only charon-systemd; starter needs /usr/lib/ipsec/charon
    if not Path("/usr/lib/ipsec/charon").exists():
        out["charon"] = {
            "ok": False,
            "error": "нет /usr/lib/ipsec/charon — установите пакет strongswan-charon "
                     "(apt-get install -y strongswan-charon)",
        }
    for unit in ("strongswan-starter", "xl2tpd"):
        st = _run(["systemctl", "is-active", unit])
        if (st["stdout"] or "").strip() != "active":
            _run(["systemctl", "enable", unit])
            out[unit] = _run(["systemctl", "start", unit], timeout=30)
        else:
            out[unit] = {"ok": True, "already": True}
    return out


def cleanup_nm_vpn_only() -> list[str]:
    """Remove leftover NM L2TP profiles; keep ethernet parent (net0-l2x) intact.

    No-op when NetworkManager/nmcli is not installed (minimal VPS images).
    """
    removed: list[str] = []
    shown = _run(["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show"])
    if shown["exit_code"] == 127:
        return removed
    for line in (shown["stdout"] or "").splitlines():
        parts = line.split(":")
        if len(parts) < 2:
            continue
        name, typ = parts[0], parts[1]
        if typ == "vpn" and name.startswith("l2x-"):
            _run(["nmcli", "connection", "down", name], timeout=30)
            _run(["nmcli", "connection", "delete", name], timeout=30)
            removed.append(name)
    return removed


def _write_ppp_options(name: str, username: str, password: str) -> Path:
    iface = ifname_for(name)
    path = tunnel_dir(name) / "ppp.options"
    # nodefaultroute: do not steal host default gateway
    content = "\n".join(
        [
            f'user "{username}"',
            f'password "{password}"',
            "noauth",
            "nodefaultroute",
            "noipdefault",
            "nodetach",
            f"ifname {iface}",
            "mtu 1400",
            "mru 1400",
            "lcp-echo-failure 4",
            "lcp-echo-interval 30",
            "",
        ]
    )
    path.write_text(content, encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def _resolve_ips(host: str) -> list[str]:
    r = _run(["getent", "ahostsv4", host])
    ips: list[str] = []
    for line in (r["stdout"] or "").splitlines():
        parts = line.split()
        if parts and parts[0][0].isdigit() and parts[0] not in ips:
            ips.append(parts[0])
    if not ips:
        r2 = _run(["dig", "+short", "A", host])
        for line in (r2["stdout"] or "").splitlines():
            line = line.strip()
            if line and line[0].isdigit() and line not in ips:
                ips.append(line)
    return ips


def _local_ipv4() -> str:
    """Host WAN address (net0), never a PPP/l2x address."""
    # prefer address on the default-route iface, skipping l2x-/ppp
    r = _run(["ip", "-4", "route", "show", "default"])
    iface = ""
    for line in (r["stdout"] or "").splitlines():
        parts = line.split()
        if "dev" in parts:
            cand = parts[parts.index("dev") + 1]
            if not cand.startswith("l2x-") and not cand.startswith("ppp"):
                iface = cand
                break
    if iface:
        addr_r = _run(["ip", "-4", "-br", "addr", "show", "dev", iface])
        for tok in (addr_r["stdout"] or "").split():
            if "/" in tok and tok[0].isdigit():
                ip = tok.split("/")[0]
                if not ip.startswith("10.50."):
                    return ip
    # fallback: route get, but reject PPP-looking sources
    r = _run(["ip", "-4", "route", "get", "1.1.1.1"])
    parts = (r["stdout"] or "").split()
    if "src" in parts:
        src = parts[parts.index("src") + 1]
        if not src.startswith("10.50."):
            return src
    return ""


def _rebuild_psk_aggregate() -> None:
    """Write PSK directly into /etc/ipsec.secrets.

    strongSwan starter often fails to reload secrets from `include` files;
    inlining is reliable and still scoped per-peer IP lines.
    """
    ensure_runtime_dirs()
    chunks: list[str] = ["# Managed by L2X Panel — regenerated on Connect/Delete\n"]
    for path in sorted(IPSEC_DIR.glob("l2xgw-*.secrets")):
        chunks.append(f"# {path.name}\n" + path.read_text(encoding="utf-8").rstrip() + "\n")
    body = "".join(chunks) if len(chunks) > 1 else "# no l2tp psk yet\n"
    agg = IPSEC_DIR / "l2x-psk.secrets"
    agg.write_text(body, encoding="utf-8")
    os.chmod(agg, 0o600)
    main = Path("/etc/ipsec.secrets")
    main.write_text(body, encoding="utf-8")
    os.chmod(main, 0o600)
    _run(["ipsec", "rereadsecrets"])


LNS_CACHE = Path("/var/lib/l2xpanel/lns-cache.json")


def _load_lns_cache() -> dict:
    try:
        return json.loads(LNS_CACHE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _save_lns_cache(cache: dict) -> None:
    ensure_runtime_dirs()
    LNS_CACHE.write_text(json.dumps(cache, indent=2), encoding="utf-8")


def _remember_lns_ip(server_host: str, ip: str) -> None:
    if not ip or not ip[0].isdigit():
        return
    cache = _load_lns_cache()
    cache[server_host] = ip
    _save_lns_cache(cache)


def _lns_candidates(server_host: str) -> list[str]:
    """Ordered LNS IPs: last-good first, then remaining A records (stable order)."""
    ips = _resolve_ips(server_host)
    # stable order so reconnects don't flip between equally-fresh A records
    ips = sorted(set(ips), key=lambda x: tuple(int(p) for p in x.split(".")))
    cached = _load_lns_cache().get(server_host)
    out: list[str] = []
    if cached and cached in ips:
        out.append(cached)
    for ip in ips:
        if ip not in out:
            out.append(ip)
    if not out:
        out.append(server_host)
    return out


def _pick_lns_ip(server_host: str) -> str:
    """Pin one A-record so IPsec right= and xl2tpd lns= always match."""
    return _lns_candidates(server_host)[0]


def _write_ipsec_conn(server_host: str, psk: str, right_ip: str | None = None) -> str:
    """One transport SA per LNS gateway; shared by tunnels to that host."""
    ensure_runtime_dirs()
    conn = gw_conn_name(server_host)
    conf = IPSEC_DIR / f"{conn}.conf"
    secrets = IPSEC_DIR / f"{conn}.secrets"
    # IMPORTANT: never use left=%defaultroute after an L2TP is up — strongSwan may
    # pick the PPP address (e.g. 10.50.60.2) as source and break the next tunnel.
    left = _local_ipv4() or "%defaultroute"
    right = right_ip or _pick_lns_ip(server_host)
    conf.write_text(
        "\n".join(
            [
                f"conn {conn}",
                "    auto=add",
                "    keyexchange=ikev1",
                "    authby=secret",
                "    type=transport",
                f"    left={left}",
                "    leftprotoport=17/%any",
                f"    right={right}",
                # peer often responds with a different IDir IP than DNS A record
                "    rightid=%any",
                "    rightprotoport=17/1701",
                "    ike=aes256-sha1-modp2048,aes128-sha1-modp2048,aes256-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024!",
                "    esp=aes256-sha1,aes128-sha1,3des-sha1!",
                "    aggressive=no",
                "    keyingtries=3",
                "    ikelifetime=8h",
                "    keylife=1h",
                "    dpddelay=30",
                "    dpdtimeout=120",
                "    dpdaction=clear",
                "",
            ]
        ),
        encoding="utf-8",
    )
    local = _local_ipv4()
    lines = [
        f'%any {server_host} : PSK "{psk}"',
        f'%any {right} : PSK "{psk}"',
    ]
    ips = _resolve_ips(server_host)
    for ip in ips:
        lines.append(f'%any {ip} : PSK "{psk}"')
        if local:
            lines.append(f'{local} {ip} : PSK "{psk}"')
    if local:
        lines.append(f'{local} {right} : PSK "{psk}"')
        lines.append(f'{local} %any : PSK "{psk}"')
    if not ips and right == server_host:
        lines.append(f': PSK "{psk}"')
    secrets.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.chmod(secrets, 0o600)
    _rebuild_psk_aggregate()
    upd = _run(["ipsec", "update"])
    if upd["exit_code"] != 0:
        _run(["ipsec", "reload"])
    return conn


def _ipsec_loaded(conn: str) -> bool:
    status = _run(["ipsec", "statusall"])
    text = status["stdout"] or ""
    return any(line.startswith(f"{conn}:") for line in text.splitlines())


def _ipsec_established(conn: str) -> bool:
    status = _run(["ipsec", "status", conn])
    text = f"{status['stdout']}\n{status['stderr']}"
    return "ESTABLISHED" in text


def _ipsec_up(conn: str, expect_right: str | None = None) -> dict:
    # ensure conf snippets are loaded (does not tear down existing SAs)
    _run(["ipsec", "rereadsecrets"])
    _run(["ipsec", "update"])
    if not _ipsec_loaded(conn):
        _run(["ipsec", "reload"])
        time.sleep(1)
    if not _ipsec_loaded(conn):
        return {"ok": False, "error": f"ipsec config '{conn}' not loaded after update"}
    if _ipsec_established(conn):
        status = _run(["ipsec", "status", conn])
        text = f"{status['stdout']}\n{status['stderr']}"
        if expect_right and expect_right not in text:
            # established to a different A-record — rebuild SA
            _run(["timeout", "15", "ipsec", "down", conn], timeout=20)
            time.sleep(0.5)
        else:
            return {"ok": True, "already": True}
    # clear stuck CONNECTING SAs for this conn
    _run(["timeout", "15", "ipsec", "down", conn], timeout=20)
    time.sleep(0.5)
    up = _run(["timeout", "35", "ipsec", "up", conn], timeout=45)
    out = f"{up['stdout']}\n{up['stderr']}"
    ok = _ipsec_established(conn) or (
        up["exit_code"] == 0 and "established" in out.lower() and "no config named" not in out.lower()
    )
    return {
        "ok": ok,
        "error": "" if ok else (up["stderr"] or up["stdout"] or out or "ipsec up failed"),
        "up": up,
    }


def _ipsec_down_if_unused(conn: str, server_host: str, store_l2tp: list[dict], except_name: str) -> None:
    still = [
        x
        for x in store_l2tp
        if x.get("name") != except_name
        and x.get("server_host") == server_host
        and x.get("status") == "connected"
    ]
    # also check live ifaces for other tunnels to same host
    live_others = False
    for x in store_l2tp:
        if x.get("name") == except_name or x.get("server_host") != server_host:
            continue
        if iface_is_up(ifname_for(x["name"])):
            live_others = True
            break
    if still or live_others:
        return
    _run(["ipsec", "down", conn], timeout=60)


def _iface_exists(iface: str) -> bool:
    return _run(["ip", "link", "show", "dev", iface], timeout=5)["exit_code"] == 0


def _purge_iface(iface: str) -> None:
    """Remove leftover PPP device so pppd can recreate ifname=l2x-*."""
    if not _iface_exists(iface):
        return
    _run(["ip", "link", "set", "dev", iface, "down"], timeout=10)
    _run(["ip", "link", "delete", "dev", iface], timeout=10)


def _xl2tp_add(name: str, server_host: str, ppp_opt: Path, lns_ip: str | None = None) -> dict:
    lac = lac_name(name)
    lns = lns_ip or _pick_lns_ip(server_host)
    # remove stale definition then add (does not affect other lac)
    _run(["xl2tpd-control", "-c", CONTROL, "remove-lac", lac], timeout=30)
    add = _run(
        [
            "xl2tpd-control",
            "-c",
            CONTROL,
            "add-lac",
            lac,
            f"lns={lns}",
            f"pppoptfile={ppp_opt}",
            "redial=no",
            "require chap=yes",
            "refuse pap=yes",
            "require authentication=yes",
            "name=l2xpanel",
        ],
        timeout=30,
    )
    return add


def iface_is_up(iface: str) -> bool:
    """PPP ifaces often show state UNKNOWN — treat as up when they have an IPv4 address."""
    r = _run(["ip", "-4", "-br", "addr", "show", "dev", iface])
    if r["exit_code"] != 0:
        return False
    return bool(re.search(r"\b\d+\.\d+\.\d+\.\d+", r["stdout"] or ""))


def iface_addrs(iface: str) -> str:
    r = _run(["ip", "-4", "-br", "addr", "show", "dev", iface])
    return (r["stdout"] or "").strip()


def parse_ppp_endpoints(iface: str) -> tuple[str, str]:
    """Return (local_ip, peer_ip) for a PPP iface."""
    r = _run(["ip", "-4", "addr", "show", "dev", iface])
    local = peer = ""
    for line in (r["stdout"] or "").splitlines():
        line = line.strip()
        if not line.startswith("inet "):
            continue
        parts = line.split()
        # inet 10.50.60.2 peer 10.50.60.1/32 scope global ...
        if len(parts) >= 2:
            local = parts[1].split("/")[0]
        if "peer" in parts:
            peer = parts[parts.index("peer") + 1].split("/")[0]
    return local, peer


def probe_public_ip(iface: str, timeout: int = 8) -> str:
    for url in ("https://ifconfig.me", "http://ifconfig.me", "https://api.ipify.org"):
        r = _run(
            ["curl", "-4", "-s", "--max-time", str(timeout), "--interface", iface, url],
            timeout=timeout + 5,
        )
        ip = (r["stdout"] or "").strip()
        if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", ip):
            return ip
    return ""


def ping_host_ms(host: str, timeout: int = 4) -> float | None:
    """ICMP RTT to LNS host in ms (rough pre-filter before connecting)."""
    host = (host or "").strip()
    if not host:
        return None
    r = _run(["ping", "-4", "-c", "2", "-W", str(timeout), host], timeout=timeout * 3 + 2)
    text = (r.get("stdout") or "") + "\n" + (r.get("stderr") or "")
    # rtt min/avg/max/mdev = 12.3/14.1/...
    m = re.search(r"=\s*([\d.]+)/([\d.]+)/", text)
    if m:
        return round(float(m.group(2)), 1)
    m = re.search(r"time[=<]([\d.]+)\s*ms", text)
    return round(float(m.group(1)), 1) if m else None


def measure_iface(iface: str, *, dl_bytes: int = 8_000_000, ul_bytes: int = 2_000_000) -> dict:
    """Egress quality through a PPP iface: ping ms, download/upload Mbps."""
    out: dict = {"ok": False, "ping_ms": None, "dl_mbps": None, "ul_mbps": None, "error": ""}
    if not iface or not iface_is_up(iface):
        out["error"] = "iface down"
        return out
    # TCP connect time to a light endpoint ≈ latency through the tunnel
    ping = _run(
        ["curl", "-4", "-s", "-o", "/dev/null", "-w", "%{time_connect}",
         "--max-time", "8", "--interface", iface, "https://www.gstatic.com/generate_204"],
        timeout=12,
    )
    try:
        out["ping_ms"] = round(float((ping.get("stdout") or "0").strip()) * 1000, 1)
    except ValueError:
        out["ping_ms"] = None
    dl = _run(
        ["curl", "-4", "-s", "-o", "/dev/null",
         "-w", "%{speed_download}", "--max-time", "25", "--interface", iface,
         f"https://speed.cloudflare.com/__down?bytes={int(dl_bytes)}"],
        timeout=30,
    )
    try:
        out["dl_mbps"] = round(float((dl.get("stdout") or "0").strip()) * 8 / 1e6, 2)
    except ValueError:
        out["dl_mbps"] = None
    # Cloudflare upload sink (small blob through the tunnel)
    tmp = f"/tmp/l2x-ul-{os.getpid()}-{iface.replace('/', '_')}.bin"
    ul: dict = {"stdout": "", "stderr": "", "exit_code": 1}
    try:
        with open(tmp, "wb") as f:
            f.write(b"\0" * max(64_000, int(ul_bytes)))
        ul = _run(
            ["curl", "-4", "-s", "-o", "/dev/null",
             "-w", "%{speed_upload}", "--max-time", "20", "--interface", iface,
             "-X", "POST", "--data-binary", f"@{tmp}",
             "https://speed.cloudflare.com/__up"],
            timeout=25,
        )
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
    try:
        out["ul_mbps"] = round(float((ul.get("stdout") or "0").strip()) * 8 / 1e6, 2)
    except ValueError:
        out["ul_mbps"] = None
    out["ok"] = out["dl_mbps"] is not None and out["dl_mbps"] > 0
    if not out["ok"]:
        out["error"] = (dl.get("stderr") or ul.get("stderr") or "measure failed")[:200]
    return out


def score_tunnel(metrics: dict) -> float:
    """Higher is better: prefer throughput, penalize latency."""
    dl = float(metrics.get("dl_mbps") or 0)
    ul = float(metrics.get("ul_mbps") or 0)
    ping = float(metrics.get("ping_ms") or metrics.get("lns_ping_ms") or 9999)
    # Mbps dominate; ping penalty softens after ~50 ms
    return round(dl * 1.0 + ul * 0.5 - min(ping, 2000) / 20.0, 3)


def setup_tunnel_isolation(name: str, iface: str) -> dict:
    """Isolate overlapping PPP addresses with per-tunnel routing tables.

    Many L2TP providers hand out the same 10.x.x.x via IPCP to every session.
    We cannot change that (LNS assigns it), but we can:
      - put default/peer routes into a dedicated table keyed by oif
      - loosen rp_filter
      - probe the real public egress IP for the UI
    """
    table = tunnel_table_id(name)
    local, peer = parse_ppp_endpoints(iface)
    return setup_tunnel_policy_routing(name, iface, table, local, peer)


def setup_tunnel_policy_routing(name: str, iface: str, table: int, local: str, peer: str) -> dict:
    """Fallback when VRF unavailable: oif-based policy routing."""
    pref = table
    _run(["ip", "rule", "del", "pref", str(pref)], timeout=5)
    _run(["ip", "route", "flush", "table", str(table)], timeout=5)
    if peer:
        # drop ambiguous main-table peer route for this iface only
        _run(["ip", "route", "del", peer, "dev", iface], timeout=5)
        _run(
            ["ip", "route", "replace", f"{peer}/32", "dev", iface, "src", local or "0.0.0.0", "table", str(table)],
            timeout=5,
        )
        _run(
            ["ip", "route", "replace", "default", "via", peer, "dev", iface, "onlink", "table", str(table)],
            timeout=5,
        )
    _run(["ip", "rule", "add", "pref", str(pref), "oif", iface, "lookup", str(table)], timeout=5)
    # avoid blackholes on 1400-MTU PPP when clients send large TCP segments
    for chain in ("FORWARD", "OUTPUT"):
        mss = [
            "iptables", "-t", "mangle", "-C", chain, "-o", iface, "-p", "tcp",
            "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu",
        ]
        if _run(mss, timeout=5)["exit_code"] != 0:
            mss[3] = "-A"
            _run(mss, timeout=5)
    try:
        Path(f"/proc/sys/net/ipv4/conf/{iface}/rp_filter").write_text("2", encoding="utf-8")
    except OSError:
        pass
    public_ip = probe_public_ip(iface)
    return {
        "ok": True,
        "mode": "policy",
        "table": table,
        "vrf": "",
        "local": local,
        "peer": peer,
        "public_ip": public_ip,
    }


def teardown_tunnel_isolation(name: str, iface: str) -> None:
    table = tunnel_table_id(name)
    vrf = vrf_name(name)
    _run(["ip", "link", "set", "dev", iface, "nomaster"], timeout=10)
    _run(["ip", "link", "del", vrf], timeout=10)
    _run(["ip", "rule", "del", "pref", str(table)], timeout=5)
    _run(["ip", "route", "flush", "table", str(table)], timeout=5)


def is_connected(name: str) -> bool:
    return iface_is_up(ifname_for(name))


def write_tunnel_configs(item: dict, password: str, psk: str, lns_ip: str | None = None) -> dict:
    name = item["name"]
    if not password:
        return {"ok": False, "error": "password is empty — re-save connection with password"}
    ensure_services()
    ppp = _write_ppp_options(name, item["username"], password)
    lns = lns_ip or _pick_lns_ip(item["server_host"])
    meta = {
        "name": name,
        "ifname": ifname_for(name),
        "lac": lac_name(name),
        "server_host": item["server_host"],
        "lns_ip": lns,
        "ppp_options": str(ppp),
        "psk_set": bool(psk),
    }
    (tunnel_dir(name) / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    conn = None
    if psk:
        conn = _write_ipsec_conn(item["server_host"], psk, right_ip=lns)
        meta["ipsec_conn"] = conn
        (tunnel_dir(name) / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    add = _xl2tp_add(name, item["server_host"], ppp, lns_ip=lns)
    if add["exit_code"] != 0:
        return {
            "ok": False,
            "error": add["stderr"] or add["stdout"] or "xl2tpd add-lac failed",
            "details": add,
        }
    return {"ok": True, "meta": meta, "add": add, "lns_ip": lns}


def _wait_ppp_up(iface: str, seconds: float = 45.0) -> bool:
    deadline = time.time() + seconds
    while time.time() < deadline:
        if iface_is_up(iface):
            return True
        time.sleep(0.5)
    return False


def _ppp_failure_hint(iface: str) -> str:
    """Pull last pppd/xl2tpd reason for this iface (CHAP fail, File exists, …)."""
    log = _run(
        ["journalctl", "-u", "xl2tpd", "--since", "2 min ago", "--no-pager"],
        timeout=10,
    )
    text = f"{log.get('stdout', '')}\n{log.get('stderr', '')}"
    hits: list[str] = []
    for line in text.splitlines():
        low = line.lower()
        if iface.lower() not in low and "chap" not in low and "auth" not in low and "file exists" not in low:
            continue
        if any(
            k in low
            for k in (
                "chap authentication failed",
                "ms-chap authentication failed",
                "authentication failed",
                "file exists",
                "connection terminated",
                "modem hangup",
                "couldn't create ppp",
            )
        ):
            hits.append(line.strip()[-160:])
    if hits:
        return hits[-1]
    return f"iface {iface} did not come up"


def connect_tunnel(item: dict, password: str, psk: str) -> dict:
    svc = ensure_services()
    if (svc.get("charon") or {}).get("ok") is False:
        return {"ok": False, "error": svc["charon"]["error"], "details": svc}
    swan = svc.get("strongswan-starter") or {}
    if swan.get("exit_code") not in (None, 0) and not swan.get("already"):
        return {"ok": False, "error": f"strongSwan не запущен: {swan.get('stderr') or swan}", "details": svc}
    cleanup_nm_vpn_only()
    iface = ifname_for(item["name"])
    lac = lac_name(item["name"])
    host = item["server_host"]
    candidates = _lns_candidates(host)
    steps: dict = {"candidates": candidates, "services": svc}
    last_up: dict | None = None

    for lns in candidates:
        _run(["xl2tpd-control", "-c", CONTROL, "disconnect-lac", lac], timeout=30)
        teardown_tunnel_isolation(item["name"], iface)
        _purge_iface(iface)
        time.sleep(0.3)

        written = write_tunnel_configs(item, password, psk, lns_ip=lns)
        if not written.get("ok"):
            steps[f"write:{lns}"] = written
            continue
        attempt: dict = {"written": written, "lns_ip": lns}

        if psk:
            conn = gw_conn_name(host)
            ipsec = _ipsec_up(conn, expect_right=lns)
            attempt["ipsec"] = ipsec
            if not ipsec.get("ok"):
                steps[f"try:{lns}"] = attempt
                continue

        conn_lac = _run(["xl2tpd-control", "-c", CONTROL, "connect-lac", lac], timeout=90)
        attempt["connect_lac"] = conn_lac
        if not _wait_ppp_up(iface, 45.0):
            hint = _ppp_failure_hint(iface)
            attempt["error"] = conn_lac["stderr"] or conn_lac["stdout"] or hint
            attempt["ppp_hint"] = hint
            steps[f"try:{lns}"] = attempt
            # leftover DOWN iface after failed pppd blocks the next attempt
            _purge_iface(iface)
            continue

        iso = setup_tunnel_isolation(item["name"], iface)
        attempt["isolation"] = iso
        result = {
            "ok": True,
            "ifname": iface,
            "addr": iface_addrs(iface),
            "local_ip": iso.get("local") or "",
            "peer_ip": iso.get("peer") or "",
            "public_ip": iso.get("public_ip") or "",
            "vrf": iso.get("vrf") or "",
            "table": iso.get("table"),
            "lns_ip": lns,
            "details": {**steps, f"try:{lns}": attempt},
        }
        if result["public_ip"]:
            _remember_lns_ip(host, lns)
            return result
        # PPP up but no internet via this A-record — remember as last resort, try next
        last_up = result
        steps[f"try:{lns}"] = attempt

    if last_up:
        # keep session that at least brought PPP up
        if last_up.get("lns_ip"):
            _remember_lns_ip(host, last_up["lns_ip"])
        last_up["details"] = steps
        return last_up

    err = "all LNS candidates failed"
    for key in reversed(list(steps)):
        if key.startswith("try:") and isinstance(steps[key], dict) and steps[key].get("error"):
            err = steps[key]["error"]
            break
    return {"ok": False, "error": err, "details": steps}


def disconnect_tunnel(item: dict, store_l2tp: list[dict] | None = None) -> dict:
    name = item["name"]
    lac = lac_name(name)
    iface = ifname_for(name)
    teardown_tunnel_isolation(name, iface)
    down = _run(["xl2tpd-control", "-c", CONTROL, "disconnect-lac", lac], timeout=60)
    # wait for OUR iface only — never touch net0 or other l2x-* ifaces
    for _ in range(40):
        if not iface_is_up(iface):
            break
        time.sleep(0.25)
    # always purge named PPP device (DOWN leftovers block next pppd ifname=)
    _purge_iface(iface)
    if store_l2tp is not None and item.get("psk_set", True):
        conn = gw_conn_name(item["server_host"])
        _ipsec_down_if_unused(conn, item["server_host"], store_l2tp, name)
    ok = not _iface_exists(iface)
    return {
        "ok": ok,
        "error": "" if ok else (down["stderr"] or down["stdout"] or f"{iface} still present"),
        "details": down,
        "ifname": iface,
    }


def delete_tunnel(item: dict, store_l2tp: list[dict] | None = None) -> dict:
    disconnect_tunnel(item, store_l2tp=store_l2tp)
    lac = lac_name(item["name"])
    _run(["xl2tpd-control", "-c", CONTROL, "remove-lac", lac], timeout=30)
    # remove NM leftovers for this name only
    nm = f"l2x-{item['name']}"
    _run(["nmcli", "connection", "delete", nm], timeout=20)
    # remove per-tunnel files; keep shared ipsec gw conf until unused
    tdir = TUN_DIR / item["name"]
    if tdir.exists():
        for f in tdir.iterdir():
            try:
                f.unlink()
            except OSError:
                pass
        try:
            tdir.rmdir()
        except OSError:
            pass
    if store_l2tp is not None:
        host = item["server_host"]
        others = [x for x in store_l2tp if x.get("name") != item["name"] and x.get("server_host") == host]
        if not others:
            conn = gw_conn_name(host)
            _run(["ipsec", "down", conn], timeout=30)
            for ext in (".conf", ".secrets"):
                p = IPSEC_DIR / f"{conn}{ext}"
                if p.exists():
                    p.unlink()
            _run(["ipsec", "rereadsecrets"])
            _run(["ipsec", "update"])
    return {"ok": True}
